package api

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"nanoio/internal/auth"
	"nanoio/internal/bucket/nslock"
	"nanoio/internal/iam"
	"nanoio/internal/storage/fs"
)

func (e *testEnv) asUser(ak, sk, method, path string, body string) int {
	e.t.Helper()
	s := auth.Signer{AccessKey: ak, SecretKey: sk}
	var r *strings.Reader
	if body != "" {
		r = strings.NewReader(body)
	} else {
		r = strings.NewReader("")
	}
	resp, _ := e.send(&s, method, path, r, nil)
	return resp.StatusCode
}

func putJSON(t *testing.T, e *testEnv, path string, v any) {
	t.Helper()
	b, _ := json.Marshal(v)
	resp, body := e.do("PUT", path, strings.NewReader(string(b)), nil)
	if resp.StatusCode != 204 {
		t.Fatalf("PUT %s: %d %s", path, resp.StatusCode, body)
	}
}

func TestRuntimeIAMUsersGroupsAndPolicies(t *testing.T) {
	e := newEnv(t)
	e.mb("iambkt")
	e.put("/iambkt/doc.txt", "doc", nil)

	// A new user can do nothing, then something, then is cut off.
	putJSON(t, e, "/_nanoio/admin/iam/user", iam.UserEntry{AccessKey: "alice", SecretKey: "alice-secret-1"})
	if st := e.asUser("alice", "alice-secret-1", "GET", "/iambkt/doc.txt", ""); st != 403 {
		t.Fatalf("a user with no policy read an object: %d", st)
	}
	putJSON(t, e, "/_nanoio/admin/iam/policy", map[string]any{"name": "read-iambkt", "policy": json.RawMessage(
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::iambkt/*"}]}`)})
	putJSON(t, e, "/_nanoio/admin/iam/user", iam.UserEntry{AccessKey: "alice", SecretKey: "alice-secret-1", Policies: []string{"read-iambkt"}})
	if st := e.asUser("alice", "alice-secret-1", "GET", "/iambkt/doc.txt", ""); st != 200 {
		t.Errorf("after attaching the policy: %d", st)
	}
	if st := e.asUser("alice", "alice-secret-1", "PUT", "/iambkt/new.txt", "x"); st != 403 {
		t.Errorf("a read policy allowed a write: %d", st)
	}

	// A group grants write to its members; an explicit deny in the group
	// overrides an allow of the user.
	putJSON(t, e, "/_nanoio/admin/iam/group", iam.GroupEntry{Name: "writers", Members: []string{"alice"}, Policies: []string{"writeonly"}})
	if st := e.asUser("alice", "alice-secret-1", "PUT", "/iambkt/new.txt", "x"); st != 200 {
		t.Errorf("write through a group: %d", st)
	}
	putJSON(t, e, "/_nanoio/admin/iam/policy", map[string]any{"name": "no-new", "policy": json.RawMessage(
		`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:PutObject","Resource":"arn:aws:s3:::iambkt/new*"}]}`)})
	putJSON(t, e, "/_nanoio/admin/iam/group", iam.GroupEntry{Name: "writers", Members: []string{"alice"}, Policies: []string{"writeonly", "no-new"}})
	if st := e.asUser("alice", "alice-secret-1", "PUT", "/iambkt/new2.txt", "x"); st != 403 {
		t.Errorf("a group Deny did not apply: %d", st)
	}
	// A disabled group contributes nothing.
	putJSON(t, e, "/_nanoio/admin/iam/group", iam.GroupEntry{Name: "writers", Status: "disabled", Members: []string{"alice"}, Policies: []string{"writeonly"}})
	if st := e.asUser("alice", "alice-secret-1", "PUT", "/iambkt/other.txt", "x"); st != 403 {
		t.Errorf("a disabled group granted access: %d", st)
	}

	// Listings never reveal secrets; the group appears on the user.
	resp, b := e.do("GET", "/_nanoio/admin/iam/user", nil, nil)
	if resp.StatusCode != 200 || strings.Contains(string(b), "alice-secret-1") || !strings.Contains(string(b), `"writers"`) {
		t.Errorf("user list = %d %s", resp.StatusCode, b)
	}

	// A policy in use cannot be removed; users can; the key then stops working.
	resp, b = e.do("DELETE", "/_nanoio/admin/iam/policy?name=read-iambkt", nil, nil)
	wantError(t, resp, b, 409, "PolicyInUse")
	if r, _ := e.do("DELETE", "/_nanoio/admin/iam/user?accessKey=alice", nil, nil); r.StatusCode != 204 {
		t.Fatalf("delete user = %d", r.StatusCode)
	}
	if st := e.asUser("alice", "alice-secret-1", "GET", "/iambkt/doc.txt", ""); st != 403 {
		t.Errorf("a deleted user still authenticates: %d", st)
	}

	// Only root manages IAM; names from the IAM file are protected.
	resp, b = e.doAs("reader", "PUT", "/_nanoio/admin/iam/user", strings.NewReader(`{"accessKey":"mallory","secretKey":"mallory-secret"}`), nil)
	wantError(t, resp, b, 403, "AccessDenied")
	bad, _ := json.Marshal(iam.UserEntry{AccessKey: "reader", SecretKey: "changed-secret-1"})
	resp, b = e.do("PUT", "/_nanoio/admin/iam/user", strings.NewReader(string(bad)), nil)
	wantError(t, resp, b, 403, "AccessDenied")
	bad, _ = json.Marshal(iam.UserEntry{AccessKey: rootAK, SecretKey: "whatever-secret"})
	resp, b = e.do("PUT", "/_nanoio/admin/iam/user", strings.NewReader(string(bad)), nil)
	wantError(t, resp, b, 400, "InvalidArgument")
	resp, b = e.do("PUT", "/_nanoio/admin/iam/user", strings.NewReader(`{"accessKey":"bob","secretKey":"bob-secret-12","policies":["nope"]}`), nil)
	wantError(t, resp, b, 400, "InvalidArgument")
	resp, b = e.do("PUT", "/_nanoio/admin/iam/policy", strings.NewReader(`{"name":"bad","policy":{"Statement":"x"}}`), nil)
	wantError(t, resp, b, 400, "InvalidArgument")
}

// Two servers over one backend (two nodes) see each other's IAM changes, and
// a restart loses nothing.
func TestRuntimeIAMIsSharedAndPersistent(t *testing.T) {
	be, err := fs.New(t.TempDir(), fs.Options{Locker: nslock.New(5 * time.Second), Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { be.Close() })
	a := serve(t, be, be)
	b := serve(t, be, be)
	putJSON(t, a, "/_nanoio/admin/iam/user", iam.UserEntry{AccessKey: "carol", SecretKey: "carol-secret-1", Policies: []string{"readwrite"}})
	a.mb("sharedbkt")
	deadline := time.Now().Add(10 * time.Second)
	for b.asUser("carol", "carol-secret-1", "GET", "/sharedbkt?list-type=2", "") != 200 {
		if time.Now().After(deadline) {
			t.Fatal("the second node never saw the new user")
		}
		time.Sleep(50 * time.Millisecond)
	}
	// A third server started later loads it at startup.
	c := serve(t, be, be)
	if st := c.asUser("carol", "carol-secret-1", "GET", "/sharedbkt?list-type=2", ""); st != 200 {
		t.Errorf("a new node did not load runtime users: %d", st)
	}
}
