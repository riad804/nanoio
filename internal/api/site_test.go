package api

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"nanoio/internal/auth"
	"nanoio/internal/iam"
)

// join adds peer to the group a belongs to, as an operator would.
func (a *testSite) join(peer *testSite, name, selfName string) {
	a.t.Helper()
	req := map[string]any{
		"self": map[string]string{"name": selfName, "endpoint": a.url()},
		"site": map[string]string{"name": name, "endpoint": peer.url(), "accessKey": rootAK, "secretKey": rootSK},
	}
	b, _ := json.Marshal(req)
	resp, body := a.env.do("POST", "/_nanoio/admin/site/add", strings.NewReader(string(b)), nil)
	if resp.StatusCode != 204 {
		a.t.Fatalf("site add: %d %s", resp.StatusCode, body)
	}
}

func (s *testSite) userCan(ak, sk, method, path string) int {
	s.t.Helper()
	signer := auth.Signer{AccessKey: ak, SecretKey: sk}
	resp, _ := s.env.send(&signer, method, path, strings.NewReader(""), nil)
	return resp.StatusCode
}

func (s *testSite) putUser(u iam.UserEntry) {
	s.t.Helper()
	putJSON(s.t, s.env, "/_nanoio/admin/iam/user", u)
}

func (s *testSite) bucketPolicy(bucket string) string {
	resp, b := s.env.do("GET", "/"+bucket+"?policy", nil, nil)
	if resp.StatusCode != 200 {
		return ""
	}
	return string(b)
}

const polOpen = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::%s/*"}]}`
const polClosed = `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:DeleteObject","Resource":"arn:aws:s3:::%s/*"}]}`

func TestSiteReplicationPropagatesIAMBucketsConfigAndObjects(t *testing.T) {
	a, b := newSite(t), newSite(t)
	a.join(b, "site-b", "site-a")

	// IAM: both directions, groups and policies too.
	a.putUser(iam.UserEntry{AccessKey: "alice", SecretKey: "alice-secret-1", Policies: []string{"readwrite"}})
	putJSON(t, b.env, "/_nanoio/admin/iam/policy", map[string]any{"name": "ro-docs", "policy": json.RawMessage(
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::docs/*"}]}`)})
	waitUntil(t, "policy a<-b", func() bool {
		resp, body := a.env.do("GET", "/_nanoio/admin/iam/policy", nil, nil)
		return resp.StatusCode == 200 && strings.Contains(string(body), "ro-docs")
	})
	// (The policy document is visible a moment before this node's store
	// has loaded it, so the group is created once it is accepted.)
	grp, _ := json.Marshal(iam.GroupEntry{Name: "readers", Members: []string{"alice"}, Policies: []string{"ro-docs"}})
	waitUntil(t, "group creation", func() bool {
		resp, _ := a.env.do("PUT", "/_nanoio/admin/iam/group", strings.NewReader(string(grp)), nil)
		return resp.StatusCode == 204
	})
	waitUntil(t, "group a->b", func() bool {
		resp, body := b.env.do("GET", "/_nanoio/admin/iam/group", nil, nil)
		return resp.StatusCode == 200 && strings.Contains(string(body), "readers")
	})

	// Buckets and their configuration.
	a.env.mb("docs")
	waitUntil(t, "bucket a->b", func() bool {
		resp, _ := b.env.do("HEAD", "/docs", nil, nil)
		return resp.StatusCode == 200
	})
	// (The bucket appears a moment before its versioning is switched on.)
	waitUntil(t, "versioning on the replicated bucket", func() bool {
		_, body := b.env.do("GET", "/docs?versioning", nil, nil)
		return strings.Contains(string(body), "Enabled")
	})
	pol := fmt.Sprintf(polOpen, "docs")
	if resp, body := a.env.do("PUT", "/docs?policy", strings.NewReader(pol), nil); resp.StatusCode != 204 {
		t.Fatalf("put policy: %d %s", resp.StatusCode, body)
	}
	lc := lcXML(`<Rule><ID>old</ID><Status>Enabled</Status><Filter><Prefix>tmp/</Prefix></Filter><Expiration><Days>30</Days></Expiration></Rule>`)
	if resp, body := a.env.do("PUT", "/docs?lifecycle", strings.NewReader(lc), nil); resp.StatusCode != 200 {
		t.Fatalf("put lifecycle: %d %s", resp.StatusCode, body)
	}
	waitUntil(t, "policy and lifecycle a->b", func() bool {
		r, body := b.env.do("GET", "/docs?lifecycle", nil, nil)
		return strings.Contains(b.bucketPolicy("docs"), "GetObject") && r.StatusCode == 200 && strings.Contains(string(body), "<ID>old</ID>")
	})

	// The user created on a authenticates on b, with the group's policy.
	b.env.put("/docs/readme", "hello", nil)
	waitUntil(t, "user and group on b", func() bool {
		return b.userCan("alice", "alice-secret-1", "GET", "/docs/readme") == 200
	})

	// Objects flow both ways through the automatic bucket replication.
	r := a.env.put("/docs/from-a.txt", "written on a", nil)
	vid := r.Header.Get("x-amz-version-id")
	waitUntil(t, "object a->b", func() bool {
		resp, _ := b.env.do("HEAD", "/docs/from-a.txt?versionId="+vid, nil, nil)
		return resp.StatusCode == 200
	})
	waitUntil(t, "readme b->a", func() bool {
		got, resp := a.env.get("/docs/readme")
		return resp.StatusCode == 200 && got == "hello"
	})
	// Deleting propagates, as a marker.
	a.env.do("DELETE", "/docs/from-a.txt", nil, nil)
	waitUntil(t, "marker a->b", func() bool {
		resp, _ := b.env.do("GET", "/docs/from-a.txt", nil, nil)
		return resp.StatusCode == 404
	})
	waitUntil(t, "histories equal", func() bool { return fmt.Sprint(a.versions("docs")) == fmt.Sprint(b.versions("docs")) })

	// Service accounts are not part of the replicated IAM.
	_, ul := a.env.do("GET", "/_nanoio/admin/iam/user", nil, nil)
	if !strings.Contains(string(ul), "alice") {
		t.Errorf("user list = %s", ul)
	}
	// Deleting an empty bucket propagates; so does removing a user.
	a.env.mb("scratch")
	waitUntil(t, "scratch on b", func() bool {
		resp, _ := b.env.do("HEAD", "/scratch", nil, nil)
		return resp.StatusCode == 200
	})
	if resp, _ := a.env.do("DELETE", "/scratch", nil, nil); resp.StatusCode != 204 {
		t.Fatalf("delete bucket = %d", resp.StatusCode)
	}
	waitUntil(t, "scratch gone from b", func() bool {
		resp, _ := b.env.do("HEAD", "/scratch", nil, nil)
		return resp.StatusCode == 404
	})
	a.env.do("DELETE", "/_nanoio/admin/iam/user?accessKey=alice", nil, nil)
	waitUntil(t, "alice gone from b", func() bool {
		return b.userCan("alice", "alice-secret-1", "GET", "/docs/readme") == 403
	})
}

func TestSiteReplicationThreeSiteMesh(t *testing.T) {
	a, b, c := newSite(t), newSite(t), newSite(t)
	a.join(b, "b", "a")
	a.join(c, "c", "a")

	c.putUser(iam.UserEntry{AccessKey: "carol", SecretKey: "carol-secret-1", Policies: []string{"readwrite"}})
	b.env.mb("meshbkt")
	for _, s := range []*testSite{a, c} {
		s := s
		waitUntil(t, "bucket everywhere", func() bool {
			resp, _ := s.env.do("HEAD", "/meshbkt", nil, nil)
			return resp.StatusCode == 200
		})
	}
	waitUntil(t, "carol everywhere", func() bool {
		return a.userCan("carol", "carol-secret-1", "GET", "/meshbkt?list-type=2") == 200 &&
			b.userCan("carol", "carol-secret-1", "GET", "/meshbkt?list-type=2") == 200
	})
	// A write on any site reaches the other two, directly (replicas are not
	// forwarded, so each pair has its own rule).
	for i, s := range []*testSite{a, b, c} {
		s.env.put(fmt.Sprintf("/meshbkt/from-%d", i), fmt.Sprintf("site %d", i), nil)
	}
	waitUntil(t, "all histories equal", func() bool {
		av := fmt.Sprint(a.versions("meshbkt"))
		return len(a.versions("meshbkt")) == 3 && av == fmt.Sprint(b.versions("meshbkt")) && av == fmt.Sprint(c.versions("meshbkt"))
	})
	// And it stays at three versions: no site re-sends what it received.
	time.Sleep(800 * time.Millisecond)
	if n := len(a.versions("meshbkt")); n != 3 {
		t.Errorf("history grew to %d", n)
	}
	// Status from any member lists the other two, online.
	resp, body := c.env.do("GET", "/_nanoio/admin/site/status", nil, nil)
	var st struct {
		Enabled bool
		Peers   []struct{ Online bool }
	}
	json.Unmarshal(body, &st)
	if resp.StatusCode != 200 || !st.Enabled || len(st.Peers) != 2 || !st.Peers[0].Online || !st.Peers[1].Online {
		t.Errorf("status = %d %s", resp.StatusCode, body)
	}
}

func TestSiteJoinRefusalsAndServiceAccountLimits(t *testing.T) {
	a, b := newSite(t), newSite(t)
	b.env.mb("already-here")
	body, _ := json.Marshal(map[string]any{
		"self": map[string]string{"name": "a", "endpoint": a.url()},
		"site": map[string]string{"name": "b", "endpoint": b.url(), "accessKey": rootAK, "secretKey": rootSK},
	})
	resp, rb := a.env.do("POST", "/_nanoio/admin/site/add", strings.NewReader(string(body)), nil)
	wantError(t, resp, rb, 400, "InvalidArgument")
	if !strings.Contains(string(rb), "empty") {
		t.Errorf("message = %s", rb)
	}
	// Wrong credentials.
	bad, _ := json.Marshal(map[string]any{
		"self": map[string]string{"endpoint": a.url()},
		"site": map[string]string{"endpoint": b.url(), "accessKey": rootAK, "secretKey": "not-the-secret"},
	})
	resp, rb = a.env.do("POST", "/_nanoio/admin/site/add", strings.NewReader(string(bad)), nil)
	wantError(t, resp, rb, 400, "InvalidArgument")
	// Only root manages membership.
	resp, rb = a.env.doAs("nobody", "POST", "/_nanoio/admin/site/add", strings.NewReader(string(body)), nil)
	wantError(t, resp, rb, 403, "AccessDenied")

	// With a valid, empty pair joined, the peer's service credential can
	// replicate but cannot administer.
	c := newSite(t)
	a.join(c, "c", "a")
	cfg := a.api.site.config(context.Background())
	if cfg == nil || len(cfg.Peers) != 1 {
		t.Fatalf("config = %+v", cfg)
	}
	p := cfg.Peers[0]
	signer := auth.Signer{AccessKey: p.AccessKey, SecretKey: p.SecretKey}
	resp, _ = c.env.send(&signer, "GET", "/_nanoio/admin/site/state", strings.NewReader(""), nil)
	if resp.StatusCode != 200 {
		t.Errorf("the service account cannot read site state: %d", resp.StatusCode)
	}
	resp, _ = c.env.send(&signer, "PUT", "/_nanoio/admin/iam/user", strings.NewReader(`{"accessKey":"evil","secretKey":"evil-secret-1"}`), nil)
	if resp.StatusCode != 403 {
		t.Errorf("the service account can manage IAM: %d", resp.StatusCode)
	}
	resp, _ = c.env.send(&signer, "PUT", "/_nanoio/admin/tier", strings.NewReader(`{}`), nil)
	if resp.StatusCode != 403 {
		t.Errorf("the service account can manage tiers: %d", resp.StatusCode)
	}
	// A site that is in a group cannot be added to another.
	d := newSite(t)
	body2, _ := json.Marshal(map[string]any{
		"self": map[string]string{"name": "d", "endpoint": d.url()},
		"site": map[string]string{"name": "c", "endpoint": c.url(), "accessKey": rootAK, "secretKey": rootSK},
	})
	resp, rb = d.env.do("POST", "/_nanoio/admin/site/add", strings.NewReader(string(body2)), nil)
	wantError(t, resp, rb, 400, "InvalidArgument")
}

// A queue that outlives a restart, and a partition that heals: nothing a
// site did while cut off is lost, and where both sides changed the same
// thing the later change wins everywhere.
func TestSiteReplicationPartitionHealAndLastWriterWins(t *testing.T) {
	a, b := newSite(t), newSite(t)
	a.join(b, "b", "a")
	a.env.mb("splitbkt")
	waitUntil(t, "bucket on b", func() bool {
		resp, _ := b.env.do("HEAD", "/splitbkt", nil, nil)
		return resp.StatusCode == 200
	})

	cut := func(down bool) { a.partition.Store(down); b.partition.Store(down) } // the link between them
	cut(true)
	// a, alone: a policy, a user, an object.
	pa := fmt.Sprintf(polOpen, "splitbkt")
	a.env.do("PUT", "/splitbkt?policy", strings.NewReader(pa), nil)
	a.putUser(iam.UserEntry{AccessKey: "dave", SecretKey: "dave-secret-1", Policies: []string{"readwrite"}})
	a.env.put("/splitbkt/while-split", "from a", nil)
	time.Sleep(50 * time.Millisecond)
	// b, alone, later: a different policy on the same bucket.
	pb := fmt.Sprintf(polClosed, "splitbkt")
	b.env.do("PUT", "/splitbkt?policy", strings.NewReader(pb), nil)
	b.env.put("/splitbkt/b-only", "from b", nil)

	// a restarts while the partition lasts: its queue is on disk.
	a.stop()
	a.start()
	time.Sleep(300 * time.Millisecond)
	if b.userCan("dave", "dave-secret-1", "GET", "/splitbkt?list-type=2") == 200 {
		t.Fatal("a change crossed the partition")
	}

	cut(false) // heal
	waitUntil(t, "convergence", func() bool {
		return strings.Contains(a.bucketPolicy("splitbkt"), "DeleteObject") &&
			strings.Contains(b.bucketPolicy("splitbkt"), "DeleteObject") &&
			b.userCan("dave", "dave-secret-1", "GET", "/splitbkt?list-type=2") == 200 &&
			fmt.Sprint(a.versions("splitbkt")) == fmt.Sprint(b.versions("splitbkt")) && len(a.versions("splitbkt")) == 2
	})
	// The later write (b's policy) won on both; the lost one is on record.
	if strings.Contains(a.bucketPolicy("splitbkt"), "GetObject") {
		t.Error("a's older policy survived the merge")
	}
	resp, body := a.env.do("GET", "/_nanoio/admin/site/status", nil, nil)
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"conflicts"`) || !strings.Contains(string(body), "splitbkt/policy") {
		t.Errorf("status does not record the resolved conflict:\n%s", body)
	}

	// An operator can declare one site right: a's view is stamped now and
	// overwrites b's.
	if resp, body := a.env.do("PUT", "/splitbkt?policy", strings.NewReader(pa), nil); resp.StatusCode != 204 {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	waitUntil(t, "a's newer policy everywhere", func() bool { return strings.Contains(b.bucketPolicy("splitbkt"), "GetObject") })
	cut(true)
	b.env.do("PUT", "/splitbkt?policy", strings.NewReader(pb), nil) // b diverges again, but later than a's last
	time.Sleep(20 * time.Millisecond)
	resp, body = a.env.do("POST", "/_nanoio/admin/site/resync?authoritative=true", nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("authoritative resync: %d %s", resp.StatusCode, body)
	}
	cut(false)
	waitUntil(t, "authoritative state wins", func() bool {
		return strings.Contains(b.bucketPolicy("splitbkt"), "GetObject") && !strings.Contains(b.bucketPolicy("splitbkt"), "DeleteObject")
	})
}
