package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"nanoio/internal/auth"
	"nanoio/internal/madmincrypt"
)

func (e *testEnv) madminAs(user, method, op string, query url.Values, plain []byte) (*http.Response, []byte) {
	e.t.Helper()
	var body *bytes.Reader
	if plain != nil {
		enc, _ := madmincrypt.Encrypt(secretOf(user), plain)
		body = bytes.NewReader(enc)
	} else {
		body = bytes.NewReader(nil)
	}
	path := "/minio/admin/v3/" + op
	if len(query) > 0 {
		path += "?" + query.Encode()
	}
	s := signerFor(user)
	return e.send(&s, method, path, body, nil)
}

func secretOf(user string) string {
	if user == rootAK {
		return rootSK
	}
	return signerFor(user).SecretKey
}

func TestMadminAuthGate(t *testing.T) {
	e := fedServe(t)
	// No credentials at all: refused, with an error body, not served.
	resp, b := e.doAnon("GET", "/minio/admin/v3/info", nil, nil)
	if resp.StatusCode != 403 || !strings.Contains(string(b), "XMinioAdminAccessDenied") {
		t.Errorf("anonymous admin call: %d %s", resp.StatusCode, b)
	}
	// A signed call by a user with no admin policy is refused.
	for _, u := range []string{"reader", "writer", "nobody"} {
		if resp, b := e.madminAs(u, "GET", "info", nil, nil); resp.StatusCode != 403 {
			t.Errorf("%s: info = %d %s", u, resp.StatusCode, b)
		}
		if resp, b := e.madminAs(u, "PUT", "add-user", url.Values{"accessKey": {"x"}}, []byte(`{"secretKey":"xxxxxxxx-xx"}`)); resp.StatusCode != 403 {
			t.Errorf("%s: add-user = %d %s", u, resp.StatusCode, b)
		}
	}
	// A disabled user and a wrong signature fail authentication.
	if resp, _ := e.madminAs("retired", "GET", "info", nil, nil); resp.StatusCode != 403 {
		t.Errorf("disabled user: %d", resp.StatusCode)
	}
	bad := auth.Signer{AccessKey: rootAK, SecretKey: "not-the-secret-key"}
	if resp, _ := e.send(&bad, "GET", "/minio/admin/v3/info", nil, nil); resp.StatusCode != 403 {
		t.Errorf("wrong secret: %d", resp.StatusCode)
	}
	// Root works; so does a user whose policy grants exactly one admin action.
	if resp, b := e.madminAs(rootAK, "GET", "info", nil, nil); resp.StatusCode != 200 {
		t.Fatalf("root info: %d %s", resp.StatusCode, b)
	}
	pol := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["admin:ServerInfo"]}]}`
	if resp, b := e.madminDo("PUT", "add-canned-policy", url.Values{"name": {"info-only"}}, nil); resp.StatusCode != 400 {
		t.Logf("empty policy body: %d %s", resp.StatusCode, b)
	}
	e.rawPut("add-canned-policy", url.Values{"name": {"info-only"}}, pol)
	if resp, b := e.madminDo("PUT", "add-user", url.Values{"accessKey": {"monitor"}}, []byte(`{"secretKey":"monitor-secret-1","policy":"info-only"}`)); resp.StatusCode != 200 {
		t.Fatalf("add-user: %d %s", resp.StatusCode, b)
	}
	sig := auth.Signer{AccessKey: "monitor", SecretKey: "monitor-secret-1"}
	if resp, b := e.send(&sig, "GET", "/minio/admin/v3/info", nil, nil); resp.StatusCode != 200 {
		t.Errorf("monitor info: %d %s", resp.StatusCode, b)
	}
	if resp, b := e.send(&sig, "GET", "/minio/admin/v3/list-users", nil, nil); resp.StatusCode != 403 {
		t.Errorf("monitor list-users: %d %s", resp.StatusCode, b)
	}
	// Unknown operations are 404, not an accidental success.
	if resp, _ := e.madminAs(rootAK, "GET", "no-such-op", nil, nil); resp.StatusCode != 404 {
		t.Errorf("unknown op: %d", resp.StatusCode)
	}
	// Health endpoints are open (probes carry no credentials).
	if resp, _ := e.doAnon("GET", "/minio/health/live", nil, nil); resp.StatusCode != 200 {
		t.Errorf("health/live: %d", resp.StatusCode)
	}
}

func (e *testEnv) rawPut(op string, q url.Values, body string) {
	e.t.Helper()
	path := "/minio/admin/v3/" + op + "?" + q.Encode()
	resp, b := e.do("PUT", path, strings.NewReader(body), nil)
	if resp.StatusCode != 200 {
		e.t.Fatalf("PUT %s: %d %s", op, resp.StatusCode, b)
	}
}

func TestMadminRejectsTamperedEnvelope(t *testing.T) {
	e := fedServe(t)
	enc, _ := madmincrypt.Encrypt(rootSK, []byte(`{"secretKey":"tamper-secret-1"}`))
	enc[len(enc)-1] ^= 0xff
	resp, b := e.do("PUT", "/minio/admin/v3/add-user?accessKey=tam", bytes.NewReader(enc), nil)
	if resp.StatusCode != 400 {
		t.Errorf("tampered body: %d %s", resp.StatusCode, b)
	}
	// Encrypted under another secret: also refused.
	enc, _ = madmincrypt.Encrypt("some-other-secret-key", []byte(`{"secretKey":"tamper-secret-1"}`))
	resp, b = e.do("PUT", "/minio/admin/v3/add-user?accessKey=tam", bytes.NewReader(enc), nil)
	if resp.StatusCode != 400 {
		t.Errorf("wrong key: %d %s", resp.StatusCode, b)
	}
	if _, ok := e.iamUser("tam"); ok {
		t.Error("a tampered request created a user")
	}
}

func (e *testEnv) iamUser(ak string) (json.RawMessage, bool) {
	e.t.Helper()
	resp, b := e.madminDo("GET", "user-info", url.Values{"accessKey": {ak}}, nil)
	return b, resp.StatusCode == 200
}

func TestMadminConfigKV(t *testing.T) {
	e := fedServe(t)
	put := func(line string) (*http.Response, []byte) {
		return e.madminDo("PUT", "set-config-kv", nil, []byte(line))
	}
	if resp, b := put("region name=x"); resp.StatusCode != 400 {
		t.Errorf("unsupported sub-system accepted: %d %s", resp.StatusCode, b)
	}
	if resp, b := put("identity_ldap bogus_key=1"); resp.StatusCode != 400 {
		t.Errorf("unknown key accepted: %d %s", resp.StatusCode, b)
	}
	if resp, b := put("identity_ldap server_addr=127.0.0.1:389"); resp.StatusCode != 400 {
		t.Errorf("incomplete ldap config accepted: %d %s", resp.StatusCode, b)
	}
	if resp, b := put("identity_openid config_url=http://idp.example.com/.well-known/openid-configuration client_id=x"); resp.StatusCode != 400 {
		t.Errorf("plain-http remote issuer accepted: %d %s", resp.StatusCode, b)
	}
	ok := "identity_openid config_url=https://idp.example.com/.well-known/openid-configuration client_id=cid client_secret=sekret claim_name=groups"
	if resp, b := put(ok); resp.StatusCode != 200 {
		t.Fatalf("valid config: %d %s", resp.StatusCode, b)
	}
	// History records the change and a restore brings the old state back.
	resp, enc := e.madminDo("GET", "list-config-history-kv", url.Values{"count": {"5"}}, nil)
	plain, err := madmincrypt.Decrypt(rootSK, bytes.NewReader(enc))
	var hist []struct{ RestoreID string }
	if resp.StatusCode != 200 || err != nil || json.Unmarshal(plain, &hist) != nil || len(hist) == 0 {
		t.Fatalf("history: %d %v %s", resp.StatusCode, err, plain)
	}
	if resp, b := e.madminDo("PUT", "restore-config-history-kv", url.Values{"restoreId": {hist[0].RestoreID}}, nil); resp.StatusCode != 200 {
		t.Fatalf("restore: %d %s", resp.StatusCode, b)
	}
	resp, enc = e.madminDo("GET", "get-config-kv", url.Values{"key": {"identity_openid"}}, nil)
	plain, _ = madmincrypt.Decrypt(rootSK, bytes.NewReader(enc))
	if strings.Contains(string(plain), "client_id") {
		t.Errorf("restore did not bring back the previous state: %s", plain)
	}
}

func TestMadminExportImportIAM(t *testing.T) {
	a := fedServe(t)
	for _, kv := range [][2]string{{"add-user", `{"secretKey":"export-secret-1"}`}} {
		if resp, b := a.madminDo("PUT", kv[0], url.Values{"accessKey": {"exported"}}, []byte(kv[1])); resp.StatusCode != 200 {
			t.Fatalf("%s: %d %s", kv[0], resp.StatusCode, b)
		}
	}
	a.rawPut("add-canned-policy", url.Values{"name": {"exp-pol"}},
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::*"}]}`)
	resp, zipb := a.do("GET", "/minio/admin/v3/export-iam", nil, nil)
	if resp.StatusCode != 200 || len(zipb) == 0 {
		t.Fatalf("export: %d", resp.StatusCode)
	}
	b := fedServe(t)
	resp, out := b.do("PUT", "/minio/admin/v3/import-iam-v2", bytes.NewReader(zipb), nil)
	if resp.StatusCode != 200 {
		t.Fatalf("import: %d %s", resp.StatusCode, out)
	}
	if _, ok := b.iamUser("exported"); !ok {
		t.Errorf("the user did not arrive: %s", out)
	}
	if resp, _ := b.do("PUT", "/minio/admin/v3/import-iam", strings.NewReader("not a zip"), nil); resp.StatusCode != 400 {
		t.Errorf("non-zip import: %d", resp.StatusCode)
	}
}

func TestSTSCredentialExpires(t *testing.T) {
	e := fedServe(t)
	e.mb("expbkt")
	e.put("/expbkt/o", "x", nil)
	resp, b := e.sts(&auth.Signer{AccessKey: "reader", SecretKey: signerFor("reader").SecretKey, Service: "sts"},
		url.Values{"Action": {"AssumeRole"}, "DurationSeconds": {"900"}})
	if resp.StatusCode != 200 {
		t.Fatalf("assume: %d %s", resp.StatusCode, b)
	}
	c := parseCreds(t, b)
	if st := e.asTemp(c, true, "GET", "/expbkt/o", ""); st != 200 {
		t.Fatalf("fresh: %d", st)
	}
	// Expire the stored document (the store clock is wall time, so move
	// the expiry into the past and let the cache entry lapse).
	srv := &Server{st: e.st}
	d, err := srv.stsGet(context.Background(), c.AccessKeyID)
	if err != nil || d == nil {
		t.Fatalf("stored credential: %v %v", d, err)
	}
	d.Entry.Expiry = time.Now().Add(-time.Minute)
	if err := srv.stsPut(context.Background(), d.Entry); err != nil {
		t.Fatal(err)
	}
	e.iam.Forget(c.AccessKeyID)
	if st := e.asTemp(c, true, "GET", "/expbkt/o", ""); st != 403 {
		t.Errorf("expired credential: %d", st)
	}
}
