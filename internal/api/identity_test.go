package api

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"nanoio/internal/auth"
	"nanoio/internal/bucket/nslock"
	"nanoio/internal/madmincrypt"
	"nanoio/internal/storage/fs"
)

// fedServe is a server with federation enabled: session tokens accepted and
// the STS endpoint verified for service "sts".
func fedServe(t *testing.T) *testEnv {
	t.Helper()
	be, err := fs.New(t.TempDir(), fs.Options{Locker: nslock.New(5 * time.Second), Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { be.Close() })
	return serve(t, be, be, func(o *Options) {
		o.Auth = &auth.Verifier{Provider: o.IAM, Region: "us-east-1", AllowSessionToken: true}
		o.STSAuth = &auth.Verifier{Provider: o.IAM, Region: "us-east-1", Service: "sts", AllowSessionToken: true}
	})
}

// madminDo sends an admin API request signed by the root user; plain, when
// not nil, is sent in the madmin encryption envelope.
func (e *testEnv) madminDo(method, op string, query url.Values, plain []byte) (*http.Response, []byte) {
	e.t.Helper()
	var body io.Reader
	if plain != nil {
		enc, err := madmincrypt.Encrypt(rootSK, plain)
		if err != nil {
			e.t.Fatal(err)
		}
		body = bytes.NewReader(enc)
	}
	path := "/minio/admin/v3/" + op
	if len(query) > 0 {
		path += "?" + query.Encode()
	}
	return e.do(method, path, body, nil)
}

func (e *testEnv) setConfig(line string) {
	e.t.Helper()
	resp, b := e.madminDo("PUT", "set-config-kv", nil, []byte(line))
	if resp.StatusCode != 200 {
		e.t.Fatalf("set-config-kv %q: %d %s", line, resp.StatusCode, b)
	}
}

// sts posts a form to the STS endpoint, signed when signer != nil.
func (e *testEnv) sts(signer *auth.Signer, form url.Values) (*http.Response, []byte) {
	e.t.Helper()
	body := form.Encode()
	req, _ := http.NewRequest("POST", e.srv.URL+"/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if signer != nil {
		signer.Sign(req, sha256hex(body), time.Now())
	}
	return e.exec(req)
}

type stsCredsOut struct {
	AccessKeyID     string `xml:"AccessKeyId"`
	SecretAccessKey string `xml:"SecretAccessKey"`
	SessionToken    string `xml:"SessionToken"`
	Expiration      string `xml:"Expiration"`
}

func parseCreds(t *testing.T, b []byte) stsCredsOut {
	t.Helper()
	var r struct {
		Creds stsCredsOut `xml:"Credentials"`
	}
	// Any of the three result wrappers.
	var raw struct {
		Inner struct {
			Creds stsCredsOut `xml:"Credentials"`
		} `xml:",any"`
	}
	if err := xml.Unmarshal(b, &raw); err != nil {
		t.Fatalf("parse %s: %v", b, err)
	}
	r.Creds = raw.Inner.Creds
	if r.Creds.AccessKeyID == "" {
		t.Fatalf("no credentials in %s", b)
	}
	return r.Creds
}

// asTemp signs a request with temporary credentials (token optional).
func (e *testEnv) asTemp(c stsCredsOut, token bool, method, path, body string) int {
	e.t.Helper()
	h := hdr{}
	if token {
		h["X-Amz-Security-Token"] = c.SessionToken
	}
	s := auth.Signer{AccessKey: c.AccessKeyID, SecretKey: c.SecretAccessKey}
	resp, _ := e.send(&s, method, path, strings.NewReader(body), h)
	return resp.StatusCode
}

// ---- a mock OpenID provider -------------------------------------------------------------------

type mockIDP struct {
	srv  *httptest.Server
	mu   sync.Mutex
	keys map[string]*rsa.PrivateKey
}

func newMockIDP(t *testing.T) *mockIDP {
	m := &mockIDP{keys: map[string]*rsa.PrivateKey{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"issuer": m.srv.URL, "jwks_uri": m.srv.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()
		var ks []map[string]string
		for kid, k := range m.keys {
			ks = append(ks, map[string]string{"kty": "RSA", "kid": kid, "use": "sig",
				"n": base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes())})
		}
		json.NewEncoder(w).Encode(map[string]any{"keys": ks})
	})
	m.srv = httptest.NewServer(mux)
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mockIDP) setKey(kid string) {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	m.mu.Lock()
	m.keys = map[string]*rsa.PrivateKey{kid: k} // rotation replaces the set
	m.mu.Unlock()
}

func (m *mockIDP) token(t *testing.T, kid string, claims map[string]any) string {
	m.mu.Lock()
	k := m.keys[kid]
	m.mu.Unlock()
	if k == nil {
		t.Fatalf("no key %s", kid)
	}
	seg := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	signed := seg(map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid}) + "." + seg(claims)
	sum := sha256.Sum256([]byte(signed))
	sig, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signed + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (m *mockIDP) claims(sub string, life time.Duration, extra map[string]any) map[string]any {
	c := map[string]any{"iss": m.srv.URL, "aud": "nanoio-client", "sub": sub,
		"exp": time.Now().Add(life).Unix(), "iat": time.Now().Unix()}
	for k, v := range extra {
		c[k] = v
	}
	return c
}

func TestSTSWebIdentity(t *testing.T) {
	oidcMinRefresh = 100 * time.Millisecond
	t.Cleanup(func() { oidcMinRefresh = 0 })
	idp := newMockIDP(t)
	idp.setKey("k1")
	e := fedServe(t)
	e.mb("fedbkt")
	e.put("/fedbkt/doc.txt", "document", nil)
	e.setConfig("identity_openid config_url=" + idp.srv.URL + "/.well-known/openid-configuration client_id=nanoio-client claim_name=policy")

	assume := func(tok string, extra url.Values) (*http.Response, []byte) {
		f := url.Values{"Action": {"AssumeRoleWithWebIdentity"}, "Version": {"2011-06-15"}, "WebIdentityToken": {tok}}
		for k, v := range extra {
			f[k] = v
		}
		return e.sts(nil, f)
	}

	t.Run("claim maps to a policy, session token required", func(t *testing.T) {
		resp, b := assume(idp.token(t, "k1", idp.claims("alice", time.Hour, map[string]any{"policy": "readonly"})), nil)
		if resp.StatusCode != 200 {
			t.Fatalf("assume: %d %s", resp.StatusCode, b)
		}
		c := parseCreds(t, b)
		if st := e.asTemp(c, true, "GET", "/fedbkt/doc.txt", ""); st != 200 {
			t.Errorf("read with the credential: %d", st)
		}
		if st := e.asTemp(c, true, "PUT", "/fedbkt/new.txt", "x"); st != 403 {
			t.Errorf("a readonly credential wrote: %d", st)
		}
		if st := e.asTemp(c, false, "GET", "/fedbkt/doc.txt", ""); st != 400 {
			t.Errorf("without the session token: %d, want 400 InvalidToken", st)
		}
		bad := c
		bad.SessionToken = "wrong"
		if st := e.asTemp(bad, true, "GET", "/fedbkt/doc.txt", ""); st != 400 {
			t.Errorf("wrong session token: %d", st)
		}
	})

	t.Run("a session policy narrows, never widens", func(t *testing.T) {
		deny := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::fedbkt/other/*"}]}`
		resp, b := assume(idp.token(t, "k1", idp.claims("bob", time.Hour, map[string]any{"policy": []string{"readonly"}})),
			url.Values{"Policy": {deny}})
		if resp.StatusCode != 200 {
			t.Fatalf("assume: %d %s", resp.StatusCode, b)
		}
		c := parseCreds(t, b)
		if st := e.asTemp(c, true, "GET", "/fedbkt/doc.txt", ""); st != 403 {
			t.Errorf("session policy did not narrow: %d", st)
		}
		// A session policy asking for more than the claim grants gets nothing extra.
		allow := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`
		resp, b = assume(idp.token(t, "k1", idp.claims("bob", time.Hour, map[string]any{"policy": "readonly"})), url.Values{"Policy": {allow}})
		c = parseCreds(t, b)
		if st := e.asTemp(c, true, "PUT", "/fedbkt/new.txt", "x"); st != 403 {
			t.Errorf("session policy widened the grant: %d", st)
		}
	})

	t.Run("no policy means no credentials", func(t *testing.T) {
		resp, b := assume(idp.token(t, "k1", idp.claims("carol", time.Hour, nil)), nil)
		if resp.StatusCode != 403 {
			t.Errorf("token without a policy: %d %s", resp.StatusCode, b)
		}
		resp, b = assume(idp.token(t, "k1", idp.claims("carol", time.Hour, map[string]any{"policy": "no-such-policy"})), nil)
		if resp.StatusCode != 403 {
			t.Errorf("token naming a missing policy: %d %s", resp.StatusCode, b)
		}
	})

	t.Run("expired and forged tokens are refused", func(t *testing.T) {
		resp, b := assume(idp.token(t, "k1", idp.claims("dave", -10*time.Minute, map[string]any{"policy": "readonly"})), nil)
		if resp.StatusCode != 400 || !strings.Contains(string(b), "ExpiredToken") {
			t.Errorf("expired token: %d %s", resp.StatusCode, b)
		}
		good := idp.token(t, "k1", idp.claims("dave", time.Hour, map[string]any{"policy": "readonly"}))
		parts := strings.Split(good, ".")
		forged := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"`+idp.srv.URL+
			`","aud":"nanoio-client","sub":"mallory","exp":9999999999,"policy":"consoleAdmin"}`)) + "." + parts[2]
		resp, b = assume(forged, nil)
		if resp.StatusCode != 400 {
			t.Errorf("forged payload accepted: %d %s", resp.StatusCode, b)
		}
		wrongAud := idp.token(t, "k1", idp.claims("dave", time.Hour, map[string]any{"policy": "readonly", "aud": "someone-else"}))
		if resp, b = assume(wrongAud, nil); resp.StatusCode != 400 {
			t.Errorf("wrong audience accepted: %d %s", resp.StatusCode, b)
		}
	})

	t.Run("credential lifetime never exceeds the token", func(t *testing.T) {
		resp, b := assume(idp.token(t, "k1", idp.claims("erin", 40*time.Second, map[string]any{"policy": "readonly"})),
			url.Values{"DurationSeconds": {"3600"}})
		// 3600s exceeds the token's remaining time; STS clamps rather than fail.
		if resp.StatusCode != 200 {
			t.Fatalf("assume: %d %s", resp.StatusCode, b)
		}
		c := parseCreds(t, b)
		exp, err := time.Parse(time.RFC3339, c.Expiration)
		if err != nil || exp.After(time.Now().Add(45*time.Second)) {
			t.Errorf("expiration %s outlives the 40s token", c.Expiration)
		}
	})

	t.Run("signing key rotation", func(t *testing.T) {
		// Prime the key cache with k1, then rotate to k2.
		if resp, b := assume(idp.token(t, "k1", idp.claims("fay", time.Hour, map[string]any{"policy": "readonly"})), nil); resp.StatusCode != 200 {
			t.Fatalf("before rotation: %d %s", resp.StatusCode, b)
		}
		old := idp.token(t, "k1", idp.claims("fay", time.Hour, map[string]any{"policy": "readonly"}))
		idp.setKey("k2")
		time.Sleep(200 * time.Millisecond) // past the refresh floor
		if resp, b := assume(idp.token(t, "k2", idp.claims("fay", time.Hour, map[string]any{"policy": "readonly"})), nil); resp.StatusCode != 200 {
			t.Fatalf("token signed with the rotated key: %d %s", resp.StatusCode, b)
		}
		// A token from the withdrawn key (valid signature, unknown now) is refused.
		if resp, b := assume(old, nil); resp.StatusCode != 400 {
			t.Errorf("token from a withdrawn key accepted: %d %s", resp.StatusCode, b)
		}
	})

	t.Run("deleting the credential revokes it", func(t *testing.T) {
		resp, b := assume(idp.token(t, "k2", idp.claims("gus", time.Hour, map[string]any{"policy": "readonly"})), nil)
		c := parseCreds(t, b)
		if st := e.asTemp(c, true, "GET", "/fedbkt/doc.txt", ""); st != 200 {
			t.Fatalf("fresh credential: %d", st)
		}
		resp, b = e.madminDo("DELETE", "delete-service-account", url.Values{"accessKey": {c.AccessKeyID}}, nil)
		if resp.StatusCode != 204 {
			t.Fatalf("revoke: %d %s", resp.StatusCode, b)
		}
		// The deleting node forgets it at once.
		if st := e.asTemp(c, true, "GET", "/fedbkt/doc.txt", ""); st != 403 {
			t.Errorf("revoked credential still works: %d", st)
		}
	})
}

func TestSTSAssumeRoleAndCallerIdentity(t *testing.T) {
	e := fedServe(t)
	e.mb("rolebkt")
	e.put("/rolebkt/doc.txt", "d", nil)
	root := auth.Signer{AccessKey: rootAK, SecretKey: rootSK, Service: "sts"}
	reader := signerFor("reader")
	reader.Service = "sts"

	resp, b := e.sts(&reader, url.Values{"Action": {"GetCallerIdentity"}, "Version": {"2011-06-15"}})
	if resp.StatusCode != 200 || !strings.Contains(string(b), "reader") {
		t.Fatalf("GetCallerIdentity: %d %s", resp.StatusCode, b)
	}
	if resp, b = e.sts(nil, url.Values{"Action": {"GetCallerIdentity"}}); resp.StatusCode != 403 {
		t.Errorf("unsigned GetCallerIdentity: %d %s", resp.StatusCode, b)
	}
	// reader (a readonly user in the test IAM file) assumes a role: same rights.
	resp, b = e.sts(&reader, url.Values{"Action": {"AssumeRole"}, "Version": {"2011-06-15"}, "DurationSeconds": {"900"}})
	if resp.StatusCode != 200 {
		t.Fatalf("AssumeRole: %d %s", resp.StatusCode, b)
	}
	c := parseCreds(t, b)
	if st := e.asTemp(c, true, "GET", "/rolebkt/doc.txt", ""); st != 200 {
		t.Errorf("assumed credential read: %d", st)
	}
	if st := e.asTemp(c, true, "PUT", "/rolebkt/x.txt", "x"); st != 403 {
		t.Errorf("assumed credential exceeded its parent: %d", st)
	}
	// Chaining is refused.
	tmp := auth.Signer{AccessKey: c.AccessKeyID, SecretKey: c.SecretAccessKey, Service: "sts"}
	req, _ := http.NewRequest("POST", e.srv.URL+"/", strings.NewReader("Action=AssumeRole&Version=2011-06-15"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Amz-Security-Token", c.SessionToken)
	tmp.Sign(req, sha256hex("Action=AssumeRole&Version=2011-06-15"), time.Now())
	if resp, b := e.exec(req); resp.StatusCode != 403 {
		t.Errorf("a temporary credential assumed a role: %d %s", resp.StatusCode, b)
	}
	// Bad durations.
	if resp, b = e.sts(&root, url.Values{"Action": {"AssumeRole"}, "DurationSeconds": {"10"}}); resp.StatusCode != 400 {
		t.Errorf("duration 10s: %d %s", resp.StatusCode, b)
	}
	if resp, b = e.sts(&root, url.Values{"Action": {"Nope"}}); resp.StatusCode != 400 {
		t.Errorf("unknown action: %d %s", resp.StatusCode, b)
	}
}

func TestLoginLimiter(t *testing.T) {
	var l loginLimiter
	for i := 0; i < loginMaxFails; i++ {
		if !l.allow("Mallory") {
			t.Fatalf("refused after %d failures", i)
		}
		l.fail("Mallory")
	}
	if l.allow("mallory") {
		t.Error("not throttled (and the name is case-insensitive)")
	}
	if !l.allow("alice") {
		t.Error("another name was throttled")
	}
	l.reset("mallory")
	if !l.allow("mallory") {
		t.Error("a successful sign-in did not clear the counter")
	}
}
