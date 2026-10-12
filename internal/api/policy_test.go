package api

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"nanoio/internal/auth"
)

// polBucketPolicy is the bucket policy the authorization matrix runs under.
const polBucketPolicy = `{"Version":"2012-10-17","Statement":[
 {"Sid":"public-read-pub","Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::polbkt/pub/*"},
 {"Sid":"writer-uploads","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::nanoio:user/writer"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::polbkt/up/*"},
 {"Sid":"list-pub","Effect":"Allow","Principal":"*","Action":"s3:ListBucket","Resource":"arn:aws:s3:::polbkt","Condition":{"StringLike":{"s3:prefix":"pub/*"}}},
 {"Sid":"nobody-trusted-agent","Effect":"Allow","Principal":{"AWS":["nobody"]},"Action":"s3:GetObject","Resource":"arn:aws:s3:::polbkt/priv/*","Condition":{"StringLike":{"aws:UserAgent":"trusted-*"}}},
 {"Sid":"referer-ref","Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::polbkt/ref/*","Condition":{"StringLike":{"aws:Referer":"https://example.com/*"}}},
 {"Sid":"tls-only-allow","Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::polbkt/tlsonly/*"},
 {"Sid":"tls-only-deny","Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::polbkt/tlsonly/*","Condition":{"Bool":{"aws:SecureTransport":"false"}}},
 {"Sid":"no-deletes","Effect":"Deny","Principal":"*","Action":"s3:DeleteObject","Resource":"arn:aws:s3:::polbkt/*"},
 {"Sid":"secret-from-outside","Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::polbkt/pub/secret*","Condition":{"NotIpAddress":{"aws:SourceIp":"10.0.0.0/8"}}},
 {"Sid":"allow-loopback-list-all","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::nanoio:user/scoped"},"Action":"s3:ListBucket","Resource":"arn:aws:s3:::polbkt","Condition":{"IpAddress":{"aws:SourceIp":"127.0.0.0/8"}}}
]}`

func polEnv(t *testing.T) *testEnv {
	t.Helper()
	e := newEnv(t)
	e.mb("polbkt")
	for _, k := range []string{"pub/a.txt", "pub/del.txt", "pub/secret1", "priv/b.txt", "ref/r.txt", "tlsonly/t.txt"} {
		e.put("/polbkt/"+k, "body of "+k, nil)
	}
	if r, b := e.do("PUT", "/polbkt?policy", strings.NewReader(polBucketPolicy), nil); r.StatusCode != 204 {
		t.Fatalf("PUT ?policy: %d %s", r.StatusCode, b)
	}
	return e
}

func TestBucketPolicyAuthorizationMatrix(t *testing.T) {
	e := polEnv(t)
	type tc struct {
		name      string
		principal string // "" anonymous, else a test user
		method    string
		path      string
		hdr       hdr
		body      string
		want      int
	}
	cases := []tc{
		// Anonymous: only what the bucket policy allows.
		{"anon GET pub object", "", "GET", "/polbkt/pub/a.txt", nil, "", 200},
		{"anon HEAD pub object", "", "HEAD", "/polbkt/pub/a.txt", nil, "", 200},
		{"anon GET priv object", "", "GET", "/polbkt/priv/b.txt", nil, "", 403},
		{"anon GET pub secret (deny from outside 10/8)", "", "GET", "/polbkt/pub/secret1", nil, "", 403},
		{"anon PUT into up/", "", "PUT", "/polbkt/up/x", nil, "x", 403},
		{"anon DELETE pub object", "", "DELETE", "/polbkt/pub/a.txt", nil, "", 403},
		{"anon list prefix pub/", "", "GET", "/polbkt?list-type=2&prefix=pub/", nil, "", 200},
		{"anon list prefix priv/", "", "GET", "/polbkt?list-type=2&prefix=priv/", nil, "", 403},
		{"anon list without prefix", "", "GET", "/polbkt?list-type=2", nil, "", 403},
		{"anon GET ref without Referer", "", "GET", "/polbkt/ref/r.txt", nil, "", 403},
		{"anon GET ref with allowed Referer", "", "GET", "/polbkt/ref/r.txt", hdr{"Referer": "https://example.com/page"}, "", 200},
		{"anon GET ref with other Referer", "", "GET", "/polbkt/ref/r.txt", hdr{"Referer": "https://evil.test/"}, "", 403},
		{"anon GET tls-only over http (Bool deny)", "", "GET", "/polbkt/tlsonly/t.txt", nil, "", 403},
		{"anon service listing", "", "GET", "/", nil, "", 403},
		{"anon GET missing bucket", "", "GET", "/ghostbucket/x", nil, "", 403},
		{"anon read the policy", "", "GET", "/polbkt?policy", nil, "", 403},
		// Identity policy unioned with the bucket policy.
		{"reader GET priv via identity", "reader", "GET", "/polbkt/priv/b.txt", nil, "", 200},
		{"reader GET pub secret: policy Deny beats identity Allow", "reader", "GET", "/polbkt/pub/secret1", nil, "", 403},
		{"reader GET tls-only over http: Deny", "reader", "GET", "/polbkt/tlsonly/t.txt", nil, "", 403},
		{"reader DELETE: nothing allows it", "reader", "DELETE", "/polbkt/pub/a.txt", nil, "", 403},
		{"writer PUT up/ by bucket policy and identity", "writer", "PUT", "/polbkt/up/x", nil, "x", 200},
		{"writer PUT elsewhere by identity", "writer", "PUT", "/polbkt/other/x", nil, "x", 200},
		{"writer GET pub by Principal *", "writer", "GET", "/polbkt/pub/a.txt", nil, "", 200},
		{"writer DELETE: bucket policy Deny", "writer", "DELETE", "/polbkt/up/x", nil, "", 403},
		{"nobody GET priv with trusted UA", "nobody", "GET", "/polbkt/priv/b.txt", hdr{"User-Agent": "trusted-agent/1.0"}, "", 200},
		{"nobody GET priv with other UA", "nobody", "GET", "/polbkt/priv/b.txt", hdr{"User-Agent": "evil/1.0"}, "", 403},
		{"nobody GET pub by Principal *", "nobody", "GET", "/polbkt/pub/a.txt", nil, "", 200},
		{"nobody PUT up/", "nobody", "PUT", "/polbkt/up/z", nil, "x", 403},
		{"nobody put the policy", "nobody", "PUT", "/polbkt?policy", nil, polBucketPolicy, 403},
		{"scoped list all (IpAddress condition)", "scoped", "GET", "/polbkt?list-type=2", nil, "", 200},
		{"scoped GET pub by Principal *", "scoped", "GET", "/polbkt/pub/a.txt", nil, "", 200},
		{"uploader (other bucket only) GET priv", "uploader", "GET", "/polbkt/priv/b.txt", nil, "", 403},
		// Root is subject to neither policy.
		{"root GET pub secret", "root", "GET", "/polbkt/pub/secret1", nil, "", 200},
		{"root GET tls-only over http", "root", "GET", "/polbkt/tlsonly/t.txt", nil, "", 200},
		{"root DELETE despite the Deny", "root", "DELETE", "/polbkt/pub/del.txt", nil, "", 204},
		// Credentials that fail are never downgraded to anonymous.
		{"disabled user does not fall back to Principal *", "retired", "GET", "/polbkt/pub/a.txt", nil, "", 403},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var body *strings.Reader
			if c.body != "" {
				body = strings.NewReader(c.body)
			} else {
				body = strings.NewReader("")
			}
			var resp *http.Response
			var b []byte
			switch c.principal {
			case "":
				resp, b = e.doAnon(c.method, c.path, body, c.hdr)
			case "root":
				resp, b = e.do(c.method, c.path, body, c.hdr)
			default:
				resp, b = e.doAs(c.principal, c.method, c.path, body, c.hdr)
			}
			if resp.StatusCode != c.want {
				t.Errorf("status = %d, want %d (%s)", resp.StatusCode, c.want, strings.TrimSpace(string(b)))
			}
			if c.want == 403 && c.method == "GET" && strings.Contains(string(b), "body of") {
				t.Error("a refused request leaked object data")
			}
		})
	}

	t.Run("wrong secret is not anonymous", func(t *testing.T) {
		req, _ := http.NewRequest("GET", e.srv.URL+"/polbkt/pub/a.txt", nil)
		auth.Signer{AccessKey: rootAK, SecretKey: "wrong-secret-key"}.Sign(req, sha256hex(""), time.Now())
		resp, _ := e.exec(req)
		if resp.StatusCode != 403 {
			t.Errorf("status = %d, want 403", resp.StatusCode)
		}
	})
	t.Run("anonymous write succeeds once a policy allows it", func(t *testing.T) {
		pol := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":["s3:PutObject","s3:GetObject"],"Resource":"arn:aws:s3:::polbkt/drop/*"}]}`
		if r, b := e.do("PUT", "/polbkt?policy", strings.NewReader(pol), nil); r.StatusCode != 204 {
			t.Fatalf("%d %s", r.StatusCode, b)
		}
		if r, b := e.doAnon("PUT", "/polbkt/drop/f", strings.NewReader("dropped"), nil); r.StatusCode != 200 {
			t.Fatalf("anonymous PUT: %d %s", r.StatusCode, b)
		}
		r, b := e.doAnon("GET", "/polbkt/drop/f", nil, nil)
		if r.StatusCode != 200 || string(b) != "dropped" {
			t.Errorf("anonymous GET: %d %q", r.StatusCode, b)
		}
		// Replacing the policy takes effect immediately on this node.
		if r, _ := e.doAnon("GET", "/polbkt/pub/a.txt", nil, nil); r.StatusCode != 403 {
			t.Errorf("old grant still applies: %d", r.StatusCode)
		}
		// Deleting it returns the bucket to private.
		if r, _ := e.do("DELETE", "/polbkt?policy", nil, nil); r.StatusCode != 204 {
			t.Errorf("DELETE ?policy = %d", r.StatusCode)
		}
		if r, _ := e.doAnon("GET", "/polbkt/drop/f", nil, nil); r.StatusCode != 403 {
			t.Errorf("anonymous GET after DELETE ?policy = %d", r.StatusCode)
		}
	})
}

func TestBucketPolicyCRUDAndValidation(t *testing.T) {
	e := newEnv(t)
	e.mb("polcrud")
	r, b := e.do("GET", "/polcrud?policy", nil, nil)
	wantError(t, r, b, 404, "NoSuchBucketPolicy")
	ok := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::polcrud/*"}]}`
	if r, b := e.do("PUT", "/polcrud?policy", strings.NewReader(ok), nil); r.StatusCode != 204 {
		t.Fatalf("%d %s", r.StatusCode, b)
	}
	gr, gb := e.do("GET", "/polcrud?policy", nil, nil)
	if gr.StatusCode != 200 || string(gb) != ok || gr.Header.Get("Content-Type") != "application/json" {
		t.Errorf("GET ?policy: %d %q %q", gr.StatusCode, gb, gr.Header.Get("Content-Type"))
	}
	bad := map[string]string{
		"not json":              `nope`,
		"no version":            `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::polcrud/*"}]}`,
		"no principal":          `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::polcrud/*"}]}`,
		"both principals":       `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","NotPrincipal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::polcrud/*"}]}`,
		"other bucket":          `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::someoneelse/*"}]}`,
		"resource star":         `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*"}]}`,
		"prefix of the bucket":  `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::polcrud-other/*"}]}`,
		"foreign account":       `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::polcrud/*"}]}`,
		"service principal":     `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"x.amazonaws.com"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::polcrud/*"}]}`,
		"non-s3 action":         `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"ec2:*","Resource":"arn:aws:s3:::polcrud/*"}]}`,
		"unknown operator":      `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"arn:aws:s3:::polcrud/*","Condition":{"DateGreaterThan":{"aws:CurrentTime":"2030-01-01T00:00:00Z"}}}]}`,
		"bad effect":            `{"Version":"2012-10-17","Statement":[{"Effect":"Maybe","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::polcrud/*"}]}`,
		"bad cidr":              `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::polcrud/*","Condition":{"IpAddress":{"aws:SourceIp":"not-an-ip"}}}]}`,
		"too large":             `{"Version":"2012-10-17","Id":"` + strings.Repeat("x", 21<<10) + `","Statement":[]}`,
		"empty statement array": `{"Version":"2012-10-17","Statement":[]}`,
	}
	for name, doc := range bad {
		t.Run(name, func(t *testing.T) {
			r, b := e.do("PUT", "/polcrud?policy", strings.NewReader(doc), nil)
			if r.StatusCode != 400 {
				t.Fatalf("status %d: %s", r.StatusCode, b)
			}
			if !strings.Contains(string(b), "MalformedPolicy") && !strings.Contains(string(b), "EntityTooLarge") {
				t.Errorf("unexpected error %s", b)
			}
		})
	}
	// A rejected PUT leaves the previous policy in place.
	if _, gb := e.do("GET", "/polcrud?policy", nil, nil); string(gb) != ok {
		t.Errorf("policy changed by rejected PUTs: %q", gb)
	}
	// Policy on a bucket that does not exist.
	r, b = e.do("PUT", "/nopolbucket?policy", strings.NewReader(strings.ReplaceAll(ok, "polcrud", "nopolbucket")), nil)
	wantError(t, r, b, 404, "NoSuchBucket")
	// Deleting the bucket removes its policy.
	if r, _ := e.do("DELETE", "/polcrud?policy", nil, nil); r.StatusCode != 204 {
		t.Fatalf("DELETE ?policy = %d", r.StatusCode)
	}
	e.do("PUT", "/polcrud?policy", strings.NewReader(ok), nil)
	e.do("DELETE", "/polcrud", nil, nil)
	e.mb("polcrud")
	r, b = e.do("GET", "/polcrud?policy", nil, nil)
	wantError(t, r, b, 404, "NoSuchBucketPolicy")
	_ = fmt.Sprint
}

func TestBucketPolicyDenyOverridesAllowRegardlessOfSource(t *testing.T) {
	e := newEnv(t)
	e.mb("poldeny")
	e.put("/poldeny/k", "v", nil)
	// Identity allows (readwrite is root-like via "reader"? use reader's
	// readonly); the bucket Deny names that user explicitly.
	pol := `{"Version":"2012-10-17","Statement":[
	  {"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::poldeny/*"},
	  {"Effect":"Deny","Principal":{"AWS":"arn:aws:iam::nanoio:user/reader"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::poldeny/*"}]}`
	e.do("PUT", "/poldeny?policy", strings.NewReader(pol), nil)
	if r, _ := e.doAs("reader", "GET", "/poldeny/k", nil, nil); r.StatusCode != 403 {
		t.Errorf("explicitly denied principal = %d", r.StatusCode)
	}
	if r, _ := e.doAs("nobody", "GET", "/poldeny/k", nil, nil); r.StatusCode != 200 {
		t.Errorf("everyone else = %d", r.StatusCode)
	}
	// NotPrincipal: deny everyone except writer.
	pol = `{"Version":"2012-10-17","Statement":[
	  {"Effect":"Deny","NotPrincipal":{"AWS":"writer"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::poldeny/*"},
	  {"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::poldeny/*"}]}`
	e.do("PUT", "/poldeny?policy", strings.NewReader(pol), nil)
	if r, _ := e.doAs("writer", "GET", "/poldeny/k", nil, nil); r.StatusCode != 200 {
		t.Errorf("writer under NotPrincipal = %d", r.StatusCode)
	}
	if r, _ := e.doAs("reader", "GET", "/poldeny/k", nil, nil); r.StatusCode != 403 {
		t.Errorf("reader under NotPrincipal = %d", r.StatusCode)
	}
	if r, _ := e.doAnon("GET", "/poldeny/k", nil, nil); r.StatusCode != 403 {
		t.Errorf("anonymous under NotPrincipal = %d", r.StatusCode)
	}
}
