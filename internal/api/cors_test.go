package api

import (
	"fmt"
	"strings"
	"testing"
)

const corsConfigXML = `<CORSConfiguration>
 <CORSRule><ID>r1</ID>
  <AllowedOrigin>https://app.example.com</AllowedOrigin>
  <AllowedMethod>GET</AllowedMethod><AllowedMethod>HEAD</AllowedMethod>
  <AllowedHeader>x-custom-*</AllowedHeader><AllowedHeader>content-type</AllowedHeader>
  <ExposeHeader>ETag</ExposeHeader><ExposeHeader>x-amz-request-id</ExposeHeader>
  <MaxAgeSeconds>3000</MaxAgeSeconds>
 </CORSRule>
 <CORSRule><ID>r2</ID>
  <AllowedOrigin>https://*.example.org</AllowedOrigin>
  <AllowedMethod>PUT</AllowedMethod><AllowedMethod>POST</AllowedMethod><AllowedMethod>DELETE</AllowedMethod>
  <AllowedHeader>*</AllowedHeader>
  <MaxAgeSeconds>600</MaxAgeSeconds>
 </CORSRule>
 <CORSRule><ID>r3</ID>
  <AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod>
 </CORSRule>
</CORSConfiguration>`

func corsEnv(t *testing.T) *testEnv {
	t.Helper()
	e := newEnv(t)
	e.mb("corsbkt")
	e.put("/corsbkt/obj", "cors body", nil)
	if r, b := e.do("PUT", "/corsbkt?cors", strings.NewReader(corsConfigXML), nil); r.StatusCode != 200 {
		t.Fatalf("PUT ?cors: %d %s", r.StatusCode, b)
	}
	e.mb("nocorsbkt")
	return e
}

func TestCORSPreflightMatrix(t *testing.T) {
	e := corsEnv(t)
	type want struct {
		status                                  int
		allowOrigin, allowMethods, allowHeaders string
		maxAge, credentials, exposeContainsETag string
	}
	cases := []struct {
		name, path, origin, method, headers string
		want                                want
	}{
		{"exact origin GET", "/corsbkt/obj", "https://app.example.com", "GET", "", want{status: 200, allowOrigin: "https://app.example.com", allowMethods: "GET, HEAD", maxAge: "3000", credentials: "true", exposeContainsETag: "yes"}},
		{"exact origin HEAD", "/corsbkt/obj", "https://app.example.com", "HEAD", "", want{status: 200, allowOrigin: "https://app.example.com", allowMethods: "GET, HEAD", maxAge: "3000", credentials: "true"}},
		{"exact origin PUT: no rule", "/corsbkt/obj", "https://app.example.com", "PUT", "", want{status: 403}},
		{"allowed headers (wildcard + exact, any case)", "/corsbkt/obj", "https://app.example.com", "GET", "X-Custom-Foo, Content-Type", want{status: 200, allowOrigin: "https://app.example.com", allowMethods: "GET, HEAD", allowHeaders: "X-Custom-Foo, Content-Type", maxAge: "3000", credentials: "true"}},
		{"disallowed header falls through to r3, which allows none", "/corsbkt/obj", "https://app.example.com", "GET", "Authorization", want{status: 403}},
		{"subdomain wildcard origin PUT with headers", "/corsbkt/obj", "https://a.example.org", "PUT", "x-amz-meta-foo, authorization", want{status: 200, allowOrigin: "https://a.example.org", allowMethods: "PUT, POST, DELETE", allowHeaders: "x-amz-meta-foo, authorization", maxAge: "600", credentials: "true"}},
		{"subdomain wildcard origin DELETE", "/corsbkt/obj", "https://deep.sub.example.org", "DELETE", "", want{status: 200, allowOrigin: "https://deep.sub.example.org", allowMethods: "PUT, POST, DELETE", maxAge: "600", credentials: "true"}},
		{"bare domain does not match the subdomain wildcard", "/corsbkt/obj", "https://example.org", "PUT", "", want{status: 403}},
		{"scheme must match", "/corsbkt/obj", "http://a.example.org", "PUT", "", want{status: 403}},
		{"star origin GET", "/corsbkt/obj", "https://anything.test", "GET", "", want{status: 200, allowOrigin: "*", allowMethods: "GET"}},
		{"star origin PUT", "/corsbkt/obj", "https://anything.test", "PUT", "", want{status: 403}},
		{"request method is case-insensitive", "/corsbkt/obj", "https://app.example.com", "get", "", want{status: 200, allowOrigin: "https://app.example.com", allowMethods: "GET, HEAD", maxAge: "3000", credentials: "true"}},
		{"unsupported method", "/corsbkt/obj", "https://app.example.com", "PATCH", "", want{status: 403}},
		{"bucket-level preflight", "/corsbkt", "https://app.example.com", "GET", "", want{status: 200, allowOrigin: "https://app.example.com", allowMethods: "GET, HEAD", maxAge: "3000", credentials: "true"}},
		{"bucket without CORS", "/nocorsbkt/obj", "https://app.example.com", "GET", "", want{status: 403}},
		{"bucket that does not exist", "/ghost/obj", "https://app.example.com", "GET", "", want{status: 403}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := hdr{"Origin": c.origin, "Access-Control-Request-Method": c.method}
			if c.headers != "" {
				h["Access-Control-Request-Headers"] = c.headers
			}
			// Preflights carry no credentials.
			r, b := e.doAnon("OPTIONS", c.path, nil, h)
			if r.StatusCode != c.want.status {
				t.Fatalf("status %d, want %d (%s)", r.StatusCode, c.want.status, b)
			}
			if c.want.status != 200 {
				if r.Header.Get("Access-Control-Allow-Origin") != "" {
					t.Error("refused preflight carries Allow-Origin")
				}
				return
			}
			for hn, want := range map[string]string{
				"Access-Control-Allow-Origin": c.want.allowOrigin, "Access-Control-Allow-Methods": c.want.allowMethods,
				"Access-Control-Allow-Headers": c.want.allowHeaders, "Access-Control-Max-Age": c.want.maxAge,
				"Access-Control-Allow-Credentials": c.want.credentials,
			} {
				if got := r.Header.Get(hn); got != want {
					t.Errorf("%s = %q, want %q", hn, got, want)
				}
			}
			if c.want.exposeContainsETag != "" && !strings.Contains(r.Header.Get("Access-Control-Expose-Headers"), "ETag") {
				t.Errorf("Expose-Headers = %q", r.Header.Get("Access-Control-Expose-Headers"))
			}
			if !strings.Contains(strings.Join(r.Header.Values("Vary"), ","), "Origin") {
				t.Error("no Vary: Origin")
			}
		})
	}
	// An OPTIONS request that is not a preflight is still a plain 405.
	if r, _ := e.doAnon("OPTIONS", "/corsbkt/obj", nil, hdr{"Origin": "https://app.example.com"}); r.StatusCode != 405 {
		t.Errorf("OPTIONS without Access-Control-Request-Method = %d", r.StatusCode)
	}
}

func TestCORSHeadersOnActualRequests(t *testing.T) {
	e := corsEnv(t)
	t.Run("matching origin and method", func(t *testing.T) {
		r, _ := e.do("GET", "/corsbkt/obj", nil, hdr{"Origin": "https://app.example.com"})
		if r.StatusCode != 200 || r.Header.Get("Access-Control-Allow-Origin") != "https://app.example.com" ||
			r.Header.Get("Access-Control-Allow-Credentials") != "true" ||
			!strings.Contains(r.Header.Get("Access-Control-Expose-Headers"), "ETag") ||
			!strings.Contains(r.Header.Get("Vary"), "Origin") {
			t.Errorf("headers: %v", r.Header)
		}
	})
	t.Run("star rule", func(t *testing.T) {
		r, _ := e.do("GET", "/corsbkt/obj", nil, hdr{"Origin": "https://random.test"})
		if r.Header.Get("Access-Control-Allow-Origin") != "*" || r.Header.Get("Access-Control-Allow-Credentials") != "" {
			t.Errorf("headers: %v", r.Header)
		}
	})
	t.Run("method not allowed for the origin", func(t *testing.T) {
		r, _ := e.do("PUT", "/corsbkt/other", strings.NewReader("x"), hdr{"Origin": "https://random.test"})
		if r.Header.Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("PUT from a GET-only origin got Allow-Origin: %v", r.Header)
		}
		if !strings.Contains(r.Header.Get("Vary"), "Origin") {
			t.Error("a bucket with CORS must vary on Origin")
		}
	})
	t.Run("errors carry the headers too", func(t *testing.T) {
		r, _ := e.do("GET", "/corsbkt/missing", nil, hdr{"Origin": "https://app.example.com"})
		if r.StatusCode != 404 || r.Header.Get("Access-Control-Allow-Origin") != "https://app.example.com" {
			t.Errorf("404 = %d %v", r.StatusCode, r.Header)
		}
		r, _ = e.doAnon("GET", "/corsbkt/obj", nil, hdr{"Origin": "https://app.example.com"})
		if r.StatusCode != 403 || r.Header.Get("Access-Control-Allow-Origin") == "" {
			t.Errorf("anonymous 403 = %d %v", r.StatusCode, r.Header)
		}
	})
	t.Run("no Origin, no CORS headers", func(t *testing.T) {
		r, _ := e.do("GET", "/corsbkt/obj", nil, nil)
		for k := range r.Header {
			if strings.HasPrefix(k, "Access-Control-") {
				t.Errorf("unexpected %s", k)
			}
		}
	})
	t.Run("bucket without CORS gets nothing", func(t *testing.T) {
		e.put("/nocorsbkt/o", "x", nil)
		r, _ := e.do("GET", "/nocorsbkt/o", nil, hdr{"Origin": "https://app.example.com"})
		if r.Header.Get("Access-Control-Allow-Origin") != "" || r.Header.Get("Vary") != "" {
			t.Errorf("headers: %v", r.Header)
		}
	})
}

func TestCORSConfigurationCRUD(t *testing.T) {
	e := newEnv(t)
	e.mb("corscrud")
	r, b := e.do("GET", "/corscrud?cors", nil, nil)
	wantError(t, r, b, 404, "NoSuchCORSConfiguration")
	if r, b := e.do("PUT", "/corscrud?cors", strings.NewReader(corsConfigXML), nil); r.StatusCode != 200 {
		t.Fatalf("%d %s", r.StatusCode, b)
	}
	r, b = e.do("GET", "/corscrud?cors", nil, nil)
	if r.StatusCode != 200 {
		t.Fatalf("%d %s", r.StatusCode, b)
	}
	for _, want := range []string{"<ID>r1</ID>", "<AllowedOrigin>https://*.example.org</AllowedOrigin>", "<AllowedHeader>x-custom-*</AllowedHeader>",
		"<ExposeHeader>ETag</ExposeHeader>", "<MaxAgeSeconds>3000</MaxAgeSeconds>", "<AllowedMethod>DELETE</AllowedMethod>"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("GET ?cors lacks %s:\n%s", want, b)
		}
	}
	rule := func(inner string) string {
		return `<CORSConfiguration><CORSRule>` + inner + `</CORSRule></CORSConfiguration>`
	}
	manyRules := "<CORSConfiguration>" + strings.Repeat(`<CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod></CORSRule>`, 101) + "</CORSConfiguration>"
	bad := map[string]string{
		"not xml":               `nope`,
		"no rules":              `<CORSConfiguration></CORSConfiguration>`,
		"no origin":             rule(`<AllowedMethod>GET</AllowedMethod>`),
		"no method":             rule(`<AllowedOrigin>*</AllowedOrigin>`),
		"unsupported method":    rule(`<AllowedOrigin>*</AllowedOrigin><AllowedMethod>PATCH</AllowedMethod>`),
		"two wildcards origin":  rule(`<AllowedOrigin>https://*.*.example.com</AllowedOrigin><AllowedMethod>GET</AllowedMethod>`),
		"two wildcards header":  rule(`<AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod><AllowedHeader>*x*</AllowedHeader>`),
		"wildcard expose":       rule(`<AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod><ExposeHeader>x-*</ExposeHeader>`),
		"negative max age":      rule(`<AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod><MaxAgeSeconds>-1</MaxAgeSeconds>`),
		"more than 100 rules":   manyRules,
		"lowercase method name": rule(`<AllowedOrigin>*</AllowedOrigin><AllowedMethod>get</AllowedMethod>`),
	}
	for name, doc := range bad {
		t.Run(name, func(t *testing.T) {
			r, b := e.do("PUT", "/corscrud?cors", strings.NewReader(doc), nil)
			if r.StatusCode != 400 {
				t.Errorf("status %d: %s", r.StatusCode, b)
			}
		})
	}
	// Permissions.
	if r, _ := e.doAs("nobody", "PUT", "/corscrud?cors", strings.NewReader(corsConfigXML), nil); r.StatusCode != 403 {
		t.Errorf("nobody PUT ?cors = %d", r.StatusCode)
	}
	if r, _ := e.doAnon("GET", "/corscrud?cors", nil, nil); r.StatusCode != 403 {
		t.Errorf("anonymous GET ?cors = %d", r.StatusCode)
	}
	// Delete.
	if r, _ := e.do("DELETE", "/corscrud?cors", nil, nil); r.StatusCode != 204 {
		t.Errorf("DELETE ?cors = %d", r.StatusCode)
	}
	r, b = e.do("GET", "/corscrud?cors", nil, nil)
	wantError(t, r, b, 404, "NoSuchCORSConfiguration")
	r, b = e.do("PUT", "/ghostcors?cors", strings.NewReader(corsConfigXML), nil)
	wantError(t, r, b, 404, "NoSuchBucket")
	_ = fmt.Sprint
}

func TestWildcardMatch(t *testing.T) {
	for _, tt := range []struct {
		pattern, s string
		fold, want bool
	}{
		{"*", "anything", false, true}, {"*", "", false, true}, {"abc", "abc", false, true}, {"abc", "ABC", false, false},
		{"abc", "ABC", true, true}, {"a*c", "abbbc", false, true}, {"a*c", "ac", false, true}, {"a*c", "a", false, false},
		{"a*c", "ab", false, false}, {"https://*.example.org", "https://x.example.org", false, true},
		{"https://*.example.org", "https://example.org", false, false}, {"x-*", "x-", false, true}, {"*-id", "request-id", false, true},
	} {
		if got := wildcardMatch(tt.pattern, tt.s, tt.fold); got != tt.want {
			t.Errorf("wildcardMatch(%q, %q, fold=%v) = %v", tt.pattern, tt.s, tt.fold, got)
		}
	}
}
