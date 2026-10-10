package api

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"nanoio/internal/auth"
	"nanoio/internal/storage"
)

// countingStorage records whether any storage method was reached, so tests
// can prove that rejected requests never touch the backend.
type countingStorage struct {
	storage.StorageAPI
	calls atomic.Int64
}

func (c *countingStorage) ListBuckets(ctx context.Context) ([]storage.BucketInfo, error) {
	c.calls.Add(1)
	return c.StorageAPI.ListBuckets(ctx)
}

func TestAnonymousRequestsAreRejectedEverywhere(t *testing.T) {
	e := newEnv(t)
	e.mb("anon")
	e.put("/anon/obj", "secret data", nil)
	reqs := []struct{ method, path string }{
		{"GET", "/"}, {"PUT", "/newbucket"}, {"HEAD", "/anon"}, {"DELETE", "/anon"},
		{"GET", "/anon?list-type=2"}, {"GET", "/anon"}, {"GET", "/anon?location"},
		{"POST", "/anon?delete"}, {"GET", "/anon/obj"}, {"HEAD", "/anon/obj"},
		{"PUT", "/anon/new"}, {"DELETE", "/anon/obj"}, {"GET", "/anon?acl"},
		{"GET", "/nosuchbucket/obj"}, {"POST", "/anon/obj?uploads"},
	}
	for _, r := range reqs {
		t.Run(r.method+" "+r.path, func(t *testing.T) {
			resp, body := e.doAnon(r.method, r.path, strings.NewReader("x"), nil)
			wantError(t, resp, body, 403, "AccessDenied")
			if strings.Contains(string(body), "secret data") {
				t.Error("anonymous response leaked object data")
			}
		})
	}
	if got, _ := e.get("/anon/obj"); got != "secret data" {
		t.Errorf("object changed by anonymous requests: %q", got)
	}
	t.Run("rejected requests do not reveal what exists", func(t *testing.T) {
		_, a := e.doAnon("GET", "/anon/obj", nil, nil)
		_, b := e.doAnon("GET", "/nosuchbucket/nosuchkey", nil, nil)
		var ea, eb errorResponse
		xml.Unmarshal(a, &ea)
		xml.Unmarshal(b, &eb)
		if ea.Code != eb.Code || ea.Message != eb.Message {
			t.Errorf("existing: %+v\nmissing:  %+v", ea, eb)
		}
	})
}

func TestSignatureFailures(t *testing.T) {
	e := newEnv(t)
	e.mb("sig")
	e.put("/sig/obj", "data", nil)

	mkReq := func(method, path string) *http.Request {
		req, _ := http.NewRequest(method, e.srv.URL+path, nil)
		return req
	}
	tests := []struct {
		name   string
		build  func() *http.Request
		status int
		code   string
		msg    string
	}{
		{"wrong secret", func() *http.Request {
			r := mkReq("GET", "/sig/obj")
			auth.Signer{AccessKey: rootAK, SecretKey: "definitely-the-wrong-one"}.Sign(r, sha256hex(""), time.Now())
			return r
		}, 403, "SignatureDoesNotMatch", ""},
		{"unknown access key", func() *http.Request {
			r := mkReq("GET", "/sig/obj")
			auth.Signer{AccessKey: "mallory", SecretKey: "mallory-secret-key"}.Sign(r, sha256hex(""), time.Now())
			return r
		}, 403, "InvalidAccessKeyId", ""},
		{"disabled user looks unknown", func() *http.Request {
			r := mkReq("GET", "/sig/obj")
			s := signerFor("retired")
			s.Sign(r, sha256hex(""), time.Now())
			return r
		}, 403, "InvalidAccessKeyId", ""},
		{"path changed after signing", func() *http.Request {
			r := mkReq("GET", "/sig/obj")
			e.root.Sign(r, sha256hex(""), time.Now())
			r.URL.Path = "/sig/other"
			return r
		}, 403, "SignatureDoesNotMatch", ""},
		{"method changed after signing", func() *http.Request {
			r := mkReq("GET", "/sig/obj")
			e.root.Sign(r, sha256hex(""), time.Now())
			r.Method = "DELETE"
			return r
		}, 403, "SignatureDoesNotMatch", ""},
		{"query changed after signing", func() *http.Request {
			r := mkReq("GET", "/sig?list-type=2&prefix=a")
			e.root.Sign(r, sha256hex(""), time.Now())
			r.URL.RawQuery = "list-type=2&prefix="
			return r
		}, 403, "SignatureDoesNotMatch", ""},
		{"signed metadata changed", func() *http.Request {
			r := mkReq("PUT", "/sig/m")
			r.Header.Set("X-Amz-Meta-Owner", "alice")
			e.root.Sign(r, sha256hex(""), time.Now())
			r.Header.Set("X-Amz-Meta-Owner", "mallory")
			return r
		}, 403, "SignatureDoesNotMatch", ""},
		{"metadata header added after signing", func() *http.Request {
			r := mkReq("PUT", "/sig/m")
			e.root.Sign(r, sha256hex(""), time.Now())
			r.Header.Set("X-Amz-Meta-Injected", "evil")
			return r
		}, 403, "AccessDenied", "not listed in SignedHeaders"},
		{"copy source added after signing", func() *http.Request {
			r := mkReq("PUT", "/sig/m")
			e.root.Sign(r, sha256hex(""), time.Now())
			r.Header.Set("X-Amz-Copy-Source", "/sig/obj")
			return r
		}, 403, "AccessDenied", "x-amz-copy-source"},
		{"signed 20 minutes ago", func() *http.Request {
			r := mkReq("GET", "/sig/obj")
			e.root.Sign(r, sha256hex(""), time.Now().Add(-20*time.Minute))
			return r
		}, 403, "RequestTimeTooSkewed", ""},
		{"signed 20 minutes ahead", func() *http.Request {
			r := mkReq("GET", "/sig/obj")
			e.root.Sign(r, sha256hex(""), time.Now().Add(20*time.Minute))
			return r
		}, 403, "RequestTimeTooSkewed", ""},
		{"wrong region", func() *http.Request {
			r := mkReq("GET", "/sig/obj")
			auth.Signer{AccessKey: rootAK, SecretKey: rootSK, Region: "eu-west-1"}.Sign(r, sha256hex(""), time.Now())
			return r
		}, 400, "AuthorizationHeaderMalformed", `expecting "us-east-1"`},
		{"wrong service", func() *http.Request {
			r := mkReq("GET", "/sig/obj")
			auth.Signer{AccessKey: rootAK, SecretKey: rootSK, Service: "ec2"}.Sign(r, sha256hex(""), time.Now())
			return r
		}, 400, "AuthorizationHeaderMalformed", ""},
		{"security token", func() *http.Request {
			r := mkReq("GET", "/sig/obj")
			r.Header.Set("X-Amz-Security-Token", "FQoGZXIvYXdz")
			e.root.Sign(r, sha256hex(""), time.Now())
			return r
		}, 400, "InvalidToken", ""},
		{"sigv2 authorization", func() *http.Request {
			r := mkReq("GET", "/sig/obj")
			r.Header.Set("Authorization", "AWS "+rootAK+":bWFsbG9yeQ==")
			return r
		}, 400, "InvalidRequest", "AWS4-HMAC-SHA256"},
		{"malformed authorization", func() *http.Request {
			r := mkReq("GET", "/sig/obj")
			r.Header.Set("Authorization", "AWS4-HMAC-SHA256 gibberish")
			return r
		}, 400, "AuthorizationHeaderMalformed", ""},
		{"missing payload hash header", func() *http.Request {
			r := mkReq("GET", "/sig/obj")
			e.root.Sign(r, sha256hex(""), time.Now())
			r.Header.Del("X-Amz-Content-Sha256")
			return r
		}, 400, "MissingSecurityHeader", "x-amz-content-sha256"},
		{"header and query auth mixed", func() *http.Request {
			r := mkReq("GET", "/sig/obj?X-Amz-Algorithm=AWS4-HMAC-SHA256")
			e.root.Sign(r, sha256hex(""), time.Now())
			return r
		}, 400, "InvalidArgument", "Only one auth mechanism"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, body := e.exec(tt.build())
			er := wantError(t, resp, body, tt.status, tt.code)
			if tt.msg != "" && !strings.Contains(er.Message, tt.msg) {
				t.Errorf("message %q does not contain %q", er.Message, tt.msg)
			}
		})
	}
	if got, _ := e.get("/sig/obj"); got != "data" {
		t.Errorf("object altered by a rejected request: %q", got)
	}
	if r, _ := e.do("HEAD", "/sig/m", nil, nil); r.StatusCode != 404 {
		t.Error("a rejected PUT created an object")
	}
}

func TestPresignedURLs(t *testing.T) {
	e := newEnv(t)
	e.mb("pre")
	e.put("/pre/doc.txt", "presigned content", nil)
	e.put("/pre/a b+c.txt", "special", nil)

	presign := func(user, method, path string, ttl time.Duration, at time.Time, h hdr) *http.Request {
		req, _ := http.NewRequest(method, e.srv.URL+path, nil)
		for k, v := range h {
			req.Header.Set(k, v)
		}
		s := signerFor(user)
		s.Presign(req, ttl, at)
		return req
	}
	t.Run("GET works without any other credentials", func(t *testing.T) {
		resp, body := e.exec(presign(rootAK, "GET", "/pre/doc.txt", time.Hour, time.Now(), nil))
		if resp.StatusCode != 200 || string(body) != "presigned content" {
			t.Errorf("%d %s", resp.StatusCode, body)
		}
	})
	t.Run("GET of a key with spaces and plus", func(t *testing.T) {
		resp, body := e.exec(presign(rootAK, "GET", "/pre/a%20b%2Bc.txt", time.Hour, time.Now(), nil))
		if resp.StatusCode != 200 || string(body) != "special" {
			t.Errorf("%d %s", resp.StatusCode, body)
		}
	})
	t.Run("query parameters that change the response are covered", func(t *testing.T) {
		req := presign(rootAK, "GET", "/pre?list-type=2&prefix=doc", time.Hour, time.Now(), nil)
		resp, body := e.exec(req)
		if resp.StatusCode != 200 || !strings.Contains(string(body), "<Key>doc.txt</Key>") {
			t.Fatalf("%d %s", resp.StatusCode, body)
		}
		req = presign(rootAK, "GET", "/pre?list-type=2&prefix=doc", time.Hour, time.Now(), nil)
		req.URL.RawQuery = strings.Replace(req.URL.RawQuery, "prefix=doc", "prefix=", 1)
		resp, body = e.exec(req)
		wantError(t, resp, body, 403, "SignatureDoesNotMatch")
	})
	t.Run("PUT upload", func(t *testing.T) {
		req := presign(rootAK, "PUT", "/pre/uploaded.txt", time.Minute, time.Now(), nil)
		req.Body = io.NopCloser(strings.NewReader("uploaded via presigned url"))
		req.ContentLength = int64(len("uploaded via presigned url"))
		resp, body := e.exec(req)
		if resp.StatusCode != 200 {
			t.Fatalf("%d %s", resp.StatusCode, body)
		}
		if got, _ := e.get("/pre/uploaded.txt"); got != "uploaded via presigned url" {
			t.Errorf("stored %q", got)
		}
	})
	t.Run("URL signed for GET cannot be used to DELETE", func(t *testing.T) {
		req := presign(rootAK, "GET", "/pre/doc.txt", time.Hour, time.Now(), nil)
		req.Method = "DELETE"
		resp, body := e.exec(req)
		wantError(t, resp, body, 403, "SignatureDoesNotMatch")
		if got, _ := e.get("/pre/doc.txt"); got != "presigned content" {
			t.Error("object deleted through a GET presign")
		}
	})
	t.Run("URL for one object cannot fetch another", func(t *testing.T) {
		req := presign(rootAK, "GET", "/pre/doc.txt", time.Hour, time.Now(), nil)
		req.URL.Path = "/pre/a b+c.txt"
		resp, body := e.exec(req)
		wantError(t, resp, body, 403, "SignatureDoesNotMatch")
	})
	t.Run("expired", func(t *testing.T) {
		req := presign(rootAK, "GET", "/pre/doc.txt", time.Minute, time.Now().Add(-10*time.Minute), nil)
		resp, body := e.exec(req)
		er := wantError(t, resp, body, 403, "AccessDenied")
		if !strings.Contains(er.Message, "expired") {
			t.Errorf("message %q", er.Message)
		}
	})
	t.Run("lifetime beyond seven days", func(t *testing.T) {
		req := presign(rootAK, "GET", "/pre/doc.txt", 8*24*time.Hour, time.Now(), nil)
		resp, body := e.exec(req)
		wantError(t, resp, body, 400, "AuthorizationQueryParametersError")
	})
	t.Run("authorisation still applies: reader URL cannot write", func(t *testing.T) {
		req := presign("reader", "PUT", "/pre/by-reader.txt", time.Hour, time.Now(), nil)
		req.Body = io.NopCloser(strings.NewReader("x"))
		req.ContentLength = 1
		resp, body := e.exec(req)
		wantError(t, resp, body, 403, "AccessDenied")
		if r, _ := e.do("HEAD", "/pre/by-reader.txt", nil, nil); r.StatusCode != 404 {
			t.Error("object created through a denied presigned PUT")
		}
	})
	t.Run("URL of a user disabled afterwards style: unknown key", func(t *testing.T) {
		req := presign("retired", "GET", "/pre/doc.txt", time.Hour, time.Now(), nil)
		resp, body := e.exec(req)
		wantError(t, resp, body, 403, "InvalidAccessKeyId")
	})
	t.Run("x-amz headers must be signed", func(t *testing.T) {
		req := presign(rootAK, "PUT", "/pre/h.txt", time.Hour, time.Now(), nil)
		req.Header.Set("X-Amz-Acl", "public-read")
		req.Body = io.NopCloser(strings.NewReader("x"))
		req.ContentLength = 1
		resp, body := e.exec(req)
		wantError(t, resp, body, 403, "AccessDenied")
	})
}

func TestAuthorizationMatrix(t *testing.T) {
	e := newEnv(t)
	e.mb("shared")
	e.put("/shared/doc.txt", "shared doc", nil)
	e.mb("scoped")
	e.put("/scoped/pub/a.txt", "public a", nil)
	e.put("/scoped/priv/b.txt", "private b", nil)

	tests := []struct {
		name         string
		user         string
		method, path string
		body         string
		status       int
	}{
		// root
		{"root lists buckets", rootAK, "GET", "/", "", 200},
		{"root deletes", rootAK, "PUT", "/shared/by-root.txt", "x", 200},
		// reader: s3:GetObject, ListBucket, GetBucketLocation, ListAllMyBuckets
		{"reader lists buckets", "reader", "GET", "/", "", 200},
		{"reader lists bucket", "reader", "GET", "/shared?list-type=2", "", 200},
		{"reader heads bucket", "reader", "HEAD", "/shared", "", 200},
		{"reader gets location", "reader", "GET", "/shared?location", "", 200},
		{"reader gets object", "reader", "GET", "/shared/doc.txt", "", 200},
		{"reader heads object", "reader", "HEAD", "/shared/doc.txt", "", 200},
		{"reader cannot put", "reader", "PUT", "/shared/r.txt", "x", 403},
		{"reader cannot delete object", "reader", "DELETE", "/shared/doc.txt", "", 403},
		{"reader cannot create bucket", "reader", "PUT", "/readerbucket", "", 403},
		{"reader cannot delete bucket", "reader", "DELETE", "/shared", "", 403},
		// writer: s3:PutObject only
		{"writer puts", "writer", "PUT", "/shared/w.txt", "x", 200},
		{"writer cannot get", "writer", "GET", "/shared/doc.txt", "", 403},
		{"writer cannot list", "writer", "GET", "/shared?list-type=2", "", 403},
		{"writer cannot list buckets", "writer", "GET", "/", "", 403},
		{"writer cannot delete", "writer", "DELETE", "/shared/w.txt", "", 403},
		// nobody: no policies
		{"nobody cannot list buckets", "nobody", "GET", "/", "", 403},
		{"nobody cannot get", "nobody", "GET", "/shared/doc.txt", "", 403},
		// retired: disabled
		{"disabled user is unknown", "retired", "GET", "/shared/doc.txt", "", 403},
		// scoped: one prefix, with a ListBucket condition on s3:prefix
		{"scoped gets in prefix", "scoped", "GET", "/scoped/pub/a.txt", "", 200},
		{"scoped puts in prefix", "scoped", "PUT", "/scoped/pub/new.txt", "x", 200},
		{"scoped deletes in prefix", "scoped", "DELETE", "/scoped/pub/new.txt", "", 204},
		{"scoped cannot get outside prefix", "scoped", "GET", "/scoped/priv/b.txt", "", 403},
		{"scoped cannot put outside prefix", "scoped", "PUT", "/scoped/priv/x.txt", "x", 403},
		{"scoped cannot reach another bucket", "scoped", "GET", "/shared/doc.txt", "", 403},
		{"scoped lists its prefix", "scoped", "GET", "/scoped?list-type=2&prefix=pub/", "", 200},
		{"scoped lists a deeper prefix", "scoped", "GET", "/scoped?list-type=2&prefix=pub/sub/", "", 200},
		{"scoped cannot list without prefix", "scoped", "GET", "/scoped?list-type=2", "", 403},
		{"scoped cannot list another prefix", "scoped", "GET", "/scoped?list-type=2&prefix=priv/", "", 403},
		{"scoped cannot list empty prefix", "scoped", "GET", "/scoped?list-type=2&prefix=", "", 403},
		{"scoped cannot list buckets", "scoped", "GET", "/", "", 403},
		{"scoped lists v1 in prefix", "scoped", "GET", "/scoped?prefix=pub/", "", 200},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, body := e.doAs(tt.user, tt.method, tt.path, strings.NewReader(tt.body), nil)
			if resp.StatusCode != tt.status {
				t.Fatalf("status %d, want %d: %s", resp.StatusCode, tt.status, body)
			}
			if tt.status == 403 && tt.method != "HEAD" {
				code := "AccessDenied"
				if tt.user == "retired" {
					code = "InvalidAccessKeyId" // a disabled key is indistinguishable from an unknown one
				}
				wantError(t, resp, body, 403, code)
			}
		})
	}
	// Denied writes had no effect; the scoped user's data stayed put.
	for _, p := range []string{"/shared/r.txt", "/scoped/priv/x.txt", "/readerbucket"} {
		if r, _ := e.do("HEAD", p, nil, nil); r.StatusCode != 404 {
			t.Errorf("%s exists after a denied write (HEAD %d)", p, r.StatusCode)
		}
	}
	if got, _ := e.get("/shared/doc.txt"); got != "shared doc" {
		t.Errorf("shared/doc.txt = %q", got)
	}
	t.Run("denial does not depend on whether the target exists", func(t *testing.T) {
		_, a := e.doAs("reader", "DELETE", "/shared/doc.txt", nil, nil)
		_, b := e.doAs("reader", "DELETE", "/shared/never-existed.txt", nil, nil)
		_, c := e.doAs("reader", "DELETE", "/no-such-bucket/x", nil, nil)
		var ea, eb, ec errorResponse
		xml.Unmarshal(a, &ea)
		xml.Unmarshal(b, &eb)
		xml.Unmarshal(c, &ec)
		if ea.Code != "AccessDenied" || eb.Code != "AccessDenied" || ec.Code != "AccessDenied" {
			t.Errorf("codes: %s %s %s", ea.Code, eb.Code, ec.Code)
		}
	})
}

func TestMultiDeleteAuthorisesPerKey(t *testing.T) {
	e := newEnv(t)
	e.mb("scoped")
	for _, k := range []string{"pub/a", "pub/c", "priv/b"} {
		e.put("/scoped/"+k, "x", nil)
	}
	body := `<Delete><Object><Key>pub/a</Key></Object><Object><Key>priv/b</Key></Object><Object><Key>pub/c</Key></Object></Delete>`
	resp, b := e.doAs("scoped", "POST", "/scoped?delete", strings.NewReader(body), nil)
	var r deleteResult
	if err := xml.Unmarshal(b, &r); err != nil || resp.StatusCode != 200 {
		t.Fatalf("%d %v %s", resp.StatusCode, err, b)
	}
	var deleted []string
	for _, d := range r.Deleted {
		deleted = append(deleted, d.Key)
	}
	if strings.Join(deleted, ",") != "pub/a,pub/c" {
		t.Errorf("deleted = %v", deleted)
	}
	if len(r.Errors) != 1 || r.Errors[0].Key != "priv/b" || r.Errors[0].Code != "AccessDenied" {
		t.Errorf("errors = %+v", r.Errors)
	}
	if r, _ := e.do("HEAD", "/scoped/priv/b", nil, nil); r.StatusCode != 200 {
		t.Error("the unauthorised key was deleted")
	}
	if r, _ := e.do("HEAD", "/scoped/pub/a", nil, nil); r.StatusCode != 404 {
		t.Error("the authorised key survived")
	}

	t.Run("a caller with no delete rights learns nothing about the bucket", func(t *testing.T) {
		del := `<Delete><Object><Key>k</Key></Object></Delete>`
		for _, bucket := range []string{"scoped", "no-such-bucket"} {
			resp, b := e.doAs("reader", "POST", "/"+bucket+"?delete", strings.NewReader(del), nil)
			var res deleteResult
			if err := xml.Unmarshal(b, &res); err != nil || resp.StatusCode != 200 ||
				len(res.Errors) != 1 || res.Errors[0].Code != "AccessDenied" {
				t.Errorf("%s: %d %v %s", bucket, resp.StatusCode, err, b)
			}
		}
	})
}

func TestSignedBodiesAreVerified(t *testing.T) {
	e := newEnv(t)
	t.Run("create bucket body matches its signed hash", func(t *testing.T) {
		cfg := `<CreateBucketConfiguration><LocationConstraint>us-east-1</LocationConstraint></CreateBucketConfiguration>`
		resp, body := e.do("PUT", "/hashok", strings.NewReader(cfg), nil)
		if resp.StatusCode != 200 {
			t.Errorf("%d %s", resp.StatusCode, body)
		}
	})
	t.Run("create bucket body differs from the signed hash", func(t *testing.T) {
		cfg := `<CreateBucketConfiguration><LocationConstraint>us-east-1</LocationConstraint></CreateBucketConfiguration>`
		resp, body := e.do("PUT", "/hashbad", strings.NewReader(cfg),
			hdr{"x-amz-content-sha256": sha256hex("something else entirely")})
		wantError(t, resp, body, 400, "XAmzContentSHA256Mismatch")
		if r, _ := e.do("HEAD", "/hashbad", nil, nil); r.StatusCode != 404 {
			t.Error("bucket created from an unverified body")
		}
	})
	t.Run("multi-delete body differs from the signed hash", func(t *testing.T) {
		e.mb("hashdel")
		e.put("/hashdel/keep", "x", nil)
		resp, body := e.do("POST", "/hashdel?delete",
			strings.NewReader(`<Delete><Object><Key>keep</Key></Object></Delete>`),
			hdr{"x-amz-content-sha256": sha256hex(`<Delete><Object><Key>other</Key></Object></Delete>`)})
		wantError(t, resp, body, 400, "XAmzContentSHA256Mismatch")
		if r, _ := e.do("HEAD", "/hashdel/keep", nil, nil); r.StatusCode != 200 {
			t.Error("object deleted from an unverified body")
		}
	})
	t.Run("unsigned payload is accepted for small bodies", func(t *testing.T) {
		resp, body := e.do("POST", "/hashdel?delete",
			strings.NewReader(`<Delete><Object><Key>keep</Key></Object></Delete>`),
			hdr{"x-amz-content-sha256": "UNSIGNED-PAYLOAD"})
		if resp.StatusCode != 200 {
			t.Errorf("%d %s", resp.StatusCode, body)
		}
	})
}

func TestStorageUntouchedByRejectedRequests(t *testing.T) {
	e := newEnv(t)
	cs := &countingStorage{StorageAPI: e.fs}
	e2 := serve(t, cs, e.fs)
	reqs := []func() (*http.Response, []byte){
		func() (*http.Response, []byte) { return e2.doAnon("GET", "/", nil, nil) },
		func() (*http.Response, []byte) { return e2.doAs("nobody", "GET", "/", nil, nil) },
		func() (*http.Response, []byte) { return e2.doAs("retired", "GET", "/", nil, nil) },
		func() (*http.Response, []byte) {
			r, _ := http.NewRequest("GET", e2.srv.URL+"/", nil)
			auth.Signer{AccessKey: rootAK, SecretKey: "wrong-secret-key"}.Sign(r, sha256hex(""), time.Now())
			return e2.exec(r)
		},
	}
	for i, f := range reqs {
		resp, _ := f()
		if resp.StatusCode != 403 {
			t.Errorf("request %d: status %d", i, resp.StatusCode)
		}
	}
	if n := cs.calls.Load(); n != 0 {
		t.Errorf("storage was called %d times by rejected requests", n)
	}
	if resp, _ := e2.do("GET", "/", nil, nil); resp.StatusCode != 200 || cs.calls.Load() != 1 {
		t.Errorf("authorised request: %d, storage calls %d", resp.StatusCode, cs.calls.Load())
	}
}

func TestInsecureNoAuthMode(t *testing.T) {
	be := newEnv(t).fs
	h, err := New(Options{Storage: be, InsecureNoAuth: true, Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	e := &testEnv{t: t, fs: be}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	e.srv = srv
	for _, call := range []struct{ method, path, body string }{
		{"PUT", "/open", ""}, {"PUT", "/open/k", "v"}, {"GET", "/open/k", ""}, {"GET", "/", ""},
	} {
		resp, body := e.doAnon(call.method, call.path, strings.NewReader(call.body), nil)
		if resp.StatusCode != 200 {
			t.Errorf("%s %s: %d %s", call.method, call.path, resp.StatusCode, body)
		}
	}
	t.Run("signed requests are still accepted", func(t *testing.T) {
		resp, _ := e.send(&auth.Signer{AccessKey: "whoever", SecretKey: "whatever-secret"}, "GET", "/open/k", nil, nil)
		if resp.StatusCode != 200 {
			t.Errorf("status %d", resp.StatusCode)
		}
	})
}

func TestAuthFailureResponsesDoNotLeakSecrets(t *testing.T) {
	e := newEnv(t)
	req, _ := http.NewRequest("GET", e.srv.URL+"/", nil)
	auth.Signer{AccessKey: rootAK, SecretKey: "an-incorrect-secret"}.Sign(req, sha256hex(""), time.Now())
	resp, body := e.exec(req)
	text := fmt.Sprint(resp.Header) + string(body)
	for _, secret := range []string{rootSK, "an-incorrect-secret", "reader-secret-key"} {
		if strings.Contains(text, secret) {
			t.Errorf("response contains secret %q", secret)
		}
	}
	// SignatureDoesNotMatch must not echo the canonical request or string to
	// sign (some servers do, which helps debugging and helps attackers).
	for _, leak := range []string{"StringToSign", "CanonicalRequest", "AWS4-HMAC-SHA256\n"} {
		if strings.Contains(string(body), leak) {
			t.Errorf("response exposes %q", leak)
		}
	}
}
