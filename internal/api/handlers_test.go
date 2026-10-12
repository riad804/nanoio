package api

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"nanoio/internal/auth"
	"nanoio/internal/bucket/nslock"
	"nanoio/internal/iam"
	"nanoio/internal/storage"
	"nanoio/internal/storage/fs"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

const (
	rootAK = "nanoroot"
	rootSK = "nanoroot-secret-key"
)

// Users used across the auth tests. The scoped policy is the classic
// "one prefix of one bucket" grant, including the ListBucket condition.
var testIAMFile = &iam.File{
	Users: []iam.UserEntry{
		{AccessKey: "reader", SecretKey: "reader-secret-key", Policies: []string{"readonly"}},
		{AccessKey: "writer", SecretKey: "writer-secret-key", Policies: []string{"writeonly"}},
		{AccessKey: "scoped", SecretKey: "scoped-secret-key", Policies: []string{"pub-only"}},
		{AccessKey: "nobody", SecretKey: "nobody-secret-key"},
		{AccessKey: "retired", SecretKey: "retired-secret-key", Status: "disabled", Policies: []string{"readwrite"}},
		{AccessKey: "uploader", SecretKey: "uploader-secret-key", Policies: []string{"mp-full"}},
		// Both work on the object lock test bucket; only "governor" may
		// bypass governance retention.
		{AccessKey: "locker", SecretKey: "locker-secret-key", Policies: []string{"lock-ops"}},
		{AccessKey: "governor", SecretKey: "governor-secret-key", Policies: []string{"lock-ops", "lock-bypass"}},
	},
	Policies: map[string]json.RawMessage{
		// Everything multipart needs on one bucket, and nothing else.
		"mp-full": json.RawMessage(`{"Version":"2012-10-17","Statement":[
			{"Effect":"Allow","Action":["s3:PutObject","s3:GetObject","s3:AbortMultipartUpload",
			 "s3:ListMultipartUploadParts"],"Resource":"arn:aws:s3:::mpa/*"},
			{"Effect":"Allow","Action":["s3:ListBucketMultipartUploads","s3:ListBucket"],"Resource":"arn:aws:s3:::mpa"}]}`),
		"lock-ops": json.RawMessage(`{"Version":"2012-10-17","Statement":[
			{"Effect":"Allow","Action":["s3:PutObject","s3:GetObject","s3:GetObjectVersion","s3:DeleteObject",
			 "s3:DeleteObjectVersion","s3:PutObjectRetention","s3:GetObjectRetention","s3:PutObjectLegalHold",
			 "s3:GetObjectLegalHold"],"Resource":"arn:aws:s3:::lockapi/*"},
			{"Effect":"Allow","Action":["s3:ListBucket","s3:ListBucketVersions","s3:GetBucketObjectLockConfiguration"],
			 "Resource":"arn:aws:s3:::lockapi"}]}`),
		"lock-bypass": json.RawMessage(`{"Version":"2012-10-17","Statement":[
			{"Effect":"Allow","Action":"s3:BypassGovernanceRetention","Resource":"arn:aws:s3:::lockapi/*"}]}`),
		"pub-only": json.RawMessage(`{"Version":"2012-10-17","Statement":[
			{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject","s3:DeleteObject"],"Resource":"arn:aws:s3:::scoped/pub/*"},
			{"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::scoped",
			 "Condition":{"StringLike":{"s3:prefix":"pub/*"}}}]}`),
	},
}

func signerFor(ak string) auth.Signer {
	secrets := map[string]string{
		rootAK: rootSK, "reader": "reader-secret-key", "writer": "writer-secret-key",
		"scoped": "scoped-secret-key", "nobody": "nobody-secret-key", "retired": "retired-secret-key",
		"uploader": "uploader-secret-key", "locker": "locker-secret-key", "governor": "governor-secret-key",
	}
	return auth.Signer{AccessKey: ak, SecretKey: secrets[ak]}
}

type testEnv struct {
	t   *testing.T
	srv *httptest.Server
	st  storage.StorageAPI
	// drives are the xl drive directories, when the backend is xl.
	drives []string
	fs     *fs.FS
	host   string // host:port of srv
	root   auth.Signer
	iam    *iam.Store
}

// newEnv serves a real fs backend over HTTP with authentication on.
func newEnv(t *testing.T) *testEnv {
	t.Helper()
	be, err := fs.New(t.TempDir(), fs.Options{Locker: nslock.New(5 * time.Second), Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { be.Close() })
	return serve(t, be, be)
}

func serve(t *testing.T, st storage.StorageAPI, be *fs.FS, mutate ...func(*Options)) *testEnv {
	t.Helper()
	store, err := iam.New(iam.Credential{AccessKey: rootAK, SecretKey: rootSK}, testIAMFile)
	if err != nil {
		t.Fatal(err)
	}
	opts := Options{
		Storage: st, Auth: &auth.Verifier{Provider: store, Region: "us-east-1"}, Authz: store,
		Domains: []string{"localhost"}, Region: "us-east-1", Logger: quiet, IAM: store,
	}
	for _, m := range mutate {
		m(&opts)
	}
	h, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	return &testEnv{t: t, srv: srv, st: st, fs: be, host: u.Host, root: signerFor(rootAK), iam: store}
}

type hdr map[string]string

// do sends a request signed as the root user.
func (e *testEnv) do(method, path string, body io.Reader, h hdr) (*http.Response, []byte) {
	e.t.Helper()
	s := e.root
	return e.send(&s, method, path, body, h)
}

// doAs signs as the named test user.
func (e *testEnv) doAs(user, method, path string, body io.Reader, h hdr) (*http.Response, []byte) {
	e.t.Helper()
	s := signerFor(user)
	return e.send(&s, method, path, body, h)
}

// doAnon sends the request without any credentials.
func (e *testEnv) doAnon(method, path string, body io.Reader, h hdr) (*http.Response, []byte) {
	e.t.Helper()
	return e.send(nil, method, path, body, h)
}

// send builds, optionally signs, and executes a request, returning the
// response with its body fully read. The payload hash header is honoured
// when the test sets one (to provoke mismatches); otherwise the body's
// SHA-256 is signed.
func (e *testEnv) send(signer *auth.Signer, method, path string, body io.Reader, h hdr) (*http.Response, []byte) {
	e.t.Helper()
	var payload []byte
	if body != nil {
		var err error
		if payload, err = io.ReadAll(body); err != nil {
			e.t.Fatal(err)
		}
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(payload)
	}
	req, err := http.NewRequest(method, e.srv.URL+path, rd)
	if err != nil {
		e.t.Fatal(err)
	}
	// Stop Go's transport from transparently gunzipping objects stored with
	// Content-Encoding: gzip; the tests want the bytes as served.
	req.Header.Set("Accept-Encoding", "identity")
	declared := ""
	for k, v := range h {
		if strings.EqualFold(k, "Host") {
			req.Host = v
			continue
		}
		if strings.EqualFold(k, "x-amz-content-sha256") {
			declared = v
		}
		req.Header.Set(k, v)
	}
	if signer != nil {
		if declared == "" {
			declared = sha256hex(string(payload))
		}
		signer.Sign(req, declared, time.Now())
	}
	return e.exec(req)
}

func (e *testEnv) exec(req *http.Request) (*http.Response, []byte) {
	e.t.Helper()
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		e.t.Fatalf("%s %s: %v", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		e.t.Fatalf("read body of %s %s: %v", req.Method, req.URL.Path, err)
	}
	return resp, b
}

func (e *testEnv) mb(bucket string) {
	e.t.Helper()
	if resp, b := e.do("PUT", "/"+bucket, nil, nil); resp.StatusCode != 200 {
		e.t.Fatalf("create bucket %s: %d %s", bucket, resp.StatusCode, b)
	}
}

func (e *testEnv) put(path, body string, h hdr) *http.Response {
	e.t.Helper()
	resp, b := e.do("PUT", path, strings.NewReader(body), h)
	if resp.StatusCode != 200 {
		e.t.Fatalf("PUT %s: %d %s", path, resp.StatusCode, b)
	}
	return resp
}

func (e *testEnv) get(path string) (string, *http.Response) {
	e.t.Helper()
	resp, b := e.do("GET", path, nil, nil)
	return string(b), resp
}

// wantError asserts an S3 error response and returns the parsed body.
func wantError(t *testing.T, resp *http.Response, body []byte, status int, code string) errorResponse {
	t.Helper()
	var er errorResponse
	if resp.StatusCode != status {
		t.Errorf("status = %d, want %d (body %s)", resp.StatusCode, status, body)
		return er
	}
	if resp.Request.Method == "HEAD" {
		return er
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/xml" {
		t.Errorf("error Content-Type = %q", ct)
	}
	if err := xml.Unmarshal(body, &er); err != nil {
		t.Fatalf("error body is not XML: %v\n%s", err, body)
	}
	if er.Code != code {
		t.Errorf("code = %q, want %q (message %q)", er.Code, code, er.Message)
	}
	if er.RequestID == "" || er.RequestID != resp.Header.Get("x-amz-request-id") {
		t.Errorf("RequestId %q does not match header %q", er.RequestID, resp.Header.Get("x-amz-request-id"))
	}
	return er
}

func md5hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func md5b64(s string) string {
	sum := md5.Sum([]byte(s))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestBucketLifecycle(t *testing.T) {
	e := newEnv(t)
	hex16 := regexp.MustCompile(`^[0-9A-F]{16}$`)

	t.Run("create", func(t *testing.T) {
		resp, body := e.do("PUT", "/mybucket", nil, nil)
		if resp.StatusCode != 200 || len(body) != 0 || resp.Header.Get("Location") != "/mybucket" {
			t.Errorf("create = %d %q Location=%q", resp.StatusCode, body, resp.Header.Get("Location"))
		}
		if !hex16.MatchString(resp.Header.Get("x-amz-request-id")) || resp.Header.Get("Server") != "NanoIO" {
			t.Errorf("missing standard headers: %v", resp.Header)
		}
	})
	t.Run("create with location constraint is accepted", func(t *testing.T) {
		cfg := `<CreateBucketConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><LocationConstraint>eu-west-1</LocationConstraint></CreateBucketConfiguration>`
		resp, body := e.do("PUT", "/withregion", strings.NewReader(cfg), nil)
		if resp.StatusCode != 200 {
			t.Errorf("status %d: %s", resp.StatusCode, body)
		}
	})
	tests := []struct {
		name   string
		method string
		path   string
		body   string
		status int
		code   string
	}{
		{"duplicate", "PUT", "/mybucket", "", 409, "BucketAlreadyOwnedByYou"},
		{"uppercase name", "PUT", "/Bad_Name", "", 400, "InvalidBucketName"},
		{"too short", "PUT", "/ab", "", 400, "InvalidBucketName"},
		{"malformed config body", "PUT", "/badcfg", "<not-xml", 400, "MalformedXML"},
		{"head missing", "HEAD", "/nope", "", 404, ""},
		{"delete missing", "DELETE", "/nope", "", 404, "NoSuchBucket"},
		{"location of missing", "GET", "/nope?location", "", 404, "NoSuchBucket"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, body := e.do(tt.method, tt.path, strings.NewReader(tt.body), nil)
			er := wantError(t, resp, body, tt.status, tt.code)
			if tt.method != "HEAD" && tt.name == "delete missing" && er.BucketName != "nope" {
				t.Errorf("BucketName = %q", er.BucketName)
			}
			if tt.method == "HEAD" && len(body) != 0 {
				t.Errorf("HEAD error carried a body: %q", body)
			}
		})
	}

	t.Run("head existing", func(t *testing.T) {
		resp, body := e.do("HEAD", "/mybucket", nil, nil)
		if resp.StatusCode != 200 || len(body) != 0 || resp.Header.Get("x-amz-bucket-region") != "us-east-1" {
			t.Errorf("HEAD = %d region=%q", resp.StatusCode, resp.Header.Get("x-amz-bucket-region"))
		}
	})
	t.Run("list buckets", func(t *testing.T) {
		resp, body := e.do("GET", "/", nil, nil)
		if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/xml" {
			t.Fatalf("status %d ct %q", resp.StatusCode, resp.Header.Get("Content-Type"))
		}
		if !strings.HasPrefix(string(body), `<?xml version="1.0" encoding="UTF-8"?>`) {
			t.Errorf("missing XML declaration: %.60s", body)
		}
		var r listAllMyBucketsResult
		if err := xml.Unmarshal(body, &r); err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, b := range r.Buckets.Bucket {
			names = append(names, b.Name)
			if _, err := time.Parse(timeLayout, b.CreationDate); err != nil {
				t.Errorf("CreationDate %q: %v", b.CreationDate, err)
			}
		}
		if got := strings.Join(names, ","); got != "mybucket,withregion" {
			t.Errorf("buckets = %s", got)
		}
		if r.Owner.ID == "" {
			t.Error("Owner missing")
		}
	})
	t.Run("get location", func(t *testing.T) {
		resp, body := e.do("GET", "/mybucket?location", nil, nil)
		want := `<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></LocationConstraint>`
		if resp.StatusCode != 200 || !strings.HasSuffix(string(body), want) {
			t.Errorf("location = %d %s", resp.StatusCode, body)
		}
	})
	t.Run("delete non-empty then empty", func(t *testing.T) {
		e.put("/mybucket/k", "v", nil)
		resp, body := e.do("DELETE", "/mybucket", nil, nil)
		wantError(t, resp, body, 409, "BucketNotEmpty")
		if resp, _ := e.do("DELETE", "/mybucket/k", nil, nil); resp.StatusCode != 204 {
			t.Fatalf("delete object: %d", resp.StatusCode)
		}
		resp, body = e.do("DELETE", "/mybucket", nil, nil)
		if resp.StatusCode != 204 || len(body) != 0 {
			t.Errorf("delete bucket = %d %q", resp.StatusCode, body)
		}
		resp, _ = e.do("HEAD", "/mybucket", nil, nil)
		if resp.StatusCode != 404 {
			t.Errorf("bucket still exists: %d", resp.StatusCode)
		}
	})
}

func TestObjectRoundTrip(t *testing.T) {
	e := newEnv(t)
	e.mb("objs")
	body := "hello, object"
	e.put("/objs/dir/hello.txt", body, hdr{
		"Content-Type":        "text/plain; charset=utf-8",
		"Cache-Control":       "max-age=60",
		"Content-Disposition": `attachment; filename="h.txt"`,
		"Content-Language":    "en",
		"Content-Encoding":    "gzip",
		"Expires":             "Thu, 01 Jan 2099 00:00:00 GMT",
		"x-amz-meta-owner":    "alice",
		"X-Amz-Meta-Purpose":  "test",
	})

	check := func(t *testing.T, resp *http.Response, wantBody string, head bool) {
		t.Helper()
		if resp.StatusCode != 200 {
			t.Fatalf("status %d", resp.StatusCode)
		}
		want := map[string]string{
			"ETag":                `"` + md5hex(body) + `"`,
			"Content-Type":        "text/plain; charset=utf-8",
			"Content-Length":      fmt.Sprint(len(body)),
			"Accept-Ranges":       "bytes",
			"Cache-Control":       "max-age=60",
			"Content-Disposition": `attachment; filename="h.txt"`,
			"Content-Language":    "en",
			"Content-Encoding":    "gzip",
			"Expires":             "Thu, 01 Jan 2099 00:00:00 GMT",
			"X-Amz-Meta-Owner":    "alice",
			"X-Amz-Meta-Purpose":  "test",
		}
		for k, v := range want {
			if got := resp.Header.Get(k); got != v {
				t.Errorf("%s = %q, want %q", k, got, v)
			}
		}
		lm, err := http.ParseTime(resp.Header.Get("Last-Modified"))
		if err != nil || time.Since(lm) > time.Minute || time.Since(lm) < -time.Minute {
			t.Errorf("Last-Modified = %q (%v)", resp.Header.Get("Last-Modified"), err)
		}
		if head && wantBody != "" {
			t.Error("test bug: HEAD with expected body")
		}
	}
	t.Run("GET", func(t *testing.T) {
		got, resp := e.get("/objs/dir/hello.txt")
		check(t, resp, got, false)
		if got != body {
			t.Errorf("body = %q", got)
		}
	})
	t.Run("HEAD", func(t *testing.T) {
		resp, b := e.do("HEAD", "/objs/dir/hello.txt", nil, nil)
		check(t, resp, string(b), true)
		if len(b) != 0 {
			t.Errorf("HEAD returned a body of %d bytes", len(b))
		}
	})
	t.Run("put response carries the ETag", func(t *testing.T) {
		resp := e.put("/objs/etag", "abc", nil)
		if got := resp.Header.Get("ETag"); got != `"`+md5hex("abc")+`"` {
			t.Errorf("ETag = %q", got)
		}
	})
	t.Run("default content type", func(t *testing.T) {
		e.put("/objs/untyped", "x", nil)
		_, resp := e.get("/objs/untyped")
		// Go's client adds no Content-Type on PUT with a string body.
		if ct := resp.Header.Get("Content-Type"); ct == "" {
			t.Error("no Content-Type on GET")
		}
	})
	t.Run("keys with spaces, plus and unicode", func(t *testing.T) {
		for _, key := range []string{"a b", "a+b", "日本語/ファイル.txt", "sym&bols=1;x", "100%"} {
			p := "/objs/" + (&url.URL{Path: key}).EscapedPath()
			e.put(p, "v:"+key, nil)
			if got, _ := e.get(p); got != "v:"+key {
				t.Errorf("key %q: got %q", key, got)
			}
		}
	})
	t.Run("zero-byte object", func(t *testing.T) {
		e.put("/objs/empty", "", nil)
		got, resp := e.get("/objs/empty")
		if got != "" || resp.Header.Get("Content-Length") != "0" || resp.StatusCode != 200 {
			t.Errorf("empty: %q %d len=%s", got, resp.StatusCode, resp.Header.Get("Content-Length"))
		}
	})
	t.Run("folder placeholder", func(t *testing.T) {
		e.put("/objs/folder/", "", hdr{"Content-Type": "application/x-directory"})
		_, resp := e.get("/objs/folder/")
		if resp.StatusCode != 200 {
			t.Errorf("status %d", resp.StatusCode)
		}
	})
	t.Run("missing key", func(t *testing.T) {
		resp, b := e.do("GET", "/objs/nope", nil, nil)
		er := wantError(t, resp, b, 404, "NoSuchKey")
		if er.Key != "nope" || er.BucketName != "objs" || er.Resource != "/objs/nope" {
			t.Errorf("error context: %+v", er)
		}
		resp, b = e.do("HEAD", "/objs/nope", nil, nil)
		wantError(t, resp, b, 404, "")
		if len(b) != 0 {
			t.Error("HEAD 404 carried a body")
		}
	})
	t.Run("missing bucket", func(t *testing.T) {
		resp, b := e.do("GET", "/ghostbucket/k", nil, nil)
		wantError(t, resp, b, 404, "NoSuchBucket")
		resp, b = e.do("PUT", "/ghostbucket/k", strings.NewReader("x"), nil)
		wantError(t, resp, b, 404, "NoSuchBucket")
	})
	t.Run("delete is idempotent", func(t *testing.T) {
		for i := 0; i < 2; i++ {
			resp, b := e.do("DELETE", "/objs/etag", nil, nil)
			if resp.StatusCode != 204 || len(b) != 0 {
				t.Errorf("delete #%d = %d %q", i, resp.StatusCode, b)
			}
		}
		resp, b := e.do("GET", "/objs/etag", nil, nil)
		wantError(t, resp, b, 404, "NoSuchKey")
	})
	t.Run("large object streams intact", func(t *testing.T) {
		big := make([]byte, 8<<20+123)
		rand.New(rand.NewSource(7)).Read(big)
		e.put("/objs/big", string(big), nil)
		got, resp := e.get("/objs/big")
		if resp.Header.Get("Content-Length") != fmt.Sprint(len(big)) || got != string(big) {
			t.Errorf("large object differs (got %d bytes)", len(got))
		}
	})
}

func TestPutValidation(t *testing.T) {
	e := newEnv(t)
	e.mb("val")
	e.put("/val/existing", "v1", nil)
	tests := []struct {
		name   string
		path   string
		body   string
		h      hdr
		status int
		code   string
		absent string // object that must not exist afterwards
	}{
		{"md5 matches", "/val/md5ok", "abc", hdr{"Content-MD5": md5b64("abc")}, 200, "", ""},
		{"md5 mismatch", "/val/md5bad", "abc", hdr{"Content-MD5": md5b64("other")}, 400, "BadDigest", "md5bad"},
		{"md5 not base64", "/val/md5junk", "abc", hdr{"Content-MD5": "!!!"}, 400, "InvalidDigest", "md5junk"},
		{"md5 wrong length", "/val/md5short", "abc", hdr{"Content-MD5": base64.StdEncoding.EncodeToString([]byte("short"))}, 400, "InvalidDigest", "md5short"},
		{"sha256 matches", "/val/shaok", "abc", hdr{"x-amz-content-sha256": sha256hex("abc")}, 200, "", ""},
		{"sha256 mismatch", "/val/shabad", "abc", hdr{"x-amz-content-sha256": sha256hex("other")}, 400, "XAmzContentSHA256Mismatch", "shabad"},
		{"sha256 junk", "/val/shajunk", "abc", hdr{"x-amz-content-sha256": "nothex"}, 400, "InvalidArgument", "shajunk"},
		{"unsigned payload", "/val/unsigned", "abc", hdr{"x-amz-content-sha256": "UNSIGNED-PAYLOAD"}, 200, "", ""},
		{"copy of a missing source", "/val/copy", "", hdr{"x-amz-copy-source": "/val/no-such-source"}, 404, "NoSuchKey", "copy"},
		{"copy with a bad source", "/val/copybad", "", hdr{"x-amz-copy-source": "nobucketslash"}, 400, "InvalidArgument", "copybad"},
		{"reserved tag key", "/val/tagged", "x", hdr{"x-amz-tagging": "aws:a=b"}, 400, "InvalidTag", "tagged"},
		{"metadata too large", "/val/bigmeta", "x", hdr{"x-amz-meta-big": strings.Repeat("a", 2100)}, 400, "MetadataTooLarge", "bigmeta"},
		{"if-none-match on existing", "/val/existing", "v2", hdr{"If-None-Match": "*"}, 412, "PreconditionFailed", ""},
		{"if-none-match on new", "/val/created-once", "v", hdr{"If-None-Match": "*"}, 200, "", ""},
		{"invalid key", "/val/a//b", "x", nil, 400, "XNanoIOInvalidObjectName", ""},
		{"reserved key", "/val/dir/xl.meta", "x", nil, 400, "XNanoIOInvalidObjectName", ""},
		{"key too long", "/val/" + strings.Repeat("k", 300), "x", nil, 400, "KeyTooLongError", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, body := e.do("PUT", tt.path, strings.NewReader(tt.body), tt.h)
			if tt.code == "" {
				if resp.StatusCode != tt.status {
					t.Fatalf("status %d: %s", resp.StatusCode, body)
				}
			} else {
				wantError(t, resp, body, tt.status, tt.code)
			}
			if tt.absent != "" {
				r, _ := e.do("HEAD", "/val/"+tt.absent, nil, nil)
				if r.StatusCode != 404 {
					t.Errorf("rejected upload left an object behind (HEAD %d)", r.StatusCode)
				}
			}
		})
	}
	if got, _ := e.get("/val/existing"); got != "v1" {
		t.Errorf("existing object changed to %q by a rejected put", got)
	}

	t.Run("missing content-length", func(t *testing.T) {
		req, _ := http.NewRequest("PUT", e.srv.URL+"/val/nolen", io.NopCloser(strings.NewReader("abc")))
		req.ContentLength = -1 // sends Transfer-Encoding: chunked
		e.root.Sign(req, auth.PayloadUnsigned, time.Now())
		resp, b := e.exec(req)
		wantError(t, resp, b, 411, "MissingContentLength")
	})
	t.Run("body shorter than declared", func(t *testing.T) {
		// Sign a 10-byte body, then send only 3 of its bytes and half-close.
		req, _ := http.NewRequest("PUT", e.srv.URL+"/val/short", strings.NewReader("abcdefghij"))
		req.Host = e.host
		e.root.Sign(req, sha256hex("abcdefghij"), time.Now())
		var wire bytes.Buffer
		if err := req.Write(&wire); err != nil {
			t.Fatal(err)
		}
		raw := wire.Bytes()
		raw = raw[:len(raw)-len("defghij")]
		conn, err := net.Dial("tcp", e.host)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.Write(raw)
		conn.(*net.TCPConn).CloseWrite()
		resp, err := http.ReadResponse(bufioReader(conn), &http.Request{Method: "PUT"})
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		wantError(t, resp, b, 400, "IncompleteBody")
		if r, _ := e.do("HEAD", "/val/short", nil, nil); r.StatusCode != 404 {
			t.Error("truncated upload became visible")
		}
	})
}

// streamOpts shapes a streaming upload built by streamingPut.
type streamOpts struct {
	kind     string   // auth.PayloadStreaming*; default signed
	parts    []string // chunk bodies; the final empty chunk is added
	decoded  string   // x-amz-decoded-content-length; default sum of parts, "-" omits
	trailers []string // "name:value" lines for the TRAILER variants
	headers  hdr
	// mutate edits the chunk list before encoding, to model tampering.
	mutate func(chunks []encChunk) []encChunk
}

type encChunk struct {
	data string
	sig  string
	// final marks the zero-length chunk.
	final bool
}

// streamingPut signs a streaming PUT as root and returns the response.
func (e *testEnv) streamingPut(path string, o streamOpts) (*http.Response, []byte) {
	e.t.Helper()
	kind := o.kind
	if kind == "" {
		kind = auth.PayloadStreamingSigned
	}
	now := time.Now()
	total := 0
	for _, p := range o.parts {
		total += len(p)
	}
	req, _ := http.NewRequest("PUT", e.srv.URL+path, nil)
	req.Header.Set("Content-Encoding", "aws-chunked")
	req.Header.Set("Accept-Encoding", "identity")
	switch o.decoded {
	case "":
		req.Header.Set("X-Amz-Decoded-Content-Length", fmt.Sprint(total))
	case "-":
	default:
		req.Header.Set("X-Amz-Decoded-Content-Length", o.decoded)
	}
	for k, v := range o.headers {
		req.Header.Set(k, v)
	}
	seed := e.root.Sign(req, kind, now)

	signed := kind == auth.PayloadStreamingSigned || kind == auth.PayloadStreamingTrailer
	cs := e.root.NewChunkSigner(seed, now, kind == auth.PayloadStreamingTrailer)
	var chunks []encChunk
	for _, p := range o.parts {
		c := encChunk{data: p}
		if signed {
			c.sig = cs.SignChunk([]byte(p))
		}
		chunks = append(chunks, c)
	}
	final := encChunk{final: true}
	if signed {
		final.sig = cs.SignChunk(nil)
	}
	chunks = append(chunks, final)
	if o.mutate != nil {
		chunks = o.mutate(chunks)
	}

	var body strings.Builder
	for _, c := range chunks {
		ext := ""
		if c.sig != "" {
			ext = ";chunk-signature=" + c.sig
		}
		fmt.Fprintf(&body, "%x%s\r\n", len(c.data), ext)
		if !c.final || c.data != "" {
			body.WriteString(c.data + "\r\n")
		}
		if c.final {
			canonical := ""
			for _, l := range o.trailers {
				body.WriteString(l + "\r\n")
				name, value, _ := strings.Cut(l, ":")
				canonical += strings.ToLower(name) + ":" + value + "\n"
			}
			if kind == auth.PayloadStreamingTrailer {
				fmt.Fprintf(&body, "x-amz-trailer-signature:%s\r\n", cs.SignTrailer(canonical))
			}
			body.WriteString("\r\n")
		}
	}
	req.Body = io.NopCloser(strings.NewReader(body.String()))
	req.ContentLength = int64(body.Len())
	return e.exec(req)
}

func TestSignedStreamingUploads(t *testing.T) {
	e := newEnv(t)
	e.mb("stream")
	flip := func(sig string) string {
		b := []byte(sig)
		if b[0] == 'a' {
			b[0] = 'b'
		} else {
			b[0] = 'a'
		}
		return string(b)
	}
	payload := strings.Repeat("0123456789", 7000) // 70,000 bytes in three chunks
	three := []string{payload[:30000], payload[30000:60000], payload[60000:]}

	good := []struct {
		name string
		o    streamOpts
		want string
	}{
		{"signed chunks", streamOpts{parts: []string{"hello", " world"}}, "hello world"},
		{"signed, multi-chunk body", streamOpts{parts: three}, payload},
		{"signed empty payload", streamOpts{parts: nil}, ""},
		{"signed with trailer", streamOpts{kind: auth.PayloadStreamingTrailer, parts: []string{"hello", " world"},
			trailers: []string{"x-amz-checksum-crc32:AAAAAA=="}}, "hello world"},
		{"signed with no trailer lines", streamOpts{kind: auth.PayloadStreamingTrailer, parts: []string{"abc"}}, "abc"},
		{"unsigned with trailer", streamOpts{kind: auth.PayloadStreamingUnsigned, parts: []string{"hello", " world"},
			trailers: []string{"x-amz-checksum-crc32:AAAAAA=="}}, "hello world"},
		{"real content encoding survives", streamOpts{parts: []string{"zipped"},
			headers: hdr{"Content-Encoding": "gzip, aws-chunked"}}, "zipped"},
	}
	for i, tt := range good {
		t.Run(tt.name, func(t *testing.T) {
			path := fmt.Sprintf("/stream/ok%d", i)
			resp, body := e.streamingPut(path, tt.o)
			if resp.StatusCode != 200 {
				t.Fatalf("status %d: %s", resp.StatusCode, body)
			}
			got, r := e.get(path)
			if got != tt.want {
				t.Errorf("stored %d bytes, want %d", len(got), len(tt.want))
			}
			if r.Header.Get("ETag") != `"`+md5hex(tt.want)+`"` {
				t.Errorf("ETag = %s", r.Header.Get("ETag"))
			}
			if enc := r.Header.Get("Content-Encoding"); enc != "" && enc != "gzip" {
				t.Errorf("transport encoding leaked into metadata: %q", enc)
			}
		})
	}

	bad := []struct {
		name   string
		o      streamOpts
		status int
		code   string
	}{
		{"chunk data modified", streamOpts{parts: three, mutate: func(c []encChunk) []encChunk {
			c[1].data = strings.Replace(c[1].data, "0", "X", 1)
			return c
		}}, 403, "SignatureDoesNotMatch"},
		{"chunk signature modified", streamOpts{parts: three, mutate: func(c []encChunk) []encChunk {
			c[0].sig = flip(c[0].sig)
			return c
		}}, 403, "SignatureDoesNotMatch"},
		{"chunks reordered", streamOpts{parts: three, mutate: func(c []encChunk) []encChunk {
			c[0], c[1] = c[1], c[0]
			return c
		}}, 403, "SignatureDoesNotMatch"},
		{"chunk dropped", streamOpts{parts: three, decoded: "40000", mutate: func(c []encChunk) []encChunk {
			return append(c[:1], c[2:]...)
		}}, 403, "SignatureDoesNotMatch"},
		{"final chunk signature modified", streamOpts{parts: three, mutate: func(c []encChunk) []encChunk {
			c[len(c)-1].sig = flip(c[len(c)-1].sig)
			return c
		}}, 403, "SignatureDoesNotMatch"},
		{"chunk without signature", streamOpts{parts: three, mutate: func(c []encChunk) []encChunk {
			c[0].sig = ""
			return c
		}}, 403, "SignatureDoesNotMatch"},
		{"final chunk missing", streamOpts{parts: three, mutate: func(c []encChunk) []encChunk {
			return c[:len(c)-1]
		}}, 400, "IncompleteBody"},
		{"more data than declared", streamOpts{parts: three, decoded: "100", mutate: nil}, 400, "InvalidRequest"},
		{"fewer bytes than declared", streamOpts{parts: []string{"short"}, decoded: "50"}, 400, "IncompleteBody"},
		{"missing decoded length", streamOpts{parts: []string{"x"}, decoded: "-"}, 411, "MissingContentLength"},
	}
	for i, tt := range bad {
		t.Run(tt.name, func(t *testing.T) {
			path := fmt.Sprintf("/stream/bad%d", i)
			resp, body := e.streamingPut(path, tt.o)
			wantError(t, resp, body, tt.status, tt.code)
			if r, _ := e.do("HEAD", path, nil, nil); r.StatusCode != 404 {
				t.Errorf("rejected streaming upload left an object (HEAD %d)", r.StatusCode)
			}
		})
	}

	t.Run("a trailer edited after signing is rejected", func(t *testing.T) {
		now := time.Now()
		req, _ := http.NewRequest("PUT", e.srv.URL+"/stream/trailer-tamper", nil)
		req.Header.Set("Content-Encoding", "aws-chunked")
		req.Header.Set("X-Amz-Decoded-Content-Length", "3")
		seed := e.root.Sign(req, auth.PayloadStreamingTrailer, now)
		cs := e.root.NewChunkSigner(seed, now, true)
		c1 := cs.SignChunk([]byte("abc"))
		c2 := cs.SignChunk(nil)
		tsig := cs.SignTrailer("x-amz-checksum-crc32:AAAAAA==\n")
		body := fmt.Sprintf("3;chunk-signature=%s\r\nabc\r\n0;chunk-signature=%s\r\n"+
			"x-amz-checksum-crc32:ZZZZZZ==\r\nx-amz-trailer-signature:%s\r\n\r\n", c1, c2, tsig)
		req.Body = io.NopCloser(strings.NewReader(body))
		req.ContentLength = int64(len(body))
		resp, b := e.exec(req)
		wantError(t, resp, b, 403, "SignatureDoesNotMatch")
		if r, _ := e.do("HEAD", "/stream/trailer-tamper", nil, nil); r.StatusCode != 404 {
			t.Error("object committed despite a bad trailer signature")
		}
	})
	t.Run("chunks signed for a different request are rejected", func(t *testing.T) {
		// Capture valid chunk signatures for one object, replay them on another.
		now := time.Now()
		sign := func(path string) (*http.Request, string) {
			req, _ := http.NewRequest("PUT", e.srv.URL+path, nil)
			req.Header.Set("Content-Encoding", "aws-chunked")
			req.Header.Set("X-Amz-Decoded-Content-Length", "3")
			return req, e.root.Sign(req, auth.PayloadStreamingSigned, now)
		}
		_, seedA := sign("/stream/a")
		reqB, _ := sign("/stream/b")
		csA := e.root.NewChunkSigner(seedA, now, false)
		body := fmt.Sprintf("3;chunk-signature=%s\r\nabc\r\n0;chunk-signature=%s\r\n\r\n",
			csA.SignChunk([]byte("abc")), csA.SignChunk(nil))
		reqB.Body = io.NopCloser(strings.NewReader(body))
		reqB.ContentLength = int64(len(body))
		resp, b := e.exec(reqB)
		wantError(t, resp, b, 403, "SignatureDoesNotMatch")
	})
	t.Run("aws-chunked needs a STREAMING payload hash", func(t *testing.T) {
		resp, b := e.do("PUT", "/stream/mismatch", strings.NewReader("3\r\nabc\r\n0\r\n\r\n"), hdr{
			"Content-Encoding": "aws-chunked", "x-amz-decoded-content-length": "3"})
		wantError(t, resp, b, 400, "InvalidRequest")
	})
}

func TestRangeRequests(t *testing.T) {
	e := newEnv(t)
	e.mb("rng")
	e.put("/rng/digits", "0123456789", nil)
	tests := []struct {
		name         string
		rng          string
		status       int
		body         string
		contentRange string
		code         string
	}{
		{"first five", "bytes=0-4", 206, "01234", "bytes 0-4/10", ""},
		{"middle", "bytes=3-6", 206, "3456", "bytes 3-6/10", ""},
		{"open ended", "bytes=7-", 206, "789", "bytes 7-9/10", ""},
		{"suffix", "bytes=-3", 206, "789", "bytes 7-9/10", ""},
		{"suffix longer than object", "bytes=-100", 206, "0123456789", "bytes 0-9/10", ""},
		{"end clamped", "bytes=8-100", 206, "89", "bytes 8-9/10", ""},
		{"single byte", "bytes=9-9", 206, "9", "bytes 9-9/10", ""},
		{"start past end", "bytes=10-", 416, "", "", "InvalidRange"},
		{"zero suffix", "bytes=-0", 416, "", "", "InvalidRange"},
		{"wrong unit is ignored", "items=0-1", 200, "0123456789", "", ""},
		{"garbage is ignored", "bytes=abc", 200, "0123456789", "", ""},
		{"reversed is ignored", "bytes=5-2", 200, "0123456789", "", ""},
		{"multiple ranges served whole", "bytes=0-1,4-5", 200, "0123456789", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, body := e.do("GET", "/rng/digits", nil, hdr{"Range": tt.rng})
			if tt.code != "" {
				wantError(t, resp, body, tt.status, tt.code)
				return
			}
			if resp.StatusCode != tt.status || string(body) != tt.body {
				t.Fatalf("got %d %q, want %d %q", resp.StatusCode, body, tt.status, tt.body)
			}
			if got := resp.Header.Get("Content-Range"); got != tt.contentRange {
				t.Errorf("Content-Range = %q, want %q", got, tt.contentRange)
			}
			if resp.Header.Get("Content-Length") != fmt.Sprint(len(tt.body)) {
				t.Errorf("Content-Length = %s", resp.Header.Get("Content-Length"))
			}
			if resp.Header.Get("ETag") != `"`+md5hex("0123456789")+`"` {
				t.Errorf("ETag describes the wrong thing: %s", resp.Header.Get("ETag"))
			}
		})
	}
	t.Run("HEAD honours range", func(t *testing.T) {
		resp, body := e.do("HEAD", "/rng/digits", nil, hdr{"Range": "bytes=2-4"})
		if resp.StatusCode != 206 || len(body) != 0 || resp.Header.Get("Content-Length") != "3" ||
			resp.Header.Get("Content-Range") != "bytes 2-4/10" {
			t.Errorf("HEAD range = %d len=%s cr=%s", resp.StatusCode, resp.Header.Get("Content-Length"), resp.Header.Get("Content-Range"))
		}
	})
	t.Run("empty object", func(t *testing.T) {
		e.put("/rng/empty", "", nil)
		resp, body := e.do("GET", "/rng/empty", nil, hdr{"Range": "bytes=0-0"})
		wantError(t, resp, body, 416, "InvalidRange")
	})
}

func TestConditionalRequests(t *testing.T) {
	e := newEnv(t)
	e.mb("cnd")
	e.put("/cnd/k", "content", nil)
	etag := `"` + md5hex("content") + `"`
	past := time.Now().Add(-48 * time.Hour).UTC().Format(http.TimeFormat)
	future := time.Now().Add(48 * time.Hour).UTC().Format(http.TimeFormat)
	tests := []struct {
		name   string
		h      hdr
		status int
	}{
		{"if-match hits", hdr{"If-Match": etag}, 200},
		{"if-match list hits", hdr{"If-Match": `"nope", ` + etag}, 200},
		{"if-match star", hdr{"If-Match": "*"}, 200},
		{"if-match misses", hdr{"If-Match": `"nope"`}, 412},
		{"if-none-match hits", hdr{"If-None-Match": etag}, 304},
		{"if-none-match weak hits", hdr{"If-None-Match": "W/" + etag}, 304},
		{"if-none-match star", hdr{"If-None-Match": "*"}, 304},
		{"if-none-match misses", hdr{"If-None-Match": `"nope"`}, 200},
		{"if-modified-since in future", hdr{"If-Modified-Since": future}, 304},
		{"if-modified-since in past", hdr{"If-Modified-Since": past}, 200},
		{"if-unmodified-since in past", hdr{"If-Unmodified-Since": past}, 412},
		{"if-unmodified-since in future", hdr{"If-Unmodified-Since": future}, 200},
		{"unparseable date ignored", hdr{"If-Modified-Since": "yesterday"}, 200},
		{"if-match wins over if-unmodified-since", hdr{"If-Match": etag, "If-Unmodified-Since": past}, 200},
		{"if-none-match wins over if-modified-since", hdr{"If-None-Match": `"nope"`, "If-Modified-Since": future}, 200},
		{"failed if-match beats if-none-match", hdr{"If-Match": `"nope"`, "If-None-Match": etag}, 412},
		{"both pass", hdr{"If-Match": etag, "If-None-Match": `"nope"`}, 200},
	}
	for _, tt := range tests {
		for _, method := range []string{"GET", "HEAD"} {
			t.Run(tt.name+"/"+method, func(t *testing.T) {
				resp, body := e.do(method, "/cnd/k", nil, tt.h)
				if resp.StatusCode != tt.status {
					t.Fatalf("status %d, want %d (%s)", resp.StatusCode, tt.status, body)
				}
				switch tt.status {
				case 304:
					if len(body) != 0 || resp.Header.Get("ETag") != etag || resp.Header.Get("Last-Modified") == "" {
						t.Errorf("304 must be empty and carry validators: body=%q hdr=%v", body, resp.Header)
					}
				case 412:
					if method == "GET" {
						wantError(t, resp, body, 412, "PreconditionFailed")
					}
				case 200:
					if method == "GET" && string(body) != "content" {
						t.Errorf("body = %q", body)
					}
				}
			})
		}
	}
}

func TestVirtualHostStyle(t *testing.T) {
	e := newEnv(t)

	t.Run("create bucket via host", func(t *testing.T) {
		resp, body := e.do("PUT", "/", nil, hdr{"Host": "vhbucket.localhost"})
		if resp.StatusCode != 200 {
			t.Fatalf("%d %s", resp.StatusCode, body)
		}
		if r, _ := e.do("HEAD", "/vhbucket", nil, nil); r.StatusCode != 200 {
			t.Errorf("bucket not visible path-style: %d", r.StatusCode)
		}
	})
	t.Run("object round trip across styles", func(t *testing.T) {
		resp, body := e.do("PUT", "/dir/key.txt", strings.NewReader("virtual"), hdr{"Host": "vhbucket.localhost:9000"})
		if resp.StatusCode != 200 {
			t.Fatalf("%d %s", resp.StatusCode, body)
		}
		if got, _ := e.get("/vhbucket/dir/key.txt"); got != "virtual" {
			t.Errorf("path-style read = %q", got)
		}
		resp, body = e.do("GET", "/dir/key.txt", nil, hdr{"Host": "vhbucket.localhost"})
		if resp.StatusCode != 200 || string(body) != "virtual" {
			t.Errorf("virtual-host read = %d %q", resp.StatusCode, body)
		}
	})
	t.Run("bucket listing via host", func(t *testing.T) {
		resp, body := e.do("GET", "/?list-type=2&prefix=dir/", nil, hdr{"Host": "vhbucket.localhost"})
		var r listBucketResultV2
		if err := xml.Unmarshal(body, &r); err != nil || resp.StatusCode != 200 {
			t.Fatalf("%d %v %s", resp.StatusCode, err, body)
		}
		if r.Name != "vhbucket" || len(r.Contents) != 1 || r.Contents[0].Key != "dir/key.txt" {
			t.Errorf("listing = %+v", r)
		}
	})
	t.Run("service listing is still path-style on the bare host", func(t *testing.T) {
		resp, body := e.do("GET", "/", nil, hdr{"Host": "localhost:9000"})
		if resp.StatusCode != 200 || !strings.Contains(string(body), "ListAllMyBucketsResult") {
			t.Errorf("%d %s", resp.StatusCode, body)
		}
	})
	t.Run("unknown domain falls back to path-style", func(t *testing.T) {
		resp, body := e.do("GET", "/", nil, hdr{"Host": "vhbucket.other.test"})
		if resp.StatusCode != 200 || !strings.Contains(string(body), "ListAllMyBucketsResult") {
			t.Errorf("%d %s", resp.StatusCode, body)
		}
	})
	t.Run("missing virtual-host bucket", func(t *testing.T) {
		resp, body := e.do("GET", "/k", nil, hdr{"Host": "nobucket.localhost"})
		er := wantError(t, resp, body, 404, "NoSuchBucket")
		if er.BucketName != "nobucket" {
			t.Errorf("BucketName = %q", er.BucketName)
		}
	})
}

type listed struct {
	keys     []string
	prefixes []string
	next     string
	trunc    bool
}

func (e *testEnv) listV2(query string) (listBucketResultV2, listed) {
	e.t.Helper()
	resp, body := e.do("GET", "/lst?list-type=2&"+query, nil, nil)
	if resp.StatusCode != 200 {
		e.t.Fatalf("list %q: %d %s", query, resp.StatusCode, body)
	}
	var r listBucketResultV2
	if err := xml.Unmarshal(body, &r); err != nil {
		e.t.Fatal(err)
	}
	l := listed{next: r.NextContinuationToken, trunc: r.IsTruncated}
	for _, c := range r.Contents {
		l.keys = append(l.keys, c.Key)
	}
	for _, p := range r.CommonPrefixes {
		l.prefixes = append(l.prefixes, p.Prefix)
	}
	return r, l
}

func TestListObjects(t *testing.T) {
	e := newEnv(t)
	e.mb("lst")
	keys := []string{"a", "a-b", "a/b", "a/c/d", "b", "dir/", "z/1", "z/2", "z/sub/3", "sp ace", "plus+sign", "ünï/cödé"}
	for _, k := range keys {
		e.put("/lst/"+(&url.URL{Path: k}).EscapedPath(), "body-"+k, nil)
	}
	sorted := append([]string(nil), keys...)
	sort.Strings(sorted)

	t.Run("v2 everything", func(t *testing.T) {
		r, l := e.listV2("")
		if strings.Join(l.keys, "|") != strings.Join(sorted, "|") {
			t.Errorf("keys = %q\nwant  %q", l.keys, sorted)
		}
		if r.KeyCount != len(keys) || r.MaxKeys != 1000 || r.IsTruncated || r.Name != "lst" {
			t.Errorf("envelope: %+v", r)
		}
		for _, c := range r.Contents {
			if c.StorageClass != "STANDARD" || c.Owner != nil || !strings.HasPrefix(c.ETag, `"`) {
				t.Errorf("entry %+v", c)
			}
		}
	})
	t.Run("v2 delimiter", func(t *testing.T) {
		r, l := e.listV2("delimiter=/")
		wantKeys := []string{"a", "a-b", "b", "plus+sign", "sp ace"}
		wantPfx := []string{"a/", "dir/", "z/", "ünï/"}
		if strings.Join(l.keys, "|") != strings.Join(wantKeys, "|") || strings.Join(l.prefixes, "|") != strings.Join(wantPfx, "|") {
			t.Errorf("keys=%q prefixes=%q", l.keys, l.prefixes)
		}
		if r.KeyCount != len(wantKeys)+len(wantPfx) || r.Delimiter != "/" {
			t.Errorf("KeyCount=%d Delimiter=%q", r.KeyCount, r.Delimiter)
		}
	})
	t.Run("v2 prefix", func(t *testing.T) {
		_, l := e.listV2("prefix=z/&delimiter=/")
		if strings.Join(l.keys, "|") != "z/1|z/2" || strings.Join(l.prefixes, "|") != "z/sub/" {
			t.Errorf("keys=%q prefixes=%q", l.keys, l.prefixes)
		}
	})
	t.Run("v2 start-after and echo", func(t *testing.T) {
		r, l := e.listV2("start-after=b&prefix=")
		if len(l.keys) == 0 || l.keys[0] != "dir/" || r.StartAfter != "b" {
			t.Errorf("keys=%q StartAfter=%q", l.keys, r.StartAfter)
		}
	})
	t.Run("v2 fetch-owner", func(t *testing.T) {
		r, _ := e.listV2("fetch-owner=true&max-keys=1")
		if r.Contents[0].Owner == nil || r.Contents[0].Owner.ID == "" {
			t.Error("owner missing with fetch-owner=true")
		}
	})
	t.Run("url encoding", func(t *testing.T) {
		r, l := e.listV2("encoding-type=url&prefix=sp&delimiter=/")
		if r.EncodingType != "url" || r.Prefix != "sp" || strings.Join(l.keys, "|") != "sp%20ace" {
			t.Errorf("EncodingType=%q Prefix=%q keys=%q", r.EncodingType, r.Prefix, l.keys)
		}
		_, l = e.listV2("encoding-type=url&prefix=plus&delimiter=/")
		if strings.Join(l.keys, "|") != "plus%2Bsign" {
			t.Errorf("keys=%q", l.keys)
		}
		_, l = e.listV2("encoding-type=url&delimiter=/&prefix=%C3%BC")
		if strings.Join(l.prefixes, "|") != "%C3%BCn%C3%AF/" {
			t.Errorf("prefixes=%q", l.prefixes)
		}
		// Without encoding-type the raw key comes back.
		_, l = e.listV2("prefix=sp&delimiter=/")
		if strings.Join(l.keys, "|") != "sp ace" {
			t.Errorf("unencoded keys=%q", l.keys)
		}
	})
	t.Run("v2 pagination follows continuation tokens", func(t *testing.T) {
		for _, delim := range []string{"", "/"} {
			for _, size := range []int{1, 2, 3, 5} {
				var all []string
				token := ""
				for pages := 0; ; pages++ {
					if pages > 50 {
						t.Fatal("pagination did not terminate")
					}
					q := fmt.Sprintf("max-keys=%d&encoding-type=url", size)
					if delim != "" {
						q += "&delimiter=" + url.QueryEscape(delim)
					}
					if token != "" {
						q += "&continuation-token=" + url.QueryEscape(token)
					}
					r, l := e.listV2(q)
					if r.KeyCount > size {
						t.Fatalf("page of %d exceeds max-keys %d", r.KeyCount, size)
					}
					if token != "" && r.ContinuationToken != token {
						t.Errorf("ContinuationToken echo = %q, want %q", r.ContinuationToken, token)
					}
					all = append(all, l.keys...)
					all = append(all, l.prefixes...)
					if !r.IsTruncated {
						if r.NextContinuationToken != "" {
							t.Error("NextContinuationToken on the last page")
						}
						break
					}
					if r.NextContinuationToken == "" || r.NextContinuationToken == token {
						t.Fatalf("truncated page without a fresh token: %q", r.NextContinuationToken)
					}
					token = r.NextContinuationToken
				}
				_, full := e.listV2("encoding-type=url&delimiter=" + url.QueryEscape(delim))
				want := append(append([]string(nil), full.keys...), full.prefixes...)
				sort.Strings(want)
				sort.Strings(all)
				if strings.Join(all, "|") != strings.Join(want, "|") {
					t.Errorf("delim=%q size=%d: paged %q != full %q", delim, size, all, want)
				}
			}
		}
	})
	t.Run("v2 max-keys=0", func(t *testing.T) {
		r, l := e.listV2("max-keys=0")
		if len(l.keys) != 0 || r.IsTruncated || r.KeyCount != 0 || r.MaxKeys != 0 {
			t.Errorf("max-keys=0 returned %+v", r)
		}
	})
	t.Run("v2 max-keys above cap is clamped", func(t *testing.T) {
		r, _ := e.listV2("max-keys=99999")
		if r.MaxKeys != 1000 {
			t.Errorf("MaxKeys = %d", r.MaxKeys)
		}
	})

	t.Run("v1 listing and marker pagination", func(t *testing.T) {
		var all []string
		marker := ""
		for pages := 0; ; pages++ {
			if pages > 50 {
				t.Fatal("v1 pagination did not terminate")
			}
			resp, body := e.do("GET", "/lst?max-keys=4&marker="+url.QueryEscape(marker), nil, nil)
			var r listBucketResultV1
			if err := xml.Unmarshal(body, &r); err != nil || resp.StatusCode != 200 {
				t.Fatalf("%d %v %s", resp.StatusCode, err, body)
			}
			if r.Marker != marker || r.NextMarker != "" || r.Delimiter != "" {
				t.Errorf("v1 envelope: marker=%q next=%q delim=%q", r.Marker, r.NextMarker, r.Delimiter)
			}
			for _, c := range r.Contents {
				all = append(all, c.Key)
				if c.Owner == nil {
					t.Error("v1 entries carry an Owner")
				}
			}
			if !r.IsTruncated {
				break
			}
			// No delimiter: S3 omits NextMarker; the client uses the last key.
			marker = r.Contents[len(r.Contents)-1].Key
		}
		if strings.Join(all, "|") != strings.Join(sorted, "|") {
			t.Errorf("v1 paged = %q", all)
		}
	})
	t.Run("v1 NextMarker with delimiter", func(t *testing.T) {
		resp, body := e.do("GET", "/lst?delimiter=/&max-keys=2", nil, nil)
		var r listBucketResultV1
		if err := xml.Unmarshal(body, &r); err != nil || resp.StatusCode != 200 {
			t.Fatal(err, string(body))
		}
		if !r.IsTruncated || r.NextMarker == "" || r.Delimiter != "/" {
			t.Errorf("%+v", r)
		}
	})

	errs := []struct {
		name  string
		path  string
		code  string
		state int
	}{
		{"max-keys not a number", "/lst?list-type=2&max-keys=abc", "InvalidArgument", 400},
		{"negative max-keys", "/lst?list-type=2&max-keys=-1", "InvalidArgument", 400},
		{"v1 bad max-keys", "/lst?max-keys=x", "InvalidArgument", 400},
		{"list-type 1", "/lst?list-type=1", "InvalidArgument", 400},
		{"list-type 3", "/lst?list-type=3", "InvalidArgument", 400},
		{"garbage continuation token", "/lst?list-type=2&continuation-token=!!!", "InvalidArgument", 400},
		{"empty continuation token", "/lst?list-type=2&continuation-token=", "InvalidArgument", 400},
		{"bad encoding type", "/lst?list-type=2&encoding-type=base64", "InvalidArgument", 400},
		{"missing bucket v2", "/ghost?list-type=2", "NoSuchBucket", 404},
		{"missing bucket v1", "/ghost", "NoSuchBucket", 404},
		{"missing bucket max-keys=0", "/ghost?list-type=2&max-keys=0", "NoSuchBucket", 404},
	}
	for _, tt := range errs {
		t.Run(tt.name, func(t *testing.T) {
			resp, body := e.do("GET", tt.path, nil, nil)
			wantError(t, resp, body, tt.state, tt.code)
		})
	}
}

func TestDeleteObjects(t *testing.T) {
	e := newEnv(t)
	e.mb("multi")
	for _, k := range []string{"a", "b", "c", "d/e"} {
		e.put("/multi/"+k, "x", nil)
	}
	post := func(path, body string) (*http.Response, []byte) {
		return e.do("POST", path, strings.NewReader(body), nil)
	}
	del := func(quiet bool, keys ...string) string {
		var b strings.Builder
		b.WriteString(`<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`)
		if quiet {
			b.WriteString("<Quiet>true</Quiet>")
		}
		for _, k := range keys {
			b.WriteString("<Object><Key>" + k + "</Key></Object>")
		}
		b.WriteString("</Delete>")
		return b.String()
	}

	t.Run("deletes, reports missing as deleted", func(t *testing.T) {
		resp, body := post("/multi?delete", del(false, "a", "b", "never-existed", "d/e"))
		var r deleteResult
		if err := xml.Unmarshal(body, &r); err != nil || resp.StatusCode != 200 {
			t.Fatalf("%d %v %s", resp.StatusCode, err, body)
		}
		var deleted []string
		for _, d := range r.Deleted {
			deleted = append(deleted, d.Key)
		}
		if strings.Join(deleted, ",") != "a,b,never-existed,d/e" || len(r.Errors) != 0 {
			t.Errorf("deleted=%v errors=%v", deleted, r.Errors)
		}
		if r, _ := e.do("HEAD", "/multi/a", nil, nil); r.StatusCode != 404 {
			t.Error("a survived")
		}
		if r, _ := e.do("HEAD", "/multi/c", nil, nil); r.StatusCode != 200 {
			t.Error("c was deleted but not requested")
		}
	})
	t.Run("quiet mode", func(t *testing.T) {
		resp, body := post("/multi?delete", del(true, "c"))
		var r deleteResult
		if err := xml.Unmarshal(body, &r); err != nil || resp.StatusCode != 200 || len(r.Deleted) != 0 || len(r.Errors) != 0 {
			t.Errorf("quiet result %d %+v %v", resp.StatusCode, r, err)
		}
		if r, _ := e.do("HEAD", "/multi/c", nil, nil); r.StatusCode != 404 {
			t.Error("c survived a quiet delete")
		}
	})
	t.Run("per-key errors do not abort the batch", func(t *testing.T) {
		e.put("/multi/keep", "x", nil)
		body := `<Delete><Object><Key>a//b</Key></Object><Object><Key>keep</Key></Object>` +
			`<Object><Key>v</Key><VersionId>abc</VersionId></Object></Delete>`
		resp, b := post("/multi?delete", body)
		var r deleteResult
		if err := xml.Unmarshal(b, &r); err != nil || resp.StatusCode != 200 {
			t.Fatalf("%d %v %s", resp.StatusCode, err, b)
		}
		codes := map[string]string{}
		for _, x := range r.Errors {
			codes[x.Key] = x.Code
		}
		if codes["a//b"] != "XNanoIOInvalidObjectName" || codes["v"] != "InvalidArgument" {
			t.Errorf("errors = %+v", r.Errors)
		}
		if len(r.Deleted) != 1 || r.Deleted[0].Key != "keep" {
			t.Errorf("deleted = %+v", r.Deleted)
		}
	})
	t.Run("rejects bad requests", func(t *testing.T) {
		var many strings.Builder
		many.WriteString("<Delete>")
		for i := 0; i < 1001; i++ {
			many.WriteString("<Object><Key>k</Key></Object>")
		}
		many.WriteString("</Delete>")
		tests := []struct {
			name, path, body string
			status           int
			code             string
		}{
			{"malformed xml", "/multi?delete", "<Delete><Object>", 400, "MalformedXML"},
			{"no objects", "/multi?delete", "<Delete></Delete>", 400, "MalformedXML"},
			{"over 1000 keys", "/multi?delete", many.String(), 400, "MalformedXML"},
			{"missing bucket", "/ghost?delete", del(false, "a"), 404, "NoSuchBucket"},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				resp, b := post(tt.path, tt.body)
				wantError(t, resp, b, tt.status, tt.code)
			})
		}
	})
}

func TestUnsupportedFeaturesAreRefused(t *testing.T) {
	e := newEnv(t)
	e.mb("uns")
	e.put("/uns/obj", "original", nil)
	tests := []struct {
		method, path string
	}{
		{"GET", "/uns/obj?partNumber=2"}, // reading one part of a finished object
		{"PUT", "/uns/obj?partNumber=1"}, // a part number with no upload id
		{"POST", "/uns/obj?select&select-type=2"},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			resp, body := e.do(tt.method, tt.path, strings.NewReader("x"), nil)
			wantError(t, resp, body, 501, "NotImplemented")
		})
	}
	if r, _ := e.do("HEAD", "/ghostbucket", nil, nil); r.StatusCode != 404 {
		t.Error("PUT /ghostbucket?acl created a bucket")
	}
	if got, _ := e.get("/uns/obj"); got != "original" {
		t.Errorf("a refused request modified the object: %q", got)
	}
	// Version IDs are validated, and an unknown (well-formed) one is not found.
	resp, body := e.do("GET", "/uns/obj?versionId=abc", nil, nil)
	wantError(t, resp, body, 400, "InvalidArgument")
	resp, body = e.do("GET", "/uns/obj?versionId=9f0c1b9e-1111-4222-8333-444455556666", nil, nil)
	wantError(t, resp, body, 404, "NoSuchVersion")
}

func TestMethodNotAllowed(t *testing.T) {
	e := newEnv(t)
	e.mb("mna")
	tests := []struct{ method, path string }{
		{"POST", "/"}, {"PUT", "/"}, {"DELETE", "/"},
		{"POST", "/mna"}, {"PATCH", "/mna"}, {"OPTIONS", "/mna"},
		{"POST", "/mna/k"}, {"PATCH", "/mna/k"}, {"OPTIONS", "/mna/k"},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			resp, body := e.do(tt.method, tt.path, nil, nil)
			wantError(t, resp, body, 405, "MethodNotAllowed")
		})
	}
}

// failing replaces selected StorageAPI methods with a fixed error or panic.
type failing struct {
	storage.StorageAPI
	err      error
	panicMsg string
}

func (f failing) fail() error {
	if f.panicMsg != "" {
		panic(f.panicMsg)
	}
	return f.err
}
func (f failing) ListBuckets(context.Context) ([]storage.BucketInfo, error) { return nil, f.fail() }
func (f failing) StatObject(context.Context, string, string, storage.GetOptions) (storage.ObjectInfo, error) {
	return storage.ObjectInfo{}, f.fail()
}
func (f failing) GetObject(context.Context, string, string, storage.GetOptions) (io.ReadCloser, storage.ObjectInfo, error) {
	return nil, storage.ObjectInfo{}, f.fail()
}
func (f failing) PutObject(_ context.Context, _, _ string, r io.Reader, _ int64, _ storage.PutOptions) (storage.ObjectInfo, error) {
	io.Copy(io.Discard, r)
	return storage.ObjectInfo{}, f.fail()
}
func (f failing) DeleteObject(context.Context, string, string, storage.DeleteOptions) (storage.DeleteResult, error) {
	return storage.DeleteResult{}, f.fail()
}

func TestStorageFailuresBecomeS3Errors(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{"lock timeout", storage.ErrLockTimeout, 503, "SlowDown"},
		{"disk full", storage.Wrap(storage.ErrDiskFull, "b", "k"), 507, "XNanoIOStorageFull"},
		{"backend closed", storage.ErrBackendUnavailable, 503, "ServiceUnavailable"},
		{"corruption", fmt.Errorf("%w: /secret/disk/path", storage.ErrCorrupted), 500, "InternalError"},
		{"unknown failure", errors.New("raw failure at /secret/disk/path"), 500, "InternalError"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := serve(t, failing{err: tt.err}, nil)
			for _, call := range []struct{ method, path string }{
				{"GET", "/"}, {"GET", "/b/k"}, {"PUT", "/b/k"}, {"DELETE", "/b/k"},
			} {
				resp, body := e.do(call.method, call.path, strings.NewReader("data"), nil)
				wantError(t, resp, body, tt.status, tt.code)
				if strings.Contains(string(body), "secret") {
					t.Errorf("%s %s leaked internals: %s", call.method, call.path, body)
				}
			}
			resp, body := e.do("HEAD", "/b/k", nil, nil)
			wantError(t, resp, body, tt.status, "")
		})
	}
	t.Run("panic is contained", func(t *testing.T) {
		e := serve(t, failing{panicMsg: "boom /secret"}, nil)
		resp, body := e.do("GET", "/b/k", nil, nil)
		wantError(t, resp, body, 500, "InternalError")
		if strings.Contains(string(body), "boom") || strings.Contains(string(body), "secret") {
			t.Errorf("panic text leaked: %s", body)
		}
		// The server survives and keeps answering.
		resp, body = e.do("GET", "/b/k", nil, nil)
		wantError(t, resp, body, 500, "InternalError")
	})
}

func TestEveryResponseCarriesIdentity(t *testing.T) {
	e := newEnv(t)
	e.mb("idb")
	seen := map[string]bool{}
	for _, c := range []struct{ method, path string }{
		{"GET", "/"}, {"HEAD", "/idb"}, {"GET", "/idb?list-type=2"}, {"GET", "/idb/missing"},
		{"POST", "/"}, {"PUT", "/idb/k"}, {"DELETE", "/idb/k"},
	} {
		resp, _ := e.do(c.method, c.path, nil, nil)
		id := resp.Header.Get("x-amz-request-id")
		if id == "" || resp.Header.Get("x-amz-id-2") == "" || resp.Header.Get("Server") != "NanoIO" {
			t.Errorf("%s %s: missing identity headers %v", c.method, c.path, resp.Header)
		}
		if seen[id] {
			t.Errorf("request id %s reused", id)
		}
		seen[id] = true
	}
}

func bufioReader(c net.Conn) *bufio.Reader { return bufio.NewReader(c) }
