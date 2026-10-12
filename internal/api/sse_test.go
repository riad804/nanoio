package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nanoio/internal/bucket/nslock"
	"nanoio/internal/kms"
	"nanoio/internal/sse"
	"nanoio/internal/storage"
	"nanoio/internal/storage/fs"
	"nanoio/internal/storage/xl"
)

func randKey() []byte {
	b := make([]byte, 32)
	rand.Read(b)
	return b
}

func randString(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return string(b)
}

func newLocalKMS(t *testing.T, keys map[string][]kms.LocalKey) *kms.Local {
	t.Helper()
	l, err := kms.NewLocal(keys)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func defaultKMS(t *testing.T) *kms.Local {
	return newLocalKMS(t, map[string][]kms.LocalKey{
		"default": {{Version: 1, Key: randKey()}},
		"other":   {{Version: 1, Key: randKey()}},
	})
}

// sseEnv serves a backend ("fs" or "xl") with a KMS and SSE-C over plain
// HTTP allowed, which is what the httptest listener can do.
func sseEnv(t *testing.T, backend string, mutate ...func(*Options)) *testEnv {
	t.Helper()
	opts := func(o *Options) {
		o.KMS, o.DefaultKMSKey, o.AllowInsecureSSEC = defaultKMS(t), "default", true
	}
	all := append([]func(*Options){opts}, mutate...)
	switch backend {
	case "fs":
		be, err := fs.New(t.TempDir(), fs.Options{Locker: nslock.New(5 * time.Second), Logger: quiet})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { be.Close() })
		return serve(t, be, be, all...)
	case "xl":
		dirs := make([]string, 4)
		for i := range dirs {
			dirs[i] = t.TempDir()
		}
		x, err := xl.New(dirs, xl.Options{Locker: nslock.New(5 * time.Second), Logger: quiet, ParityBlocks: 2, ScanInterval: -1,
			StorageClasses: map[string]int{"LIMITED": 1}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { x.Close() })
		e := serve(t, x, nil, all...)
		e.drives = dirs
		return e
	}
	t.Fatalf("unknown backend %q", backend)
	return nil
}

func eachBackend(t *testing.T, fn func(t *testing.T, e *testEnv)) {
	for _, b := range []string{"fs", "xl"} {
		t.Run(b, func(t *testing.T) { fn(t, sseEnv(t, b)) })
	}
}

func ssecH(key []byte) hdr {
	return hdr{
		"x-amz-server-side-encryption-customer-algorithm": "AES256",
		"x-amz-server-side-encryption-customer-key":       base64.StdEncoding.EncodeToString(key),
		"x-amz-server-side-encryption-customer-key-MD5":   md5b64(string(key)),
	}
}

func ssecCopyH(key []byte) hdr {
	return hdr{
		"x-amz-copy-source-server-side-encryption-customer-algorithm": "AES256",
		"x-amz-copy-source-server-side-encryption-customer-key":       base64.StdEncoding.EncodeToString(key),
		"x-amz-copy-source-server-side-encryption-customer-key-MD5":   md5b64(string(key)),
	}
}

func merge(hs ...hdr) hdr {
	out := hdr{}
	for _, h := range hs {
		for k, v := range h {
			out[k] = v
		}
	}
	return out
}

// stored returns the bytes and metadata the backend holds for an object.
func (e *testEnv) stored(bucket, key string) ([]byte, storage.ObjectInfo) {
	e.t.Helper()
	rc, info, err := e.st.GetObject(context.Background(), bucket, key, storage.GetOptions{})
	if err != nil {
		e.t.Fatalf("storage GetObject %s/%s: %v", bucket, key, err)
	}
	defer rc.Close()
	b, err := io.ReadAll(rc)
	if err != nil {
		e.t.Fatal(err)
	}
	return b, info
}

// modes the round trip tests cover.
type sseCase struct {
	name string
	h    func() hdr
	want func(t *testing.T, resp *http.Response)
}

func sseCases() []sseCase {
	ckey := randKey()
	_ = ckey
	return []sseCase{
		{"plain", func() hdr { return nil }, func(t *testing.T, r *http.Response) {
			if r.Header.Get("x-amz-server-side-encryption") != "" {
				t.Errorf("plain object reports encryption %q", r.Header.Get("x-amz-server-side-encryption"))
			}
		}},
		{"sse-s3", func() hdr { return hdr{"x-amz-server-side-encryption": "AES256"} }, func(t *testing.T, r *http.Response) {
			if r.Header.Get("x-amz-server-side-encryption") != "AES256" ||
				r.Header.Get("x-amz-server-side-encryption-aws-kms-key-id") != "arn:aws:kms:default" {
				t.Errorf("SSE-S3 headers = %v", r.Header)
			}
		}},
		{"sse-kms", func() hdr {
			return hdr{
				"x-amz-server-side-encryption":                "aws:kms",
				"x-amz-server-side-encryption-aws-kms-key-id": "other",
				"x-amz-server-side-encryption-context":        base64.StdEncoding.EncodeToString([]byte(`{"team":"blue"}`)),
			}
		}, func(t *testing.T, r *http.Response) {
			if r.Header.Get("x-amz-server-side-encryption") != "aws:kms" ||
				r.Header.Get("x-amz-server-side-encryption-aws-kms-key-id") != "arn:aws:kms:other" {
				t.Errorf("SSE-KMS headers = %v", r.Header)
			}
			ctx, _ := base64.StdEncoding.DecodeString(r.Header.Get("x-amz-server-side-encryption-context"))
			if string(ctx) != `{"team":"blue"}` {
				t.Errorf("context header = %q", ctx)
			}
		}},
	}
}

func TestSSERoundTrip(t *testing.T) {
	eachBackend(t, func(t *testing.T, e *testEnv) {
		e.mb("rtbucket")
		sizes := []int{0, 1, 65535, 65536, 65537, 200000}
		for _, c := range sseCases() {
			for _, n := range sizes {
				key := fmt.Sprintf("%s-%d", c.name, n)
				body := randString(n)
				resp, b := e.do("PUT", "/rtbucket/"+key, strings.NewReader(body), c.h())
				if resp.StatusCode != 200 {
					t.Fatalf("%s PUT: %d %s", key, resp.StatusCode, b)
				}
				c.want(t, resp)
				if got := resp.Header.Get("ETag"); got != `"`+md5hex(body)+`"` {
					t.Errorf("%s PUT ETag = %s, want plaintext MD5", key, got)
				}
				got, gresp := e.get("/rtbucket/" + key)
				if gresp.StatusCode != 200 || got != body {
					t.Fatalf("%s GET: %d, equal=%v", key, gresp.StatusCode, got == body)
				}
				c.want(t, gresp)
				if gresp.Header.Get("ETag") != `"`+md5hex(body)+`"` || gresp.Header.Get("Content-Length") != fmt.Sprint(n) {
					t.Errorf("%s GET ETag %s length %s", key, gresp.Header.Get("ETag"), gresp.Header.Get("Content-Length"))
				}
				hresp, _ := e.do("HEAD", "/rtbucket/"+key, nil, nil)
				if hresp.StatusCode != 200 || hresp.Header.Get("Content-Length") != fmt.Sprint(n) {
					t.Errorf("%s HEAD: %d length %s", key, hresp.StatusCode, hresp.Header.Get("Content-Length"))
				}
				c.want(t, hresp)

				// What is on disk is ciphertext, with no reserved key leaked.
				raw, info := e.stored("rtbucket", key)
				if c.name == "plain" {
					if string(raw) != body || sse.Encrypted(info.UserDefined) {
						t.Errorf("%s: plain object was altered", key)
					}
					continue
				}
				if int64(len(raw)) != sse.CipherSize(int64(n)) {
					t.Errorf("%s stored %d bytes, want %d", key, len(raw), sse.CipherSize(int64(n)))
				}
				if n >= 64 && strings.Contains(string(raw), body[:64]) {
					t.Errorf("%s: plaintext found in stored bytes", key)
				}
				if info.ETag == md5hex(body) && n > 0 {
					t.Errorf("%s: stored ETag is the plaintext MD5", key)
				}
				for k := range hdrToMap(gresp.Header) {
					if strings.HasPrefix(strings.ToLower(k), "x-nanoio-internal") {
						t.Errorf("%s: reserved header %s leaked", key, k)
					}
				}
			}
		}
		// A listing reports plaintext sizes.
		resp, b := e.do("GET", "/rtbucket?list-type=2&prefix=sse-s3-", nil, nil)
		if resp.StatusCode != 200 {
			t.Fatal(string(b))
		}
		for _, n := range sizes {
			if !strings.Contains(string(b), fmt.Sprintf("<Key>sse-s3-%d</Key>", n)) ||
				!strings.Contains(string(b), fmt.Sprintf("<Size>%d</Size>", n)) {
				t.Errorf("listing lacks sse-s3-%d with size %d", n, n)
			}
		}
	})
}

func hdrToMap(h http.Header) map[string]string {
	m := map[string]string{}
	for k, v := range h {
		m[k] = strings.Join(v, ",")
	}
	return m
}

func TestSSECRoundTripAndKeyChecks(t *testing.T) {
	eachBackend(t, func(t *testing.T, e *testEnv) {
		e.mb("ssec")
		key := randKey()
		body := randString(150000)
		resp, b := e.do("PUT", "/ssec/o", strings.NewReader(body), ssecH(key))
		if resp.StatusCode != 200 {
			t.Fatalf("PUT: %d %s", resp.StatusCode, b)
		}
		if resp.Header.Get("x-amz-server-side-encryption-customer-algorithm") != "AES256" ||
			resp.Header.Get("x-amz-server-side-encryption-customer-key-MD5") != md5b64(string(key)) {
			t.Errorf("PUT headers = %v", resp.Header)
		}
		// Right key.
		gresp, gb := e.do("GET", "/ssec/o", nil, ssecH(key))
		if gresp.StatusCode != 200 || string(gb) != body {
			t.Fatalf("GET with key: %d", gresp.StatusCode)
		}
		// Wrong key: 403.
		r, b := e.do("GET", "/ssec/o", nil, ssecH(randKey()))
		wantError(t, r, b, 403, "AccessDenied")
		r, _ = e.do("HEAD", "/ssec/o", nil, ssecH(randKey()))
		if r.StatusCode != 403 {
			t.Errorf("HEAD with wrong key = %d", r.StatusCode)
		}
		// No key: 400.
		r, b = e.do("GET", "/ssec/o", nil, nil)
		wantError(t, r, b, 400, "InvalidRequest")
		// MD5 mismatch: 400.
		bad := ssecH(key)
		bad["x-amz-server-side-encryption-customer-key-MD5"] = md5b64("something else")
		r, b = e.do("GET", "/ssec/o", nil, bad)
		wantError(t, r, b, 400, "InvalidArgument")
		r, b = e.do("PUT", "/ssec/o2", strings.NewReader("x"), bad)
		wantError(t, r, b, 400, "InvalidArgument")
		// Malformed: wrong algorithm, short key, partial set.
		h := ssecH(key)
		h["x-amz-server-side-encryption-customer-algorithm"] = "AES128"
		r, b = e.do("PUT", "/ssec/o2", strings.NewReader("x"), h)
		wantError(t, r, b, 400, "InvalidArgument")
		short := []byte("short-key")
		r, b = e.do("PUT", "/ssec/o2", strings.NewReader("x"), ssecH(short))
		wantError(t, r, b, 400, "InvalidArgument")
		h = ssecH(key)
		delete(h, "x-amz-server-side-encryption-customer-key-MD5")
		r, b = e.do("PUT", "/ssec/o2", strings.NewReader("x"), h)
		wantError(t, r, b, 400, "InvalidArgument")
		// SSE-C headers for an object that is not SSE-C.
		e.put("/ssec/plain", "p", nil)
		r, b = e.do("GET", "/ssec/plain", nil, ssecH(key))
		wantError(t, r, b, 400, "InvalidRequest")
		// SSE-C combined with another mode.
		r, b = e.do("PUT", "/ssec/o3", strings.NewReader("x"), merge(ssecH(key), hdr{"x-amz-server-side-encryption": "AES256"}))
		wantError(t, r, b, 400, "InvalidArgument")
		// Write-side headers on a read.
		r, b = e.do("GET", "/ssec/plain", nil, hdr{"x-amz-server-side-encryption": "AES256"})
		wantError(t, r, b, 400, "InvalidArgument")
		// The key is never stored: nothing in the metadata contains it.
		_, info := e.stored("ssec", "o")
		for k, v := range info.UserDefined {
			if strings.Contains(v, base64.StdEncoding.EncodeToString(key)) {
				t.Errorf("metadata %s contains the key", k)
			}
		}
		if _, ok := info.UserDefined[sse.KeyKMSWrapped]; ok {
			t.Error("SSE-C object has a KMS wrap")
		}
	})
}

func TestSSECRequiresTLSUnlessAllowed(t *testing.T) {
	e := sseEnv(t, "fs", func(o *Options) { o.AllowInsecureSSEC = false })
	e.mb("tls")
	r, b := e.do("PUT", "/tls/o", strings.NewReader("x"), ssecH(randKey()))
	wantError(t, r, b, 400, "InvalidRequest")
	// SSE-S3 is unaffected.
	r, _ = e.do("PUT", "/tls/o", strings.NewReader("x"), hdr{"x-amz-server-side-encryption": "AES256"})
	if r.StatusCode != 200 {
		t.Errorf("SSE-S3 PUT = %d", r.StatusCode)
	}
}

func TestSSEWithoutKMS(t *testing.T) {
	e := sseEnv(t, "fs", func(o *Options) { o.KMS, o.DefaultKMSKey = nil, "" })
	e.mb("nokms")
	r, b := e.do("PUT", "/nokms/o", strings.NewReader("x"), hdr{"x-amz-server-side-encryption": "AES256"})
	wantError(t, r, b, 501, "NotImplemented")
	r, b = e.do("PUT", "/nokms/o", strings.NewReader("x"), hdr{"x-amz-server-side-encryption": "aws:kms"})
	wantError(t, r, b, 501, "NotImplemented")
	// SSE-C needs no KMS.
	key := randKey()
	e.do("PUT", "/nokms/c", strings.NewReader("secret"), ssecH(key))
	resp, got := e.do("GET", "/nokms/c", nil, ssecH(key))
	if resp.StatusCode != 200 || string(got) != "secret" {
		t.Errorf("SSE-C without KMS: %d %q", resp.StatusCode, got)
	}
	// Bucket default encryption needs one.
	r, b = e.do("PUT", "/nokms?encryption", strings.NewReader(
		`<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>`), nil)
	wantError(t, r, b, 501, "NotImplemented")
}

func TestSSEUnknownKMSKeyAndBadContext(t *testing.T) {
	e := sseEnv(t, "fs")
	e.mb("badkey")
	r, b := e.do("PUT", "/badkey/o", strings.NewReader("x"), hdr{
		"x-amz-server-side-encryption": "aws:kms", "x-amz-server-side-encryption-aws-kms-key-id": "no-such-key"})
	wantError(t, r, b, 400, "KMS.NotFoundException")
	for name, h := range map[string]hdr{
		"context not base64": {"x-amz-server-side-encryption": "aws:kms", "x-amz-server-side-encryption-context": "%%%"},
		"context not json":   {"x-amz-server-side-encryption": "aws:kms", "x-amz-server-side-encryption-context": base64.StdEncoding.EncodeToString([]byte("[1]"))},
		"unknown algorithm":  {"x-amz-server-side-encryption": "AES512"},
		"kms id without kms": {"x-amz-server-side-encryption": "AES256", "x-amz-server-side-encryption-aws-kms-key-id": "k"},
		"reserved header":    {"x-nanoio-internal-sse-mode": "c"},
	} {
		r, b := e.do("PUT", "/badkey/o", strings.NewReader("x"), h)
		if r.StatusCode != 400 {
			t.Errorf("%s: status %d %s", name, r.StatusCode, b)
		}
	}
}

func TestSSERanges(t *testing.T) {
	eachBackend(t, func(t *testing.T, e *testEnv) {
		e.mb("rng")
		body := randString(5*65536 + 1234)
		e.put("/rng/o", body, hdr{"x-amz-server-side-encryption": "AES256"})
		ranges := [][2]int{{0, 0}, {0, 9}, {65535, 65536}, {65536, 70000}, {100, len(body) - 1}, {len(body) - 5, len(body) - 1}, {3 * 65536, 3*65536 + 65535}}
		for _, rg := range ranges {
			resp, b := e.do("GET", "/rng/o", nil, hdr{"Range": fmt.Sprintf("bytes=%d-%d", rg[0], rg[1])})
			if resp.StatusCode != 206 || string(b) != body[rg[0]:rg[1]+1] {
				t.Errorf("range %v: %d, equal=%v", rg, resp.StatusCode, string(b) == body[rg[0]:rg[1]+1])
			}
			want := fmt.Sprintf("bytes %d-%d/%d", rg[0], rg[1], len(body))
			if resp.Header.Get("Content-Range") != want {
				t.Errorf("range %v Content-Range = %q, want %q", rg, resp.Header.Get("Content-Range"), want)
			}
		}
		resp, b := e.do("GET", "/rng/o", nil, hdr{"Range": "bytes=-100"})
		if resp.StatusCode != 206 || string(b) != body[len(body)-100:] {
			t.Errorf("suffix range: %d", resp.StatusCode)
		}
		resp, b = e.do("GET", "/rng/o", nil, hdr{"Range": fmt.Sprintf("bytes=%d-", len(body))})
		wantError(t, resp, b, 416, "InvalidRange")
	})
}

func TestSSEConditionalETag(t *testing.T) {
	e := sseEnv(t, "fs")
	e.mb("cond")
	resp := e.put("/cond/o", "hello world", hdr{"x-amz-server-side-encryption": "AES256"})
	etag := resp.Header.Get("ETag")
	r, _ := e.do("GET", "/cond/o", nil, hdr{"If-None-Match": etag})
	if r.StatusCode != 304 {
		t.Errorf("If-None-Match with the plaintext ETag = %d", r.StatusCode)
	}
	r, _ = e.do("GET", "/cond/o", nil, hdr{"If-Match": etag})
	if r.StatusCode != 200 {
		t.Errorf("If-Match with the plaintext ETag = %d", r.StatusCode)
	}
	// The stored (listing) ETag is accepted as well.
	_, info := e.stored("cond", "o")
	r, _ = e.do("GET", "/cond/o", nil, hdr{"If-Match": `"` + info.ETag + `"`})
	if r.StatusCode != 200 {
		t.Errorf("If-Match with the stored ETag = %d", r.StatusCode)
	}
}

func TestSSEDigestVerification(t *testing.T) {
	e := sseEnv(t, "fs")
	e.mb("dig")
	h := hdr{"x-amz-server-side-encryption": "AES256"}
	// Content-MD5 is checked over the plaintext.
	r, b := e.do("PUT", "/dig/o", strings.NewReader("payload"), merge(h, hdr{"Content-MD5": md5b64("other")}))
	wantError(t, r, b, 400, "BadDigest")
	r, _ = e.do("PUT", "/dig/o", strings.NewReader("payload"), merge(h, hdr{"Content-MD5": md5b64("payload")}))
	if r.StatusCode != 200 {
		t.Errorf("good Content-MD5 = %d", r.StatusCode)
	}
	r, b = e.do("PUT", "/dig/o2", strings.NewReader("payload"), merge(h, hdr{"x-amz-content-sha256": strings.Repeat("0", 64)}))
	wantError(t, r, b, 400, "XAmzContentSHA256Mismatch")
	// A failed upload leaves nothing behind.
	r, _ = e.do("HEAD", "/dig/o2", nil, nil)
	if r.StatusCode != 404 {
		t.Errorf("failed upload left an object: %d", r.StatusCode)
	}
}

func TestSSEMultipart(t *testing.T) {
	eachBackend(t, func(t *testing.T, e *testEnv) {
		e.mb("mpu")
		ckey := randKey()
		for _, c := range []struct {
			name string
			h    hdr
			part hdr // headers every part must carry
		}{
			{"sse-s3", hdr{"x-amz-server-side-encryption": "AES256"}, nil},
			{"sse-kms", hdr{"x-amz-server-side-encryption": "aws:kms", "x-amz-server-side-encryption-aws-kms-key-id": "other"}, nil},
			{"sse-c", ssecH(ckey), ssecH(ckey)},
		} {
			t.Run(c.name, func(t *testing.T) {
				key := "mp-" + c.name
				resp, b := e.do("POST", "/mpu/"+key+"?uploads", nil, c.h)
				if resp.StatusCode != 200 {
					t.Fatalf("create: %d %s", resp.StatusCode, b)
				}
				var init initiateMultipartUploadResult
				xml.Unmarshal(b, &init)
				id := init.UploadID
				parts := []string{randString(5 << 20), randString(5<<20 + 77), "tail"}
				var etags []string
				for i, p := range parts {
					r, b := e.do("PUT", fmt.Sprintf("/mpu/%s?partNumber=%d&uploadId=%s", key, i+1, id), strings.NewReader(p), c.part)
					if r.StatusCode != 200 {
						t.Fatalf("part %d: %d %s", i+1, r.StatusCode, b)
					}
					etags = append(etags, r.Header.Get("ETag"))
				}
				if c.name == "sse-c" {
					// Every part must carry the same key.
					r, b := e.do("PUT", fmt.Sprintf("/mpu/%s?partNumber=4&uploadId=%s", key, id), strings.NewReader("x"), nil)
					wantError(t, r, b, 400, "InvalidRequest")
					r, b = e.do("PUT", fmt.Sprintf("/mpu/%s?partNumber=4&uploadId=%s", key, id), strings.NewReader("x"), ssecH(randKey()))
					wantError(t, r, b, 403, "AccessDenied")
				} else {
					// SSE-C headers on a non-SSE-C upload.
					r, b := e.do("PUT", fmt.Sprintf("/mpu/%s?partNumber=4&uploadId=%s", key, id), strings.NewReader("x"), ssecH(ckey))
					wantError(t, r, b, 400, "InvalidRequest")
				}
				// ListParts reports plaintext sizes.
				lr, lb := e.do("GET", fmt.Sprintf("/mpu/%s?uploadId=%s", key, id), nil, nil)
				if lr.StatusCode != 200 || !strings.Contains(string(lb), fmt.Sprintf("<Size>%d</Size>", len(parts[0]))) ||
					!strings.Contains(string(lb), "<Size>4</Size>") {
					t.Errorf("ListParts: %d %s", lr.StatusCode, lb)
				}
				var cx bytes.Buffer
				cx.WriteString("<CompleteMultipartUpload>")
				for i, et := range etags {
					fmt.Fprintf(&cx, "<Part><PartNumber>%d</PartNumber><ETag>%s</ETag></Part>", i+1, et)
				}
				cx.WriteString("</CompleteMultipartUpload>")
				r, b := e.do("POST", fmt.Sprintf("/mpu/%s?uploadId=%s", key, id), &cx, nil)
				if r.StatusCode != 200 {
					t.Fatalf("complete: %d %s", r.StatusCode, b)
				}
				whole := strings.Join(parts, "")
				gr, got := e.do("GET", "/mpu/"+key, nil, c.part)
				if gr.StatusCode != 200 || string(got) != whole {
					t.Fatalf("GET: %d equal=%v", gr.StatusCode, string(got) == whole)
				}
				if gr.Header.Get("Content-Length") != fmt.Sprint(len(whole)) {
					t.Errorf("Content-Length = %s", gr.Header.Get("Content-Length"))
				}
				// A range that crosses part boundaries.
				lo, hi := len(parts[0])-10, len(parts[0])+len(parts[1])+2
				rr, rg := e.do("GET", "/mpu/"+key, nil, merge(c.part, hdr{"Range": fmt.Sprintf("bytes=%d-%d", lo, hi)}))
				if rr.StatusCode != 206 || string(rg) != whole[lo:hi+1] {
					t.Errorf("cross-part range: %d equal=%v", rr.StatusCode, string(rg) == whole[lo:hi+1])
				}
				raw, info := e.stored("mpu", key)
				if len(info.Parts) != 3 || strings.Contains(string(raw), parts[2]) {
					t.Errorf("stored parts %d, plaintext leaked=%v", len(info.Parts), strings.Contains(string(raw), parts[2]))
				}
			})
		}
	})
}

func TestSSEMultipartEnforcesPlaintextMinimum(t *testing.T) {
	e := sseEnv(t, "fs")
	e.mb("minpart")
	resp, b := e.do("POST", "/minpart/o?uploads", nil, hdr{"x-amz-server-side-encryption": "AES256"})
	var init initiateMultipartUploadResult
	xml.Unmarshal(b, &init)
	_ = resp
	// 5 MiB - 1 plaintext bytes: its ciphertext is larger than 5 MiB, so
	// storage alone would accept it.
	small := randString(5<<20 - 1)
	r1, _ := e.do("PUT", "/minpart/o?partNumber=1&uploadId="+init.UploadID, strings.NewReader(small), nil)
	r2, _ := e.do("PUT", "/minpart/o?partNumber=2&uploadId="+init.UploadID, strings.NewReader("x"), nil)
	body := fmt.Sprintf("<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>%s</ETag></Part><Part><PartNumber>2</PartNumber><ETag>%s</ETag></Part></CompleteMultipartUpload>",
		r1.Header.Get("ETag"), r2.Header.Get("ETag"))
	r, b := e.do("POST", "/minpart/o?uploadId="+init.UploadID, strings.NewReader(body), nil)
	wantError(t, r, b, 400, "EntityTooSmall")
}

type copyResult struct {
	ETag string `xml:"ETag"`
}

func (e *testEnv) copyObj(dst, src string, h hdr) (*http.Response, []byte) {
	return e.do("PUT", dst, nil, merge(hdr{"x-amz-copy-source": src}, h))
}

func TestSSECopyBetweenModes(t *testing.T) {
	eachBackend(t, func(t *testing.T, e *testEnv) {
		e.mb("cpy")
		body := randString(180000)
		akey, bkey := randKey(), randKey()
		s3H := hdr{"x-amz-server-side-encryption": "AES256"}
		kmsH := hdr{"x-amz-server-side-encryption": "aws:kms", "x-amz-server-side-encryption-aws-kms-key-id": "other"}

		e.put("/cpy/plain", body, nil)
		e.put("/cpy/s3", body, s3H)
		e.put("/cpy/c", body, ssecH(akey))

		check := func(dst string, readH hdr, wantMode sse.Mode) {
			t.Helper()
			r, got := e.do("GET", "/cpy/"+dst, nil, readH)
			if r.StatusCode != 200 || string(got) != body {
				t.Fatalf("GET %s: %d equal=%v", dst, r.StatusCode, string(got) == body)
			}
			_, info := e.stored("cpy", dst)
			if mode := sse.ModeOf(info.UserDefined); mode != wantMode {
				t.Errorf("%s stored with mode %q, want %q", dst, mode, wantMode)
			}
		}

		// plain -> SSE-S3, SSE-KMS, SSE-C
		for _, c := range []struct {
			dst  string
			h    hdr
			read hdr
			mode sse.Mode
		}{
			{"p2s3", s3H, nil, sse.ModeS3},
			{"p2kms", kmsH, nil, sse.ModeKMS},
			{"p2c", ssecH(bkey), ssecH(bkey), sse.ModeC},
		} {
			r, b := e.copyObj("/cpy/"+c.dst, "/cpy/plain", c.h)
			if r.StatusCode != 200 {
				t.Fatalf("copy plain -> %s: %d %s", c.dst, r.StatusCode, b)
			}
			var cr copyResult
			xml.Unmarshal(b, &cr)
			if cr.ETag != `"`+md5hex(body)+`"` {
				t.Errorf("copy ETag = %s", cr.ETag)
			}
			check(c.dst, c.read, c.mode)
		}
		// SSE-S3 -> SSE-C, SSE-C -> SSE-KMS, SSE-C -> plain
		r, b := e.copyObj("/cpy/s32c", "/cpy/s3", ssecH(bkey))
		if r.StatusCode != 200 {
			t.Fatalf("%d %s", r.StatusCode, b)
		}
		check("s32c", ssecH(bkey), sse.ModeC)
		r, b = e.copyObj("/cpy/c2kms", "/cpy/c", merge(kmsH, ssecCopyH(akey)))
		if r.StatusCode != 200 {
			t.Fatalf("%d %s", r.StatusCode, b)
		}
		check("c2kms", nil, sse.ModeKMS)
		r, b = e.copyObj("/cpy/c2plain", "/cpy/c", ssecCopyH(akey))
		if r.StatusCode != 200 {
			t.Fatalf("%d %s", r.StatusCode, b)
		}
		check("c2plain", nil, "")
		// A copy gets its own object key.
		_, a := e.stored("cpy", "s3")
		_, c2 := e.stored("cpy", "p2s3")
		if a.UserDefined[sse.KeySealed] == c2.UserDefined[sse.KeySealed] {
			t.Error("copy reuses the source's sealed key")
		}

		// Wrong or missing source key.
		r, b = e.copyObj("/cpy/x", "/cpy/c", merge(s3H, ssecCopyH(randKey())))
		wantError(t, r, b, 403, "AccessDenied")
		r, b = e.copyObj("/cpy/x", "/cpy/c", s3H)
		wantError(t, r, b, 400, "InvalidRequest")
		if r, _ := e.do("HEAD", "/cpy/x", nil, nil); r.StatusCode != 404 {
			t.Error("a failed copy created the destination")
		}
		// Copy source conditions use the plaintext ETag.
		r, _ = e.copyObj("/cpy/cond", "/cpy/s3", hdr{"x-amz-copy-source-if-match": `"` + md5hex(body) + `"`})
		if r.StatusCode != 200 {
			t.Errorf("copy-source-if-match = %d", r.StatusCode)
		}
		r, _ = e.copyObj("/cpy/cond2", "/cpy/s3", hdr{"x-amz-copy-source-if-match": `"` + md5hex("nope") + `"`})
		if r.StatusCode != 412 {
			t.Errorf("failing copy-source-if-match = %d", r.StatusCode)
		}
	})
}

// A self-copy that changes encryption or metadata must not touch the data.
func TestSSESelfCopyRewrapsWithoutRewritingData(t *testing.T) {
	eachBackend(t, func(t *testing.T, e *testEnv) {
		e.mb("selfcpy")
		body := randString(300000)
		akey, bkey := randKey(), randKey()
		e.put("/selfcpy/o", body, merge(ssecH(akey), hdr{"Content-Type": "text/one", "x-amz-meta-v": "1"}))
		before, binfo := e.stored("selfcpy", "o")
		sealedBefore := binfo.UserDefined[sse.KeySealed]

		same := func(step string) {
			t.Helper()
			after, ainfo := e.stored("selfcpy", "o")
			if !bytes.Equal(before, after) {
				t.Errorf("%s: stored data changed", step)
			}
			if ainfo.ETag != binfo.ETag {
				t.Errorf("%s: stored ETag changed", step)
			}
		}

		// SSE-C key rotation: old key in the copy-source headers, new key in
		// the destination headers.
		r, b := e.copyObj("/selfcpy/o", "/selfcpy/o", merge(ssecCopyH(akey), ssecH(bkey)))
		if r.StatusCode != 200 {
			t.Fatalf("key rotation: %d %s", r.StatusCode, b)
		}
		same("SSE-C key rotation")
		gr, got := e.do("GET", "/selfcpy/o", nil, ssecH(bkey))
		if gr.StatusCode != 200 || string(got) != body {
			t.Fatalf("GET with the new key: %d", gr.StatusCode)
		}
		r, b = e.do("GET", "/selfcpy/o", nil, ssecH(akey))
		wantError(t, r, b, 403, "AccessDenied")
		if _, i := e.stored("selfcpy", "o"); i.UserDefined[sse.KeySealed] == sealedBefore {
			t.Error("sealed key unchanged after rotation")
		}

		// Move SSE-C -> SSE-S3 in place.
		r, b = e.copyObj("/selfcpy/o", "/selfcpy/o", merge(ssecCopyH(bkey), hdr{"x-amz-server-side-encryption": "AES256"}))
		if r.StatusCode != 200 {
			t.Fatalf("SSE-C -> SSE-S3: %d %s", r.StatusCode, b)
		}
		same("SSE-C -> SSE-S3")
		gr, got = e.do("GET", "/selfcpy/o", nil, nil)
		if gr.StatusCode != 200 || string(got) != body || gr.Header.Get("x-amz-server-side-encryption") != "AES256" {
			t.Fatalf("GET after SSE-S3: %d %v", gr.StatusCode, gr.Header)
		}
		// And to SSE-KMS under another key.
		r, b = e.copyObj("/selfcpy/o", "/selfcpy/o", hdr{"x-amz-server-side-encryption": "aws:kms", "x-amz-server-side-encryption-aws-kms-key-id": "other"})
		if r.StatusCode != 200 {
			t.Fatalf("SSE-S3 -> SSE-KMS: %d %s", r.StatusCode, b)
		}
		same("SSE-S3 -> SSE-KMS")

		// REPLACE metadata keeps the encryption and the data.
		r, b = e.copyObj("/selfcpy/o", "/selfcpy/o", hdr{
			"x-amz-metadata-directive": "REPLACE", "Content-Type": "text/two", "x-amz-meta-v": "2"})
		if r.StatusCode != 200 {
			t.Fatalf("REPLACE: %d %s", r.StatusCode, b)
		}
		same("metadata REPLACE")
		hr, _ := e.do("HEAD", "/selfcpy/o", nil, nil)
		if hr.Header.Get("Content-Type") != "text/two" || hr.Header.Get("x-amz-meta-v") != "2" ||
			hr.Header.Get("x-amz-server-side-encryption") != "aws:kms" {
			t.Errorf("after REPLACE: %v", hr.Header)
		}
		if got, _ := e.get("/selfcpy/o"); got != body {
			t.Error("body changed after REPLACE")
		}

		// Copying onto itself with nothing to change is refused.
		r, b = e.copyObj("/selfcpy/o", "/selfcpy/o", nil)
		wantError(t, r, b, 400, "InvalidRequest")
	})
}

func TestSSEUploadPartCopy(t *testing.T) {
	e := sseEnv(t, "fs")
	e.mb("upc")
	akey := randKey()
	body := randString(5<<20 + 1000)
	e.put("/upc/src", body, ssecH(akey))
	resp, b := e.do("POST", "/upc/dst?uploads", nil, hdr{"x-amz-server-side-encryption": "AES256"})
	var init initiateMultipartUploadResult
	xml.Unmarshal(b, &init)
	_ = resp
	r, b := e.do("PUT", "/upc/dst?partNumber=1&uploadId="+init.UploadID, nil, merge(
		hdr{"x-amz-copy-source": "/upc/src", "x-amz-copy-source-range": fmt.Sprintf("bytes=0-%d", 5<<20-1)}, ssecCopyH(akey)))
	if r.StatusCode != 200 {
		t.Fatalf("UploadPartCopy: %d %s", r.StatusCode, b)
	}
	var cp copyPartResult
	xml.Unmarshal(b, &cp)
	r2, b := e.do("PUT", "/upc/dst?partNumber=2&uploadId="+init.UploadID, nil, merge(
		hdr{"x-amz-copy-source": "/upc/src", "x-amz-copy-source-range": fmt.Sprintf("bytes=%d-%d", 5<<20, len(body)-1)}, ssecCopyH(akey)))
	if r2.StatusCode != 200 {
		t.Fatalf("UploadPartCopy 2: %d %s", r2.StatusCode, b)
	}
	var cp2 copyPartResult
	xml.Unmarshal(b, &cp2)
	// Wrong source key.
	r3, b := e.do("PUT", "/upc/dst?partNumber=3&uploadId="+init.UploadID, nil, merge(hdr{"x-amz-copy-source": "/upc/src"}, ssecCopyH(randKey())))
	wantError(t, r3, b, 403, "AccessDenied")
	done := fmt.Sprintf("<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>%s</ETag></Part><Part><PartNumber>2</PartNumber><ETag>%s</ETag></Part></CompleteMultipartUpload>", cp.ETag, cp2.ETag)
	if r, b := e.do("POST", "/upc/dst?uploadId="+init.UploadID, strings.NewReader(done), nil); r.StatusCode != 200 {
		t.Fatalf("complete: %d %s", r.StatusCode, b)
	}
	got, gr := e.get("/upc/dst")
	if gr.StatusCode != 200 || got != body {
		t.Errorf("assembled object differs (%d)", gr.StatusCode)
	}
}

func TestBucketDefaultEncryption(t *testing.T) {
	eachBackend(t, func(t *testing.T, e *testEnv) {
		e.mb("defenc")
		r, b := e.do("GET", "/defenc?encryption", nil, nil)
		wantError(t, r, b, 404, "ServerSideEncryptionConfigurationNotFoundError")

		cfg := `<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>`
		if r, b := e.do("PUT", "/defenc?encryption", strings.NewReader(cfg), nil); r.StatusCode != 200 {
			t.Fatalf("PUT ?encryption: %d %s", r.StatusCode, b)
		}
		r, b = e.do("GET", "/defenc?encryption", nil, nil)
		if r.StatusCode != 200 || !strings.Contains(string(b), "<SSEAlgorithm>AES256</SSEAlgorithm>") {
			t.Fatalf("GET ?encryption: %d %s", r.StatusCode, b)
		}
		// A write with no SSE headers is encrypted.
		resp := e.put("/defenc/o", "by default", nil)
		if resp.Header.Get("x-amz-server-side-encryption") != "AES256" {
			t.Errorf("PUT response lacks the default's header: %v", resp.Header)
		}
		raw, info := e.stored("defenc", "o")
		if sse.ModeOf(info.UserDefined) != sse.ModeS3 || strings.Contains(string(raw), "by default") {
			t.Error("object not encrypted by the bucket default")
		}
		if got, _ := e.get("/defenc/o"); got != "by default" {
			t.Errorf("GET = %q", got)
		}
		// SSE-C wins over the default.
		key := randKey()
		e.put("/defenc/c", "mine", ssecH(key))
		if _, i := e.stored("defenc", "c"); sse.ModeOf(i.UserDefined) != sse.ModeC {
			t.Errorf("explicit SSE-C overridden: %q", sse.ModeOf(i.UserDefined))
		}
		// Default KMS key id round trip.
		cfg = `<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>aws:kms</SSEAlgorithm><KMSMasterKeyID>other</KMSMasterKeyID></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>`
		if r, b := e.do("PUT", "/defenc?encryption", strings.NewReader(cfg), nil); r.StatusCode != 200 {
			t.Fatalf("%d %s", r.StatusCode, b)
		}
		e.put("/defenc/k", "kms default", nil)
		if _, i := e.stored("defenc", "k"); sse.ModeOf(i.UserDefined) != sse.ModeKMS || i.UserDefined[sse.KeyKMSKeyID] != "other" {
			t.Errorf("KMS default not applied: %v", i.UserDefined)
		}
		// A key the KMS does not know is refused when the config is set.
		bad := strings.Replace(cfg, "other", "ghost", 1)
		r, b = e.do("PUT", "/defenc?encryption", strings.NewReader(bad), nil)
		wantError(t, r, b, 400, "KMS.NotFoundException")
		// Multipart uploads get it too.
		_, b = e.do("POST", "/defenc/mp?uploads", nil, nil)
		var init initiateMultipartUploadResult
		xml.Unmarshal(b, &init)
		pr, _ := e.do("PUT", "/defenc/mp?partNumber=1&uploadId="+init.UploadID, strings.NewReader("part"), nil)
		if pr.Header.Get("x-amz-server-side-encryption") != "aws:kms" {
			t.Errorf("part response: %v", pr.Header)
		}
		// Remove it.
		if r, _ := e.do("DELETE", "/defenc?encryption", nil, nil); r.StatusCode != 204 {
			t.Errorf("DELETE ?encryption = %d", r.StatusCode)
		}
		e.put("/defenc/plain", "plain again", nil)
		if _, i := e.stored("defenc", "plain"); sse.Encrypted(i.UserDefined) {
			t.Error("encryption applied after the default was removed")
		}
		// The configuration bucket is not part of the S3 namespace, and a
		// deleted bucket's configuration does not come back.
		lr, lb := e.do("GET", "/", nil, nil)
		if lr.StatusCode != 200 || strings.Contains(string(lb), sysBucket) {
			t.Errorf("ListBuckets exposes the system bucket: %s", lb)
		}
		r, b = e.do("GET", "/"+sysBucket+"/defenc/encryption", nil, nil)
		wantError(t, r, b, 404, "NoSuchBucket")
		r, b = e.do("PUT", "/"+sysBucket, nil, nil)
		wantError(t, r, b, 400, "InvalidBucketName")
	})
}

func TestBucketDefaultEncryptionDiesWithBucket(t *testing.T) {
	e := sseEnv(t, "fs")
	e.mb("diesbkt")
	cfg := `<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>`
	e.do("PUT", "/diesbkt?encryption", strings.NewReader(cfg), nil)
	if r, b := e.do("DELETE", "/diesbkt", nil, nil); r.StatusCode != 204 {
		t.Fatalf("delete bucket: %d %s", r.StatusCode, b)
	}
	e.mb("diesbkt")
	e.put("/diesbkt/o", "x", nil)
	if _, i := e.stored("diesbkt", "o"); sse.Encrypted(i.UserDefined) {
		t.Error("a new bucket inherited its predecessor's default encryption")
	}
}

func TestSSEVersioning(t *testing.T) {
	eachBackend(t, func(t *testing.T, e *testEnv) {
		e.mb("verenc")
		e.do("PUT", "/verenc?versioning", strings.NewReader(`<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`), nil)
		key := randKey()
		r1 := e.put("/verenc/o", "version one", hdr{"x-amz-server-side-encryption": "AES256"})
		r2 := e.put("/verenc/o", "version two!", ssecH(key))
		v1, v2 := r1.Header.Get("x-amz-version-id"), r2.Header.Get("x-amz-version-id")
		if v1 == "" || v1 == v2 {
			t.Fatalf("version IDs %q %q", v1, v2)
		}
		if got, _ := e.get("/verenc/o?versionId=" + v1); got != "version one" {
			t.Errorf("v1 = %q", got)
		}
		resp, got := e.do("GET", "/verenc/o?versionId="+v2, nil, ssecH(key))
		if resp.StatusCode != 200 || string(got) != "version two!" {
			t.Errorf("v2 = %d %q", resp.StatusCode, got)
		}
		// Latest is the SSE-C version: no key, no read.
		r, b := e.do("GET", "/verenc/o", nil, nil)
		wantError(t, r, b, 400, "InvalidRequest")
		// Listing reports plaintext sizes for every version.
		_, lb := e.do("GET", "/verenc?versions", nil, nil)
		if !strings.Contains(string(lb), "<Size>11</Size>") || !strings.Contains(string(lb), "<Size>12</Size>") {
			t.Errorf("version sizes: %s", lb)
		}
		// Self-copy of the latest rewraps in place without a new version.
		r, b = e.copyObj("/verenc/o", "/verenc/o", merge(ssecCopyH(key), hdr{"x-amz-server-side-encryption": "AES256"}))
		if r.StatusCode != 200 {
			t.Fatalf("self copy: %d %s", r.StatusCode, b)
		}
		_, lb = e.do("GET", "/verenc?versions", nil, nil)
		if n := strings.Count(string(lb), "<Version>"); n != 2 {
			t.Errorf("versions after an in-place re-wrap = %d, want 2", n)
		}
		if got, _ := e.get("/verenc/o"); got != "version two!" {
			t.Errorf("latest after re-wrap = %q", got)
		}
	})
}

// Erasure coding: shards are ciphertext; losing drives or corrupting a
// shard is repaired from parity before decryption.
func TestSSEOverErasureCodingSurvivesDriveLossAndBitrot(t *testing.T) {
	e := sseEnv(t, "xl")
	e.mb("ecc")
	body := randString(500000)
	e.put("/ecc/o", body, hdr{"x-amz-server-side-encryption": "AES256"})

	// No shard file contains plaintext.
	for _, d := range e.drives {
		filepath.WalkDir(d, func(p string, de os.DirEntry, err error) error {
			if err != nil || de.IsDir() {
				return nil
			}
			b, _ := os.ReadFile(p)
			if bytes.Contains(b, []byte(body[1000:1064])) {
				t.Errorf("plaintext found in %s", p)
			}
			return nil
		})
	}
	// Corrupt one shard's bytes.
	corrupted := false
	filepath.WalkDir(e.drives[0], func(p string, de os.DirEntry, err error) error {
		if err == nil && !de.IsDir() && strings.HasPrefix(de.Name(), "part.") && !corrupted {
			b, _ := os.ReadFile(p)
			for i := 100; i < 200 && i < len(b); i++ {
				b[i] ^= 0xff
			}
			os.WriteFile(p, b, 0o644)
			corrupted = true
		}
		return nil
	})
	if !corrupted {
		t.Fatal("found no shard to corrupt")
	}
	// And lose a whole drive's copy.
	os.RemoveAll(filepath.Join(e.drives[1], "ecc", "o"))
	got, resp := e.get("/ecc/o")
	if resp.StatusCode != 200 || got != body {
		t.Fatalf("GET after bitrot and drive loss: %d equal=%v", resp.StatusCode, got == body)
	}
	// Heal needs no key: it rebuilds ciphertext shards from ciphertext
	// shards and republishes the metadata, reserved keys included.
	x := e.st.(*xl.XL)
	if _, err := x.HealObject(context.Background(), "ecc", "o", true); err != nil {
		t.Fatalf("HealObject: %v", err)
	}
	for i, d := range e.drives {
		if _, err := os.Stat(filepath.Join(d, "ecc", "o", "xl.meta")); err != nil {
			t.Errorf("drive %d has no xl.meta after heal: %v", i, err)
		}
	}
	raw, info := e.stored("ecc", "o")
	if int64(len(raw)) != sse.CipherSize(int64(len(body))) || sse.ModeOf(info.UserDefined) != sse.ModeS3 {
		t.Errorf("after heal: %d bytes, mode %q", len(raw), sse.ModeOf(info.UserDefined))
	}
	if got, resp := e.get("/ecc/o"); resp.StatusCode != 200 || got != body {
		t.Errorf("GET after heal: %d", resp.StatusCode)
	}
}

func TestKEKRotationRewrapsWithoutTouchingData(t *testing.T) {
	eachBackend(t, func(t *testing.T, e *testEnv) {
		keyA1, keyA2, keyO1, keyO2 := randKey(), randKey(), randKey(), randKey()
		v1 := newLocalKMS(t, map[string][]kms.LocalKey{
			"default": {{Version: 1, Key: keyA1}}, "other": {{Version: 1, Key: keyO1}}})
		s1 := serve(t, e.st, e.fs, func(o *Options) { o.KMS, o.DefaultKMSKey, o.AllowInsecureSSEC = v1, "default", true })
		s1.mb("rot")
		type obj struct {
			key, body string
			h, read   hdr
		}
		ck := randKey()
		objs := []obj{
			{"s3", randString(100000), hdr{"x-amz-server-side-encryption": "AES256"}, nil},
			{"kms", randString(70000), hdr{"x-amz-server-side-encryption": "aws:kms", "x-amz-server-side-encryption-aws-kms-key-id": "other",
				"x-amz-server-side-encryption-context": base64.StdEncoding.EncodeToString([]byte(`{"a":"b"}`))}, nil},
			{"c", randString(50000), ssecH(ck), ssecH(ck)},
			{"plain", "unencrypted", nil, nil},
		}
		beforeBytes := map[string][]byte{}
		beforeWrap := map[string]string{}
		for _, o := range objs {
			s1.put("/rot/"+o.key, o.body, o.h)
			b, info := s1.stored("rot", o.key)
			beforeBytes[o.key], beforeWrap[o.key] = b, info.UserDefined[sse.KeyKMSWrapped]
		}

		// Rotate: both KEKs gain a version 2.
		v2 := newLocalKMS(t, map[string][]kms.LocalKey{
			"default": {{Version: 1, Key: keyA1}, {Version: 2, Key: keyA2}},
			"other":   {{Version: 1, Key: keyO1}, {Version: 2, Key: keyO2}}})
		s2 := serve(t, e.st, e.fs, func(o *Options) { o.KMS, o.DefaultKMSKey, o.AllowInsecureSSEC = v2, "default", true })
		r, b := s2.do("POST", "/_nanoio/admin/rewrap", nil, nil)
		if r.StatusCode != 200 {
			t.Fatalf("rewrap: %d %s", r.StatusCode, b)
		}
		var st RewrapStats
		if err := json.Unmarshal(b, &st); err != nil {
			t.Fatal(err)
		}
		if st.Rewrapped != 2 || st.Failed != 0 || st.Encrypted != 2 {
			t.Fatalf("stats = %+v", st)
		}
		for _, o := range objs {
			after, info := s2.stored("rot", o.key)
			if !bytes.Equal(after, beforeBytes[o.key]) {
				t.Errorf("%s: stored data changed by the rewrap", o.key)
			}
			switch o.key {
			case "s3", "kms":
				if info.UserDefined[sse.KeyKMSWrapped] == beforeWrap[o.key] {
					t.Errorf("%s: wrapped key not replaced", o.key)
				}
				if info.UserDefined[sse.KeyKMSVersion] != "2" {
					t.Errorf("%s: version %q, want 2", o.key, info.UserDefined[sse.KeyKMSVersion])
				}
			}
		}
		// A second sweep finds nothing to do.
		r, b = s2.do("POST", "/_nanoio/admin/rewrap", nil, nil)
		var st2 RewrapStats
		json.Unmarshal(b, &st2)
		if r.StatusCode != 200 || st2.Rewrapped != 0 || st2.Current != 2 {
			t.Errorf("second sweep = %d %+v", r.StatusCode, st2)
		}

		// Retire version 1 of both KEKs: everything still reads.
		v3 := newLocalKMS(t, map[string][]kms.LocalKey{
			"default": {{Version: 2, Key: keyA2}}, "other": {{Version: 2, Key: keyO2}}})
		s3 := serve(t, e.st, e.fs, func(o *Options) { o.KMS, o.DefaultKMSKey, o.AllowInsecureSSEC = v3, "default", true })
		for _, o := range objs {
			resp, got := s3.do("GET", "/rot/"+o.key, nil, o.read)
			if resp.StatusCode != 200 || string(got) != o.body {
				t.Errorf("%s after retiring v1: %d equal=%v", o.key, resp.StatusCode, string(got) == o.body)
			}
		}
		// A server still on KEK v1 cannot read a v2 wrap, which is why the
		// old version must stay until every node has the new one.
		resp, _ := s1.do("GET", "/rot/s3", nil, nil)
		if resp.StatusCode != 500 {
			t.Errorf("server without KEK v2 reading a v2 wrap: %d, want 500", resp.StatusCode)
		}
	})
}

func TestRewrapNeedsRootAndAKMS(t *testing.T) {
	e := sseEnv(t, "fs")
	r, b := e.doAs("reader", "POST", "/_nanoio/admin/rewrap", nil, nil)
	wantError(t, r, b, 403, "AccessDenied")
	r, _ = e.doAnon("POST", "/_nanoio/admin/rewrap", nil, nil)
	if r.StatusCode != 403 {
		t.Errorf("anonymous rewrap = %d", r.StatusCode)
	}
	r, _ = e.do("GET", "/_nanoio/admin/rewrap", nil, nil)
	if r.StatusCode != 405 {
		t.Errorf("GET rewrap = %d", r.StatusCode)
	}
	nokms := sseEnv(t, "fs", func(o *Options) { o.KMS, o.DefaultKMSKey = nil, "" })
	r, b = nokms.do("POST", "/_nanoio/admin/rewrap", nil, nil)
	wantError(t, r, b, 501, "NotImplemented")
}

func TestCopyObjectPlain(t *testing.T) {
	e := sseEnv(t, "fs")
	e.mb("plaincopy")
	e.put("/plaincopy/src", "source body", hdr{"Content-Type": "text/src", "x-amz-meta-a": "1"})
	// COPY keeps the source's metadata.
	r, b := e.copyObj("/plaincopy/dst", "/plaincopy/src", nil)
	if r.StatusCode != 200 {
		t.Fatalf("%d %s", r.StatusCode, b)
	}
	hr, _ := e.do("HEAD", "/plaincopy/dst", nil, nil)
	if hr.Header.Get("Content-Type") != "text/src" || hr.Header.Get("x-amz-meta-a") != "1" {
		t.Errorf("COPY lost metadata: %v", hr.Header)
	}
	// REPLACE uses the request's.
	r, b = e.copyObj("/plaincopy/dst2", "/plaincopy/src", hdr{"x-amz-metadata-directive": "REPLACE", "Content-Type": "text/new", "x-amz-meta-b": "2"})
	if r.StatusCode != 200 {
		t.Fatalf("%d %s", r.StatusCode, b)
	}
	hr, _ = e.do("HEAD", "/plaincopy/dst2", nil, nil)
	if hr.Header.Get("Content-Type") != "text/new" || hr.Header.Get("x-amz-meta-b") != "2" || hr.Header.Get("x-amz-meta-a") != "" {
		t.Errorf("REPLACE: %v", hr.Header)
	}
	if got, _ := e.get("/plaincopy/dst2"); got != "source body" {
		t.Errorf("body = %q", got)
	}
	// Unknown directive.
	r, b = e.copyObj("/plaincopy/dst3", "/plaincopy/src", hdr{"x-amz-metadata-directive": "MERGE"})
	wantError(t, r, b, 400, "InvalidArgument")
	// A plain self-copy that only REPLACEs metadata is in place.
	r, b = e.copyObj("/plaincopy/src", "/plaincopy/src", hdr{"x-amz-metadata-directive": "REPLACE", "Content-Type": "text/changed"})
	if r.StatusCode != 200 {
		t.Fatalf("%d %s", r.StatusCode, b)
	}
	hr, _ = e.do("HEAD", "/plaincopy/src", nil, nil)
	if hr.Header.Get("Content-Type") != "text/changed" {
		t.Errorf("in-place REPLACE: %v", hr.Header)
	}
	// A plain object cannot be copied from a bucket the caller cannot read.
	r, b = e.doAs("writer", "PUT", "/plaincopy/x", nil, hdr{"x-amz-copy-source": "/plaincopy/src"})
	if r.StatusCode != 403 {
		t.Errorf("copy without read access = %d %s", r.StatusCode, b)
	}
}
