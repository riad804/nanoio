package api

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"nanoio/internal/auth"
)

const minPart = 5 << 20

var blockA, blockB = func() ([]byte, []byte) {
	a, b := make([]byte, minPart), make([]byte, minPart)
	rand.New(rand.NewSource(11)).Read(a)
	rand.New(rand.NewSource(12)).Read(b)
	return a, b
}()

func (e *testEnv) initiate(bucket, key string, h hdr) string {
	e.t.Helper()
	return e.initiateAs(rootAK, bucket, key, h)
}

func (e *testEnv) initiateAs(user, bucket, key string, h hdr) string {
	e.t.Helper()
	resp, body := e.doAs(user, "POST", "/"+bucket+"/"+key+"?uploads", nil, h)
	if resp.StatusCode != 200 {
		e.t.Fatalf("initiate %s/%s: %d %s", bucket, key, resp.StatusCode, body)
	}
	var r initiateMultipartUploadResult
	wantKey, _ := url.PathUnescape(key)
	if err := xml.Unmarshal(body, &r); err != nil || r.UploadID == "" || r.Bucket != bucket || r.Key != wantKey {
		e.t.Fatalf("initiate response %+v %v\n%s", r, err, body)
	}
	return r.UploadID
}

// uploadPart sends one part and returns its ETag as returned (quoted).
func (e *testEnv) uploadPart(bucket, key, id string, n int, data []byte) string {
	e.t.Helper()
	resp, body := e.do("PUT", fmt.Sprintf("/%s/%s?partNumber=%d&uploadId=%s", bucket, key, n, id), bytes.NewReader(data), nil)
	if resp.StatusCode != 200 {
		e.t.Fatalf("upload part %d: %d %s", n, resp.StatusCode, body)
	}
	return resp.Header.Get("ETag")
}

func completeXML(parts ...[2]string) string {
	var b strings.Builder
	b.WriteString(`<CompleteMultipartUpload xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`)
	for _, p := range parts {
		fmt.Fprintf(&b, "<Part><PartNumber>%s</PartNumber><ETag>%s</ETag></Part>", p[0], p[1])
	}
	b.WriteString("</CompleteMultipartUpload>")
	return b.String()
}

func md5Bytes(data []byte) string {
	s := md5.Sum(data)
	return hex.EncodeToString(s[:])
}

func mpETag(parts ...[]byte) string {
	h := md5.New()
	for _, p := range parts {
		s := md5.Sum(p)
		h.Write(s[:])
	}
	return fmt.Sprintf("%x-%d", h.Sum(nil), len(parts))
}

func TestMultipartLifecycleOverHTTP(t *testing.T) {
	e := newEnv(t)
	e.mb("mpb")
	tail := []byte("the final, small part")

	id := e.initiate("mpb", "dir/big.bin", hdr{
		"Content-Type": "application/x-custom", "x-amz-meta-origin": "multipart", "Cache-Control": "max-age=9",
	})
	if len(id) < 8 {
		t.Fatalf("upload id %q", id)
	}

	// Parts, deliberately out of order.
	et3 := e.uploadPart("mpb", "dir/big.bin", id, 3, tail)
	et1 := e.uploadPart("mpb", "dir/big.bin", id, 1, blockA)
	et2 := e.uploadPart("mpb", "dir/big.bin", id, 2, blockB)
	for _, c := range []struct {
		got  string
		data []byte
	}{{et1, blockA}, {et2, blockB}, {et3, tail}} {
		if c.got != `"`+md5Bytes(c.data)+`"` {
			t.Errorf("part ETag %s, want quoted md5 %s", c.got, md5Bytes(c.data))
		}
	}

	t.Run("not visible until completed", func(t *testing.T) {
		resp, body := e.do("GET", "/mpb/dir/big.bin", nil, nil)
		wantError(t, resp, body, 404, "NoSuchKey")
		resp, body = e.do("GET", "/mpb?list-type=2", nil, nil)
		if resp.StatusCode != 200 || strings.Contains(string(body), "big.bin") {
			t.Errorf("incomplete upload appears in the listing: %s", body)
		}
	})
	t.Run("ListParts", func(t *testing.T) {
		resp, body := e.do("GET", "/mpb/dir/big.bin?uploadId="+id, nil, nil)
		if resp.StatusCode != 200 {
			t.Fatalf("%d %s", resp.StatusCode, body)
		}
		var r listPartsResult
		if err := xml.Unmarshal(body, &r); err != nil {
			t.Fatal(err)
		}
		if r.Bucket != "mpb" || r.Key != "dir/big.bin" || r.UploadID != id || r.MaxParts != 1000 ||
			r.IsTruncated || r.StorageClass != "STANDARD" || r.Owner.ID == "" || r.Initiator.ID == "" || len(r.Parts) != 3 {
			t.Errorf("envelope %+v", r)
		}
		for i, want := range []struct {
			n    int
			size int
			etag string
		}{{1, minPart, et1}, {2, minPart, et2}, {3, len(tail), et3}} {
			p := r.Parts[i]
			if p.PartNumber != want.n || p.Size != int64(want.size) || p.ETag != want.etag {
				t.Errorf("part %d = %+v", i, p)
			}
			if _, err := time.Parse(timeLayout, p.LastModified); err != nil {
				t.Errorf("LastModified %q: %v", p.LastModified, err)
			}
		}
	})
	t.Run("ListMultipartUploads shows it", func(t *testing.T) {
		resp, body := e.do("GET", "/mpb?uploads", nil, nil)
		var r listMultipartUploadsResult
		if err := xml.Unmarshal(body, &r); err != nil || resp.StatusCode != 200 {
			t.Fatalf("%d %v %s", resp.StatusCode, err, body)
		}
		if r.Bucket != "mpb" || len(r.Uploads) != 1 || r.Uploads[0].Key != "dir/big.bin" ||
			r.Uploads[0].UploadID != id || r.MaxUploads != 1000 || r.IsTruncated {
			t.Errorf("%+v", r)
		}
		if _, err := time.Parse(timeLayout, r.Uploads[0].Initiated); err != nil {
			t.Errorf("Initiated: %v", err)
		}
	})

	wantETag := mpETag(blockA, blockB, tail)
	t.Run("complete", func(t *testing.T) {
		resp, body := e.do("POST", "/mpb/dir/big.bin?uploadId="+id, strings.NewReader(
			completeXML([2]string{"1", et1}, [2]string{"2", et2}, [2]string{"3", et3})), nil)
		if resp.StatusCode != 200 {
			t.Fatalf("%d %s", resp.StatusCode, body)
		}
		var r completeMultipartUploadResult
		if err := xml.Unmarshal(body, &r); err != nil {
			t.Fatal(err)
		}
		if r.Bucket != "mpb" || r.Key != "dir/big.bin" || r.ETag != `"`+wantETag+`"` ||
			!strings.HasSuffix(r.Location, "/mpb/dir/big.bin") {
			t.Errorf("%+v (want etag %s)", r, wantETag)
		}
	})
	t.Run("the assembled object", func(t *testing.T) {
		resp, body := e.do("GET", "/mpb/dir/big.bin", nil, nil)
		if resp.StatusCode != 200 {
			t.Fatalf("%d", resp.StatusCode)
		}
		want := append(append(append([]byte{}, blockA...), blockB...), tail...)
		if !bytes.Equal(body, want) {
			t.Errorf("content differs (%d bytes, want %d)", len(body), len(want))
		}
		for k, v := range map[string]string{
			"ETag": `"` + wantETag + `"`, "Content-Type": "application/x-custom",
			"X-Amz-Meta-Origin": "multipart", "Cache-Control": "max-age=9",
			"Content-Length": fmt.Sprint(len(want)),
		} {
			if got := resp.Header.Get(k); got != v {
				t.Errorf("%s = %q, want %q", k, got, v)
			}
		}
		// A range that straddles the first part boundary.
		resp, body = e.do("GET", "/mpb/dir/big.bin", nil, hdr{"Range": fmt.Sprintf("bytes=%d-%d", minPart-3, minPart+4)})
		if resp.StatusCode != 206 || !bytes.Equal(body, want[minPart-3:minPart+5]) {
			t.Errorf("straddling range: %d, %d bytes", resp.StatusCode, len(body))
		}
		// Listing carries the multipart ETag too.
		_, lb := e.do("GET", "/mpb?list-type=2", nil, nil)
		if !strings.Contains(string(lb), wantETag) {
			t.Errorf("listing lacks the multipart etag: %s", lb)
		}
	})
	t.Run("consumed", func(t *testing.T) {
		resp, body := e.do("GET", "/mpb/dir/big.bin?uploadId="+id, nil, nil)
		wantError(t, resp, body, 404, "NoSuchUpload")
		resp, body = e.do("POST", "/mpb/dir/big.bin?uploadId="+id, strings.NewReader(
			completeXML([2]string{"1", et1})), nil)
		wantError(t, resp, body, 404, "NoSuchUpload")
	})
}

func TestMultipartErrorsOverHTTP(t *testing.T) {
	e := newEnv(t)
	e.mb("mpe")
	id := e.initiate("mpe", "k", nil)
	e1 := e.uploadPart("mpe", "k", id, 1, []byte("tiny one"))
	e2 := e.uploadPart("mpe", "k", id, 2, []byte("tiny two"))
	const ghost = "11111111-1111-4111-8111-111111111111"
	q := func(n, uid string) string { return fmt.Sprintf("/mpe/k?partNumber=%s&uploadId=%s", n, uid) }

	tests := []struct {
		name         string
		method, path string
		body         string
		hdr          hdr
		status       int
		code         string
		msg          string
	}{
		{"part number zero", "PUT", q("0", id), "x", nil, 400, "InvalidArgument", "between 1 and 10000"},
		{"part number too large", "PUT", q("10001", id), "x", nil, 400, "InvalidArgument", "between 1 and 10000"},
		{"part number not numeric", "PUT", q("one", id), "x", nil, 400, "InvalidArgument", ""},
		{"part number missing", "PUT", "/mpe/k?uploadId=" + id, "x", nil, 400, "InvalidArgument", ""},
		{"unknown upload id", "PUT", q("1", ghost), "x", nil, 404, "NoSuchUpload", ""},
		{"garbage upload id", "PUT", q("1", "not-an-id"), "x", nil, 404, "NoSuchUpload", ""},
		{"upload id of another key", "PUT", "/mpe/other?partNumber=1&uploadId=" + id, "x", nil, 404, "NoSuchUpload", ""},
		{"missing bucket on initiate", "POST", "/no-such-bucket/k?uploads", "", nil, 404, "NoSuchBucket", ""},
		{"invalid key on initiate", "POST", "/mpe/a//b?uploads", "", nil, 400, "XNanoIOInvalidObjectName", ""},
		{"content-md5 mismatch", "PUT", q("5", id), "abc", hdr{"Content-MD5": md5b64("other")}, 400, "BadDigest", ""},
		{"payload hash mismatch", "PUT", q("5", id), "abc", hdr{"x-amz-content-sha256": sha256hex("other")}, 400, "XAmzContentSHA256Mismatch", ""},
		{"list parts of an unknown upload", "GET", "/mpe/k?uploadId=" + ghost, "", nil, 404, "NoSuchUpload", ""},
		{"abort an unknown upload", "DELETE", "/mpe/k?uploadId=" + ghost, "", nil, 404, "NoSuchUpload", ""},
		{"complete with malformed xml", "POST", "/mpe/k?uploadId=" + id, "<CompleteMultipartUpload><Part>", nil, 400, "MalformedXML", ""},
		{"complete with no parts", "POST", "/mpe/k?uploadId=" + id, "<CompleteMultipartUpload></CompleteMultipartUpload>", nil, 400, "MalformedXML", ""},
		{"complete with a part lacking its etag", "POST", "/mpe/k?uploadId=" + id,
			completeXML([2]string{"1", ""}), nil, 400, "MalformedXML", ""},
		{"complete with part number 0", "POST", "/mpe/k?uploadId=" + id,
			completeXML([2]string{"0", e1}), nil, 400, "MalformedXML", ""},
		{"complete with a part below the minimum", "POST", "/mpe/k?uploadId=" + id,
			completeXML([2]string{"1", e1}, [2]string{"2", e2}), nil, 400, "EntityTooSmall", "Part 1"},
		{"complete with a wrong etag", "POST", "/mpe/k?uploadId=" + id,
			completeXML([2]string{"1", `"` + md5hex("other") + `"`}), nil, 400, "InvalidPart", ""},
		{"complete with a part never uploaded", "POST", "/mpe/k?uploadId=" + id,
			completeXML([2]string{"9", e1}), nil, 400, "InvalidPart", "Part 9"},
		{"complete out of order", "POST", "/mpe/k?uploadId=" + id,
			completeXML([2]string{"2", e2}, [2]string{"1", e1}), nil, 400, "InvalidPartOrder", ""},
		{"complete with a repeated part", "POST", "/mpe/k?uploadId=" + id,
			completeXML([2]string{"1", e1}, [2]string{"1", e1}), nil, 400, "InvalidPartOrder", ""},
		{"complete of an unknown upload", "POST", "/mpe/k?uploadId=" + ghost,
			completeXML([2]string{"1", e1}), nil, 404, "NoSuchUpload", ""},
		{"complete with the declared body hash wrong", "POST", "/mpe/k?uploadId=" + id,
			completeXML([2]string{"1", e1}), hdr{"x-amz-content-sha256": sha256hex("different")}, 400, "XAmzContentSHA256Mismatch", ""},
		{"list uploads: bad max-uploads", "GET", "/mpe?uploads&max-uploads=-1", "", nil, 400, "InvalidArgument", ""},
		{"list uploads: upload-id-marker without key-marker", "GET", "/mpe?uploads&upload-id-marker=" + id, "", nil, 400, "InvalidArgument", ""},
		{"list uploads: bad encoding type", "GET", "/mpe?uploads&encoding-type=base64", "", nil, 400, "InvalidArgument", ""},
		{"list uploads: missing bucket", "GET", "/ghost-bucket?uploads", "", nil, 404, "NoSuchBucket", ""},
		{"list parts: bad max-parts", "GET", "/mpe/k?uploadId=" + id + "&max-parts=x", "", nil, 400, "InvalidArgument", ""},
		{"list parts: bad marker", "GET", "/mpe/k?uploadId=" + id + "&part-number-marker=-3", "", nil, 400, "InvalidArgument", ""},
		{"wrong method with uploadId", "PATCH", "/mpe/k?uploadId=" + id, "", nil, 405, "MethodNotAllowed", ""},
		{"HEAD with uploadId", "HEAD", "/mpe/k?uploadId=" + id, "", nil, 405, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, body := e.do(tt.method, tt.path, strings.NewReader(tt.body), tt.hdr)
			er := wantError(t, resp, body, tt.status, tt.code)
			if tt.msg != "" && !strings.Contains(er.Message, tt.msg) {
				t.Errorf("message %q does not contain %q", er.Message, tt.msg)
			}
		})
	}
	// None of the rejected calls damaged the upload.
	resp, body := e.do("GET", "/mpe/k?uploadId="+id, nil, nil)
	var r listPartsResult
	xml.Unmarshal(body, &r)
	if resp.StatusCode != 200 || len(r.Parts) != 2 {
		t.Errorf("upload damaged: %d %+v", resp.StatusCode, r.Parts)
	}
	t.Run("missing content-length on a part", func(t *testing.T) {
		req, _ := http.NewRequest("PUT", e.srv.URL+q("4", id), io.NopCloser(strings.NewReader("abc")))
		req.ContentLength = -1
		e.root.Sign(req, auth.PayloadUnsigned, time.Now())
		resp, b := e.exec(req)
		wantError(t, resp, b, 411, "MissingContentLength")
	})
}

func TestAbortOverHTTP(t *testing.T) {
	e := newEnv(t)
	e.mb("mpa2")
	id := e.initiate("mpa2", "k", nil)
	e.uploadPart("mpa2", "k", id, 1, []byte("data"))
	resp, body := e.do("DELETE", "/mpa2/k?uploadId="+id, nil, nil)
	if resp.StatusCode != 204 || len(body) != 0 {
		t.Fatalf("abort = %d %q", resp.StatusCode, body)
	}
	for _, c := range []struct{ method, path, body string }{
		{"PUT", "/mpa2/k?partNumber=2&uploadId=" + id, "x"},
		{"GET", "/mpa2/k?uploadId=" + id, ""},
		{"DELETE", "/mpa2/k?uploadId=" + id, ""},
		{"POST", "/mpa2/k?uploadId=" + id, completeXML([2]string{"1", `"x"`})},
	} {
		resp, body := e.do(c.method, c.path, strings.NewReader(c.body), nil)
		wantError(t, resp, body, 404, "NoSuchUpload")
	}
	if r, _ := e.do("HEAD", "/mpa2/k", nil, nil); r.StatusCode != 404 {
		t.Error("an aborted upload produced an object")
	}
	// The bucket is free to delete again.
	if r, _ := e.do("DELETE", "/mpa2", nil, nil); r.StatusCode != 204 {
		t.Errorf("DeleteBucket after abort: %d", r.StatusCode)
	}
}

func TestBucketWithIncompleteUploadIsNotEmpty(t *testing.T) {
	e := newEnv(t)
	e.mb("mpn")
	id := e.initiate("mpn", "k", nil)
	resp, body := e.do("DELETE", "/mpn", nil, nil)
	wantError(t, resp, body, 409, "BucketNotEmpty")
	e.do("DELETE", "/mpn/k?uploadId="+id, nil, nil)
	if r, _ := e.do("DELETE", "/mpn", nil, nil); r.StatusCode != 204 {
		t.Errorf("DeleteBucket after abort: %d", r.StatusCode)
	}
}

func TestUploadIDIsBoundToBucketAndKey(t *testing.T) {
	e := newEnv(t)
	e.mb("mpx")
	e.mb("mpy")
	id := e.initiate("mpx", "k", nil)
	for _, path := range []string{
		"/mpy/k?partNumber=1&uploadId=" + id, // other bucket
		"/mpx/j?partNumber=1&uploadId=" + id, // other key
	} {
		resp, body := e.do("PUT", path, strings.NewReader("x"), nil)
		wantError(t, resp, body, 404, "NoSuchUpload")
	}
	resp, body := e.do("POST", "/mpy/k?uploadId="+id, strings.NewReader(completeXML([2]string{"1", `"x"`})), nil)
	wantError(t, resp, body, 404, "NoSuchUpload")
}

func TestUploadPartCopy(t *testing.T) {
	e := newEnv(t)
	e.mb("cps")
	e.mb("cpd")
	src := append(append([]byte{}, blockA...), blockB[:1000]...) // 5 MiB + 1000
	e.put("/cps/source.bin", string(src), hdr{"Content-Type": "application/octet-stream"})
	srcETag := `"` + md5Bytes(src) + `"`
	id := e.initiate("cpd", "copied.bin", nil)

	copyPart := func(n int, h hdr) (*http.Response, []byte) {
		return e.do("PUT", fmt.Sprintf("/cpd/copied.bin?partNumber=%d&uploadId=%s", n, id), nil, h)
	}
	t.Run("whole object and a byte range, completed into one object", func(t *testing.T) {
		resp, body := copyPart(1, hdr{"x-amz-copy-source": "/cps/source.bin"})
		if resp.StatusCode != 200 {
			t.Fatalf("%d %s", resp.StatusCode, body)
		}
		var r1 copyPartResult
		if err := xml.Unmarshal(body, &r1); err != nil || r1.ETag != `"`+md5Bytes(src)+`"` {
			t.Fatalf("%+v %v\n%s", r1, err, body)
		}
		if _, err := time.Parse(timeLayout, r1.LastModified); err != nil {
			t.Errorf("LastModified: %v", err)
		}

		resp, body = copyPart(2, hdr{
			"x-amz-copy-source": "cps/source.bin", "x-amz-copy-source-range": "bytes=10-19",
		})
		var r2 copyPartResult
		if err := xml.Unmarshal(body, &r2); err != nil || resp.StatusCode != 200 || r2.ETag != `"`+md5Bytes(src[10:20])+`"` {
			t.Fatalf("range copy: %d %+v %v", resp.StatusCode, r2, err)
		}

		resp, body = e.do("POST", "/cpd/copied.bin?uploadId="+id, strings.NewReader(
			completeXML([2]string{"1", r1.ETag}, [2]string{"2", r2.ETag})), nil)
		if resp.StatusCode != 200 {
			t.Fatalf("complete: %d %s", resp.StatusCode, body)
		}
		got, _ := e.get("/cpd/copied.bin")
		if got != string(src)+string(src[10:20]) {
			t.Errorf("assembled %d bytes", len(got))
		}
	})

	id2 := e.initiate("cpd", "second.bin", nil)
	copyTo := func(h hdr) (*http.Response, []byte) {
		return e.do("PUT", fmt.Sprintf("/cpd/second.bin?partNumber=1&uploadId=%s", id2), nil, h)
	}
	t.Run("percent-encoded source and a version id suffix", func(t *testing.T) {
		e.put("/cps/with%20space+plus.txt", "spaced", nil)
		resp, body := copyTo(hdr{"x-amz-copy-source": "/cps/with%20space%2Bplus.txt"})
		if resp.StatusCode != 200 {
			t.Fatalf("%d %s", resp.StatusCode, body)
		}
		resp, body = copyTo(hdr{"x-amz-copy-source": "/cps/source.bin?versionId=9f0c1b9e-1111-4222-8333-444455556666", "x-amz-copy-source-range": "bytes=0-1"})
		wantError(t, resp, body, 404, "NoSuchVersion")
	})
	errs := []struct {
		name   string
		h      hdr
		status int
		code   string
	}{
		{"missing source object", hdr{"x-amz-copy-source": "/cps/absent"}, 404, "NoSuchKey"},
		{"missing source bucket", hdr{"x-amz-copy-source": "/nobucket/k"}, 404, "NoSuchBucket"},
		{"source without a key", hdr{"x-amz-copy-source": "/cps"}, 400, "InvalidArgument"},
		{"empty source", hdr{"x-amz-copy-source": "/"}, 400, "InvalidArgument"},
		{"range without a unit", hdr{"x-amz-copy-source": "/cps/source.bin", "x-amz-copy-source-range": "0-9"}, 400, "InvalidArgument"},
		{"suffix range is not allowed", hdr{"x-amz-copy-source": "/cps/source.bin", "x-amz-copy-source-range": "bytes=-5"}, 400, "InvalidArgument"},
		{"open ended range is not allowed", hdr{"x-amz-copy-source": "/cps/source.bin", "x-amz-copy-source-range": "bytes=5-"}, 400, "InvalidArgument"},
		{"reversed range", hdr{"x-amz-copy-source": "/cps/source.bin", "x-amz-copy-source-range": "bytes=9-5"}, 400, "InvalidArgument"},
		{"range past the end", hdr{"x-amz-copy-source": "/cps/source.bin", "x-amz-copy-source-range": fmt.Sprintf("bytes=0-%d", len(src))}, 416, "InvalidRange"},
		{"if-match fails", hdr{"x-amz-copy-source": "/cps/source.bin", "x-amz-copy-source-if-match": `"nope"`}, 412, "PreconditionFailed"},
		{"if-none-match hits", hdr{"x-amz-copy-source": "/cps/source.bin", "x-amz-copy-source-if-none-match": srcETag}, 412, "PreconditionFailed"},
		{"if-unmodified-since in the past", hdr{"x-amz-copy-source": "/cps/source.bin",
			"x-amz-copy-source-if-unmodified-since": time.Now().Add(-24 * time.Hour).UTC().Format(http.TimeFormat)}, 412, "PreconditionFailed"},
	}
	for _, tt := range errs {
		t.Run(tt.name, func(t *testing.T) {
			resp, body := copyTo(tt.h)
			wantError(t, resp, body, tt.status, tt.code)
		})
	}
	t.Run("conditions that hold", func(t *testing.T) {
		resp, body := copyTo(hdr{"x-amz-copy-source": "/cps/source.bin", "x-amz-copy-source-range": "bytes=0-3",
			"x-amz-copy-source-if-match": srcETag})
		if resp.StatusCode != 200 {
			t.Errorf("%d %s", resp.StatusCode, body)
		}
	})
}

func TestMultipartListingsOverHTTP(t *testing.T) {
	e := newEnv(t)
	e.mb("mpl")
	keys := []string{"b/two", "a/one", "b/one", "c", "sp ace/x"}
	ids := map[string]string{}
	for _, k := range keys {
		ids[k] = e.initiate("mpl", (&url.URL{Path: k}).EscapedPath(), nil)
		time.Sleep(2 * time.Millisecond)
	}
	list := func(query string) listMultipartUploadsResult {
		t.Helper()
		resp, body := e.do("GET", "/mpl?uploads&"+query, nil, nil)
		var r listMultipartUploadsResult
		if err := xml.Unmarshal(body, &r); err != nil || resp.StatusCode != 200 {
			t.Fatalf("%q: %d %v %s", query, resp.StatusCode, err, body)
		}
		return r
	}
	keysOf := func(r listMultipartUploadsResult) string {
		var ks []string
		for _, u := range r.Uploads {
			ks = append(ks, u.Key)
		}
		return strings.Join(ks, ",")
	}

	if got := keysOf(list("")); got != "a/one,b/one,b/two,c,sp ace/x" {
		t.Errorf("all = %s", got)
	}
	if got := keysOf(list("prefix=b/")); got != "b/one,b/two" {
		t.Errorf("prefix = %s", got)
	}
	d := list("delimiter=/")
	var pfx []string
	for _, p := range d.CommonPrefixes {
		pfx = append(pfx, p.Prefix)
	}
	if keysOf(d) != "c" || strings.Join(pfx, ",") != "a/,b/,sp ace/" {
		t.Errorf("delimiter: %s %v", keysOf(d), pfx)
	}
	if r := list("encoding-type=url&prefix=sp"); r.EncodingType != "url" || keysOf(r) != "sp%20ace/x" || r.Prefix != "sp" {
		t.Errorf("url encoding: %+v", r)
	}
	if r := list("max-uploads=0"); len(r.Uploads) != 0 || r.IsTruncated || r.MaxUploads != 0 {
		t.Errorf("max-uploads=0: %+v", r)
	}

	var seen []string
	query := "max-uploads=2"
	for guard := 0; ; guard++ {
		if guard > 10 {
			t.Fatal("pagination did not terminate")
		}
		r := list(query)
		if len(r.Uploads)+len(r.CommonPrefixes) > 2 {
			t.Fatalf("page too large: %+v", r)
		}
		for _, u := range r.Uploads {
			seen = append(seen, u.Key)
		}
		if !r.IsTruncated {
			if r.NextKeyMarker != "" || r.NextUploadIDMarker != "" {
				t.Error("markers on the last page")
			}
			break
		}
		if r.NextKeyMarker == "" {
			t.Fatal("truncated page without NextKeyMarker")
		}
		query = fmt.Sprintf("max-uploads=2&key-marker=%s&upload-id-marker=%s",
			url.QueryEscape(r.NextKeyMarker), url.QueryEscape(r.NextUploadIDMarker))
	}
	if strings.Join(seen, ",") != "a/one,b/one,b/two,c,sp ace/x" {
		t.Errorf("paginated = %v", seen)
	}
}

func TestListPartsPaginationOverHTTP(t *testing.T) {
	e := newEnv(t)
	e.mb("mpp")
	id := e.initiate("mpp", "k", nil)
	for _, n := range []int{4, 1, 9, 2, 7} {
		e.uploadPart("mpp", "k", id, n, []byte(fmt.Sprintf("p%d", n)))
	}
	var got []int
	marker := 0
	for guard := 0; ; guard++ {
		if guard > 10 {
			t.Fatal("did not terminate")
		}
		resp, body := e.do("GET", fmt.Sprintf("/mpp/k?uploadId=%s&max-parts=2&part-number-marker=%d", id, marker), nil, nil)
		var r listPartsResult
		if err := xml.Unmarshal(body, &r); err != nil || resp.StatusCode != 200 {
			t.Fatalf("%d %v %s", resp.StatusCode, err, body)
		}
		if r.MaxParts != 2 || r.PartNumberMarker != marker {
			t.Errorf("echo: %+v", r)
		}
		for _, p := range r.Parts {
			got = append(got, p.PartNumber)
		}
		if !r.IsTruncated {
			break
		}
		if r.NextPartNumberMarker <= marker {
			t.Fatalf("marker did not advance: %+v", r)
		}
		marker = r.NextPartNumberMarker
	}
	if fmt.Sprint(got) != "[1 2 4 7 9]" {
		t.Errorf("parts = %v", got)
	}
	resp, body := e.do("GET", "/mpp/k?uploadId="+id+"&max-parts=0", nil, nil)
	var r listPartsResult
	xml.Unmarshal(body, &r)
	if resp.StatusCode != 200 || len(r.Parts) != 0 || r.IsTruncated {
		t.Errorf("max-parts=0: %d %+v", resp.StatusCode, r)
	}
}

func TestMultipartAuthorization(t *testing.T) {
	e := newEnv(t)
	e.mb("mpa")
	e.mb("private")
	e.put("/private/secret.bin", "classified", nil)
	e.mb("scoped")
	rootID := e.initiate("mpa", "k", nil)
	e.uploadPart("mpa", "k", rootID, 1, []byte("root part"))

	tests := []struct {
		name         string
		user         string
		method, path string
		body         string
		status       int
	}{
		// uploader: PutObject, GetObject, Abort, ListParts, ListUploads on mpa
		{"uploader initiates", "uploader", "POST", "/mpa/up?uploads", "", 200},
		{"uploader lists uploads", "uploader", "GET", "/mpa?uploads", "", 200},
		{"uploader lists parts", "uploader", "GET", "/mpa/k?uploadId=" + rootID, "", 200},
		{"uploader uploads a part", "uploader", "PUT", "/mpa/k?partNumber=2&uploadId=" + rootID, "more", 200},
		{"uploader aborts", "uploader", "DELETE", "/mpa/up2?uploadId=00000000-0000-4000-8000-000000000000", "", 404},
		{"uploader cannot initiate elsewhere", "uploader", "POST", "/private/k?uploads", "", 403},
		{"uploader cannot list uploads elsewhere", "uploader", "GET", "/private?uploads", "", 403},
		// reader: read-only policy has none of the multipart write actions
		{"reader cannot initiate", "reader", "POST", "/mpa/r?uploads", "", 403},
		{"reader cannot upload a part", "reader", "PUT", "/mpa/k?partNumber=3&uploadId=" + rootID, "x", 403},
		{"reader cannot abort", "reader", "DELETE", "/mpa/k?uploadId=" + rootID, "", 403},
		{"reader cannot list parts", "reader", "GET", "/mpa/k?uploadId=" + rootID, "", 403},
		{"reader cannot list uploads", "reader", "GET", "/mpa?uploads", "", 403},
		{"reader cannot complete", "reader", "POST", "/mpa/k?uploadId=" + rootID, completeXML([2]string{"1", `"x"`}), 403},
		// writer: s3:PutObject only, which covers create, upload and complete
		{"writer initiates", "writer", "POST", "/mpa/w?uploads", "", 200},
		{"writer cannot abort", "writer", "DELETE", "/mpa/k?uploadId=" + rootID, "", 403},
		{"writer cannot list parts", "writer", "GET", "/mpa/k?uploadId=" + rootID, "", 403},
		{"writer cannot list uploads", "writer", "GET", "/mpa?uploads", "", 403},
		// scoped: PutObject only under scoped/pub/
		{"scoped initiates in its prefix", "scoped", "POST", "/scoped/pub/k?uploads", "", 200},
		{"scoped cannot initiate outside it", "scoped", "POST", "/scoped/priv/k?uploads", "", 403},
		// nobody and anonymous
		{"nobody cannot initiate", "nobody", "POST", "/mpa/n?uploads", "", 403},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, body := e.doAs(tt.user, tt.method, tt.path, strings.NewReader(tt.body), nil)
			if resp.StatusCode != tt.status {
				t.Fatalf("status %d, want %d: %s", resp.StatusCode, tt.status, body)
			}
			if tt.status == 403 {
				wantError(t, resp, body, 403, "AccessDenied")
			}
		})
	}
	// Anonymous callers cannot touch uploads either.
	for _, c := range []struct{ method, path string }{
		{"POST", "/mpa/k?uploads"}, {"PUT", "/mpa/k?partNumber=1&uploadId=" + rootID},
		{"GET", "/mpa?uploads"}, {"DELETE", "/mpa/k?uploadId=" + rootID},
	} {
		resp, body := e.doAnon(c.method, c.path, strings.NewReader("x"), nil)
		wantError(t, resp, body, 403, "AccessDenied")
	}

	t.Run("UploadPartCopy needs read access to the source", func(t *testing.T) {
		resp, body := e.doAs("uploader", "PUT", "/mpa/k?partNumber=5&uploadId="+rootID, nil,
			hdr{"x-amz-copy-source": "/private/secret.bin"})
		wantError(t, resp, body, 403, "AccessDenied")
		// The part must not exist: nothing was copied.
		resp, body = e.do("GET", "/mpa/k?uploadId="+rootID, nil, nil)
		if strings.Contains(string(body), "<PartNumber>5</PartNumber>") {
			t.Errorf("a denied copy created a part: %s", body)
		}
		// With the source readable (the bucket the user may read), it works.
		e.put("/mpa/readable.txt", "readable", nil)
		resp, body = e.doAs("uploader", "PUT", "/mpa/k?partNumber=5&uploadId="+rootID, nil,
			hdr{"x-amz-copy-source": "/mpa/readable.txt"})
		if resp.StatusCode != 200 {
			t.Errorf("%d %s", resp.StatusCode, body)
		}
	})
	t.Run("a user who cannot see the source learns nothing about it", func(t *testing.T) {
		_, a := e.doAs("uploader", "PUT", "/mpa/k?partNumber=6&uploadId="+rootID, nil, hdr{"x-amz-copy-source": "/private/secret.bin"})
		_, b := e.doAs("uploader", "PUT", "/mpa/k?partNumber=6&uploadId="+rootID, nil, hdr{"x-amz-copy-source": "/private/no-such-object"})
		_, c := e.doAs("uploader", "PUT", "/mpa/k?partNumber=6&uploadId="+rootID, nil, hdr{"x-amz-copy-source": "/no-such-bucket/x"})
		for _, body := range [][]byte{a, b, c} {
			if !strings.Contains(string(body), "<Code>AccessDenied</Code>") {
				t.Errorf("response: %s", body)
			}
		}
	})
}

func TestMultipartPartsViaSignedStreaming(t *testing.T) {
	e := newEnv(t)
	e.mb("mps")
	id := e.initiate("mps", "streamed", nil)
	path := func(n int) string { return fmt.Sprintf("/mps/streamed?partNumber=%d&uploadId=%s", n, id) }

	data := bytes.Repeat([]byte("0123456789abcdef"), 4096) // 64 KiB
	resp, body := e.streamingPut(path(1), streamOpts{parts: []string{string(data[:20000]), string(data[20000:])}})
	if resp.StatusCode != 200 {
		t.Fatalf("signed streaming part: %d %s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("ETag"); got != `"`+md5Bytes(data)+`"` {
		t.Errorf("ETag %s", got)
	}

	// Tampered data inside a signed chunk: rejected, and no part appears.
	resp, body = e.streamingPut(path(2), streamOpts{parts: []string{"clean", "dirty"},
		mutate: func(c []encChunk) []encChunk { c[1].data = "DIRTY"; return c }})
	wantError(t, resp, body, 403, "SignatureDoesNotMatch")
	resp, body = e.do("GET", "/mps/streamed?uploadId="+id, nil, nil)
	var r listPartsResult
	xml.Unmarshal(body, &r)
	if len(r.Parts) != 1 || r.Parts[0].PartNumber != 1 {
		t.Errorf("parts after a rejected streaming upload: %+v", r.Parts)
	}

	// Unsigned-trailer framing (what newer SDKs send) works too.
	resp, body = e.streamingPut(path(3), streamOpts{kind: auth.PayloadStreamingUnsigned,
		parts: []string{"trailing checksum payload"}, trailers: []string{"x-amz-checksum-crc32:AAAAAA=="}})
	if resp.StatusCode != 200 {
		t.Errorf("unsigned-trailer part: %d %s", resp.StatusCode, body)
	}
}

func TestMultipartVirtualHostStyle(t *testing.T) {
	e := newEnv(t)
	e.mb("vhm")
	host := hdr{"Host": "vhm.localhost:9000"}
	resp, body := e.do("POST", "/obj.bin?uploads", nil, host)
	var init initiateMultipartUploadResult
	if err := xml.Unmarshal(body, &init); err != nil || resp.StatusCode != 200 || init.Bucket != "vhm" || init.Key != "obj.bin" {
		t.Fatalf("%d %v %s", resp.StatusCode, err, body)
	}
	resp, _ = e.do("PUT", "/obj.bin?partNumber=1&uploadId="+init.UploadID, strings.NewReader("virtual part"), host)
	etag := resp.Header.Get("ETag")
	if resp.StatusCode != 200 || etag == "" {
		t.Fatalf("part: %d", resp.StatusCode)
	}
	resp, body = e.do("POST", "/obj.bin?uploadId="+init.UploadID, strings.NewReader(completeXML([2]string{"1", etag})), host)
	if resp.StatusCode != 200 {
		t.Fatalf("complete: %d %s", resp.StatusCode, body)
	}
	if got, _ := e.get("/vhm/obj.bin"); got != "virtual part" {
		t.Errorf("object = %q", got)
	}
}
