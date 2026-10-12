package storagetest

import (
	"strings"
	"testing"
	"time"

	"nanoio/internal/storage"
)

func testUpdateMetadata(t *testing.T, f Factory) {
	h := newHarness(t, f)
	h.mkbucket("meta")
	put, err := h.be.PutObject(bg, "meta", "k", strings.NewReader("hello"), 5, storage.PutOptions{
		ContentType: "text/plain", UserDefined: map[string]string{"x-amz-meta-a": "1", "x-nanoio-internal-x": "keep"},
	})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)

	// Replace metadata and content type; ETag, size and body are untouched
	// and the modification time stays.
	info, err := h.be.UpdateObjectMetadata(bg, "meta", "k", storage.UpdateMetaOptions{
		UserDefined: map[string]string{"x-amz-meta-b": "2"}, ContentType: "text/html",
	})
	if err != nil {
		t.Fatalf("UpdateObjectMetadata: %v", err)
	}
	if info.ETag != put.ETag || info.Size != 5 || info.ContentType != "text/html" || !info.ModTime.Equal(put.ModTime) {
		t.Errorf("returned info = %+v, want ETag %s, size 5, text/html, ModTime %v", info, put.ETag, put.ModTime)
	}
	if len(info.UserDefined) != 1 || info.UserDefined["x-amz-meta-b"] != "2" {
		t.Errorf("UserDefined = %v", info.UserDefined)
	}
	body, got := h.get("meta", "k")
	if body != "hello" || got.ETag != put.ETag || got.UserDefined["x-amz-meta-b"] != "2" || got.ContentType != "text/html" {
		t.Errorf("after update: body %q info %+v", body, got)
	}
	if st, _ := h.be.StatObject(bg, "meta", "k", storage.GetOptions{}); !st.ModTime.Equal(put.ModTime) {
		t.Errorf("ModTime changed without Touch: %v != %v", st.ModTime, put.ModTime)
	}

	// nil UserDefined leaves the map alone; Touch moves the time.
	info, err = h.be.UpdateObjectMetadata(bg, "meta", "k", storage.UpdateMetaOptions{Touch: true})
	if err != nil {
		t.Fatal(err)
	}
	if info.UserDefined["x-amz-meta-b"] != "2" || !info.ModTime.After(put.ModTime) {
		t.Errorf("Touch update: %+v", info)
	}

	// An empty non-nil map clears.
	info, err = h.be.UpdateObjectMetadata(bg, "meta", "k", storage.UpdateMetaOptions{UserDefined: map[string]string{}})
	if err != nil || len(info.UserDefined) != 0 {
		t.Errorf("clear: %+v, %v", info.UserDefined, err)
	}
	if _, st := h.get("meta", "k"); len(st.UserDefined) != 0 {
		t.Errorf("clear not persisted: %v", st.UserDefined)
	}

	// Conditional on the ETag: a rewritten object is not overwritten.
	old := h.stat("meta", "k", "")
	h.put("meta", "k", "second")
	_, err = h.be.UpdateObjectMetadata(bg, "meta", "k", storage.UpdateMetaOptions{
		UserDefined: map[string]string{"x-amz-meta-stale": "yes"}, IfETag: old.ETag,
	})
	wantErr(t, "stale IfETag", err, storage.ErrPreconditionFailed)
	if _, st := h.get("meta", "k"); st.UserDefined["x-amz-meta-stale"] != "" {
		t.Error("a stale update was applied")
	}
	cur := h.stat("meta", "k", "")
	if _, err := h.be.UpdateObjectMetadata(bg, "meta", "k", storage.UpdateMetaOptions{
		UserDefined: map[string]string{"x-amz-meta-ok": "1"}, IfETag: cur.ETag,
	}); err != nil {
		t.Errorf("matching IfETag: %v", err)
	}

	// Errors.
	_, err = h.be.UpdateObjectMetadata(bg, "meta", "absent", storage.UpdateMetaOptions{Touch: true})
	wantErr(t, "missing object", err, storage.ErrObjectNotFound)
	_, err = h.be.UpdateObjectMetadata(bg, "nobucket", "k", storage.UpdateMetaOptions{Touch: true})
	wantErr(t, "missing bucket", err, storage.ErrBucketNotFound)
}

func testUpdateMetadataMultipartAndVersions(t *testing.T, f Factory) {
	h := newHarness(t, f)
	h.mkbucket("metaver")
	if err := h.be.SetBucketVersioning(bg, "metaver", storage.VersioningEnabled); err != nil {
		t.Fatal(err)
	}
	v1 := h.put("metaver", "k", "one")
	v2 := h.put("metaver", "k", "two")

	// Update the older version only.
	if _, err := h.be.UpdateObjectMetadata(bg, "metaver", "k", storage.UpdateMetaOptions{
		VersionID: v1.VersionID, UserDefined: map[string]string{"x-amz-meta-v": "1"},
	}); err != nil {
		t.Fatal(err)
	}
	if got := h.stat("metaver", "k", v1.VersionID); got.UserDefined["x-amz-meta-v"] != "1" {
		t.Errorf("v1 = %+v", got.UserDefined)
	}
	if got := h.stat("metaver", "k", v2.VersionID); got.UserDefined["x-amz-meta-v"] != "" {
		t.Errorf("v2 changed: %+v", got.UserDefined)
	}
	vs, err := h.be.ListObjectVersions(bg, "metaver", storage.ListOptions{})
	if err != nil || len(vs.Versions) != 2 {
		t.Fatalf("versions = %d, %v", len(vs.Versions), err)
	}

	// A multipart object keeps its parts and ETag.
	id, err := h.be.NewMultipartUpload(bg, "metaver", "mp", storage.PutOptions{UserDefined: map[string]string{"x-amz-meta-m": "0"}})
	if err != nil {
		t.Fatal(err)
	}
	p1 := strings.Repeat("a", 5<<20)
	pi1, err := h.be.PutObjectPart(bg, "metaver", "mp", id, 1, strings.NewReader(p1), int64(len(p1)), storage.PartOptions{})
	if err != nil {
		t.Fatal(err)
	}
	pi2, err := h.be.PutObjectPart(bg, "metaver", "mp", id, 2, strings.NewReader("tail"), 4, storage.PartOptions{})
	if err != nil {
		t.Fatal(err)
	}
	done, err := h.be.CompleteMultipartUpload(bg, "metaver", "mp", id,
		[]storage.CompletePart{{Number: 1, ETag: pi1.ETag}, {Number: 2, ETag: pi2.ETag}}, storage.PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	upd, err := h.be.UpdateObjectMetadata(bg, "metaver", "mp", storage.UpdateMetaOptions{UserDefined: map[string]string{"x-amz-meta-m": "1"}})
	if err != nil {
		t.Fatal(err)
	}
	if upd.ETag != done.ETag || len(upd.Parts) != 2 || upd.Parts[0].Size != int64(len(p1)) || upd.Parts[1].Number != 2 {
		t.Errorf("multipart after update: %+v", upd)
	}
	rc, _, err := h.be.GetObject(bg, "metaver", "mp", storage.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	rc.Close()
}

func testPutFinalize(t *testing.T, f Factory) {
	h := newHarness(t, f)
	h.mkbucket("fin")
	var calls int
	info, err := h.be.PutObject(bg, "fin", "k", strings.NewReader("data"), 4, storage.PutOptions{
		UserDefined: map[string]string{"x-amz-meta-a": "1"},
		Finalize: func() map[string]string {
			calls++
			return map[string]string{"x-nanoio-internal-seal": "s"}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Errorf("Finalize called %d times", calls)
	}
	st := h.stat("fin", "k", info.VersionID)
	if st.UserDefined["x-nanoio-internal-seal"] != "s" || st.UserDefined["x-amz-meta-a"] != "1" {
		t.Errorf("UserDefined = %v", st.UserDefined)
	}
	// Not called when the body fails verification.
	calls = 0
	_, err = h.be.PutObject(bg, "fin", "k2", strings.NewReader("data"), 4, storage.PutOptions{
		ContentMD5: strings.Repeat("0", 32), Finalize: func() map[string]string { calls++; return nil },
	})
	wantErr(t, "bad digest", err, storage.ErrBadDigest)
	if calls != 0 {
		t.Error("Finalize ran for a rejected body")
	}
}
