// Package storagetest is the conformance suite every storage.StorageAPI
// backend must pass unchanged. A backend's own test calls Run with a factory
// that builds a fresh, empty instance around the supplied Locker.
package storagetest

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"nanoio/internal/bucket/nslock"
	"nanoio/internal/storage"
)

// Factory returns a fresh empty backend that takes its namespace locks from
// locker. The suite closes it.
type Factory func(t *testing.T, locker storage.Locker) storage.StorageAPI

// recorder wraps a Locker, logging acquisitions and counting held locks.
type recorder struct {
	storage.Locker
	mu   sync.Mutex
	held int
	log  []string
}

func (r *recorder) wrap(kind, bucket, object string, u func(), err error) (func(), error) {
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.held++
	r.log = append(r.log, kind+" "+bucket+"/"+object)
	r.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			r.mu.Lock()
			r.held--
			r.mu.Unlock()
			u()
		})
	}, nil
}

func (r *recorder) Lock(ctx context.Context, bucket, object string) (func(), error) {
	u, err := r.Locker.Lock(ctx, bucket, object)
	return r.wrap("Lock", bucket, object, u, err)
}

func (r *recorder) RLock(ctx context.Context, bucket, object string) (func(), error) {
	u, err := r.Locker.RLock(ctx, bucket, object)
	return r.wrap("RLock", bucket, object, u, err)
}

func (r *recorder) reset() {
	r.mu.Lock()
	r.log = nil
	r.mu.Unlock()
}

func (r *recorder) snapshot() (held int, log []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.held, append([]string(nil), r.log...)
}

type harness struct {
	t   *testing.T
	be  storage.StorageAPI
	rec *recorder
}

func newHarness(t *testing.T, f Factory) *harness {
	t.Helper()
	rec := &recorder{Locker: nslock.New(10 * time.Second)}
	be := f(t, rec)
	t.Cleanup(func() {
		if err := be.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
		if held, _ := rec.snapshot(); held != 0 {
			t.Errorf("%d namespace locks still held after the test", held)
		}
	})
	return &harness{t: t, be: be, rec: rec}
}

var bg = context.Background()

func (h *harness) mkbucket(name string) {
	h.t.Helper()
	if err := h.be.MakeBucket(bg, name, storage.MakeBucketOptions{}); err != nil {
		h.t.Fatalf("MakeBucket(%q): %v", name, err)
	}
}

func (h *harness) put(bucket, key, body string) storage.ObjectInfo {
	h.t.Helper()
	info, err := h.be.PutObject(bg, bucket, key, strings.NewReader(body), int64(len(body)), storage.PutOptions{})
	if err != nil {
		h.t.Fatalf("PutObject(%q/%q): %v", bucket, key, err)
	}
	return info
}

func (h *harness) get(bucket, key string) (string, storage.ObjectInfo) {
	h.t.Helper()
	rc, info, err := h.be.GetObject(bg, bucket, key, storage.GetOptions{})
	if err != nil {
		h.t.Fatalf("GetObject(%q/%q): %v", bucket, key, err)
	}
	defer rc.Close()
	b, err := io.ReadAll(rc)
	if err != nil {
		h.t.Fatalf("read %q/%q: %v", bucket, key, err)
	}
	return string(b), info
}

func md5hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func wantErr(t *testing.T, what string, got, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Errorf("%s: error = %v, want %v", what, got, want)
	}
}

// Run executes the whole suite against backends built by newBackend.
func Run(t *testing.T, newBackend Factory) {
	for _, tc := range []struct {
		name string
		fn   func(*testing.T, Factory)
	}{
		{"Buckets", testBuckets},
		{"BucketNames", testBucketNames},
		{"PutGetStat", testPutGetStat},
		{"PutErrors", testPutErrors},
		{"Overwrite", testOverwrite},
		{"Ranges", testRanges},
		{"Missing", testMissing},
		{"Delete", testDelete},
		{"SnapshotReads", testSnapshotReads},
		{"List", testList},
		{"ListPagination", testListPagination},
		{"Locking", testLocking},
		{"Concurrency", testConcurrency},
		{"Cancellation", testCancellation},
		{"Multipart", testMultipart},
		{"MultipartErrors", testMultipartErrors},
		{"MultipartListing", testMultipartListing},
		{"MultipartConcurrency", testMultipartConcurrency},
		{"VersioningState", testVersioningState},
		{"UpdateMetadata", testUpdateMetadata},
		{"UpdateMetadataMultipartAndVersions", testUpdateMetadataMultipartAndVersions},
		{"PutFinalize", testPutFinalize},
		{"Closed", testClosed},
	} {
		t.Run(tc.name, func(t *testing.T) { tc.fn(t, newBackend) })
	}
}

func testBuckets(t *testing.T, f Factory) {
	h := newHarness(t, f)
	for _, b := range []string{"charlie", "alpha", "bravo"} {
		h.mkbucket(b)
	}
	wantErr(t, "duplicate MakeBucket", h.be.MakeBucket(bg, "alpha", storage.MakeBucketOptions{}), storage.ErrBucketExists)

	list, err := h.be.ListBuckets(bg)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, b := range list {
		names = append(names, b.Name)
		if age := time.Since(b.Created); b.Created.IsZero() || age < -time.Minute || age > time.Minute {
			t.Errorf("bucket %s Created = %v", b.Name, b.Created)
		}
	}
	if got, want := strings.Join(names, ","), "alpha,bravo,charlie"; got != want {
		t.Errorf("ListBuckets = %s, want %s", got, want)
	}

	i1, err := h.be.GetBucketInfo(bg, "alpha")
	if err != nil || i1.Name != "alpha" {
		t.Fatalf("GetBucketInfo = %+v, %v", i1, err)
	}
	h.put("alpha", "k", "v") // must not move Created
	if i2, _ := h.be.GetBucketInfo(bg, "alpha"); !i2.Created.Equal(i1.Created) {
		t.Errorf("Created changed from %v to %v after a write", i1.Created, i2.Created)
	}

	for _, tt := range []struct {
		name string
		call func() (bool, error)
		want bool
	}{
		{"exists", func() (bool, error) { return h.be.BucketExists(bg, "bravo") }, true},
		{"missing", func() (bool, error) { return h.be.BucketExists(bg, "delta") }, false},
	} {
		got, err := tt.call()
		if err != nil || got != tt.want {
			t.Errorf("BucketExists %s = %v, %v; want %v", tt.name, got, err, tt.want)
		}
	}
	_, err = h.be.GetBucketInfo(bg, "delta")
	wantErr(t, "GetBucketInfo(missing)", err, storage.ErrBucketNotFound)
	wantErr(t, "DeleteBucket(missing)", h.be.DeleteBucket(bg, "delta", storage.DeleteBucketOptions{}), storage.ErrBucketNotFound)

	wantErr(t, "DeleteBucket(non-empty)", h.be.DeleteBucket(bg, "alpha", storage.DeleteBucketOptions{}), storage.ErrBucketNotEmpty)
	if ok, _ := h.be.BucketExists(bg, "alpha"); !ok {
		t.Error("non-empty bucket vanished after refused delete")
	}
	if got, _ := h.get("alpha", "k"); got != "v" {
		t.Error("object lost after refused bucket delete")
	}
	if err := h.be.DeleteBucket(bg, "alpha", storage.DeleteBucketOptions{Force: true}); err != nil {
		t.Errorf("forced delete: %v", err)
	}
	if err := h.be.DeleteBucket(bg, "bravo", storage.DeleteBucketOptions{}); err != nil {
		t.Errorf("delete empty: %v", err)
	}
	if ok, _ := h.be.BucketExists(bg, "bravo"); ok {
		t.Error("deleted bucket still exists")
	}
	// A deleted bucket's name is reusable and starts empty.
	h.mkbucket("alpha")
	res, err := h.be.ListObjects(bg, "alpha", storage.ListOptions{})
	if err != nil || len(res.Objects) != 0 {
		t.Errorf("recreated bucket not empty: %+v, %v", res, err)
	}
}

func testBucketNames(t *testing.T, f Factory) {
	h := newHarness(t, f)
	for _, name := range []string{"ab", "UPPER", "has_underscore", "-lead", "trail-", ".nanoio.sys", "a..b", "10.0.0.1", strings.Repeat("a", 64)} {
		t.Run(name, func(t *testing.T) {
			wantErr(t, "MakeBucket", h.be.MakeBucket(bg, name, storage.MakeBucketOptions{}), storage.ErrInvalidBucketName)
			_, err := h.be.GetBucketInfo(bg, name)
			wantErr(t, "GetBucketInfo", err, storage.ErrInvalidBucketName)
			ok, err := h.be.BucketExists(bg, name)
			wantErr(t, "BucketExists", err, storage.ErrInvalidBucketName)
			if ok {
				t.Error("BucketExists = true for invalid name")
			}
			wantErr(t, "DeleteBucket", h.be.DeleteBucket(bg, name, storage.DeleteBucketOptions{}), storage.ErrInvalidBucketName)
			_, err = h.be.PutObject(bg, name, "k", strings.NewReader(""), 0, storage.PutOptions{})
			wantErr(t, "PutObject", err, storage.ErrInvalidBucketName)
		})
	}
	if list, _ := h.be.ListBuckets(bg); len(list) != 0 {
		t.Errorf("invalid names created buckets: %+v", list)
	}
}

func testPutGetStat(t *testing.T, f Factory) {
	h := newHarness(t, f)
	h.mkbucket("data")
	big := make([]byte, 1<<20+17)
	rand.New(rand.NewSource(1)).Read(big)

	tests := []struct {
		name string
		key  string
		body string
		ct   string
		meta map[string]string
	}{
		{"empty body", "empty", "", "", nil},
		{"small", "hello.txt", "hello", "text/plain", nil},
		{"default content type", "noct", "x", "", nil},
		{"nested key", "a/b/c.txt", "nested", "text/plain", nil},
		{"unicode key", "日本語/ファイル.txt", "unicode", "", nil},
		{"user metadata", "meta", "m", "text/plain", map[string]string{"x-amz-meta-owner": "alice", "x-amz-meta-n": "1"}},
		{"folder placeholder", "folder/", "", "application/x-directory", nil},
		{"1 MiB+", "big.bin", string(big), "application/octet-stream", nil},
		{"spaces and symbols", "a b/c+d=e&f.txt", "sym", "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			put, err := h.be.PutObject(bg, "data", tt.key, strings.NewReader(tt.body), int64(len(tt.body)),
				storage.PutOptions{ContentType: tt.ct, UserDefined: tt.meta})
			if err != nil {
				t.Fatalf("PutObject: %v", err)
			}
			wantCT := tt.ct
			if wantCT == "" {
				wantCT = "binary/octet-stream"
			}
			check := func(what string, info storage.ObjectInfo) {
				t.Helper()
				if info.Bucket != "data" || info.Name != tt.key {
					t.Errorf("%s: identity = %q/%q", what, info.Bucket, info.Name)
				}
				if info.Size != int64(len(tt.body)) {
					t.Errorf("%s: Size = %d, want %d", what, info.Size, len(tt.body))
				}
				if info.ETag != md5hex(tt.body) {
					t.Errorf("%s: ETag = %q, want %q", what, info.ETag, md5hex(tt.body))
				}
				if info.ContentType != wantCT {
					t.Errorf("%s: ContentType = %q, want %q", what, info.ContentType, wantCT)
				}
				if len(tt.meta) != len(info.UserDefined) {
					t.Errorf("%s: UserDefined = %v, want %v", what, info.UserDefined, tt.meta)
				}
				for k, v := range tt.meta {
					if info.UserDefined[k] != v {
						t.Errorf("%s: UserDefined[%q] = %q, want %q", what, k, info.UserDefined[k], v)
					}
				}
				if info.DeleteMarker {
					t.Errorf("%s: unexpected delete marker", what)
				}
				if d := time.Since(info.ModTime); info.ModTime.IsZero() || d < -time.Minute || d > time.Minute {
					t.Errorf("%s: ModTime = %v", what, info.ModTime)
				}
			}
			check("put", put)
			stat, err := h.be.StatObject(bg, "data", tt.key, storage.GetOptions{})
			if err != nil {
				t.Fatalf("StatObject: %v", err)
			}
			check("stat", stat)
			body, info := h.get("data", tt.key)
			check("get", info)
			if body != tt.body {
				t.Errorf("body differs (got %d bytes, want %d)", len(body), len(tt.body))
			}
		})
	}

	t.Run("unknown size", func(t *testing.T) {
		info, err := h.be.PutObject(bg, "data", "stream", strings.NewReader("streamed"), -1, storage.PutOptions{})
		if err != nil || info.Size != 8 {
			t.Fatalf("Put(size -1) = %+v, %v", info, err)
		}
		if got, _ := h.get("data", "stream"); got != "streamed" {
			t.Errorf("body = %q", got)
		}
	})
	t.Run("accepted digests", func(t *testing.T) {
		_, err := h.be.PutObject(bg, "data", "digests", strings.NewReader("abc"), 3, storage.PutOptions{
			ContentMD5: strings.ToUpper(md5hex("abc")), ContentSHA256: sha256hex("abc"),
		})
		if err != nil {
			t.Errorf("valid digests rejected: %v", err)
		}
	})
}

func testPutErrors(t *testing.T, f Factory) {
	h := newHarness(t, f)
	h.mkbucket("errs")
	put := func(key, body string, size int64, o storage.PutOptions) error {
		_, err := h.be.PutObject(bg, "errs", key, strings.NewReader(body), size, o)
		return err
	}
	absent := func(t *testing.T, key string) {
		t.Helper()
		_, err := h.be.StatObject(bg, "errs", key, storage.GetOptions{})
		wantErr(t, "object must not exist: "+key, err, storage.ErrObjectNotFound)
	}

	h.put("errs", "existing", "v1")
	etag := md5hex("v1")
	tests := []struct {
		name string
		key  string
		body string
		size int64
		opts storage.PutOptions
		want error
		keep string // key that must still hold "v1"
	}{
		{"body shorter than size", "short", "abc", 10, storage.PutOptions{}, storage.ErrIncompleteBody, ""},
		{"md5 mismatch", "md5", "abc", 3, storage.PutOptions{ContentMD5: md5hex("other")}, storage.ErrBadDigest, ""},
		{"sha256 mismatch", "sha", "abc", 3, storage.PutOptions{ContentSHA256: sha256hex("other")}, storage.ErrSHA256Mismatch, ""},
		{"failed overwrite keeps old", "existing", "abc", 10, storage.PutOptions{}, storage.ErrIncompleteBody, "existing"},
		{"bad digest overwrite keeps old", "existing", "abc", 3, storage.PutOptions{ContentMD5: md5hex("other")}, storage.ErrBadDigest, "existing"},
		{"if-none-match on existing", "existing", "v2", 2, storage.PutOptions{IfNoneMatch: "*"}, storage.ErrPreconditionFailed, "existing"},
		{"if-match wrong etag", "existing", "v2", 2, storage.PutOptions{IfMatch: md5hex("nope")}, storage.ErrPreconditionFailed, "existing"},
		{"if-match on missing", "ghost", "v", 1, storage.PutOptions{IfMatch: etag}, storage.ErrPreconditionFailed, ""},
		{"too large", "huge", "", 6 << 40, storage.PutOptions{}, storage.ErrEntityTooLarge, ""},
		{"empty key", "", "x", 1, storage.PutOptions{}, storage.ErrInvalidObjectName, ""},
		{"dotdot key", "a/../b", "x", 1, storage.PutOptions{}, storage.ErrInvalidObjectName, ""},
		{"empty segment", "a//b", "x", 1, storage.PutOptions{}, storage.ErrInvalidObjectName, ""},
		{"reserved name", "dir/xl.meta", "x", 1, storage.PutOptions{}, storage.ErrInvalidObjectName, ""},
		{"reserved prefix", ".nanoio-x", "x", 1, storage.PutOptions{}, storage.ErrInvalidObjectName, ""},
		{"key too long", strings.Repeat("a", 300), "x", 1, storage.PutOptions{}, storage.ErrKeyTooLong, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantErr(t, "PutObject", put(tt.key, tt.body, tt.size, tt.opts), tt.want)
			if tt.keep != "" {
				if got, _ := h.get("errs", tt.keep); got != "v1" {
					t.Errorf("existing object changed to %q", got)
				}
			} else if tt.key != "" && tt.want != storage.ErrInvalidObjectName && tt.want != storage.ErrKeyTooLong {
				absent(t, tt.key)
			}
		})
	}

	t.Run("missing bucket", func(t *testing.T) {
		_, err := h.be.PutObject(bg, "nobucket", "k", strings.NewReader("x"), 1, storage.PutOptions{})
		wantErr(t, "PutObject", err, storage.ErrBucketNotFound)
		if ok, _ := h.be.BucketExists(bg, "nobucket"); ok {
			t.Error("PutObject created the bucket")
		}
	})
	t.Run("conditions that pass", func(t *testing.T) {
		if err := put("fresh", "x", 1, storage.PutOptions{IfNoneMatch: "*"}); err != nil {
			t.Errorf("if-none-match on missing: %v", err)
		}
		if err := put("existing", "v2", 2, storage.PutOptions{IfMatch: `"` + etag + `"`}); err != nil {
			t.Errorf("if-match with quoted etag: %v", err)
		}
		if got, _ := h.get("errs", "existing"); got != "v2" {
			t.Errorf("body = %q, want v2", got)
		}
	})
	t.Run("nothing leaked into listing", func(t *testing.T) {
		res, err := h.be.ListObjects(bg, "errs", storage.ListOptions{})
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, o := range res.Objects {
			got = append(got, o.Name)
		}
		if want := "existing,fresh"; strings.Join(got, ",") != want {
			t.Errorf("listing = %v, want %s", got, want)
		}
	})
}

func testOverwrite(t *testing.T, f Factory) {
	h := newHarness(t, f)
	h.mkbucket("owr")
	first := h.put("owr", "k", "first version")
	second := h.put("owr", "k", "v2")
	if got, info := h.get("owr", "k"); got != "v2" || info.ETag != second.ETag || info.ETag == first.ETag || info.Size != 2 {
		t.Errorf("after overwrite: body=%q info=%+v", got, info)
	}
	res, err := h.be.ListObjects(bg, "owr", storage.ListOptions{})
	if err != nil || len(res.Objects) != 1 || res.Objects[0].Size != 2 {
		t.Errorf("listing after overwrite = %+v, %v", res, err)
	}
	h.put("owr", "k", "") // overwrite with empty
	if got, info := h.get("owr", "k"); got != "" || info.Size != 0 {
		t.Errorf("empty overwrite: body=%q size=%d", got, info.Size)
	}
}

func testRanges(t *testing.T, f Factory) {
	h := newHarness(t, f)
	h.mkbucket("rng")
	h.put("rng", "digits", "0123456789")
	h.put("rng", "empty", "")
	tests := []struct {
		name  string
		key   string
		rng   storage.ByteRange
		want  string
		errIs error
	}{
		{"whole via range", "digits", storage.ByteRange{Start: 0, Length: 10}, "0123456789", nil},
		{"first byte", "digits", storage.ByteRange{Start: 0, Length: 1}, "0", nil},
		{"middle", "digits", storage.ByteRange{Start: 3, Length: 4}, "3456", nil},
		{"last byte", "digits", storage.ByteRange{Start: 9, Length: 1}, "9", nil},
		{"negative start", "digits", storage.ByteRange{Start: -1, Length: 2}, "", storage.ErrInvalidRange},
		{"zero length", "digits", storage.ByteRange{Start: 0, Length: 0}, "", storage.ErrInvalidRange},
		{"past end", "digits", storage.ByteRange{Start: 5, Length: 6}, "", storage.ErrInvalidRange},
		{"start at size", "digits", storage.ByteRange{Start: 10, Length: 1}, "", storage.ErrInvalidRange},
		{"range on empty object", "empty", storage.ByteRange{Start: 0, Length: 1}, "", storage.ErrInvalidRange},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rg := tt.rng
			rc, info, err := h.be.GetObject(bg, "rng", tt.key, storage.GetOptions{Range: &rg})
			if tt.errIs != nil {
				wantErr(t, "GetObject", err, tt.errIs)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer rc.Close()
			b, _ := io.ReadAll(rc)
			if string(b) != tt.want {
				t.Errorf("body = %q, want %q", b, tt.want)
			}
			if info.Size != 10 {
				t.Errorf("info.Size = %d, want full size 10", info.Size)
			}
		})
	}
}

func testMissing(t *testing.T, f Factory) {
	h := newHarness(t, f)
	h.mkbucket("have")
	tests := []struct {
		name        string
		bucket, key string
		want        error
	}{
		{"missing key", "have", "nope", storage.ErrObjectNotFound},
		{"missing nested key", "have", "a/b/c", storage.ErrObjectNotFound},
		{"missing bucket", "gone", "k", storage.ErrBucketNotFound},
		{"invalid key", "have", "a/../b", storage.ErrInvalidObjectName},
		{"invalid bucket", "X", "k", storage.ErrInvalidBucketName},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := h.be.StatObject(bg, tt.bucket, tt.key, storage.GetOptions{})
			wantErr(t, "StatObject", err, tt.want)
			rc, _, err := h.be.GetObject(bg, tt.bucket, tt.key, storage.GetOptions{})
			wantErr(t, "GetObject", err, tt.want)
			if rc != nil {
				rc.Close()
				t.Error("GetObject returned a reader with an error")
			}
		})
	}
	// A directory-like prefix is not an object.
	h.put("have", "dir/file", "x")
	_, err := h.be.StatObject(bg, "have", "dir", storage.GetOptions{})
	wantErr(t, "Stat(prefix)", err, storage.ErrObjectNotFound)
}

func testDelete(t *testing.T, f Factory) {
	h := newHarness(t, f)
	h.mkbucket("del")
	del := func(key string) error {
		_, err := h.be.DeleteObject(bg, "del", key, storage.DeleteOptions{})
		return err
	}
	gone := func(key string) {
		t.Helper()
		_, err := h.be.StatObject(bg, "del", key, storage.GetOptions{})
		wantErr(t, "Stat after delete: "+key, err, storage.ErrObjectNotFound)
	}

	t.Run("existing then missing is idempotent", func(t *testing.T) {
		h.put("del", "k", "v")
		if err := del("k"); err != nil {
			t.Fatal(err)
		}
		gone("k")
		if err := del("k"); err != nil {
			t.Errorf("second delete: %v", err)
		}
		if err := del("never/existed"); err != nil {
			t.Errorf("delete of missing nested key: %v", err)
		}
	})
	t.Run("missing bucket", func(t *testing.T) {
		_, err := h.be.DeleteObject(bg, "nobucket", "k", storage.DeleteOptions{})
		wantErr(t, "DeleteObject", err, storage.ErrBucketNotFound)
	})
	t.Run("invalid key", func(t *testing.T) {
		wantErr(t, "DeleteObject", del("a/../b"), storage.ErrInvalidObjectName)
	})
	t.Run("parent key survives child delete and vice versa", func(t *testing.T) {
		h.put("del", "a", "A")
		h.put("del", "a/b", "AB")
		h.put("del", "a/b/c", "ABC")
		if err := del("a"); err != nil {
			t.Fatal(err)
		}
		gone("a")
		if got, _ := h.get("del", "a/b"); got != "AB" {
			t.Errorf("a/b = %q", got)
		}
		if got, _ := h.get("del", "a/b/c"); got != "ABC" {
			t.Errorf("a/b/c = %q", got)
		}
		if err := del("a/b/c"); err != nil {
			t.Fatal(err)
		}
		if got, _ := h.get("del", "a/b"); got != "AB" {
			t.Errorf("a/b after child delete = %q", got)
		}
		if err := del("a/b"); err != nil {
			t.Fatal(err)
		}
		res, err := h.be.ListObjects(bg, "del", storage.ListOptions{})
		if err != nil || len(res.Objects)+len(res.Prefixes) != 0 {
			t.Errorf("listing after deleting everything = %+v, %v", res, err)
		}
	})
	t.Run("folder placeholder is distinct from same-named key", func(t *testing.T) {
		h.put("del", "p", "file")
		h.put("del", "p/", "")
		if err := del("p/"); err != nil {
			t.Fatal(err)
		}
		gone("p/")
		if got, _ := h.get("del", "p"); got != "file" {
			t.Errorf("p = %q after deleting p/", got)
		}
		if err := del("p"); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("pruning leaves an empty bucket deletable", func(t *testing.T) {
		h.put("del", "deep/er/and/deeper", "x")
		if err := del("deep/er/and/deeper"); err != nil {
			t.Fatal(err)
		}
		if err := h.be.DeleteBucket(bg, "del", storage.DeleteBucketOptions{}); err != nil {
			t.Errorf("DeleteBucket without force: %v", err)
		}
	})
}

func testSnapshotReads(t *testing.T, f Factory) {
	h := newHarness(t, f)
	h.mkbucket("snap")
	old := strings.Repeat("old-", 1024)
	h.put("snap", "k", old)
	rc, _, err := h.be.GetObject(bg, "snap", "k", storage.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	head := make([]byte, 7)
	if _, err := io.ReadFull(rc, head); err != nil {
		t.Fatal(err)
	}

	h.put("snap", "k", "replacement")
	if _, err := h.be.DeleteObject(bg, "snap", "k", storage.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	rest, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("reading after overwrite+delete: %v", err)
	}
	if got := string(head) + string(rest); got != old {
		t.Errorf("snapshot reader returned %d bytes that differ from the original %d", len(got), len(old))
	}

	// The same for a multipart object, whose parts are opened lazily while
	// streaming: a replacement must not pull them out from under a reader.
	t.Run("multipart object", func(t *testing.T) {
		big := string(partBlock)
		id := h.newUpload("snap", "mp", storage.PutOptions{})
		p1 := h.part("snap", "mp", id, 1, big)
		p2 := h.part("snap", "mp", id, 2, big[:MinPartSize-1]+"!") // every part but the last must be >= 5 MiB
		p3 := h.part("snap", "mp", id, 3, "the end")
		if _, err := h.be.CompleteMultipartUpload(bg, "snap", "mp", id, completeParts(p1, p2, p3), storage.PutOptions{}); err != nil {
			t.Fatal(err)
		}
		want := big + big[:MinPartSize-1] + "!" + "the end"
		rc, _, err := h.be.GetObject(bg, "snap", "mp", storage.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		defer rc.Close()
		first := make([]byte, 100)
		if _, err := io.ReadFull(rc, first); err != nil {
			t.Fatal(err)
		}
		// Replace, then delete, while the reader is mid-stream in part 1
		// and has not yet opened parts 2 and 3.
		h.put("snap", "mp", "a completely different object")
		if _, err := h.be.DeleteObject(bg, "snap", "mp", storage.DeleteOptions{}); err != nil {
			t.Fatal(err)
		}
		rest, err := io.ReadAll(rc)
		if err != nil {
			t.Fatalf("reading a multipart snapshot after overwrite+delete: %v", err)
		}
		if got := string(first) + string(rest); got != want {
			t.Errorf("multipart snapshot differs: %d bytes, want %d", len(got), len(want))
		}
	})
}

var listKeys = []string{"a", "a-b", "a/b", "a/c/d", "b", "dir/", "z/1", "z/2", "z/sub/3"}

func testList(t *testing.T, f Factory) {
	h := newHarness(t, f)
	h.mkbucket("lst")
	// Insert out of order to prove the result is sorted, not creation order.
	order := []int{5, 0, 8, 2, 7, 1, 4, 3, 6}
	for _, i := range order {
		h.put("lst", listKeys[i], "body-"+listKeys[i])
	}
	tests := []struct {
		name     string
		opts     storage.ListOptions
		objects  string
		prefixes string
		trunc    bool
		next     string
	}{
		{"everything, byte order", storage.ListOptions{}, "a,a-b,a/b,a/c/d,b,dir/,z/1,z/2,z/sub/3", "", false, ""},
		{"delimiter slash", storage.ListOptions{Delimiter: "/"}, "a,a-b,b", "a/,dir/,z/", false, ""},
		{"prefix a/ delimiter", storage.ListOptions{Prefix: "a/", Delimiter: "/"}, "a/b", "a/c/", false, ""},
		{"prefix z/ delimiter", storage.ListOptions{Prefix: "z/", Delimiter: "/"}, "z/1,z/2", "z/sub/", false, ""},
		{"prefix a, no delimiter", storage.ListOptions{Prefix: "a"}, "a,a-b,a/b,a/c/d", "", false, ""},
		{"prefix a/, no delimiter", storage.ListOptions{Prefix: "a/"}, "a/b,a/c/d", "", false, ""},
		{"partial segment prefix", storage.ListOptions{Prefix: "z/s"}, "z/sub/3", "", false, ""},
		{"prefix matches placeholder", storage.ListOptions{Prefix: "di"}, "dir/", "", false, ""},
		{"prefix is whole placeholder", storage.ListOptions{Prefix: "dir/"}, "dir/", "", false, ""},
		{"prefix with no match", storage.ListOptions{Prefix: "nope"}, "", "", false, ""},
		{"marker", storage.ListOptions{Marker: "a-b"}, "a/b,a/c/d,b,dir/,z/1,z/2,z/sub/3", "", false, ""},
		{"marker between keys", storage.ListOptions{Marker: "a0"}, "b,dir/,z/1,z/2,z/sub/3", "", false, ""},
		{"start-after", storage.ListOptions{StartAfter: "b"}, "dir/,z/1,z/2,z/sub/3", "", false, ""},
		{"greater of marker and start-after", storage.ListOptions{Marker: "a", StartAfter: "b"}, "dir/,z/1,z/2,z/sub/3", "", false, ""},
		{"marker equal to a common prefix skips it", storage.ListOptions{Delimiter: "/", Marker: "a/"}, "b", "dir/,z/", false, ""},
		{"max keys truncates", storage.ListOptions{MaxKeys: 3}, "a,a-b,a/b", "", true, "a/b"},
		{"max keys counts prefixes", storage.ListOptions{Delimiter: "/", MaxKeys: 4}, "a,a-b,b", "a/", true, "b"},
		{"max keys exactly the total", storage.ListOptions{Prefix: "z/", MaxKeys: 3}, "z/1,z/2,z/sub/3", "", false, ""},
		{"max keys above cap is clamped", storage.ListOptions{MaxKeys: 5000}, "a,a-b,a/b,a/c/d,b,dir/,z/1,z/2,z/sub/3", "", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := h.be.ListObjects(bg, "lst", tt.opts)
			if err != nil {
				t.Fatal(err)
			}
			var objs []string
			for _, o := range res.Objects {
				objs = append(objs, o.Name)
				if o.Bucket != "lst" || o.Size != int64(len("body-"+o.Name)) || o.ETag != md5hex("body-"+o.Name) {
					t.Errorf("object info for %q is wrong: %+v", o.Name, o)
				}
			}
			if got := strings.Join(objs, ","); got != tt.objects {
				t.Errorf("objects = %q, want %q", got, tt.objects)
			}
			if got := strings.Join(res.Prefixes, ","); got != tt.prefixes {
				t.Errorf("prefixes = %q, want %q", got, tt.prefixes)
			}
			if res.IsTruncated != tt.trunc || res.NextMarker != tt.next {
				t.Errorf("truncated=%v next=%q, want %v %q", res.IsTruncated, res.NextMarker, tt.trunc, tt.next)
			}
		})
	}

	t.Run("missing bucket", func(t *testing.T) {
		_, err := h.be.ListObjects(bg, "nobucket", storage.ListOptions{})
		wantErr(t, "ListObjects", err, storage.ErrBucketNotFound)
	})
	t.Run("empty bucket", func(t *testing.T) {
		h.mkbucket("empty")
		res, err := h.be.ListObjects(bg, "empty", storage.ListOptions{})
		if err != nil || len(res.Objects) != 0 || len(res.Prefixes) != 0 || res.IsTruncated {
			t.Errorf("empty list = %+v, %v", res, err)
		}
	})
}

func testListPagination(t *testing.T, f Factory) {
	h := newHarness(t, f)
	h.mkbucket("pgn")
	var keys []string
	for i := 0; i < 23; i++ {
		keys = append(keys, fmt.Sprintf("k%02d", i), fmt.Sprintf("d%d/f%02d", i%4, i))
	}
	for _, k := range keys {
		h.put("pgn", k, k)
	}
	collect := func(opts storage.ListOptions) []string {
		var names []string
		for guard := 0; ; guard++ {
			if guard > 200 {
				t.Fatal("pagination did not terminate")
			}
			res, err := h.be.ListObjects(bg, "pgn", opts)
			if err != nil {
				t.Fatal(err)
			}
			if n := len(res.Objects) + len(res.Prefixes); opts.MaxKeys > 0 && n > opts.MaxKeys {
				t.Fatalf("page has %d entries, MaxKeys %d", n, opts.MaxKeys)
			}
			for _, o := range res.Objects {
				names = append(names, o.Name)
			}
			names = append(names, res.Prefixes...)
			if !res.IsTruncated {
				break
			}
			if res.NextMarker == "" || res.NextMarker <= opts.Marker {
				t.Fatalf("NextMarker %q does not advance past %q", res.NextMarker, opts.Marker)
			}
			opts.Marker = res.NextMarker
		}
		sort.Strings(names)
		return names
	}
	for _, delim := range []string{"", "/"} {
		want := collect(storage.ListOptions{Delimiter: delim})
		for _, size := range []int{1, 2, 3, 7, 100} {
			t.Run(fmt.Sprintf("delim=%q size=%d", delim, size), func(t *testing.T) {
				got := collect(storage.ListOptions{Delimiter: delim, MaxKeys: size})
				if strings.Join(got, ",") != strings.Join(want, ",") {
					t.Errorf("paged listing differs from unpaged:\n got %v\nwant %v", got, want)
				}
				for i := 1; i < len(got); i++ {
					if got[i] == got[i-1] {
						t.Errorf("duplicate entry %q across pages", got[i])
					}
				}
			})
		}
	}
	if got := collect(storage.ListOptions{}); len(got) != len(keys) {
		t.Errorf("unpaged listing has %d keys, want %d", len(got), len(keys))
	}
}

func testLocking(t *testing.T, f Factory) {
	h := newHarness(t, f)
	h.mkbucket("lck")

	idx := func(log []string, entry string) int {
		for i, e := range log {
			if e == entry {
				return i
			}
		}
		return -1
	}
	t.Run("put locks bucket shared then key exclusive", func(t *testing.T) {
		h.rec.reset()
		h.put("lck", "k", "v")
		held, log := h.rec.snapshot()
		if held != 0 {
			t.Errorf("%d locks held after PutObject", held)
		}
		b, k := idx(log, "RLock lck/"), idx(log, "Lock lck/k")
		if b < 0 || k < 0 || b > k {
			t.Errorf("lock log %v: want bucket RLock before key Lock", log)
		}
	})
	t.Run("get releases its lock before streaming", func(t *testing.T) {
		rc, _, err := h.be.GetObject(bg, "lck", "k", storage.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		defer rc.Close()
		if held, log := h.rec.snapshot(); held != 0 {
			t.Errorf("%d locks still held while the reader is open: %v", held, log)
		}
		if _, log := h.rec.snapshot(); idx(log, "RLock lck/k") < 0 {
			t.Errorf("GetObject took no shared key lock: %v", log)
		}
	})
	t.Run("delete takes the key exclusively", func(t *testing.T) {
		h.rec.reset()
		if _, err := h.be.DeleteObject(bg, "lck", "k", storage.DeleteOptions{}); err != nil {
			t.Fatal(err)
		}
		held, log := h.rec.snapshot()
		if held != 0 || idx(log, "Lock lck/k") < 0 {
			t.Errorf("held=%d log=%v", held, log)
		}
	})
	t.Run("bucket create and delete lock the bucket", func(t *testing.T) {
		h.rec.reset()
		h.mkbucket("lck2")
		if err := h.be.DeleteBucket(bg, "lck2", storage.DeleteBucketOptions{}); err != nil {
			t.Fatal(err)
		}
		held, log := h.rec.snapshot()
		n := 0
		for _, e := range log {
			if e == "Lock lck2/" {
				n++
			}
		}
		// One per call per underlying set: a single-set backend takes
		// exactly 2, a backend over several sets a multiple of that.
		if held != 0 || n < 2 || n%2 != 0 {
			t.Errorf("held=%d, bucket Lock count=%d (want a positive even number): %v", held, n, log)
		}
	})
	t.Run("lock failure surfaces and leaves no lock behind", func(t *testing.T) {
		boom := errors.New("lock refused")
		h2 := &harness{t: t, rec: &recorder{Locker: failingLocker{boom}}}
		h2.be = f(t, h2.rec)
		defer h2.be.Close()
		err := h2.be.MakeBucket(bg, "failing", storage.MakeBucketOptions{})
		wantErr(t, "MakeBucket", err, boom)
		if held, _ := h2.rec.snapshot(); held != 0 {
			t.Errorf("%d locks held after failed acquire", held)
		}
	})
}

type failingLocker struct{ err error }

func (l failingLocker) Lock(context.Context, string, string) (func(), error)  { return nil, l.err }
func (l failingLocker) RLock(context.Context, string, string) (func(), error) { return nil, l.err }

func testConcurrency(t *testing.T, f Factory) {
	h := newHarness(t, f)
	h.mkbucket("ccn")
	const n = 24
	body := func(i int) string { return strings.Repeat(string(rune('A'+i)), 64<<10) }

	t.Run("same key, last writer wins whole", func(t *testing.T) {
		var wg sync.WaitGroup
		errs := make(chan error, n)
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				b := body(i)
				_, err := h.be.PutObject(bg, "ccn", "hot", strings.NewReader(b), int64(len(b)), storage.PutOptions{})
				errs <- err
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Errorf("concurrent put: %v", err)
			}
		}
		got, info := h.get("ccn", "hot")
		matched := false
		for i := 0; i < n; i++ {
			if got == body(i) {
				matched = true
			}
		}
		if !matched {
			t.Error("final object is not exactly one writer's body (torn write)")
		}
		if info.ETag != md5hex(got) || info.Size != int64(len(got)) {
			t.Errorf("metadata does not match content: %+v", info)
		}
	})

	t.Run("distinct keys all land", func(t *testing.T) {
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				h.put("ccn", fmt.Sprintf("many/%02d", i), body(i)[:100])
			}()
		}
		wg.Wait()
		res, err := h.be.ListObjects(bg, "ccn", storage.ListOptions{Prefix: "many/"})
		if err != nil || len(res.Objects) != n {
			t.Errorf("listed %d objects, want %d (%v)", len(res.Objects), n, err)
		}
	})

	t.Run("put, get and delete interleaved never expose torn data", func(t *testing.T) {
		stop := make(chan struct{})
		var wg sync.WaitGroup
		var mu sync.Mutex
		var failures []string
		fail := func(format string, args ...any) {
			mu.Lock()
			failures = append(failures, fmt.Sprintf(format, args...))
			mu.Unlock()
		}
		for w := 0; w < 4; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; ; i++ {
					select {
					case <-stop:
						return
					default:
					}
					b := body((w*7 + i) % n)
					if _, err := h.be.PutObject(bg, "ccn", "mix", strings.NewReader(b), int64(len(b)), storage.PutOptions{}); err != nil {
						fail("put: %v", err)
					}
					if i%3 == 0 {
						if _, err := h.be.DeleteObject(bg, "ccn", "mix", storage.DeleteOptions{}); err != nil {
							fail("delete: %v", err)
						}
					}
				}
			}()
		}
		deadline := time.Now().Add(400 * time.Millisecond)
		for time.Now().Before(deadline) {
			rc, info, err := h.be.GetObject(bg, "ccn", "mix", storage.GetOptions{})
			if errors.Is(err, storage.ErrObjectNotFound) {
				continue
			}
			if err != nil {
				fail("get: %v", err)
				break
			}
			b, rerr := io.ReadAll(rc)
			rc.Close()
			if rerr != nil || md5hex(string(b)) != info.ETag || int64(len(b)) != info.Size {
				fail("torn read: err=%v len=%d size=%d", rerr, len(b), info.Size)
				break
			}
		}
		close(stop)
		wg.Wait()
		for _, m := range failures {
			t.Error(m)
		}
	})
}

type cancelAfter struct {
	n      int
	cancel context.CancelFunc
	read   int
}

func (c *cancelAfter) Read(p []byte) (int, error) {
	if c.read >= c.n {
		c.cancel()
		return 0, nil // ctx is now done; a well-behaved backend notices
	}
	k := min(len(p), c.n-c.read)
	for i := 0; i < k; i++ {
		p[i] = 'x'
	}
	c.read += k
	return k, nil
}

func testCancellation(t *testing.T, f Factory) {
	h := newHarness(t, f)
	h.mkbucket("cxl")
	h.put("cxl", "keep", "original")

	t.Run("cancelled before the call", func(t *testing.T) {
		ctx, cancel := context.WithCancel(bg)
		cancel()
		_, err := h.be.PutObject(ctx, "cxl", "new", strings.NewReader("data"), 4, storage.PutOptions{})
		if !errors.Is(err, context.Canceled) {
			t.Errorf("error = %v, want context.Canceled", err)
		}
		_, err = h.be.StatObject(bg, "cxl", "new", storage.GetOptions{})
		wantErr(t, "object after cancelled put", err, storage.ErrObjectNotFound)
	})
	t.Run("cancelled mid-upload keeps the old object", func(t *testing.T) {
		ctx, cancel := context.WithCancel(bg)
		defer cancel()
		src := &cancelAfter{n: 1000, cancel: cancel}
		_, err := h.be.PutObject(ctx, "cxl", "keep", src, 1<<20, storage.PutOptions{})
		if err == nil {
			t.Fatal("PutObject succeeded despite cancellation")
		}
		if got, _ := h.get("cxl", "keep"); got != "original" {
			t.Errorf("object changed to %d bytes after cancelled overwrite", len(got))
		}
	})
	t.Run("deadline already passed on list", func(t *testing.T) {
		ctx, cancel := context.WithDeadline(bg, time.Now().Add(-time.Second))
		defer cancel()
		_, err := h.be.ListObjects(ctx, "cxl", storage.ListOptions{})
		if err == nil {
			t.Error("ListObjects ignored an expired context")
		}
	})
}

// MinPartSize is the smallest non-final part the suite assumes: S3's 5 MiB.
const MinPartSize = 5 << 20

var partBlock = func() []byte {
	b := make([]byte, MinPartSize)
	rand.New(rand.NewSource(42)).Read(b)
	return b
}()

// mpEtag is the S3 multipart ETag: MD5 of the concatenated binary part MD5s,
// then "-<count>".
func mpEtag(parts ...string) string {
	h := md5.New()
	for _, p := range parts {
		sum := md5.Sum([]byte(p))
		h.Write(sum[:])
	}
	return fmt.Sprintf("%x-%d", h.Sum(nil), len(parts))
}

func (h *harness) newUpload(bucket, key string, opts storage.PutOptions) string {
	h.t.Helper()
	id, err := h.be.NewMultipartUpload(bg, bucket, key, opts)
	if err != nil {
		h.t.Fatalf("NewMultipartUpload(%s/%s): %v", bucket, key, err)
	}
	if id == "" {
		h.t.Fatal("empty upload id")
	}
	return id
}

func (h *harness) part(bucket, key, id string, n int, body string) storage.PartInfo {
	h.t.Helper()
	p, err := h.be.PutObjectPart(bg, bucket, key, id, n, strings.NewReader(body), int64(len(body)), storage.PartOptions{})
	if err != nil {
		h.t.Fatalf("PutObjectPart(%d): %v", n, err)
	}
	return p
}

func completeParts(parts ...storage.PartInfo) []storage.CompletePart {
	out := make([]storage.CompletePart, len(parts))
	for i, p := range parts {
		out[i] = storage.CompletePart{Number: p.Number, ETag: p.ETag}
	}
	return out
}

func testMultipart(t *testing.T, f Factory) {
	h := newHarness(t, f)
	h.mkbucket("mpu")
	big := string(partBlock)
	p1body, p2body, p3body := big, big[:MinPartSize-1000]+strings.Repeat("Z", 1000), "tail bytes"

	t.Run("full lifecycle", func(t *testing.T) {
		id := h.newUpload("mpu", "dir/assembled.bin", storage.PutOptions{
			ContentType: "application/x-test", UserDefined: map[string]string{"x-amz-meta-origin": "mpu"}})

		// A visible, empty upload.
		res, err := h.be.ListObjectParts(bg, "mpu", "dir/assembled.bin", id, storage.ListPartsOptions{})
		if err != nil || len(res.Parts) != 0 {
			t.Fatalf("fresh upload parts = %+v, %v", res, err)
		}
		if _, err := h.be.StatObject(bg, "mpu", "dir/assembled.bin", storage.GetOptions{}); !errors.Is(err, storage.ErrObjectNotFound) {
			t.Errorf("object visible before completion: %v", err)
		}

		// Upload out of order.
		pi3 := h.part("mpu", "dir/assembled.bin", id, 3, p3body)
		pi1 := h.part("mpu", "dir/assembled.bin", id, 1, p1body)
		pi2 := h.part("mpu", "dir/assembled.bin", id, 2, p2body)
		for _, c := range []struct {
			p    storage.PartInfo
			body string
		}{{pi1, p1body}, {pi2, p2body}, {pi3, p3body}} {
			if c.p.ETag != md5hex(c.body) || c.p.Size != int64(len(c.body)) || c.p.Number == 0 || c.p.ModTime.IsZero() {
				t.Errorf("part info %+v", c.p)
			}
		}
		if _, err := h.be.StatObject(bg, "mpu", "dir/assembled.bin", storage.GetOptions{}); err == nil {
			t.Error("object visible with parts uploaded but not completed")
		}

		list, err := h.be.ListObjectParts(bg, "mpu", "dir/assembled.bin", id, storage.ListPartsOptions{})
		if err != nil || len(list.Parts) != 3 || list.IsTruncated {
			t.Fatalf("list = %+v, %v", list, err)
		}
		for i, want := range []storage.PartInfo{pi1, pi2, pi3} {
			if g := list.Parts[i]; g.Number != want.Number || g.ETag != want.ETag || g.Size != want.Size {
				t.Errorf("listed part %d = %+v, want %+v", i, g, want)
			}
		}

		info, err := h.be.CompleteMultipartUpload(bg, "mpu", "dir/assembled.bin", id,
			completeParts(pi1, pi2, pi3), storage.PutOptions{})
		if err != nil {
			t.Fatalf("Complete: %v", err)
		}
		wantSize := int64(len(p1body) + len(p2body) + len(p3body))
		wantETag := mpEtag(p1body, p2body, p3body)
		if info.Size != wantSize || info.ETag != wantETag {
			t.Errorf("complete info size=%d etag=%s, want %d %s", info.Size, info.ETag, wantSize, wantETag)
		}
		got, ginfo := h.get("mpu", "dir/assembled.bin")
		if got != p1body+p2body+p3body {
			t.Errorf("assembled object differs (%d bytes, want %d)", len(got), wantSize)
		}
		if ginfo.ETag != wantETag || ginfo.ContentType != "application/x-test" ||
			ginfo.UserDefined["x-amz-meta-origin"] != "mpu" || len(ginfo.Parts) != 3 {
			t.Errorf("object info = %+v", ginfo)
		}
		// The upload is consumed.
		_, err = h.be.ListObjectParts(bg, "mpu", "dir/assembled.bin", id, storage.ListPartsOptions{})
		wantErr(t, "ListObjectParts after completion", err, storage.ErrNoSuchUpload)
		_, err = h.be.CompleteMultipartUpload(bg, "mpu", "dir/assembled.bin", id, completeParts(pi1, pi2, pi3), storage.PutOptions{})
		wantErr(t, "second Complete", err, storage.ErrNoSuchUpload)
		ups, err := h.be.ListMultipartUploads(bg, "mpu", storage.ListUploadsOptions{})
		if err != nil || len(ups.Uploads) != 0 {
			t.Errorf("uploads after completion = %+v, %v", ups, err)
		}
	})

	t.Run("ranges across part boundaries", func(t *testing.T) {
		id := h.newUpload("mpu", "ranged", storage.PutOptions{})
		a := h.part("mpu", "ranged", id, 1, p1body)
		b := h.part("mpu", "ranged", id, 2, p3body)
		if _, err := h.be.CompleteMultipartUpload(bg, "mpu", "ranged", id, completeParts(a, b), storage.PutOptions{}); err != nil {
			t.Fatal(err)
		}
		whole := p1body + p3body
		for _, rg := range []storage.ByteRange{
			{Start: 0, Length: 10},
			{Start: int64(len(p1body)) - 5, Length: 15}, // straddles the boundary
			{Start: int64(len(p1body)), Length: int64(len(p3body))},
			{Start: int64(len(whole)) - 1, Length: 1},
			{Start: 0, Length: int64(len(whole))},
		} {
			rc, _, err := h.be.GetObject(bg, "mpu", "ranged", storage.GetOptions{Range: &rg})
			if err != nil {
				t.Fatalf("range %+v: %v", rg, err)
			}
			got, _ := io.ReadAll(rc)
			rc.Close()
			if string(got) != whole[rg.Start:rg.Start+rg.Length] {
				t.Errorf("range %+v returned wrong bytes", rg)
			}
		}
	})

	t.Run("non-contiguous part numbers", func(t *testing.T) {
		id := h.newUpload("mpu", "sparse", storage.PutOptions{})
		a := h.part("mpu", "sparse", id, 7, p1body)
		b := h.part("mpu", "sparse", id, 10000, "last")
		info, err := h.be.CompleteMultipartUpload(bg, "mpu", "sparse", id, completeParts(a, b), storage.PutOptions{})
		if err != nil || info.ETag != mpEtag(p1body, "last") {
			t.Fatalf("%+v, %v", info, err)
		}
		if got, _ := h.get("mpu", "sparse"); got != p1body+"last" {
			t.Error("content differs")
		}
	})

	t.Run("single small part", func(t *testing.T) {
		id := h.newUpload("mpu", "tiny", storage.PutOptions{})
		a := h.part("mpu", "tiny", id, 1, "x")
		info, err := h.be.CompleteMultipartUpload(bg, "mpu", "tiny", id, completeParts(a), storage.PutOptions{})
		if err != nil || info.ETag != mpEtag("x") || info.Size != 1 {
			t.Fatalf("%+v, %v", info, err)
		}
	})

	t.Run("a subset of the uploaded parts", func(t *testing.T) {
		id := h.newUpload("mpu", "subset", storage.PutOptions{})
		a := h.part("mpu", "subset", id, 1, p1body)
		h.part("mpu", "subset", id, 2, "not wanted")
		c := h.part("mpu", "subset", id, 3, "wanted")
		info, err := h.be.CompleteMultipartUpload(bg, "mpu", "subset", id, completeParts(a, c), storage.PutOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := h.get("mpu", "subset"); got != p1body+"wanted" || info.ETag != mpEtag(p1body, "wanted") {
			t.Errorf("assembled %d bytes, etag %s", len(got), info.ETag)
		}
	})

	t.Run("re-uploading a part replaces it", func(t *testing.T) {
		id := h.newUpload("mpu", "replace", storage.PutOptions{})
		first := h.part("mpu", "replace", id, 1, "first attempt")
		second := h.part("mpu", "replace", id, 1, "second attempt, longer")
		if first.ETag == second.ETag {
			t.Fatal("ETags equal for different bytes")
		}
		list, _ := h.be.ListObjectParts(bg, "mpu", "replace", id, storage.ListPartsOptions{})
		if len(list.Parts) != 1 || list.Parts[0].ETag != second.ETag || list.Parts[0].Size != int64(len("second attempt, longer")) {
			t.Fatalf("listing = %+v", list.Parts)
		}
		_, err := h.be.CompleteMultipartUpload(bg, "mpu", "replace", id, completeParts(first), storage.PutOptions{})
		wantErr(t, "Complete with the replaced ETag", err, storage.ErrInvalidPart)
		if _, err := h.be.CompleteMultipartUpload(bg, "mpu", "replace", id, completeParts(second), storage.PutOptions{}); err != nil {
			t.Fatal(err)
		}
		if got, _ := h.get("mpu", "replace"); got != "second attempt, longer" {
			t.Errorf("object = %q", got)
		}
	})

	t.Run("completing over an existing object replaces it", func(t *testing.T) {
		h.put("mpu", "over", "old content")
		id := h.newUpload("mpu", "over", storage.PutOptions{})
		a := h.part("mpu", "over", id, 1, "new content")
		if _, err := h.be.CompleteMultipartUpload(bg, "mpu", "over", id, completeParts(a), storage.PutOptions{}); err != nil {
			t.Fatal(err)
		}
		if got, info := h.get("mpu", "over"); got != "new content" || info.ETag != mpEtag("new content") {
			t.Errorf("%q %s", got, info.ETag)
		}
	})

	t.Run("failed precondition leaves the upload usable", func(t *testing.T) {
		h.put("mpu", "cond", "existing")
		id := h.newUpload("mpu", "cond", storage.PutOptions{})
		a := h.part("mpu", "cond", id, 1, "contender")
		_, err := h.be.CompleteMultipartUpload(bg, "mpu", "cond", id, completeParts(a), storage.PutOptions{IfNoneMatch: "*"})
		wantErr(t, "conditional Complete", err, storage.ErrPreconditionFailed)
		if got, _ := h.get("mpu", "cond"); got != "existing" {
			t.Errorf("object = %q", got)
		}
		if _, err := h.be.CompleteMultipartUpload(bg, "mpu", "cond", id, completeParts(a), storage.PutOptions{}); err != nil {
			t.Errorf("retry after a failed precondition: %v", err)
		}
	})

	t.Run("abort", func(t *testing.T) {
		id := h.newUpload("mpu", "aborted", storage.PutOptions{})
		a := h.part("mpu", "aborted", id, 1, "doomed")
		if err := h.be.AbortMultipartUpload(bg, "mpu", "aborted", id); err != nil {
			t.Fatal(err)
		}
		_, err := h.be.PutObjectPart(bg, "mpu", "aborted", id, 2, strings.NewReader("x"), 1, storage.PartOptions{})
		wantErr(t, "part after abort", err, storage.ErrNoSuchUpload)
		_, err = h.be.CompleteMultipartUpload(bg, "mpu", "aborted", id, completeParts(a), storage.PutOptions{})
		wantErr(t, "complete after abort", err, storage.ErrNoSuchUpload)
		wantErr(t, "second abort", h.be.AbortMultipartUpload(bg, "mpu", "aborted", id), storage.ErrNoSuchUpload)
		if _, err := h.be.StatObject(bg, "mpu", "aborted", storage.GetOptions{}); err == nil {
			t.Error("aborted upload produced an object")
		}
	})

	t.Run("deleting a multipart object removes it", func(t *testing.T) {
		id := h.newUpload("mpu", "todelete", storage.PutOptions{})
		a := h.part("mpu", "todelete", id, 1, p1body)
		b := h.part("mpu", "todelete", id, 2, "end")
		if _, err := h.be.CompleteMultipartUpload(bg, "mpu", "todelete", id, completeParts(a, b), storage.PutOptions{}); err != nil {
			t.Fatal(err)
		}
		if _, err := h.be.DeleteObject(bg, "mpu", "todelete", storage.DeleteOptions{}); err != nil {
			t.Fatal(err)
		}
		_, err := h.be.StatObject(bg, "mpu", "todelete", storage.GetOptions{})
		wantErr(t, "Stat after delete", err, storage.ErrObjectNotFound)
	})

	t.Run("incomplete uploads keep a bucket from being deleted", func(t *testing.T) {
		h.mkbucket("mpudel")
		id := h.newUpload("mpudel", "k", storage.PutOptions{})
		wantErr(t, "DeleteBucket", h.be.DeleteBucket(bg, "mpudel", storage.DeleteBucketOptions{}), storage.ErrBucketNotEmpty)
		if err := h.be.AbortMultipartUpload(bg, "mpudel", "k", id); err != nil {
			t.Fatal(err)
		}
		if err := h.be.DeleteBucket(bg, "mpudel", storage.DeleteBucketOptions{}); err != nil {
			t.Errorf("DeleteBucket after abort: %v", err)
		}
		// Forced deletion discards uploads, and a recreated bucket starts clean.
		h.mkbucket("mpudel")
		h.newUpload("mpudel", "k", storage.PutOptions{})
		if err := h.be.DeleteBucket(bg, "mpudel", storage.DeleteBucketOptions{Force: true}); err != nil {
			t.Fatal(err)
		}
		h.mkbucket("mpudel")
		ups, err := h.be.ListMultipartUploads(bg, "mpudel", storage.ListUploadsOptions{})
		if err != nil || len(ups.Uploads) != 0 {
			t.Errorf("recreated bucket has uploads: %+v, %v", ups, err)
		}
	})
}

func testMultipartErrors(t *testing.T, f Factory) {
	h := newHarness(t, f)
	h.mkbucket("mpe")
	h.mkbucket("mpe2")
	small := "tiny"
	id := h.newUpload("mpe", "k", storage.PutOptions{})
	p1 := h.part("mpe", "k", id, 1, small)
	p2 := h.part("mpe", "k", id, 2, small)
	const ghost = "11111111-1111-4111-8111-111111111111"

	t.Run("complete", func(t *testing.T) {
		tests := []struct {
			name  string
			parts []storage.CompletePart
			want  error
		}{
			{"non-final part below the minimum", completeParts(p1, p2), storage.ErrEntityTooSmall},
			{"no parts", nil, storage.ErrInvalidPart},
			{"part never uploaded", []storage.CompletePart{{Number: 9, ETag: p1.ETag}}, storage.ErrInvalidPart},
			{"wrong etag", []storage.CompletePart{{Number: 1, ETag: md5hex("other")}}, storage.ErrInvalidPart},
			{"etag with quotes is accepted as a match", []storage.CompletePart{{Number: 1, ETag: `"` + p1.ETag + `"`}}, nil},
			{"descending", []storage.CompletePart{{Number: 2, ETag: p2.ETag}, {Number: 1, ETag: p1.ETag}}, storage.ErrInvalidPartOrder},
			{"duplicate", []storage.CompletePart{{Number: 1, ETag: p1.ETag}, {Number: 1, ETag: p1.ETag}}, storage.ErrInvalidPartOrder},
			{"part number zero", []storage.CompletePart{{Number: 0, ETag: p1.ETag}}, storage.ErrInvalidPart},
			{"part number too large", []storage.CompletePart{{Number: 10001, ETag: p1.ETag}}, storage.ErrInvalidPart},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				// Use a fresh upload each time: success consumes it.
				u := h.newUpload("mpe", "k", storage.PutOptions{})
				h.part("mpe", "k", u, 1, small)
				h.part("mpe", "k", u, 2, small)
				_, err := h.be.CompleteMultipartUpload(bg, "mpe", "k", u, tt.parts, storage.PutOptions{})
				if tt.want == nil {
					if err != nil {
						t.Errorf("unexpected error: %v", err)
					}
					return
				}
				wantErr(t, "CompleteMultipartUpload", err, tt.want)
				// A rejected completion leaves the upload and its parts intact.
				if l, err := h.be.ListObjectParts(bg, "mpe", "k", u, storage.ListPartsOptions{}); err != nil || len(l.Parts) != 2 {
					t.Errorf("upload damaged by a rejected completion: %+v, %v", l, err)
				}
			})
		}
	})

	t.Run("upload identity", func(t *testing.T) {
		tests := []struct {
			name            string
			bucket, key, id string
			want            error
		}{
			{"unknown id", "mpe", "k", ghost, storage.ErrNoSuchUpload},
			{"not an id at all", "mpe", "k", "not-an-upload-id", storage.ErrNoSuchUpload},
			{"path traversal id", "mpe", "k", "../../../etc", storage.ErrNoSuchUpload},
			{"empty id", "mpe", "k", "", storage.ErrNoSuchUpload},
			{"id used for a different key", "mpe", "other", id, storage.ErrNoSuchUpload},
			{"id used in a different bucket", "mpe2", "k", id, storage.ErrNoSuchUpload},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				_, err := h.be.PutObjectPart(bg, tt.bucket, tt.key, tt.id, 1, strings.NewReader("x"), 1, storage.PartOptions{})
				wantErr(t, "PutObjectPart", err, tt.want)
				_, err = h.be.ListObjectParts(bg, tt.bucket, tt.key, tt.id, storage.ListPartsOptions{})
				wantErr(t, "ListObjectParts", err, tt.want)
				_, err = h.be.CompleteMultipartUpload(bg, tt.bucket, tt.key, tt.id, completeParts(p1), storage.PutOptions{})
				wantErr(t, "CompleteMultipartUpload", err, tt.want)
				wantErr(t, "AbortMultipartUpload", h.be.AbortMultipartUpload(bg, tt.bucket, tt.key, tt.id), tt.want)
			})
		}
	})

	t.Run("part validation", func(t *testing.T) {
		put := func(n int, body string, size int64, o storage.PartOptions) error {
			_, err := h.be.PutObjectPart(bg, "mpe", "k", id, n, strings.NewReader(body), size, o)
			return err
		}
		tests := []struct {
			name string
			err  error
			want error
		}{
			{"part number 0", put(0, "x", 1, storage.PartOptions{}), storage.ErrInvalidPart},
			{"part number 10001", put(10001, "x", 1, storage.PartOptions{}), storage.ErrInvalidPart},
			{"negative part number", put(-1, "x", 1, storage.PartOptions{}), storage.ErrInvalidPart},
			{"short body", put(3, "abc", 10, storage.PartOptions{}), storage.ErrIncompleteBody},
			{"md5 mismatch", put(3, "abc", 3, storage.PartOptions{ContentMD5: md5hex("other")}), storage.ErrBadDigest},
			{"sha256 mismatch", put(3, "abc", 3, storage.PartOptions{ContentSHA256: sha256hex("other")}), storage.ErrSHA256Mismatch},
			{"too large", put(3, "", 6<<30, storage.PartOptions{}), storage.ErrEntityTooLarge},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) { wantErr(t, tt.name, tt.err, tt.want) })
		}
		l, _ := h.be.ListObjectParts(bg, "mpe", "k", id, storage.ListPartsOptions{})
		if len(l.Parts) != 2 {
			t.Errorf("a rejected part became visible: %+v", l.Parts)
		}
		if err := put(3, "good", 4, storage.PartOptions{ContentMD5: md5hex("good"), ContentSHA256: sha256hex("good")}); err != nil {
			t.Errorf("valid digests rejected: %v", err)
		}
	})

	t.Run("names and buckets", func(t *testing.T) {
		_, err := h.be.NewMultipartUpload(bg, "no-such-bucket", "k", storage.PutOptions{})
		wantErr(t, "missing bucket", err, storage.ErrBucketNotFound)
		_, err = h.be.NewMultipartUpload(bg, "mpe", "a//b", storage.PutOptions{})
		wantErr(t, "invalid key", err, storage.ErrInvalidObjectName)
		_, err = h.be.NewMultipartUpload(bg, "BAD", "k", storage.PutOptions{})
		wantErr(t, "invalid bucket", err, storage.ErrInvalidBucketName)
		_, err = h.be.ListMultipartUploads(bg, "no-such-bucket", storage.ListUploadsOptions{})
		wantErr(t, "list uploads, missing bucket", err, storage.ErrBucketNotFound)
	})

	t.Run("cancelled part upload commits nothing", func(t *testing.T) {
		ctx, cancel := context.WithCancel(bg)
		src := &cancelAfter{n: 100, cancel: cancel}
		_, err := h.be.PutObjectPart(ctx, "mpe", "k", id, 8, src, 1<<20, storage.PartOptions{})
		cancel()
		if err == nil {
			t.Fatal("PutObjectPart succeeded despite cancellation")
		}
		l, _ := h.be.ListObjectParts(bg, "mpe", "k", id, storage.ListPartsOptions{})
		for _, p := range l.Parts {
			if p.Number == 8 {
				t.Error("cancelled part is listed")
			}
		}
	})
}

func testMultipartListing(t *testing.T, f Factory) {
	h := newHarness(t, f)
	h.mkbucket("mpl")

	t.Run("parts pagination", func(t *testing.T) {
		id := h.newUpload("mpl", "paged", storage.PutOptions{})
		for _, n := range []int{5, 1, 9, 3, 7} {
			h.part("mpl", "paged", id, n, fmt.Sprintf("part-%d", n))
		}
		var seen []int
		marker := 0
		for guard := 0; ; guard++ {
			if guard > 10 {
				t.Fatal("did not terminate")
			}
			res, err := h.be.ListObjectParts(bg, "mpl", "paged", id, storage.ListPartsOptions{PartNumberMarker: marker, MaxParts: 2})
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Parts) > 2 {
				t.Fatalf("page of %d", len(res.Parts))
			}
			for _, p := range res.Parts {
				seen = append(seen, p.Number)
			}
			if !res.IsTruncated {
				if res.NextPartNumberMarker != 0 {
					t.Error("NextPartNumberMarker set on the last page")
				}
				break
			}
			if res.NextPartNumberMarker <= marker {
				t.Fatalf("marker did not advance: %d -> %d", marker, res.NextPartNumberMarker)
			}
			marker = res.NextPartNumberMarker
		}
		if fmt.Sprint(seen) != "[1 3 5 7 9]" {
			t.Errorf("parts = %v", seen)
		}
		res, _ := h.be.ListObjectParts(bg, "mpl", "paged", id, storage.ListPartsOptions{PartNumberMarker: 5})
		if len(res.Parts) != 2 || res.Parts[0].Number != 7 {
			t.Errorf("after marker 5: %+v", res.Parts)
		}
		if err := h.be.AbortMultipartUpload(bg, "mpl", "paged", id); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("uploads: order, filters, pagination", func(t *testing.T) {
		keys := []string{"b/two", "a/one", "b/one", "c", "a/one"} // a/one twice
		ids := make([]string, len(keys))
		for i, k := range keys {
			ids[i] = h.newUpload("mpl", k, storage.PutOptions{})
			time.Sleep(2 * time.Millisecond) // distinct initiation times
		}
		list := func(o storage.ListUploadsOptions) storage.ListUploadsResult {
			t.Helper()
			r, err := h.be.ListMultipartUploads(bg, "mpl", o)
			if err != nil {
				t.Fatal(err)
			}
			return r
		}
		names := func(r storage.ListUploadsResult) string {
			var out []string
			for _, u := range r.Uploads {
				out = append(out, u.Object)
			}
			return strings.Join(out, ",")
		}

		all := list(storage.ListUploadsOptions{})
		if got := names(all); got != "a/one,a/one,b/one,b/two,c" {
			t.Errorf("order = %s", got)
		}
		// Same key: ordered by initiation time.
		if all.Uploads[0].UploadID != ids[1] || all.Uploads[1].UploadID != ids[4] {
			t.Error("uploads of one key are not in initiation order")
		}
		for _, u := range all.Uploads {
			if u.UploadID == "" || u.Initiated.IsZero() {
				t.Errorf("incomplete entry %+v", u)
			}
		}
		if got := names(list(storage.ListUploadsOptions{Prefix: "b/"})); got != "b/one,b/two" {
			t.Errorf("prefix b/ = %s", got)
		}
		d := list(storage.ListUploadsOptions{Delimiter: "/"})
		if names(d) != "c" || strings.Join(d.Prefixes, ",") != "a/,b/" {
			t.Errorf("delimiter: uploads=%s prefixes=%v", names(d), d.Prefixes)
		}
		// Paginate one upload at a time with the returned markers.
		var got []string
		o := storage.ListUploadsOptions{MaxUploads: 1}
		for guard := 0; ; guard++ {
			if guard > 10 {
				t.Fatal("did not terminate")
			}
			r := list(o)
			for _, u := range r.Uploads {
				got = append(got, u.Object+"@"+u.UploadID)
			}
			if !r.IsTruncated {
				break
			}
			o.KeyMarker, o.UploadIDMarker = r.NextKeyMarker, r.NextUploadIDMarker
		}
		if len(got) != 5 {
			t.Errorf("paginated listing = %v", got)
		}
		seen := map[string]bool{}
		for _, g := range got {
			if seen[g] {
				t.Errorf("duplicate %s across pages", g)
			}
			seen[g] = true
		}
		// A key marker alone skips every upload of that key.
		if got := names(list(storage.ListUploadsOptions{KeyMarker: "a/one"})); got != "b/one,b/two,c" {
			t.Errorf("key-marker = %s", got)
		}
		for i, k := range keys {
			h.be.AbortMultipartUpload(bg, "mpl", k, ids[i])
		}
	})
}

func testMultipartConcurrency(t *testing.T, f Factory) {
	h := newHarness(t, f)
	h.mkbucket("mpc")
	const n = 20
	id := h.newUpload("mpc", "k", storage.PutOptions{})
	bodies := make([]string, n)
	infos := make([]storage.PartInfo, n)
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		bodies[i] = fmt.Sprintf("%02d:%s", i, strings.Repeat("x", 100+i))
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, err := h.be.PutObjectPart(bg, "mpc", "k", id, i+1, strings.NewReader(bodies[i]), int64(len(bodies[i])), storage.PartOptions{})
			infos[i] = p
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent part: %v", err)
		}
	}
	l, err := h.be.ListObjectParts(bg, "mpc", "k", id, storage.ListPartsOptions{})
	if err != nil || len(l.Parts) != n {
		t.Fatalf("%d parts listed, want %d (%v)", len(l.Parts), n, err)
	}
	// Re-upload the same part number concurrently: exactly one winner remains.
	var wg2 sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			body := fmt.Sprintf("contender-%d", i)
			h.be.PutObjectPart(bg, "mpc", "k", id, 1, strings.NewReader(body), int64(len(body)), storage.PartOptions{})
		}()
	}
	wg2.Wait()
	l, _ = h.be.ListObjectParts(bg, "mpc", "k", id, storage.ListPartsOptions{})
	p1 := l.Parts[0]
	won := false
	for i := 0; i < 8; i++ {
		if b := fmt.Sprintf("contender-%d", i); p1.ETag == md5hex(b) && p1.Size == int64(len(b)) {
			won = true
		}
	}
	if !won {
		t.Errorf("part 1 matches no contender: %+v", p1)
	}
	// All 20 parts are tiny, so completing them must be refused (every part
	// but the last needs the minimum size) and must leave the upload intact.
	complete := make([]storage.CompletePart, n)
	for i := 0; i < n; i++ {
		complete[i] = storage.CompletePart{Number: l.Parts[i].Number, ETag: l.Parts[i].ETag}
	}
	_, err = h.be.CompleteMultipartUpload(bg, "mpc", "k", id, complete, storage.PutOptions{})
	wantErr(t, "tiny non-final parts", err, storage.ErrEntityTooSmall)
	if l2, err := h.be.ListObjectParts(bg, "mpc", "k", id, storage.ListPartsOptions{}); err != nil || len(l2.Parts) != n {
		t.Errorf("upload damaged: %d parts, %v", len(l2.Parts), err)
	}

	// Concurrent Complete and Abort race: exactly one outcome, never both.
	id2 := h.newUpload("mpc", "race", storage.PutOptions{})
	p := h.part("mpc", "race", id2, 1, "only part")
	var completeErr, abortErr error
	var wg3 sync.WaitGroup
	wg3.Add(2)
	go func() {
		defer wg3.Done()
		_, completeErr = h.be.CompleteMultipartUpload(bg, "mpc", "race", id2, completeParts(p), storage.PutOptions{})
	}()
	go func() {
		defer wg3.Done()
		abortErr = h.be.AbortMultipartUpload(bg, "mpc", "race", id2)
	}()
	wg3.Wait()
	_, statErr := h.be.StatObject(bg, "mpc", "race", storage.GetOptions{})
	switch {
	case completeErr == nil && abortErr != nil:
		if statErr != nil {
			t.Errorf("complete won but the object is missing: %v", statErr)
		}
	case completeErr != nil && abortErr == nil:
		if statErr == nil {
			t.Error("abort won but an object exists")
		}
	default:
		t.Errorf("complete=%v abort=%v: exactly one must succeed", completeErr, abortErr)
	}
}

func testClosed(t *testing.T, f Factory) {
	h := newHarness(t, f)
	h.mkbucket("cls")
	h.put("cls", "k", "v")
	if err := h.be.Close(); err != nil {
		t.Fatal(err)
	}
	if err := h.be.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	calls := map[string]func() error{
		"MakeBucket":    func() error { return h.be.MakeBucket(bg, "other", storage.MakeBucketOptions{}) },
		"ListBuckets":   func() error { _, err := h.be.ListBuckets(bg); return err },
		"BucketExists":  func() error { _, err := h.be.BucketExists(bg, "cls"); return err },
		"GetBucketInfo": func() error { _, err := h.be.GetBucketInfo(bg, "cls"); return err },
		"DeleteBucket":  func() error { return h.be.DeleteBucket(bg, "cls", storage.DeleteBucketOptions{}) },
		"PutObject": func() error {
			_, err := h.be.PutObject(bg, "cls", "k2", bytes.NewReader(nil), 0, storage.PutOptions{})
			return err
		},
		"GetObject": func() error {
			rc, _, err := h.be.GetObject(bg, "cls", "k", storage.GetOptions{})
			if rc != nil {
				rc.Close()
			}
			return err
		},
		"StatObject":   func() error { _, err := h.be.StatObject(bg, "cls", "k", storage.GetOptions{}); return err },
		"DeleteObject": func() error { _, err := h.be.DeleteObject(bg, "cls", "k", storage.DeleteOptions{}); return err },
		"ListObjects":  func() error { _, err := h.be.ListObjects(bg, "cls", storage.ListOptions{}); return err },
		"Info":         func() error { _, err := h.be.Info(bg); return err },
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			wantErr(t, name, call(), storage.ErrBackendUnavailable)
		})
	}
}
