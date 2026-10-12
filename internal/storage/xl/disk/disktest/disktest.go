// Package disktest is the contract suite every disk.Disk implementation
// must pass. The local filesystem drive and, later, the remote drive run the
// same tests, so a remote drive cannot drift from the semantics xl relies
// on.
package disktest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"nanoio/internal/meta"
	"nanoio/internal/storage"
	"nanoio/internal/storage/xl/disk"
)

// Factory returns a fresh, opened and formatted drive that Ready reports
// usable, and a function that takes the drive's backing storage away (for a
// local drive, closing it; for a remote one, closing it on its node). The
// suite closes the returned drive itself.
type Factory func(t *testing.T) (d disk.Disk, kill func())

var bg = context.Background()

const (
	blockSize  = 64
	dataBlocks = 2
	uploadID   = "11111111-1111-4111-8111-111111111111"
	otherID    = "22222222-2222-4222-8222-222222222222"
)

// frame builds a valid shard stream for plaintext of the given size: a
// hash-prefixed record per block. The shard bytes are arbitrary here; the
// drive only verifies framing and hashes.
func frame(partSize int64) []byte {
	var out bytes.Buffer
	for b := int64(0); b < disk.BlockCount(partSize, blockSize); b++ {
		blockLen := min(int64(blockSize), partSize-b*blockSize)
		shard := bytes.Repeat([]byte{byte('a' + b%26)}, int(disk.ShardLen(blockLen, dataBlocks)))
		sum := sha256.Sum256(shard)
		out.Write(sum[:])
		out.Write(shard)
	}
	return out.Bytes()
}

func writeStage(t *testing.T, d disk.Disk, stage, rel string, data []byte) {
	t.Helper()
	w, err := d.CreateStageFile(bg, stage, rel)
	if err != nil {
		t.Fatalf("CreateStageFile(%s, %s): %v", stage, rel, err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

func version(dataDir string, size int64, etag string) meta.Version {
	return meta.Version{
		Type: meta.TypeObject, ModTime: time.Now().UTC(), Size: size, ETag: etag,
		DataDir: dataDir, ContentType: "text/plain",
		Parts: []meta.Part{{N: 1, Size: size, ETag: etag}},
		Erasure: &meta.Erasure{Algorithm: "reedsolomon", DataBlocks: dataBlocks, ParityBlocks: 1,
			BlockSize: blockSize, Index: 0, Distribution: []int{0, 1, 2}},
	}
}

// put stages and commits an object version (not finished) and returns the
// commit and the shard bytes.
func put(t *testing.T, d disk.Disk, bucket, object, dataDir, stage string, size int64) (disk.Commit, []byte) {
	t.Helper()
	data := frame(size)
	writeStage(t, d, stage, dataDir+"/part.1", data)
	c, err := d.CommitObject(bg, disk.CommitRequest{Bucket: bucket, Object: object, StageID: stage,
		DataDir: dataDir, Version: version(dataDir, size, "etag-"+dataDir)})
	if err != nil {
		t.Fatalf("CommitObject: %v", err)
	}
	return c, data
}

func readAll(t *testing.T, sh disk.Shard) []byte {
	t.Helper()
	buf := make([]byte, sh.Size())
	if _, err := sh.ReadAt(buf, 0); err != nil && err != io.EOF {
		t.Fatal(err)
	}
	return buf
}

func metaOf(t *testing.T, d disk.Disk, bucket, object string) *meta.Version {
	t.Helper()
	raw, err := d.ReadMeta(bg, bucket, object)
	if err != nil {
		t.Fatalf("ReadMeta(%s/%s): %v", bucket, object, err)
	}
	f, err := meta.Decode(raw)
	if err != nil {
		t.Fatalf("xl.meta does not decode: %v", err)
	}
	return f.Latest()
}

// Run executes the suite.
func Run(t *testing.T, newDisk Factory) {
	plain := func(f func(*testing.T, disk.Disk)) func(*testing.T, disk.Disk, func()) {
		return func(t *testing.T, d disk.Disk, _ func()) { f(t, d) }
	}
	cases := []struct {
		name string
		fn   func(*testing.T, disk.Disk, func())
	}{
		{"Buckets", plain(testBuckets)},
		{"CommitAndRead", plain(testCommitAndRead)},
		{"Overwrite", plain(testOverwrite)},
		{"Rollback", plain(testRollback)},
		{"PinKeepsDataAlive", plain(testPin)},
		{"Delete", plain(testDelete)},
		{"Staging", plain(testStaging)},
		{"VerifyShard", plain(testVerifyShard)},
		{"Uploads", plain(testUploads)},
		{"Parts", plain(testParts)},
		{"CompleteViaLink", plain(testLink)},
		{"Maintenance", plain(testMaintenance)},
		{"Orphans", plain(testOrphans)},
		{"KeysAndNames", plain(testKeys)},
		{"Concurrency", plain(testConcurrency)},
		{"ConditionalCommit", plain(testCAS)},
		{"TypedErrors", plain(testTypedErrors)},
		{"BucketVersioning", plain(testBucketVersioning)},
		{"VersionOps", plain(testVersionOps)},
		{"VersionReplace", plain(testVersionReplace)},
		{"BucketSettings", plain(testBucketSettings)},
		{"ObjectLock", plain(testObjectLock)},
		{"OfflineAfterClose", testClosed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, kill := newDisk(t)
			t.Cleanup(func() { d.Close() })
			if !d.Ready(bg) {
				t.Fatal("factory returned a drive that is not ready")
			}
			c.fn(t, d, kill)
		})
	}
}

func testBuckets(t *testing.T, d disk.Disk) {
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	made, err := d.MakeBucket(bg, "alpha", created)
	if err != nil || !made {
		t.Fatalf("MakeBucket = %v, %v", made, err)
	}
	if made, err := d.MakeBucket(bg, "alpha", time.Now()); err != nil || made {
		t.Errorf("second MakeBucket = %v, %v; want idempotent no-op", made, err)
	}
	exists, got, err := d.StatBucket(bg, "alpha")
	if err != nil || !exists || !got.Equal(created) {
		t.Errorf("StatBucket = %v %v %v; want exists, created %v (the first creation time)", exists, got, err, created)
	}
	if exists, _, err := d.StatBucket(bg, "missing"); err != nil || exists {
		t.Errorf("StatBucket(missing) = %v, %v", exists, err)
	}
	d.MakeBucket(bg, "bravo", created)
	names, err := d.ListBuckets(bg)
	sort.Strings(names)
	if err != nil || strings.Join(names, ",") != "alpha,bravo" {
		t.Errorf("ListBuckets = %v, %v", names, err)
	}

	// DeleteBucket takes objects and uploads with it.
	c, _ := put(t, d, "alpha", "k", ".nanoio-data-d1", "s1", 100)
	c.Finish(bg)
	if err := d.CreateUpload(bg, "alpha", uploadID, []byte(`{"object":"k"}`)); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteBucket(bg, "alpha"); err != nil {
		t.Fatal(err)
	}
	if exists, _, _ := d.StatBucket(bg, "alpha"); exists {
		t.Error("bucket survived DeleteBucket")
	}
	if _, err := d.ReadMeta(bg, "alpha", "k"); !errors.Is(err, disk.ErrNotFound) {
		t.Errorf("object survived: %v", err)
	}
	if _, err := d.ReadUpload(bg, "alpha", uploadID); !errors.Is(err, disk.ErrNotFound) {
		t.Errorf("upload survived: %v", err)
	}
	if err := d.DeleteBucket(bg, "alpha"); err != nil {
		t.Errorf("DeleteBucket of a missing bucket: %v", err)
	}
}

func testCommitAndRead(t *testing.T, d disk.Disk) {
	d.MakeBucket(bg, "b", time.Now())
	if _, err := d.ReadMeta(bg, "b", "nope"); !errors.Is(err, disk.ErrNotFound) {
		t.Errorf("ReadMeta of a missing object: %v", err)
	}
	c, data := put(t, d, "b", "dir/obj.bin", ".nanoio-data-v1", "stage-1", 300)
	if err := c.Finish(bg); err != nil {
		t.Fatal(err)
	}
	v := metaOf(t, d, "b", "dir/obj.bin")
	if v.DataDir != ".nanoio-data-v1" || v.Size != 300 || v.ETag != "etag-.nanoio-data-v1" || v.Erasure == nil || v.Erasure.DataBlocks != 2 {
		t.Errorf("stored version = %+v", v)
	}
	sh, err := d.OpenShard(bg, "b", "dir/obj.bin", ".nanoio-data-v1", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer sh.Close()
	if sh.Size() != int64(len(data)) || !bytes.Equal(readAll(t, sh), data) {
		t.Errorf("shard bytes differ (size %d, want %d)", sh.Size(), len(data))
	}
	if n, err := d.StatShard(bg, "b", "dir/obj.bin", ".nanoio-data-v1", 1); err != nil || n != int64(len(data)) {
		t.Errorf("StatShard = %d, %v", n, err)
	}
	if _, err := d.OpenShard(bg, "b", "dir/obj.bin", ".nanoio-data-v1", 2); !errors.Is(err, disk.ErrNotFound) {
		t.Errorf("OpenShard of a missing part: %v", err)
	}
	if _, err := d.StatShard(bg, "b", "dir/obj.bin", ".nanoio-data-gone", 1); !errors.Is(err, disk.ErrNotFound) {
		t.Errorf("StatShard of a missing dir: %v", err)
	}
	// The stage was consumed.
	writeStage(t, d, "stage-1", "again", []byte("x")) // would fail if "again" still existed
}

func testOverwrite(t *testing.T, d disk.Disk) {
	d.MakeBucket(bg, "b", time.Now())
	c1, _ := put(t, d, "b", "k", ".nanoio-data-v1", "s1", 100)
	c1.Finish(bg)
	c2, data2 := put(t, d, "b", "k", ".nanoio-data-v2", "s2", 200)
	// Until Finish both versions' data exist; xl.meta already names v2.
	if v := metaOf(t, d, "b", "k"); v.DataDir != ".nanoio-data-v2" {
		t.Fatalf("latest = %s", v.DataDir)
	}
	if _, err := d.OpenShard(bg, "b", "k", ".nanoio-data-v1", 1); err != nil {
		t.Errorf("superseded data removed before Finish: %v", err)
	}
	if err := c2.Finish(bg); err != nil {
		t.Fatal(err)
	}
	if _, err := d.OpenShard(bg, "b", "k", ".nanoio-data-v1", 1); !errors.Is(err, disk.ErrNotFound) {
		t.Errorf("superseded data survived Finish: %v", err)
	}
	sh, err := d.OpenShard(bg, "b", "k", ".nanoio-data-v2", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer sh.Close()
	if !bytes.Equal(readAll(t, sh), data2) {
		t.Error("new data differs")
	}
}

func testRollback(t *testing.T, d disk.Disk) {
	d.MakeBucket(bg, "b", time.Now())
	// Rolling back a first write leaves nothing.
	c, _ := put(t, d, "b", "fresh", ".nanoio-data-v1", "s1", 50)
	if err := c.Rollback(bg); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ReadMeta(bg, "b", "fresh"); !errors.Is(err, disk.ErrNotFound) {
		t.Errorf("rolled-back object visible: %v", err)
	}
	if _, err := d.StatShard(bg, "b", "fresh", ".nanoio-data-v1", 1); !errors.Is(err, disk.ErrNotFound) {
		t.Errorf("rolled-back data remains: %v", err)
	}

	// Rolling back an overwrite restores the previous version whole.
	c1, data1 := put(t, d, "b", "k", ".nanoio-data-v1", "s2", 100)
	c1.Finish(bg)
	c2, _ := put(t, d, "b", "k", ".nanoio-data-v2", "s3", 400)
	if err := c2.Rollback(bg); err != nil {
		t.Fatal(err)
	}
	v := metaOf(t, d, "b", "k")
	if v.DataDir != ".nanoio-data-v1" || v.Size != 100 {
		t.Errorf("after rollback: %+v", v)
	}
	sh, err := d.OpenShard(bg, "b", "k", ".nanoio-data-v1", 1)
	if err != nil {
		t.Fatalf("previous data lost: %v", err)
	}
	defer sh.Close()
	if !bytes.Equal(readAll(t, sh), data1) {
		t.Error("previous data damaged")
	}
	if _, err := d.StatShard(bg, "b", "k", ".nanoio-data-v2", 1); !errors.Is(err, disk.ErrNotFound) {
		t.Errorf("rolled-back data remains: %v", err)
	}
}

func testPin(t *testing.T, d disk.Disk) {
	d.MakeBucket(bg, "b", time.Now())
	c1, data1 := put(t, d, "b", "k", ".nanoio-data-v1", "s1", 100)
	c1.Finish(bg)
	release, err := d.PinData(bg, "b", "k", ".nanoio-data-v1")
	if err != nil {
		t.Fatal(err)
	}
	c2, _ := put(t, d, "b", "k", ".nanoio-data-v2", "s2", 120)
	c2.Finish(bg) // would remove v1 were it not pinned

	sh, err := d.OpenShard(bg, "b", "k", ".nanoio-data-v1", 1)
	if err != nil {
		t.Fatalf("pinned data was removed: %v", err)
	}
	if !bytes.Equal(readAll(t, sh), data1) {
		t.Error("pinned data differs")
	}
	sh.Close()
	release()
	release() // idempotent
	if _, err := d.OpenShard(bg, "b", "k", ".nanoio-data-v1", 1); !errors.Is(err, disk.ErrNotFound) {
		t.Errorf("data survived the last release: %v", err)
	}

	// The same holds for deletion.
	release, err = d.PinData(bg, "b", "k", ".nanoio-data-v2")
	if err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteObject(bg, "b", "k"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ReadMeta(bg, "b", "k"); !errors.Is(err, disk.ErrNotFound) {
		t.Errorf("deleted object still has metadata: %v", err)
	}
	if _, err := d.StatShard(bg, "b", "k", ".nanoio-data-v2", 1); err != nil {
		t.Errorf("pinned data of a deleted object removed early: %v", err)
	}
	release()
	if _, err := d.StatShard(bg, "b", "k", ".nanoio-data-v2", 1); !errors.Is(err, disk.ErrNotFound) {
		t.Errorf("data survived release after delete: %v", err)
	}
}

func testDelete(t *testing.T, d disk.Disk) {
	d.MakeBucket(bg, "b", time.Now())
	if err := d.DeleteObject(bg, "b", "never/existed"); err != nil {
		t.Errorf("deleting a missing object: %v", err)
	}
	for _, k := range []string{"a", "a/b", "a/b/c"} {
		c, _ := put(t, d, "b", k, ".nanoio-data-"+strings.ReplaceAll(k, "/", "-"), "s-"+strings.ReplaceAll(k, "/", "-"), 10)
		c.Finish(bg)
	}
	if err := d.DeleteObject(bg, "b", "a/b"); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"a", "a/b/c"} {
		if _, err := d.ReadMeta(bg, "b", k); err != nil {
			t.Errorf("sibling %s damaged: %v", k, err)
		}
	}
	d.DeleteObject(bg, "b", "a/b/c")
	d.DeleteObject(bg, "b", "a")
	keys, err := d.ListKeys(bg, "b", "")
	if err != nil || len(keys) != 0 {
		t.Errorf("keys after deleting everything: %v, %v", keys, err)
	}
}

func testStaging(t *testing.T, d disk.Disk) {
	w, err := d.CreateStageFile(bg, "stg", "f")
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("hello"))
	if _, err := d.CreateStageFile(bg, "stg", "f"); err == nil {
		t.Error("a staged file was created twice")
	}
	w.Abort()
	// Aborting removed the file, so the name is free again.
	w2, err := d.CreateStageFile(bg, "stg", "f")
	if err != nil {
		t.Fatalf("after Abort: %v", err)
	}
	w2.Write([]byte("kept"))
	w2.Close()

	// A held stage survives a sweep that would remove everything unheld.
	d.SweepStaging(bg, -1)
	if _, err := d.CreateStageFile(bg, "stg", "f"); err == nil {
		t.Error("a held staging area was swept")
	}
	d.RemoveStage(bg, "stg")
	if w3, err := d.CreateStageFile(bg, "stg", "f"); err != nil {
		t.Errorf("after RemoveStage: %v", err)
	} else {
		w3.Abort()
	}
	d.RemoveStage(bg, "stg")
	d.RemoveStage(bg, "never-existed") // harmless
}

func testVerifyShard(t *testing.T, d disk.Disk) {
	d.MakeBucket(bg, "b", time.Now())
	c, data := put(t, d, "b", "k", ".nanoio-data-v1", "s1", 200)
	c.Finish(bg)
	root, err := d.VerifyShard(bg, "b", "k", ".nanoio-data-v1", 1, 200, blockSize, dataBlocks)
	if err != nil || len(root) != 64 {
		t.Fatalf("VerifyShard = %q, %v", root, err)
	}
	want, _ := disk.VerifyStream(bytes.NewReader(data), 200, blockSize, dataBlocks)
	if root != want {
		t.Errorf("root = %s, want %s", root, want)
	}
	// The wrong declared size must not verify.
	if _, err := d.VerifyShard(bg, "b", "k", ".nanoio-data-v1", 1, 5000, blockSize, dataBlocks); err == nil {
		t.Error("a shard verified against the wrong part size")
	}
	if _, err := d.VerifyShard(bg, "b", "k", ".nanoio-data-v1", 7, 200, blockSize, dataBlocks); !errors.Is(err, disk.ErrNotFound) {
		t.Errorf("VerifyShard of a missing part: %v", err)
	}

	// A flipped bit fails verification.
	bad := bytes.Clone(data)
	bad[len(bad)-1] ^= 0xff
	writeStage(t, d, "s2", ".nanoio-data-bad/part.1", bad)
	cm, err := d.CommitObject(bg, disk.CommitRequest{Bucket: "b", Object: "rot", StageID: "s2",
		DataDir: ".nanoio-data-bad", Version: version(".nanoio-data-bad", 200, "x")})
	if err != nil {
		t.Fatal(err)
	}
	cm.Finish(bg)
	if _, err := d.VerifyShard(bg, "b", "rot", ".nanoio-data-bad", 1, 200, blockSize, dataBlocks); err == nil {
		t.Error("a corrupted shard verified")
	}
}

func partRecord(n int, file string, size int64, etag string) ([]byte, disk.PartRecord) {
	pr := disk.PartRecord{Number: n, File: file, Size: size, ETag: etag, ModTime: time.Now().UTC(),
		Root: "root-" + etag, ShardSize: disk.ShardFileSize(size, blockSize, dataBlocks)}
	b, _ := json.Marshal(pr)
	return b, pr
}

func commitPart(t *testing.T, d disk.Disk, n int, token string, size int64, etag string) disk.Commit {
	t.Helper()
	file := fmt.Sprintf("%d.%s.data", n, token)
	stage := "part-" + token
	writeStage(t, d, stage, file, frame(size))
	rec, _ := partRecord(n, file, size, etag)
	c, err := d.CommitPart(bg, disk.PartCommit{Bucket: "b", UploadID: uploadID, StageID: stage, DataFile: file, Number: n, Record: rec})
	if err != nil {
		t.Fatalf("CommitPart: %v", err)
	}
	return c
}

func testUploads(t *testing.T, d disk.Disk) {
	d.MakeBucket(bg, "b", time.Now())
	if ids, err := d.ListUploadIDs(bg, "b"); err != nil || len(ids) != 0 {
		t.Errorf("fresh bucket uploads = %v, %v", ids, err)
	}
	doc := []byte(`{"object":"k","initiated":"2026-01-01T00:00:00Z"}`)
	if err := d.CreateUpload(bg, "b", uploadID, doc); err != nil {
		t.Fatal(err)
	}
	if err := d.CreateUpload(bg, "b", otherID, doc); err != nil {
		t.Fatal(err)
	}
	got, err := d.ReadUpload(bg, "b", uploadID)
	if err != nil || !bytes.Equal(got, doc) {
		t.Errorf("ReadUpload = %q, %v", got, err)
	}
	ids, _ := d.ListUploadIDs(bg, "b")
	sort.Strings(ids)
	if strings.Join(ids, ",") != uploadID+","+otherID {
		t.Errorf("ids = %v", ids)
	}
	// IDs that are not generated upload IDs never reach the filesystem.
	for _, bad := range []string{"", "../../etc", "not-an-id", strings.Repeat("a", 36)} {
		if _, err := d.ReadUpload(bg, "b", bad); !errors.Is(err, disk.ErrNotFound) {
			t.Errorf("ReadUpload(%q) = %v, want ErrNotFound", bad, err)
		}
		if err := d.DiscardUpload(bg, "b", bad); err != nil {
			t.Errorf("DiscardUpload(%q) = %v", bad, err)
		}
	}
	if err := d.DiscardUpload(bg, "b", uploadID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ReadUpload(bg, "b", uploadID); !errors.Is(err, disk.ErrNotFound) {
		t.Errorf("discarded upload readable: %v", err)
	}
	if err := d.DiscardUpload(bg, "b", uploadID); err != nil {
		t.Errorf("discarding twice: %v", err)
	}
	if _, err := d.ReadUpload(bg, "b", otherID); err != nil {
		t.Errorf("the other upload was affected: %v", err)
	}
}

func testParts(t *testing.T, d disk.Disk) {
	d.MakeBucket(bg, "b", time.Now())
	if _, err := d.ListParts(bg, "b", uploadID); !errors.Is(err, disk.ErrNotFound) {
		t.Errorf("ListParts of a missing upload: %v", err)
	}
	d.CreateUpload(bg, "b", uploadID, []byte(`{}`))

	c1 := commitPart(t, d, 1, "aaaa", 150, "e1")
	c1.Finish(bg)
	c3 := commitPart(t, d, 3, "bbbb", 70, "e3")
	c3.Finish(bg)
	parts, err := d.ListParts(bg, "b", uploadID)
	if err != nil || len(parts) != 2 {
		t.Fatalf("parts = %+v, %v", parts, err)
	}
	sort.Slice(parts, func(i, j int) bool { return parts[i].Number < parts[j].Number })
	if parts[0].Number != 1 || parts[0].ETag != "e1" || parts[0].Size != 150 || parts[1].Number != 3 || parts[1].File != "3.bbbb.data" {
		t.Errorf("parts = %+v", parts)
	}

	// Replacing a part: until Finish the old bytes still exist, and a
	// rollback restores the old record.
	r := commitPart(t, d, 1, "cccc", 90, "e1-new")
	if err := r.Rollback(bg); err != nil {
		t.Fatal(err)
	}
	parts, _ = d.ListParts(bg, "b", uploadID)
	for _, p := range parts {
		if p.Number == 1 && (p.ETag != "e1" || p.File != "1.aaaa.data") {
			t.Errorf("rollback did not restore part 1: %+v", p)
		}
	}
	r = commitPart(t, d, 1, "dddd", 90, "e1-final")
	if err := r.Finish(bg); err != nil {
		t.Fatal(err)
	}
	parts, _ = d.ListParts(bg, "b", uploadID)
	for _, p := range parts {
		if p.Number == 1 && (p.ETag != "e1-final" || p.File != "1.dddd.data" || p.Size != 90) {
			t.Errorf("part 1 = %+v", p)
		}
	}
	if err := d.LinkPartIntoStage(bg, "b", uploadID, "1.aaaa.data", "probe", "x"); !errors.Is(err, disk.ErrNotFound) {
		t.Errorf("the replaced part's data file survived Finish: %v", err)
	}
	d.RemoveStage(bg, "probe")

	// A part whose shard file has the wrong size is not listed.
	if _, err := d.CommitPart(bg, disk.PartCommit{Bucket: "b", UploadID: uploadID, StageID: "nostage", DataFile: "9.zz.data", Number: 9,
		Record: []byte(`{}`)}); err == nil {
		t.Error("CommitPart of a missing staged file succeeded")
	}
}

func testLink(t *testing.T, d disk.Disk) {
	d.MakeBucket(bg, "b", time.Now())
	d.CreateUpload(bg, "b", uploadID, []byte(`{}`))
	commitPart(t, d, 1, "aaaa", 100, "e1").Finish(bg)
	commitPart(t, d, 2, "bbbb", 50, "e2").Finish(bg)

	// Assemble the object the way CompleteMultipartUpload does.
	for _, l := range []struct{ file, rel string }{
		{"1.aaaa.data", ".nanoio-data-mp/part.1"},
		{"2.bbbb.data", ".nanoio-data-mp/part.2"},
	} {
		if err := d.LinkPartIntoStage(bg, "b", uploadID, l.file, "complete", l.rel); err != nil {
			t.Fatalf("LinkPartIntoStage(%s): %v", l.file, err)
		}
	}
	if err := d.LinkPartIntoStage(bg, "b", uploadID, "9.nope.data", "complete", ".nanoio-data-mp/part.9"); !errors.Is(err, disk.ErrNotFound) {
		t.Errorf("linking a missing part: %v", err)
	}
	v := version(".nanoio-data-mp", 150, "etag-mp")
	v.Parts = []meta.Part{{N: 1, Size: 100, ETag: "e1"}, {N: 2, Size: 50, ETag: "e2"}}
	c, err := d.CommitObject(bg, disk.CommitRequest{Bucket: "b", Object: "assembled", StageID: "complete", DataDir: ".nanoio-data-mp", Version: v})
	if err != nil {
		t.Fatal(err)
	}
	c.Finish(bg)
	for n, size := range map[int]int64{1: 100, 2: 50} {
		sh, err := d.OpenShard(bg, "b", "assembled", ".nanoio-data-mp", n)
		if err != nil {
			t.Fatalf("part %d: %v", n, err)
		}
		if sh.Size() != disk.ShardFileSize(size, blockSize, dataBlocks) {
			t.Errorf("part %d size %d", n, sh.Size())
		}
		sh.Close()
	}
	// The object stands on its own once the upload is gone.
	d.DiscardUpload(bg, "b", uploadID)
	sh, err := d.OpenShard(bg, "b", "assembled", ".nanoio-data-mp", 1)
	if err != nil {
		t.Fatalf("object lost its data with the upload: %v", err)
	}
	sh.Close()
}

func testMaintenance(t *testing.T, d disk.Disk) {
	d.MakeBucket(bg, "live", time.Now())
	d.CreateUpload(bg, "live", uploadID, []byte(`{}`))
	// Upload in a bucket that does not exist on this drive.
	d.CreateUpload(bg, "ghost", otherID, []byte(`{}`))

	stale, err := d.StaleUploads(bg, time.Hour)
	if err != nil || len(stale) != 1 || stale[0].Bucket != "ghost" || stale[0].ID != otherID || !stale[0].BucketGone {
		t.Fatalf("StaleUploads(1h) = %+v, %v", stale, err)
	}
	if ok, err := d.DiscardUploadIfStale(bg, "live", uploadID, time.Hour); err != nil || ok {
		t.Errorf("a fresh upload was discarded: %v, %v", ok, err)
	}
	if ok, err := d.DiscardUploadIfStale(bg, "ghost", otherID, time.Hour); err != nil || !ok {
		t.Errorf("an upload of a vanished bucket was kept: %v, %v", ok, err)
	}
	// With a negative window every upload is stale.
	stale, _ = d.StaleUploads(bg, -1)
	if len(stale) != 1 || stale[0].ID != uploadID {
		t.Errorf("StaleUploads(-1) = %+v", stale)
	}
	if ok, _ := d.DiscardUploadIfStale(bg, "live", uploadID, -1); !ok {
		t.Error("stale upload not discarded")
	}
	if ids, _ := d.ListUploadIDs(bg, "live"); len(ids) != 0 {
		t.Errorf("uploads left: %v", ids)
	}
}

func testOrphans(t *testing.T, d disk.Disk) {
	d.MakeBucket(bg, "b", time.Now())
	c1, _ := put(t, d, "b", "obj", ".nanoio-data-v1", "s1", 60)
	c1.Finish(bg)
	if o, err := d.FindOrphans(bg, "b"); err != nil || len(o) != 0 {
		t.Fatalf("orphans of a healthy bucket = %+v, %v", o, err)
	}
	// Committing v2 without finishing leaves v1's data unreferenced.
	c2, _ := put(t, d, "b", "obj", ".nanoio-data-v2", "s2", 60)
	orphans, err := d.FindOrphans(bg, "b")
	if err != nil || len(orphans) != 1 || orphans[0].Object != "obj" ||
		len(orphans[0].DataDirs) != 1 || orphans[0].DataDirs[0] != ".nanoio-data-v1" {
		t.Fatalf("orphans = %+v, %v", orphans, err)
	}
	// Names that are not data directories are refused, and referenced ones kept.
	n, err := d.RemoveOrphans(bg, "b", "obj", []string{".nanoio-data-v2", "../escape", "xl.meta", ".nanoio-data-v1"})
	if err != nil || n != 1 {
		t.Errorf("RemoveOrphans removed %d, %v; want exactly the unreferenced one", n, err)
	}
	if _, err := d.StatShard(bg, "b", "obj", ".nanoio-data-v1", 1); !errors.Is(err, disk.ErrNotFound) {
		t.Errorf("orphan survived: %v", err)
	}
	if _, err := d.StatShard(bg, "b", "obj", ".nanoio-data-v2", 1); err != nil {
		t.Errorf("the live data directory was removed: %v", err)
	}
	c2.Finish(bg)
}

func testKeys(t *testing.T, d disk.Disk) {
	d.MakeBucket(bg, "b", time.Now())
	keys := []string{"a", "a/b", "dir/", "z/y/x", "with space", "ünï"}
	for i, k := range keys {
		c, _ := put(t, d, "b", k, fmt.Sprintf(".nanoio-data-k%d", i), fmt.Sprintf("s%d", i), 10)
		c.Finish(bg)
	}
	got, err := d.ListKeys(bg, "b", "")
	sort.Strings(got)
	want := append([]string(nil), keys...)
	sort.Strings(want)
	if err != nil || strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("ListKeys = %q, %v; want %q", got, err, want)
	}
	got, _ = d.ListKeys(bg, "b", "z/")
	if len(got) != 1 || got[0] != "z/y/x" {
		t.Errorf("prefix z/ = %q", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := d.ListKeys(ctx, "b", ""); err == nil {
		t.Error("ListKeys ignored a cancelled context")
	}
	// Hostile names never escape the drive.
	for _, bad := range []string{"../x", "a/../../x"} {
		if _, err := d.ReadMeta(bg, "b", bad); err == nil {
			t.Errorf("ReadMeta(%q) succeeded", bad)
		}
	}
}

func testConcurrency(t *testing.T, d disk.Disk) {
	d.MakeBucket(bg, "b", time.Now())
	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			obj := fmt.Sprintf("obj-%02d", i)
			dd := fmt.Sprintf(".nanoio-data-c%02d", i)
			st := fmt.Sprintf("stage-%02d", i)
			w, err := d.CreateStageFile(bg, st, dd+"/part.1")
			if err != nil {
				errs <- err
				return
			}
			w.Write(frame(80))
			if err := w.Close(); err != nil {
				errs <- err
				return
			}
			c, err := d.CommitObject(bg, disk.CommitRequest{Bucket: "b", Object: obj, StageID: st,
				DataDir: dd, Version: version(dd, 80, "e")})
			if err != nil {
				errs <- err
				return
			}
			errs <- c.Finish(bg)
			d.RemoveStage(bg, st)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	keys, _ := d.ListKeys(bg, "b", "")
	if len(keys) != 16 {
		t.Errorf("%d objects committed, want 16", len(keys))
	}
}

func testClosed(t *testing.T, d disk.Disk, kill func()) {
	d.MakeBucket(bg, "b", time.Now())
	kill()
	if d.Ready(bg) {
		t.Error("a closed drive reports ready")
	}
	checks := map[string]error{}
	_, checks["MakeBucket"] = d.MakeBucket(bg, "x", time.Now())
	_, _, checks["StatBucket"] = d.StatBucket(bg, "b")
	_, checks["ListBuckets"] = d.ListBuckets(bg)
	_, checks["ReadMeta"] = d.ReadMeta(bg, "b", "k")
	_, checks["OpenShard"] = d.OpenShard(bg, "b", "k", ".nanoio-data-x", 1)
	_, checks["CreateStageFile"] = d.CreateStageFile(bg, "s", "f")
	checks["DeleteObject"] = d.DeleteObject(bg, "b", "k")
	checks["CreateUpload"] = d.CreateUpload(bg, "b", uploadID, nil)
	for name, err := range checks {
		if !errors.Is(err, disk.ErrOffline) {
			t.Errorf("%s on a closed drive = %v, want ErrOffline", name, err)
		}
		if _, ok := err.(*disk.Error); !ok {
			t.Errorf("%s returned %T, want *disk.Error outermost", name, err)
		}
	}
}

// commitGen stages and commits generation gen of an object, conditional on
// the drive not holding more than prev when check is set.
func commitGen(t *testing.T, d disk.Disk, obj, dataDir, stage string, gen, prev uint64, check bool) (disk.Commit, error) {
	t.Helper()
	writeStage(t, d, stage, dataDir+"/part.1", frame(40))
	v := version(dataDir, 40, "etag-"+dataDir)
	v.Generation = gen
	req := disk.CommitRequest{Bucket: "b", Object: obj, StageID: stage, DataDir: dataDir,
		Version: v, CheckGen: check, PrevGen: prev}
	if check { // a numbered write; an unconditional one lets the drive number it
		req.Seq = gen
	}
	return d.CommitObject(bg, req)
}

func testCAS(t *testing.T, d disk.Disk) {
	d.MakeBucket(bg, "b", time.Now())
	gen := func() uint64 { return metaOf(t, d, "b", "o").Generation }

	c, err := commitGen(t, d, "o", ".nanoio-data-g1", "s1", 1, 0, true)
	if err != nil {
		t.Fatalf("first write: %v", err)
	}
	c.Finish(bg)
	c, err = commitGen(t, d, "o", ".nanoio-data-g2", "s2", 2, 1, true)
	if err != nil {
		t.Fatalf("second write: %v", err)
	}
	c.Finish(bg)

	// A writer that read generation 1 loses, and changes nothing.
	if _, err := commitGen(t, d, "o", ".nanoio-data-late", "s3", 2, 1, true); !errors.Is(err, disk.ErrConflict) {
		t.Fatalf("stale writer = %v, want ErrConflict", err)
	}
	if g := gen(); g != 2 {
		t.Errorf("generation after a refused commit = %d", g)
	}
	if v := metaOf(t, d, "b", "o"); v.DataDir != ".nanoio-data-g2" {
		t.Errorf("a refused commit moved the object to %s", v.DataDir)
	}
	if _, err := d.StatShard(bg, "b", "o", ".nanoio-data-late", 1); !errors.Is(err, disk.ErrNotFound) {
		t.Errorf("a refused commit left its data behind: %v", err)
	}
	d.RemoveStage(bg, "s3")

	// An unconditional commit (a repair) is not subject to the check.
	c, err = commitGen(t, d, "o", ".nanoio-data-fix", "s4", 2, 0, false)
	if err != nil {
		t.Fatalf("repair commit: %v", err)
	}
	c.Finish(bg)

	// A drive that is behind accepts a newer write.
	c, err = commitGen(t, d, "o", ".nanoio-data-g5", "s5", 5, 4, true)
	if err != nil {
		t.Fatalf("catching up: %v", err)
	}
	c.Finish(bg)
	if g := gen(); g != 5 {
		t.Errorf("generation = %d, want 5", g)
	}

	// A rollback that arrives after another writer committed over this
	// version must leave the newer state alone.
	c6, err := commitGen(t, d, "o", ".nanoio-data-g6", "s6", 6, 5, true)
	if err != nil {
		t.Fatal(err)
	}
	c7, err := commitGen(t, d, "o", ".nanoio-data-g7", "s7", 7, 6, true)
	if err != nil {
		t.Fatal(err)
	}
	c6.Rollback(bg)
	if g := gen(); g != 7 {
		t.Errorf("a stale rollback clobbered the newer commit: generation %d", g)
	}
	if _, err := d.StatShard(bg, "b", "o", ".nanoio-data-g7", 1); err != nil {
		t.Errorf("a stale rollback removed the newer data: %v", err)
	}
	c7.Finish(bg)
}

// testTypedErrors: every failure is an *disk.Error as the outermost error,
// and classification by errors.Is does not depend on where the drive lives.
func testTypedErrors(t *testing.T, d disk.Disk) {
	d.MakeBucket(bg, "b", time.Now())
	kindOf := func(name string, err error) disk.Kind {
		t.Helper()
		e, ok := err.(*disk.Error)
		if !ok {
			t.Fatalf("%s returned %T (%v), want *disk.Error outermost", name, err, err)
		}
		return e.Kind
	}
	_, err := d.ReadMeta(bg, "b", "absent")
	if k := kindOf("ReadMeta", err); k != disk.KindNotFound || !errors.Is(err, disk.ErrNotFound) {
		t.Errorf("missing object: kind %v, is-NotFound %v", k, errors.Is(err, disk.ErrNotFound))
	}
	_, err = d.OpenShard(bg, "b", "absent", ".nanoio-data-x", 1)
	if k := kindOf("OpenShard", err); k != disk.KindNotFound {
		t.Errorf("OpenShard kind %v", k)
	}
	_, err = d.ReadUpload(bg, "b", uploadID)
	if k := kindOf("ReadUpload", err); k != disk.KindNotFound {
		t.Errorf("ReadUpload kind %v", k)
	}
	if errors.Is(err, disk.ErrOffline) || errors.Is(err, disk.ErrConflict) {
		t.Error("a not-found error also matches unrelated sentinels")
	}

	// A cancelled context is its own kind and still matches context.Canceled.
	ctx, cancel := context.WithCancel(bg)
	cancel()
	_, err = d.ListBuckets(ctx)
	if k := kindOf("ListBuckets(cancelled)", err); k != disk.KindCanceled {
		t.Errorf("cancelled call kind %v", k)
	}
	if !errors.Is(err, context.Canceled) || !errors.Is(err, disk.ErrCanceled) {
		t.Errorf("cancelled call does not match context.Canceled / ErrCanceled: %v", err)
	}
	if d.Ready(ctx) {
		t.Error("Ready reported true on a cancelled context")
	}

	// A conditional-commit loss is KindConflict.
	c, err := commitGen(t, d, "tc", ".nanoio-data-t1", "ts1", 2, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	c.Finish(bg)
	_, err = commitGen(t, d, "tc", ".nanoio-data-t2", "ts2", 2, 1, true)
	if k := kindOf("CommitObject", err); k != disk.KindConflict || !errors.Is(err, disk.ErrConflict) {
		t.Errorf("lost CAS: kind %v err %v", k, err)
	}
	d.RemoveStage(bg, "ts2")
}

func testBucketVersioning(t *testing.T, d disk.Disk) {
	created := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	if _, err := d.MakeBucket(bg, "vb", created); err != nil {
		t.Fatal(err)
	}
	st, seq, err := d.ReadBucketVersioning(bg, "vb")
	if err != nil || st != "" || seq != 0 {
		t.Fatalf("fresh bucket = %q, %d, %v", st, seq, err)
	}
	if err := d.WriteBucketVersioning(bg, "vb", "Enabled", 1); err != nil {
		t.Fatal(err)
	}
	if st, seq, err = d.ReadBucketVersioning(bg, "vb"); err != nil || st != "Enabled" || seq != 1 {
		t.Fatalf("after write = %q, %d, %v", st, seq, err)
	}
	// The creation record survives, and so does the state across other
	// bucket and object activity.
	if exists, got, err := d.StatBucket(bg, "vb"); err != nil || !exists || !got.Equal(created) {
		t.Errorf("StatBucket = %v %v %v; want created %v", exists, got, err, created)
	}
	c, _ := put(t, d, "vb", "obj", ".nanoio-data-v1", "vs1", 50)
	c.Finish(bg)
	if st, seq, _ = d.ReadBucketVersioning(bg, "vb"); st != "Enabled" || seq != 1 {
		t.Errorf("state changed by an object write: %q, %d", st, seq)
	}
	if err := d.WriteBucketVersioning(bg, "vb", "Suspended", 2); err != nil {
		t.Fatal(err)
	}
	if st, seq, _ = d.ReadBucketVersioning(bg, "vb"); st != "Suspended" || seq != 2 {
		t.Errorf("after second write = %q, %d", st, seq)
	}
	// The drive stores what it is told; ordering and repair are the
	// caller's job (xl writes every drive and heals laggards).
	if err := d.WriteBucketVersioning(bg, "vb", "Suspended", 2); err != nil {
		t.Errorf("rewriting the same value = %v", err)
	}
	if err := d.WriteBucketVersioning(bg, "vb", "Enabled", 7); err != nil {
		t.Fatal(err)
	}
	if _, seq, _ = d.ReadBucketVersioning(bg, "vb"); seq != 7 {
		t.Errorf("seq = %d", seq)
	}
	if _, _, err := d.ReadBucketVersioning(bg, "missing"); !errors.Is(err, disk.ErrNotFound) {
		t.Errorf("read of a missing bucket = %v", err)
	}
	if err := d.WriteBucketVersioning(bg, "missing", "Enabled", 1); !errors.Is(err, disk.ErrNotFound) {
		t.Errorf("write to a missing bucket = %v", err)
	}
	// A deleted and re-created bucket starts unversioned again.
	d.DeleteBucket(bg, "vb")
	d.MakeBucket(bg, "vb", created)
	if st, seq, _ = d.ReadBucketVersioning(bg, "vb"); st != "" || seq != 0 {
		t.Errorf("recreated bucket = %q, %d", st, seq)
	}
}

// putVer stages and commits one numbered version of obj.
func putVer(t *testing.T, d disk.Disk, obj, id, dataDir string, seq uint64) disk.Commit {
	t.Helper()
	stage := "pv-" + dataDir
	writeStage(t, d, stage, dataDir+"/part.1", frame(30))
	v := version(dataDir, 30, "etag-"+dataDir)
	v.VersionID = id
	c, err := d.CommitObject(bg, disk.CommitRequest{Bucket: "vb", Object: obj, Op: disk.OpPut,
		StageID: stage, DataDir: dataDir, Version: v, Seq: seq, CheckGen: true, PrevGen: seq - 1})
	if err != nil {
		t.Fatalf("OpPut %s@%q seq %d: %v", obj, id, seq, err)
	}
	t.Cleanup(func() { d.RemoveStage(bg, stage) })
	return c
}

func fileOf(t *testing.T, d disk.Disk, obj string) *meta.File {
	t.Helper()
	raw, err := d.ReadMeta(bg, "vb", obj)
	if err != nil {
		t.Fatalf("ReadMeta(%s): %v", obj, err)
	}
	f, err := meta.Decode(raw)
	if err != nil {
		t.Fatalf("xl.meta of %s does not decode: %v", obj, err)
	}
	return f
}

func hasData(d disk.Disk, obj, dataDir string) bool {
	_, err := d.StatShard(bg, "vb", obj, dataDir, 1)
	return err == nil
}

func versionIDs(f *meta.File) []string {
	var out []string
	for _, v := range f.Versions {
		out = append(out, v.VersionID)
	}
	return out
}

func testVersionOps(t *testing.T, d disk.Disk) {
	d.MakeBucket(bg, "vb", time.Now())
	same := func(got, want []string, what string) {
		t.Helper()
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s = %v, want %v", what, got, want)
		}
	}

	// Versions accumulate, newest first, each with its own data.
	putVer(t, d, "k", "ida", ".nanoio-data-a", 1).Finish(bg)
	putVer(t, d, "k", "idb", ".nanoio-data-b", 2).Finish(bg)
	f := fileOf(t, d, "k")
	same(versionIDs(f), []string{"idb", "ida"}, "versions")
	if f.Gen != 2 || f.Versions[0].Seq != 2 || f.Versions[1].Seq != 1 {
		t.Errorf("gen %d seqs %d,%d", f.Gen, f.Versions[0].Seq, f.Versions[1].Seq)
	}
	if !hasData(d, "k", ".nanoio-data-a") || !hasData(d, "k", ".nanoio-data-b") {
		t.Error("a version's data is missing")
	}

	// The null version is replaced; its data goes at Finish, not before.
	putVer(t, d, "k", "", ".nanoio-data-n1", 3).Finish(bg)
	c := putVer(t, d, "k", "", ".nanoio-data-n2", 4)
	same(versionIDs(fileOf(t, d, "k")), []string{"", "idb", "ida"}, "versions with the null version")
	if !hasData(d, "k", ".nanoio-data-n1") {
		t.Error("a replaced null version's data was removed before Finish")
	}
	c.Finish(bg)
	if hasData(d, "k", ".nanoio-data-n1") {
		t.Error("a replaced null version's data survived Finish")
	}

	// A delete marker, then removing it.
	mv := meta.Version{Type: meta.TypeDeleteMarker, VersionID: "m1", ModTime: time.Now().UTC()}
	mc, err := d.CommitObject(bg, disk.CommitRequest{Bucket: "vb", Object: "k", Op: disk.OpMarker, Version: mv,
		Seq: 5, CheckGen: true, PrevGen: 4})
	if err != nil {
		t.Fatal(err)
	}
	mc.Finish(bg)
	f = fileOf(t, d, "k")
	if f.Latest().Type != meta.TypeDeleteMarker || f.Latest().VersionID != "m1" || f.Gen != 5 {
		t.Errorf("latest = %+v gen %d", f.Latest(), f.Gen)
	}
	rm := func(id string, seq uint64) (disk.Commit, error) {
		return d.CommitObject(bg, disk.CommitRequest{Bucket: "vb", Object: "k", Op: disk.OpRemove,
			VersionID: id, Seq: seq, CheckGen: true, PrevGen: seq - 1})
	}
	c, err = rm("m1", 6)
	if err != nil {
		t.Fatal(err)
	}
	c.Finish(bg)
	same(versionIDs(fileOf(t, d, "k")), []string{"", "idb", "ida"}, "after removing the marker")

	// Removal: data stays until Finish, and a rollback restores everything.
	c, err = rm("ida", 7)
	if err != nil {
		t.Fatal(err)
	}
	same(versionIDs(fileOf(t, d, "k")), []string{"", "idb"}, "after OpRemove")
	if !hasData(d, "k", ".nanoio-data-a") {
		t.Error("a removed version's data went before Finish")
	}
	if err := c.Rollback(bg); err != nil {
		t.Fatal(err)
	}
	f = fileOf(t, d, "k")
	same(versionIDs(f), []string{"", "idb", "ida"}, "after rolling the removal back")
	if f.Gen != 6 || !hasData(d, "k", ".nanoio-data-a") {
		t.Errorf("rollback left gen %d, data %v", f.Gen, hasData(d, "k", ".nanoio-data-a"))
	}
	c, err = rm("ida", 7)
	if err != nil {
		t.Fatal(err)
	}
	c.Finish(bg)
	if hasData(d, "k", ".nanoio-data-a") {
		t.Error("a removed version's data survived Finish")
	}
	// Removing a version this drive never had still advances its generation.
	c, err = rm("never-had", 8)
	if err != nil {
		t.Fatal(err)
	}
	c.Finish(bg)
	if f = fileOf(t, d, "k"); f.Gen != 8 || len(f.Versions) != 2 {
		t.Errorf("after removing an unknown version: gen %d, %d versions", f.Gen, len(f.Versions))
	}

	// Conditional commits.
	_, err = d.CommitObject(bg, disk.CommitRequest{Bucket: "vb", Object: "k", Op: disk.OpRemove, VersionID: "idb",
		Seq: 6, CheckGen: true, PrevGen: 5})
	if !errors.Is(err, disk.ErrConflict) {
		t.Errorf("removal based on an old generation = %v, want ErrConflict", err)
	}
	// A drive that is behind accepts a newer write.
	c, err = d.CommitObject(bg, disk.CommitRequest{Bucket: "vb", Object: "k", Op: disk.OpMarker,
		Version: meta.Version{Type: meta.TypeDeleteMarker, VersionID: "m2", ModTime: time.Now().UTC()},
		Seq:     20, CheckGen: true, PrevGen: 19})
	if err != nil {
		t.Fatalf("catching up: %v", err)
	}
	c.Finish(bg)
	if f = fileOf(t, d, "k"); f.Gen != 20 {
		t.Errorf("gen = %d", f.Gen)
	}

	// Removing the last version removes the key.
	for i, id := range []string{"m2", "idb", ""} {
		seq := uint64(21 + i)
		c, err := d.CommitObject(bg, disk.CommitRequest{Bucket: "vb", Object: "k", Op: disk.OpRemove,
			VersionID: id, Seq: seq, CheckGen: true, PrevGen: seq - 1})
		if err != nil {
			t.Fatal(err)
		}
		c.Finish(bg)
	}
	if _, err := d.ReadMeta(bg, "vb", "k"); !errors.Is(err, disk.ErrNotFound) {
		t.Errorf("xl.meta of a key with no versions: %v", err)
	}
	if keys, _ := d.ListKeys(bg, "vb", ""); len(keys) != 0 {
		t.Errorf("keys = %v", keys)
	}
	// Removing from a key that has nothing is a no-op.
	c, err = d.CommitObject(bg, disk.CommitRequest{Bucket: "vb", Object: "k", Op: disk.OpRemove,
		VersionID: "idb", Seq: 30})
	if err != nil {
		t.Fatalf("remove from an absent key: %v", err)
	}
	c.Finish(bg)
	c.Rollback(bg)
}

func testVersionReplace(t *testing.T, d disk.Disk) {
	d.MakeBucket(bg, "vb", time.Now())
	putVer(t, d, "r", "x1", ".nanoio-data-x1", 1).Finish(bg)
	putVer(t, d, "r", "x2", ".nanoio-data-x2", 2).Finish(bg)

	// Repair: the file becomes {x2 (kept), x3 (staged data)}; x1 is not in
	// it, so its data goes at Finish.
	writeStage(t, d, "repair", ".nanoio-data-x3/part.1", frame(30))
	cur := fileOf(t, d, "r")
	x3 := version(".nanoio-data-x3", 30, "etag-x3")
	x3.VersionID, x3.Seq = "x3", 3
	next := &meta.File{Format: meta.FormatVersion, Gen: 3, Versions: []meta.Version{x3, *cur.Find("x2")}}
	c, err := d.CommitObject(bg, disk.CommitRequest{Bucket: "vb", Object: "r", Op: disk.OpReplace,
		StageID: "repair", DataDirs: []string{".nanoio-data-x3"}, File: next})
	if err != nil {
		t.Fatal(err)
	}
	if !hasData(d, "r", ".nanoio-data-x1") {
		t.Error("data of a dropped version went before Finish")
	}
	c.Finish(bg)
	f := fileOf(t, d, "r")
	if strings.Join(versionIDs(f), ",") != "x3,x2" || f.Gen != 3 {
		t.Errorf("after replace: %v gen %d", versionIDs(f), f.Gen)
	}
	if hasData(d, "r", ".nanoio-data-x1") {
		t.Error("data of a dropped version survived Finish")
	}
	if !hasData(d, "r", ".nanoio-data-x3") || !hasData(d, "r", ".nanoio-data-x2") {
		t.Error("data of a kept version is missing")
	}
	d.RemoveStage(bg, "repair")

	// A replace can be rolled back whole.
	writeStage(t, d, "repair2", ".nanoio-data-y1/part.1", frame(30))
	y1 := version(".nanoio-data-y1", 30, "etag-y1")
	y1.VersionID, y1.Seq = "y1", 9
	c, err = d.CommitObject(bg, disk.CommitRequest{Bucket: "vb", Object: "r", Op: disk.OpReplace,
		StageID: "repair2", DataDirs: []string{".nanoio-data-y1"},
		File: &meta.File{Format: meta.FormatVersion, Gen: 9, Versions: []meta.Version{y1}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Rollback(bg); err != nil {
		t.Fatal(err)
	}
	f = fileOf(t, d, "r")
	if strings.Join(versionIDs(f), ",") != "x3,x2" || f.Gen != 3 {
		t.Errorf("after rolling a replace back: %v gen %d", versionIDs(f), f.Gen)
	}
	if hasData(d, "r", ".nanoio-data-y1") || !hasData(d, "r", ".nanoio-data-x2") {
		t.Error("rollback left the wrong data directories")
	}
	d.RemoveStage(bg, "repair2")
}

func testBucketSettings(t *testing.T, d disk.Disk) {
	if _, err := d.ReadBucketSettings(bg, "missing"); !errors.Is(err, disk.ErrNotFound) {
		t.Errorf("ReadBucketSettings(missing) = %v, want ErrNotFound", err)
	}
	if err := d.WriteBucketObjectLock(bg, "missing", `{"enabled":true}`, 1); !errors.Is(err, disk.ErrNotFound) {
		t.Errorf("WriteBucketObjectLock(missing) = %v, want ErrNotFound", err)
	}
	if _, err := d.MakeBucket(bg, "bs", time.Now()); err != nil {
		t.Fatal(err)
	}
	if got, err := d.ReadBucketSettings(bg, "bs"); err != nil || got != (disk.BucketSettings{}) {
		t.Fatalf("fresh settings = %+v, %v", got, err)
	}
	if err := d.WriteBucketVersioning(bg, "bs", "Enabled", 1); err != nil {
		t.Fatal(err)
	}
	doc := `{"enabled":true,"default":{"mode":"GOVERNANCE","days":3}}`
	if err := d.WriteBucketObjectLock(bg, "bs", doc, 4); err != nil {
		t.Fatal(err)
	}
	want := disk.BucketSettings{Versioning: "Enabled", VersioningSeq: 1, ObjectLock: doc, ObjectLockSeq: 4}
	if got, err := d.ReadBucketSettings(bg, "bs"); err != nil || got != want {
		t.Fatalf("settings = %+v, %v; want %+v", got, err, want)
	}
	// Each write keeps the other document.
	if err := d.WriteBucketVersioning(bg, "bs", "Suspended", 2); err != nil {
		t.Fatal(err)
	}
	if got, _ := d.ReadBucketSettings(bg, "bs"); got.ObjectLock != doc || got.ObjectLockSeq != 4 || got.Versioning != "Suspended" {
		t.Errorf("a versioning write disturbed the lock document: %+v", got)
	}
	if err := d.WriteBucketObjectLock(bg, "bs", doc, 5); err != nil {
		t.Fatal(err)
	}
	if got, _ := d.ReadBucketSettings(bg, "bs"); got.Versioning != "Suspended" || got.VersioningSeq != 2 || got.ObjectLockSeq != 5 {
		t.Errorf("a lock write disturbed the versioning state: %+v", got)
	}
	// The creation time survives both.
	if _, created, _ := d.StatBucket(bg, "bs"); created.IsZero() {
		t.Error("creation time lost")
	}
}

// testObjectLock pins that a drive refuses, whatever the caller asks, to
// remove or replace a version object lock protects: this is the second line
// of defence behind the coordinator's own check.
func testObjectLock(t *testing.T, d disk.Disk) {
	if _, err := d.MakeBucket(bg, "vb", time.Now()); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	hour := now.Add(time.Hour)
	putLocked := func(obj, id, dataDir string, seq uint64, l *meta.Lock) {
		t.Helper()
		stage := "lk-" + dataDir
		writeStage(t, d, stage, dataDir+"/part.1", frame(30))
		v := version(dataDir, 30, "etag-"+dataDir)
		v.VersionID, v.Lock = id, l
		c, err := d.CommitObject(bg, disk.CommitRequest{Bucket: "vb", Object: obj, Op: disk.OpPut,
			StageID: stage, DataDir: dataDir, Version: v, Seq: seq, CheckGen: true, PrevGen: seq - 1})
		if err != nil {
			t.Fatalf("OpPut %s@%q: %v", obj, id, err)
		}
		c.Finish(bg)
		t.Cleanup(func() { d.RemoveStage(bg, stage) })
	}
	remove := func(obj, id string, seq uint64, g meta.Guard) error {
		_, err := d.CommitObject(bg, disk.CommitRequest{Bucket: "vb", Object: obj, Op: disk.OpRemove,
			VersionID: id, Seq: seq, CheckGen: true, PrevGen: seq - 1, Guard: g})
		return err
	}
	setLock := func(obj, id string, seq uint64, l *meta.Lock, g meta.Guard) error {
		t.Helper()
		c, err := d.CommitObject(bg, disk.CommitRequest{Bucket: "vb", Object: obj, Op: disk.OpSetLock,
			VersionID: id, Lock: l, Seq: seq, CheckGen: true, PrevGen: seq - 1, Guard: g})
		if err == nil {
			c.Finish(bg)
		}
		return err
	}
	locked := func(err error) bool {
		return errors.Is(err, disk.ErrLocked) && errors.Is(err, storage.ErrObjectLocked)
	}

	// COMPLIANCE: removal refused, bypass or not, and nothing changes.
	putLocked("c", "ida", ".nanoio-data-c1", 1, &meta.Lock{Mode: meta.ModeCompliance, RetainUntil: hour})
	for _, g := range []meta.Guard{{}, {Now: now}, {Now: now, BypassGovernance: true}} {
		if err := remove("c", "ida", 2, g); !locked(err) {
			t.Fatalf("OpRemove of a COMPLIANCE version with guard %+v = %v, want ErrLocked", g, err)
		}
	}
	if f := fileOf(t, d, "c"); f.Gen != 1 || len(f.Versions) != 1 || !hasData(d, "c", ".nanoio-data-c1") {
		t.Errorf("a refused removal changed the drive: gen %d, %d versions", f.Gen, len(f.Versions))
	}
	// Whole-key removal is refused as well.
	if err := d.DeleteObject(bg, "vb", "c"); !locked(err) {
		t.Errorf("DeleteObject of a key with a protected version = %v, want ErrLocked", err)
	}
	if !hasData(d, "c", ".nanoio-data-c1") {
		t.Error("DeleteObject removed the data of a protected version")
	}
	// Shortening, removing and downgrading the retention is refused;
	// extending is not.
	for name, l := range map[string]*meta.Lock{
		"shorten":   {Mode: meta.ModeCompliance, RetainUntil: now.Add(time.Minute)},
		"remove":    nil,
		"downgrade": {Mode: meta.ModeGovernance, RetainUntil: hour.Add(time.Hour)},
	} {
		if err := setLock("c", "ida", 2, l, meta.Guard{Now: now, BypassGovernance: true}); !locked(err) {
			t.Errorf("OpSetLock %s = %v, want ErrLocked", name, err)
		}
	}
	if err := setLock("c", "ida", 2, &meta.Lock{Mode: meta.ModeCompliance, RetainUntil: hour.Add(time.Hour), LegalHold: true},
		meta.Guard{Now: now}); err != nil {
		t.Fatalf("extending: %v", err)
	}
	if f := fileOf(t, d, "c"); f.Gen != 2 || f.Versions[0].Lock == nil || !f.Versions[0].Lock.LegalHold ||
		!f.Versions[0].Lock.RetainUntil.Equal(hour.Add(time.Hour)) {
		t.Errorf("lock after extending: %+v (gen %d)", f.Versions[0].Lock, f.Gen)
	}
	// Expired by the caller's clock, the hold is what still protects it.
	late := meta.Guard{Now: hour.Add(3 * time.Hour)}
	if err := remove("c", "ida", 3, late); !locked(err) {
		t.Errorf("removal under a legal hold = %v, want ErrLocked", err)
	}
	if err := setLock("c", "ida", 3, &meta.Lock{Mode: meta.ModeCompliance, RetainUntil: hour.Add(time.Hour)}, late); err != nil {
		t.Fatalf("lifting the hold: %v", err)
	}
	if err := remove("c", "ida", 4, late); err != nil {
		t.Errorf("removal after expiry and hold lifted: %v", err)
	}

	// GOVERNANCE: bypass is the only way.
	putLocked("g", "idg", ".nanoio-data-g1", 1, &meta.Lock{Mode: meta.ModeGovernance, RetainUntil: hour})
	if err := remove("g", "idg", 2, meta.Guard{Now: now}); !locked(err) {
		t.Errorf("OpRemove of a GOVERNANCE version = %v, want ErrLocked", err)
	}
	if err := remove("g", "idg", 2, meta.Guard{Now: now, BypassGovernance: true}); err != nil {
		t.Errorf("OpRemove with bypass: %v", err)
	}

	// The null version of a locked object is not replaced by a write or a
	// delete marker.
	putLocked("n", "", ".nanoio-data-n1", 1, &meta.Lock{Mode: meta.ModeCompliance, RetainUntil: hour})
	stage := "lk-n2"
	writeStage(t, d, stage, ".nanoio-data-n2/part.1", frame(30))
	t.Cleanup(func() { d.RemoveStage(bg, stage) })
	v := version(".nanoio-data-n2", 30, "etag-n2")
	_, err := d.CommitObject(bg, disk.CommitRequest{Bucket: "vb", Object: "n", Op: disk.OpPut, StageID: stage,
		DataDir: ".nanoio-data-n2", Version: v, Seq: 2, CheckGen: true, PrevGen: 1, Guard: meta.Guard{Now: now, BypassGovernance: true}})
	if !locked(err) {
		t.Errorf("OpPut over a locked null version = %v, want ErrLocked", err)
	}
	_, err = d.CommitObject(bg, disk.CommitRequest{Bucket: "vb", Object: "n", Op: disk.OpMarker,
		Version: meta.Version{Type: meta.TypeDeleteMarker, ModTime: now}, Seq: 2, CheckGen: true, PrevGen: 1,
		Guard: meta.Guard{Now: now}})
	if !locked(err) {
		t.Errorf("null OpMarker over a locked null version = %v, want ErrLocked", err)
	}
	// A marker with a new ID stacks on top and is fine.
	c, err := d.CommitObject(bg, disk.CommitRequest{Bucket: "vb", Object: "n", Op: disk.OpMarker,
		Version: meta.Version{Type: meta.TypeDeleteMarker, VersionID: "m1", ModTime: now}, Seq: 2, CheckGen: true, PrevGen: 1,
		Guard: meta.Guard{Now: now}})
	if err != nil {
		t.Fatalf("stacking a marker: %v", err)
	}
	c.Finish(bg)
	// Markers carry no lock and cannot be given one.
	if err := setLock("n", "m1", 3, &meta.Lock{LegalHold: true}, meta.Guard{Now: now}); err == nil {
		t.Error("OpSetLock on a delete marker succeeded")
	}
	if err := setLock("n", "no-such", 3, &meta.Lock{LegalHold: true}, meta.Guard{Now: now}); !errors.Is(err, disk.ErrNotFound) {
		t.Errorf("OpSetLock of a missing version = %v, want ErrNotFound", err)
	}
	if err := setLock("no-such-key", "", 1, &meta.Lock{LegalHold: true}, meta.Guard{Now: now}); !errors.Is(err, disk.ErrNotFound) {
		t.Errorf("OpSetLock of a missing key = %v, want ErrNotFound", err)
	}
}
