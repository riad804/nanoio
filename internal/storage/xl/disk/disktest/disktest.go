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
	return d.CommitObject(bg, disk.CommitRequest{Bucket: "b", Object: obj, StageID: stage, DataDir: dataDir,
		Version: v, CheckGen: check, PrevGen: prev})
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
