package fs

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"nanoio/internal/storage"
)

func md5hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// small keeps multipart tests fast: every non-final part must reach 16 bytes.
func small(o *Options) { o.MinPartSize = 16 }

func partBody(n int) string { return fmt.Sprintf("part-%02d:%s", n, strings.Repeat("#", 20)) }

// upload creates an upload for bucket/key with the given part numbers
// (bodies from partBody) and returns its ID and the part infos.
func upload(t *testing.T, f *FS, bucket, key string, numbers ...int) (string, []storage.PartInfo) {
	t.Helper()
	id, err := f.NewMultipartUpload(bg, bucket, key, storage.PutOptions{ContentType: "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	var infos []storage.PartInfo
	for _, n := range numbers {
		b := partBody(n)
		p, err := f.PutObjectPart(bg, bucket, key, id, n, strings.NewReader(b), int64(len(b)), storage.PartOptions{})
		if err != nil {
			t.Fatal(err)
		}
		infos = append(infos, p)
	}
	return id, infos
}

func asCompleteParts(ps []storage.PartInfo) []storage.CompletePart {
	out := make([]storage.CompletePart, len(ps))
	for i, p := range ps {
		out[i] = storage.CompletePart{Number: p.Number, ETag: p.ETag}
	}
	return out
}

func uploadDirOf(t *testing.T, f *FS, bucket, id string) string {
	t.Helper()
	d, err := f.uploadDir(bucket, id)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func backdate(t *testing.T, path string, age time.Duration) {
	t.Helper()
	old := time.Now().Add(-age)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
}

func TestMultiFileReader(t *testing.T) {
	dir := t.TempDir()
	contents := []string{"abc", "", "defgh", "ij", "klmnopq"} // includes an empty part
	var paths []string
	var sizes []int64
	for i, c := range contents {
		p := filepath.Join(dir, fmt.Sprintf("p%d", i))
		os.WriteFile(p, []byte(c), 0o644)
		paths = append(paths, p)
		sizes = append(sizes, int64(len(c)))
	}
	whole := strings.Join(contents, "")

	t.Run("ReadAt every offset and length", func(t *testing.T) {
		m := newMultiFile(paths, sizes)
		defer m.Close()
		for off := 0; off <= len(whole); off++ {
			for n := 0; n+off <= len(whole); n++ {
				buf := make([]byte, n)
				got, err := m.ReadAt(buf, int64(off))
				if got != n || (err != nil && err != io.EOF) || string(buf) != whole[off:off+n] {
					t.Fatalf("ReadAt(len=%d, off=%d) = %d %v %q, want %q", n, off, got, err, buf, whole[off:off+n])
				}
			}
		}
	})
	t.Run("ReadAt past the end", func(t *testing.T) {
		m := newMultiFile(paths, sizes)
		defer m.Close()
		buf := make([]byte, 10)
		n, err := m.ReadAt(buf, int64(len(whole))-3)
		if n != 3 || err != io.EOF || string(buf[:n]) != whole[len(whole)-3:] {
			t.Errorf("= %d %v %q", n, err, buf[:n])
		}
		if n, err := m.ReadAt(buf, int64(len(whole))+5); n != 0 || err != io.EOF {
			t.Errorf("beyond end = %d %v", n, err)
		}
		if _, err := m.ReadAt(buf, -1); err == nil {
			t.Error("negative offset accepted")
		}
	})
	t.Run("sequential Read in odd chunks", func(t *testing.T) {
		for _, chunk := range []int{1, 2, 3, 7, 100} {
			m := newMultiFile(paths, sizes)
			var out []byte
			buf := make([]byte, chunk)
			for {
				n, err := m.Read(buf)
				out = append(out, buf[:n]...)
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			m.Close()
			if string(out) != whole {
				t.Errorf("chunk %d: %q", chunk, out)
			}
		}
	})
	t.Run("Seek", func(t *testing.T) {
		m := newMultiFile(paths, sizes)
		defer m.Close()
		tests := []struct {
			off    int64
			whence int
			want   string
		}{
			{4, io.SeekStart, whole[4:8]},
			{-5, io.SeekEnd, whole[len(whole)-5 : len(whole)-1]},
			{2, io.SeekCurrent, ""}, // computed below
		}
		for _, tt := range tests[:2] {
			if _, err := m.Seek(tt.off, tt.whence); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 4)
			io.ReadFull(m, buf)
			if string(buf) != tt.want {
				t.Errorf("seek %d/%d read %q, want %q", tt.off, tt.whence, buf, tt.want)
			}
		}
		pos, _ := m.Seek(0, io.SeekStart)
		pos, _ = m.Seek(3, io.SeekCurrent)
		if pos != 3 {
			t.Errorf("SeekCurrent pos = %d", pos)
		}
		if _, err := m.Seek(-1, io.SeekStart); err == nil {
			t.Error("negative seek accepted")
		}
		if _, err := m.Seek(0, 99); err == nil {
			t.Error("bad whence accepted")
		}
		if pos, _ := m.Seek(0, io.SeekEnd); pos != int64(len(whole)) {
			t.Errorf("SeekEnd = %d", pos)
		}
		if n, err := m.Read(make([]byte, 1)); n != 0 || err != io.EOF {
			t.Errorf("read at end = %d %v", n, err)
		}
	})
	t.Run("a file shrunk after verification is an error, not silent corruption", func(t *testing.T) {
		m := newMultiFile(paths, sizes)
		defer m.Close()
		os.Truncate(paths[2], 1)
		buf := make([]byte, len(whole))
		_, err := m.ReadAt(buf, 0)
		if err == nil || err == io.EOF {
			t.Errorf("error = %v, want an unexpected-EOF style error", err)
		}
		os.WriteFile(paths[2], []byte(contents[2]), 0o644)
	})
	t.Run("many parts hold one descriptor", func(t *testing.T) {
		var ps []string
		var ss []int64
		for i := 0; i < 600; i++ {
			p := filepath.Join(dir, fmt.Sprintf("m%d", i))
			os.WriteFile(p, []byte{byte(i)}, 0o644)
			ps = append(ps, p)
			ss = append(ss, 1)
		}
		m := newMultiFile(ps, ss)
		defer m.Close()
		all, err := io.ReadAll(m)
		if err != nil || len(all) != 600 || all[599] != byte(599%256) {
			t.Fatalf("%d bytes, %v", len(all), err)
		}
	})
	t.Run("Close is idempotent", func(t *testing.T) {
		m := newMultiFile(paths, sizes)
		m.ReadAt(make([]byte, 1), 0)
		if err := m.Close(); err != nil {
			t.Fatal(err)
		}
		if err := m.Close(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestPartFaultInjection(t *testing.T) {
	crash := errors.New("simulated crash")
	tests := []struct {
		point       string
		newVisible  bool
		wantOrphans bool // a garbage data file remains for the collector
	}{
		{FaultPartStaged, false, false},
		{FaultPartData, false, true},
		{FaultPartMeta, true, true}, // committed; the replaced data file is leftover
	}
	for _, tt := range tests {
		for _, replace := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/replace=%v", tt.point, replace), func(t *testing.T) {
				var armed atomic.Bool
				f := newFS(t, t.TempDir(), small, func(o *Options) {
					o.Fault = func(p string) error {
						if armed.Load() && p == tt.point {
							return crash
						}
						return nil
					}
				})
				mkbucket(t, f, "pfi")
				id, infos := upload(t, f, "pfi", "k", 1, 2)
				oldETag := infos[0].ETag
				target := 3
				if replace {
					target = 1
				}

				armed.Store(true)
				_, err := f.PutObjectPart(bg, "pfi", "k", id, target, strings.NewReader("replacement-bytes!"), 18, storage.PartOptions{})
				armed.Store(false)
				if !errors.Is(err, crash) {
					t.Fatalf("error = %v, want the injected crash", err)
				}

				// Invariant: a part is either wholly old or wholly new.
				l, err := f.ListObjectParts(bg, "pfi", "k", id, storage.ListPartsOptions{})
				if err != nil {
					t.Fatal(err)
				}
				byN := map[int]storage.PartInfo{}
				for _, p := range l.Parts {
					byN[p.Number] = p
				}
				switch {
				case tt.newVisible:
					if p := byN[target]; p.ETag != md5hex("replacement-bytes!") || p.Size != 18 {
						t.Errorf("committed part not visible: %+v", p)
					}
				case replace:
					if p := byN[1]; p.ETag != oldETag {
						t.Errorf("part 1 changed by an uncommitted write: %+v", p)
					}
				default:
					if _, ok := byN[3]; ok {
						t.Error("an uncommitted part is visible")
					}
				}

				// The collector reclaims whatever the crash left in the upload.
				stats, err := f.GC(bg)
				if err != nil {
					t.Fatal(err)
				}
				// A committed fresh part number replaced nothing, so the crash
				// left no stale file; every other case leaves exactly one.
				wantOrphan := tt.wantOrphans && !(tt.point == FaultPartMeta && !replace)
				if wantOrphan && stats.OrphanPartFiles == 0 {
					t.Errorf("GC removed no orphan part file: %+v", stats)
				}
				// The upload still completes into a correct object.
				l, _ = f.ListObjectParts(bg, "pfi", "k", id, storage.ListPartsOptions{})
				var c []storage.CompletePart
				want := ""
				for _, p := range l.Parts {
					c = append(c, storage.CompletePart{Number: p.Number, ETag: p.ETag})
				}
				// Parts are 29 bytes (>= 16) except a short final one.
				if _, err := f.CompleteMultipartUpload(bg, "pfi", "k", id, c, storage.PutOptions{}); err != nil {
					t.Fatalf("complete after crash: %v", err)
				}
				for _, p := range l.Parts {
					switch p.ETag {
					case md5hex("replacement-bytes!"):
						want += "replacement-bytes!"
					default:
						want += partBody(p.Number)
					}
				}
				if got, err := read(t, f, "pfi", "k"); err != nil || got != want {
					t.Errorf("object = %q, %v; want %q", got, err, want)
				}
			})
		}
	}
}

func TestCompleteFaultInjection(t *testing.T) {
	crash := errors.New("simulated crash")
	points := []struct {
		point     string
		committed bool
	}{
		{FaultStaged, false},
		{FaultMetaStaged, false},
		{FaultDataRenamed, false},
		{FaultMetaRenamed, true},
	}
	for _, p := range points {
		for _, existing := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/existing=%v", p.point, existing), func(t *testing.T) {
				root := t.TempDir()
				var armed atomic.Bool
				f := newFS(t, root, small, func(o *Options) {
					o.Fault = func(pt string) error {
						if armed.Load() && pt == p.point {
							return crash
						}
						return nil
					}
				})
				mkbucket(t, f, "cfi")
				if existing {
					put(t, f, "cfi", "k", "old object")
				}
				id, infos := upload(t, f, "cfi", "k", 1, 2)
				want := partBody(1) + partBody(2)

				armed.Store(true)
				_, err := f.CompleteMultipartUpload(bg, "cfi", "k", id, asCompleteParts(infos), storage.PutOptions{})
				armed.Store(false)
				if !errors.Is(err, crash) {
					t.Fatalf("error = %v, want the injected crash", err)
				}

				got, err := read(t, f, "cfi", "k")
				switch {
				case p.committed:
					if err != nil || got != want {
						t.Errorf("after the commit point: %q, %v", got, err)
					}
				case existing:
					if err != nil || got != "old object" {
						t.Errorf("before the commit point: %q, %v; want the old object", got, err)
					}
				default:
					if !errors.Is(err, storage.ErrObjectNotFound) {
						t.Errorf("before the commit point on a fresh key: %q, %v", got, err)
					}
				}
				if !p.committed {
					// No parts were lost: the upload is whole and retryable.
					l, err := f.ListObjectParts(bg, "cfi", "k", id, storage.ListPartsOptions{})
					if err != nil || len(l.Parts) != 2 {
						t.Fatalf("upload damaged by a crash before commit: %+v, %v", l, err)
					}
				}

				// Retrying succeeds and yields exactly the right object.
				if _, err := f.CompleteMultipartUpload(bg, "cfi", "k", id, asCompleteParts(infos), storage.PutOptions{}); err != nil {
					t.Fatalf("retry: %v", err)
				}
				if got, err := read(t, f, "cfi", "k"); err != nil || got != want {
					t.Errorf("after retry: %q, %v", got, err)
				}
				if _, err := f.ListObjectParts(bg, "cfi", "k", id, storage.ListPartsOptions{}); !errors.Is(err, storage.ErrNoSuchUpload) {
					t.Errorf("upload still present after a successful completion: %v", err)
				}

				// A restart sweeps the staging debris and GC finds nothing live to harm.
				f.Close()
				f2 := newFS(t, root, small, func(o *Options) { o.TmpMaxAge = -1 })
				if _, err := f2.GC(bg); err != nil {
					t.Fatal(err)
				}
				if got, err := read(t, f2, "cfi", "k"); err != nil || got != want {
					t.Errorf("after restart and GC: %q, %v", got, err)
				}
			})
		}
	}
}

func TestMultipartObjectCorruptionIsDetected(t *testing.T) {
	tests := []struct {
		name   string
		damage func(t *testing.T, dataDir string)
	}{
		{"part truncated", func(t *testing.T, d string) { os.Truncate(filepath.Join(d, "part.2"), 3) }},
		{"part missing", func(t *testing.T, d string) { os.Remove(filepath.Join(d, "part.3")) }},
		{"part grown", func(t *testing.T, d string) {
			fh, _ := os.OpenFile(filepath.Join(d, "part.1"), os.O_APPEND|os.O_WRONLY, 0)
			fh.WriteString("extra")
			fh.Close()
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			f := newFS(t, root, small)
			mkbucket(t, f, "cor")
			id, infos := upload(t, f, "cor", "k", 1, 2, 3)
			if _, err := f.CompleteMultipartUpload(bg, "cor", "k", id, asCompleteParts(infos), storage.PutOptions{}); err != nil {
				t.Fatal(err)
			}
			keyDir := filepath.Join(root, "cor", "k")
			entries, _ := os.ReadDir(keyDir)
			var dataDir string
			for _, e := range entries {
				if e.IsDir() {
					dataDir = filepath.Join(keyDir, e.Name())
				}
			}
			if _, err := os.Stat(filepath.Join(dataDir, "part.3")); err != nil {
				t.Fatalf("expected part.N files in %s: %v", dataDir, err)
			}
			tt.damage(t, dataDir)
			_, err := read(t, f, "cor", "k")
			wantIs(t, "GetObject", err, storage.ErrCorrupted)
			if _, err := f.StatObject(bg, "cor", "k", storage.GetOptions{}); err != nil {
				t.Errorf("Stat should still work from intact metadata: %v", err)
			}
		})
	}
}

func TestGC(t *testing.T) {
	newStore := func(t *testing.T, mut ...func(*Options)) (*FS, string) {
		root := t.TempDir()
		opts := append([]func(*Options){small, func(o *Options) {
			o.UploadExpiry = time.Hour
			o.GCInterval = -1 // collection only when the test asks
		}}, mut...)
		return newFS(t, root, opts...), root
	}

	t.Run("a healthy store is left alone", func(t *testing.T) {
		f, _ := newStore(t)
		mkbucket(t, f, "gcb")
		put(t, f, "gcb", "plain", "plain object")
		put(t, f, "gcb", "a/b/c", "nested")
		id, infos := upload(t, f, "gcb", "assembled", 1, 2)
		if _, err := f.CompleteMultipartUpload(bg, "gcb", "assembled", id, asCompleteParts(infos), storage.PutOptions{}); err != nil {
			t.Fatal(err)
		}
		liveID, _ := upload(t, f, "gcb", "inflight", 1)
		stats, err := f.GC(bg)
		if err != nil || stats.Total() != 0 {
			t.Fatalf("stats = %+v, %v", stats, err)
		}
		if got, _ := read(t, f, "gcb", "assembled"); got != partBody(1)+partBody(2) {
			t.Error("multipart object damaged")
		}
		if l, err := f.ListObjectParts(bg, "gcb", "inflight", liveID, storage.ListPartsOptions{}); err != nil || len(l.Parts) != 1 {
			t.Errorf("live upload damaged: %+v, %v", l, err)
		}
	})

	t.Run("expired uploads are aborted, fresh ones kept", func(t *testing.T) {
		f, _ := newStore(t)
		mkbucket(t, f, "gcb")
		stale, _ := upload(t, f, "gcb", "stale", 1)
		fresh, _ := upload(t, f, "gcb", "fresh", 1)
		backdate(t, uploadDirOf(t, f, "gcb", stale), 2*time.Hour)
		stats, err := f.GC(bg)
		if err != nil || stats.ExpiredUploads != 1 {
			t.Fatalf("stats = %+v, %v", stats, err)
		}
		if _, err := f.ListObjectParts(bg, "gcb", "stale", stale, storage.ListPartsOptions{}); !errors.Is(err, storage.ErrNoSuchUpload) {
			t.Errorf("stale upload survived: %v", err)
		}
		if _, err := f.ListObjectParts(bg, "gcb", "fresh", fresh, storage.ListPartsOptions{}); err != nil {
			t.Errorf("fresh upload removed: %v", err)
		}
		if ups, _ := f.ListMultipartUploads(bg, "gcb", storage.ListUploadsOptions{}); len(ups.Uploads) != 1 {
			t.Errorf("uploads = %+v", ups.Uploads)
		}
	})

	t.Run("activity keeps an old upload alive", func(t *testing.T) {
		f, _ := newStore(t)
		mkbucket(t, f, "gcb")
		id, _ := upload(t, f, "gcb", "busy", 1)
		backdate(t, uploadDirOf(t, f, "gcb", id), 2*time.Hour)
		b := partBody(2)
		if _, err := f.PutObjectPart(bg, "gcb", "busy", id, 2, strings.NewReader(b), int64(len(b)), storage.PartOptions{}); err != nil {
			t.Fatal(err)
		}
		if stats, _ := f.GC(bg); stats.ExpiredUploads != 0 {
			t.Errorf("an upload that just received a part was expired: %+v", stats)
		}
	})

	t.Run("uploads of a vanished bucket are removed at once", func(t *testing.T) {
		f, root := newStore(t)
		mkbucket(t, f, "gone")
		upload(t, f, "gone", "k", 1)
		os.RemoveAll(filepath.Join(root, "gone")) // crash mid bucket delete
		stats, err := f.GC(bg)
		if err != nil || stats.ExpiredUploads != 1 {
			t.Errorf("stats = %+v, %v", stats, err)
		}
		if entries, _ := os.ReadDir(filepath.Join(root, ".nanoio.sys", "multipart")); len(entries) != 0 {
			t.Errorf("multipart dir not cleaned: %v", entries)
		}
	})

	t.Run("orphan part files go, referenced ones stay", func(t *testing.T) {
		f, _ := newStore(t)
		mkbucket(t, f, "gcb")
		id, infos := upload(t, f, "gcb", "k", 1, 2)
		dir := uploadDirOf(t, f, "gcb", id)
		os.WriteFile(filepath.Join(dir, "1.deadbeefdeadbeef.data"), []byte("left by a crash"), 0o644)
		os.WriteFile(filepath.Join(dir, "7.cafecafecafecafe.data"), []byte("another"), 0o644)
		stats, err := f.GC(bg)
		if err != nil || stats.OrphanPartFiles != 2 {
			t.Fatalf("stats = %+v, %v", stats, err)
		}
		if _, err := f.CompleteMultipartUpload(bg, "gcb", "k", id, asCompleteParts(infos), storage.PutOptions{}); err != nil {
			t.Errorf("upload no longer completes: %v", err)
		}
		if got, _ := read(t, f, "gcb", "k"); got != partBody(1)+partBody(2) {
			t.Error("content differs")
		}
	})

	t.Run("orphan data dirs go, the live one stays", func(t *testing.T) {
		f, root := newStore(t)
		mkbucket(t, f, "gcb")
		put(t, f, "gcb", "obj", "live data")
		keyDir := filepath.Join(root, "gcb", "obj")
		orphan := filepath.Join(keyDir, ".nanoio-data-orphaned")
		os.MkdirAll(orphan, 0o755)
		os.WriteFile(filepath.Join(orphan, "part.1"), []byte("stale"), 0o644)
		// A fresh key whose commit never happened: data dir, no xl.meta.
		fresh := filepath.Join(root, "gcb", "x", "y")
		os.MkdirAll(filepath.Join(fresh, ".nanoio-data-never-committed"), 0o755)

		stats, err := f.GC(bg)
		if err != nil || stats.OrphanDataDirs != 2 {
			t.Fatalf("stats = %+v, %v", stats, err)
		}
		if _, err := os.Stat(orphan); !errors.Is(err, os.ErrNotExist) {
			t.Error("orphan data dir survived")
		}
		if got, err := read(t, f, "gcb", "obj"); err != nil || got != "live data" {
			t.Errorf("live object: %q, %v", got, err)
		}
		if _, err := os.Stat(filepath.Join(root, "gcb", "x")); !errors.Is(err, os.ErrNotExist) {
			t.Error("the empty key directories left behind were not pruned")
		}
		if _, err := os.Stat(filepath.Join(root, "gcb")); err != nil {
			t.Errorf("bucket directory removed: %v", err)
		}
	})

	t.Run("nothing is deleted next to unreadable metadata", func(t *testing.T) {
		f, root := newStore(t)
		mkbucket(t, f, "gcb")
		put(t, f, "gcb", "damaged", "precious")
		keyDir := filepath.Join(root, "gcb", "damaged")
		meta := filepath.Join(keyDir, "xl.meta")
		b, _ := os.ReadFile(meta)
		os.WriteFile(meta, b[:len(b)/2], 0o644) // corrupt it
		extra := filepath.Join(keyDir, ".nanoio-data-looks-orphaned")
		os.MkdirAll(extra, 0o755)
		stats, err := f.GC(bg)
		if err != nil || stats.OrphanDataDirs != 0 {
			t.Fatalf("stats = %+v, %v", stats, err)
		}
		entries, _ := os.ReadDir(keyDir)
		if len(entries) != 3 { // xl.meta, the live data dir, the extra dir
			t.Errorf("entries = %v; the collector touched a directory with corrupt metadata", entries)
		}
	})

	t.Run("staging: old debris removed, held stages kept", func(t *testing.T) {
		f, root := newStore(t)
		mkbucket(t, f, "gcb")
		tmp := filepath.Join(root, ".nanoio.sys", "tmp")
		os.MkdirAll(filepath.Join(tmp, "ancient", "x"), 0o755)
		backdate(t, filepath.Join(tmp, "ancient"), 48*time.Hour)
		os.MkdirAll(filepath.Join(tmp, "recent"), 0o755)

		// A long upload: its staging dir is old but its writer is alive.
		pr, pw := io.Pipe()
		done := make(chan error, 1)
		go func() {
			_, err := f.PutObject(bg, "gcb", "slow", pr, 10, storage.PutOptions{})
			done <- err
		}()
		pw.Write([]byte("hello"))
		var held string
		deadline := time.Now().Add(3 * time.Second)
		for held == "" && time.Now().Before(deadline) {
			entries, _ := os.ReadDir(tmp)
			for _, e := range entries {
				if e.Name() != "ancient" && e.Name() != "recent" {
					held = filepath.Join(tmp, e.Name())
				}
			}
			time.Sleep(5 * time.Millisecond)
		}
		if held == "" {
			t.Fatal("never saw the in-flight staging dir")
		}
		backdate(t, held, 72*time.Hour)

		stats, err := f.GC(bg)
		if err != nil {
			t.Fatal(err)
		}
		if stats.StagingEntries != 1 {
			t.Errorf("StagingEntries = %d, want only the ancient one", stats.StagingEntries)
		}
		if _, err := os.Stat(filepath.Join(tmp, "ancient")); !errors.Is(err, os.ErrNotExist) {
			t.Error("ancient staging dir survived")
		}
		if _, err := os.Stat(filepath.Join(tmp, "recent")); err != nil {
			t.Error("recent staging dir removed")
		}
		if _, err := os.Stat(held); err != nil {
			t.Fatal("the staging dir of a live upload was removed")
		}
		pw.Write([]byte("world"))
		pw.Close()
		if err := <-done; err != nil {
			t.Fatalf("the long upload failed: %v", err)
		}
		if got, _ := read(t, f, "gcb", "slow"); got != "helloworld" {
			t.Errorf("object = %q", got)
		}
	})

	t.Run("collection while writers run never harms live data", func(t *testing.T) {
		f, _ := newStore(t, func(o *Options) { o.UploadExpiry = time.Hour })
		mkbucket(t, f, "gcb")
		stop := make(chan struct{})
		var gcWG sync.WaitGroup
		gcWG.Add(1)
		go func() {
			defer gcWG.Done()
			for {
				select {
				case <-stop:
					return
				default:
					if _, err := f.GC(bg); err != nil {
						t.Errorf("GC: %v", err)
						return
					}
				}
			}
		}()
		var wg sync.WaitGroup
		errs := make(chan error, 64)
		for w := 0; w < 6; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < 10; i++ {
					key := fmt.Sprintf("w%d/obj%d", w, i)
					id, infos := upload(t, f, "gcb", key, 1, 2, 3)
					if _, err := f.CompleteMultipartUpload(bg, "gcb", key, id, asCompleteParts(infos), storage.PutOptions{}); err != nil {
						errs <- fmt.Errorf("%s: %w", key, err)
						return
					}
					want := partBody(1) + partBody(2) + partBody(3)
					if got, err := read(t, f, "gcb", key); err != nil || got != want {
						errs <- fmt.Errorf("%s read back %q, %v", key, got, err)
						return
					}
					put(t, f, "gcb", key+".plain", "plain")
					if i%3 == 0 {
						f.DeleteObject(bg, "gcb", key, storage.DeleteOptions{})
					}
				}
			}()
		}
		wg.Wait()
		close(stop)
		gcWG.Wait()
		close(errs)
		for err := range errs {
			t.Error(err)
		}
	})

	t.Run("GC after Close is refused", func(t *testing.T) {
		f, _ := newStore(t)
		f.Close()
		if _, err := f.GC(bg); !errors.Is(err, storage.ErrBackendUnavailable) {
			t.Errorf("error = %v", err)
		}
	})
}

func TestBackgroundCollector(t *testing.T) {
	root := t.TempDir()
	f := newFS(t, root, small, func(o *Options) {
		o.GCInterval = 25 * time.Millisecond
		o.UploadExpiry = 150 * time.Millisecond
	})
	mkbucket(t, f, "bgc")
	id, _ := upload(t, f, "bgc", "abandoned", 1)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := f.ListObjectParts(bg, "bgc", "abandoned", id, storage.ListPartsOptions{}); errors.Is(err, storage.ErrNoSuchUpload) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the background collector never expired the abandoned upload")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Close stops the loop promptly and does not hang waiting on it.
	closed := make(chan error, 1)
	go func() { closed <- f.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Close hung")
	}
	// A restart on the same root works (the lock was released).
	f2, err := New(root, Options{Locker: f.locker, Logger: discard, GCInterval: -1})
	if err != nil {
		t.Fatal(err)
	}
	f2.Close()
}

func TestCollectorDisabledByNegativeInterval(t *testing.T) {
	f := newFS(t, t.TempDir(), small, func(o *Options) {
		o.GCInterval = -1
		o.UploadExpiry = time.Millisecond
	})
	mkbucket(t, f, "off")
	id, _ := upload(t, f, "off", "k", 1)
	time.Sleep(100 * time.Millisecond)
	if _, err := f.ListObjectParts(bg, "off", "k", id, storage.ListPartsOptions{}); err != nil {
		t.Errorf("upload removed although background GC is disabled: %v", err)
	}
	if err := f.Close(); err != nil { // must not wait on a loop that never ran
		t.Fatal(err)
	}
}
