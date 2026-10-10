package fs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"nanoio/internal/bucket/nslock"
	"nanoio/internal/meta"
	"nanoio/internal/storage"
	"nanoio/internal/storage/storagetest"
)

var (
	bg      = context.Background()
	discard = slog.New(slog.NewTextHandler(io.Discard, nil))
)

func newFS(t *testing.T, root string, mut ...func(*Options)) *FS {
	t.Helper()
	opts := Options{Locker: nslock.New(5 * time.Second), Logger: discard}
	for _, m := range mut {
		m(&opts)
	}
	f, err := New(root, opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func put(t *testing.T, f *FS, bucket, key, body string) storage.ObjectInfo {
	t.Helper()
	info, err := f.PutObject(bg, bucket, key, strings.NewReader(body), int64(len(body)), storage.PutOptions{})
	if err != nil {
		t.Fatalf("PutObject(%s/%s): %v", bucket, key, err)
	}
	return info
}

func read(t *testing.T, f *FS, bucket, key string) (string, error) {
	t.Helper()
	rc, _, err := f.GetObject(bg, bucket, key, storage.GetOptions{})
	if err != nil {
		return "", err
	}
	defer rc.Close()
	b, err := io.ReadAll(rc)
	return string(b), err
}

func mkbucket(t *testing.T, f *FS, name string) {
	t.Helper()
	if err := f.MakeBucket(bg, name, storage.MakeBucketOptions{}); err != nil {
		t.Fatal(err)
	}
}

func TestConformance(t *testing.T) {
	storagetest.Run(t, func(t *testing.T, l storage.Locker) storage.StorageAPI {
		f, err := New(t.TempDir(), Options{Locker: l, Logger: discard})
		if err != nil {
			t.Fatal(err)
		}
		return f
	})
}

func TestNewValidation(t *testing.T) {
	tests := []struct {
		name string
		root string
		opts Options
	}{
		{"nil locker", t.TempDir(), Options{}},
		{"empty root", "", Options{Locker: nslock.New(0)}},
		{"root is a file", func() string {
			p := filepath.Join(t.TempDir(), "file")
			os.WriteFile(p, []byte("x"), 0o644)
			return p
		}(), Options{Locker: nslock.New(0)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if f, err := New(tt.root, tt.opts); err == nil {
				f.Close()
				t.Error("New succeeded")
			}
		})
	}
}

func TestOnDiskLayout(t *testing.T) {
	root := t.TempDir()
	f := newFS(t, root)
	mkbucket(t, f, "lay")
	put(t, f, "lay", "a/b.txt", "hello")
	put(t, f, "lay", "folder/", "")

	if _, err := os.Stat(filepath.Join(root, ".nanoio.sys", "format.json")); err != nil {
		t.Errorf("format.json: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "lay", ".nanoio-bucket")); err != nil {
		t.Errorf("bucket marker: %v", err)
	}

	keyDir := filepath.Join(root, "lay", "a", "b.txt")
	raw, err := os.ReadFile(filepath.Join(keyDir, "xl.meta"))
	if err != nil {
		t.Fatal(err)
	}
	file, err := meta.Decode(raw)
	if err != nil {
		t.Fatalf("xl.meta does not decode: %v", err)
	}
	v := file.Latest()
	if v == nil || len(file.Versions) != 1 || v.VersionID != "" || v.Size != 5 || v.Erasure != nil {
		t.Fatalf("unexpected metadata: %+v", file)
	}
	if !strings.HasPrefix(v.DataDir, storage.DataDirPrefix) {
		t.Errorf("DataDir %q lacks the reserved prefix", v.DataDir)
	}
	if b, err := os.ReadFile(filepath.Join(keyDir, v.DataDir, "part.1")); err != nil || string(b) != "hello" {
		t.Errorf("part.1 = %q, %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(root, "lay", "folder"+storage.DirObjectSuffix, "xl.meta")); err != nil {
		t.Errorf("placeholder layout: %v", err)
	}
	if left, _ := os.ReadDir(filepath.Join(root, ".nanoio.sys", "tmp")); len(left) != 0 {
		t.Errorf("%d staging entries left behind after successful writes", len(left))
	}
	// One data dir per key after an overwrite.
	put(t, f, "lay", "a/b.txt", "second")
	entries, _ := os.ReadDir(keyDir)
	if len(entries) != 2 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("key dir has %v, want xl.meta plus one data dir", names)
	}
}

func TestFaultInjection(t *testing.T) {
	crash := errors.New("simulated crash")
	points := []struct {
		point         string
		newVisible    bool
		leavesStaging bool
	}{
		{FaultStaged, false, true},
		{FaultMetaStaged, false, true},
		{FaultDataRenamed, false, true},
		{FaultMetaRenamed, true, true},
	}
	for _, p := range points {
		for _, existing := range []bool{true, false} {
			name := fmt.Sprintf("%s/existing=%v", p.point, existing)
			t.Run(name, func(t *testing.T) {
				root := t.TempDir()
				var armed atomic.Bool
				mkFS := func(sweep time.Duration) *FS {
					return newFS(t, root, func(o *Options) {
						o.TmpMaxAge = sweep
						o.Fault = func(pt string) error {
							if armed.Load() && pt == p.point {
								return crash
							}
							return nil
						}
					})
				}
				f := mkFS(0)
				mkbucket(t, f, "flt")
				if existing {
					put(t, f, "flt", "k", "old")
				}

				armed.Store(true)
				_, err := f.PutObject(bg, "flt", "k", strings.NewReader("new"), 3, storage.PutOptions{})
				armed.Store(false)
				if !errors.Is(err, crash) {
					t.Fatalf("PutObject error = %v, want the injected crash", err)
				}

				// The invariant: old state, or the complete new state. Never partial.
				got, err := read(t, f, "flt", "k")
				switch {
				case p.newVisible:
					if err != nil || got != "new" {
						t.Errorf("after commit-point crash: %q, %v; want new", got, err)
					}
				case existing:
					if err != nil || got != "old" {
						t.Errorf("after pre-commit crash: %q, %v; want old", got, err)
					}
				default:
					if !errors.Is(err, storage.ErrObjectNotFound) {
						t.Errorf("after pre-commit crash on fresh key: %q, %v; want ErrObjectNotFound", got, err)
					}
				}
				res, err := f.ListObjects(bg, "flt", storage.ListOptions{})
				if err != nil {
					t.Fatal(err)
				}
				wantListed := existing || p.newVisible
				if (len(res.Objects) == 1) != wantListed {
					t.Errorf("listing = %+v, want listed=%v", res.Objects, wantListed)
				}

				if p.leavesStaging {
					left, _ := os.ReadDir(filepath.Join(root, ".nanoio.sys", "tmp"))
					if len(left) == 0 {
						t.Error("crash left no staging dir; the fault did not simulate a crash")
					}
				}

				// The store keeps working, and a restart sweeps the debris.
				put(t, f, "flt", "k", "final")
				if got, err := read(t, f, "flt", "k"); err != nil || got != "final" {
					t.Errorf("put after crash: %q, %v", got, err)
				}
				if err := f.Close(); err != nil {
					t.Fatal(err)
				}
				f2 := newFS(t, root, func(o *Options) { o.TmpMaxAge = -1 })
				if left, _ := os.ReadDir(filepath.Join(root, ".nanoio.sys", "tmp")); len(left) != 0 {
					t.Errorf("restart sweep left %d staging entries", len(left))
				}
				if got, err := read(t, f2, "flt", "k"); err != nil || got != "final" {
					t.Errorf("after restart: %q, %v", got, err)
				}
				if err := f2.DeleteBucket(bg, "flt", storage.DeleteBucketOptions{Force: true}); err != nil {
					t.Errorf("force-deleting a bucket with crash debris: %v", err)
				}
			})
		}
	}
}

func TestCorruption(t *testing.T) {
	type damage func(t *testing.T, keyDir, dataDir string)
	meta := func(t *testing.T, keyDir string, mutate func([]byte) []byte) {
		t.Helper()
		p := filepath.Join(keyDir, "xl.meta")
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, mutate(b), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	tests := []struct {
		name       string
		damage     damage
		statFails  bool
		getFailsIs error
	}{
		{"xl.meta truncated", func(t *testing.T, k, _ string) {
			meta(t, k, func(b []byte) []byte { return b[:len(b)/2] })
		}, true, storage.ErrCorrupted},
		{"xl.meta bit flip", func(t *testing.T, k, _ string) {
			meta(t, k, func(b []byte) []byte { b[len(b)-2] ^= 0x10; return b })
		}, true, storage.ErrCorrupted},
		{"xl.meta replaced by garbage", func(t *testing.T, k, _ string) {
			meta(t, k, func([]byte) []byte { return []byte("not metadata at all, but long enough") })
		}, true, storage.ErrCorrupted},
		{"xl.meta emptied", func(t *testing.T, k, _ string) {
			meta(t, k, func([]byte) []byte { return nil })
		}, true, storage.ErrCorrupted},
		{"part file truncated", func(t *testing.T, k, d string) {
			os.WriteFile(filepath.Join(k, d, "part.1"), []byte("sh"), 0o644)
		}, false, storage.ErrCorrupted},
		{"part file missing", func(t *testing.T, k, d string) {
			os.Remove(filepath.Join(k, d, "part.1"))
		}, false, storage.ErrCorrupted},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			f := newFS(t, root)
			mkbucket(t, f, "cor")
			put(t, f, "cor", "victim", "hello world")
			put(t, f, "cor", "healthy", "fine")
			keyDir := filepath.Join(root, "cor", "victim")
			raw, _ := os.ReadFile(filepath.Join(keyDir, "xl.meta"))
			file, _ := meta2(raw)
			tt.damage(t, keyDir, file.Latest().DataDir)

			_, err := f.StatObject(bg, "cor", "victim", storage.GetOptions{})
			if tt.statFails {
				wantIs(t, "StatObject", err, storage.ErrCorrupted)
			} else if err != nil {
				t.Errorf("StatObject: %v", err)
			}
			_, err = read(t, f, "cor", "victim")
			wantIs(t, "GetObject", err, tt.getFailsIs)

			// Corruption is never mistaken for absence, and does not take
			// healthy neighbours down with it.
			if got, err := read(t, f, "cor", "healthy"); err != nil || got != "fine" {
				t.Errorf("healthy object: %q, %v", got, err)
			}
			res, err := f.ListObjects(bg, "cor", storage.ListOptions{})
			if err != nil {
				t.Fatal(err)
			}
			var names []string
			for _, o := range res.Objects {
				names = append(names, o.Name)
			}
			if tt.statFails {
				if strings.Join(names, ",") != "healthy" {
					t.Errorf("listing = %v, want only healthy", names)
				}
				if info, _ := f.Info(bg); info.Corrupted == 0 {
					t.Error("Info().Corrupted = 0 after skipping a corrupt key")
				}
			}
			// The corrupt object can still be replaced by a fresh write... except
			// when its metadata is unreadable, which must not be silently overwritten.
			_, err = f.PutObject(bg, "cor", "victim", strings.NewReader("again"), 5, storage.PutOptions{})
			if tt.statFails {
				wantIs(t, "overwrite of unreadable metadata", err, storage.ErrCorrupted)
			}
		})
	}
}

func meta2(b []byte) (*meta.File, error) { return meta.Decode(b) }

func wantIs(t *testing.T, what string, got, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Errorf("%s: error = %v, want %v", what, got, want)
	}
}

func TestSecondInstanceRefused(t *testing.T) {
	root := t.TempDir()
	first := newFS(t, root)
	if _, err := New(root, Options{Locker: nslock.New(0), Logger: discard}); err == nil || !strings.Contains(err.Error(), "in use") {
		t.Fatalf("second New error = %v, want an in-use error", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := New(root, Options{Locker: nslock.New(0), Logger: discard})
	if err != nil {
		t.Fatalf("New after Close: %v", err)
	}
	second.Close()
}

func TestFormatVersionGate(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr bool
	}{
		{"current", `{"format":1,"id":"x"}`, false},
		{"future format", `{"format":99,"id":"x"}`, true},
		{"not json", `{{{`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			os.MkdirAll(filepath.Join(root, ".nanoio.sys"), 0o755)
			os.WriteFile(filepath.Join(root, ".nanoio.sys", "format.json"), []byte(tt.content), 0o644)
			f, err := New(root, Options{Locker: nslock.New(0), Logger: discard})
			if tt.wantErr {
				wantIs(t, "New", err, storage.ErrCorrupted)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			f.Close()
			if b, _ := os.ReadFile(filepath.Join(root, ".nanoio.sys", "format.json")); string(b) != tt.content {
				t.Error("existing format.json was rewritten")
			}
		})
	}
}

func TestStartupSweep(t *testing.T) {
	tests := []struct {
		name     string
		maxAge   time.Duration
		age      time.Duration
		wantKept bool
	}{
		{"fresh kept under default age", 0, 0, true},
		{"day-old removed under default age", 0, 25 * time.Hour, false},
		{"fresh removed when maxAge negative", -1, 0, false},
		{"older than custom age removed", time.Hour, 2 * time.Hour, false},
		{"younger than custom age kept", time.Hour, time.Minute, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			tmp := filepath.Join(root, ".nanoio.sys", "tmp")
			os.MkdirAll(filepath.Join(tmp, "stale", "sub"), 0o755)
			old := time.Now().Add(-tt.age)
			os.Chtimes(filepath.Join(tmp, "stale"), old, old)
			f := newFS(t, root, func(o *Options) { o.TmpMaxAge = tt.maxAge })
			_ = f
			_, err := os.Stat(filepath.Join(tmp, "stale"))
			if kept := err == nil; kept != tt.wantKept {
				t.Errorf("kept = %v, want %v", kept, tt.wantKept)
			}
		})
	}
}

func TestNotImplementedIsExplicit(t *testing.T) {
	f := newFS(t, t.TempDir())
	mkbucket(t, f, "nim")
	put(t, f, "nim", "k", "v")
	calls := map[string]func() error{
		"versioned put": func() error {
			_, err := f.PutObject(bg, "nim", "k", strings.NewReader("v"), 1, storage.PutOptions{Versioned: true})
			return err
		},
		"versioned delete": func() error {
			_, err := f.DeleteObject(bg, "nim", "k", storage.DeleteOptions{Versioned: true})
			return err
		},
		"delete by version id": func() error {
			_, err := f.DeleteObject(bg, "nim", "k", storage.DeleteOptions{VersionID: "abc"})
			return err
		},
		"CopyObject": func() error {
			_, err := f.CopyObject(bg, storage.ObjectRef{}, storage.ObjectRef{}, storage.CopyOptions{})
			return err
		},
		"UpdateObjectMetadata": func() error {
			_, err := f.UpdateObjectMetadata(bg, "nim", "k", storage.UpdateMetaOptions{})
			return err
		},
		"ListObjectVersions": func() error {
			_, err := f.ListObjectVersions(bg, "nim", storage.ListOptions{})
			return err
		},
		"versioned NewMultipartUpload": func() error {
			_, err := f.NewMultipartUpload(bg, "nim", "k", storage.PutOptions{Versioned: true})
			return err
		},
		"versioned CompleteMultipartUpload": func() error {
			_, err := f.CompleteMultipartUpload(bg, "nim", "k", "00000000-0000-4000-8000-000000000000",
				[]storage.CompletePart{{Number: 1, ETag: "x"}}, storage.PutOptions{Versioned: true})
			return err
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) { wantIs(t, name, call(), storage.ErrNotImplemented) })
	}
	// And the refused versioned put did not damage the object.
	if got, err := read(t, f, "nim", "k"); err != nil || got != "v" {
		t.Errorf("object after refused calls: %q, %v", got, err)
	}
}

func TestGetByUnknownVersion(t *testing.T) {
	f := newFS(t, t.TempDir())
	mkbucket(t, f, "ver")
	put(t, f, "ver", "k", "v")
	_, err := f.StatObject(bg, "ver", "k", storage.GetOptions{VersionID: "no-such-version"})
	wantIs(t, "StatObject(version)", err, storage.ErrVersionNotFound)
}

func TestInfo(t *testing.T) {
	f := newFS(t, t.TempDir())
	info, err := f.Info(bg)
	if err != nil {
		t.Fatal(err)
	}
	if info.Kind != "fs" || info.Disks != 1 || !info.Healthy || info.TotalBytes == 0 || info.FreeBytes > info.TotalBytes || info.Corrupted != 0 {
		t.Errorf("Info = %+v", info)
	}
}

func TestBucketMarkerFallback(t *testing.T) {
	root := t.TempDir()
	f := newFS(t, root)
	mkbucket(t, f, "fall")
	os.Remove(filepath.Join(root, "fall", ".nanoio-bucket"))
	info, err := f.GetBucketInfo(bg, "fall")
	if err != nil || info.Created.IsZero() {
		t.Errorf("GetBucketInfo without marker = %+v, %v", info, err)
	}
}

func TestStrayAndHostileEntriesInRoot(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "secret"), []byte("s"), 0o644)
	f := newFS(t, root)
	mkbucket(t, f, "real")
	os.Symlink(outside, filepath.Join(root, "linked"))             // symlinked "bucket"
	os.WriteFile(filepath.Join(root, "afile"), []byte("x"), 0o644) // plain file
	os.Mkdir(filepath.Join(root, "UPPER"), 0o755)                  // not a valid name

	list, err := f.ListBuckets(bg)
	if err != nil || len(list) != 1 || list[0].Name != "real" {
		t.Errorf("ListBuckets = %+v, %v; want only real", list, err)
	}
	for _, name := range []string{"linked", "afile"} {
		ok, err := f.BucketExists(bg, name)
		if err != nil || ok {
			t.Errorf("BucketExists(%q) = %v, %v; want false", name, ok, err)
		}
		_, err = f.PutObject(bg, name, "k", strings.NewReader("x"), 1, storage.PutOptions{})
		wantIs(t, "PutObject into "+name, err, storage.ErrBucketNotFound)
	}
	if _, err := os.Stat(filepath.Join(outside, "k")); err == nil {
		t.Error("write escaped through a symlinked bucket")
	}
}

func TestListIgnoresDebris(t *testing.T) {
	root := t.TempDir()
	f := newFS(t, root)
	mkbucket(t, f, "deb")
	put(t, f, "deb", "real", "x")
	// Empty dirs, a data dir without xl.meta, and a stray file.
	os.MkdirAll(filepath.Join(root, "deb", "ghost", "inner"), 0o755)
	os.MkdirAll(filepath.Join(root, "deb", "orphan", ".nanoio-data-x"), 0o755)
	os.WriteFile(filepath.Join(root, "deb", "orphan", ".nanoio-data-x", "part.1"), []byte("junk"), 0o644)
	os.WriteFile(filepath.Join(root, "deb", "stray.txt"), []byte("junk"), 0o644)

	res, err := f.ListObjects(bg, "deb", storage.ListOptions{})
	if err != nil || len(res.Objects) != 1 || res.Objects[0].Name != "real" {
		t.Errorf("listing = %+v, %v", res, err)
	}
	if _, err := f.StatObject(bg, "deb", "orphan", storage.GetOptions{}); !errors.Is(err, storage.ErrObjectNotFound) {
		t.Errorf("Stat(orphan) = %v, want ErrObjectNotFound", err)
	}
}

// Deleting one key prunes empty parents while a sibling key is being
// written; the retry in PutObject must absorb the race.
func TestPrunedParentRace(t *testing.T) {
	f := newFS(t, t.TempDir())
	mkbucket(t, f, "race")
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	loop := func(key string) {
		defer wg.Done()
		for i := 0; i < 60; i++ {
			if _, err := f.PutObject(bg, "race", key, strings.NewReader("x"), 1, storage.PutOptions{}); err != nil {
				errs <- fmt.Errorf("put %s: %w", key, err)
				return
			}
			if _, err := f.DeleteObject(bg, "race", key, storage.DeleteOptions{}); err != nil {
				errs <- fmt.Errorf("delete %s: %w", key, err)
				return
			}
		}
	}
	for _, k := range []string{"x/y/z/one", "x/y/z/two", "x/y/other", "x/third"} {
		wg.Add(1)
		go loop(k)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	res, _ := f.ListObjects(bg, "race", storage.ListOptions{})
	if len(res.Objects) != 0 {
		t.Errorf("%d objects left", len(res.Objects))
	}
}

func TestCloseWaitsForInFlight(t *testing.T) {
	f := newFS(t, t.TempDir())
	mkbucket(t, f, "slow")
	pr, pw := io.Pipe()
	putDone := make(chan error, 1)
	go func() {
		_, err := f.PutObject(bg, "slow", "k", pr, -1, storage.PutOptions{})
		putDone <- err
	}()
	time.Sleep(50 * time.Millisecond) // let the put start streaming
	closed := make(chan struct{})
	go func() { f.Close(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("Close returned while a PutObject was still in flight")
	case <-time.After(100 * time.Millisecond):
	}
	pw.Write([]byte("tail"))
	pw.Close()
	if err := <-putDone; err != nil {
		t.Errorf("in-flight put failed during shutdown: %v", err)
	}
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("Close never returned after the put finished")
	}
}
