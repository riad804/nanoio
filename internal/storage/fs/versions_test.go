package fs

import (
	"strings"
	"testing"

	"nanoio/internal/meta"
	"nanoio/internal/storage"
)

// The collector must treat every version's data directory as live.
func TestGCKeepsEveryVersion(t *testing.T) {
	f := newFS(t, t.TempDir())
	mkbucket(t, f, "gcv")
	if err := f.SetBucketVersioning(bg, "gcv", storage.VersioningEnabled); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for i, body := range []string{"one", "two", "three"} {
		info, err := f.PutObject(bg, "gcv", "k", strings.NewReader(body), int64(len(body)), storage.PutOptions{})
		if err != nil {
			t.Fatal(i, err)
		}
		ids = append(ids, info.VersionID)
	}
	f.DeleteObject(bg, "gcv", "k", storage.DeleteOptions{}) // plus a marker
	st, err := f.GC(bg)
	if err != nil {
		t.Fatal(err)
	}
	if st.OrphanDataDirs != 0 {
		t.Errorf("GC removed %d data directories of live versions", st.OrphanDataDirs)
	}
	for i, id := range ids {
		rc, _, err := f.GetObject(bg, "gcv", "k", storage.GetOptions{VersionID: id})
		if err != nil {
			t.Fatalf("version %d after GC: %v", i, err)
		}
		rc.Close()
	}
}

// Every key written by this build carries a generation and per-version
// sequence numbers (format 2), versioned or not; a versioned key's file also
// holds its delete markers and older versions in newest-first order.
func TestVersionedMetadataLayout(t *testing.T) {
	root := t.TempDir()
	f := newFS(t, root)
	mkbucket(t, f, "plain")
	mkbucket(t, f, "layout")
	put(t, f, "plain", "k", "v")
	if err := f.SetBucketVersioning(bg, "layout", storage.VersioningEnabled); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{"a", "b", "c"} {
		put(t, f, "layout", "k", body)
	}
	f.DeleteObject(bg, "layout", "k", storage.DeleteOptions{})

	load := func(bucket string) *meta.File {
		t.Helper()
		kd, _ := f.keyDir(bucket, "k")
		file, err := f.readMeta(kd)
		if err != nil || file == nil {
			t.Fatalf("readMeta(%s): %v", bucket, err)
		}
		return file
	}
	if p := load("plain"); p.Format != meta.FormatVersioned || len(p.Versions) != 1 || p.Gen != 1 || p.Versions[0].Seq != 1 {
		t.Errorf("unversioned key: format %d, %d versions, gen %d", p.Format, len(p.Versions), p.Gen)
	}
	l := load("layout")
	if l.Format != meta.FormatVersioned || len(l.Versions) != 4 || l.Gen != 4 {
		t.Fatalf("versioned key: format %d, %d versions, gen %d", l.Format, len(l.Versions), l.Gen)
	}
	for i, v := range l.Versions {
		if want := uint64(4 - i); v.Seq != want {
			t.Errorf("version %d has seq %d, want %d (newest first)", i, v.Seq, want)
		}
	}
	if l.Versions[0].Type != meta.TypeDeleteMarker {
		t.Errorf("newest entry is %q, want the delete marker", l.Versions[0].Type)
	}
}
