package storagetest

import (
	"errors"
	"strings"
	"testing"
	"time"

	"nanoio/internal/storage"
)

// testImport pins what replication relies on: a version can be written under
// its source's ID and time, such a write is idempotent, the history orders
// by time (a late replica of an older version does not become current), and
// a delete marker can be imported the same way.
func testImport(t *testing.T, f Factory) {
	h := newHarness(t, f)
	h.mkbucket("imp")
	imp := func(id string, mod time.Time, body string) (storage.ObjectInfo, error) {
		return h.be.PutObject(bg, "imp", "k", strings.NewReader(body), int64(len(body)),
			storage.PutOptions{Import: &storage.VersionImport{VersionID: id, ModTime: mod}})
	}
	base := time.Now().Add(-time.Hour).UTC().Truncate(time.Millisecond)
	const idOld, idNew = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"

	// Unversioned buckets cannot hold replicas.
	if _, err := imp(idOld, base, "x"); !errors.Is(err, storage.ErrInvalidBucketState) {
		t.Fatalf("import into an unversioned bucket = %v", err)
	}
	h.enable("imp")

	// Import the newer version first, then the older one arrives late.
	n, err := imp(idNew, base.Add(10*time.Minute), "newer")
	if err != nil || n.VersionID != idNew || !n.ModTime.Equal(base.Add(10*time.Minute)) || !n.IsLatest {
		t.Fatalf("import newer = %+v, %v", n, err)
	}
	o, err := imp(idOld, base, "older")
	if err != nil || o.VersionID != idOld || !o.ModTime.Equal(base) || o.IsLatest {
		t.Fatalf("import older = %+v, %v", o, err)
	}
	if got, info, err := h.getV("imp", "k", ""); err != nil || got != "newer" || info.VersionID != idNew {
		t.Fatalf("latest = %q %+v %v, want the newer import", got, info, err)
	}
	h.mustGetV("imp", "k", idOld, "older")

	// Idempotent: a retry changes nothing, even with different bytes.
	again, err := imp(idOld, base, "different bytes")
	if err != nil || again.ETag != o.ETag {
		t.Fatalf("re-import = %+v, %v", again, err)
	}
	h.mustGetV("imp", "k", idOld, "older")
	vers := h.listVersions("imp", storage.ListOptions{})
	if len(vers.Versions) != 2 || vers.Versions[0].VersionID != idNew || vers.Versions[1].VersionID != idOld {
		t.Fatalf("history = %+v", vers.Versions)
	}

	// A local write after imports is newer than all of them, even when the
	// imported time is in this node's future.
	future := time.Now().Add(time.Hour).UTC().Truncate(time.Millisecond)
	if _, err := imp("33333333-3333-4333-8333-333333333333", future, "from the future"); err != nil {
		t.Fatal(err)
	}
	local := h.put("imp", "k", "local write")
	if !local.ModTime.After(future) || !local.IsLatest {
		t.Errorf("a local write = %+v, want it after the future import", local)
	}
	if got, _, _ := h.getV("imp", "k", ""); got != "local write" {
		t.Errorf("latest = %q", got)
	}

	// Delete markers import under their own ID and time, idempotently.
	const idMarker = "44444444-4444-4444-8444-444444444444"
	mt := time.Now().Add(2 * time.Hour).UTC().Truncate(time.Millisecond)
	mk := func() storage.DeleteResult {
		t.Helper()
		r, err := h.be.DeleteObject(bg, "imp", "k", storage.DeleteOptions{ImportMarker: &storage.VersionImport{VersionID: idMarker, ModTime: mt}})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if r := mk(); !r.DeleteMarker || r.VersionID != idMarker {
		t.Errorf("import marker = %+v", r)
	}
	mk()
	n2 := 0
	for _, v := range h.listVersions("imp", storage.ListOptions{}).Versions {
		if v.DeleteMarker {
			n2++
			if v.VersionID != idMarker || !v.ModTime.Equal(mt) || !v.IsLatest {
				t.Errorf("marker = %+v", v)
			}
		}
	}
	if n2 != 1 {
		t.Errorf("%d markers after importing the same one twice", n2)
	}
	if _, _, err := h.getV("imp", "k", ""); !errors.Is(err, storage.ErrObjectNotFound) {
		t.Errorf("GET of a key whose latest version is an imported marker = %v", err)
	}
}
