package storagetest

import (
	"errors"
	"fmt"
	"io"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"nanoio/internal/storage"
)

func testVersioningState(t *testing.T, f Factory) {
	h := newHarness(t, f)
	h.mkbucket("vstate")
	state := func() storage.VersioningConfig {
		t.Helper()
		c, err := h.be.GetBucketVersioning(bg, "vstate")
		if err != nil {
			t.Fatalf("GetBucketVersioning: %v", err)
		}
		return c
	}
	set := func(s storage.VersioningState) error {
		return h.be.SetBucketVersioning(bg, "vstate", s)
	}

	if c := state(); c.State != storage.VersioningUnversioned || c.Seq != 0 {
		t.Fatalf("fresh bucket = %+v, want unversioned", c)
	}
	// Setting "unversioned" on an unversioned bucket changes nothing.
	if err := set(storage.VersioningUnversioned); err != nil {
		t.Errorf("unversioned -> unversioned: %v", err)
	}

	steps := []struct {
		name string
		to   storage.VersioningState
		want storage.VersioningState // state afterwards
		err  error
	}{
		{"unversioned -> enabled", storage.VersioningEnabled, storage.VersioningEnabled, nil},
		{"enabled -> enabled is a no-op", storage.VersioningEnabled, storage.VersioningEnabled, nil},
		{"enabled -> suspended", storage.VersioningSuspended, storage.VersioningSuspended, nil},
		{"suspended -> suspended is a no-op", storage.VersioningSuspended, storage.VersioningSuspended, nil},
		{"suspended -> enabled", storage.VersioningEnabled, storage.VersioningEnabled, nil},
		{"enabled -> unversioned is refused", storage.VersioningUnversioned, storage.VersioningEnabled, storage.ErrIllegalVersioning},
		{"enabled -> suspended again", storage.VersioningSuspended, storage.VersioningSuspended, nil},
		{"suspended -> unversioned is refused", storage.VersioningUnversioned, storage.VersioningSuspended, storage.ErrIllegalVersioning},
		{"unknown state is refused", storage.VersioningState("Paused"), storage.VersioningSuspended, storage.ErrIllegalVersioning},
	}
	var lastSeq uint64
	for _, st := range steps {
		before := state()
		err := set(st.to)
		if st.err != nil {
			wantErr(t, st.name, err, st.err)
		} else if err != nil {
			t.Errorf("%s: %v", st.name, err)
		}
		after := state()
		if after.State != st.want {
			t.Errorf("%s: state = %q, want %q", st.name, after.State, st.want)
		}
		if after.State == before.State && after.Seq != before.Seq {
			t.Errorf("%s: sequence moved (%d -> %d) without a change", st.name, before.Seq, after.Seq)
		}
		if after.State != before.State && after.Seq <= before.Seq {
			t.Errorf("%s: sequence did not advance (%d -> %d)", st.name, before.Seq, after.Seq)
		}
		if after.Seq < lastSeq {
			t.Errorf("%s: sequence went backwards", st.name)
		}
		lastSeq = after.Seq
	}

	t.Run("missing and invalid buckets", func(t *testing.T) {
		_, err := h.be.GetBucketVersioning(bg, "no-such-bucket")
		wantErr(t, "Get on a missing bucket", err, storage.ErrBucketNotFound)
		wantErr(t, "Set on a missing bucket",
			h.be.SetBucketVersioning(bg, "no-such-bucket", storage.VersioningEnabled), storage.ErrBucketNotFound)
		_, err = h.be.GetBucketVersioning(bg, "Bad_Name")
		wantErr(t, "Get with an invalid name", err, storage.ErrInvalidBucketName)
	})

	t.Run("a recreated bucket starts unversioned", func(t *testing.T) {
		h.mkbucket("vrecreate")
		if err := h.be.SetBucketVersioning(bg, "vrecreate", storage.VersioningEnabled); err != nil {
			t.Fatal(err)
		}
		if err := h.be.DeleteBucket(bg, "vrecreate", storage.DeleteBucketOptions{}); err != nil {
			t.Fatal(err)
		}
		h.mkbucket("vrecreate")
		c, err := h.be.GetBucketVersioning(bg, "vrecreate")
		if err != nil || c.State != storage.VersioningUnversioned {
			t.Errorf("recreated bucket = %+v, %v", c, err)
		}
	})

	t.Run("concurrent changes leave a legal, agreed state", func(t *testing.T) {
		h.mkbucket("vconcurrent")
		var wg sync.WaitGroup
		for i := 0; i < 12; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				to := storage.VersioningEnabled
				if i%2 == 1 {
					to = storage.VersioningSuspended
				}
				if err := h.be.SetBucketVersioning(bg, "vconcurrent", to); err != nil {
					t.Errorf("Set(%q): %v", to, err)
				}
			}()
		}
		wg.Wait()
		c, err := h.be.GetBucketVersioning(bg, "vconcurrent")
		if err != nil {
			t.Fatal(err)
		}
		if c.State != storage.VersioningEnabled && c.State != storage.VersioningSuspended {
			t.Errorf("state = %q after concurrent changes", c.State)
		}
		if c.Seq == 0 || c.Seq > 12 {
			t.Errorf("sequence = %d", c.Seq)
		}
		// Every read, including after the dust settled, agrees.
		for i := 0; i < 5; i++ {
			if again, _ := h.be.GetBucketVersioning(bg, "vconcurrent"); again != c {
				t.Errorf("read %d = %+v, first read %+v", i, again, c)
			}
		}
	})

	t.Run("locking", func(t *testing.T) {
		h.rec.reset()
		if err := h.be.SetBucketVersioning(bg, "vstate", storage.VersioningEnabled); err != nil {
			t.Fatal(err)
		}
		_, log := h.rec.snapshot()
		if logIndex(log, "Lock vstate/") < 0 {
			t.Errorf("a versioning change did not take the bucket lock exclusively: %v", log)
		}
		h.rec.reset()
		h.be.GetBucketVersioning(bg, "vstate")
		_, log = h.rec.snapshot()
		if logIndex(log, "RLock vstate/") < 0 {
			t.Errorf("reading the state did not take the bucket lock shared: %v", log)
		}
	})
}

// logIndex finds entry in a recorder log, or -1.
func logIndex(log []string, entry string) int {
	for i, e := range log {
		if e == entry {
			return i
		}
	}
	return -1
}

// RunVersioned executes the object-versioning suite. It is separate from Run
// so a backend can adopt it when it implements versioned objects.
func RunVersioned(t *testing.T, newBackend Factory) {
	for _, tc := range []struct {
		name string
		fn   func(*testing.T, Factory)
	}{
		{"VersionedEnabled", testVersionedEnabled},
		{"VersionedDeleteMarkers", testVersionedDeleteMarkers},
		{"VersionedRemoveVersion", testVersionedRemoveVersion},
		{"VersionedSuspended", testVersionedSuspended},
		{"VersionedFromUnversioned", testVersionedFromUnversioned},
		{"VersionedMultipart", testVersionedMultipart},
		{"VersionedSnapshotRead", testVersionedSnapshotRead},
		{"VersionedPreconditions", testVersionedPreconditions},
		{"VersionedConcurrentPuts", testVersionedConcurrentPuts},
		{"VersionedBucketNotEmpty", testVersionedBucketNotEmpty},
		{"VersionedListing", testVersionedListing},
		{"VersionedListingPagination", testVersionedListingPagination},
		{"VersionedInterleavedModel", testVersionedInterleavedModel},
		{"VersionedConcurrentListing", testVersionedConcurrentListing},
	} {
		t.Run(tc.name, func(t *testing.T) { tc.fn(t, newBackend) })
	}
}

const uuidLen = 36

func (h *harness) enable(bucket string) {
	h.t.Helper()
	if err := h.be.SetBucketVersioning(bg, bucket, storage.VersioningEnabled); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) suspend(bucket string) {
	h.t.Helper()
	if err := h.be.SetBucketVersioning(bg, bucket, storage.VersioningSuspended); err != nil {
		h.t.Fatal(err)
	}
}

// getV reads bucket/key at a version ("" = latest).
func (h *harness) getV(bucket, key, version string) (string, storage.ObjectInfo, error) {
	h.t.Helper()
	rc, info, err := h.be.GetObject(bg, bucket, key, storage.GetOptions{VersionID: version})
	if err != nil {
		return "", info, err
	}
	defer rc.Close()
	b, err := io.ReadAll(rc)
	if err != nil {
		h.t.Fatalf("read %s/%s@%s: %v", bucket, key, version, err)
	}
	return string(b), info, nil
}

func (h *harness) mustGetV(bucket, key, version, want string) storage.ObjectInfo {
	h.t.Helper()
	got, info, err := h.getV(bucket, key, version)
	if err != nil {
		h.t.Fatalf("GetObject(%s/%s@%q): %v", bucket, key, version, err)
	}
	if got != want {
		h.t.Fatalf("GetObject(%s/%s@%q) = %q, want %q", bucket, key, version, got, want)
	}
	return info
}

func (h *harness) del(bucket, key, version string) storage.DeleteResult {
	h.t.Helper()
	res, err := h.be.DeleteObject(bg, bucket, key, storage.DeleteOptions{VersionID: version})
	if err != nil {
		h.t.Fatalf("DeleteObject(%s/%s@%q): %v", bucket, key, version, err)
	}
	return res
}

func (h *harness) listKeys(bucket string) []string {
	h.t.Helper()
	res, err := h.be.ListObjects(bg, bucket, storage.ListOptions{})
	if err != nil {
		h.t.Fatal(err)
	}
	var out []string
	for _, o := range res.Objects {
		out = append(out, o.Name)
	}
	return out
}

func testVersionedEnabled(t *testing.T, f Factory) {
	h := newHarness(t, f)
	h.mkbucket("venabled")
	h.enable("venabled")

	ids := map[string]string{}
	for _, body := range []string{"first", "second", "third"} {
		info := h.put("venabled", "doc", body)
		if len(info.VersionID) != uuidLen {
			t.Fatalf("PutObject version ID %q is not a UUID", info.VersionID)
		}
		if _, dup := ids[info.VersionID]; dup {
			t.Fatalf("version ID %s issued twice", info.VersionID)
		}
		ids[info.VersionID] = body
		if !info.IsLatest {
			t.Errorf("the object just written is not latest: %+v", info)
		}
	}
	// Every version is individually readable, and only the newest is latest.
	for id, body := range ids {
		info := h.mustGetV("venabled", "doc", id, body)
		if info.VersionID != id {
			t.Errorf("GetObject@%s reports version %q", id, info.VersionID)
		}
		if info.IsLatest != (body == "third") {
			t.Errorf("version %s (%s): IsLatest = %v", id, body, info.IsLatest)
		}
		st, err := h.be.StatObject(bg, "venabled", "doc", storage.GetOptions{VersionID: id})
		if err != nil || st.ETag != md5hex(body) || st.VersionID != id {
			t.Errorf("StatObject@%s = %+v, %v", id, st, err)
		}
	}
	info := h.mustGetV("venabled", "doc", "", "third")
	if info.VersionID == "" || info.VersionID == storage.NullVersionID {
		t.Errorf("latest reports version %q", info.VersionID)
	}
	if keys := h.listKeys("venabled"); len(keys) != 1 || keys[0] != "doc" {
		t.Errorf("ListObjects = %v, want one key however many versions it has", keys)
	}
	// Bad IDs.
	_, _, err := h.getV("venabled", "doc", "not-a-uuid")
	wantErr(t, "malformed version ID", err, storage.ErrInvalidVersionID)
	_, _, err = h.getV("venabled", "doc", "9f0c1b9e-1111-4222-8333-444455556666")
	wantErr(t, "unknown version ID", err, storage.ErrVersionNotFound)
	_, _, err = h.getV("venabled", "doc", storage.NullVersionID)
	wantErr(t, "null version when there is none", err, storage.ErrVersionNotFound)
}

func testVersionedDeleteMarkers(t *testing.T, f Factory) {
	h := newHarness(t, f)
	h.mkbucket("vmarkers")
	h.enable("vmarkers")
	v1 := h.put("vmarkers", "k", "one").VersionID
	v2 := h.put("vmarkers", "k", "two").VersionID

	res := h.del("vmarkers", "k", "")
	if !res.DeleteMarker || len(res.VersionID) != uuidLen {
		t.Fatalf("delete without a version = %+v, want a marker with a UUID", res)
	}
	marker := res.VersionID

	// Latest is a marker: "not found" carrying the marker's identity.
	_, _, err := h.getV("vmarkers", "k", "")
	wantErr(t, "GET latest = marker", err, storage.ErrObjectNotFound)
	var dm *storage.DeleteMarkerError
	if !errors.As(err, &dm) || dm.VersionID != marker || dm.Explicit || dm.ModTime.IsZero() {
		t.Errorf("marker error = %+v", dm)
	}
	_, err = h.be.StatObject(bg, "vmarkers", "k", storage.GetOptions{})
	wantErr(t, "HEAD latest = marker", err, storage.ErrObjectNotFound)
	// Naming the marker is "method not allowed".
	_, _, err = h.getV("vmarkers", "k", marker)
	wantErr(t, "GET marker version", err, storage.ErrIsDeleteMarker)
	if !errors.As(err, &dm) || !dm.Explicit || dm.VersionID != marker {
		t.Errorf("explicit marker error = %+v", dm)
	}
	// The data is all still there, and the plain listing hides the key.
	h.mustGetV("vmarkers", "k", v1, "one")
	h.mustGetV("vmarkers", "k", v2, "two")
	if keys := h.listKeys("vmarkers"); len(keys) != 0 {
		t.Errorf("ListObjects = %v, want the deleted key hidden", keys)
	}
	// A second delete stacks another marker.
	res2 := h.del("vmarkers", "k", "")
	if !res2.DeleteMarker || res2.VersionID == marker {
		t.Errorf("second delete = %+v", res2)
	}
	// Removing the markers undeletes: the newest real version is back.
	for _, id := range []string{res2.VersionID, marker} {
		r := h.del("vmarkers", "k", id)
		if !r.DeleteMarker || r.VersionID != id {
			t.Errorf("removing marker %s = %+v", id, r)
		}
	}
	info := h.mustGetV("vmarkers", "k", "", "two")
	if info.VersionID != v2 || !info.IsLatest {
		t.Errorf("after undelete: %+v", info)
	}
	if keys := h.listKeys("vmarkers"); len(keys) != 1 {
		t.Errorf("ListObjects after undelete = %v", keys)
	}
	// Deleting a key that never existed still makes a marker (as S3 does).
	res = h.del("vmarkers", "ghost", "")
	if !res.DeleteMarker || len(res.VersionID) != uuidLen {
		t.Errorf("delete of a missing key = %+v", res)
	}
	_, _, err = h.getV("vmarkers", "ghost", "")
	wantErr(t, "GET ghost", err, storage.ErrObjectNotFound)
}

func testVersionedRemoveVersion(t *testing.T, f Factory) {
	h := newHarness(t, f)
	h.mkbucket("vremove")
	h.enable("vremove")
	v1 := h.put("vremove", "k", "one").VersionID
	v2 := h.put("vremove", "k", "two").VersionID
	v3 := h.put("vremove", "k", "three").VersionID

	// Remove the middle version: the others are untouched.
	if r := h.del("vremove", "k", v2); r.DeleteMarker || r.VersionID != v2 {
		t.Errorf("remove v2 = %+v", r)
	}
	_, _, err := h.getV("vremove", "k", v2)
	wantErr(t, "removed version", err, storage.ErrVersionNotFound)
	h.mustGetV("vremove", "k", v1, "one")
	h.mustGetV("vremove", "k", "", "three")
	// Removing the latest promotes the next newest.
	h.del("vremove", "k", v3)
	info := h.mustGetV("vremove", "k", "", "one")
	if info.VersionID != v1 || !info.IsLatest {
		t.Errorf("after removing the latest: %+v", info)
	}
	// Removing a version that is not there succeeds.
	if _, err := h.be.DeleteObject(bg, "vremove", "k", storage.DeleteOptions{VersionID: v2}); err != nil {
		t.Errorf("removing a version twice: %v", err)
	}
	if _, err := h.be.DeleteObject(bg, "vremove", "never", storage.DeleteOptions{VersionID: v2}); err != nil {
		t.Errorf("removing a version of a missing key: %v", err)
	}
	_, err = h.be.DeleteObject(bg, "vremove", "k", storage.DeleteOptions{VersionID: "garbage"})
	wantErr(t, "malformed version ID", err, storage.ErrInvalidVersionID)
	// Removing the last version removes the key.
	h.del("vremove", "k", v1)
	_, err = h.be.StatObject(bg, "vremove", "k", storage.GetOptions{})
	wantErr(t, "stat of a key with no versions", err, storage.ErrObjectNotFound)
	var dm *storage.DeleteMarkerError
	if errors.As(err, &dm) {
		t.Errorf("a key with no versions reports a delete marker: %+v", dm)
	}
	if keys := h.listKeys("vremove"); len(keys) != 0 {
		t.Errorf("ListObjects = %v", keys)
	}
	// The key can be written again.
	h.put("vremove", "k", "again")
	h.mustGetV("vremove", "k", "", "again")
}

func testVersionedSuspended(t *testing.T, f Factory) {
	h := newHarness(t, f)
	h.mkbucket("vsusp")
	h.enable("vsusp")
	v1 := h.put("vsusp", "k", "enabled-1").VersionID
	h.suspend("vsusp")

	// Writes now replace the null version and leave real versions alone.
	n1 := h.put("vsusp", "k", "null-1")
	if n1.VersionID != storage.NullVersionID {
		t.Fatalf("suspended PUT reports version %q, want null", n1.VersionID)
	}
	h.mustGetV("vsusp", "k", storage.NullVersionID, "null-1")
	h.mustGetV("vsusp", "k", "", "null-1")
	n2 := h.put("vsusp", "k", "null-2")
	if n2.VersionID != storage.NullVersionID {
		t.Errorf("second suspended PUT reports %q", n2.VersionID)
	}
	h.mustGetV("vsusp", "k", storage.NullVersionID, "null-2")
	h.mustGetV("vsusp", "k", v1, "enabled-1")

	// Delete without a version replaces the null version with a null marker.
	res := h.del("vsusp", "k", "")
	if !res.DeleteMarker || res.VersionID != storage.NullVersionID {
		t.Fatalf("suspended delete = %+v, want a null marker", res)
	}
	_, _, err := h.getV("vsusp", "k", "")
	wantErr(t, "GET after suspended delete", err, storage.ErrObjectNotFound)
	var dm *storage.DeleteMarkerError
	if !errors.As(err, &dm) || dm.VersionID != storage.NullVersionID {
		t.Errorf("marker = %+v", dm)
	}
	h.mustGetV("vsusp", "k", v1, "enabled-1")
	// The null object's data is gone with its replacement.
	_, _, err = h.getV("vsusp", "k", storage.NullVersionID)
	wantErr(t, "null version after a null marker replaced it", err, storage.ErrIsDeleteMarker)
	// A new PUT replaces the null marker.
	h.put("vsusp", "k", "null-3")
	h.mustGetV("vsusp", "k", "", "null-3")
	// Re-enabling creates real versions again, newest first.
	h.enable("vsusp")
	v2 := h.put("vsusp", "k", "enabled-2").VersionID
	if len(v2) != uuidLen {
		t.Errorf("version after re-enable = %q", v2)
	}
	h.mustGetV("vsusp", "k", "", "enabled-2")
	h.mustGetV("vsusp", "k", storage.NullVersionID, "null-3")
	h.mustGetV("vsusp", "k", v1, "enabled-1")
}

func testVersionedFromUnversioned(t *testing.T, f Factory) {
	h := newHarness(t, f)
	h.mkbucket("vfrom")
	// While unversioned there are no version IDs to report.
	info := h.put("vfrom", "k", "before")
	if info.VersionID != "" {
		t.Errorf("unversioned PUT reports version %q", info.VersionID)
	}
	h.mustGetV("vfrom", "k", "", "before")
	if got := h.mustGetV("vfrom", "k", storage.NullVersionID, "before"); got.VersionID != "" {
		t.Errorf("unversioned GET reports version %q", got.VersionID)
	}
	h.put("vfrom", "k", "before-2") // replaces
	h.enable("vfrom")

	// The existing object is now the null version.
	info = h.mustGetV("vfrom", "k", "", "before-2")
	if info.VersionID != storage.NullVersionID {
		t.Errorf("existing object after enabling reports %q, want null", info.VersionID)
	}
	v := h.put("vfrom", "k", "after").VersionID
	h.mustGetV("vfrom", "k", "", "after")
	h.mustGetV("vfrom", "k", storage.NullVersionID, "before-2")
	// Deleting the latest version restores the null version as latest.
	h.del("vfrom", "k", v)
	info = h.mustGetV("vfrom", "k", "", "before-2")
	if !info.IsLatest || info.VersionID != storage.NullVersionID {
		t.Errorf("null version after the newer one was removed: %+v", info)
	}
}

func testVersionedMultipart(t *testing.T, f Factory) {
	h := newHarness(t, f)
	h.mkbucket("vmpu")
	h.enable("vmpu")
	complete := func(key, body string) storage.ObjectInfo {
		t.Helper()
		id, err := h.be.NewMultipartUpload(bg, "vmpu", key, storage.PutOptions{})
		if err != nil {
			t.Fatal(err)
		}
		p, err := h.be.PutObjectPart(bg, "vmpu", key, id, 1, strings.NewReader(body), int64(len(body)), storage.PartOptions{})
		if err != nil {
			t.Fatal(err)
		}
		info, err := h.be.CompleteMultipartUpload(bg, "vmpu", key, id,
			[]storage.CompletePart{{Number: 1, ETag: p.ETag}}, storage.PutOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return info
	}
	a := complete("k", "multipart-one")
	b := complete("k", "multipart-two")
	if len(a.VersionID) != uuidLen || len(b.VersionID) != uuidLen || a.VersionID == b.VersionID {
		t.Fatalf("completed uploads got versions %q and %q", a.VersionID, b.VersionID)
	}
	h.mustGetV("vmpu", "k", a.VersionID, "multipart-one")
	h.mustGetV("vmpu", "k", "", "multipart-two")
	h.suspend("vmpu")
	c := complete("k", "multipart-null")
	if c.VersionID != storage.NullVersionID {
		t.Errorf("suspended completion reports %q", c.VersionID)
	}
	h.mustGetV("vmpu", "k", a.VersionID, "multipart-one")
}

func testVersionedSnapshotRead(t *testing.T, f Factory) {
	h := newHarness(t, f)
	h.mkbucket("vsnap")
	h.enable("vsnap")
	body := strings.Repeat("snapshot-", 1000)
	v1 := h.put("vsnap", "k", body).VersionID
	h.put("vsnap", "k", "newer")

	rc, _, err := h.be.GetObject(bg, "vsnap", "k", storage.GetOptions{VersionID: v1})
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	head := make([]byte, 100)
	if _, err := io.ReadFull(rc, head); err != nil {
		t.Fatal(err)
	}
	// The version is removed while the reader is open.
	h.del("vsnap", "k", v1)
	rest, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read after the version was removed: %v", err)
	}
	if got := string(head) + string(rest); got != body {
		t.Errorf("stream changed under the reader (%d bytes, want %d)", len(got), len(body))
	}
	_, _, err = h.getV("vsnap", "k", v1)
	wantErr(t, "removed version", err, storage.ErrVersionNotFound)
}

func testVersionedPreconditions(t *testing.T, f Factory) {
	h := newHarness(t, f)
	h.mkbucket("vpre")
	h.enable("vpre")
	h.put("vpre", "k", "v")
	h.del("vpre", "k", "") // latest is now a marker: the key "does not exist"

	_, err := h.be.PutObject(bg, "vpre", "k", strings.NewReader("w"), 1, storage.PutOptions{IfNoneMatch: "*"})
	if err != nil {
		t.Errorf("If-None-Match: * over a delete marker: %v", err)
	}
	h.del("vpre", "k", "")
	_, err = h.be.PutObject(bg, "vpre", "k", strings.NewReader("x"), 1, storage.PutOptions{IfMatch: md5hex("w")})
	wantErr(t, "If-Match over a delete marker", err, storage.ErrPreconditionFailed)
}

func testVersionedConcurrentPuts(t *testing.T, f Factory) {
	h := newHarness(t, f)
	h.mkbucket("vconc")
	h.enable("vconc")
	const writers = 16
	ids := make([]string, writers)
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body := "writer-" + strings.Repeat("x", i)
			info, err := h.be.PutObject(bg, "vconc", "k", strings.NewReader(body), int64(len(body)), storage.PutOptions{})
			if err != nil {
				t.Errorf("writer %d: %v", i, err)
				return
			}
			ids[i] = info.VersionID
		}()
	}
	wg.Wait()
	seen := map[string]bool{}
	for i, id := range ids {
		if id == "" {
			continue
		}
		if seen[id] {
			t.Errorf("version %s issued to two writers", id)
		}
		seen[id] = true
		h.mustGetV("vconc", "k", id, "writer-"+strings.Repeat("x", i))
	}
	if len(seen) != writers {
		t.Errorf("%d distinct versions, want %d", len(seen), writers)
	}
	_, info, err := h.getV("vconc", "k", "")
	if err != nil || !seen[info.VersionID] {
		t.Errorf("latest = %+v, %v; want one of the writers' versions", info, err)
	}
}

func (h *harness) listVersions(bucket string, opts storage.ListOptions) storage.ListVersionsResult {
	h.t.Helper()
	res, err := h.be.ListObjectVersions(bg, bucket, opts)
	if err != nil {
		h.t.Fatalf("ListObjectVersions(%s, %+v): %v", bucket, opts, err)
	}
	return res
}

// allVersions pages through the whole listing with the given page size.
func (h *harness) allVersions(bucket string, base storage.ListOptions, pageSize int) (versions []storage.ObjectInfo, prefixes []string) {
	h.t.Helper()
	opts := base
	opts.MaxKeys = pageSize
	for pages := 0; ; pages++ {
		if pages > 10000 {
			h.t.Fatal("version listing does not terminate")
		}
		res := h.listVersions(bucket, opts)
		versions = append(versions, res.Versions...)
		prefixes = append(prefixes, res.Prefixes...)
		if !res.IsTruncated {
			return versions, prefixes
		}
		if res.NextMarker == "" {
			h.t.Fatalf("truncated page without a NextMarker: %+v", res)
		}
		opts.Marker, opts.VersionIDMarker = res.NextMarker, res.NextVersionIDMarker
	}
}

func idsOf(vs []storage.ObjectInfo) string {
	var b strings.Builder
	for _, v := range vs {
		b.WriteString(v.Name + "@" + v.VersionID)
		if v.DeleteMarker {
			b.WriteString("(dm)")
		}
		b.WriteString(" ")
	}
	return b.String()
}

func testVersionedListing(t *testing.T, f Factory) {
	h := newHarness(t, f)
	h.mkbucket("vlist")
	h.enable("vlist")
	a1 := h.put("vlist", "a", "a1").VersionID
	a2 := h.put("vlist", "a", "a2").VersionID
	am := h.del("vlist", "a", "").VersionID
	b1 := h.put("vlist", "dir/b", "b1").VersionID
	c1 := h.put("vlist", "dir/c", "c1").VersionID
	h.suspend("vlist")
	cn := h.put("vlist", "dir/c", "c-null") // null version, after a real one
	if cn.VersionID != storage.NullVersionID {
		t.Fatalf("null put reported %q", cn.VersionID)
	}

	res := h.listVersions("vlist", storage.ListOptions{})
	want := "a@" + am + "(dm) a@" + a2 + " a@" + a1 + " dir/b@" + b1 + " dir/c@null dir/c@" + c1 + " "
	if got := idsOf(res.Versions); got != want {
		t.Fatalf("listing\n got %s\nwant %s", got, want)
	}
	if res.IsTruncated || len(res.Prefixes) != 0 {
		t.Errorf("truncated=%v prefixes=%v", res.IsTruncated, res.Prefixes)
	}
	latest := map[string]string{}
	for _, v := range res.Versions {
		if v.IsLatest {
			if prev, dup := latest[v.Name]; dup {
				t.Errorf("two latest versions for %s: %s and %s", v.Name, prev, v.VersionID)
			}
			latest[v.Name] = v.VersionID
		}
		if v.Bucket != "vlist" {
			t.Errorf("bucket %q", v.Bucket)
		}
		if !v.DeleteMarker && v.ETag == "" {
			t.Errorf("version %s@%s has no ETag", v.Name, v.VersionID)
		}
	}
	if latest["a"] != am || latest["dir/b"] != b1 || latest["dir/c"] != storage.NullVersionID {
		t.Errorf("latest flags: %v", latest)
	}

	t.Run("prefix and delimiter", func(t *testing.T) {
		res := h.listVersions("vlist", storage.ListOptions{Delimiter: "/"})
		if len(res.Prefixes) != 1 || res.Prefixes[0] != "dir/" {
			t.Errorf("prefixes = %v", res.Prefixes)
		}
		if got := idsOf(res.Versions); got != "a@"+am+"(dm) a@"+a2+" a@"+a1+" " {
			t.Errorf("versions = %s", got)
		}
		res = h.listVersions("vlist", storage.ListOptions{Prefix: "dir/"})
		if len(res.Versions) != 3 || res.Versions[0].Name != "dir/b" {
			t.Errorf("prefix dir/ = %s", idsOf(res.Versions))
		}
	})
	t.Run("an unversioned bucket reports no version IDs", func(t *testing.T) {
		h.mkbucket("vplain")
		h.put("vplain", "k", "v")
		r := h.listVersions("vplain", storage.ListOptions{})
		if len(r.Versions) != 1 || r.Versions[0].VersionID != "" || !r.Versions[0].IsLatest {
			t.Errorf("listing = %+v", r.Versions)
		}
	})
	t.Run("missing bucket", func(t *testing.T) {
		_, err := h.be.ListObjectVersions(bg, "nope-bucket", storage.ListOptions{})
		wantErr(t, "ListObjectVersions", err, storage.ErrBucketNotFound)
	})
}

func testVersionedListingPagination(t *testing.T, f Factory) {
	h := newHarness(t, f)
	h.mkbucket("vpage")
	h.enable("vpage")
	keys := []string{"a", "b", "dir/x", "dir/y", "z"}
	for i, k := range keys {
		for v := 0; v <= i%3+1; v++ {
			h.put("vpage", k, fmt.Sprintf("%s-%d", k, v))
		}
		if i%2 == 0 {
			h.del("vpage", k, "")
		}
	}
	whole, _ := h.allVersions("vpage", storage.ListOptions{}, 1000)
	if len(whole) < 12 {
		t.Fatalf("only %d versions", len(whole))
	}
	for _, size := range []int{1, 2, 3, 5, 7} {
		got, _ := h.allVersions("vpage", storage.ListOptions{}, size)
		if idsOf(got) != idsOf(whole) {
			t.Errorf("page size %d:\n got %s\nwant %s", size, idsOf(got), idsOf(whole))
		}
		gv, gp := h.allVersions("vpage", storage.ListOptions{Delimiter: "/"}, size)
		wv, wp := h.allVersions("vpage", storage.ListOptions{Delimiter: "/"}, 1000)
		if idsOf(gv) != idsOf(wv) || strings.Join(gp, ",") != strings.Join(wp, ",") {
			t.Errorf("page size %d with a delimiter differs", size)
		}
	}

	t.Run("marker semantics", func(t *testing.T) {
		// Key marker alone skips the whole key.
		res := h.listVersions("vpage", storage.ListOptions{Marker: "b"})
		if len(res.Versions) == 0 || res.Versions[0].Name != "dir/x" {
			t.Errorf("after key marker b: %s", idsOf(res.Versions))
		}
		// Key + version marker resumes inside the key.
		var bVersions []storage.ObjectInfo
		for _, v := range whole {
			if v.Name == "b" {
				bVersions = append(bVersions, v)
			}
		}
		if len(bVersions) < 3 {
			t.Fatalf("b has %d versions", len(bVersions))
		}
		res = h.listVersions("vpage", storage.ListOptions{Marker: "b", VersionIDMarker: bVersions[0].VersionID, Prefix: "b"})
		if len(res.Versions) != len(bVersions)-1 || res.Versions[0].VersionID != bVersions[1].VersionID {
			t.Errorf("after (b, newest): %s", idsOf(res.Versions))
		}
		// A marker version that no longer exists resumes at the next key.
		h.del("vpage", "b", bVersions[1].VersionID)
		res = h.listVersions("vpage", storage.ListOptions{Marker: "b", VersionIDMarker: bVersions[1].VersionID})
		if len(res.Versions) == 0 || res.Versions[0].Name != "dir/x" {
			t.Errorf("after a vanished marker version: %s", idsOf(res.Versions))
		}
	})
}

// versionModel is a reference implementation of one key's version list.
type versionModel struct {
	versions []modelEntry // newest first
}

type modelEntry struct {
	id     string // reported: UUID or "null"
	marker bool
}

func (m *versionModel) add(e modelEntry) {
	if e.id == storage.NullVersionID { // replaces the null version
		m.remove(e.id)
	}
	m.versions = append([]modelEntry{e}, m.versions...)
}

func (m *versionModel) remove(id string) {
	for i, e := range m.versions {
		if e.id == id {
			m.versions = append(m.versions[:i:i], m.versions[i+1:]...)
			return
		}
	}
}

func (m *versionModel) String(key string) string {
	var b strings.Builder
	for _, e := range m.versions {
		b.WriteString(key + "@" + e.id)
		if e.marker {
			b.WriteString("(dm)")
		}
		b.WriteString(" ")
	}
	return b.String()
}

// testVersionedInterleavedModel interleaves PUT, DELETE (marker), DELETE of
// a version and state changes across several keys, and after every step
// checks the listing against a reference model: newest first within each
// key, keys ascending, identical when repeated, identical when paged.
func testVersionedInterleavedModel(t *testing.T, f Factory) {
	h := newHarness(t, f)
	h.mkbucket("vmodel")
	h.enable("vmodel")
	keys := []string{"k1", "k2", "dir/k3"}
	models := map[string]*versionModel{}
	for _, k := range keys {
		models[k] = &versionModel{}
	}
	state := storage.VersioningEnabled
	rng := rand.New(rand.NewSource(20260101))
	expected := func() string {
		sorted := append([]string(nil), keys...)
		sort.Strings(sorted)
		var b strings.Builder
		for _, k := range sorted {
			b.WriteString(models[k].String(k))
		}
		return b.String()
	}
	for step := 0; step < 90; step++ {
		k := keys[rng.Intn(len(keys))]
		m := models[k]
		switch op := rng.Intn(10); {
		case op < 4: // PUT
			info := h.put("vmodel", k, fmt.Sprintf("body-%d", step))
			id := info.VersionID
			if state == storage.VersioningSuspended {
				id = storage.NullVersionID
			}
			m.add(modelEntry{id: id})
		case op < 6: // DELETE without a version: a marker
			res := h.del("vmodel", k, "")
			id := res.VersionID
			if state == storage.VersioningSuspended {
				id = storage.NullVersionID
			}
			m.add(modelEntry{id: id, marker: true})
		case op < 9: // DELETE one version
			if len(m.versions) == 0 {
				continue
			}
			e := m.versions[rng.Intn(len(m.versions))]
			h.del("vmodel", k, e.id)
			m.remove(e.id)
		default: // flip the state
			if state == storage.VersioningEnabled {
				h.suspend("vmodel")
				state = storage.VersioningSuspended
			} else {
				h.enable("vmodel")
				state = storage.VersioningEnabled
			}
		}
		got, _ := h.allVersions("vmodel", storage.ListOptions{}, 1000)
		if idsOf(got) != expected() {
			t.Fatalf("step %d: listing differs from the model\n got %s\nwant %s", step, idsOf(got), expected())
		}
		if again, _ := h.allVersions("vmodel", storage.ListOptions{}, 1000); idsOf(again) != idsOf(got) {
			t.Fatalf("step %d: two listings with no change in between differ", step)
		}
		if step%9 == 0 {
			paged, _ := h.allVersions("vmodel", storage.ListOptions{}, 2)
			if idsOf(paged) != idsOf(got) {
				t.Fatalf("step %d: paged listing differs\n got %s\nwant %s", step, idsOf(paged), idsOf(got))
			}
		}
	}
	// Every version the model has is readable, and each key's latest is the
	// model's newest entry.
	for _, k := range keys {
		m := models[k]
		for _, e := range m.versions {
			_, _, err := h.getV("vmodel", k, e.id)
			switch {
			case e.marker:
				wantErr(t, k+"@"+e.id, err, storage.ErrIsDeleteMarker)
			case err != nil:
				t.Errorf("%s@%s: %v", k, e.id, err)
			}
		}
	}
}

// testVersionedConcurrentListing runs writers, deleters and listers
// together. Listers must never see a key's versions out of order, a
// duplicated version, or two latest entries; afterwards the listing holds
// exactly the versions the writers got IDs for and nobody removed.
func testVersionedConcurrentListing(t *testing.T, f Factory) {
	h := newHarness(t, f)
	h.mkbucket("vconclist")
	h.enable("vconclist")
	keys := []string{"c1", "c2", "c3"}

	var mu sync.Mutex
	added := map[string]bool{}   // key@id
	removed := map[string]bool{} // key@id
	record := func(m map[string]bool, key, id string) {
		mu.Lock()
		m[key+"@"+id] = true
		mu.Unlock()
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})

	for w := 0; w < 6; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(w) + 1))
			var mine []struct{ key, id string }
			for i := 0; i < 25; i++ {
				key := keys[rng.Intn(len(keys))]
				switch r := rng.Intn(10); {
				case r < 6:
					body := fmt.Sprintf("w%d-%d", w, i)
					info, err := h.be.PutObject(bg, "vconclist", key, strings.NewReader(body), int64(len(body)), storage.PutOptions{})
					if err != nil {
						t.Errorf("put: %v", err)
						return
					}
					record(added, key, info.VersionID)
					mine = append(mine, struct{ key, id string }{key, info.VersionID})
				case r < 8:
					res, err := h.be.DeleteObject(bg, "vconclist", key, storage.DeleteOptions{})
					if err != nil {
						t.Errorf("delete: %v", err)
						return
					}
					record(added, key, res.VersionID)
				default:
					if len(mine) == 0 {
						continue
					}
					j := rng.Intn(len(mine))
					v := mine[j]
					mine = append(mine[:j], mine[j+1:]...)
					if _, err := h.be.DeleteObject(bg, "vconclist", v.key, storage.DeleteOptions{VersionID: v.id}); err != nil {
						t.Errorf("delete version: %v", err)
						return
					}
					record(removed, v.key, v.id)
				}
			}
		}()
	}
	var lw sync.WaitGroup
	for l := 0; l < 2; l++ {
		lw.Add(1)
		go func() {
			defer lw.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				res, err := h.be.ListObjectVersions(bg, "vconclist", storage.ListOptions{})
				if err != nil {
					t.Errorf("list: %v", err)
					return
				}
				seen := map[string]bool{}
				var prevKey string
				var prevTime time.Time
				latestSeen := map[string]bool{}
				for i, v := range res.Versions {
					id := v.Name + "@" + v.VersionID
					if seen[id] {
						t.Errorf("version %s listed twice", id)
					}
					seen[id] = true
					if i > 0 && v.Name < prevKey {
						t.Errorf("keys out of order: %s after %s", v.Name, prevKey)
					}
					if v.Name == prevKey {
						if v.ModTime.After(prevTime) {
							t.Errorf("%s: %s is newer than the entry before it", v.Name, v.VersionID)
						}
						if v.IsLatest {
							t.Errorf("%s: a later entry is flagged latest", v.Name)
						}
					} else if !v.IsLatest {
						t.Errorf("%s: first entry of a key is not latest", v.Name)
					}
					if v.IsLatest {
						if latestSeen[v.Name] {
							t.Errorf("%s has two latest entries", v.Name)
						}
						latestSeen[v.Name] = true
					}
					prevKey, prevTime = v.Name, v.ModTime
				}
			}
		}()
	}
	wg.Wait()
	close(stop)
	lw.Wait()

	final, _ := h.allVersions("vconclist", storage.ListOptions{}, 1000)
	got := map[string]bool{}
	for _, v := range final {
		got[v.Name+"@"+v.VersionID] = true
	}
	for id := range added {
		if removed[id] {
			if got[id] {
				t.Errorf("removed version %s is still listed", id)
			}
			continue
		}
		if !got[id] {
			t.Errorf("version %s was created and never removed but is not listed", id)
		}
	}
	if len(got) != len(added)-len(removed) {
		t.Errorf("%d versions listed, want %d", len(got), len(added)-len(removed))
	}
}

// A bucket whose keys were all "deleted" still holds their versions and
// delete markers, so it is not empty (as in S3).
func testVersionedBucketNotEmpty(t *testing.T, f Factory) {
	h := newHarness(t, f)
	h.mkbucket("vnotempty")
	h.enable("vnotempty")
	v := h.put("vnotempty", "k", "x").VersionID
	marker := h.del("vnotempty", "k", "").VersionID

	err := h.be.DeleteBucket(bg, "vnotempty", storage.DeleteBucketOptions{})
	wantErr(t, "bucket holding a version and a marker", err, storage.ErrBucketNotEmpty)
	h.del("vnotempty", "k", v)
	err = h.be.DeleteBucket(bg, "vnotempty", storage.DeleteBucketOptions{})
	wantErr(t, "bucket holding only a delete marker", err, storage.ErrBucketNotEmpty)
	h.del("vnotempty", "k", marker)
	if err := h.be.DeleteBucket(bg, "vnotempty", storage.DeleteBucketOptions{}); err != nil {
		t.Errorf("bucket with nothing left: %v", err)
	}
	// Force removes everything, versions included.
	h.mkbucket("vforce")
	h.enable("vforce")
	h.put("vforce", "k", "x")
	h.del("vforce", "k", "")
	if err := h.be.DeleteBucket(bg, "vforce", storage.DeleteBucketOptions{Force: true}); err != nil {
		t.Errorf("forced delete: %v", err)
	}
}
