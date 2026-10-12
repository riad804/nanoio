package storagetest

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"nanoio/internal/storage"
)

// RunObjectLock executes the S3 Object Lock suite. A backend adopts it when
// it implements object lock; it builds on RunVersioned.
func RunObjectLock(t *testing.T, newBackend Factory) {
	for _, tc := range []struct {
		name string
		fn   func(*testing.T, Factory)
	}{
		{"LockBucketSettings", testLockBucketSettings},
		{"LockDeletionMatrix", testLockDeletionMatrix},
		{"LockRetentionChangeMatrix", testLockRetentionChangeMatrix},
		{"LockDeleteWithoutVersionMakesMarker", testLockMarkerWithoutVersion},
		{"LockExpiry", testLockExpiry},
		{"LockInvalidRetention", testLockInvalidRetention},
		{"LockDefaultRetention", testLockDefaultRetention},
		{"LockMultipart", testLockMultipart},
		{"LockForceDeleteBucket", testLockForceDeleteBucket},
		{"LockBadTargets", testLockBadTargets},
		{"LockRefusalChangesNothing", testLockRefusalChangesNothing},
		{"LockConcurrentDeletes", testLockConcurrentDeletes},
	} {
		t.Run(tc.name, func(t *testing.T) { tc.fn(t, newBackend) })
	}
}

func (h *harness) mkLockBucket(name string) {
	h.t.Helper()
	if err := h.be.MakeBucket(bg, name, storage.MakeBucketOptions{ObjectLock: true}); err != nil {
		h.t.Fatalf("MakeBucket(%q, object lock): %v", name, err)
	}
}

// putLocked writes a version with the given lock and returns its ID.
func (h *harness) putLocked(bucket, key, body string, r storage.Retention, hold bool) storage.ObjectInfo {
	h.t.Helper()
	info, err := h.be.PutObject(bg, bucket, key, strings.NewReader(body), int64(len(body)),
		storage.PutOptions{Retention: r, LegalHold: hold})
	if err != nil {
		h.t.Fatalf("PutObject(%s/%s, %+v hold=%v): %v", bucket, key, r, hold, err)
	}
	if info.VersionID == "" || info.VersionID == storage.NullVersionID {
		h.t.Fatalf("PutObject on an object lock bucket returned version %q, want a UUID", info.VersionID)
	}
	return info
}

func (h *harness) stat(bucket, key, version string) storage.ObjectInfo {
	h.t.Helper()
	info, err := h.be.StatObject(bg, bucket, key, storage.GetOptions{VersionID: version})
	if err != nil {
		h.t.Fatalf("StatObject(%s/%s@%s): %v", bucket, key, version, err)
	}
	return info
}

func sameInstant(a, b time.Time) bool { return a.Truncate(time.Millisecond).Equal(b.Truncate(time.Millisecond)) }

func testLockBucketSettings(t *testing.T, f Factory) {
	h := newHarness(t, f)
	h.mkLockBucket("lockset")

	// A bucket created with object lock is born versioned.
	if c, err := h.be.GetBucketVersioning(bg, "lockset"); err != nil || c.State != storage.VersioningEnabled {
		t.Fatalf("versioning = %+v, %v; want Enabled", c, err)
	}
	cfg, err := h.be.GetBucketObjectLock(bg, "lockset")
	if err != nil || !cfg.Enabled || cfg.Default != nil {
		t.Fatalf("object lock = %+v, %v; want enabled, no default", cfg, err)
	}
	// Versioning cannot be suspended on it, and the refusal changes nothing.
	wantErr(t, "suspend", h.be.SetBucketVersioning(bg, "lockset", storage.VersioningSuspended), storage.ErrInvalidBucketState)
	if c, _ := h.be.GetBucketVersioning(bg, "lockset"); c.State != storage.VersioningEnabled {
		t.Errorf("versioning after refused suspend = %q", c.State)
	}
	if err := h.be.SetBucketVersioning(bg, "lockset", storage.VersioningEnabled); err != nil {
		t.Errorf("re-enabling: %v", err)
	}

	// The default retention can be set, replaced and cleared; the lock
	// itself cannot be turned off.
	def := &storage.DefaultRetention{Mode: storage.RetentionGovernance, Days: 7}
	if err := h.be.SetBucketObjectLock(bg, "lockset", storage.ObjectLockConfig{Enabled: true, Default: def}); err != nil {
		t.Fatalf("set default: %v", err)
	}
	cfg, _ = h.be.GetBucketObjectLock(bg, "lockset")
	if cfg.Default == nil || *cfg.Default != *def {
		t.Errorf("default = %+v, want %+v", cfg.Default, def)
	}
	years := &storage.DefaultRetention{Mode: storage.RetentionCompliance, Years: 1}
	if err := h.be.SetBucketObjectLock(bg, "lockset", storage.ObjectLockConfig{Enabled: true, Default: years}); err != nil {
		t.Fatalf("replace default: %v", err)
	}
	if err := h.be.SetBucketObjectLock(bg, "lockset", storage.ObjectLockConfig{Enabled: true}); err != nil {
		t.Fatalf("clear default: %v", err)
	}
	if cfg, _ = h.be.GetBucketObjectLock(bg, "lockset"); cfg.Default != nil || !cfg.Enabled {
		t.Errorf("after clearing: %+v", cfg)
	}
	wantErr(t, "disable", h.be.SetBucketObjectLock(bg, "lockset", storage.ObjectLockConfig{}), storage.ErrInvalidBucketState)
	for _, bad := range []storage.DefaultRetention{
		{Mode: storage.RetentionGovernance},
		{Mode: storage.RetentionGovernance, Days: 1, Years: 1},
		{Mode: "LOOSE", Days: 1},
		{Mode: storage.RetentionCompliance, Days: -1},
	} {
		err := h.be.SetBucketObjectLock(bg, "lockset", storage.ObjectLockConfig{Enabled: true, Default: &bad})
		wantErr(t, "bad default", err, storage.ErrInvalidRetention)
	}

	// A bucket created without object lock cannot have it enabled later,
	// and takes no lock on its objects.
	h.mkbucket("nolock")
	cfg, err = h.be.GetBucketObjectLock(bg, "nolock")
	if err != nil || cfg.Enabled {
		t.Fatalf("plain bucket object lock = %+v, %v", cfg, err)
	}
	wantErr(t, "enable later", h.be.SetBucketObjectLock(bg, "nolock", storage.ObjectLockConfig{Enabled: true}), storage.ErrInvalidBucketState)
	_, err = h.be.PutObject(bg, "nolock", "k", strings.NewReader("x"), 1,
		storage.PutOptions{Retention: storage.Retention{Mode: storage.RetentionGovernance, Until: time.Now().Add(time.Hour)}})
	wantErr(t, "retention on a plain bucket", err, storage.ErrObjectLockNotEnabled)
	_, err = h.be.PutObject(bg, "nolock", "k", strings.NewReader("x"), 1, storage.PutOptions{LegalHold: true})
	wantErr(t, "legal hold on a plain bucket", err, storage.ErrObjectLockNotEnabled)
	info := h.put("nolock", "k", "x")
	_, err = h.be.SetObjectRetention(bg, storage.ObjectRef{Bucket: "nolock", Object: "k", VersionID: info.VersionID},
		storage.Retention{Mode: storage.RetentionGovernance, Until: time.Now().Add(time.Hour)}, storage.RetentionOptions{})
	wantErr(t, "SetObjectRetention on a plain bucket", err, storage.ErrObjectLockNotEnabled)
	_, err = h.be.SetObjectLegalHold(bg, storage.ObjectRef{Bucket: "nolock", Object: "k"}, true)
	wantErr(t, "SetObjectLegalHold on a plain bucket", err, storage.ErrObjectLockNotEnabled)
	wantErr(t, "missing bucket", func() error {
		_, err := h.be.GetBucketObjectLock(bg, "nosuchbucket")
		return err
	}(), storage.ErrBucketNotFound)
}

// lockCase is one row of the enforcement matrix: a version created with
// (mode, hours until, hold) and what each caller may then do to it.
type lockCase struct {
	name  string
	mode  storage.RetentionMode
	hours int // retain-until, hours from now
	hold  bool
	// delete is the outcome of DeleteObject of the version.
	deleteOK       bool
	deleteBypassOK bool
}

func (c lockCase) retention() storage.Retention {
	if c.mode == "" {
		return storage.Retention{}
	}
	return storage.Retention{Mode: c.mode, Until: time.Now().Add(time.Duration(c.hours) * time.Hour)}
}

// testLockDeletionMatrix is the deletion half of the enforcement matrix, run
// against every backend.
func testLockDeletionMatrix(t *testing.T, f Factory) {
	cases := []lockCase{
		{name: "no lock", deleteOK: true, deleteBypassOK: true},
		{name: "compliance", mode: storage.RetentionCompliance, hours: 24, deleteOK: false, deleteBypassOK: false},
		{name: "compliance + hold", mode: storage.RetentionCompliance, hours: 24, hold: true},
		{name: "governance", mode: storage.RetentionGovernance, hours: 24, deleteOK: false, deleteBypassOK: true},
		{name: "governance + hold", mode: storage.RetentionGovernance, hours: 24, hold: true, deleteOK: false, deleteBypassOK: false},
		{name: "legal hold only", hold: true, deleteOK: false, deleteBypassOK: false},
	}
	h := newHarness(t, f)
	h.mkLockBucket("lockdel")
	for i, c := range cases {
		key := "k" + string(rune('a'+i))
		for _, bypass := range []bool{false, true} {
			t.Run(c.name+map[bool]string{false: "", true: "/bypass"}[bypass], func(t *testing.T) {
				h.t = t
				want := c.deleteOK
				if bypass {
					want = c.deleteBypassOK
				}
				info := h.putLocked("lockdel", key+map[bool]string{false: "n", true: "b"}[bypass], "data", c.retention(), c.hold)
				k := info.Name
				_, err := h.be.DeleteObject(bg, "lockdel", k, storage.DeleteOptions{VersionID: info.VersionID, BypassGovernance: bypass})
				if want {
					if err != nil {
						t.Fatalf("DeleteObject = %v, want success", err)
					}
					// Gone: the key had no other version, so backends differ on
					// whether they say "no such version" or "no such key".
					if _, err := h.be.StatObject(bg, "lockdel", k, storage.GetOptions{VersionID: info.VersionID}); !errors.Is(err, storage.ErrVersionNotFound) && !errors.Is(err, storage.ErrObjectNotFound) {
						t.Errorf("version still there after delete: %v", err)
					}
					return
				}
				if !errors.Is(err, storage.ErrObjectLocked) {
					t.Fatalf("DeleteObject = %v, want ErrObjectLocked", err)
				}
				// The refusal removed nothing: the version still reads back.
				h.mustGetV("lockdel", k, info.VersionID, "data")
			})
		}
	}
}

// testLockRetentionChangeMatrix is the modification half: what a retention
// may become.
func testLockRetentionChangeMatrix(t *testing.T, f Factory) {
	h := newHarness(t, f)
	h.mkLockBucket("lockchg")
	hrs := func(n int) time.Time { return time.Now().Add(time.Duration(n) * time.Hour) }
	gov := func(n int) storage.Retention { return storage.Retention{Mode: storage.RetentionGovernance, Until: hrs(n)} }
	comp := func(n int) storage.Retention { return storage.Retention{Mode: storage.RetentionCompliance, Until: hrs(n)} }
	cases := []struct {
		name    string
		start   storage.Retention
		next    storage.Retention
		bypass  bool
		allowed bool
	}{
		{"none -> governance", storage.Retention{}, gov(5), false, true},
		{"none -> compliance", storage.Retention{}, comp(5), false, true},

		{"compliance extend", comp(5), comp(10), false, true},
		{"compliance shorten", comp(10), comp(5), false, false},
		{"compliance shorten with bypass", comp(10), comp(5), true, false},
		{"compliance remove", comp(10), storage.Retention{}, false, false},
		{"compliance remove with bypass", comp(10), storage.Retention{}, true, false},
		{"compliance to governance", comp(5), gov(10), true, false},

		{"governance extend", gov(5), gov(10), false, true},
		{"governance to compliance", gov(5), comp(5), false, true},
		{"governance shorten", gov(10), gov(5), false, false},
		{"governance shorten with bypass", gov(10), gov(5), true, true},
		{"governance remove", gov(10), storage.Retention{}, false, false},
		{"governance remove with bypass", gov(10), storage.Retention{}, true, true},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h.t = t
			key := "k" + string(rune('A'+i))
			info := h.putLocked("lockchg", key, "v", c.start, false)
			ref := storage.ObjectRef{Bucket: "lockchg", Object: key, VersionID: info.VersionID}
			got, err := h.be.SetObjectRetention(bg, ref, c.next, storage.RetentionOptions{BypassGovernance: c.bypass})
			if c.allowed {
				if err != nil {
					t.Fatalf("SetObjectRetention = %v, want success", err)
				}
				if got.Retention.Mode != c.next.Mode || !sameInstant(got.Retention.Until, c.next.Until) {
					t.Errorf("returned retention = %+v, want %+v", got.Retention, c.next)
				}
				now := h.stat("lockchg", key, info.VersionID)
				if now.Retention.Mode != c.next.Mode || !sameInstant(now.Retention.Until, c.next.Until) {
					t.Errorf("stored retention = %+v, want %+v", now.Retention, c.next)
				}
				return
			}
			if !errors.Is(err, storage.ErrObjectLocked) {
				t.Fatalf("SetObjectRetention = %v, want ErrObjectLocked", err)
			}
			now := h.stat("lockchg", key, info.VersionID)
			if now.Retention.Mode != c.start.Mode || !sameInstant(now.Retention.Until, c.start.Until) {
				t.Errorf("a refused change altered the retention: %+v, want %+v", now.Retention, c.start)
			}
		})
	}

	t.Run("legal hold toggles freely and blocks deletion", func(t *testing.T) {
		h.t = t
		info := h.putLocked("lockchg", "holdkey", "v", comp(5), false)
		ref := storage.ObjectRef{Bucket: "lockchg", Object: "holdkey", VersionID: info.VersionID}
		got, err := h.be.SetObjectLegalHold(bg, ref, true)
		if err != nil || !got.LegalHold || got.Retention.Mode != storage.RetentionCompliance {
			t.Fatalf("hold on = %+v, %v", got, err)
		}
		if now := h.stat("lockchg", "holdkey", info.VersionID); !now.LegalHold {
			t.Error("hold not stored")
		}
		got, err = h.be.SetObjectLegalHold(bg, ref, false)
		if err != nil || got.LegalHold || got.Retention.Mode != storage.RetentionCompliance {
			t.Fatalf("hold off = %+v, %v (turning the hold off must keep the retention)", got, err)
		}
		// A hold on a version whose retention has ended still blocks.
		gov := h.putLocked("lockchg", "holdgov", "v", storage.Retention{}, false)
		gref := storage.ObjectRef{Bucket: "lockchg", Object: "holdgov", VersionID: gov.VersionID}
		if _, err := h.be.SetObjectLegalHold(bg, gref, true); err != nil {
			t.Fatal(err)
		}
		_, err = h.be.DeleteObject(bg, "lockchg", "holdgov", storage.DeleteOptions{VersionID: gov.VersionID, BypassGovernance: true})
		wantErr(t, "delete under hold", err, storage.ErrObjectLocked)
		if _, err := h.be.SetObjectLegalHold(bg, gref, false); err != nil {
			t.Fatal(err)
		}
		if _, err := h.be.DeleteObject(bg, "lockchg", "holdgov", storage.DeleteOptions{VersionID: gov.VersionID}); err != nil {
			t.Errorf("delete after the hold was lifted: %v", err)
		}
	})
}

// testLockMarkerWithoutVersion pins the other half of the deletion rule:
// DeleteObject without a version ID is not refused by a lock. It adds a
// delete marker and removes nothing, so only the version is protected.
func testLockMarkerWithoutVersion(t *testing.T, f Factory) {
	h := newHarness(t, f)
	h.mkLockBucket("lockmark")
	for _, c := range []lockCase{
		{name: "compliance", mode: storage.RetentionCompliance, hours: 24},
		{name: "governance", mode: storage.RetentionGovernance, hours: 24},
		{name: "legal hold", hold: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			h.t = t
			key := "m-" + strings.ReplaceAll(c.name, " ", "-")
			info := h.putLocked("lockmark", key, "data", c.retention(), c.hold)
			res, err := h.be.DeleteObject(bg, "lockmark", key, storage.DeleteOptions{})
			if err != nil {
				t.Fatalf("DeleteObject without a version = %v, want a delete marker", err)
			}
			if !res.DeleteMarker || res.VersionID == "" || res.VersionID == info.VersionID {
				t.Fatalf("result = %+v, want a new delete marker", res)
			}
			// The key now reads as deleted, the protected version is intact.
			if _, err := h.be.StatObject(bg, "lockmark", key, storage.GetOptions{}); !errors.Is(err, storage.ErrObjectNotFound) {
				t.Errorf("latest after marker: %v, want not found", err)
			}
			h.mustGetV("lockmark", key, info.VersionID, "data")
			// Removing the marker itself is allowed (it carries no lock) and
			// undeletes the key.
			if _, err := h.be.DeleteObject(bg, "lockmark", key, storage.DeleteOptions{VersionID: res.VersionID}); err != nil {
				t.Fatalf("removing the marker: %v", err)
			}
			h.mustGetV("lockmark", key, "", "data")
		})
	}
}

// testLockExpiry: retention that has ended protects nothing, and can be
// replaced. It waits for real time to pass; the dates are the shortest the
// future-date check allows.
func testLockExpiry(t *testing.T, f Factory) {
	h := newHarness(t, f)
	h.mkLockBucket("lockexp")
	short := func(mode storage.RetentionMode) storage.Retention {
		return storage.Retention{Mode: mode, Until: time.Now().Add(1500 * time.Millisecond)}
	}
	comp := h.putLocked("lockexp", "comp", "c", short(storage.RetentionCompliance), false)
	gov := h.putLocked("lockexp", "gov", "g", short(storage.RetentionGovernance), false)
	again := h.putLocked("lockexp", "again", "a", short(storage.RetentionCompliance), false)

	_, err := h.be.DeleteObject(bg, "lockexp", "comp", storage.DeleteOptions{VersionID: comp.VersionID})
	wantErr(t, "delete before expiry", err, storage.ErrObjectLocked)
	_, err = h.be.DeleteObject(bg, "lockexp", "gov", storage.DeleteOptions{VersionID: gov.VersionID})
	wantErr(t, "delete governance before expiry", err, storage.ErrObjectLocked)

	time.Sleep(1700 * time.Millisecond)

	if _, err := h.be.DeleteObject(bg, "lockexp", "comp", storage.DeleteOptions{VersionID: comp.VersionID}); err != nil {
		t.Errorf("delete compliance after expiry: %v", err)
	}
	if _, err := h.be.DeleteObject(bg, "lockexp", "gov", storage.DeleteOptions{VersionID: gov.VersionID}); err != nil {
		t.Errorf("delete governance after expiry: %v", err)
	}
	// An expired COMPLIANCE retention can be replaced, even with a shorter
	// future date than the one it had: it protects nothing now.
	ref := storage.ObjectRef{Bucket: "lockexp", Object: "again", VersionID: again.VersionID}
	next := storage.Retention{Mode: storage.RetentionGovernance, Until: time.Now().Add(time.Hour)}
	if _, err := h.be.SetObjectRetention(bg, ref, next, storage.RetentionOptions{}); err != nil {
		t.Errorf("replace expired retention: %v", err)
	}
}

func testLockInvalidRetention(t *testing.T, f Factory) {
	h := newHarness(t, f)
	h.mkLockBucket("lockinv")
	past := time.Now().Add(-time.Minute)
	future := time.Now().Add(time.Hour)
	bad := []struct {
		name string
		r    storage.Retention
	}{
		{"compliance in the past", storage.Retention{Mode: storage.RetentionCompliance, Until: past}},
		{"governance in the past", storage.Retention{Mode: storage.RetentionGovernance, Until: past}},
		{"compliance now", storage.Retention{Mode: storage.RetentionCompliance, Until: time.Now()}},
		{"unknown mode", storage.Retention{Mode: "LOOSE", Until: future}},
		{"mode without a date", storage.Retention{Mode: storage.RetentionGovernance}},
		{"date without a mode", storage.Retention{Until: future}},
	}
	good := h.putLocked("lockinv", "k", "v", storage.Retention{}, false)
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			_, err := h.be.PutObject(bg, "lockinv", "put-"+strings.ReplaceAll(c.name, " ", "-"), strings.NewReader("x"), 1,
				storage.PutOptions{Retention: c.r})
			if !errors.Is(err, storage.ErrInvalidRetention) {
				t.Errorf("PutObject = %v, want ErrInvalidRetention", err)
			}
			_, err = h.be.SetObjectRetention(bg, storage.ObjectRef{Bucket: "lockinv", Object: "k", VersionID: good.VersionID},
				c.r, storage.RetentionOptions{})
			if !errors.Is(err, storage.ErrInvalidRetention) {
				t.Errorf("SetObjectRetention = %v, want ErrInvalidRetention", err)
			}
		})
	}
	// Nothing was written by the refused puts.
	if keys := h.listKeys("lockinv"); len(keys) != 1 || keys[0] != "k" {
		t.Errorf("keys after refused puts = %v", keys)
	}
}

func testLockDefaultRetention(t *testing.T, f Factory) {
	h := newHarness(t, f)
	h.mkLockBucket("lockdef")
	if err := h.be.SetBucketObjectLock(bg, "lockdef", storage.ObjectLockConfig{Enabled: true,
		Default: &storage.DefaultRetention{Mode: storage.RetentionGovernance, Days: 2}}); err != nil {
		t.Fatal(err)
	}
	before := time.Now()
	info := h.putLocked("lockdef", "d", "v", storage.Retention{}, false)
	got := h.stat("lockdef", "d", info.VersionID).Retention
	if got.Mode != storage.RetentionGovernance {
		t.Fatalf("default mode = %q", got.Mode)
	}
	if want := before.AddDate(0, 0, 2); got.Until.Before(want) || got.Until.After(want.Add(time.Minute)) {
		t.Errorf("default until = %v, want about %v", got.Until, want)
	}
	// The default protects the version.
	_, err := h.be.DeleteObject(bg, "lockdef", "d", storage.DeleteOptions{VersionID: info.VersionID})
	wantErr(t, "delete under default retention", err, storage.ErrObjectLocked)

	// An explicit retention replaces the default rather than adding to it.
	exp := storage.Retention{Mode: storage.RetentionCompliance, Until: time.Now().Add(72 * time.Hour)}
	e := h.putLocked("lockdef", "e", "v", exp, false)
	if got := h.stat("lockdef", "e", e.VersionID).Retention; got.Mode != storage.RetentionCompliance || !sameInstant(got.Until, exp.Until) {
		t.Errorf("explicit retention = %+v, want %+v", got, exp)
	}
	// A legal hold alone still gets the default retention.
	l := h.putLocked("lockdef", "l", "v", storage.Retention{}, true)
	if got := h.stat("lockdef", "l", l.VersionID); !got.LegalHold || got.Retention.Mode != storage.RetentionGovernance {
		t.Errorf("hold + default = %+v", got)
	}
	// Years.
	if err := h.be.SetBucketObjectLock(bg, "lockdef", storage.ObjectLockConfig{Enabled: true,
		Default: &storage.DefaultRetention{Mode: storage.RetentionCompliance, Years: 1}}); err != nil {
		t.Fatal(err)
	}
	y := h.putLocked("lockdef", "y", "v", storage.Retention{}, false)
	if got := h.stat("lockdef", "y", y.VersionID).Retention; got.Mode != storage.RetentionCompliance || got.Until.Before(time.Now().AddDate(0, 11, 0)) {
		t.Errorf("one-year default = %+v", got)
	}
	// The default applies to writes made after it, not to what exists.
	if got := h.stat("lockdef", "d", info.VersionID).Retention; got.Mode != storage.RetentionGovernance {
		t.Errorf("an older version's retention changed with the default: %+v", got)
	}
	// Clearing it stops it applying.
	if err := h.be.SetBucketObjectLock(bg, "lockdef", storage.ObjectLockConfig{Enabled: true}); err != nil {
		t.Fatal(err)
	}
	n := h.putLocked("lockdef", "n", "v", storage.Retention{}, false)
	if got := h.stat("lockdef", "n", n.VersionID); !got.Retention.IsZero() || got.LegalHold {
		t.Errorf("write with no default has lock %+v", got)
	}
}

func testLockMultipart(t *testing.T, f Factory) {
	h := newHarness(t, f)
	h.mkLockBucket("lockmpu")
	until := time.Now().Add(time.Hour)
	id, err := h.be.NewMultipartUpload(bg, "lockmpu", "big", storage.PutOptions{
		Retention: storage.Retention{Mode: storage.RetentionCompliance, Until: until}, LegalHold: true})
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Repeat("p", 1024)
	part, err := h.be.PutObjectPart(bg, "lockmpu", "big", id, 1, strings.NewReader(body), int64(len(body)), storage.PartOptions{})
	if err != nil {
		t.Fatal(err)
	}
	info, err := h.be.CompleteMultipartUpload(bg, "lockmpu", "big", id,
		[]storage.CompletePart{{Number: 1, ETag: part.ETag}}, storage.PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	got := h.stat("lockmpu", "big", info.VersionID)
	if got.Retention.Mode != storage.RetentionCompliance || !sameInstant(got.Retention.Until, until) || !got.LegalHold {
		t.Errorf("completed upload lock = %+v hold=%v", got.Retention, got.LegalHold)
	}
	_, err = h.be.DeleteObject(bg, "lockmpu", "big", storage.DeleteOptions{VersionID: info.VersionID, BypassGovernance: true})
	wantErr(t, "delete multipart version", err, storage.ErrObjectLocked)

	// Asking for a lock a bucket cannot honour is refused at the start, not
	// after the parts have been uploaded.
	h.mkbucket("lockmpuplain")
	_, err = h.be.NewMultipartUpload(bg, "lockmpuplain", "x", storage.PutOptions{LegalHold: true})
	wantErr(t, "initiate on a plain bucket", err, storage.ErrObjectLockNotEnabled)
	_, err = h.be.NewMultipartUpload(bg, "lockmpu", "x", storage.PutOptions{
		Retention: storage.Retention{Mode: storage.RetentionGovernance, Until: time.Now().Add(-time.Hour)}})
	wantErr(t, "initiate with a past date", err, storage.ErrInvalidRetention)
}

func testLockForceDeleteBucket(t *testing.T, f Factory) {
	h := newHarness(t, f)
	h.mkLockBucket("lockforce")
	info := h.putLocked("lockforce", "k", "v", storage.Retention{Mode: storage.RetentionGovernance, Until: time.Now().Add(time.Hour)}, false)

	// Without Force a bucket with versions is not empty; with Force it must
	// still not be a way around the lock.
	wantErr(t, "delete non-empty", h.be.DeleteBucket(bg, "lockforce", storage.DeleteBucketOptions{}), storage.ErrBucketNotEmpty)
	wantErr(t, "force delete", h.be.DeleteBucket(bg, "lockforce", storage.DeleteBucketOptions{Force: true}), storage.ErrObjectLocked)
	h.mustGetV("lockforce", "k", info.VersionID, "v")

	// Once nothing in it is protected, Force works.
	ref := storage.ObjectRef{Bucket: "lockforce", Object: "k", VersionID: info.VersionID}
	if _, err := h.be.SetObjectRetention(bg, ref, storage.Retention{}, storage.RetentionOptions{BypassGovernance: true}); err != nil {
		t.Fatal(err)
	}
	if err := h.be.DeleteBucket(bg, "lockforce", storage.DeleteBucketOptions{Force: true}); err != nil {
		t.Errorf("force delete of an unprotected bucket: %v", err)
	}
}

func testLockBadTargets(t *testing.T, f Factory) {
	h := newHarness(t, f)
	h.mkLockBucket("lockbad")
	until := storage.Retention{Mode: storage.RetentionGovernance, Until: time.Now().Add(time.Hour)}
	info := h.putLocked("lockbad", "k", "v", storage.Retention{}, false)
	mark := h.del("lockbad", "k", "")

	ref := func(key, ver string) storage.ObjectRef {
		return storage.ObjectRef{Bucket: "lockbad", Object: key, VersionID: ver}
	}
	cases := []struct {
		name string
		ref  storage.ObjectRef
		want error
	}{
		{"missing key", ref("nokey", ""), storage.ErrObjectNotFound},
		{"missing version", ref("k", "00000000-0000-4000-8000-000000000000"), storage.ErrVersionNotFound},
		{"latest is a delete marker", ref("k", ""), storage.ErrObjectNotFound},
		{"the delete marker itself", ref("k", mark.VersionID), storage.ErrIsDeleteMarker},
		{"malformed version", ref("k", "not-a-version"), storage.ErrInvalidVersionID},
		{"missing bucket", storage.ObjectRef{Bucket: "nosuchbucket", Object: "k"}, storage.ErrBucketNotFound},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := h.be.SetObjectRetention(bg, c.ref, until, storage.RetentionOptions{})
			if !errors.Is(err, c.want) {
				t.Errorf("SetObjectRetention = %v, want %v", err, c.want)
			}
			_, err = h.be.SetObjectLegalHold(bg, c.ref, true)
			if !errors.Is(err, c.want) {
				t.Errorf("SetObjectLegalHold = %v, want %v", err, c.want)
			}
		})
	}
	// The earlier version is addressable by its ID.
	if _, err := h.be.SetObjectRetention(bg, ref("k", info.VersionID), until, storage.RetentionOptions{}); err != nil {
		t.Errorf("SetObjectRetention of a covered version: %v", err)
	}
}

// testLockRefusalChangesNothing: a refused deletion and a refused change must
// leave the version list exactly as it was, generation included, so a refusal
// is not a side channel for moving state.
func testLockRefusalChangesNothing(t *testing.T, f Factory) {
	h := newHarness(t, f)
	h.mkLockBucket("lockstate")
	r := storage.Retention{Mode: storage.RetentionCompliance, Until: time.Now().Add(time.Hour)}
	a := h.putLocked("lockstate", "k", "one", r, true)
	b := h.putLocked("lockstate", "k", "two", storage.Retention{}, false)

	snapshot := func() string {
		res := h.listVersions("lockstate", storage.ListOptions{})
		var sb strings.Builder
		for _, v := range res.Versions {
			sb.WriteString(v.VersionID + "|" + v.ETag + "|" + v.Retention.Until.Format(time.RFC3339Nano) + "|")
			sb.WriteString(string(v.Retention.Mode) + "|" + map[bool]string{true: "H", false: "-"}[v.LegalHold] + ";")
		}
		return sb.String()
	}
	before := snapshot()
	attempts := []func() error{
		func() error {
			_, err := h.be.DeleteObject(bg, "lockstate", "k", storage.DeleteOptions{VersionID: a.VersionID, BypassGovernance: true})
			return err
		},
		func() error {
			_, err := h.be.SetObjectRetention(bg, storage.ObjectRef{Bucket: "lockstate", Object: "k", VersionID: a.VersionID},
				storage.Retention{}, storage.RetentionOptions{BypassGovernance: true})
			return err
		},
		func() error {
			_, err := h.be.SetObjectRetention(bg, storage.ObjectRef{Bucket: "lockstate", Object: "k", VersionID: a.VersionID},
				storage.Retention{Mode: storage.RetentionCompliance, Until: time.Now().Add(time.Minute)}, storage.RetentionOptions{})
			return err
		},
	}
	for i, try := range attempts {
		if err := try(); !errors.Is(err, storage.ErrObjectLocked) {
			t.Fatalf("attempt %d = %v, want ErrObjectLocked", i, err)
		}
		if got := snapshot(); got != before {
			t.Fatalf("attempt %d changed the version list:\n before %s\n after  %s", i, before, got)
		}
	}
	// And the unprotected sibling is still deletable: the lock is per version.
	if _, err := h.be.DeleteObject(bg, "lockstate", "k", storage.DeleteOptions{VersionID: b.VersionID}); err != nil {
		t.Errorf("deleting the unprotected version: %v", err)
	}
}

// testLockConcurrentDeletes: many writers racing to delete and to weaken a
// COMPLIANCE version never succeed, whatever the interleaving.
func testLockConcurrentDeletes(t *testing.T, f Factory) {
	h := newHarness(t, f)
	h.mkLockBucket("lockrace")
	r := storage.Retention{Mode: storage.RetentionCompliance, Until: time.Now().Add(time.Hour)}
	info := h.putLocked("lockrace", "k", "keep", r, false)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var unexpected []error
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, err := h.be.DeleteObject(bg, "lockrace", "k", storage.DeleteOptions{VersionID: info.VersionID, BypassGovernance: true})
			if !errors.Is(err, storage.ErrObjectLocked) {
				mu.Lock()
				unexpected = append(unexpected, err)
				mu.Unlock()
			}
		}()
		go func() {
			defer wg.Done()
			_, err := h.be.SetObjectRetention(bg, storage.ObjectRef{Bucket: "lockrace", Object: "k", VersionID: info.VersionID},
				storage.Retention{}, storage.RetentionOptions{BypassGovernance: true})
			if !errors.Is(err, storage.ErrObjectLocked) {
				mu.Lock()
				unexpected = append(unexpected, err)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	for _, err := range unexpected {
		t.Errorf("a racing change was not refused: %v", err)
	}
	h.mustGetV("lockrace", "k", info.VersionID, "keep")
	if got := h.stat("lockrace", "k", info.VersionID).Retention; got.Mode != storage.RetentionCompliance {
		t.Errorf("retention after the race = %+v", got)
	}
}
