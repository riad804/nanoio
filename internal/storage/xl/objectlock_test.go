package xl

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nanoio/internal/storage"
)

func lockedPut(t *testing.T, x *XL, bucket, key, body string, r storage.Retention, hold bool) storage.ObjectInfo {
	t.Helper()
	info, err := x.PutObject(bg, bucket, key, strings.NewReader(body), int64(len(body)),
		storage.PutOptions{Retention: r, LegalHold: hold})
	if err != nil {
		t.Fatalf("PutObject(%s/%s): %v", bucket, key, err)
	}
	return info
}

// TestObjectLockSurvivesDamageHealAndRestart: retention is part of the
// version's metadata, so it must be what heal republishes and what a
// restarted set reads back.
func TestObjectLockSurvivesDamageHealAndRestart(t *testing.T) {
	l := layout{"4+4", 8, 4, 16 << 10}
	x, dirs := newXL(t, l)
	if err := x.MakeBucket(bg, "locked", storage.MakeBucketOptions{ObjectLock: true}); err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(6 * time.Hour).UTC().Truncate(time.Millisecond)
	body := strings.Repeat("retained-", 9000)
	info := lockedPut(t, x, "locked", "k", body, storage.Retention{Mode: storage.RetentionCompliance, Until: until}, true)

	// Wipe one drive's copy, rot another's shard and lose a third's metadata.
	os.RemoveAll(objDirOn(dirs, 1, "locked", "k"))
	for _, p := range shardPathsOn(t, dirs, 2, "locked", "k") {
		files, _ := filepath.Glob(filepath.Join(p, "part.*"))
		for _, f := range files {
			b, _ := os.ReadFile(f)
			b[len(b)/2] ^= 0xff
			os.WriteFile(f, b, 0o644)
		}
	}
	os.Remove(filepath.Join(objDirOn(dirs, 3, "locked", "k"), "xl.meta"))

	// Still protected while damaged.
	_, err := x.DeleteObject(bg, "locked", "k", storage.DeleteOptions{VersionID: info.VersionID, BypassGovernance: true})
	if !errors.Is(err, storage.ErrObjectLocked) {
		t.Fatalf("delete of a damaged locked version = %v, want ErrObjectLocked", err)
	}
	if _, err := x.HealObject(bg, "locked", "k", true); err != nil {
		t.Fatal(err)
	}
	for i := range dirs {
		v := metaOn(t, dirs, i, "locked", "k").Find(info.VersionID)
		if v == nil || v.Lock == nil || string(v.Lock.Mode) != "COMPLIANCE" || !v.Lock.LegalHold || !v.Lock.RetainUntil.Equal(until) {
			t.Errorf("drive %d: lock after heal = %+v", i, v)
		}
	}

	// Restart: the same drives, a new set.
	if err := x.Close(); err != nil {
		t.Fatal(err)
	}
	x = openXL(t, dirs, l)
	got, err := x.StatObject(bg, "locked", "k", storage.GetOptions{VersionID: info.VersionID})
	if err != nil {
		t.Fatal(err)
	}
	if got.Retention.Mode != storage.RetentionCompliance || !got.Retention.Until.Equal(until) || !got.LegalHold {
		t.Errorf("after restart: %+v hold=%v", got.Retention, got.LegalHold)
	}
	_, err = x.DeleteObject(bg, "locked", "k", storage.DeleteOptions{VersionID: info.VersionID, BypassGovernance: true})
	if !errors.Is(err, storage.ErrObjectLocked) {
		t.Errorf("delete after restart = %v, want ErrObjectLocked", err)
	}
	cfg, err := x.GetBucketObjectLock(bg, "locked")
	if err != nil || !cfg.Enabled {
		t.Errorf("bucket lock after restart = %+v, %v", cfg, err)
	}
}

// TestObjectLockBucketSettingsConverge: a drive that lost its marker (or was
// replaced) is brought back to the agreed lock configuration, and until it
// is, the quorum's answer is what writes see: a drive can never make a
// locked bucket read as unlocked.
func TestObjectLockBucketSettingsConverge(t *testing.T) {
	x, dirs := newXL(t, layout{"4+4", 8, 4, 16 << 10})
	if err := x.MakeBucket(bg, "conv", storage.MakeBucketOptions{ObjectLock: true}); err != nil {
		t.Fatal(err)
	}
	def := &storage.DefaultRetention{Mode: storage.RetentionGovernance, Days: 2}
	if err := x.SetBucketObjectLock(bg, "conv", storage.ObjectLockConfig{Enabled: true, Default: def}); err != nil {
		t.Fatal(err)
	}
	// Drives 0-3 lose their marker documents altogether.
	for i := 0; i < 4; i++ {
		if err := os.RemoveAll(filepath.Join(dirs[i], "conv")); err != nil {
			t.Fatal(err)
		}
	}
	// Exactly K=4 drives still hold it: the quorum stands.
	cfg, err := x.GetBucketObjectLock(bg, "conv")
	if err != nil || !cfg.Enabled || cfg.Default == nil || *cfg.Default != *def {
		t.Fatalf("lock config with half the markers gone = %+v, %v", cfg, err)
	}
	info := lockedPut(t, x, "conv", "k", "v", storage.Retention{}, false)
	if got, _ := x.StatObject(bg, "conv", "k", storage.GetOptions{VersionID: info.VersionID}); got.Retention.Mode != storage.RetentionGovernance {
		t.Errorf("write with the default after losing markers: %+v", got.Retention)
	}
	if _, err := x.HealBucket(bg, "conv"); err != nil {
		t.Fatal(err)
	}
	for i, d := range x.drives {
		s, err := d.ReadBucketSettings(bg, "conv")
		if err != nil {
			t.Fatalf("drive %d: %v", i, err)
		}
		if s.Versioning != "Enabled" || s.ObjectLock == "" || s.ObjectLockSeq == 0 {
			t.Errorf("drive %d settings after heal = %+v", i, s)
		}
	}
}

// TestObjectLockCannotBeRemovedWholesale: whole-key removal paths refuse a
// protected key.
func TestObjectLockCannotBeRemovedWholesale(t *testing.T) {
	x, dirs := newXL(t, layout{"2+1", 3, 1, 64 << 10})
	if err := x.MakeBucket(bg, "whole", storage.MakeBucketOptions{ObjectLock: true}); err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(time.Hour)
	info := lockedPut(t, x, "whole", "k", "data", storage.Retention{Mode: storage.RetentionCompliance, Until: until}, false)
	// A forced bucket delete is refused.
	if err := x.DeleteBucket(bg, "whole", storage.DeleteBucketOptions{Force: true}); !errors.Is(err, storage.ErrObjectLocked) {
		t.Errorf("forced bucket delete = %v, want ErrObjectLocked", err)
	}
	// A drive asked to remove the key outright refuses.
	for i, d := range x.drives {
		if err := d.DeleteObject(bg, "whole", "k"); err == nil {
			t.Errorf("drive %d removed a protected key", i)
		}
	}
	// And the object reads back from every drive's metadata.
	for i := range dirs {
		if v := metaOn(t, dirs, i, "whole", "k").Find(info.VersionID); v == nil || v.Lock == nil {
			t.Errorf("drive %d lost the version or its lock: %+v", i, v)
		}
	}
	rc, _, err := x.GetObject(bg, "whole", "k", storage.GetOptions{VersionID: info.VersionID})
	if err != nil {
		t.Fatal(err)
	}
	rc.Close()
}
