package cluster

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"nanoio/internal/storage"
)

// TestAddedPoolGetsObjectLock: a pool added to a cluster that holds a locked
// bucket must create the bucket locked. Creating it bare would make writes
// that the ring routes there unprotected.
func TestAddedPoolGetsObjectLock(t *testing.T) {
	tp := newTopo(t)
	one := open(t, tp, Options{}, tp.pools(t, []string{"a", "b"}))
	if err := one.MakeBucket(bg, "wormgrow", storage.MakeBucketOptions{ObjectLock: true}); err != nil {
		t.Fatal(err)
	}
	def := &storage.DefaultRetention{Mode: storage.RetentionGovernance, Days: 1}
	if err := one.SetBucketObjectLock(bg, "wormgrow", storage.ObjectLockConfig{Enabled: true, Default: def}); err != nil {
		t.Fatal(err)
	}
	one.Close()

	two := open(t, tp, Options{}, tp.pools(t, []string{"a", "b"}, []string{"c", "d"}))
	if err := two.EnsureBuckets(bg); err != nil {
		t.Fatal(err)
	}
	for i := range two.sets {
		cfg, err := two.sets[i].GetBucketObjectLock(bg, "wormgrow")
		if err != nil || !cfg.Enabled || cfg.Default == nil || *cfg.Default != *def {
			t.Errorf("set %d lock config = %+v, %v", i, cfg, err)
		}
		if v, _ := two.sets[i].GetBucketVersioning(bg, "wormgrow"); v.State != storage.VersioningEnabled {
			t.Errorf("set %d versioning = %q", i, v.State)
		}
	}
	// Every key, whichever set it lands on, is protected by the default.
	seen := map[int]bool{}
	for i := 0; i < 40; i++ {
		k := fmt.Sprintf("obj-%02d", i)
		info, err := two.PutObject(bg, "wormgrow", k, strings.NewReader("v"), 1, storage.PutOptions{})
		if err != nil {
			t.Fatal(err)
		}
		seen[two.ringSet("wormgrow", k)] = true
		_, err = two.DeleteObject(bg, "wormgrow", k, storage.DeleteOptions{VersionID: info.VersionID})
		if !errors.Is(err, storage.ErrObjectLocked) {
			t.Fatalf("delete of %s = %v, want ErrObjectLocked", k, err)
		}
	}
	if !seen[2] && !seen[3] {
		t.Fatal("no key went to the new pool; the test would prove nothing")
	}
}

// TestObjectLockDivergedSetsReconcile: a configuration change that reached
// only some sets is carried to the others, and in the meantime the newer one
// is what the cluster reports.
func TestObjectLockDivergedSetsReconcile(t *testing.T) {
	tp := newTopo(t)
	s := open(t, tp, Options{}, tp.pools(t, []string{"a", "b"}, []string{"c"}))
	if err := s.MakeBucket(bg, "diverge", storage.MakeBucketOptions{ObjectLock: true}); err != nil {
		t.Fatal(err)
	}
	def := &storage.DefaultRetention{Mode: storage.RetentionCompliance, Years: 1}
	// A change applied to one set only, as a failed fan-out leaves it.
	if err := s.sets[1].SetBucketObjectLock(bg, "diverge", storage.ObjectLockConfig{Enabled: true, Default: def}); err != nil {
		t.Fatal(err)
	}
	cfg, err := s.GetBucketObjectLock(bg, "diverge")
	if err != nil || cfg.Default == nil || *cfg.Default != *def {
		t.Fatalf("cluster view = %+v, %v; want the newer default", cfg, err)
	}
	if err := s.EnsureBuckets(bg); err != nil {
		t.Fatal(err)
	}
	for i := range s.sets {
		c, _ := s.sets[i].GetBucketObjectLock(bg, "diverge")
		if c.Default == nil || *c.Default != *def {
			t.Errorf("set %d after reconcile = %+v", i, c)
		}
	}
}

// TestObjectLockClusterRoutesVersionOps: retention and legal hold find the
// set that holds the version, and deletion of a locked version is refused
// wherever it lives.
func TestObjectLockClusterRoutesVersionOps(t *testing.T) {
	tp := newTopo(t)
	s := open(t, tp, Options{}, tp.pools(t, []string{"a", "b"}, []string{"c"}))
	if err := s.MakeBucket(bg, "route", storage.MakeBucketOptions{ObjectLock: true}); err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(time.Hour)
	for i := 0; i < 12; i++ {
		k := fmt.Sprintf("k%02d", i)
		info, err := s.PutObject(bg, "route", k, strings.NewReader("v"), 1, storage.PutOptions{})
		if err != nil {
			t.Fatal(err)
		}
		ref := storage.ObjectRef{Bucket: "route", Object: k, VersionID: info.VersionID}
		if _, err := s.SetObjectRetention(bg, ref, storage.Retention{Mode: storage.RetentionCompliance, Until: until}, storage.RetentionOptions{}); err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		if _, err := s.SetObjectLegalHold(bg, ref, true); err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		got, err := s.StatObject(bg, "route", k, storage.GetOptions{VersionID: info.VersionID})
		if err != nil || got.Retention.Mode != storage.RetentionCompliance || !got.LegalHold {
			t.Fatalf("%s lock = %+v hold=%v, %v", k, got.Retention, got.LegalHold, err)
		}
		_, err = s.DeleteObject(bg, "route", k, storage.DeleteOptions{VersionID: info.VersionID, BypassGovernance: true})
		if !errors.Is(err, storage.ErrObjectLocked) {
			t.Fatalf("%s delete = %v, want ErrObjectLocked", k, err)
		}
	}
	_, err := s.SetObjectRetention(bg, storage.ObjectRef{Bucket: "route", Object: "absent"},
		storage.Retention{Mode: storage.RetentionGovernance, Until: until}, storage.RetentionOptions{})
	if !errors.Is(err, storage.ErrObjectNotFound) {
		t.Errorf("retention of a missing key = %v", err)
	}
}
