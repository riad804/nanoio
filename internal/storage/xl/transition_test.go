package xl

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"nanoio/internal/storage"
)

func TestTransitionLeavesAStubAndFreesData(t *testing.T) {
	l := layout{"4+2", 6, 2, 16 << 10}
	var mu sync.Mutex
	var freed []storage.TransitionInfo
	x, dirs := newXL(t, l, func(o *Options) {
		o.OnTransitionFreed = func(_, _ string, tr storage.TransitionInfo) {
			mu.Lock()
			freed = append(freed, tr)
			mu.Unlock()
		}
	})
	if err := x.MakeBucket(bg, "tbk", storage.MakeBucketOptions{}); err != nil {
		t.Fatal(err)
	}
	body := strings.Repeat("tiered-bytes-", 5000)
	put := func(key string) storage.ObjectInfo {
		info, err := x.PutObject(bg, "tbk", key, strings.NewReader(body), int64(len(body)),
			storage.PutOptions{ContentType: "text/plain", UserDefined: map[string]string{"x-amz-meta-a": "b"}})
		if err != nil {
			t.Fatal(err)
		}
		return info
	}
	info := put("k")
	ref := storage.ObjectRef{Bucket: "tbk", Object: "k"}
	tr := storage.TransitionInfo{Tier: "COLD", Object: "tbk/k/uuid", VersionID: "rv1"}

	// Stale ETag: refused, nothing changes.
	if _, err := x.TransitionObject(bg, ref, tr, "not-the-etag"); !errors.Is(err, storage.ErrPreconditionFailed) {
		t.Fatalf("stale etag = %v", err)
	}
	got, err := x.TransitionObject(bg, ref, tr, info.ETag)
	if err != nil {
		t.Fatal(err)
	}
	if got.Transition == nil || got.Transition.Tier != "COLD" || got.Size != int64(len(body)) || got.ETag != info.ETag {
		t.Fatalf("info after transition = %+v", got)
	}
	if _, err := x.TransitionObject(bg, ref, tr, info.ETag); !errors.Is(err, storage.ErrAlreadyTransitioned) {
		t.Errorf("second transition = %v", err)
	}

	// Stat keeps working and reports the stub; Get says where the data is.
	st, err := x.StatObject(bg, "tbk", "k", storage.GetOptions{})
	if err != nil || st.Transition == nil || st.Transition.Object != "tbk/k/uuid" || st.ContentType != "text/plain" ||
		st.UserDefined["x-amz-meta-a"] != "b" || st.Size != int64(len(body)) {
		t.Fatalf("stat = %+v, %v", st, err)
	}
	_, _, err = x.GetObject(bg, "tbk", "k", storage.GetOptions{})
	var te *storage.TransitionedError
	if !errors.As(err, &te) || te.Info.Transition == nil || !errors.Is(err, storage.ErrTransitioned) {
		t.Fatalf("GetObject = %v, want a TransitionedError", err)
	}

	// Local shard data is gone on every drive; the stub xl.meta remains.
	for i := range dirs {
		if p := shardPathsOn(t, dirs, i, "tbk", "k"); len(p) != 0 {
			t.Errorf("drive %d still holds data dirs %v", i, p)
		}
		if _, err := os.Stat(objDirOn(dirs, i, "tbk", "k") + "/xl.meta"); err != nil {
			t.Errorf("drive %d lost the stub: %v", i, err)
		}
		if v := metaOn(t, dirs, i, "tbk", "k").Latest(); v.Transition == nil || v.DataDir != "" || v.Erasure != nil {
			t.Errorf("drive %d version = %+v", i, v)
		}
	}

	// Healing leaves a stub alone and repairs a drive that lost its xl.meta.
	os.Remove(objDirOn(dirs, 2, "tbk", "k") + "/xl.meta")
	if res, err := x.HealObject(bg, "tbk", "k", true); err != nil || len(res.Healed) != 1 {
		t.Fatalf("heal = %+v, %v", res, err)
	}
	if v := metaOn(t, dirs, 2, "tbk", "k").Latest(); v.Transition == nil {
		t.Errorf("healed drive lost the stub: %+v", v)
	}
	mu.Lock()
	if len(freed) != 0 {
		t.Errorf("freed = %v before anything was removed", freed)
	}
	mu.Unlock()

	// Removing the stub reports the remote copy as freed, exactly once.
	if _, err := x.DeleteObject(bg, "tbk", "k", storage.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if len(freed) != 1 || freed[0].Object != "tbk/k/uuid" {
		t.Errorf("freed after delete = %v", freed)
	}
	mu.Unlock()

	// Overwriting a stub (unversioned null version) frees it too.
	put("o")
	if _, err := x.TransitionObject(bg, storage.ObjectRef{Bucket: "tbk", Object: "o"},
		storage.TransitionInfo{Tier: "COLD", Object: "tbk/o/uuid"}, ""); err != nil {
		t.Fatal(err)
	}
	put("o")
	mu.Lock()
	defer mu.Unlock()
	if len(freed) != 2 || freed[1].Object != "tbk/o/uuid" {
		t.Errorf("freed after overwrite = %v", freed)
	}
}

func TestTransitionOfVersionedObjectAndMarkers(t *testing.T) {
	l := layout{"4+2", 6, 2, 16 << 10}
	x, _ := newXL(t, l)
	x.MakeBucket(bg, "vtb", storage.MakeBucketOptions{})
	if err := x.SetBucketVersioning(bg, "vtb", storage.VersioningEnabled); err != nil {
		t.Fatal(err)
	}
	v1, _ := x.PutObject(bg, "vtb", "k", strings.NewReader("one"), 3, storage.PutOptions{})
	v2, _ := x.PutObject(bg, "vtb", "k", strings.NewReader("two"), 3, storage.PutOptions{})
	// Transition the older, noncurrent version only.
	if _, err := x.TransitionObject(bg, storage.ObjectRef{Bucket: "vtb", Object: "k", VersionID: v1.VersionID},
		storage.TransitionInfo{Tier: "COLD", Object: "vtb/k/1"}, v1.ETag); err != nil {
		t.Fatal(err)
	}
	rc, _, err := x.GetObject(bg, "vtb", "k", storage.GetOptions{})
	if err != nil {
		t.Fatalf("the current version must stay readable: %v", err)
	}
	rc.Close()
	if _, _, err := x.GetObject(bg, "vtb", "k", storage.GetOptions{VersionID: v1.VersionID}); !errors.Is(err, storage.ErrTransitioned) {
		t.Errorf("old version = %v", err)
	}
	vers, _ := x.ListObjectVersions(bg, "vtb", storage.ListOptions{})
	n := 0
	for _, v := range vers.Versions {
		if v.Transition != nil {
			n++
			if v.VersionID != v1.VersionID {
				t.Errorf("wrong version transitioned: %+v", v)
			}
		}
	}
	if n != 1 {
		t.Errorf("listing shows %d stubs", n)
	}
	// A delete marker cannot be transitioned.
	dm, _ := x.DeleteObject(bg, "vtb", "k", storage.DeleteOptions{})
	if _, err := x.TransitionObject(bg, storage.ObjectRef{Bucket: "vtb", Object: "k", VersionID: dm.VersionID},
		storage.TransitionInfo{Tier: "COLD", Object: "x"}, ""); err == nil {
		t.Error("a delete marker was transitioned")
	}
	_ = v2
}

func TestTierToTierMoveFreesTheOldCopy(t *testing.T) {
	var mu sync.Mutex
	var freed []string
	x, _ := newXL(t, layout{"4+2", 6, 2, 16 << 10}, func(o *Options) {
		o.OnTransitionFreed = func(_, _ string, tr storage.TransitionInfo) {
			mu.Lock()
			freed = append(freed, tr.Tier+":"+tr.Object)
			mu.Unlock()
		}
	})
	x.MakeBucket(bg, "mvb", storage.MakeBucketOptions{})
	info, _ := x.PutObject(bg, "mvb", "k", strings.NewReader("data"), 4, storage.PutOptions{})
	ref := storage.ObjectRef{Bucket: "mvb", Object: "k"}
	if _, err := x.TransitionObject(bg, ref, storage.TransitionInfo{Tier: "WARM", Object: "w/1"}, info.ETag); err != nil {
		t.Fatal(err)
	}
	// Same tier again: refused. A different tier: the stub is replaced.
	if _, err := x.TransitionObject(bg, ref, storage.TransitionInfo{Tier: "WARM", Object: "w/2"}, info.ETag); !errors.Is(err, storage.ErrAlreadyTransitioned) {
		t.Errorf("same tier = %v", err)
	}
	got, err := x.TransitionObject(bg, ref, storage.TransitionInfo{Tier: "COLD", Object: "c/1"}, info.ETag)
	if err != nil || got.Transition.Tier != "COLD" {
		t.Fatalf("move = %+v, %v", got, err)
	}
	st, _ := x.StatObject(bg, "mvb", "k", storage.GetOptions{})
	if st.Transition == nil || st.Transition.Object != "c/1" {
		t.Errorf("stat = %+v", st.Transition)
	}
	mu.Lock()
	defer mu.Unlock()
	if fmt.Sprint(freed) != "[WARM:w/1]" {
		t.Errorf("freed = %v", freed)
	}
}
