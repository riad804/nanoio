package xl

import (
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nanoio/internal/meta"
	"nanoio/internal/storage"
	"nanoio/internal/storage/xl/disk"
)

// versionedKey is a key with several versions and a trailing delete marker,
// and what each version should read as.
type versionedKey struct {
	key      string
	ids      []string // oldest first
	bodies   map[string]string
	markerID string
}

func writeVersions(t *testing.T, x *XL, rng *rand.Rand, bucket, key string, n, size int) versionedKey {
	t.Helper()
	vk := versionedKey{key: key, bodies: map[string]string{}}
	for i := 0; i < n; i++ {
		body := string(randBytes(rng, size+i*37))
		info, err := x.PutObject(bg, bucket, key, strings.NewReader(body), int64(len(body)), storage.PutOptions{})
		if err != nil {
			t.Fatalf("put %s v%d: %v", key, i, err)
		}
		vk.ids = append(vk.ids, info.VersionID)
		vk.bodies[info.VersionID] = body
	}
	res, err := x.DeleteObject(bg, bucket, key, storage.DeleteOptions{})
	if err != nil || !res.DeleteMarker {
		t.Fatalf("delete marker: %+v, %v", res, err)
	}
	vk.markerID = res.VersionID
	return vk
}

func (vk versionedKey) verify(t *testing.T, x *XL, bucket string) error {
	t.Helper()
	for _, id := range vk.ids {
		rc, _, err := x.GetObject(bg, bucket, vk.key, storage.GetOptions{VersionID: id})
		if err != nil {
			return fmt.Errorf("version %s: %w", id, err)
		}
		got, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return fmt.Errorf("version %s: read: %w", id, err)
		}
		if string(got) != vk.bodies[id] {
			return fmt.Errorf("version %s: content differs", id)
		}
	}
	_, err := x.StatObject(bg, bucket, vk.key, storage.GetOptions{})
	var dm *storage.DeleteMarkerError
	if !errorsAs(err, &dm) || dm.VersionID != vk.markerID {
		return fmt.Errorf("latest is not the delete marker: %v", err)
	}
	return nil
}

func errorsAs(err error, target **storage.DeleteMarkerError) bool {
	for err != nil {
		if dm, ok := err.(*storage.DeleteMarkerError); ok {
			*target = dm
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// dataDirOf returns the data directory of one version on drive i.
func dataDirOf(t *testing.T, dirs []string, i int, bucket, key, versionID string) string {
	t.Helper()
	f := metaOn(t, dirs, i, bucket, key)
	v := f.Find(versionID)
	if v == nil {
		t.Fatalf("drive %d has no version %s", i, versionID)
	}
	return filepath.Join(objDirOn(dirs, i, bucket, key), v.DataDir)
}

func TestHealRepairsEveryVersion(t *testing.T) {
	x, dirs := newXL(t, layout{"4+4", 8, 4, 16 << 10})
	mkbucket(t, x, "heal-v")
	if err := x.SetBucketVersioning(bg, "heal-v", storage.VersioningEnabled); err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewSource(7))
	vk := writeVersions(t, x, rng, "heal-v", "doc", 4, 50<<10)

	// Damage three different kinds of things on different drives, none of
	// them touching more than M=4 drives for any version.
	oldest, middle := vk.ids[0], vk.ids[1]
	os.RemoveAll(dataDirOf(t, dirs, 1, "heal-v", "doc", oldest)) // an old version's shards gone
	os.RemoveAll(objDirOn(dirs, 2, "heal-v", "doc"))             // a whole drive's copy gone
	p := filepath.Join(dataDirOf(t, dirs, 3, "heal-v", "doc", middle), "part.1")
	b, _ := os.ReadFile(p)
	b[len(b)/2] ^= 0xff // bitrot in a middle version
	os.WriteFile(p, b, 0o644)
	os.Remove(filepath.Join(objDirOn(dirs, 4, "heal-v", "doc"), "xl.meta")) // metadata gone, shards left

	if err := vk.verify(t, x, "heal-v"); err != nil {
		t.Fatalf("reads must survive the damage: %v", err)
	}
	res, err := x.HealObject(bg, "heal-v", "doc", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Healed) == 0 {
		t.Fatalf("nothing healed: %+v", res)
	}
	if res, err = x.HealObject(bg, "heal-v", "doc", true); err != nil || res.Skipped != "healthy" {
		t.Fatalf("after healing: %+v, %v", res, err)
	}
	if err := vk.verify(t, x, "heal-v"); err != nil {
		t.Fatalf("after heal: %v", err)
	}
	// Every drive now lists the same versions, in the same order.
	var want string
	for i := range dirs {
		f := metaOn(t, dirs, i, "heal-v", "doc")
		var ids []string
		for _, v := range f.Versions {
			ids = append(ids, v.VersionID+":"+string(v.Type))
		}
		got := strings.Join(ids, ",")
		if want == "" {
			want = got
		} else if got != want {
			t.Errorf("drive %d lists %s, drive 0 lists %s", i, got, want)
		}
		if f.Generation() != 5 { // 4 puts + 1 marker
			t.Errorf("drive %d generation %d, want 5", i, f.Generation())
		}
	}
}

// A drive that holds a version the quorum does not (a write that reached
// too few drives) must not resurrect it, and heal drops it.
func TestHealDropsAStrayVersion(t *testing.T) {
	x, dirs := newXL(t, layout{"4+2", 6, 2, 16 << 10})
	mkbucket(t, x, "stray")
	x.SetBucketVersioning(bg, "stray", storage.VersioningEnabled)
	vk := writeVersions(t, x, rand.New(rand.NewSource(3)), "stray", "k", 2, 20<<10)

	// Fabricate the remnant of a failed write on one drive only: commit a
	// newer version straight to drive 0.
	d := x.drives[0]
	stage := "stray-stage"
	w, err := d.CreateStageFile(bg, stage, ".nanoio-data-stray/part.1")
	if err != nil {
		t.Fatal(err)
	}
	w.Write(make([]byte, 40))
	w.Close()
	cur := metaOn(t, dirs, 0, "stray", "k")
	v := meta.Version{Type: meta.TypeObject, VersionID: "f0f0f0f0-1111-4222-8333-444455556666", Seq: cur.Gen + 1,
		ModTime: cur.Latest().ModTime.Add(1e9), Size: 5, ETag: "x", DataDir: ".nanoio-data-stray",
		Erasure: &meta.Erasure{Algorithm: algorithm, DataBlocks: 4, ParityBlocks: 2, BlockSize: 16 << 10,
			Index: 0, Distribution: []int{0, 1, 2, 3, 4, 5}}}
	c, err := d.CommitObject(bg, diskCommit(stage, v))
	if err != nil {
		t.Fatal(err)
	}
	c.Finish(bg)

	if err := vk.verify(t, x, "stray"); err != nil {
		t.Fatalf("a stray version on one drive changed what reads see: %v", err)
	}
	if _, err := x.HealObject(bg, "stray", "k", true); err != nil {
		t.Fatal(err)
	}
	f := metaOn(t, dirs, 0, "stray", "k")
	if f.Find(v.VersionID) != nil {
		t.Error("heal left the stray version on its drive")
	}
	if _, err := os.Stat(filepath.Join(objDirOn(dirs, 0, "stray", "k"), ".nanoio-data-stray")); err == nil {
		t.Error("heal left the stray version's data behind")
	}
	if res, err := x.HealObject(bg, "stray", "k", true); err != nil || res.Skipped != "healthy" {
		t.Errorf("after healing: %+v, %v", res, err)
	}
}

func TestKillRandomShardsOfVersionedKeys(t *testing.T) {
	for _, l := range []layout{{"4+4", 8, 4, 8 << 10}, {"3+2", 5, 2, 4 << 10}} {
		t.Run(l.name, func(t *testing.T) {
			rng := rand.New(rand.NewSource(11))
			x, dirs := newXL(t, l)
			mkbucket(t, x, "kill-v")
			x.SetBucketVersioning(bg, "kill-v", storage.VersioningEnabled)
			var keys []versionedKey
			for i := 0; i < 4; i++ {
				keys = append(keys, writeVersions(t, x, rng, "kill-v", fmt.Sprintf("dir/k%d", i), 3, 3000+i*5000))
			}
			m := l.parity
			for round := 0; round < 6; round++ {
				// Damage up to M drives' copies of each key, in a random way.
				for _, vk := range keys {
					for _, i := range pickDrives(rng, l.drives, 1+rng.Intn(m)) {
						damages[rng.Intn(len(damages))].apply(t, rng, dirs, i, "kill-v", vk.key)
					}
				}
				for _, vk := range keys {
					if err := vk.verify(t, x, "kill-v"); err != nil {
						t.Fatalf("round %d, %s: %v", round, vk.key, err)
					}
					if _, err := x.HealObject(bg, "kill-v", vk.key, true); err != nil {
						t.Fatalf("round %d heal %s: %v", round, vk.key, err)
					}
					if res, err := x.HealObject(bg, "kill-v", vk.key, true); err != nil || res.Skipped != "healthy" {
						t.Fatalf("round %d, %s not healthy after heal: %+v, %v", round, vk.key, res, err)
					}
				}
			}
		})
	}
}

// diskCommit builds an OpPut request for a hand-made remnant.
func diskCommit(stage string, v meta.Version) disk.CommitRequest {
	return disk.CommitRequest{Bucket: "stray", Object: "k", Op: disk.OpPut, StageID: stage,
		DataDir: v.DataDir, Version: v, Seq: v.Seq}
}
