package xl

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"nanoio/internal/bucket/nslock"
	"nanoio/internal/meta"
	"nanoio/internal/storage"
)

var classLayout = layout{"4+4", 8, 4, 64 << 10}

func classSet(t *testing.T) (*XL, []string) {
	t.Helper()
	return newXL(t, classLayout, func(o *Options) {
		o.StorageClasses = map[string]int{"BALANCED": 2} // 6+2; REDUCED_REDUNDANCY defaults to 7+1; STANDARD is 4+4
	})
}

func putClass(t *testing.T, x *XL, bucket, key, body, class string) storage.ObjectInfo {
	t.Helper()
	info, err := x.PutObject(bg, bucket, key, strings.NewReader(body), int64(len(body)), storage.PutOptions{StorageClass: class})
	if err != nil {
		t.Fatalf("PutObject(%s, class %q): %v", key, class, err)
	}
	return info
}

// lose removes the first n drives' copies of an object, as a lost drive does.
func lose(t *testing.T, dirs []string, n int, bucket, key string) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := os.RemoveAll(objDirOn(dirs, i, bucket, key)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestStorageClassLayoutsAndFaultTolerance(t *testing.T) {
	for _, c := range []struct {
		class         string
		wantK, wantM  int
		tolerates     int // drives that may be lost
		recordedClass string
		infoClass     string
	}{
		{"", 4, 4, 4, "", ""},
		{"STANDARD", 4, 4, 4, "", ""},
		{"REDUCED_REDUNDANCY", 7, 1, 1, "REDUCED_REDUNDANCY", "REDUCED_REDUNDANCY"},
		{"BALANCED", 6, 2, 2, "BALANCED", "BALANCED"},
	} {
		t.Run("class "+c.class, func(t *testing.T) {
			x, dirs := classSet(t)
			mkbucket(t, x, "classes")
			body := strings.Repeat("x", 300_000) + "tail"
			info := putClass(t, x, "classes", "obj", body, c.class)
			if info.StorageClass != c.infoClass {
				t.Errorf("PutObject StorageClass = %q, want %q", info.StorageClass, c.infoClass)
			}
			if st, err := x.StatObject(bg, "classes", "obj", storage.GetOptions{}); err != nil || st.StorageClass != c.infoClass {
				t.Errorf("StatObject StorageClass = %q, %v", st.StorageClass, err)
			}
			for i := range dirs {
				f := metaOn(t, dirs, i, "classes", "obj")
				v := f.Versions[0]
				if v.Erasure.DataBlocks != c.wantK || v.Erasure.ParityBlocks != c.wantM || v.StorageClass != c.recordedClass {
					t.Fatalf("drive %d records %d+%d class %q, want %d+%d class %q", i,
						v.Erasure.DataBlocks, v.Erasure.ParityBlocks, v.StorageClass, c.wantK, c.wantM, c.recordedClass)
				}
				if c.recordedClass != "" && f.Format != meta.FormatClassed {
					t.Errorf("drive %d file format %d, want %d", i, f.Format, meta.FormatClassed)
				}
			}
			// Readable with exactly as many drives lost as the class tolerates.
			lose(t, dirs, c.tolerates, "classes", "obj")
			if got, err := read(t, x, "classes", "obj"); err != nil || got != body {
				t.Fatalf("read with %d drives lost: err=%v equal=%v", c.tolerates, err, got == body)
			}
		})
	}
}

func TestStorageClassBeyondToleranceFails(t *testing.T) {
	x, dirs := classSet(t)
	mkbucket(t, x, "classes")
	body := strings.Repeat("y", 200_000)
	putClass(t, x, "classes", "rrs", body, "REDUCED_REDUNDANCY")
	putClass(t, x, "classes", "std", body, "")
	// Two drives lost: STANDARD (4+4) survives, REDUCED_REDUNDANCY (7+1) does not.
	lose(t, dirs, 2, "classes", "rrs")
	lose(t, dirs, 2, "classes", "std")
	if got, err := read(t, x, "classes", "std"); err != nil || got != body {
		t.Errorf("STANDARD with 2 drives lost: %v", err)
	}
	if _, err := read(t, x, "classes", "rrs"); err == nil {
		t.Error("REDUCED_REDUNDANCY object read back with 2 of 8 drives lost; it has 1 parity")
	}
}

// A class's own layout sets how many drives a write must reach.
func TestStorageClassWriteQuorum(t *testing.T) {
	x, dirs := classSet(t)
	mkbucket(t, x, "classes")
	// Two drives vanish: STANDARD (4+4) needs 5 of 8, REDUCED_REDUNDANCY (7+1) needs 7.
	for i := 0; i < 2; i++ {
		if err := os.RemoveAll(dirs[i]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := x.PutObject(bg, "classes", "std", strings.NewReader("data"), 4, storage.PutOptions{}); err != nil {
		t.Fatalf("STANDARD write with 2 drives down: %v", err)
	}
	_, err := x.PutObject(bg, "classes", "rrs", strings.NewReader("data"), 4, storage.PutOptions{StorageClass: "REDUCED_REDUNDANCY"})
	if !errors.Is(err, storage.ErrBackendUnavailable) {
		t.Errorf("REDUCED_REDUNDANCY write with 2 drives down = %v, want ErrBackendUnavailable", err)
	}
	if _, e := x.StatObject(bg, "classes", "rrs", storage.GetOptions{}); e == nil {
		t.Error("the refused write left an object")
	}
}

func TestStorageClassInvalid(t *testing.T) {
	x, _ := classSet(t)
	mkbucket(t, x, "classes")
	for _, bad := range []string{"GLACIER", "standard", "ARCHIVE2", "REDUCED_REDUNDANCY "} {
		_, err := x.PutObject(bg, "classes", "k", strings.NewReader("d"), 1, storage.PutOptions{StorageClass: bad})
		if !errors.Is(err, storage.ErrInvalidStorageClass) {
			t.Errorf("PutObject class %q = %v", bad, err)
		}
		_, err = x.NewMultipartUpload(bg, "classes", "k", storage.PutOptions{StorageClass: bad})
		if !errors.Is(err, storage.ErrInvalidStorageClass) {
			t.Errorf("NewMultipartUpload class %q = %v", bad, err)
		}
	}
}

func TestStorageClassMultipart(t *testing.T) {
	x, dirs := classSet(t)
	mkbucket(t, x, "classes")
	id, err := x.NewMultipartUpload(bg, "classes", "mp", storage.PutOptions{StorageClass: "BALANCED"})
	if err != nil {
		t.Fatal(err)
	}
	p1 := strings.Repeat("a", 5<<20)
	p2 := "the end"
	pi1, err := x.PutObjectPart(bg, "classes", "mp", id, 1, strings.NewReader(p1), int64(len(p1)), storage.PartOptions{})
	if err != nil {
		t.Fatal(err)
	}
	pi2, err := x.PutObjectPart(bg, "classes", "mp", id, 2, strings.NewReader(p2), int64(len(p2)), storage.PartOptions{})
	if err != nil {
		t.Fatal(err)
	}
	info, err := x.CompleteMultipartUpload(bg, "classes", "mp", id,
		[]storage.CompletePart{{Number: 1, ETag: pi1.ETag}, {Number: 2, ETag: pi2.ETag}}, storage.PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if info.StorageClass != "BALANCED" {
		t.Errorf("Complete StorageClass = %q", info.StorageClass)
	}
	v := metaOn(t, dirs, 0, "classes", "mp").Versions[0]
	if v.Erasure.DataBlocks != 6 || v.Erasure.ParityBlocks != 2 || v.StorageClass != "BALANCED" || len(v.Parts) != 2 {
		t.Errorf("recorded %+v", v)
	}
	lose(t, dirs, 2, "classes", "mp")
	if got, err := read(t, x, "classes", "mp"); err != nil || got != p1+p2 {
		t.Errorf("read after losing 2 drives: err=%v equal=%v", err, got == p1+p2)
	}
}

func TestStorageClassHealAndReopen(t *testing.T) {
	x, dirs := classSet(t)
	mkbucket(t, x, "classes")
	body := strings.Repeat("h", 250_000)
	putClass(t, x, "classes", "rrs", body, "REDUCED_REDUNDANCY")
	putClass(t, x, "classes", "arc", body, "BALANCED")
	for _, k := range []string{"rrs", "arc"} {
		for _, p := range shardPathsOn(t, dirs, 3, "classes", k) {
			os.Remove(p)
		}
		res, err := x.HealObject(bg, "classes", k, true)
		if err != nil {
			t.Fatalf("heal %s: %v", k, err)
		}
		if len(shardPathsOn(t, dirs, 3, "classes", k)) == 0 {
			t.Errorf("%s: shards not rebuilt (%+v)", k, res)
		}
		if got, err := read(t, x, "classes", k); err != nil || got != body {
			t.Errorf("%s after heal: %v", k, err)
		}
	}
	// A restart with different class settings keeps reading what was written.
	x.Close()
	y := openXL(t, dirs, classLayout, func(o *Options) { o.StorageClasses = map[string]int{"OTHER": 3} })
	for _, k := range []string{"rrs", "arc"} {
		if got, err := read(t, y, "classes", k); err != nil || got != body {
			t.Errorf("%s after reopening with other classes: %v", k, err)
		}
	}
	st, _ := y.StatObject(bg, "classes", "arc", storage.GetOptions{})
	if st.StorageClass != "BALANCED" {
		t.Errorf("class after reopen = %q", st.StorageClass)
	}
}

func TestStorageClassConfigValidation(t *testing.T) {
	for name, classes := range map[string]map[string]int{
		"parity above half the drives":    {"BIG": 5},
		"zero parity":                     {"NONE": 0},
		"redefining STANDARD":             {"STANDARD": 3},
		"lower-case name":                 {"cold": 2},
		"name with a space":               {"A B": 2},
		"REDUCED_REDUNDANCY out of range": {"REDUCED_REDUNDANCY": 6},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := New(driveDirs(t, 8), Options{Locker: nslock.New(10 * time.Second), Logger: discard, ParityBlocks: 2, StorageClasses: classes, ScanInterval: -1})
			if err == nil {
				t.Error("accepted")
			}
		})
	}
	// STANDARD may be restated when it matches.
	x, err := New(driveDirs(t, 8), Options{Locker: nslock.New(10 * time.Second), Logger: discard, ParityBlocks: 2,
		StorageClasses: map[string]int{"STANDARD": 2, "COLD": 1}, ScanInterval: -1})
	if err != nil {
		t.Fatalf("matching STANDARD: %v", err)
	}
	x.Close()
}
