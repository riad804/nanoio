package xl

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"nanoio/internal/storage"
)

var l44 = layout{"4+4", 8, 4, 32 << 10}
var l62 = layout{"6+2", 8, 2, 32 << 10}

// kill removes a drive's directory, as a dead disk would vanish.
func kill(t *testing.T, dirs []string, idx ...int) {
	t.Helper()
	for _, i := range idx {
		// A live scanner may be writing into the directory; retry.
		var err error
		for try := 0; try < 50; try++ {
			if err = os.RemoveAll(dirs[i]); err == nil {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}

// replace swaps a drive for a blank one.
func replace(t *testing.T, dirs []string, idx ...int) {
	t.Helper()
	kill(t, dirs, idx...)
	for _, i := range idx {
		if err := os.MkdirAll(dirs[i], 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func fill(t *testing.T, x *XL, bucket string, n int, seed int64) map[string]string {
	t.Helper()
	rng := rand.New(rand.NewSource(seed))
	out := map[string]string{}
	for i := 0; i < n; i++ {
		key := fmt.Sprintf("d%d/obj-%03d", i%4, i)
		body := string(randBytes(rng, rng.Intn(3*int(x.blockSize))+1))
		put(t, x, bucket, key, body)
		out[key] = body
	}
	return out
}

func checkAll(t *testing.T, x *XL, bucket string, want map[string]string) {
	t.Helper()
	for key, body := range want {
		got, err := read(t, x, bucket, key)
		if err != nil {
			t.Fatalf("read %s: %v", key, err)
		}
		if got != body {
			t.Fatalf("SILENT CORRUPTION: %s", key)
		}
	}
}

func TestReadsSurviveLosingParityDrives(t *testing.T) {
	for _, l := range []layout{l44, l62, {"3+1", 4, 1, 16 << 10}} {
		t.Run(l.name, func(t *testing.T) {
			x, dirs := newXL(t, l)
			mkbucket(t, x, "loss")
			objs := fill(t, x, "loss", 12, 1)
			rng := rand.New(rand.NewSource(2))
			kill(t, dirs, pickDrives(rng, l.drives, l.parity)...)
			checkAll(t, x, "loss", objs)
			info, _ := x.Info(bg)
			if info.Healthy || info.Disks != l.drives || x.OnlineDrives() != l.drives-l.parity {
				t.Errorf("Info = %+v online=%d", info, x.OnlineDrives())
			}
			// Listings and stats still work.
			res, err := x.ListObjects(bg, "loss", storage.ListOptions{})
			if err != nil || len(res.Objects) != len(objs) {
				t.Errorf("listing with %d drives down: %d objects, %v", l.parity, len(res.Objects), err)
			}
		})
	}
}

func TestLosingMoreThanParityIsUnavailableNotMissing(t *testing.T) {
	x, dirs := newXL(t, l44)
	mkbucket(t, x, "toomany")
	objs := fill(t, x, "toomany", 3, 3)
	kill(t, dirs, 0, 1, 2, 3, 4) // M+1 drives gone
	for key := range objs {
		_, err := read(t, x, "toomany", key)
		if !errors.Is(err, storage.ErrBackendUnavailable) {
			t.Errorf("%s: error = %v, want ErrBackendUnavailable (not NotFound, not data)", key, err)
		}
		if errors.Is(err, storage.ErrObjectNotFound) {
			t.Errorf("an object on unreachable drives must not be reported as nonexistent")
		}
	}
	if _, err := x.PutObject(bg, "toomany", "new", strings.NewReader("x"), 1, storage.PutOptions{}); err == nil {
		t.Error("a write succeeded with fewer drives than the write quorum")
	}
}

// With K == M the write quorum is K+1, so losing M drives leaves reads
// working but refuses writes; with K > M, losing M drives still allows them.
func TestWriteQuorumRules(t *testing.T) {
	t.Run("K==M refuses writes at M drives down", func(t *testing.T) {
		x, dirs := newXL(t, l44)
		mkbucket(t, x, "wqr")
		put(t, x, "wqr", "before", "stays readable")
		kill(t, dirs, 0, 1, 2, 3)
		if got := mustRead(t, x, "wqr", "before"); got != "stays readable" {
			t.Error("read failed")
		}
		_, err := x.PutObject(bg, "wqr", "after", strings.NewReader("x"), 1, storage.PutOptions{})
		if !errors.Is(err, storage.ErrBackendUnavailable) {
			t.Errorf("error = %v, want ErrBackendUnavailable", err)
		}
		if _, err := read(t, x, "wqr", "after"); !errors.Is(err, storage.ErrObjectNotFound) && !errors.Is(err, storage.ErrBackendUnavailable) {
			t.Errorf("a refused write left something readable: %v", err)
		}
	})
	t.Run("K>M keeps accepting writes at M drives down", func(t *testing.T) {
		x, dirs := newXL(t, l62)
		mkbucket(t, x, "wqr")
		kill(t, dirs, 3, 6)
		put(t, x, "wqr", "degraded", "written with two drives down")
		if got := mustRead(t, x, "wqr", "degraded"); got != "written with two drives down" {
			t.Error("read back differs")
		}
		// Bring the drives back; the scanner re-protects the object.
		replace(t, dirs, 3, 6)
		st, err := x.Scan(bg, true)
		if err != nil || st.DrivesFormatted != 2 {
			t.Fatalf("scan = %+v, %v", st, err)
		}
		// The background repair a degraded write queues may have rebuilt
		// some of it first; what matters is where things stand.
		for _, d := range []int{3, 6} {
			metaOn(t, dirs, d, "wqr", "degraded")
		}
		if res, _ := x.HealObject(bg, "wqr", "degraded", true); res.Skipped != "healthy" {
			t.Fatalf("not healthy after the scan: %+v", res)
		}
		kill(t, dirs, 0, 1) // two different drives now
		if got := mustRead(t, x, "wqr", "degraded"); got != "written with two drives down" {
			t.Error("not redundant after healing")
		}
	})
}

func TestFailedCommitRollsBack(t *testing.T) {
	for _, point := range []string{FaultPreCommit, FaultDataRenamed, FaultMetaRenamed} {
		t.Run(point, func(t *testing.T) {
			var failOn atomic.Value
			failOn.Store(map[int]bool{})
			x, dirs := newXL(t, l44, func(o *Options) {
				o.Fault = func(p string, d int) error {
					if p == point && failOn.Load().(map[int]bool)[d] {
						return errors.New("injected drive failure")
					}
					return nil
				}
			})
			mkbucket(t, x, "rbk")
			put(t, x, "rbk", "k", "original content")
			put(t, x, "rbk", "other", "untouched")

			// Four of eight drives fail: commits reach 4 < write quorum 5.
			failOn.Store(map[int]bool{0: true, 2: true, 4: true, 6: true})
			_, err := x.PutObject(bg, "rbk", "k", strings.NewReader("replacement"), 11, storage.PutOptions{})
			if !errors.Is(err, storage.ErrBackendUnavailable) {
				t.Fatalf("error = %v, want ErrBackendUnavailable", err)
			}
			// The old object is whole, on every drive, with one data dir each.
			if got := mustRead(t, x, "rbk", "k"); got != "original content" {
				t.Fatalf("object after a failed overwrite = %q", got)
			}
			for d := range dirs {
				if n := len(shardPathsOn(t, dirs, d, "rbk", "k")); n != 1 {
					t.Errorf("drive %d has %d shard files; a rolled-back write left debris", d, n)
				}
				if f := metaOn(t, dirs, d, "rbk", "k"); f.Latest().ETag != md5hex("original content") {
					t.Errorf("drive %d xl.meta was not restored", d)
				}
			}
			// A failed *new* key leaves nothing at all.
			_, err = x.PutObject(bg, "rbk", "fresh", strings.NewReader("never"), 5, storage.PutOptions{})
			if err == nil {
				t.Fatal("write succeeded below quorum")
			}
			for d := range dirs {
				if _, err := os.Stat(objDirOn(dirs, d, "rbk", "fresh")); err == nil {
					if entries, _ := os.ReadDir(objDirOn(dirs, d, "rbk", "fresh")); len(entries) > 0 {
						t.Errorf("drive %d kept %v of a rolled-back new object", d, entries)
					}
				}
			}
			if _, err := read(t, x, "rbk", "fresh"); err == nil {
				t.Error("rolled-back object is readable")
			}
			// Staging is clean, and writes resume once the faults clear.
			for d := range dirs {
				if es, _ := os.ReadDir(filepath.Join(dirs[d], ".nanoio.sys", "tmp")); len(es) != 0 {
					t.Errorf("drive %d staging not cleaned: %v", d, es)
				}
			}
			failOn.Store(map[int]bool{})
			put(t, x, "rbk", "k", "now it works")
			if got := mustRead(t, x, "rbk", "k"); got != "now it works" {
				t.Errorf("after recovery: %q", got)
			}
		})
	}
}

func TestPartialCommitStaysConsistentAndIsHealed(t *testing.T) {
	// Drives 1 and 5 refuse every commit while the fault is armed, so they
	// miss the overwrite and the background repair cannot fix them yet.
	var armed atomic.Bool
	x, dirs := newXL(t, l62, func(o *Options) {
		o.Fault = func(p string, d int) error {
			if armed.Load() && p == FaultPreCommit && (d == 1 || d == 5) {
				return errors.New("injected")
			}
			return nil
		}
	})
	mkbucket(t, x, "pcm")
	put(t, x, "pcm", "k", "version one")
	armed.Store(true)
	put(t, x, "pcm", "k", "version two, longer than one")

	// Exactly the quorum (6 of 8) holds the new version; two drives hold the
	// old one and must never be served.
	stale := func() int {
		n := 0
		for d := range dirs {
			if metaOn(t, dirs, d, "pcm", "k").Latest().ETag == md5hex("version one") {
				n++
			}
		}
		return n
	}
	for i := 0; i < 25; i++ {
		if got := mustRead(t, x, "pcm", "k"); got != "version two, longer than one" {
			t.Fatalf("read #%d returned %q: a stale drive influenced the result", i, got)
		}
	}
	if n := stale(); n != 2 {
		t.Fatalf("%d stale drives, want 2", n)
	}
	st, err := x.StatObject(bg, "pcm", "k", storage.GetOptions{})
	if err != nil || st.ETag != md5hex("version two, longer than one") {
		t.Fatalf("stat = %+v %v", st, err)
	}
	// Once the drives can commit again, healing brings them up to date.
	armed.Store(false)
	res, err := x.HealObject(bg, "pcm", "k", false)
	if err != nil || len(res.Healed) != 2 {
		t.Fatalf("heal = %+v %v", res, err)
	}
	if n := stale(); n != 0 {
		t.Fatalf("%d drives still stale after healing", n)
	}
	for _, d := range []int{1, 5} {
		if n := len(shardPathsOn(t, dirs, d, "pcm", "k")); n != 1 {
			t.Errorf("drive %d holds %d shard files (old data dir not replaced)", d, n)
		}
	}
	kill(t, dirs, 0, 2) // full redundancy again
	if got := mustRead(t, x, "pcm", "k"); got != "version two, longer than one" {
		t.Errorf("after healing and losing two drives: %q", got)
	}
}

func TestDriveReplacementIsFormattedAndRepopulated(t *testing.T) {
	x, dirs := newXL(t, l44)
	mkbucket(t, x, "repl")
	objs := fill(t, x, "repl", 10, 4)
	mp, _ := x.NewMultipartUpload(bg, "repl", "pending", storage.PutOptions{})
	_ = mp

	replace(t, dirs, 1, 6)
	if x.OnlineDrives() != 6 {
		t.Fatalf("online = %d", x.OnlineDrives())
	}
	st, err := x.Scan(bg, true)
	if err != nil {
		t.Fatal(err)
	}
	if st.DrivesFormatted != 2 || st.ShardsHealed < 2*len(objs) || st.BucketsHealed != 2 {
		t.Errorf("stats = %+v", st)
	}
	if x.OnlineDrives() != 8 {
		t.Errorf("online after scan = %d", x.OnlineDrives())
	}
	// The new drives carry format identity and every object.
	for _, d := range []int{1, 6} {
		if _, err := os.Stat(filepath.Join(dirs[d], ".nanoio.sys", "format.json")); err != nil {
			t.Errorf("drive %d not formatted: %v", d, err)
		}
		for key := range objs {
			metaOn(t, dirs, d, "repl", key)
		}
	}
	// A second pass finds nothing to do.
	st2, err := x.Scan(bg, true)
	if err != nil || st2.ShardsHealed != 0 || st2.DrivesFormatted != 0 {
		t.Errorf("second scan changed things: %+v %v", st2, err)
	}
	// Full redundancy: any 4 drives can now be lost.
	kill(t, dirs, 0, 2, 3, 7)
	checkAll(t, x, "repl", objs)
}

func TestDanglingRemnantsAreRemoved(t *testing.T) {
	setup := func(t *testing.T) (*XL, []string) {
		x, dirs := newXL(t, l44)
		mkbucket(t, x, "dng")
		put(t, x, "dng", "ghost", "a write that never reached quorum")
		put(t, x, "dng", "real", "a healthy object")
		for _, d := range []int{0, 1, 2, 3, 4} { // leaves 3 copies: below K=4
			os.RemoveAll(objDirOn(dirs, d, "dng", "ghost"))
		}
		return x, dirs
	}
	t.Run("removed when every drive answered, including a blank replacement", func(t *testing.T) {
		x, dirs := setup(t)
		if _, err := read(t, x, "dng", "ghost"); !errors.Is(err, storage.ErrObjectNotFound) {
			t.Fatalf("a below-quorum object must read as missing: %v", err)
		}
		res, err := x.ListObjects(bg, "dng", storage.ListOptions{})
		if err != nil || len(res.Objects) != 1 || res.Objects[0].Name != "real" {
			t.Fatalf("listing shows the remnant: %+v %v", res, err)
		}
		st, err := x.Scan(bg, false)
		if err != nil || st.Dangling != 1 {
			t.Fatalf("scan = %+v, %v", st, err)
		}
		for d := range dirs {
			if _, err := os.Stat(objDirOn(dirs, d, "dng", "ghost")); err == nil {
				t.Errorf("drive %d still holds the remnant", d)
			}
		}
		if got := mustRead(t, x, "dng", "real"); got != "a healthy object" {
			t.Error("collateral damage to a healthy object")
		}
	})
	t.Run("kept when a drive is unavailable", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("permission bits do not bind root")
		}
		x, dirs := setup(t)
		// One drive cannot answer but still holds its data (unreadable, not
		// erased): the remnant might be recoverable once it returns.
		if err := os.Chmod(dirs[7], 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(dirs[7], 0o755) })
		st, err := x.Scan(bg, false)
		if err != nil || st.Dangling != 0 {
			t.Fatalf("scan = %+v, %v", st, err)
		}
		// The remnants were on drives 5, 6 and 7; 7 is unreadable right now.
		for _, d := range []int{5, 6} {
			if _, err := os.Stat(objDirOn(dirs, d, "dng", "ghost")); err != nil {
				t.Errorf("drive %d lost its remnant although a drive could not answer: %v", d, err)
			}
		}
		os.Chmod(dirs[7], 0o755)
		if _, err := os.Stat(objDirOn(dirs, 7, "dng", "ghost")); err != nil {
			t.Errorf("the unreachable drive's copy was touched: %v", err)
		}
	})
}

func TestReadDamageQueuesBackgroundRepair(t *testing.T) {
	x, dirs := newXL(t, l44)
	mkbucket(t, x, "bgr")
	body := string(randBytes(rand.New(rand.NewSource(6)), 100000))
	put(t, x, "bgr", "o", body)
	victims := []int{0, 3, 5}
	for _, d := range victims {
		for _, p := range shardPathsOn(t, dirs, d, "bgr", "o") {
			os.Remove(p)
		}
	}
	if got := mustRead(t, x, "bgr", "o"); got != body {
		t.Fatal("degraded read differs")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		missing := 0
		for _, d := range victims {
			if len(shardPathsOn(t, dirs, d, "bgr", "o")) == 0 {
				missing++
			}
		}
		if missing == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d shards still missing after 5s: the read did not trigger a repair", missing)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestBackgroundScannerRepairsWithoutBeingAsked(t *testing.T) {
	x, dirs := newXL(t, l62, func(o *Options) { o.ScanInterval = 40 * time.Millisecond })
	mkbucket(t, x, "auto")
	objs := fill(t, x, "auto", 6, 9)
	replace(t, dirs, 2)
	for key := range objs {
		for _, p := range shardPathsOn(t, dirs, 5, "auto", key) {
			flipByteIn(t, rand.New(rand.NewSource(1)), p)
		}
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		ok := true
		for key := range objs {
			if _, err := os.Stat(filepath.Join(objDirOn(dirs, 2, "auto", key), "xl.meta")); err != nil {
				ok = false
			}
		}
		if ok && x.OnlineDrives() == 8 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the scanner did not repopulate the replaced drive in 10s")
		}
		time.Sleep(25 * time.Millisecond)
	}
	// Close must not hang on the loop.
	done := make(chan struct{})
	go func() { x.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close hung")
	}
}

func TestStrayShardOnOneDriveIsNotListed(t *testing.T) {
	x, dirs := newXL(t, l44)
	mkbucket(t, x, "stray")
	put(t, x, "stray", "real", "x")
	// Copy a whole object directory to one drive under another key.
	src := objDirOn(dirs, 0, "stray", "real")
	dst := objDirOn(dirs, 0, "stray", "stray-key")
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := copyDir(src, dst); err != nil {
		t.Fatal(err)
	}
	res, err := x.ListObjects(bg, "stray", storage.ListOptions{})
	if err != nil || len(res.Objects) != 1 {
		t.Fatalf("listing = %+v %v", res, err)
	}
	if _, err := read(t, x, "stray", "stray-key"); !errors.Is(err, storage.ErrObjectNotFound) {
		t.Errorf("read of a one-drive remnant: %v", err)
	}
}

func copyDir(src, dst string) error {
	return filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o644)
	})
}

func TestUnwritableDriveIsSkippedNotFatal(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission bits do not bind root")
	}
	x, dirs := newXL(t, l62)
	mkbucket(t, x, "rof")
	tmp := filepath.Join(dirs[4], ".nanoio.sys", "tmp")
	os.Chmod(tmp, 0o500)
	t.Cleanup(func() { os.Chmod(tmp, 0o755) })
	body := string(randBytes(rand.New(rand.NewSource(3)), 90000))
	put(t, x, "rof", "o", body)
	if got := mustRead(t, x, "rof", "o"); got != body {
		t.Fatal("read differs")
	}
	if _, err := os.Stat(filepath.Join(objDirOn(dirs, 4, "rof", "o"), "xl.meta")); err == nil {
		t.Error("the unwritable drive somehow received the object")
	}
	os.Chmod(tmp, 0o755)
	if res, err := x.HealObject(bg, "rof", "o", false); err != nil || len(res.Healed) != 1 || res.Healed[0] != 4 {
		t.Errorf("heal = %+v %v", res, err)
	}
}

func TestCancelledWriteLeavesNothingBehind(t *testing.T) {
	x, dirs := newXL(t, l44)
	mkbucket(t, x, "cancel")
	put(t, x, "cancel", "keep", "original")
	pr, pw := io.Pipe()
	ctx, cancel := contextWithCancel()
	done := make(chan error, 1)
	go func() {
		_, err := x.PutObject(ctx, "cancel", "keep", pr, 1<<20, storage.PutOptions{})
		pr.Close() // unblock the writer below, as a real client connection would
		done <- err
	}()
	pw.Write(make([]byte, 100000))
	cancel()
	pw.Write(make([]byte, 100000))
	pw.Close()
	if err := <-done; err == nil {
		t.Fatal("cancelled PutObject succeeded")
	}
	if got := mustRead(t, x, "cancel", "keep"); got != "original" {
		t.Errorf("object = %q", got)
	}
	for d := range dirs {
		if es, _ := os.ReadDir(filepath.Join(dirs[d], ".nanoio.sys", "tmp")); len(es) != 0 {
			t.Errorf("drive %d staging not cleaned: %v", d, es)
		}
	}
}

func TestReadsDuringDriveLossStayCorrect(t *testing.T) {
	x, dirs := newXL(t, l44)
	mkbucket(t, x, "live")
	objs := fill(t, x, "live", 8, 7)
	var failures, reads atomic.Int64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				for key, body := range objs {
					got, err := read(t, x, "live", key)
					reads.Add(1)
					if err != nil || got != body {
						failures.Add(1)
						t.Errorf("read %s during drive loss: err=%v match=%v", key, err, got == body)
						return
					}
				}
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	kill(t, dirs, 0)
	time.Sleep(30 * time.Millisecond)
	kill(t, dirs, 5)
	time.Sleep(30 * time.Millisecond)
	kill(t, dirs, 2, 7)
	time.Sleep(60 * time.Millisecond)
	close(stop)
	wg.Wait()
	if failures.Load() != 0 || reads.Load() == 0 {
		t.Errorf("%d failures in %d reads", failures.Load(), reads.Load())
	}
}

func TestMultipartUploadWithDrivesDown(t *testing.T) {
	x, dirs := newXL(t, l62, func(o *Options) { o.MinPartSize = 16 })
	mkbucket(t, x, "mpd")
	rng := rand.New(rand.NewSource(12))
	id, err := x.NewMultipartUpload(bg, "mpd", "obj", storage.PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var want []byte
	var cp []storage.CompletePart
	for n := 1; n <= 4; n++ {
		if n == 2 {
			kill(t, dirs, 1) // a drive dies mid-upload
		}
		if n == 3 {
			kill(t, dirs, 6) // and another
		}
		p := randBytes(rng, 40000+n*1000)
		info, err := x.PutObjectPart(bg, "mpd", "obj", id, n, bytes.NewReader(p), int64(len(p)), storage.PartOptions{})
		if err != nil {
			t.Fatalf("part %d with %d drives down: %v", n, n-1, err)
		}
		cp = append(cp, storage.CompletePart{Number: n, ETag: info.ETag})
		want = append(want, p...)
	}
	parts, err := x.ListObjectParts(bg, "mpd", "obj", id, storage.ListPartsOptions{})
	if err != nil || len(parts.Parts) != 4 {
		t.Fatalf("parts = %+v %v", parts, err)
	}
	if _, err := x.CompleteMultipartUpload(bg, "mpd", "obj", id, cp, storage.PutOptions{}); err != nil {
		t.Fatalf("complete: %v", err)
	}
	if got := mustRead(t, x, "mpd", "obj"); got != string(want) {
		t.Fatal("assembled object differs")
	}
	// Replace the dead drives; healing rebuilds their shards of a
	// multipart object (all parts), after which they carry real weight.
	replace(t, dirs, 1, 6)
	if st, err := x.Scan(bg, true); err != nil || st.DrivesFormatted != 2 {
		t.Fatalf("scan = %+v %v", st, err)
	}
	for _, d := range []int{1, 6} {
		f := metaOn(t, dirs, d, "mpd", "obj")
		if len(f.Latest().Parts) != 4 {
			t.Fatalf("drive %d carries %d parts", d, len(f.Latest().Parts))
		}
	}
	if res, _ := x.HealObject(bg, "mpd", "obj", true); res.Skipped != "healthy" {
		t.Fatalf("multipart object not healthy after the scan: %+v", res)
	}
	kill(t, dirs, 0, 5)
	if got := mustRead(t, x, "mpd", "obj"); got != string(want) {
		t.Fatal("object differs after healing and losing two different drives")
	}
}

func TestFormatChecks(t *testing.T) {
	dirs := driveDirs(t, 4)
	l := layout{"2+2", 4, 2, 0}
	x := openXL(t, dirs, l)
	mkbucket(t, x, "fmt")
	put(t, x, "fmt", "k", "v")
	x.Close()

	reopen := func(d []string, parity int) error {
		y, err := New(d, Options{Locker: x.locker, Logger: discard, ParityBlocks: parity, ScanInterval: -1})
		if err == nil {
			y.Close()
		}
		return err
	}
	tests := []struct {
		name string
		do   func() error
		want string
	}{
		{"reopens cleanly", func() error { return reopen(dirs, 2) }, ""},
		{"reordered drives", func() error { return reopen([]string{dirs[1], dirs[0], dirs[2], dirs[3]}, 2) }, "reordered"},
		{"different parity", func() error { return reopen(dirs, 1) }, "formatted as 2+2"},
		{"a drive listed twice", func() error { return reopen([]string{dirs[0], dirs[0], dirs[2], dirs[3]}, 2) }, "twice"},
		{"too few drives", func() error { return reopen(dirs[:1], 1) }, "drives given"},
		{"parity above data", func() error { return reopen(dirs, 3) }, "1 <= parity <= data"},
		{"too many drives", func() error { return reopen(make([]string, 40), 20) }, "drives given"},
		{"foreign populated directory is never adopted", func() error {
			foreign := filepath.Join(t.TempDir(), "foreign")
			os.MkdirAll(foreign, 0o755)
			os.WriteFile(filepath.Join(foreign, "precious.txt"), []byte("do not adopt me"), 0o644)
			y, err := New([]string{dirs[0], dirs[1], dirs[2], foreign},
				Options{Locker: x.locker, Logger: discard, ParityBlocks: 2, ScanInterval: -1})
			if err != nil {
				return err
			}
			defer y.Close()
			// The set starts degraded (one drive counts as unavailable)
			// and the foreign directory is left exactly as it was.
			if y.OnlineDrives() != 3 {
				return fmt.Errorf("online drives = %d, want 3", y.OnlineDrives())
			}
			if _, err := y.Scan(bg, false); err != nil {
				return err
			}
			if b, err := os.ReadFile(filepath.Join(foreign, "precious.txt")); err != nil || string(b) != "do not adopt me" {
				return fmt.Errorf("foreign file damaged: %q %v", b, err)
			}
			if _, err := os.Stat(filepath.Join(foreign, ".nanoio.sys", "format.json")); err == nil {
				return errors.New("a populated foreign directory was formatted")
			}
			return nil
		}, ""},
		{"drive from another deployment", func() error {
			other := driveDirs(t, 4)
			o, err := New(other, Options{Locker: x.locker, Logger: discard, ParityBlocks: 2, ScanInterval: -1})
			if err != nil {
				return err
			}
			o.Close()
			return reopen([]string{dirs[0], dirs[1], dirs[2], other[3]}, 2)
		}, "deployment"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.do()
			switch {
			case tt.want == "" && err != nil:
				t.Errorf("unexpected error: %v", err)
			case tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)):
				t.Errorf("error = %v, want containing %q", err, tt.want)
			}
		})
	}
	t.Run("the data survived all of that", func(t *testing.T) {
		y := openXL(t, dirs, l)
		if got := mustRead(t, y, "fmt", "k"); got != "v" {
			t.Errorf("got %q", got)
		}
	})
	t.Run("a second process on the same drives is refused", func(t *testing.T) {
		y := openXL(t, dirs, l)
		_, err := New(dirs, Options{Locker: y.locker, Logger: discard, ParityBlocks: 2, ScanInterval: -1})
		if err == nil {
			t.Error("two instances opened the same drives")
		}
	})
	t.Run("a blank replacement joins an existing set at startup", func(t *testing.T) {
		replace(t, dirs, 2)
		y := openXL(t, dirs, l)
		if y.OnlineDrives() != 4 {
			t.Fatalf("online = %d", y.OnlineDrives())
		}
		if _, err := y.Scan(bg, true); err != nil {
			t.Fatal(err)
		}
		kill(t, dirs, 0, 3)
		if got := mustRead(t, y, "fmt", "k"); got != "v" {
			t.Errorf("got %q", got)
		}
	})
}

func TestBucketOperationsAcrossDrives(t *testing.T) {
	x, dirs := newXL(t, l62)
	kill(t, dirs, 7)
	mkbucket(t, x, "b-one") // created with one drive down
	if err := x.MakeBucket(bg, "b-one", storage.MakeBucketOptions{}); !errors.Is(err, storage.ErrBucketExists) {
		t.Errorf("duplicate: %v", err)
	}
	replace(t, dirs, 7)
	st, _ := x.Scan(bg, false)
	if st.DrivesFormatted != 1 || st.BucketsHealed != 1 {
		t.Errorf("scan = %+v", st)
	}
	if _, err := os.Stat(filepath.Join(dirs[7], "b-one")); err != nil {
		t.Errorf("bucket not recreated on the replacement: %v", err)
	}
	list, err := x.ListBuckets(bg)
	if err != nil || len(list) != 1 || list[0].Name != "b-one" || list[0].Created.IsZero() {
		t.Errorf("buckets = %+v %v", list, err)
	}
	// A bucket directory on fewer than K drives is not a bucket.
	for d := 0; d < 7; d++ {
		os.RemoveAll(filepath.Join(dirs[d], "b-one"))
	}
	os.MkdirAll(filepath.Join(dirs[0], "phantom"), 0o755)
	if ok, _ := x.BucketExists(bg, "phantom"); ok {
		t.Error("a directory on one drive counts as a bucket")
	}
	if ok, _ := x.BucketExists(bg, "b-one"); ok {
		t.Error("a bucket on one drive survived losing the rest")
	}
}

func TestCollectorExpiresUploadsAndOrphans(t *testing.T) {
	x, dirs := newXL(t, l44, func(o *Options) {
		o.UploadExpiry = time.Hour
		o.MinPartSize = 16
	})
	mkbucket(t, x, "gcc")
	put(t, x, "gcc", "live", "live object data")

	stale, _ := x.NewMultipartUpload(bg, "gcc", "stale", storage.PutOptions{})
	x.PutObjectPart(bg, "gcc", "stale", stale, 1, strings.NewReader("abandoned part"), 14, storage.PartOptions{})
	fresh, _ := x.NewMultipartUpload(bg, "gcc", "fresh", storage.PutOptions{})
	x.PutObjectPart(bg, "gcc", "fresh", fresh, 1, strings.NewReader("active part"), 11, storage.PartOptions{})
	old := time.Now().Add(-2 * time.Hour)
	for d := range dirs {
		os.Chtimes(filepath.Join(dirs[d], ".nanoio.sys", "multipart", "gcc", stale), old, old)
	}
	// An orphaned data directory next to a live object, on one drive.
	orphan := filepath.Join(objDirOn(dirs, 3, "gcc", "live"), ".nanoio-data-orphaned")
	os.MkdirAll(orphan, 0o755)
	os.WriteFile(filepath.Join(orphan, "part.1"), []byte("stale shard"), 0o644)
	// Old staging debris, and a fresh one that must stay.
	oldTmp := filepath.Join(dirs[1], ".nanoio.sys", "tmp", "ancient")
	os.MkdirAll(oldTmp, 0o755)
	os.Chtimes(oldTmp, old.Add(-48*time.Hour), old.Add(-48*time.Hour))
	freshTmp := filepath.Join(dirs[1], ".nanoio.sys", "tmp", "recent")
	os.MkdirAll(freshTmp, 0o755)

	x.tmpMaxAge = 24 * time.Hour
	st, err := x.Scan(bg, false)
	if err != nil {
		t.Fatal(err)
	}
	if st.ExpiredUploads != 8 || st.OrphanDirs != 1 || st.Staging != 1 {
		t.Errorf("stats = %+v", st)
	}
	ups, err := x.ListMultipartUploads(bg, "gcc", storage.ListUploadsOptions{})
	if err != nil || len(ups.Uploads) != 1 || ups.Uploads[0].UploadID != fresh {
		t.Errorf("uploads = %+v %v", ups.Uploads, err)
	}
	if _, err := x.ListObjectParts(bg, "gcc", "stale", stale, storage.ListPartsOptions{}); !errors.Is(err, storage.ErrNoSuchUpload) {
		t.Errorf("stale upload survived: %v", err)
	}
	if _, err := os.Stat(orphan); !errors.Is(err, os.ErrNotExist) {
		t.Error("orphan data dir survived")
	}
	if _, err := os.Stat(freshTmp); err != nil {
		t.Error("fresh staging removed")
	}
	if got := mustRead(t, x, "gcc", "live"); got != "live object data" {
		t.Errorf("live object damaged: %q", got)
	}
	if st2, _ := x.Scan(bg, false); st2.ExpiredUploads+st2.OrphanDirs != 0 {
		t.Errorf("second scan found more garbage: %+v", st2)
	}
}

func TestInfoAndLayout(t *testing.T) {
	x, dirs := newXL(t, l44)
	k, m, bs := x.Layout()
	if k != 4 || m != 4 || bs != 32<<10 {
		t.Errorf("layout = %d+%d bs=%d", k, m, bs)
	}
	info, err := x.Info(bg)
	if err != nil || info.Kind != "xl" || info.Disks != 8 || !info.Healthy || info.TotalBytes == 0 {
		t.Errorf("info = %+v %v", info, err)
	}
	kill(t, dirs, 0)
	if info, _ := x.Info(bg); info.Healthy {
		t.Error("a missing drive is not reflected in Healthy")
	}
	x.Close()
	if _, err := x.Info(bg); !errors.Is(err, storage.ErrBackendUnavailable) {
		t.Errorf("Info after Close: %v", err)
	}
}

// A drive whose directory vanished (an unmounted or removed disk) must stay
// offline: recreating the path would silently fill whatever is underneath.
func TestVanishedDriveDirectoryIsNotRecreated(t *testing.T) {
	x, dirs := newXL(t, l62)
	mkbucket(t, x, "vanish")
	objs := fill(t, x, "vanish", 5, 21)
	kill(t, dirs, 2)
	st, err := x.Scan(bg, false)
	if err != nil || st.DrivesFormatted != 0 {
		t.Fatalf("scan = %+v %v", st, err)
	}
	if _, err := os.Stat(dirs[2]); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the scanner recreated a vanished drive directory: %v", err)
	}
	checkAll(t, x, "vanish", objs)
	// Once an operator provides an empty directory, it joins and is filled.
	os.MkdirAll(dirs[2], 0o755)
	st, err = x.Scan(bg, true)
	if err != nil || st.DrivesFormatted != 1 || st.ShardsHealed != len(objs) {
		t.Fatalf("scan after provisioning = %+v %v", st, err)
	}
}
