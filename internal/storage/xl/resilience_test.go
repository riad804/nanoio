package xl

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"nanoio/internal/meta"
	"nanoio/internal/storage"
)

// A slow node must cost a write neither its full latency nor correctness:
// the write returns once its quorum is durable, and heal repairs the drives
// that were left behind.
func TestSlowNodeDoesNotStallWrites(t *testing.T) {
	tn := newThreeNodesWith(t, func(o *Options) {
		o.StragglerGrace = 100 * time.Millisecond
		o.WriteQueue = 2
		o.WriteStallTimeout = 150 * time.Millisecond
	})
	x := tn.x
	mkbucket(t, x, "slow")
	put(t, x, "slow", "warm", "warm-up") // establish connections and caches

	tn.net.Delay("n1:9000", "n3:9000", 2*time.Second)
	settle()
	body := strings.Repeat("0123456789abcdef", 24<<10) // 384 KiB: ~25 blocks of 16 KiB at 4+2 and 4 KiB blocks

	start := time.Now()
	info := put(t, x, "slow", "big", body)
	took := time.Since(start)
	if took > 1500*time.Millisecond {
		t.Errorf("a write with one node 2s away took %v; it should return at quorum", took)
	}
	if info.Size != int64(len(body)) {
		t.Errorf("size %d", info.Size)
	}

	// Metadata reads return at quorum too.
	start = time.Now()
	if _, err := x.StatObject(bg, "slow", "big", storage.GetOptions{}); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 1500*time.Millisecond {
		t.Errorf("Stat with one node 2s away took %v", d)
	}

	// The object is whole, and heal converges the drives that missed it.
	tn.net.Heal()
	waitOnline(t, x, 6)
	if got := mustRead(t, x, "slow", "big"); got != body {
		t.Fatal("object differs after a write that left stragglers")
	}
	if _, err := x.Scan(bg, true); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"warm", "big"} {
		eventuallyHealthy(t, x, "slow", key)
	}
}

// A commit delayed past a later write must not undo it: the drive's
// generation check (or the removed stage) refuses it, and the drives end up
// agreeing on the newer object.
func TestLateCommitCannotUndoANewerWrite(t *testing.T) {
	tn := newThreeNodesWith(t, func(o *Options) { o.StragglerGrace = 100 * time.Millisecond })
	x := tn.x
	mkbucket(t, x, "late")
	put(t, x, "late", "k", "version-0") // generation 1 everywhere

	// The next two commit RPCs to node 3 (its two drives of the next write)
	// are held for 1.5s.
	tn.net.DelayMatching("n1:9000", "n3:9000", "disk.commit", 1500*time.Millisecond, 2)
	start := time.Now()
	put(t, x, "late", "k", "version-1")
	if d := time.Since(start); d > time.Second {
		t.Fatalf("the write waited %v for its stragglers", d)
	}
	put(t, x, "late", "k", "version-2") // lands everywhere, generation 3
	time.Sleep(2 * time.Second)         // the delayed commits arrive now

	if got := mustRead(t, x, "late", "k"); got != "version-2" {
		t.Fatalf("read = %q after a delayed commit landed; the newer write was undone", got)
	}
	gens := map[uint64]int{}
	for i, d := range x.drives {
		raw, err := d.ReadMeta(bg, "late", "k")
		if err != nil {
			t.Fatalf("drive %d: %v", i, err)
		}
		f, err := meta.Decode(raw)
		if err != nil {
			t.Fatal(err)
		}
		gens[f.Generation()]++
	}
	if len(gens) != 1 || gens[3] != len(x.drives) {
		t.Errorf("drives hold generations %v; every drive should be at 3", gens)
	}
	eventuallyHealthy(t, x, "late", "k")
}

// A quorum that cannot be met still fails, and cleanly, even though writers
// are now asynchronous.
func TestWriteFailsWhenQuorumIsLostMidStream(t *testing.T) {
	tn := newThreeNodesWith(t, func(o *Options) { o.StragglerGrace = 100 * time.Millisecond })
	x := tn.x
	mkbucket(t, x, "lost")
	tn.net.Partition([]string{"n1:9000"}, []string{"n2:9000"}, []string{"n3:9000"})
	settle()
	body := strings.Repeat("x", 64<<10)
	_, err := x.PutObject(bg, "lost", "k", strings.NewReader(body), int64(len(body)), storage.PutOptions{})
	if err == nil {
		t.Fatal("a write with 2 of 6 drives succeeded")
	}
	tn.net.Heal()
	waitOnline(t, x, 6)
	if _, err := x.StatObject(bg, "lost", "k", storage.GetOptions{}); err == nil {
		t.Error("a refused write left an object behind")
	}
	// The set still works, and left no staging debris holding writers.
	put(t, x, "lost", "after", "fine")
	if got := mustRead(t, x, "lost", "after"); got != "fine" {
		t.Errorf("read = %q", got)
	}
}

func TestEvictedWritersDoNotLeakGoroutines(t *testing.T) {
	tn := newThreeNodesWith(t, func(o *Options) {
		o.StragglerGrace = 20 * time.Millisecond
		o.WriteQueue = 1
		o.WriteStallTimeout = 50 * time.Millisecond
	})
	x := tn.x
	mkbucket(t, x, "leak")
	tn.net.Delay("n1:9000", "n2:9000", 300*time.Millisecond)
	for i := 0; i < 5; i++ {
		put(t, x, "leak", fmt.Sprintf("k%d", i), strings.Repeat("y", 32<<10))
	}
	tn.net.Heal()
	// Evicted writers finish their abort once the slow calls return.
	time.Sleep(time.Second)
	if g := countWriterGoroutines(); g != 0 {
		t.Errorf("%d shard-writer goroutines still running", g)
	}
}

func countWriterGoroutines() int {
	buf := make([]byte, 1<<20)
	n := runtimeStack(buf)
	return strings.Count(string(buf[:n]), "(*shardWriter).run")
}

// eventuallyHealthy runs deep heals until the object needs none. A queued
// background repair may be running at the same time, so the first call is
// not necessarily the one that finds nothing to do.
func eventuallyHealthy(t *testing.T, x *XL, bucket, key string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		res, err := x.HealObject(bg, bucket, key, true)
		if err == nil && res.Skipped == "healthy" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s/%s never became healthy: %+v, %v", bucket, key, res, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
