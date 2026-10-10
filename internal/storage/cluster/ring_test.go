package cluster

import (
	"fmt"
	"testing"
)

func keys(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("dir%03d/object-%06d", i%97, i)
	}
	return out
}

func TestRingBalance(t *testing.T) {
	ids := []string{"p0s0", "p0s1", "p0s2", "p0s3", "p1s0"}
	r := NewRing(ids, 0)
	counts := make([]int, len(ids))
	const n = 50000
	for _, k := range keys(n) {
		counts[r.Locate("bucket", k)]++
	}
	want := float64(n) / float64(len(ids))
	for i, c := range counts {
		if dev := (float64(c) - want) / want; dev > 0.25 || dev < -0.25 {
			t.Errorf("set %s got %d keys, %.0f%% off the mean", ids[i], c, dev*100)
		}
	}
}

func TestRingDeterministic(t *testing.T) {
	a := NewRing([]string{"a", "b", "c"}, 0)
	b := NewRing([]string{"a", "b", "c"}, 0)
	for _, k := range keys(2000) {
		if a.Locate("bk", k) != b.Locate("bk", k) {
			t.Fatalf("two rings built from the same sets disagree on %q", k)
		}
	}
}

// TestRingExpansion is the property pool add relies on: growing the ring
// moves keys only onto the new sets, and about their fair share.
func TestRingExpansion(t *testing.T) {
	old := []string{"p0s0", "p0s1", "p0s2"}
	grown := append(append([]string(nil), old...), "p1s0", "p1s1")
	r1, r2 := NewRing(old, 0), NewRing(grown, 0)
	moved, toNew := 0, 0
	const n = 30000
	for _, k := range keys(n) {
		a, b := old[r1.Locate("bk", k)], grown[r2.Locate("bk", k)]
		if a == b {
			continue
		}
		moved++
		if b == "p1s0" || b == "p1s1" {
			toNew++
		} else {
			t.Fatalf("key %q moved between existing sets %s -> %s", k, a, b)
		}
	}
	frac := float64(moved) / n
	if want := 2.0 / 5.0; frac < want*0.7 || frac > want*1.3 {
		t.Errorf("%.1f%% of keys moved, expected about %.0f%%", frac*100, want*100)
	}
	if toNew != moved {
		t.Errorf("%d of %d moved keys went somewhere other than a new set", moved-toNew, moved)
	}
}

func TestRingSingleAndEmpty(t *testing.T) {
	if got := NewRing([]string{"only"}, 0).Locate("b", "k"); got != 0 {
		t.Errorf("single set = %d", got)
	}
	if got := NewRing(nil, 0).Locate("b", "k"); got != -1 {
		t.Errorf("empty ring = %d", got)
	}
}
