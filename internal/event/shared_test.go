package event

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// memStore is an in-memory SharedStore several managers (nodes) share.
type memStore struct {
	mu     sync.Mutex
	objs   map[string][]byte
	leases map[string]chan struct{}
	fail   atomic.Bool
}

func newMemStore() *memStore {
	return &memStore{objs: map[string][]byte{}, leases: map[string]chan struct{}{}}
}

var errDown = errors.New("below quorum")

func (s *memStore) Put(_ context.Context, name string, data []byte) error {
	if s.fail.Load() {
		return errDown
	}
	s.mu.Lock()
	s.objs[name] = append([]byte(nil), data...)
	s.mu.Unlock()
	return nil
}

func (s *memStore) Get(_ context.Context, name string) ([]byte, error) {
	if s.fail.Load() {
		return nil, errDown
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.objs[name]
	if !ok {
		return nil, ErrSharedNotFound
	}
	return b, nil
}

func (s *memStore) Delete(_ context.Context, name string) error {
	if s.fail.Load() {
		return errDown
	}
	s.mu.Lock()
	delete(s.objs, name)
	s.mu.Unlock()
	return nil
}

func (s *memStore) List(_ context.Context, prefix string, max int) ([]string, error) {
	if s.fail.Load() {
		return nil, errDown
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for n := range s.objs {
		if strings.HasPrefix(n, prefix) {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	if len(out) > max {
		out = out[:max]
	}
	return out, nil
}

func (s *memStore) Lead(ctx context.Context, key string) (func(), error) {
	s.mu.Lock()
	ch := s.leases[key]
	if ch == nil {
		ch = make(chan struct{}, 1)
		s.leases[key] = ch
	}
	s.mu.Unlock()
	select {
	case ch <- struct{}{}:
		return func() { <-ch }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *memStore) count(prefix string) int {
	n, _ := s.List(context.Background(), prefix, 100000)
	return len(n)
}

func replicatedNode(t *testing.T, dir, node string, store *memStore, tgt Target, d Delivery) (*Manager, ConfigSource) {
	t.Helper()
	m, err := NewManager(Options{Dir: dir, Region: "us-east-1", Logger: quiet, SegmentBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	arn, err := m.AddTarget("webhook", "t", Spec{Target: tgt, Delivery: d})
	if err != nil {
		t.Fatal(err)
	}
	m.SetShared(store, node)
	return m, allEvents(t, m, arn)
}

func versions(t *testing.T, tgt *fakeTarget) map[string]int {
	t.Helper()
	out := map[string]int{}
	for _, e := range tgt.delivered() {
		out[e.Key+"#"+e.ETag]++
	}
	return out
}

// Two nodes publish; exactly one delivers; every event arrives, and each
// node's own events stay in order.
func TestReplicatedQueueHasOneLeaderAndKeepsOrder(t *testing.T) {
	store := newMemStore()
	tgt := &fakeTarget{}
	a, srcA := replicatedNode(t, t.TempDir(), "A", store, tgt, fastDelivery())
	b, srcB := replicatedNode(t, t.TempDir(), "B", store, tgt, fastDelivery())
	a.Start(srcA)
	b.Start(srcB)
	defer a.Close()
	defer b.Close()
	const n = 150
	for i := 0; i < n; i++ {
		a.Publish(put("b", "from-a", i))
		b.Publish(put("b", "from-b", i))
	}
	waitFor(t, "delivery", func() bool { return len(tgt.delivered()) >= 2*n })
	next := map[string]int{}
	for _, e := range tgt.delivered() {
		if e.ETag != fmt.Sprint(next[e.Key]) {
			t.Fatalf("%s: version %s, want %d (reordered or duplicated)", e.Key, e.ETag, next[e.Key])
		}
		next[e.Key]++
	}
	leaders := 0
	for _, m := range []*Manager{a, b} {
		st := m.Status(context.Background(), false)[0]
		if !st.Replicated {
			t.Error("status does not report replication")
		}
		if st.Leader {
			leaders++
		}
	}
	if leaders != 1 {
		t.Errorf("%d nodes are delivering, want exactly 1", leaders)
	}
	waitFor(t, "shared queue to drain", func() bool { return store.count(sharedPrefix+"webhook-t/q/") == 0 })
}

// The disk of the node that took the events is gone; the events were already
// replicated, so another node delivers them.
func TestReplicatedQueueSurvivesLosingTheOriginNode(t *testing.T) {
	store := newMemStore()
	down := &fakeTarget{fail: func([]*Event) error { return errors.New("webhook down") }}
	d := fastDelivery()
	d.MaxAttempts = -1
	dirA := t.TempDir()
	a, srcA := replicatedNode(t, dirA, "A", store, down, d)
	a.Start(srcA)
	const n = 80
	for i := 0; i < n; i++ {
		a.Publish(put("b", "obj", i))
	}
	waitFor(t, "shipping", func() bool { return a.Status(context.Background(), false)[0].Shipped == n })
	a.Close()
	os.RemoveAll(dirA) // the node and its disk are gone

	up := &fakeTarget{}
	b, srcB := replicatedNode(t, t.TempDir(), "B", store, up, fastDelivery())
	b.Start(srcB)
	defer b.Close()
	waitFor(t, "takeover delivery", func() bool { return len(up.delivered()) >= n })
	for i, e := range up.delivered()[:n] {
		if e.ETag != fmt.Sprint(i) {
			t.Fatalf("event %d is version %s", i, e.ETag)
		}
	}
}

// When the leader stops mid-stream another node continues; nothing is lost
// (a few may repeat).
func TestReplicatedLeaderFailover(t *testing.T) {
	store := newMemStore()
	tgt := &fakeTarget{}
	slow := &fakeTarget{}
	a, srcA := replicatedNode(t, t.TempDir(), "A", store, tgt, fastDelivery())
	b, srcB := replicatedNode(t, t.TempDir(), "B", store, slow, fastDelivery())
	a.Start(srcA)
	waitFor(t, "A to lead", func() bool { return a.Status(context.Background(), false)[0].Leader })
	b.Start(srcB)
	defer b.Close()
	for i := 0; i < 200; i++ {
		a.Publish(put("b", "k", i))
	}
	waitFor(t, "some delivery", func() bool { return len(tgt.delivered()) > 20 })
	a.Close()
	waitFor(t, "B to take over", func() bool { return b.Status(context.Background(), false)[0].Leader })
	waitFor(t, "all delivered across both", func() bool {
		seen := versions(t, tgt)
		for k, v := range versions(t, slow) {
			seen[k] += v
		}
		return len(seen) >= 200
	})
}

// With no quorum the event stays in the local queue, nothing is delivered
// from local state, and replication resumes when quorum returns.
func TestReplicationOutageFallsBackToLocalQueue(t *testing.T) {
	store := newMemStore()
	store.fail.Store(true)
	tgt := &fakeTarget{}
	m, src := replicatedNode(t, t.TempDir(), "A", store, tgt, fastDelivery())
	m.Start(src)
	defer m.Close()
	for i := 0; i < 30; i++ {
		m.Publish(put("b", "k", i))
	}
	waitFor(t, "ship failures", func() bool {
		st := m.Status(context.Background(), false)[0]
		return st.ShipFailures >= 2 && st.QueueLength == 30 && st.LastShipError != ""
	})
	if len(tgt.delivered()) != 0 {
		t.Fatal("events were delivered while the shared queue was unreachable")
	}
	store.fail.Store(false)
	waitFor(t, "recovery", func() bool { return len(tgt.delivered()) == 30 })
	if st := m.Status(context.Background(), false)[0]; st.QueueLength != 0 || st.Shipped != 30 {
		t.Errorf("status = %+v", st)
	}
}

func TestReplicatedDeadLettersAreShared(t *testing.T) {
	store := newMemStore()
	tgt := &fakeTarget{fail: func(ev []*Event) error {
		if ev[0].Key == "poison" {
			return errors.New("400")
		}
		return nil
	}}
	m, src := replicatedNode(t, t.TempDir(), "A", store, tgt, fastDelivery())
	m.Start(src)
	defer m.Close()
	m.Publish(put("b", "poison", 0))
	waitFor(t, "dead letter", func() bool { return store.count(sharedPrefix+"webhook-t/dead/") == 1 })
	arn := m.Status(context.Background(), false)[0].ARN
	dl, err := m.DeadLetters(arn, 10)
	if err != nil || len(dl) != 1 || dl[0].Attempts != 3 {
		t.Fatalf("dead letters = %+v, %v", dl, err)
	}
	n, err := m.Requeue(arn)
	if err != nil || n != 1 {
		t.Fatalf("requeue = %d, %v", n, err)
	}
	waitFor(t, "dead letter to return", func() bool { return store.count(sharedPrefix+"webhook-t/dead/") == 1 && tgt.calls.Load() > 3 })
}
