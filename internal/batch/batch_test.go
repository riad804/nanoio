package batch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// ----- definition -------------------------------------------------------

func TestParseYAMLAndJSON(t *testing.T) {
	yamlDoc := `
apiVersion: v1
replicate:
  source: {bucket: photos, prefix: "2024/"}
  target:
    endpoint: https://s3.example.com
    bucket: backup
    credentials: {accessKey: AK, secretKey: SK}
  filter:
    olderThan: 30d
    newerThan: 1w
    tags: [{key: class, value: gold}]
    minSize: 10
  retry: {attempts: 5, delay: 500ms}
  concurrency: 4
`
	d, err := Parse([]byte(yamlDoc))
	if err != nil {
		t.Fatal(err)
	}
	r := d.Replicate
	if d.Type() != TypeReplicate || r.Source.Bucket != "photos" || r.Source.Prefix != "2024/" ||
		r.Filter.OlderThan.D() != 30*24*time.Hour || r.Filter.NewerThan.D() != 7*24*time.Hour || r.Concurrency != 4 ||
		r.Retry.Attempts != 5 || r.Retry.Delay.D() != 500*time.Millisecond || *r.Filter.MinSize != 10 {
		t.Errorf("parsed = %+v", r)
	}
	// The same document as JSON parses too, and defaults are applied.
	d2, err := Parse([]byte(`{"expire":{"bucket":"logs","prefix":"old/","filter":{"olderThan":"90d"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if e := d2.Expire; e.Versions != "latest" || e.Concurrency != 2 || e.Retry.Attempts != 3 || e.Retry.Delay.D() != time.Second {
		t.Errorf("defaults = %+v", e)
	}
	d3, err := Parse([]byte("keyrotate:\n  bucket: secrets\n  encryption: {type: sse-kms, key: newkey}\n"))
	if err != nil || d3.Type() != TypeKeyRotate {
		t.Fatalf("keyrotate = %+v, %v", d3, err)
	}
}

func TestParseRefusals(t *testing.T) {
	for name, doc := range map[string]string{
		"empty":            "",
		"two types":        "expire: {bucket: a}\nkeyrotate: {bucket: a, encryption: {type: sse-s3}}",
		"none":             "apiVersion: v1",
		"unknown field":    "expire: {bucket: a, bukcet: b}",
		"bad version":      "apiVersion: v9\nexpire: {bucket: a}",
		"no bucket":        "expire: {prefix: x}",
		"bad versions":     "expire: {bucket: a, versions: some}",
		"unbounded purge":  "expire: {bucket: a, versions: all}",
		"bad duration":     "expire: {bucket: a, filter: {olderThan: soon}}",
		"newer >= older":   "expire: {bucket: a, filter: {olderThan: 1d, newerThan: 2d}}",
		"replicate no tgt": "replicate: {source: {bucket: a}}",
		"bad endpoint":     "replicate: {source: {bucket: a}, target: {endpoint: s3.example, bucket: b, credentials: {accessKey: a, secretKey: b}}}",
		"rotate no key":    "keyrotate: {bucket: a, encryption: {type: sse-kms}}",
		"rotate s3 + key":  "keyrotate: {bucket: a, encryption: {type: sse-s3, key: k}}",
		"too concurrent":   "expire: {bucket: a, concurrency: 1000}",
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// An explicit prefix makes the permanent removal acceptable.
	if _, err := Parse([]byte("expire: {bucket: a, prefix: tmp/, versions: all}")); err != nil {
		t.Error(err)
	}
}

func TestFilterMatches(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	d, err := Parse([]byte(`expire: {bucket: a, filter: {olderThan: 30d, minSize: 10, maxSize: 100, tags: [{key: tier, value: tmp}, {key: any}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	f := d.Expire.Filter
	old := now.Add(-40 * 24 * time.Hour)
	tags := map[string]string{"tier": "tmp", "any": "x"}
	for name, tt := range map[string]struct {
		mod  time.Time
		size int64
		tags map[string]string
		want bool
	}{
		"matches":      {old, 50, tags, true},
		"too young":    {now.Add(-10 * 24 * time.Hour), 50, tags, false},
		"too small":    {old, 5, tags, false},
		"too large":    {old, 500, tags, false},
		"wrong tag":    {old, 50, map[string]string{"tier": "prod", "any": "x"}, false},
		"missing tag":  {old, 50, map[string]string{"tier": "tmp"}, false},
		"untagged":     {old, 50, nil, false},
		"size at edge": {old, 100, tags, true},
	} {
		if got := f.Matches(tt.mod, tt.size, tt.tags, now); got != tt.want {
			t.Errorf("%s: %v, want %v", name, got, tt.want)
		}
	}
}

// ----- runner -------------------------------------------------------------

type memStore struct {
	mu   sync.Mutex
	objs map[string][]byte
}

func newMemStore() *memStore { return &memStore{objs: map[string][]byte{}} }

func (s *memStore) Put(_ context.Context, n string, d []byte) error {
	s.mu.Lock()
	s.objs[n] = append([]byte(nil), d...)
	s.mu.Unlock()
	return nil
}

func (s *memStore) Get(_ context.Context, n string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.objs[n]
	if !ok {
		return nil, ErrNotFound
	}
	return b, nil
}

func (s *memStore) Delete(_ context.Context, n string) error {
	s.mu.Lock()
	delete(s.objs, n)
	s.mu.Unlock()
	return nil
}

func (s *memStore) List(_ context.Context, prefix string, max int) ([]string, error) {
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

type memLocker struct {
	mu   sync.Mutex
	held map[string]bool
}

func (l *memLocker) TryLock(_ context.Context, name string) (func(), bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.held == nil {
		l.held = map[string]bool{}
	}
	if l.held[name] {
		return nil, false, nil
	}
	l.held[name] = true
	return func() {
		l.mu.Lock()
		delete(l.held, name)
		l.mu.Unlock()
	}, true, nil
}

// fakeOp enumerates n numbered objects and does them via do.
type fakeOp struct {
	n   int
	do  func(it Item) (ItemResult, error)
	cur atomic.Int32
	max atomic.Int32
}

func (f *fakeOp) Enumerate(_ context.Context, _ *Definition, cursor string, max int, _ time.Time) ([]Item, string, error) {
	start := 0
	if cursor != "" {
		fmt.Sscanf(cursor, "%d", &start)
	}
	var items []Item
	for i := start; i < f.n && len(items) < max; i++ {
		items = append(items, Item{Bucket: "b", Key: fmt.Sprintf("k%05d", i), Size: 10})
	}
	next := start + len(items)
	if next >= f.n {
		return items, "", nil
	}
	return items, fmt.Sprint(next), nil
}

func (f *fakeOp) Do(_ context.Context, _ *Definition, it Item) (ItemResult, error) {
	c := f.cur.Add(1)
	for {
		m := f.max.Load()
		if c <= m || f.max.CompareAndSwap(m, c) {
			break
		}
	}
	defer f.cur.Add(-1)
	time.Sleep(time.Millisecond)
	if f.do != nil {
		return f.do(it)
	}
	return ItemResult{Bytes: it.Size}, nil
}

func mgr(t *testing.T, st Store, lk Locker, node string, op Operation, mut ...func(*Options)) *Manager {
	t.Helper()
	o := Options{Store: st, Locker: lk, Ops: map[string]Operation{TypeExpire: op}, Node: node,
		Workers: 3, TaskItems: 20, Tick: 10 * time.Millisecond, Log: quiet}
	for _, m := range mut {
		m(&o)
	}
	m, err := NewManager(o)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func start(t *testing.T, m *Manager) context.CancelFunc {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return cancel
}

func expireDef(t *testing.T, extra string) *Definition {
	t.Helper()
	d, err := Parse([]byte("expire: {bucket: b, prefix: p/" + extra + "}"))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func waitState(t *testing.T, m *Manager, id string, states ...string) *Status {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		st, err := m.Describe(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range states {
			if st.State == s {
				return st
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	st, _ := m.Describe(context.Background(), id)
	t.Fatalf("job never reached %v: %+v", states, st)
	return nil
}

func TestJobRunsAcrossNodesWithinTheConcurrencyLimit(t *testing.T) {
	st, lk := newMemStore(), &memLocker{}
	op := &fakeOp{n: 500}
	var seen sync.Map
	op.do = func(it Item) (ItemResult, error) {
		if _, dup := seen.LoadOrStore(it.Key, true); dup {
			return ItemResult{}, errors.New("an object was processed twice")
		}
		return ItemResult{Bytes: it.Size}, nil
	}
	m1, m2 := mgr(t, st, lk, "n1", op), mgr(t, st, lk, "n2", op)
	start(t, m1)
	start(t, m2)
	id, err := m1.Start(context.Background(), expireDef(t, ", concurrency: 2"), "root")
	if err != nil {
		t.Fatal(err)
	}
	fin := waitState(t, m2, id, StateCompleted, StateFailed)
	if fin.State != StateCompleted {
		t.Fatalf("job = %+v", fin)
	}
	p := fin.Progress
	if p.Succeeded != 500 || p.Failed != 0 || p.Bytes != 5000 || p.Tasks != 25 || p.TasksDone != 25 || !p.Enumerated {
		t.Errorf("progress = %+v", p)
	}
	// Concurrency 2 tasks cluster-wide, each task sequential: at most two
	// objects in flight even though 2 nodes x 3 workers were available.
	if m := op.max.Load(); m > 2 || m < 1 {
		t.Errorf("max concurrent objects = %d, want 1..2", m)
	}
	// Bookkeeping is cleaned up; the record keeps the totals.
	st.mu.Lock()
	defer st.mu.Unlock()
	for n := range st.objs {
		if strings.Contains(n, "/tasks/") || strings.Contains(n, "/done/") {
			t.Errorf("leftover %s", n)
		}
	}
}

func TestRetriesAndFailureReporting(t *testing.T) {
	st, lk := newMemStore(), &memLocker{}
	var attempts sync.Map
	op := &fakeOp{n: 30}
	op.do = func(it Item) (ItemResult, error) {
		switch it.Key {
		case "k00003": // transient: fails twice, then works
			n, _ := attempts.LoadOrStore(it.Key, new(atomic.Int32))
			if n.(*atomic.Int32).Add(1) <= 2 {
				return ItemResult{}, errors.New("temporary glitch")
			}
		case "k00007":
			return ItemResult{}, errors.New("permanent failure")
		case "k00009":
			return ItemResult{Skipped: true}, nil
		}
		return ItemResult{Bytes: 1}, nil
	}
	m := mgr(t, st, lk, "n1", op)
	start(t, m)
	id, _ := m.Start(context.Background(), expireDef(t, ", retry: {attempts: 3, delay: 1ms}"), "root")
	fin := waitState(t, m, id, StateCompleted, StateFailed)
	p := fin.Progress
	if p.Succeeded != 28 || p.Failed != 1 || p.Skipped != 1 {
		t.Errorf("progress = %+v", p)
	}
	if len(p.Failures) != 1 || p.Failures[0].Key != "k00007" || !strings.Contains(p.Failures[0].Error, "permanent") {
		t.Errorf("failures = %+v", p.Failures)
	}
	if n, _ := attempts.Load("k00003"); n.(*atomic.Int32).Load() != 3 {
		t.Errorf("the transient failure was attempted %d times", n.(*atomic.Int32).Load())
	}
}

func TestCancel(t *testing.T) {
	st, lk := newMemStore(), &memLocker{}
	op := &fakeOp{n: 100000}
	m := mgr(t, st, lk, "n1", op)
	start(t, m)
	id, _ := m.Start(context.Background(), expireDef(t, ""), "root")
	deadline := time.Now().Add(10 * time.Second)
	for {
		s, _ := m.Describe(context.Background(), id)
		if s.Progress.TasksDone > 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("job made no progress")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := m.Cancel(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	fin := waitState(t, m, id, StateCanceled)
	if fin.Progress.Succeeded == 0 || fin.Progress.Succeeded >= 100000 {
		t.Errorf("progress after cancel = %+v", fin.Progress)
	}
	if err := m.Cancel(context.Background(), id); err == nil {
		t.Error("cancelling a finished job must fail")
	}
	before := op.cur.Load()
	time.Sleep(100 * time.Millisecond)
	if op.cur.Load() != 0 && before != 0 {
		t.Error("work continued after cancel")
	}
}

func TestCoordinatorFailover(t *testing.T) {
	st, lk := newMemStore(), &memLocker{}
	var processed sync.Map
	op := &fakeOp{n: 400}
	op.do = func(it Item) (ItemResult, error) {
		processed.Store(it.Key, true)
		return ItemResult{Bytes: 1}, nil
	}
	m1 := mgr(t, st, lk, "n1", op)
	stop1 := start(t, m1)
	id, _ := m1.Start(context.Background(), expireDef(t, ""), "root")
	deadline := time.Now().Add(10 * time.Second)
	for {
		s, _ := m1.Describe(context.Background(), id)
		if s.Progress.TasksDone >= 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	stop1() // the node that coordinates goes away
	time.Sleep(50 * time.Millisecond)
	m2 := mgr(t, st, lk, "n2", op)
	start(t, m2)
	fin := waitState(t, m2, id, StateCompleted, StateFailed)
	if fin.State != StateCompleted {
		t.Fatalf("job = %+v", fin)
	}
	count := 0
	processed.Range(func(_, _ any) bool { count++; return true })
	if count != 400 {
		t.Errorf("%d distinct objects processed, want 400", count)
	}
	if fin.Progress.Succeeded < 400 {
		t.Errorf("succeeded = %d", fin.Progress.Succeeded)
	}
}

func TestListAndDescribeUnknown(t *testing.T) {
	st, lk := newMemStore(), &memLocker{}
	m := mgr(t, st, lk, "n1", &fakeOp{n: 1})
	if _, err := m.Describe(context.Background(), "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Describe(unknown) = %v", err)
	}
	if err := m.Cancel(context.Background(), "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Cancel(unknown) = %v", err)
	}
	a, _ := m.Start(context.Background(), expireDef(t, ""), "u")
	time.Sleep(2 * time.Millisecond)
	b, _ := m.Start(context.Background(), expireDef(t, ""), "u")
	list, err := m.List(context.Background())
	if err != nil || len(list) != 2 || list[0].ID != b || list[1].ID != a {
		t.Errorf("list = %+v, %v", list, err)
	}
}
