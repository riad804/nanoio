package event

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"nanoio/internal/config"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// fakeTarget records what it is sent; fail decides, per call, whether to
// refuse.
type fakeTarget struct {
	mu      sync.Mutex
	got     []*Event
	batches [][]string
	fail    func(events []*Event) error
	calls   atomic.Int64
	block   chan struct{} // when non-nil, Send waits on it (or ctx)
}

func (f *fakeTarget) Send(ctx context.Context, events []*Event) error {
	f.calls.Add(1)
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if f.fail != nil {
		if err := f.fail(events); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var keys []string
	for _, e := range events {
		f.got = append(f.got, e)
		keys = append(keys, e.Key)
	}
	f.batches = append(f.batches, keys)
	return nil
}

func (f *fakeTarget) Close() error { return nil }

func (f *fakeTarget) delivered() []*Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*Event(nil), f.got...)
}

func fastDelivery() Delivery {
	return Delivery{
		BatchSize: 1, MaxAttempts: 3,
		RetryBase: config.Duration(time.Millisecond), RetryMax: config.Duration(5 * time.Millisecond),
		Timeout: config.Duration(2 * time.Second),
	}
}

// allEvents routes every event of every bucket to the target's ARN.
func allEvents(t *testing.T, m *Manager, arn string) ConfigSource {
	t.Helper()
	cfg, err := ParseConfig([]byte(`<NotificationConfiguration><QueueConfiguration><Queue>`+arn+
		`</Queue><Event>s3:ObjectCreated:*</Event><Event>s3:ObjectRemoved:*</Event><Event>s3:ObjectAccessed:*</Event></QueueConfiguration></NotificationConfiguration>`), m.Resolve)
	if err != nil {
		t.Fatal(err)
	}
	return func(context.Context, string) (*Config, error) { return cfg, nil }
}

func newManager(t *testing.T, dir string, tgt Target, d Delivery) (*Manager, ConfigSource) {
	t.Helper()
	m, err := NewManager(Options{Dir: dir, Region: "us-east-1", Logger: quiet, SegmentBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	arn, err := m.AddTarget("webhook", "t", Spec{Target: tgt, Delivery: d})
	if err != nil {
		t.Fatal(err)
	}
	return m, allEvents(t, m, arn)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func put(bucket, key string, n int) *Event {
	return &Event{Name: ObjectCreatedPut, Bucket: bucket, Key: key, ETag: fmt.Sprint(n)}
}

// Events for one object reach a target in the order they were published,
// whatever the batching and however keys interleave.
func TestDeliveryOrderPerObject(t *testing.T) {
	for _, batch := range []int{1, 7} {
		t.Run(fmt.Sprintf("batch=%d", batch), func(t *testing.T) {
			tgt := &fakeTarget{}
			d := fastDelivery()
			d.BatchSize = batch
			m, src := newManager(t, t.TempDir(), tgt, d)
			m.Start(src)
			const keys, perKey = 8, 60
			var wg sync.WaitGroup
			for k := 0; k < keys; k++ {
				wg.Add(1)
				go func(k int) { // one writer per key, as one client's sequential requests
					defer wg.Done()
					for i := 0; i < perKey; i++ {
						m.Publish(put("b", fmt.Sprintf("key-%d", k), i))
					}
				}(k)
			}
			wg.Wait()
			waitFor(t, "delivery", func() bool { return len(tgt.delivered()) == keys*perKey })
			next := map[string]int{}
			for _, e := range tgt.delivered() {
				want := next[e.Key]
				if e.ETag != fmt.Sprint(want) {
					t.Fatalf("%s: got version %s, want %d (reordered)", e.Key, e.ETag, want)
				}
				next[e.Key]++
			}
			if err := m.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Events that a down target could not take are still on disk after a
// restart and are delivered, once, in order, when the target is back.
func TestNoEventLossAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	down := &fakeTarget{fail: func([]*Event) error { return errors.New("connection refused") }}
	d := fastDelivery()
	d.MaxAttempts = -1 // never dead-letter: this test is about the queue
	m, src := newManager(t, dir, down, d)
	m.Start(src)
	const n = 300
	for i := 0; i < n; i++ {
		m.Publish(put("b", "obj", i))
	}
	waitFor(t, "failed attempts", func() bool { return down.calls.Load() >= 3 })
	if err := m.Close(); err != nil { // graceful stop with the queue full
		t.Fatal(err)
	}

	up := &fakeTarget{}
	m2, src2 := newManager(t, dir, up, fastDelivery())
	if st := m2.Status(context.Background(), false); st[0].QueueLength != n {
		t.Fatalf("queue holds %d events after restart, want %d", st[0].QueueLength, n)
	}
	m2.Start(src2)
	waitFor(t, "redelivery", func() bool { return len(up.delivered()) >= n })
	got := up.delivered()
	if len(got) != n {
		t.Fatalf("delivered %d events, want exactly %d", len(got), n)
	}
	for i, e := range got {
		if e.ETag != fmt.Sprint(i) {
			t.Fatalf("event %d is version %s (lost or reordered)", i, e.ETag)
		}
	}
	m2.Close()
}

// A restart in the middle of delivery redelivers at most the batch that was
// in flight; nothing queued is lost.
func TestRestartMidDeliveryLosesNothing(t *testing.T) {
	dir := t.TempDir()
	slow := &fakeTarget{block: make(chan struct{})}
	m, src := newManager(t, dir, slow, fastDelivery())
	m.Start(src)
	for i := 0; i < 20; i++ {
		m.Publish(put("b", "k", i))
	}
	waitFor(t, "first send", func() bool { return slow.calls.Load() >= 1 })
	m.Close() // cancels the in-flight send

	up := &fakeTarget{}
	m2, src2 := newManager(t, dir, up, fastDelivery())
	m2.Start(src2)
	waitFor(t, "all delivered", func() bool { return len(up.delivered()) >= 20 })
	m2.Close()
	for i, e := range up.delivered()[:20] {
		if e.ETag != fmt.Sprint(i) {
			t.Fatalf("event %d is version %s", i, e.ETag)
		}
	}
}

// With every target hung, Publish costs microseconds and the S3 path never
// waits on delivery, on the queue, or on the configuration source.
func TestPublishLatencyUnaffectedByDownTarget(t *testing.T) {
	hung := &fakeTarget{block: make(chan struct{})}
	d := fastDelivery()
	d.Timeout = config.Duration(30 * time.Second)
	m, _ := newManager(t, t.TempDir(), hung, d)
	m.opts.DrainTimeout = 100 * time.Millisecond
	slowSrc := func(ctx context.Context, bucket string) (*Config, error) {
		select { // a configuration read that takes a long time
		case <-time.After(time.Hour):
		case <-ctx.Done():
		}
		return nil, ctx.Err()
	}
	m.Start(slowSrc)
	start := time.Now()
	for i := 0; i < 20000; i++ {
		m.Publish(put("b", "k", i))
	}
	elapsed := time.Since(start)
	if per := elapsed / 20000; per > 200*time.Microsecond {
		t.Fatalf("Publish takes %v per event with a hung pipeline", per)
	}
	close(hung.block)
	m.Close()
}

func TestDeadLetterIsolatesPoisonAndRequeues(t *testing.T) {
	var poisoned atomic.Bool
	poisoned.Store(true)
	tgt := &fakeTarget{fail: func(events []*Event) error {
		for _, e := range events {
			if e.Key == "poison" && poisoned.Load() {
				return errors.New("400 bad event")
			}
		}
		return nil
	}}
	d := fastDelivery()
	d.BatchSize = 5
	m, src := newManager(t, t.TempDir(), tgt, d)
	for _, k := range []string{"a", "b", "poison", "c", "d"} {
		m.Publish(put("b", k, 0))
	}
	m.Start(src)
	waitFor(t, "dead letter", func() bool { return m.Status(context.Background(), false)[0].DeadLettered == 1 })
	waitFor(t, "good events", func() bool { return len(tgt.delivered()) == 4 })
	var keys []string
	for _, e := range tgt.delivered() {
		keys = append(keys, e.Key)
	}
	if strings.Join(keys, ",") != "a,b,c,d" {
		t.Fatalf("delivered %v, want the four good events in order", keys)
	}
	arn := m.Status(context.Background(), false)[0].ARN
	dl, err := m.DeadLetters(arn, 10)
	if err != nil || len(dl) != 1 || !strings.Contains(dl[0].Error, "bad event") || dl[0].Attempts != 3 {
		t.Fatalf("dead letters = %+v, %v", dl, err)
	}

	poisoned.Store(false) // the destination was fixed
	moved, err := m.Requeue(arn)
	if err != nil || moved != 1 {
		t.Fatalf("Requeue = %d, %v", moved, err)
	}
	waitFor(t, "redelivery of the dead letter", func() bool { return len(tgt.delivered()) == 5 })
	if st := m.Status(context.Background(), false)[0]; st.DeadLetterLength != 0 || st.QueueLength != 0 {
		t.Errorf("status after requeue = %+v", st)
	}
	m.Close()
}

func TestQueueFullDropsAndCounts(t *testing.T) {
	hung := &fakeTarget{block: make(chan struct{})}
	d := fastDelivery()
	d.QueueLimit = 10
	d.Timeout = config.Duration(30 * time.Second)
	m, src := newManager(t, t.TempDir(), hung, d)
	m.Start(src)
	for i := 0; i < 50; i++ {
		m.Publish(put("b", "k", i))
	}
	waitFor(t, "drops", func() bool { return m.Status(context.Background(), false)[0].Dropped == 40 })
	close(hung.block)
	m.Close()
}

func TestStatusReflectsFailures(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	tgt := &fakeTarget{fail: func([]*Event) error {
		if fail.Load() {
			return errors.New("503 unavailable")
		}
		return nil
	}}
	d := fastDelivery()
	d.MaxAttempts = -1
	m, src := newManager(t, t.TempDir(), tgt, d)
	m.Start(src)
	m.Publish(put("b", "k", 0))
	waitFor(t, "failures", func() bool {
		st := m.Status(context.Background(), false)[0]
		return !st.Online && st.ConsecutiveFailures >= 2 && strings.Contains(st.LastError, "503")
	})
	fail.Store(false)
	waitFor(t, "recovery", func() bool {
		st := m.Status(context.Background(), false)[0]
		return st.Online && st.Delivered == 1 && st.QueueLength == 0 && st.LastSuccess != nil
	})
	m.Close()
}

func TestStreamReplaysThenGoesLiveWithoutGaps(t *testing.T) {
	m, err := NewManager(Options{Dir: t.TempDir(), Region: "r", Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	m.Start(func(context.Context, string) (*Config, error) { return nil, nil })
	for i := 0; i < 100; i++ {
		m.Publish(put("b", "old", i))
	}
	ctx, cancel := context.WithCancel(context.Background())
	var mu sync.Mutex
	var seen []uint64
	done := make(chan error, 1)
	go func() {
		done <- m.Stream(ctx, StreamOptions{Replay: true, Since: 0}, func(it StreamItem) error {
			if it.Event != nil {
				mu.Lock()
				seen = append(seen, it.Event.Seq)
				mu.Unlock()
			}
			return nil
		})
	}()
	for i := 0; i < 100; i++ {
		m.Publish(put("b", "new", i))
	}
	waitFor(t, "stream to see 200 events", func() bool { mu.Lock(); defer mu.Unlock(); return len(seen) == 200 })
	cancel()
	<-done
	for i := 1; i < len(seen); i++ {
		if seen[i] <= seen[i-1] {
			t.Fatalf("stream repeated or reordered at %d: %d after %d", i, seen[i], seen[i-1])
		}
	}
	// Resuming from the last seen sequence yields only newer events.
	last := seen[len(seen)-1]
	m.Publish(put("b", "after", 0))
	waitFor(t, "replay of the new event", func() bool { return m.replayed.Load() > last })
	ctx2, cancel2 := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel2()
	var after []uint64
	m.Stream(ctx2, StreamOptions{Replay: true, Since: last}, func(it StreamItem) error {
		if it.Event != nil {
			after = append(after, it.Event.Seq)
		}
		return nil
	})
	if len(after) != 1 || after[0] <= last {
		t.Fatalf("resume from %d returned %v", last, after)
	}
	m.Close()
}

func TestSequenceContinuesAfterRestart(t *testing.T) {
	dir := t.TempDir()
	m, _ := NewManager(Options{Dir: dir, Region: "r", Logger: quiet})
	m.Start(func(context.Context, string) (*Config, error) { return nil, nil })
	e := put("b", "k", 0)
	m.Publish(e)
	first := e.Seq
	m.Close()
	m2, _ := NewManager(Options{Dir: dir, Region: "r", Logger: quiet})
	e2 := put("b", "k", 1)
	m2.Publish(e2)
	if e2.Seq <= first {
		t.Fatalf("sequence went backwards across restart: %d then %d", first, e2.Seq)
	}
	m2.Close()
}

func TestResolveAndDuplicateTargets(t *testing.T) {
	m, _ := NewManager(Options{Dir: t.TempDir(), Region: "eu-1", Logger: quiet})
	defer m.Close()
	if _, err := m.AddTarget("webhook", "a", Spec{Target: &fakeTarget{}, Delivery: fastDelivery()}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AddTarget("webhook", "a", Spec{Target: &fakeTarget{}, Delivery: fastDelivery()}); err == nil {
		t.Error("a duplicate target must be refused")
	}
	if _, err := m.AddTarget("webhook", "../x", Spec{Target: &fakeTarget{}, Delivery: fastDelivery()}); err == nil {
		t.Error("a target id that is not a plain name must be refused")
	}
	for arn, want := range map[string]bool{
		"arn:minio:sqs::a:webhook":        true,
		"arn:minio:sqs:eu-1:a:webhook":    true,
		"arn:minio:sqs:us-west:a:webhook": false,
		"arn:minio:sqs::a:kafka":          false,
	} {
		if _, ok := m.Resolve(arn); ok != want {
			t.Errorf("Resolve(%s) = %v, want %v", arn, ok, want)
		}
	}
}
