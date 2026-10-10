package nslock

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"nanoio/internal/storage"
)

func TestCompatibility(t *testing.T) {
	// first op, then second op on the same (or different) key, while the
	// first is held: does the second get the lock immediately?
	tests := []struct {
		name        string
		first       string // "R" or "W"
		second      string
		sameKey     bool
		wantAcquire bool
	}{
		{"read+read", "R", "R", true, true},
		{"read+write", "R", "W", true, false},
		{"write+read", "W", "R", true, false},
		{"write+write", "W", "W", true, false},
		{"write+write other key", "W", "W", false, true},
		{"write bucket, read key", "W", "R", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := New(time.Minute)
			take := func(kind, obj string, ctx context.Context) (func(), error) {
				if kind == "W" {
					return m.Lock(ctx, "b", obj)
				}
				return m.RLock(ctx, "b", obj)
			}
			u1, err := take(tt.first, "k", context.Background())
			if err != nil {
				t.Fatal(err)
			}
			obj := "k"
			if !tt.sameKey {
				obj = "other"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			u2, err := take(tt.second, obj, ctx)
			if tt.wantAcquire {
				if err != nil {
					t.Fatalf("second lock failed: %v", err)
				}
				u2()
			} else if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("second lock error = %v, want deadline exceeded", err)
			}
			u1()
			if h := m.Held(); h != 0 {
				t.Errorf("%d entries left after release", h)
			}
		})
	}
}

func TestTimeoutReturnsErrLockTimeout(t *testing.T) {
	m := New(30 * time.Millisecond)
	u, err := m.Lock(context.Background(), "b", "k")
	if err != nil {
		t.Fatal(err)
	}
	defer u()
	_, err = m.RLock(context.Background(), "b", "k")
	if !errors.Is(err, storage.ErrLockTimeout) {
		t.Errorf("error = %v, want ErrLockTimeout", err)
	}
}

func TestCancelledContext(t *testing.T) {
	m := New(time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.Lock(ctx, "b", "k"); !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want Canceled", err)
	}
	if m.Held() != 0 {
		t.Error("cancelled acquire left an entry")
	}
}

func TestUnlockIdempotent(t *testing.T) {
	m := New(time.Minute)
	r1, _ := m.RLock(context.Background(), "b", "k")
	r2, _ := m.RLock(context.Background(), "b", "k")
	r1()
	r1() // must not release r2's hold
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := m.Lock(ctx, "b", "k"); err == nil {
		t.Fatal("exclusive lock granted while a reader remains")
	}
	r2()
	u, err := m.Lock(context.Background(), "b", "k")
	if err != nil {
		t.Fatal(err)
	}
	u()
}

func TestWaiterWakesOnRelease(t *testing.T) {
	m := New(time.Minute)
	u, _ := m.Lock(context.Background(), "b", "k")
	got := make(chan error, 1)
	go func() {
		u2, err := m.Lock(context.Background(), "b", "k")
		if err == nil {
			u2()
		}
		got <- err
	}()
	time.Sleep(20 * time.Millisecond)
	u()
	select {
	case err := <-got:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waiter never woke")
	}
}

func TestMutualExclusionUnderContention(t *testing.T) {
	m := New(time.Minute)
	var inside, maxInside, counter int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				u, err := m.Lock(context.Background(), "b", "k")
				if err != nil {
					t.Error(err)
					return
				}
				n := atomic.AddInt32(&inside, 1)
				if n > atomic.LoadInt32(&maxInside) {
					atomic.StoreInt32(&maxInside, n)
				}
				counter++ // data race unless the lock really excludes
				atomic.AddInt32(&inside, -1)
				u()
			}
		}()
	}
	wg.Wait()
	if maxInside != 1 {
		t.Errorf("max concurrent holders = %d, want 1", maxInside)
	}
	if counter != 32*50 {
		t.Errorf("counter = %d", counter)
	}
	if m.Held() != 0 {
		t.Error("entries leaked")
	}
}
