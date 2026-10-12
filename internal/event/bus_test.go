package event

import (
	"sync"
	"testing"
	"time"
)

func TestPublishNeverBlocksOnAFullSubscriber(t *testing.T) {
	b := NewBus(0)
	slow := b.Subscribe(2, nil) // never read
	fast := b.Subscribe(1000, nil)
	done := make(chan struct{})
	go func() {
		for i := 0; i < 500; i++ {
			b.Publish(&Event{Name: ObjectCreatedPut, Bucket: "b", Key: "k"})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Publish blocked on a subscriber whose buffer is full")
	}
	if got := slow.Dropped(); got != 498 {
		t.Errorf("slow subscriber dropped %d events, want 498", got)
	}
	if got := fast.Dropped(); got != 0 {
		t.Errorf("fast subscriber dropped %d events, want 0", got)
	}
	if fast.Pending() != 500 {
		t.Errorf("fast subscriber holds %d events, want 500", fast.Pending())
	}
}

func TestSubscribersSeeSequenceOrder(t *testing.T) {
	b := NewBus(0)
	subs := []*Subscription{b.Subscribe(10000, nil), b.Subscribe(10000, nil)}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				b.Publish(&Event{Name: ObjectCreatedPut})
			}
		}()
	}
	wg.Wait()
	for si, s := range subs {
		var last uint64
		for i := 0; i < 4000; i++ {
			e := <-s.C()
			if e.Seq <= last {
				t.Fatalf("subscriber %d: seq %d after %d", si, e.Seq, last)
			}
			last = e.Seq
		}
	}
}

func TestSubscribeFilterAndClose(t *testing.T) {
	b := NewBus(0)
	s := b.Subscribe(10, func(e *Event) bool { return e.Bucket == "want" })
	b.Publish(&Event{Bucket: "skip"})
	b.Publish(&Event{Bucket: "want"})
	if s.Pending() != 1 {
		t.Fatalf("filter let %d events through, want 1", s.Pending())
	}
	s.Close()
	s.Close() // idempotent
	b.Publish(&Event{Bucket: "want"})
	b.Close()
	b.Publish(&Event{Bucket: "want"}) // no-op, no panic
	if late := b.Subscribe(1, nil); func() bool { _, ok := <-late.C(); return ok }() {
		t.Error("a subscription to a closed bus must yield a closed channel")
	}
}

func TestSequenceNumbersContinueAfterStart(t *testing.T) {
	b := NewBus(uint64(time.Now().UnixNano()) + 1_000_000)
	e := &Event{}
	b.Publish(e)
	if e.Seq <= uint64(time.Now().UnixNano()) {
		t.Errorf("seq %d does not continue above the supplied start", e.Seq)
	}
}
