package event

import (
	"sync"
	"sync/atomic"
	"time"
)

// DefaultSubscriberBuffer is the per-subscriber queue length when none is
// given.
const DefaultSubscriberBuffer = 4096

// Bus is an in-process publish/subscribe hub.
//
// Backpressure policy: DROP, never block. Publish performs a non-blocking
// send to every matching subscriber and, when a subscriber's buffer is
// full, discards the new event for that subscriber and counts it
// (Subscription.Dropped). Rationale: events are a side effect of S3
// requests, which must never wait on a notification consumer; and a
// slow subscriber must not starve the others. The events that matter for
// durability are not at the mercy of this buffer for long: the Manager's
// subscriber drains it straight onto the on-disk queues. Drop-newest keeps
// every subscriber's stream a gap-after-a-prefix of the true order, so a
// consumer that sees Dropped() > 0 knows exactly that events after its
// last received sequence number were skipped and can resume from the
// replay log.
//
// Ordering: Publish assigns the sequence number and fans out under one
// lock, so every subscriber observes events in sequence order.
type Bus struct {
	mu     sync.Mutex
	seq    uint64
	subs   map[*Subscription]struct{}
	closed bool

	published atomic.Uint64
}

// NewBus returns a bus whose sequence numbers start above start (use the
// last sequence number of a previous run, or zero).
func NewBus(start uint64) *Bus {
	if now := uint64(time.Now().UnixNano()); start < now {
		// Time-based floor: sequence numbers keep rising across restarts
		// even if the replay log was lost, and are unlikely to collide
		// between nodes.
		start = now
	}
	return &Bus{seq: start, subs: map[*Subscription]struct{}{}}
}

// Publish stamps e with the next sequence number and offers it to every
// matching subscriber. It never blocks and never fails; after Close it is a
// no-op. e must not be modified afterwards.
func (b *Bus) Publish(e *Event) {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.seq++
	e.Seq = b.seq
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	if e.Sequencer == "" {
		e.Sequencer = Sequencer(e.Time, e.Seq)
	}
	for s := range b.subs {
		if s.filter != nil && !s.filter(e) {
			continue
		}
		select {
		case s.c <- e:
		default:
			s.dropped.Add(1)
		}
	}
	b.mu.Unlock()
	b.published.Add(1)
}

// Seq is the sequence number of the most recently published event.
func (b *Bus) Seq() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.seq
}

// Published counts events published since start.
func (b *Bus) Published() uint64 { return b.published.Load() }

// Subscription is one consumer's view of the bus.
type Subscription struct {
	b       *Bus
	c       chan *Event
	filter  func(*Event) bool
	dropped atomic.Uint64
	once    sync.Once
}

// Subscribe registers a consumer. filter, if non-nil, runs inside Publish
// and must be fast and non-blocking. buffer <= 0 means
// DefaultSubscriberBuffer. Subscribing to a closed bus yields a closed
// channel.
func (b *Bus) Subscribe(buffer int, filter func(*Event) bool) *Subscription {
	if buffer <= 0 {
		buffer = DefaultSubscriberBuffer
	}
	s := &Subscription{b: b, c: make(chan *Event, buffer), filter: filter}
	b.mu.Lock()
	if b.closed {
		close(s.c)
		s.once.Do(func() {})
	} else {
		b.subs[s] = struct{}{}
	}
	b.mu.Unlock()
	return s
}

// C is the event stream. It is closed by Close of the subscription or of
// the bus, after which buffered events can still be read.
func (s *Subscription) C() <-chan *Event { return s.c }

// Dropped is the number of events discarded because the buffer was full.
func (s *Subscription) Dropped() uint64 { return s.dropped.Load() }

// Pending is the number of buffered, unread events.
func (s *Subscription) Pending() int { return len(s.c) }

// Close unsubscribes. It is safe to call more than once.
func (s *Subscription) Close() {
	s.once.Do(func() {
		s.b.mu.Lock()
		delete(s.b.subs, s)
		close(s.c)
		s.b.mu.Unlock()
	})
}

// Close stops the bus: later Publish calls are ignored and every
// subscription's channel is closed once drained.
func (b *Bus) Close() {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.closed = true
	subs := make([]*Subscription, 0, len(b.subs))
	for s := range b.subs {
		subs = append(subs, s)
	}
	b.subs = map[*Subscription]struct{}{}
	for _, s := range subs {
		s.once.Do(func() { close(s.c) })
	}
	b.mu.Unlock()
}
