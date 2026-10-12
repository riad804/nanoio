package event

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

// SharedStore is the cluster-wide, quorum-backed place replicated queues
// live. The server implements it over the erasure-coded system bucket and
// the distributed lock; this package only needs these five operations.
// Names sort lexically in delivery order.
type SharedStore interface {
	// Put stores (or replaces) a small blob durably across the cluster.
	Put(ctx context.Context, name string, data []byte) error
	// Get returns a blob, or ErrSharedNotFound.
	Get(ctx context.Context, name string) ([]byte, error)
	// Delete removes a blob; deleting a missing one is not an error.
	Delete(ctx context.Context, name string) error
	// List returns up to max names with the prefix, in ascending order.
	List(ctx context.Context, prefix string, max int) ([]string, error)
	// Lead blocks until this node holds the exclusive lease named key, and
	// returns the function that gives it up. A lease held by a node that
	// dies is released by the lock manager's TTL.
	Lead(ctx context.Context, key string) (release func(), err error)
}

// ErrSharedNotFound is returned by SharedStore.Get for a missing blob.
var ErrSharedNotFound = errors.New("event: shared object not found")

// feed is what a delivery worker reads: the local Queue, or the shared
// queue of a replicated target.
type feed interface {
	Peek(n int) ([]Item, error)
	Ack(items []Item) error
}

// deadStore is a target's dead-letter store: local Queue or shared.
type deadStore interface {
	AppendEvicting(data []byte) (bool, error)
	Sync() error
	Peek(n int) ([]Item, error)
	Ack(items []Item) error
	Len() int
}

const (
	sharedPrefix = "_events/" // cannot collide with a bucket name
	shipBatch    = 256
	listCap      = 1000
)

func (r *runner) qPrefix() string    { return sharedPrefix + r.key + "/q/" }
func (r *runner) deadPrefix() string { return sharedPrefix + r.key + "/dead/" }

// objectName builds a name that sorts by time, then node, then a per-node
// counter, so each node's batches stay in order and nodes interleave by
// publish time.
func objectName(prefix string, t int64, node string, n uint64) string {
	return fmt.Sprintf("%s%020d-%s-%08d", prefix, t, node, n)
}

// enableShared switches the runner to replicated mode.
func (r *runner) enableShared(ctx context.Context, s SharedStore, node string) {
	r.shared = s
	r.node = node
	r.src = &sharedFeed{ctx: r.m.ctx, s: s, prefix: r.qPrefix(), log: r.log, corrupt: &r.corrupt}
	sd := &sharedDead{ctx: r.m.ctx, s: s, prefix: r.deadPrefix(), node: node, limit: r.d.DeadLetterLimit}
	// Dead letters recorded before replication was switched on move over.
	for {
		items, err := r.localDead.Peek(64)
		if err != nil || len(items) == 0 {
			break
		}
		failed := false
		for _, it := range items {
			if _, err := sd.AppendEvicting(it.Data); err != nil {
				failed = true
				break
			}
		}
		if failed {
			break
		}
		r.localDead.Ack(items)
	}
	r.dead = sd
}

func (r *runner) sharedPending() int {
	ctx, cancel := context.WithTimeout(r.m.ctx, 3*time.Second)
	defer cancel()
	names, err := r.shared.List(ctx, r.qPrefix(), listCap)
	if err != nil {
		return -1
	}
	return len(names)
}

// ship moves the local queue's entries into the shared store, in order, in
// batches. Until a batch is written (the cluster may be below quorum) it
// simply stays in the local queue: that is the fallback, nothing is dropped
// and delivery from the shared queue is what waits.
func (r *runner) ship(ctx context.Context, stop <-chan struct{}) {
	var seq uint64
	var last int64
	failures := 0
	for {
		items, err := r.q.Peek(shipBatch)
		if err == nil && len(items) == 0 {
			t := time.NewTimer(time.Second)
			select {
			case <-r.shipKick:
			case <-t.C:
			case <-stop:
				t.Stop()
				return
			}
			t.Stop()
			continue
		}
		if err == nil {
			raws := make([]json.RawMessage, len(items))
			for i, it := range items {
				raws[i] = it.Data
			}
			var blob []byte
			if blob, err = json.Marshal(raws); err == nil {
				ts := firstTime(items[0].Data)
				if ts <= last {
					ts = last + 1
				}
				last = ts
				seq++
				pctx, cancel := context.WithTimeout(ctx, 30*time.Second)
				err = r.shared.Put(pctx, objectName(r.qPrefix(), ts, r.node, seq), blob)
				cancel()
				if err == nil {
					if err = r.q.Ack(items); err == nil {
						r.shipped.Add(uint64(len(items)))
						failures = 0
						continue
					}
				}
			}
		}
		// Shared store unavailable (or local I/O failed): keep the events
		// local and try again with backoff.
		failures++
		r.shipFailures.Add(1)
		r.lastShipErr.Store(err.Error())
		if failures == 1 || failures%10 == 0 {
			r.log.Warn("cannot replicate the notification queue; events stay in the local queue", "failures", failures, "err", err)
		}
		if !r.sleep(stop, r.backoff(failures)) {
			return
		}
	}
}

// firstTime is the publish time (unix nanos) of a queued event, or now.
func firstTime(data []byte) int64 {
	var e struct {
		Time time.Time `json:"time"`
	}
	if json.Unmarshal(data, &e) == nil && !e.Time.IsZero() {
		return e.Time.UnixNano()
	}
	return time.Now().UnixNano()
}

// sharedFeed reads the shared queue one object (batch) at a time, in name
// order. Only the lease holder uses it. An object is deleted once all its
// events are acknowledged; a crash in between redelivers that object's
// events (at-least-once).
type sharedFeed struct {
	ctx     context.Context
	s       SharedStore
	prefix  string
	log     interface{ Warn(string, ...any) }
	corrupt interface{ Add(uint64) uint64 }

	cur string
	buf []json.RawMessage
	off int
}

func (f *sharedFeed) Peek(n int) ([]Item, error) {
	for f.off >= len(f.buf) {
		if f.cur != "" {
			if err := f.s.Delete(f.ctx, f.cur); err != nil {
				return nil, err
			}
			f.cur, f.buf, f.off = "", nil, 0
		}
		names, err := f.s.List(f.ctx, f.prefix, 1)
		if err != nil || len(names) == 0 {
			return nil, err
		}
		data, err := f.s.Get(f.ctx, names[0])
		switch {
		case errors.Is(err, ErrSharedNotFound):
			continue // taken by a previous leader between list and get
		case err != nil:
			return nil, err
		}
		var raws []json.RawMessage
		if err := json.Unmarshal(data, &raws); err != nil {
			f.log.Warn("discarding an unreadable replicated queue object", "name", names[0], "err", err)
			f.corrupt.Add(1)
			raws = nil
		}
		f.cur, f.buf, f.off = names[0], raws, 0
	}
	end := f.off + n
	if end > len(f.buf) {
		end = len(f.buf)
	}
	items := make([]Item, 0, end-f.off)
	for _, raw := range f.buf[f.off:end] {
		items = append(items, Item{Data: raw, name: f.cur})
	}
	return items, nil
}

func (f *sharedFeed) Ack(items []Item) error {
	f.off += len(items)
	if f.off >= len(f.buf) && f.cur != "" {
		if err := f.s.Delete(f.ctx, f.cur); err != nil {
			return err // Peek retries the delete before reading on
		}
		f.cur, f.buf, f.off = "", nil, 0
	}
	return nil
}

// sharedDead stores each dead-lettered event as its own shared object.
type sharedDead struct {
	ctx    context.Context
	s      SharedStore
	prefix string
	node   string
	limit  int
	seq    uint64
}

func (d *sharedDead) AppendEvicting(data []byte) (bool, error) {
	evicted := false
	if d.limit > 0 {
		names, err := d.s.List(d.ctx, d.prefix, d.limit+1)
		if err != nil {
			return false, err
		}
		if len(names) >= d.limit {
			sort.Strings(names)
			if err := d.s.Delete(d.ctx, names[0]); err != nil {
				return false, err
			}
			evicted = true
		}
	}
	d.seq++
	return evicted, d.s.Put(d.ctx, objectName(d.prefix, time.Now().UnixNano(), d.node, d.seq), data)
}

func (d *sharedDead) Sync() error { return nil }

func (d *sharedDead) Peek(n int) ([]Item, error) {
	names, err := d.s.List(d.ctx, d.prefix, n)
	if err != nil {
		return nil, err
	}
	items := make([]Item, 0, len(names))
	for _, name := range names {
		data, err := d.s.Get(d.ctx, name)
		if errors.Is(err, ErrSharedNotFound) {
			continue
		}
		if err != nil {
			return items, err
		}
		items = append(items, Item{Data: data, name: name})
	}
	return items, nil
}

func (d *sharedDead) Ack(items []Item) error {
	for _, it := range items {
		if err := d.s.Delete(d.ctx, it.name); err != nil {
			return err
		}
	}
	return nil
}

func (d *sharedDead) Len() int {
	names, err := d.s.List(d.ctx, d.prefix, listCap)
	if err != nil {
		return -1
	}
	return len(names)
}
