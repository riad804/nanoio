package event

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"os"
	"path/filepath"
	"sync"
)

// ErrQueueFull is returned by Queue.Append when the queue holds its limit
// of entries. The caller counts the event as dropped; the queue never
// evicts, so what it holds is always the oldest undelivered events, in
// order.
var ErrQueueFull = errors.New("event: queue is full")

// Queue is a durable FIFO of opaque entries on disk. Delivery is
// at-least-once: entries are removed only by Ack, and a restart redelivers
// anything not yet acknowledged (the acknowledged position is persisted
// lazily, so a crash can redeliver a few already-sent entries, never lose an
// appended one).
type Queue struct {
	log   *seglog
	limit int
	path  string // cursor file

	mu      sync.Mutex
	cursor  pos
	pending int
	// head is the position up to which Peek has handed out entries; Ack
	// moves the cursor to the Next of the acknowledged item.
}

// Item is a queue entry handed out by Peek.
type Item struct {
	Data []byte
	next pos
	// name is the shared-store object an item came from (replicated
	// queues only).
	name string
}

const cursorFile = "cursor"

// OpenQueue opens (creating if needed) the queue in dir. limit <= 0 means
// unbounded.
func OpenQueue(dir string, limit int, segMax int64) (*Queue, error) {
	l, err := openSeglog(dir, segMax)
	if err != nil {
		return nil, err
	}
	q := &Queue{log: l, limit: limit, path: filepath.Join(dir, cursorFile)}
	q.cursor = q.readCursor()
	if q.cursor.less(l.Start()) {
		q.cursor = l.Start()
	}
	// Count what is pending: everything after the cursor.
	p := q.cursor
	for {
		recs, err := l.ReadFrom(p, 1024)
		if err != nil {
			l.Close()
			return nil, err
		}
		if len(recs) == 0 {
			break
		}
		q.pending += len(recs)
		p = recs[len(recs)-1].Next
	}
	return q, nil
}

func (q *Queue) readCursor() pos {
	b, err := os.ReadFile(q.path)
	if err != nil || len(b) != 20 || crc32.Checksum(b[:16], crcTable) != binary.BigEndian.Uint32(b[16:]) {
		// No or damaged cursor: start from the oldest entry. This can only
		// duplicate deliveries, never lose them.
		return pos{}
	}
	return pos{Seg: binary.BigEndian.Uint64(b), Off: int64(binary.BigEndian.Uint64(b[8:]))}
}

func (q *Queue) writeCursor(p pos) error {
	b := make([]byte, 20)
	binary.BigEndian.PutUint64(b, p.Seg)
	binary.BigEndian.PutUint64(b[8:], uint64(p.Off))
	binary.BigEndian.PutUint32(b[16:], crc32.Checksum(b[:16], crcTable))
	tmp := q.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, q.path)
}

// Append adds an entry at the tail. It is visible to Peek at once and
// durable after Sync.
func (q *Queue) Append(data []byte) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.limit > 0 && q.pending >= q.limit {
		return ErrQueueFull
	}
	if err := q.log.Append(data); err != nil {
		return err
	}
	q.pending++
	return nil
}

// Sync flushes appended entries to stable storage.
func (q *Queue) Sync() error { return q.log.Sync() }

// Peek returns up to n of the oldest unacknowledged entries without
// removing them.
func (q *Queue) Peek(n int) ([]Item, error) {
	q.mu.Lock()
	cur := q.cursor
	q.mu.Unlock()
	recs, err := q.log.ReadFrom(cur, n)
	items := make([]Item, len(recs))
	for i, r := range recs {
		items[i] = Item{Data: r.Data, next: r.Next}
	}
	return items, err
}

// Ack removes the first n entries of items (which must be the head of the
// queue, as returned by Peek).
func (q *Queue) Ack(items []Item) error {
	if len(items) == 0 {
		return nil
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.cursor = items[len(items)-1].next
	q.pending -= len(items)
	if q.pending < 0 {
		q.pending = 0
	}
	if err := q.writeCursor(q.cursor); err != nil {
		return err
	}
	return q.log.DropBefore(q.cursor)
}

// Len is the number of unacknowledged entries.
func (q *Queue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.pending
}

// Bytes is the on-disk size.
func (q *Queue) Bytes() int64 { return q.log.Size() }

// Corrupt counts damaged records skipped.
func (q *Queue) Corrupt() uint64 { return q.log.Corrupt() }

// Close syncs and closes the queue.
func (q *Queue) Close() error { return q.log.Close() }

// AppendEvicting adds an entry, first discarding the oldest one if the
// queue is full. It is for dead-letter queues, where a bounded window of
// the most recent failures is what an operator wants. It reports whether an
// entry was evicted.
func (q *Queue) AppendEvicting(data []byte) (evicted bool, err error) {
	err = q.Append(data)
	if !errors.Is(err, ErrQueueFull) {
		return false, err
	}
	head, err := q.Peek(1)
	if err != nil {
		return false, err
	}
	if err := q.Ack(head); err != nil {
		return false, err
	}
	return true, q.Append(data)
}
