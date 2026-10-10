// Package nslock implements storage.Locker for a single node: an in-memory
// table of reference-counted shared/exclusive locks keyed by bucket and
// object. Waits honour context cancellation and a default timeout, which a
// sync.RWMutex cannot.
//
// A distributed lock manager will later sit behind the same interface.
package nslock

import (
	"context"
	"fmt"
	"sync"
	"time"

	"nanoio/internal/storage"
)

// DefaultTimeout bounds a lock wait when the context has no deadline.
const DefaultTimeout = 30 * time.Second

var _ storage.Locker = (*Manager)(nil)

// Manager is a storage.Locker. The zero value is not usable; use New.
type Manager struct {
	timeout time.Duration

	mu      sync.Mutex
	entries map[string]*entry
}

type entry struct {
	readers int
	writer  bool
	waiters int
	// changed is closed and replaced on every release, waking waiters.
	changed chan struct{}
}

// New returns a Manager. A non-positive timeout means DefaultTimeout.
func New(timeout time.Duration) *Manager {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &Manager{timeout: timeout, entries: make(map[string]*entry)}
}

// Lock takes an exclusive lock on bucket/object; an empty object locks the
// bucket itself.
func (m *Manager) Lock(ctx context.Context, bucket, object string) (func(), error) {
	return m.acquire(ctx, bucket, object, true)
}

// RLock takes a shared lock on bucket/object.
func (m *Manager) RLock(ctx context.Context, bucket, object string) (func(), error) {
	return m.acquire(ctx, bucket, object, false)
}

func (m *Manager) acquire(ctx context.Context, bucket, object string, write bool) (func(), error) {
	key := bucket + "\x00" + object
	timer := time.NewTimer(m.timeout)
	defer timer.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		m.mu.Lock()
		e := m.entries[key]
		if e == nil {
			e = &entry{changed: make(chan struct{})}
			m.entries[key] = e
		}
		if (write && !e.writer && e.readers == 0) || (!write && !e.writer) {
			if write {
				e.writer = true
			} else {
				e.readers++
			}
			m.mu.Unlock()
			return m.releaser(key, e, write), nil
		}
		e.waiters++
		ch := e.changed
		m.mu.Unlock()

		var err error
		select {
		case <-ch:
		case <-ctx.Done():
			err = ctx.Err()
		case <-timer.C:
			err = fmt.Errorf("%w: %s/%s", storage.ErrLockTimeout, bucket, object)
		}

		m.mu.Lock()
		e.waiters--
		m.gc(key, e)
		m.mu.Unlock()
		if err != nil {
			return nil, err
		}
	}
}

func (m *Manager) releaser(key string, e *entry, write bool) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			m.mu.Lock()
			defer m.mu.Unlock()
			if write {
				e.writer = false
			} else {
				e.readers--
			}
			close(e.changed)
			e.changed = make(chan struct{})
			m.gc(key, e)
		})
	}
}

// gc drops an idle entry. m.mu must be held.
func (m *Manager) gc(key string, e *entry) {
	if !e.writer && e.readers == 0 && e.waiters == 0 && m.entries[key] == e {
		delete(m.entries, key)
	}
}

// Held reports the number of keys with a holder or waiter, for tests and
// diagnostics.
func (m *Manager) Held() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.entries)
}
