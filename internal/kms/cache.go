package kms

import (
	"container/list"
	"context"
	"crypto/sha256"
	"sync"
	"time"
)

// Cache decorates a KMS with a TTL cache of Decrypt and DescribeKey
// results, so a read does not cost a KMS round trip. Only successes are
// cached. GenerateKey and Encrypt always reach the KMS.
type Cache struct {
	next KMS
	ttl  time.Duration
	max  int
	now  func() time.Time

	mu       sync.Mutex
	entries  map[[32]byte]*list.Element
	lru      *list.List
	inflight map[[32]byte]*call
	desc     map[string]descEntry
}

type entry struct {
	key     [32]byte
	val     []byte
	expires time.Time
}

type descEntry struct {
	info    KeyInfo
	expires time.Time
}

type call struct {
	done chan struct{}
	val  []byte
	err  error
}

// NewCache wraps next. ttl <= 0 disables caching (calls pass through);
// max <= 0 means 10,000 entries.
func NewCache(next KMS, ttl time.Duration, max int) *Cache {
	if max <= 0 {
		max = 10000
	}
	return &Cache{next: next, ttl: ttl, max: max, now: time.Now,
		entries: map[[32]byte]*list.Element{}, lru: list.New(),
		inflight: map[[32]byte]*call{}, desc: map[string]descEntry{}}
}

// GenerateKey implements KMS.
func (c *Cache) GenerateKey(ctx context.Context, keyID string, kctx Context) (DataKey, error) {
	return c.next.GenerateKey(ctx, keyID, kctx)
}

// Encrypt implements KMS.
func (c *Cache) Encrypt(ctx context.Context, keyID string, pt []byte, kctx Context) (Wrapped, error) {
	return c.next.Encrypt(ctx, keyID, pt, kctx)
}

func cacheKey(keyID string, ct []byte, kctx Context) [32]byte {
	h := sha256.New()
	h.Write([]byte(keyID))
	h.Write([]byte{0})
	h.Write(kctx.Canonical())
	h.Write([]byte{0})
	h.Write(ct)
	var k [32]byte
	h.Sum(k[:0])
	return k
}

// Decrypt implements KMS. The returned slice is the caller's to modify.
func (c *Cache) Decrypt(ctx context.Context, keyID string, ct []byte, kctx Context) ([]byte, error) {
	if c.ttl <= 0 {
		return c.next.Decrypt(ctx, keyID, ct, kctx)
	}
	k := cacheKey(keyID, ct, kctx)
	c.mu.Lock()
	if el, ok := c.entries[k]; ok {
		e := el.Value.(*entry)
		if c.now().Before(e.expires) {
			c.lru.MoveToFront(el)
			out := append([]byte(nil), e.val...)
			c.mu.Unlock()
			return out, nil
		}
		c.remove(el)
	}
	if cl, ok := c.inflight[k]; ok {
		c.mu.Unlock()
		select {
		case <-cl.done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if cl.err != nil {
			return nil, cl.err
		}
		return append([]byte(nil), cl.val...), nil
	}
	cl := &call{done: make(chan struct{})}
	c.inflight[k] = cl
	c.mu.Unlock()

	// The shared call must not die with one caller's context.
	cl.val, cl.err = c.next.Decrypt(context.WithoutCancel(ctx), keyID, ct, kctx)

	c.mu.Lock()
	delete(c.inflight, k)
	if cl.err == nil {
		c.entries[k] = c.lru.PushFront(&entry{key: k, val: append([]byte(nil), cl.val...), expires: c.now().Add(c.ttl)})
		for c.lru.Len() > c.max {
			c.remove(c.lru.Back())
		}
	}
	c.mu.Unlock()
	close(cl.done)
	if cl.err != nil {
		return nil, cl.err
	}
	return append([]byte(nil), cl.val...), nil
}

func (c *Cache) remove(el *list.Element) {
	e := c.lru.Remove(el).(*entry)
	Zero(e.val)
	delete(c.entries, e.key)
}

// DescribeKey implements KMS.
func (c *Cache) DescribeKey(ctx context.Context, keyID string) (KeyInfo, error) {
	if c.ttl > 0 {
		c.mu.Lock()
		if d, ok := c.desc[keyID]; ok && c.now().Before(d.expires) {
			c.mu.Unlock()
			return d.info, nil
		}
		c.mu.Unlock()
	}
	info, err := c.next.DescribeKey(ctx, keyID)
	if err == nil && c.ttl > 0 {
		c.mu.Lock()
		c.desc[keyID] = descEntry{info, c.now().Add(c.ttl)}
		c.mu.Unlock()
	}
	return info, err
}

// Len reports the number of cached Decrypt results (for tests and metrics).
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lru.Len()
}
