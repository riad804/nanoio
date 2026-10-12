package tier

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Cache is a node-local, size-bounded, expiring store of transitioned
// objects that were read or explicitly restored. It is what makes a second
// read of a cold object cheap, and what an S3 RestoreObject fills.
type Cache struct {
	dir string
	max int64
	now func() time.Time

	mu    sync.Mutex
	items map[string]*cacheItem
	total int64
}

type cacheItem struct {
	size    int64
	expiry  time.Time
	access  time.Time
	restore bool // asked for explicitly: reported by x-amz-restore
}

// NewCache opens (creating) a cache in dir holding at most maxBytes.
func NewCache(dir string, maxBytes int64) (*Cache, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	c := &Cache{dir: dir, max: maxBytes, now: time.Now, items: map[string]*cacheItem{}}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		name := e.Name()
		switch {
		case strings.HasSuffix(name, ".tmp"):
			os.Remove(filepath.Join(dir, name))
		case strings.HasSuffix(name, ".data"):
			key := strings.TrimSuffix(name, ".data")
			st, err := e.Info()
			if err != nil {
				continue
			}
			exp, restore := readExpiry(filepath.Join(dir, key+".exp"))
			if exp.IsZero() {
				os.Remove(filepath.Join(dir, name))
				continue
			}
			c.items[key] = &cacheItem{size: st.Size(), expiry: exp, access: st.ModTime(), restore: restore}
			c.total += st.Size()
		}
	}
	return c, nil
}

// SetClock replaces the clock (tests).
func (c *Cache) SetClock(now func() time.Time) { c.now = now }

// Key derives the cache key of a version.
func Key(bucket, object, versionID, etag string) string {
	h := sha256.Sum256([]byte(bucket + "\x00" + object + "\x00" + versionID + "\x00" + etag))
	return hex.EncodeToString(h[:16])
}

func readExpiry(path string) (time.Time, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}, false
	}
	s := strings.Fields(string(b))
	if len(s) == 0 {
		return time.Time{}, false
	}
	ns, err := strconv.ParseInt(s[0], 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(0, ns), len(s) > 1 && s[1] == "restore"
}

// Open returns the cached object for key, if present and unexpired.
func (c *Cache) Open(key string) (*os.File, bool) {
	c.mu.Lock()
	it := c.items[key]
	if it == nil || !c.now().Before(it.expiry) {
		if it != nil {
			c.removeLocked(key)
		}
		c.mu.Unlock()
		return nil, false
	}
	it.access = c.now()
	c.mu.Unlock()
	f, err := os.Open(filepath.Join(c.dir, key+".data"))
	if err != nil {
		c.mu.Lock()
		c.removeLocked(key)
		c.mu.Unlock()
		return nil, false
	}
	return f, true
}

// RestoreExpiry reports whether key is cached and, if it was put there by an
// explicit restore, when that restore ends.
func (c *Cache) RestoreExpiry(key string) (expiry time.Time, restored bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	it := c.items[key]
	if it == nil || !c.now().Before(it.expiry) {
		return time.Time{}, false
	}
	return it.expiry, it.restore
}

// Has reports whether key is cached and unexpired.
func (c *Cache) Has(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	it := c.items[key]
	return it != nil && c.now().Before(it.expiry)
}

func (c *Cache) removeLocked(key string) {
	if it := c.items[key]; it != nil {
		c.total -= it.size
		delete(c.items, key)
	}
	os.Remove(filepath.Join(c.dir, key+".data"))
	os.Remove(filepath.Join(c.dir, key+".exp"))
}

// Max is the size bound.
func (c *Cache) Max() int64 { return c.max }

// Writer stages a cache entry; Commit publishes it, Abort discards it.
type Writer struct {
	c       *Cache
	key     string
	f       *os.File
	n       int64
	expiry  time.Time
	restore bool
}

// Create begins an entry that will live until expiry. restore marks an
// explicit restore.
func (c *Cache) Create(key string, expiry time.Time, restore bool) (*Writer, error) {
	f, err := os.CreateTemp(c.dir, key+"-*.tmp")
	if err != nil {
		return nil, err
	}
	return &Writer{c: c, key: key, f: f, expiry: expiry, restore: restore}, nil
}

// Write implements io.Writer.
func (w *Writer) Write(p []byte) (int, error) {
	n, err := w.f.Write(p)
	w.n += int64(n)
	return n, err
}

// Abort discards the entry.
func (w *Writer) Abort() {
	w.f.Close()
	os.Remove(w.f.Name())
}

// Commit publishes the entry, evicting least-recently-used entries to stay
// within the bound. An entry larger than the whole cache is refused.
func (w *Writer) Commit() error {
	c := w.c
	if err := w.f.Sync(); err != nil {
		w.Abort()
		return err
	}
	tmp := w.f.Name()
	w.f.Close()
	if c.max > 0 && w.n > c.max {
		os.Remove(tmp)
		return io.ErrShortBuffer
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if old := c.items[w.key]; old != nil {
		c.removeLocked(w.key)
	}
	for c.max > 0 && c.total+w.n > c.max && len(c.items) > 0 {
		var keys []string
		for k := range c.items {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return c.items[keys[i]].access.Before(c.items[keys[j]].access) })
		c.removeLocked(keys[0])
	}
	marker := ""
	if w.restore {
		marker = " restore"
	}
	if err := os.WriteFile(filepath.Join(c.dir, w.key+".exp"), []byte(strconv.FormatInt(w.expiry.UnixNano(), 10)+marker), 0o600); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, filepath.Join(c.dir, w.key+".data")); err != nil {
		os.Remove(tmp)
		return err
	}
	c.items[w.key] = &cacheItem{size: w.n, expiry: w.expiry, access: c.now(), restore: w.restore}
	c.total += w.n
	return nil
}

// Size is the bytes currently held.
func (c *Cache) Size() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.total
}

// Delete drops an entry.
func (c *Cache) Delete(key string) {
	c.mu.Lock()
	c.removeLocked(key)
	c.mu.Unlock()
}
