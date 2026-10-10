// Package pins lets a backend keep a directory alive for as long as a
// reader that has begun streaming from it still needs it.
//
// Reads release their namespace lock before streaming (so a slow client
// cannot block writers), which means a concurrent overwrite or delete can
// remove the data directory a reader is about to open its next file in.
// Registering the directory here turns that removal into a deferred one that
// happens when the last reader finishes, giving every reader a stable
// snapshot without holding any lock. The registry is in-process, which is
// sufficient because a backend owns its directories exclusively.
package pins

import (
	"os"
	"sync"
)

// Registry is the set of pinned paths. The zero value is ready to use.
type Registry struct {
	mu sync.Mutex
	m  map[string]*entry
}

type entry struct {
	n      int
	remove bool
}

// Pin marks path as in use and returns the function that releases it. The
// release function is idempotent.
func (r *Registry) Pin(path string) (release func()) {
	r.mu.Lock()
	if r.m == nil {
		r.m = map[string]*entry{}
	}
	e := r.m[path]
	if e == nil {
		e = &entry{}
		r.m[path] = e
	}
	e.n++
	r.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			r.mu.Lock()
			e.n--
			doRemove := false
			if e.n == 0 {
				delete(r.m, path)
				doRemove = e.remove
			}
			r.mu.Unlock()
			if doRemove {
				os.RemoveAll(path)
			}
		})
	}
}

// Remove deletes path, immediately if nothing has it pinned and otherwise
// when the last pin is released.
func (r *Registry) Remove(path string) error {
	r.mu.Lock()
	if e := r.m[path]; e != nil && e.n > 0 {
		e.remove = true
		r.mu.Unlock()
		return nil
	}
	r.mu.Unlock()
	return os.RemoveAll(path)
}

// Pinned reports whether path is currently pinned (or awaiting deferred
// removal), so collectors leave it alone.
func (r *Registry) Pinned(path string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.m[path] != nil
}
