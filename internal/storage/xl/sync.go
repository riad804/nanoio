package xl

import "sync"

// syncWG is a WaitGroup with a Go helper.
type syncWG struct{ sync.WaitGroup }

// Go runs f in a new goroutine tracked by the group.
func (w *syncWG) Go(f func()) {
	w.Add(1)
	go func() {
		defer w.Done()
		f()
	}()
}
