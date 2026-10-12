package tier

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"nanoio/internal/storage"
)

// Janitor deletes the remote copy of a transitioned version once the stub
// that pointed at it is gone (the version was deleted or overwritten). The
// request that removed the stub only has to note the fact; each note is a
// small file in a local directory, so a crash or an unreachable tier delays
// the remote delete but never forgets it.
type Janitor struct {
	dir string
	log *slog.Logger

	mu     sync.Mutex
	mgr    *Manager
	wake   chan struct{}
	stop   chan struct{}
	done   chan struct{}
	closed bool

	deleted atomicCounter
	failed  atomicCounter
}

type atomicCounter struct {
	mu sync.Mutex
	n  uint64
}

func (c *atomicCounter) add() { c.mu.Lock(); c.n++; c.mu.Unlock() }
func (c *atomicCounter) get() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

type freedNote struct {
	Tier      string    `json:"tier"`
	Object    string    `json:"object"`
	VersionID string    `json:"versionId,omitempty"`
	Bucket    string    `json:"bucket,omitempty"`
	Key       string    `json:"key,omitempty"`
	Noted     time.Time `json:"noted"`
}

// NewJanitor prepares the janitor's directory. Start begins the work.
func NewJanitor(dir string, log *slog.Logger) (*Janitor, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if log == nil {
		log = slog.Default()
	}
	return &Janitor{dir: dir, log: log, wake: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{})}, nil
}

// Freed records that tr's remote copy is no longer referenced. It matches
// the storage layer's callback (xl.Options.OnTransitionFreed) and never
// blocks on the network.
func (j *Janitor) Freed(bucket, object string, tr storage.TransitionInfo) {
	n := freedNote{Tier: tr.Tier, Object: tr.Object, VersionID: tr.VersionID, Bucket: bucket, Key: object, Noted: time.Now().UTC()}
	data, _ := json.Marshal(n)
	var rnd [6]byte
	rand.Read(rnd[:])
	name := filepath.Join(j.dir, strconv.FormatInt(time.Now().UnixNano(), 10)+"-"+hex.EncodeToString(rnd[:])+".json")
	tmp := name + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		j.log.Error("tier: cannot record a remote object to delete; it will be orphaned in the tier",
			"tier", tr.Tier, "object", tr.Object, "err", err)
		return
	}
	if err := os.Rename(tmp, name); err != nil {
		os.Remove(tmp)
		return
	}
	select {
	case j.wake <- struct{}{}:
	default:
	}
}

// Start runs the deletion loop against mgr until Close.
func (j *Janitor) Start(mgr *Manager) {
	j.mu.Lock()
	if j.mgr != nil || j.closed {
		j.mu.Unlock()
		return
	}
	j.mgr = mgr
	j.mu.Unlock()
	go j.run()
}

// Pending is the number of remote deletions not yet done.
func (j *Janitor) Pending() int { return len(j.notes()) }

// Deleted counts remote copies removed.
func (j *Janitor) Deleted() uint64 { return j.deleted.get() }

func (j *Janitor) notes() []string {
	ents, err := os.ReadDir(j.dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if filepath.Ext(e.Name()) == ".json" {
			out = append(out, filepath.Join(j.dir, e.Name()))
		}
	}
	sort.Strings(out)
	return out
}

func (j *Janitor) run() {
	defer close(j.done)
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		j.sweep()
		select {
		case <-j.stop:
			return
		case <-j.wake:
		case <-t.C:
		}
	}
}

func (j *Janitor) sweep() {
	for _, path := range j.notes() {
		select {
		case <-j.stop:
			return
		default:
		}
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var n freedNote
		if json.Unmarshal(data, &n) != nil {
			os.Remove(path)
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		be, _, err := j.mgr.Get(ctx, n.Tier)
		switch {
		case errors.Is(err, ErrNotFound):
			j.log.Warn("tier: dropping a remote deletion for a tier that no longer exists", "tier", n.Tier, "object", n.Object)
			cancel()
			os.Remove(path)
			continue
		case err != nil:
			cancel()
			j.failed.add()
			continue
		}
		err = be.Delete(ctx, n.Object, n.VersionID)
		cancel()
		if err != nil {
			j.failed.add()
			j.log.Warn("tier: remote delete failed; will retry", "tier", n.Tier, "object", n.Object, "err", err)
			continue
		}
		j.deleted.add()
		os.Remove(path)
	}
}

// Close stops the loop. Pending notes stay on disk for the next start.
func (j *Janitor) Close() {
	j.mu.Lock()
	if j.closed {
		j.mu.Unlock()
		return
	}
	j.closed = true
	started := j.mgr != nil
	close(j.stop)
	j.mu.Unlock()
	if started {
		<-j.done
	}
}
