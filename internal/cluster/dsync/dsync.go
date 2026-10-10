// Package dsync is NanoIO's distributed namespace lock: a quorum lock over
// per-node in-memory lock tables, in the style of dsync.
//
// Every node runs a Server holding leases. A client acquires a lock by
// asking all N servers and succeeds when a quorum grants it: W = N/2+1 for
// exclusive locks, R = N-W+1 for shared locks, so any exclusive quorum
// intersects any other exclusive quorum and any shared quorum. Grants are
// leases: they expire after TTL unless the holder refreshes them, so a
// crashed holder cannot wedge a resource, and a holder that loses its
// refresh quorum learns so (Options.OnLost) before any competitor can win,
// because the competitor needs those same servers' leases to expire.
//
// What the lock does and does not give. It orders and excludes
// well-behaved writers; it is not what makes writes safe. A holder can
// stall past its lease (GC pause, partition) and then act on a lock it no
// longer holds. Safety against that comes from the compare-and-set commit
// (a per-object generation each drive checks), so the lock is a fairness
// and efficiency mechanism, and the CAS is the correctness mechanism.
//
// A restarted server forgets its table, so for one TTL after start it
// grants nothing: any lease it had issued before dying has expired by then.
// There is no queueing; contenders retry with jittered backoff, so a
// continuous stream of readers can starve a writer.
package dsync

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	mrand "math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"nanoio/internal/cluster/rpc"
	"nanoio/internal/storage"
)

// Defaults.
const (
	DefaultTTL        = 30 * time.Second
	DefaultRPCTimeout = 2 * time.Second
)

// Server is one node's lock table.
type Server struct {
	ttl time.Duration
	now func() time.Time

	mu      sync.Mutex
	started time.Time
	res     map[string]*lockState
}

type lockState struct {
	writer    string
	writerExp time.Time
	readers   map[string]time.Time
}

// NewServer returns a lock table whose leases last ttl (0 means DefaultTTL).
// It refuses grants until one TTL has passed.
func NewServer(ttl time.Duration) *Server { return newServer(ttl, time.Now) }

func newServer(ttl time.Duration, now func() time.Time) *Server {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Server{ttl: ttl, now: now, started: now(), res: map[string]*lockState{}}
}

// Quarantined reports whether the server is still in its post-start grace
// period.
func (s *Server) Quarantined() bool { return s.now().Sub(s.started) < s.ttl }

func (s *Server) state(resource string) *lockState {
	st := s.res[resource]
	if st == nil {
		st = &lockState{readers: map[string]time.Time{}}
		s.res[resource] = st
	}
	return st
}

// expire drops lapsed leases of st.
func (st *lockState) expire(now time.Time) {
	if st.writer != "" && !now.Before(st.writerExp) {
		st.writer = ""
	}
	for uid, exp := range st.readers {
		if !now.Before(exp) {
			delete(st.readers, uid)
		}
	}
}

// Acquire grants resource to uid if compatible. Re-acquiring with the same
// uid renews the lease.
func (s *Server) Acquire(resource, uid string, write bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Quarantined() {
		return false
	}
	now := s.now()
	st := s.state(resource)
	st.expire(now)
	exp := now.Add(s.ttl)
	if write {
		if st.writer == uid {
			st.writerExp = exp
			return true
		}
		if st.writer != "" || len(st.readers) > 0 {
			return false
		}
		st.writer, st.writerExp = uid, exp
		return true
	}
	if st.writer != "" {
		return false
	}
	st.readers[uid] = exp
	return true
}

// Refresh extends uid's leases on resources and reports, per resource,
// whether uid still holds it.
func (s *Server) Refresh(uid string, resources []string) []bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	out := make([]bool, len(resources))
	for i, r := range resources {
		st := s.res[r]
		if st == nil {
			continue
		}
		st.expire(now)
		exp := now.Add(s.ttl)
		switch {
		case st.writer == uid:
			st.writerExp, out[i] = exp, true
		default:
			if _, ok := st.readers[uid]; ok {
				st.readers[uid], out[i] = exp, true
			}
		}
	}
	return out
}

// Release drops uid's hold on resource. Unknown holds are ignored.
func (s *Server) Release(resource, uid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.res[resource]
	if st == nil {
		return
	}
	if st.writer == uid {
		st.writer = ""
	}
	delete(st.readers, uid)
	if st.writer == "" && len(st.readers) == 0 {
		delete(s.res, resource)
	}
}

// Held is the number of resources with at least one live lease (tests).
func (s *Server) Held() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	n := 0
	for _, st := range s.res {
		st.expire(now)
		if st.writer != "" || len(st.readers) > 0 {
			n++
		}
	}
	return n
}

// Wire documents.
type (
	acquireArgs struct {
		Resource string `json:"resource"`
		UID      string `json:"uid"`
		Write    bool   `json:"write"`
	}
	granted struct {
		OK bool `json:"ok"`
	}
	releaseArgs struct {
		Resource string `json:"resource"`
		UID      string `json:"uid"`
	}
	refreshArgs struct {
		UID       string   `json:"uid"`
		Resources []string `json:"resources"`
	}
	refreshRes struct {
		Held []bool `json:"held"`
	}
	none struct{}
)

// Register exposes the server's operations on rs.
func (s *Server) Register(rs *rpc.Server) {
	rs.Handle("lock.acquire", rpc.JSON(func(_ context.Context, _ string, a acquireArgs) (granted, error) {
		return granted{s.Acquire(a.Resource, a.UID, a.Write)}, nil
	}))
	rs.Handle("lock.release", rpc.JSON(func(_ context.Context, _ string, a releaseArgs) (none, error) {
		s.Release(a.Resource, a.UID)
		return none{}, nil
	}))
	rs.Handle("lock.refresh", rpc.JSON(func(_ context.Context, _ string, a refreshArgs) (refreshRes, error) {
		return refreshRes{s.Refresh(a.UID, a.Resources)}, nil
	}))
}

// Options configures a Locker.
type Options struct {
	// Nodes is every lock server's node ID, including Self. Required.
	Nodes []string
	// Self is this node's ID; calls to it bypass the network.
	Self string
	// Local is this node's own Server.
	Local *Server
	// Client reaches the other nodes.
	Client *rpc.Client
	// TTL must equal the servers' TTL. 0 means DefaultTTL.
	TTL time.Duration
	// RPCTimeout bounds one lock RPC. 0 means DefaultRPCTimeout.
	RPCTimeout time.Duration
	// Timeout bounds an acquisition whose context has no deadline. 0 means
	// 30 seconds.
	Timeout time.Duration
	// OnLost is called when a held lock's refresh quorum is lost, with the
	// resource name, before the lease can have expired everywhere.
	OnLost func(resource string)
}

// Locker implements storage.Locker over the cluster's lock servers.
type Locker struct {
	opt Options
	w   int // exclusive quorum
	r   int // shared quorum
}

var _ storage.Locker = (*Locker)(nil)

// NewLocker returns a Locker.
func NewLocker(opt Options) (*Locker, error) {
	n := len(opt.Nodes)
	if n == 0 {
		return nil, errors.New("dsync: no lock nodes")
	}
	if opt.Local == nil && opt.Client == nil {
		return nil, errors.New("dsync: neither a local server nor a client")
	}
	if opt.TTL <= 0 {
		opt.TTL = DefaultTTL
	}
	if opt.RPCTimeout <= 0 {
		opt.RPCTimeout = DefaultRPCTimeout
	}
	if opt.Timeout <= 0 {
		opt.Timeout = 30 * time.Second
	}
	w := n/2 + 1
	return &Locker{opt: opt, w: w, r: n - w + 1}, nil
}

// Quorums returns the exclusive and shared quorum sizes.
func (l *Locker) Quorums() (write, read int) { return l.w, l.r }

func resource(bucket, object string) string { return bucket + "\x00" + object }

// Lock takes an exclusive lock.
func (l *Locker) Lock(ctx context.Context, bucket, object string) (func(), error) {
	return l.acquire(ctx, resource(bucket, object), true)
}

// RLock takes a shared lock.
func (l *Locker) RLock(ctx context.Context, bucket, object string) (func(), error) {
	return l.acquire(ctx, resource(bucket, object), false)
}

func newUID() string {
	var b [16]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// ask sends one lock RPC to node.
func (l *Locker) ask(ctx context.Context, node, op string, in, out any) error {
	ctx, cancel := context.WithTimeout(ctx, l.opt.RPCTimeout)
	defer cancel()
	return l.opt.Client.Call(ctx, node, op, in, out)
}

func (l *Locker) tryAcquire(ctx context.Context, node, res, uid string, write bool) bool {
	if node == l.opt.Self && l.opt.Local != nil {
		return l.opt.Local.Acquire(res, uid, write)
	}
	var g granted
	if err := l.ask(ctx, node, "lock.acquire", acquireArgs{res, uid, write}, &g); err != nil {
		return false
	}
	return g.OK
}

// release sends Release to every node: a grant whose reply was lost must
// be undone too.
func (l *Locker) release(res, uid string) {
	var wg sync.WaitGroup
	for _, node := range l.opt.Nodes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if node == l.opt.Self && l.opt.Local != nil {
				l.opt.Local.Release(res, uid)
				return
			}
			l.ask(context.Background(), node, "lock.release", releaseArgs{res, uid}, nil)
		}()
	}
	wg.Wait()
}

func (l *Locker) acquire(ctx context.Context, res string, write bool) (func(), error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, l.opt.Timeout)
		defer cancel()
	}
	quorum := l.r
	if write {
		quorum = l.w
	}
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				return nil, storage.ErrLockTimeout
			}
			return nil, err
		}
		uid := newUID()
		ok, settled := l.broadcast(ctx, res, uid, write, quorum)
		if ok {
			return l.hold(res, uid, quorum, settled), nil
		}
		<-settled // no grant of this uid can arrive after the release
		l.release(res, uid)
		back := time.Duration(5+mrand.IntN(20)) * time.Millisecond * time.Duration(1+min(attempt, 8))
		select {
		case <-time.After(back):
		case <-ctx.Done():
		}
	}
}

// broadcast asks every node and reports whether quorum granted. It returns
// as soon as the outcome is decided. settled is closed once every node has
// answered or timed out: until then a grant may still arrive, so a release
// sent earlier could be overtaken by it.
func (l *Locker) broadcast(ctx context.Context, res, uid string, write bool, quorum int) (bool, <-chan struct{}) {
	n := len(l.opt.Nodes)
	replies := make(chan bool, n)
	settled := make(chan struct{})
	for _, node := range l.opt.Nodes {
		go func() { replies <- l.tryAcquire(ctx, node, res, uid, write) }()
	}
	var outcome atomic.Int32 // 0 undecided, 1 granted, 2 refused
	decided := make(chan struct{})
	go func() {
		got, answered := 0, 0
		for answered < n {
			if <-replies {
				got++
			}
			answered++
			if outcome.Load() == 0 {
				switch {
				case got >= quorum:
					outcome.Store(1)
					close(decided)
				case got+(n-answered) < quorum:
					outcome.Store(2)
					close(decided)
				}
			}
		}
		close(settled)
	}()
	<-decided
	return outcome.Load() == 1, settled
}

// hold keeps the lease alive until the returned unlock runs.
func (l *Locker) hold(res, uid string, quorum int, settled <-chan struct{}) func() {
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(l.opt.TTL / 3)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				if !l.refresh(res, uid, quorum) {
					if l.opt.OnLost != nil {
						l.opt.OnLost(res)
					}
					return
				}
			}
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			close(stop)
			<-done
			select {
			case <-settled:
				l.release(res, uid)
			default:
				// A grant of ours is still in flight; release once it
				// has landed, without holding up the caller.
				go func() {
					<-settled
					l.release(res, uid)
				}()
			}
		})
	}
}

func (l *Locker) refresh(res, uid string, quorum int) bool {
	var mu sync.Mutex
	held := 0
	var wg sync.WaitGroup
	for _, node := range l.opt.Nodes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok := false
			if node == l.opt.Self && l.opt.Local != nil {
				ok = l.opt.Local.Refresh(uid, []string{res})[0]
			} else {
				var r refreshRes
				if err := l.ask(context.Background(), node, "lock.refresh", refreshArgs{uid, []string{res}}, &r); err == nil && len(r.Held) == 1 {
					ok = r.Held[0]
				}
			}
			if ok {
				mu.Lock()
				held++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return held >= quorum
}
