package dsync

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"nanoio/internal/cluster/faultnet"
	"nanoio/internal/cluster/rpc"
	"nanoio/internal/cluster/rpcauth"
	"nanoio/internal/storage"
)

// testCluster is n nodes, each with a lock server and a Locker.
type testCluster struct {
	t       *testing.T
	net     *faultnet.Network
	ids     []string
	addr    map[string]string
	keys    *rpcauth.Keyring
	rpcs    []*rpc.Server
	servers []*Server
	lockers []*Locker
	ttl     time.Duration
	lost    func(node int, res string)

	mu sync.RWMutex // guards servers and lockers, which restart replaces
}

func (c *testCluster) locker(i int) *Locker {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lockers[i]
}

func newTestCluster(t *testing.T, n int, ttl time.Duration) *testCluster {
	t.Helper()
	keys, _ := rpcauth.NewKeyring("dsync-test-secret-0123456789")
	c := &testCluster{t: t, net: faultnet.New(), keys: keys, addr: map[string]string{}, ttl: ttl}
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("n%d", i)
		c.ids = append(c.ids, id)
		c.addr[id] = id + ":1"
	}
	for i, id := range c.ids {
		rs := rpc.NewServer(rpc.ServerConfig{Self: id, Keys: keys, Known: func(string) bool { return true }})
		c.rpcs = append(c.rpcs, rs)
		c.net.Register(c.addr[id], rs)
		c.servers = append(c.servers, nil)
		c.lockers = append(c.lockers, nil)
		c.start(i)
	}
	return c
}

// start (re)creates node i's server, as after a process restart.
func (c *testCluster) start(i int) {
	c.t.Helper()
	srv := NewServer(c.ttl)
	srv.Register(c.rpcs[i])
	client, err := rpc.NewClient(rpc.Config{Self: c.ids[i], Keys: c.keys, Peers: c.addr, HTTP: c.net.Client(c.addr[c.ids[i]])})
	if err != nil {
		c.t.Fatal(err)
	}
	l, err := NewLocker(Options{Nodes: c.ids, Self: c.ids[i], Local: srv, Client: client, TTL: c.ttl,
		RPCTimeout: 80 * time.Millisecond, Timeout: 2 * time.Second,
		OnLost: func(res string) {
			if c.lost != nil {
				c.lost(i, res)
			}
		}})
	if err != nil {
		c.t.Fatal(err)
	}
	c.mu.Lock()
	c.servers[i], c.lockers[i] = srv, l
	c.mu.Unlock()
}

// restart simulates a crash and restart of node i's lock server.
func (c *testCluster) restart(i int) { c.start(i) }

// checker asserts mutual exclusion over every resource.
type checker struct {
	mu      sync.Mutex
	writers map[string]int
	readers map[string]int
	bad     []string
	entries atomic.Int64
}

func newChecker() *checker {
	return &checker{writers: map[string]int{}, readers: map[string]int{}}
}

func (k *checker) enter(res string, write bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.entries.Add(1)
	if write {
		if k.writers[res] > 0 || k.readers[res] > 0 {
			k.bad = append(k.bad, fmt.Sprintf("writer entered %q with %d writers, %d readers inside", res, k.writers[res], k.readers[res]))
		}
		k.writers[res]++
		return
	}
	if k.writers[res] > 0 {
		k.bad = append(k.bad, fmt.Sprintf("reader entered %q with %d writers inside", res, k.writers[res]))
	}
	k.readers[res]++
}

func (k *checker) leave(res string, write bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if write {
		k.writers[res]--
	} else {
		k.readers[res]--
	}
}

func (k *checker) verify(t *testing.T) {
	t.Helper()
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, b := range k.bad {
		t.Error(b)
	}
}

// hammer runs workers over resources, each on a random node, and returns
// when every worker has done iters attempts. Acquisitions that time out are
// tolerated (and counted).
func hammer(t *testing.T, c *testCluster, k *checker, workers, iters int, resources []string, perIter func(w, i int)) (timeouts int64) {
	t.Helper()
	var wg sync.WaitGroup
	var to atomic.Int64
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rng := rand.New(rand.NewPCG(uint64(w), 42))
			for i := 0; i < iters; i++ {
				if perIter != nil {
					perIter(w, i)
				}
				node := rng.IntN(len(c.ids))
				res := resources[rng.IntN(len(resources))]
				write := rng.IntN(3) == 0
				var unlock func()
				var err error
				if write {
					unlock, err = c.locker(node).Lock(context.Background(), "b", res)
				} else {
					unlock, err = c.locker(node).RLock(context.Background(), "b", res)
				}
				if err != nil {
					if errors.Is(err, storage.ErrLockTimeout) {
						to.Add(1)
						continue
					}
					t.Errorf("acquire: %v", err)
					return
				}
				k.enter(res, write)
				time.Sleep(time.Duration(rng.IntN(1500)) * time.Microsecond)
				k.leave(res, write)
				unlock()
			}
		}()
	}
	wg.Wait()
	return to.Load()
}

func TestQuorumArithmetic(t *testing.T) {
	for n := 1; n <= 12; n++ {
		l, err := NewLocker(Options{Nodes: make([]string, n), Local: NewServer(0)})
		if err != nil {
			t.Fatal(err)
		}
		w, r := l.Quorums()
		if 2*w <= n {
			t.Errorf("N=%d: write quorum %d is not a majority; two writers could both win", n, w)
		}
		if r+w <= n {
			t.Errorf("N=%d: read %d + write %d does not exceed N; a reader and a writer could both win", n, r, w)
		}
		if r < 1 || w > n {
			t.Errorf("N=%d: quorums %d/%d out of range", n, w, r)
		}
	}
}

func TestMutualExclusion(t *testing.T) {
	c := newTestCluster(t, 5, 500*time.Millisecond)
	time.Sleep(c.ttl + 50*time.Millisecond) // a fresh server grants nothing for one TTL
	k := newChecker()
	to := hammer(t, c, k, 12, 60, []string{"r1", "r2", "r3"}, nil)
	k.verify(t)
	if to > 0 {
		t.Errorf("%d acquisitions timed out on a healthy cluster", to)
	}
	if got := k.entries.Load(); got != 12*60 {
		t.Errorf("%d critical sections ran, want %d", got, 12*60)
	}
	for i, s := range c.servers {
		deadline := time.Now().Add(time.Second)
		for s.Held() != 0 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if h := s.Held(); h != 0 {
			t.Errorf("node %d still holds %d leases after every unlock", i, h)
		}
	}
}

func TestMutualExclusionUnderFaults(t *testing.T) {
	c := newTestCluster(t, 5, 400*time.Millisecond)
	// Leases need a quiet period to start granting after boot.
	time.Sleep(c.ttl + 50*time.Millisecond)
	k := newChecker()
	var fired atomic.Bool
	to := hammer(t, c, k, 10, 40, []string{"r1", "r2"}, func(w, i int) {
		if w != 0 || i%8 != 0 {
			return
		}
		// Rotate through failure modes while the others keep going.
		switch (i / 8) % 4 {
		case 0:
			c.net.Partition([]string{"n4:1"}, []string{"n0:1", "n1:1", "n2:1", "n3:1"})
		case 1:
			c.net.Heal()
			c.net.Crash("n3:1")
		case 2:
			c.net.Restart("n3:1")
			c.restart(3) // forgets its table; must quarantine
		case 3:
			c.net.Heal()
			c.net.Delay("n1:1", "n2:1", 40*time.Millisecond)
			fired.Store(true)
		}
	})
	c.net.Heal()
	k.verify(t)
	t.Logf("%d critical sections, %d timeouts", k.entries.Load(), to)
	if k.entries.Load() == 0 {
		t.Error("no progress at all under faults")
	}
	if !fired.Load() {
		t.Error("fault schedule did not run")
	}
}

func TestSharedReadersExcludeWriter(t *testing.T) {
	c := newTestCluster(t, 3, 2*time.Second)
	time.Sleep(c.ttl + 50*time.Millisecond)
	ctx := context.Background()
	u1, err := c.lockers[0].RLock(ctx, "b", "o")
	if err != nil {
		t.Fatal(err)
	}
	u2, err := c.lockers[1].RLock(ctx, "b", "o")
	if err != nil {
		t.Fatalf("a second reader was refused: %v", err)
	}
	short, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
	defer cancel()
	if _, err := c.lockers[2].Lock(short, "b", "o"); err == nil {
		t.Fatal("a writer got in alongside readers")
	}
	u1()
	short2, cancel2 := context.WithTimeout(ctx, 150*time.Millisecond)
	defer cancel2()
	if _, err := c.lockers[2].Lock(short2, "b", "o"); err == nil {
		t.Fatal("a writer got in while one reader remained")
	}
	u2()
	uw, err := c.lockers[2].Lock(ctx, "b", "o")
	if err != nil {
		t.Fatalf("writer after all readers left: %v", err)
	}
	uw()
	uw() // idempotent
	// Object and bucket locks are independent names.
	ub, _ := c.lockers[0].Lock(ctx, "b", "")
	uo, err := c.lockers[1].Lock(ctx, "b", "o")
	if err != nil {
		t.Errorf("bucket lock blocked an object lock: %v", err)
	} else {
		uo()
	}
	ub()
}

func TestMinorityCannotLock(t *testing.T) {
	c := newTestCluster(t, 5, 2*time.Second)
	time.Sleep(c.ttl + 50*time.Millisecond)
	c.net.Partition([]string{"n0:1", "n1:1"}, []string{"n2:1", "n3:1", "n4:1"})
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := c.lockers[0].Lock(ctx, "b", "o"); !errors.Is(err, storage.ErrLockTimeout) {
		t.Errorf("minority lock = %v, want ErrLockTimeout", err)
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	u, err := c.lockers[3].Lock(ctx2, "b", "o")
	if err != nil {
		t.Fatalf("majority could not lock: %v", err)
	}
	u()
	// No stray grants from the minority's failed attempt remain.
	c.net.Heal()
	time.Sleep(50 * time.Millisecond)
	for i, s := range c.servers {
		if h := s.Held(); h != 0 {
			t.Errorf("node %d holds %d leases after a failed acquisition", i, h)
		}
	}
}

func TestEvenSplitIsUnavailable(t *testing.T) {
	c := newTestCluster(t, 4, 2*time.Second)
	time.Sleep(c.ttl + 50*time.Millisecond)
	c.net.Partition([]string{"n0:1", "n1:1"}, []string{"n2:1", "n3:1"})
	for i := range c.lockers {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		if u, err := c.lockers[i].Lock(ctx, "b", "o"); err == nil {
			u()
			t.Errorf("node %d locked from half of an even split", i)
		}
		cancel()
	}
}

// TestLeaseLossIsSignalledBeforeCompetitorWins pins the property the
// compare-and-set commit relies on to be rare: a holder cut off from its
// quorum is told before anyone else can have won.
func TestLeaseLossIsSignalledBeforeCompetitorWins(t *testing.T) {
	c := newTestCluster(t, 3, 600*time.Millisecond)
	time.Sleep(c.ttl + 50*time.Millisecond)
	var lostAt atomic.Int64
	c.lost = func(node int, res string) {
		if node == 0 {
			lostAt.CompareAndSwap(0, time.Now().UnixNano())
		}
	}
	ctx := context.Background()
	u, err := c.lockers[0].Lock(ctx, "b", "o")
	if err != nil {
		t.Fatal(err)
	}
	defer u()
	c.net.Partition([]string{"n0:1"}, []string{"n1:1", "n2:1"})

	long, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	u2, err := c.lockers[1].Lock(long, "b", "o")
	if err != nil {
		t.Fatalf("the competitor never got in after the holder was cut off: %v", err)
	}
	wonAt := time.Now().UnixNano()
	u2()
	if lostAt.Load() == 0 {
		t.Fatal("the cut-off holder was never told it lost the lock")
	}
	if lostAt.Load() > wonAt {
		t.Errorf("the competitor won %v before the holder learned it lost", time.Duration(lostAt.Load()-wonAt))
	}
}

func TestLeaseOfCrashedHolderExpires(t *testing.T) {
	c := newTestCluster(t, 3, 300*time.Millisecond)
	time.Sleep(c.ttl + 50*time.Millisecond)
	// Take the lock without a refresher, as a crashed process would leave it.
	uid := newUID()
	got := 0
	for _, s := range c.servers {
		if s.Acquire(resource("b", "o"), uid, true) {
			got++
		}
	}
	if got != 3 {
		t.Fatalf("setup granted %d", got)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := time.Now()
	u, err := c.lockers[1].Lock(ctx, "b", "o")
	if err != nil {
		t.Fatalf("a dead holder's lease never expired: %v", err)
	}
	u()
	if d := time.Since(start); d < c.ttl/2 {
		t.Errorf("got the lock after %v, before the lease could have lapsed", d)
	}
}

func TestRestartedServerQuarantines(t *testing.T) {
	c := newTestCluster(t, 3, 300*time.Millisecond)
	time.Sleep(c.ttl + 50*time.Millisecond)
	if c.servers[2].Quarantined() {
		t.Fatal("still quarantined after a full TTL")
	}
	c.restart(2)
	if !c.servers[2].Quarantined() {
		t.Fatal("a restarted server is granting immediately")
	}
	if c.servers[2].Acquire("x", "u", true) {
		t.Error("granted during quarantine")
	}
	// The other two still form a quorum of 3.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	u, err := c.lockers[0].Lock(ctx, "b", "o")
	if err != nil {
		t.Fatalf("cluster unavailable with one node quarantined: %v", err)
	}
	u()
	time.Sleep(c.ttl + 50*time.Millisecond)
	if !c.servers[2].Acquire("x", "u", true) {
		t.Error("still refusing after the quarantine")
	}
}

func TestLocksSurviveRefreshWhileHeld(t *testing.T) {
	c := newTestCluster(t, 3, 300*time.Millisecond)
	time.Sleep(c.ttl + 50*time.Millisecond)
	ctx := context.Background()
	u, err := c.lockers[0].Lock(ctx, "b", "o")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(4 * c.ttl) // far past one lease
	short, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	if _, err := c.lockers[1].Lock(short, "b", "o"); err == nil {
		t.Fatal("a held lock lapsed although it was being refreshed")
	}
	u()
}
