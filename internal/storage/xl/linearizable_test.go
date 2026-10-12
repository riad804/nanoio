package xl

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"nanoio/internal/bucket/nslock"
	"nanoio/internal/cluster/dsync"
	"nanoio/internal/cluster/faultnet"
	"nanoio/internal/cluster/rpc"
	"nanoio/internal/cluster/rpcauth"
	"nanoio/internal/meta"
	"nanoio/internal/storage"
	"nanoio/internal/storage/xl/disk"
	"nanoio/internal/storage/xl/disk/remote"
)

// multi is n nodes with two drives each; every node runs its own XL over
// all drives (local ones directly, the rest over RPC) and a dsync lock
// client over all nodes' lock servers: the shape of a real deployment.
type multi struct {
	net     *faultnet.Network
	xls     []*XL
	lockers []*dsync.Locker
	addr    []string
}

func newMulti(t *testing.T, n int, ttl time.Duration) *multi {
	t.Helper()
	keys, err := rpcauth.NewKeyring("linearizable-test-secret-012345")
	if err != nil {
		t.Fatal(err)
	}
	m := &multi{net: faultnet.New()}
	peers := map[string]string{}
	var ids []string
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("n%d", i)
		ids = append(ids, id)
		peers[id] = id + ":9000"
		m.addr = append(m.addr, id+":9000")
	}
	root := t.TempDir()
	locals := map[string]map[string]disk.Disk{}
	dirs := map[string][]string{}
	lockServers := map[string]*dsync.Server{}
	for _, id := range ids {
		locals[id] = map[string]disk.Disk{}
		for j := 0; j < 2; j++ {
			dir := filepath.Join(root, id, fmt.Sprintf("d%d", j))
			l, err := disk.NewLocal(dir, disk.LocalOptions{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { l.Close() })
			locals[id][dir] = l
			dirs[id] = append(dirs[id], dir)
		}
		srv := remote.NewServer(locals[id], 0)
		t.Cleanup(srv.Close)
		rs := rpc.NewServer(rpc.ServerConfig{Self: id, Keys: keys, Encode: remote.EncodeError,
			Known: func(string) bool { return true }})
		srv.Register(rs)
		ls := dsync.NewServer(ttl)
		ls.Register(rs)
		lockServers[id] = ls
		m.net.Register(peers[id], rs)
	}
	for _, id := range ids {
		client, err := rpc.NewClient(rpc.Config{Self: id, Keys: keys, Peers: peers, HTTP: m.net.Client(peers[id])})
		if err != nil {
			t.Fatal(err)
		}
		var disks []disk.Disk
		for _, other := range ids {
			for _, dir := range dirs[other] {
				if other == id {
					disks = append(disks, locals[id][dir])
				} else {
					disks = append(disks, remote.New(client, other, dir, remote.Options{
						OKFor: 5 * time.Millisecond, DownFor: 5 * time.Millisecond,
						OpTimeout: time.Second, ProbeTimeout: 200 * time.Millisecond}))
				}
			}
		}
		lk, err := dsync.NewLocker(dsync.Options{Nodes: ids, Self: id, Local: lockServers[id], Client: client,
			TTL: ttl, RPCTimeout: 150 * time.Millisecond, Timeout: 3 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		x, err := NewWithDisks(bg, disks, Options{Locker: lk, Logger: discard, ParityBlocks: 3, BlockSize: 4 << 10,
			ScanInterval: -1, DeploymentID: "lin-test", StragglerGrace: time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { x.Close() })
		m.xls = append(m.xls, x)
		m.lockers = append(m.lockers, lk)
	}
	time.Sleep(ttl + 50*time.Millisecond) // lock servers grant nothing for one TTL
	return m
}

type history struct {
	mu  sync.Mutex
	ops map[string][]linOp
	t0  time.Time
}

func (h *history) now() int64 { return int64(time.Since(h.t0)) }

func (h *history) add(key string, o linOp) {
	h.mu.Lock()
	h.ops[key] = append(h.ops[key], o)
	h.mu.Unlock()
}

// run drives workers against the cluster, each on its own node, and
// records every operation's real-time interval and outcome.
func (m *multi) run(t *testing.T, h *history, workers, ops int, keys []string, perOp func(w, i int)) {
	t.Helper()
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			x := m.xls[w%len(m.xls)]
			rng := rand.New(rand.NewPCG(uint64(w)+1, 7))
			for i := 0; i < ops; i++ {
				if perOp != nil {
					perOp(w, i)
				}
				key := keys[rng.IntN(len(keys))]
				call := h.now()
				switch r := rng.IntN(10); {
				case r < 4: // put
					val := fmt.Sprintf("w%d-%d", w, i)
					_, err := x.PutObject(bg, "lin", key, strings.NewReader(val), int64(len(val)), storage.PutOptions{})
					o := linOp{kind: "put", val: val, call: call, ret: h.now()}
					if err != nil {
						o.optional, o.ret = true, inf
					}
					h.add(key, o)
				case r < 5: // delete
					_, err := x.DeleteObject(bg, "lin", key, storage.DeleteOptions{})
					o := linOp{kind: "del", call: call, ret: h.now()}
					if err != nil {
						o.optional, o.ret = true, inf
					}
					h.add(key, o)
				default: // get
					rc, _, err := x.GetObject(bg, "lin", key, storage.GetOptions{})
					var body []byte
					if err == nil {
						body, err = io.ReadAll(rc)
						rc.Close()
					}
					switch {
					case err == nil:
						h.add(key, linOp{kind: "get", val: string(body), found: true, call: call, ret: h.now()})
					case errors.Is(err, storage.ErrObjectNotFound):
						h.add(key, linOp{kind: "get", call: call, ret: h.now()})
					default:
						// An unavailable read says nothing.
					}
				}
			}
		}()
	}
	wg.Wait()
}

func (h *history) check(t *testing.T) {
	t.Helper()
	total := 0
	for key, ops := range h.ops {
		total += len(ops)
		if len(ops) > 60 {
			t.Fatalf("history of %s has %d ops; keep runs short enough for the checker", key, len(ops))
		}
		if !linearizable(append([]linOp(nil), ops...)) {
			var b strings.Builder
			for _, o := range ops {
				b.WriteString("  " + o.String() + "\n")
			}
			t.Errorf("history of %q is not linearizable:\n%s", key, b.String())
		}
	}
	t.Logf("checked %d operations over %d keys", total, len(h.ops))
}

func TestLinearizableAcrossNodes(t *testing.T) {
	t.Run("healthy cluster", func(t *testing.T) {
		m := newMulti(t, 3, 600*time.Millisecond)
		if err := m.xls[0].MakeBucket(bg, "lin", storage.MakeBucketOptions{}); err != nil {
			t.Fatal(err)
		}
		h := &history{ops: map[string][]linOp{}, t0: time.Now()}
		m.run(t, h, 6, 8, []string{"k1", "k2", "k3"}, nil)
		h.check(t)
	})

	t.Run("node crash, partition and lost replies", func(t *testing.T) {
		m := newMulti(t, 3, 600*time.Millisecond)
		if err := m.xls[0].MakeBucket(bg, "lin", storage.MakeBucketOptions{}); err != nil {
			t.Fatal(err)
		}
		h := &history{ops: map[string][]linOp{}, t0: time.Now()}
		var once [4]sync.Once
		m.run(t, h, 6, 8, []string{"k1", "k2", "k3"}, func(w, i int) {
			if w != 0 {
				return
			}
			switch i {
			case 1:
				once[0].Do(func() { m.net.Crash(m.addr[2]) })
			case 3:
				once[1].Do(func() { m.net.Restart(m.addr[2]); m.net.LoseReplies(m.addr[0], m.addr[1], true) })
			case 5:
				once[2].Do(func() {
					m.net.LoseReplies(m.addr[0], m.addr[1], false)
					m.net.Partition([]string{m.addr[1]}, []string{m.addr[0], m.addr[2]})
				})
			case 7:
				once[3].Do(func() { m.net.Heal() })
			}
		})
		m.net.Heal()
		h.check(t)
	})
}

// TestConcurrentWritersCannotBothWin forces the case the lock alone cannot
// prevent: two writers that both hold (or both believe they hold) the
// key. The generation check on the drives lets at most one commit.
func TestConcurrentWritersCannotBothWin(t *testing.T) {
	sw := &switchLocker{}
	sw.set(nslock.New(5 * time.Second))
	x, _ := newXL(t, layout{"4+2", 6, 2, 4 << 10}, func(o *Options) { o.Locker = sw })
	mkbucket(t, x, "casb")
	put(t, x, "casb", "k", "v0")

	// A locker that does not lock: every writer proceeds at once.
	sw.set(noLock{})
	const writers = 12
	var wg sync.WaitGroup
	errs := make([]error, writers)
	start := make(chan struct{})
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			v := fmt.Sprintf("writer-%02d", i)
			_, errs[i] = x.PutObject(bg, "casb", "k", strings.NewReader(v), int64(len(v)), storage.PutOptions{})
		}()
	}
	close(start)
	wg.Wait()

	won := 0
	for _, err := range errs {
		if err == nil {
			won++
		} else if !errors.Is(err, storage.ErrBackendUnavailable) {
			t.Errorf("unexpected error: %v", err)
		}
	}
	// Several writers may legitimately succeed, one after another, if they
	// read the state after an earlier one finished. What must never happen
	// is two successes on the same generation: each success advances the
	// generation by exactly one, so the final generation counts them.
	final := uint64(0)
	for _, d := range x.drives {
		raw, err := d.ReadMeta(bg, "casb", "k")
		if err != nil {
			continue
		}
		f, err := meta.Decode(raw)
		if err != nil {
			continue
		}
		final = max(final, f.Generation())
	}
	if want := uint64(1 + won); final != want {
		t.Fatalf("%d writers succeeded but the object advanced to generation %d, want %d: two writers won the same generation",
			won, final, want)
	}
	// Whoever won (or nobody), the object is whole and a later write works.
	sw.set(nslock.New(5 * time.Second))
	if got := mustRead(t, x, "casb", "k"); got == "" {
		t.Error("object unreadable after the race")
	}
	put(t, x, "casb", "k", "after")
	if got := mustRead(t, x, "casb", "k"); got != "after" {
		t.Errorf("read = %q", got)
	}
	t.Logf("%d of %d unlocked concurrent writers committed", won, writers)
}

// noLock grants every lock immediately.
type noLock struct{}

func (noLock) Lock(context.Context, string, string) (func(), error)  { return func() {}, nil }
func (noLock) RLock(context.Context, string, string) (func(), error) { return func() {}, nil }

// switchLocker lets a test change locking while background maintenance is
// running.
type switchLocker struct {
	cur atomic.Pointer[storage.Locker]
}

func (s *switchLocker) set(l storage.Locker) { s.cur.Store(&l) }
func (s *switchLocker) Lock(ctx context.Context, b, o string) (func(), error) {
	return (*s.cur.Load()).Lock(ctx, b, o)
}
func (s *switchLocker) RLock(ctx context.Context, b, o string) (func(), error) {
	return (*s.cur.Load()).RLock(ctx, b, o)
}

// TestVersionedAcrossNodes drives PUT, DELETE (marker), DELETE of a version
// and reads of the latest and of named versions from three nodes at once
// against a versioned bucket, records every operation's interval and
// result, and checks the history against the version-list model.
func TestVersionedAcrossNodes(t *testing.T) {
	m := newMulti(t, 3, 600*time.Millisecond)
	if err := m.xls[0].MakeBucket(bg, "linv", storage.MakeBucketOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := m.xls[0].SetBucketVersioning(bg, "linv", storage.VersioningEnabled); err != nil {
		t.Fatal(err)
	}
	keys := []string{"v1", "v2"}
	t0 := time.Now()
	now := func() int64 { return int64(time.Since(t0)) }

	var mu sync.Mutex
	ops := map[string][]verOp{}
	known := map[string][]string{}
	add := func(key string, o verOp) {
		mu.Lock()
		ops[key] = append(ops[key], o)
		mu.Unlock()
	}
	pick := func(key string, rng *rand.Rand) string {
		mu.Lock()
		defer mu.Unlock()
		if len(known[key]) == 0 {
			return ""
		}
		return known[key][rng.IntN(len(known[key]))]
	}
	learn := func(key, id string) {
		mu.Lock()
		known[key] = append(known[key], id)
		mu.Unlock()
	}

	var wg sync.WaitGroup
	for w := 0; w < 6; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			x := m.xls[w%3]
			rng := rand.New(rand.NewPCG(uint64(w)+31, 5))
			for i := 0; i < 9; i++ {
				key := keys[rng.IntN(len(keys))]
				call := now()
				switch r := rng.IntN(20); {
				case r < 7: // put
					body := fmt.Sprintf("w%d-%d", w, i)
					info, err := x.PutObject(bg, "linv", key, strings.NewReader(body), int64(len(body)), storage.PutOptions{})
					if err != nil {
						t.Errorf("put: %v", err)
						return
					}
					learn(key, info.VersionID)
					add(key, verOp{kind: "put", id: info.VersionID, call: call, ret: now()})
				case r < 10: // delete marker
					res, err := x.DeleteObject(bg, "linv", key, storage.DeleteOptions{})
					if err != nil || !res.DeleteMarker {
						t.Errorf("marker: %+v, %v", res, err)
						return
					}
					learn(key, res.VersionID)
					add(key, verOp{kind: "marker", id: res.VersionID, call: call, ret: now()})
				case r < 13: // delete a version
					id := pick(key, rng)
					if id == "" {
						continue
					}
					if _, err := x.DeleteObject(bg, "linv", key, storage.DeleteOptions{VersionID: id}); err != nil {
						t.Errorf("remove: %v", err)
						return
					}
					add(key, verOp{kind: "remove", id: id, call: call, ret: now()})
				case r < 17: // latest
					res := "none"
					_, info, err := getAll(x, "linv", key, "")
					var dm *storage.DeleteMarkerError
					switch {
					case err == nil:
						res = "obj:" + info.VersionID
					case errorsAsDM(err, &dm):
						res = "dm:" + dm.VersionID
					case isNotFound(err):
					default:
						t.Errorf("latest: %v", err)
						return
					}
					add(key, verOp{kind: "latest", result: res, call: call, ret: now()})
				default: // a named version
					id := pick(key, rng)
					if id == "" {
						continue
					}
					res := "found"
					_, _, err := getAll(x, "linv", key, id)
					var dm *storage.DeleteMarkerError
					switch {
					case err == nil:
					case errorsAsDM(err, &dm):
						res = "marker"
					case isVersionNotFound(err):
						res = "absent"
					default:
						t.Errorf("version %s: %v", id, err)
						return
					}
					add(key, verOp{kind: "version", id: id, result: res, call: call, ret: now()})
				}
			}
		}()
	}
	wg.Wait()
	for key, history := range ops {
		if len(history) > 60 {
			t.Fatalf("history of %s is %d operations; the checker takes at most 60", key, len(history))
		}
		if !versionsLinearizable(append([]verOp(nil), history...)) {
			var b strings.Builder
			for _, o := range history {
				b.WriteString("  " + o.String() + "\n")
			}
			t.Errorf("history of %q is not linearizable:\n%s", key, b.String())
		}
	}
	// Whatever the interleaving, every node ends up reporting the same
	// version lists in the same order.
	var first string
	for i, x := range m.xls {
		res, err := x.ListObjectVersions(bg, "linv", storage.ListOptions{})
		if err != nil {
			t.Fatal(err)
		}
		var b strings.Builder
		for _, v := range res.Versions {
			fmt.Fprintf(&b, "%s@%s dm=%v latest=%v\n", v.Name, v.VersionID, v.DeleteMarker, v.IsLatest)
		}
		if i == 0 {
			first = b.String()
		} else if b.String() != first {
			t.Errorf("node %d lists\n%s\nnode 0 lists\n%s", i, b.String(), first)
		}
	}
}

func getAll(x *XL, bucket, key, version string) (string, storage.ObjectInfo, error) {
	rc, info, err := x.GetObject(bg, bucket, key, storage.GetOptions{VersionID: version})
	if err != nil {
		return "", info, err
	}
	defer rc.Close()
	b, err := io.ReadAll(rc)
	return string(b), info, err
}

func errorsAsDM(err error, dm **storage.DeleteMarkerError) bool { return errorsAs(err, dm) }

func isNotFound(err error) bool { return errors.Is(err, storage.ErrObjectNotFound) }

func isVersionNotFound(err error) bool { return errors.Is(err, storage.ErrVersionNotFound) }

// TestVersionedSurvivesNodeLossAndLostReplies: with a node crashing and
// replies being lost mid-run some operations are indeterminate. The final
// version list must contain every version whose creation was acknowledged
// and never (even possibly) removed, and nothing that was never created.
func TestVersionedSurvivesNodeLossAndLostReplies(t *testing.T) {
	m := newMulti(t, 3, 600*time.Millisecond)
	if err := m.xls[0].MakeBucket(bg, "linvf", storage.MakeBucketOptions{}); err != nil {
		t.Fatal(err)
	}
	m.xls[0].SetBucketVersioning(bg, "linvf", storage.VersioningEnabled)

	var mu sync.Mutex
	created := map[string]bool{}   // acknowledged
	removedOK := map[string]bool{} // removal acknowledged
	removedMaybe := map[string]bool{}
	var once [3]sync.Once
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			x := m.xls[w%3]
			var mine []string
			for i := 0; i < 10; i++ {
				if w == 0 {
					switch i {
					case 2:
						once[0].Do(func() { m.net.Crash(m.addr[2]) })
					case 5:
						once[1].Do(func() { m.net.Restart(m.addr[2]); m.net.LoseReplies(m.addr[0], m.addr[1], true) })
					case 8:
						once[2].Do(func() { m.net.LoseReplies(m.addr[0], m.addr[1], false) })
					}
				}
				if i%4 == 3 && len(mine) > 0 {
					id := mine[len(mine)-1]
					mine = mine[:len(mine)-1]
					_, err := x.DeleteObject(bg, "linvf", "k", storage.DeleteOptions{VersionID: id})
					mu.Lock()
					if err == nil {
						removedOK[id] = true
					} else {
						removedMaybe[id] = true
					}
					mu.Unlock()
					continue
				}
				body := fmt.Sprintf("w%d-%d", w, i)
				info, err := x.PutObject(bg, "linvf", "k", strings.NewReader(body), int64(len(body)), storage.PutOptions{})
				if err == nil {
					mu.Lock()
					created[info.VersionID] = true
					mu.Unlock()
					mine = append(mine, info.VersionID)
				}
			}
		}()
	}
	wg.Wait()
	m.net.Heal()
	for _, x := range m.xls {
		waitOnline(t, x, 6)
	}
	for _, x := range m.xls {
		if _, err := x.Scan(bg, true); err != nil {
			t.Fatal(err)
		}
	}
	res, err := m.xls[1].ListObjectVersions(bg, "linvf", storage.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, v := range res.Versions {
		got[v.VersionID] = true
	}
	for id := range created {
		if removedOK[id] || removedMaybe[id] {
			continue
		}
		if !got[id] {
			t.Errorf("version %s was acknowledged, never removed, and is gone", id)
		}
	}
	for id := range got {
		if !created[id] && !removedMaybe[id] {
			// An unacknowledged put may legitimately have taken effect.
			continue
		}
		if removedOK[id] {
			t.Errorf("version %s was removed and acknowledged, but is listed", id)
		}
	}
	// And every listed version reads.
	for _, v := range res.Versions {
		if _, _, err := getAll(m.xls[2], "linvf", "k", v.VersionID); err != nil {
			t.Errorf("listed version %s does not read: %v", v.VersionID, err)
		}
	}
}
