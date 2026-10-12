package remote_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"nanoio/internal/cluster/faultnet"
	"nanoio/internal/cluster/rpc"
	"nanoio/internal/cluster/rpcauth"
	"nanoio/internal/meta"
	"nanoio/internal/storage/xl/disk"
	"nanoio/internal/storage/xl/disk/disktest"
	"nanoio/internal/storage/xl/disk/remote"
)

const secret = "test-cluster-secret-0123456789"

// node is one server: local drives behind an RPC server on the network.
type node struct {
	id, addr string
	disks    map[string]disk.Disk
	srv      *remote.Server
	rpc      *rpc.Server
}

type env struct {
	net   *faultnet.Network
	keys  *rpcauth.Keyring
	nodes map[string]*node
	peers map[string]string
}

func newEnv(t *testing.T, ids ...string) *env {
	t.Helper()
	keys, err := rpcauth.NewKeyring(secret)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{net: faultnet.New(), keys: keys, nodes: map[string]*node{}, peers: map[string]string{}}
	for _, id := range ids {
		e.peers[id] = id + ":9000"
	}
	for _, id := range ids {
		n := &node{id: id, addr: e.peers[id], disks: map[string]disk.Disk{}}
		n.rpc = rpc.NewServer(rpc.ServerConfig{Self: id, Keys: keys, Encode: remote.EncodeError,
			Known: func(string) bool { return true }})
		e.net.Register(n.addr, n.rpc)
		e.nodes[id] = n
	}
	return e
}

// addDrive formats a local drive on node id and serves it.
func (e *env) addDrive(t *testing.T, id, name string) *disk.Local {
	t.Helper()
	n := e.nodes[id]
	l, err := disk.NewLocal(filepath.Join(t.TempDir(), name), disk.LocalOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Open(bg, true); !errors.Is(err, disk.ErrUnformatted) {
		t.Fatal(err)
	}
	if err := l.WriteFormat(bg, &disk.Format{Format: disk.FormatVersion, DeploymentID: "dep", DataBlocks: 2, ParityBlocks: 1}); err != nil {
		t.Fatal(err)
	}
	n.disks[name] = l
	if n.srv != nil {
		n.srv.Close()
	}
	n.srv = remote.NewServer(n.disks, 0)
	n.srv.Register(n.rpc)
	t.Cleanup(func() { l.Close() })
	return l
}

func (e *env) client(t *testing.T, from string) *rpc.Client {
	t.Helper()
	c, err := rpc.NewClient(rpc.Config{Self: from, Keys: e.keys, Peers: e.peers, HTTP: e.net.Client(e.peers[from])})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

var bg = context.Background()

var fast = remote.Options{OKFor: time.Millisecond, DownFor: time.Millisecond, OpTimeout: 5 * time.Second, ChunkSize: 100}

// TestRemoteContract runs the same contract suite as the local drive, with
// a small chunk size so staged files cross several append RPCs.
func TestRemoteContract(t *testing.T) {
	disktest.Run(t, func(t *testing.T) (disk.Disk, func()) {
		e := newEnv(t, "n1", "n2")
		l := e.addDrive(t, "n2", "d0")
		r := remote.New(e.client(t, "n1"), "n2", "d0", fast)
		return r, func() { l.Close(); time.Sleep(10 * time.Millisecond) } // outlast the health window
	})
}

func TestRemoteRoundTripAndAuth(t *testing.T) {
	e := newEnv(t, "n1", "n2")
	e.addDrive(t, "n2", "d0")
	r := remote.New(e.client(t, "n1"), "n2", "d0", fast)

	if _, err := r.MakeBucket(bg, "bucket", time.Now()); err != nil {
		t.Fatal(err)
	}
	if exists, _, err := r.StatBucket(bg, "bucket"); err != nil || !exists {
		t.Fatalf("StatBucket = %v, %v", exists, err)
	}

	t.Run("a different secret is refused", func(t *testing.T) {
		other, _ := rpcauth.NewKeyring("some-other-cluster-secret-xx")
		c, _ := rpc.NewClient(rpc.Config{Self: "n1", Keys: other, Peers: e.peers, HTTP: e.net.Client(e.peers["n1"])})
		bad := remote.New(c, "n2", "d0", fast)
		if bad.Ready(bg) {
			t.Error("a node with the wrong secret was served")
		}
		if _, err := bad.ListBuckets(bg); err == nil {
			t.Error("ListBuckets succeeded with the wrong secret")
		}
	})
	t.Run("an unknown drive is offline, not a path", func(t *testing.T) {
		ghost := remote.New(e.client(t, "n1"), "n2", "../../etc", fast)
		if _, err := ghost.ListBuckets(bg); !errors.Is(err, disk.ErrOffline) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("a replayed request is rejected", func(t *testing.T) {
		var captured *http.Request
		var body []byte
		spy := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			b := new(bytes.Buffer)
			b.ReadFrom(req.Body)
			body = b.Bytes()
			req.Body = readCloser(body)
			captured = req.Clone(req.Context())
			return e.net.Transport("n1:9000").RoundTrip(req)
		})}
		c, _ := rpc.NewClient(rpc.Config{Self: "n1", Keys: e.keys, Peers: e.peers, HTTP: spy})
		if _, err := remote.New(c, "n2", "d0", fast).ListBuckets(bg); err != nil {
			t.Fatal(err)
		}
		captured = captured.WithContext(context.Background())
		captured.Body = readCloser(body)
		resp, err := e.net.Transport("n1:9000").RoundTrip(captured)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("replay got status %d, want 401", resp.StatusCode)
		}
	})
}

// TestFaults is the partition / delay / crash suite increment 3 is gated on.
func TestFaults(t *testing.T) {
	t.Run("partition makes the drive offline and heals", func(t *testing.T) {
		e := newEnv(t, "n1", "n2")
		e.addDrive(t, "n2", "d0")
		r := remote.New(e.client(t, "n1"), "n2", "d0", fast)
		if !r.Ready(bg) {
			t.Fatal("not ready")
		}
		e.net.Partition([]string{"n1:9000"}, []string{"n2:9000"})
		time.Sleep(5 * time.Millisecond)
		if r.Ready(bg) {
			t.Error("a partitioned drive reports ready")
		}
		if _, err := r.ListBuckets(bg); !errors.Is(err, disk.ErrOffline) {
			t.Errorf("err = %v, want ErrOffline", err)
		}
		e.net.Heal()
		time.Sleep(5 * time.Millisecond)
		if !r.Ready(bg) {
			t.Error("the drive did not come back after the partition healed")
		}
	})

	t.Run("a slow link hits the operation deadline", func(t *testing.T) {
		e := newEnv(t, "n1", "n2")
		e.addDrive(t, "n2", "d0")
		opt := fast
		opt.OpTimeout = 50 * time.Millisecond
		r := remote.New(e.client(t, "n1"), "n2", "d0", opt)
		e.net.Delay("n1:9000", "n2:9000", 2*time.Second)
		start := time.Now()
		_, err := r.ListBuckets(bg)
		if !errors.Is(err, disk.ErrOffline) {
			t.Errorf("err = %v", err)
		}
		if d := time.Since(start); d > time.Second {
			t.Errorf("a slow peer held the caller for %v", d)
		}
	})

	t.Run("node crash mid-upload leaves nothing half-visible", func(t *testing.T) {
		e := newEnv(t, "n1", "n2")
		l := e.addDrive(t, "n2", "d0")
		r := remote.New(e.client(t, "n1"), "n2", "d0", fast)
		r.MakeBucket(bg, "bucket", time.Now())
		w, err := r.CreateStageFile(bg, "stage", "dd/part.1")
		if err != nil {
			t.Fatal(err)
		}
		w.Write(bytes.Repeat([]byte("x"), 1000)) // several appends
		e.net.Crash("n2:9000")
		if err := w.Close(); err == nil {
			t.Error("Close succeeded against a crashed node")
		}
		e.net.Restart("n2:9000")
		// The object never committed.
		if _, err := l.ReadMeta(bg, "bucket", "obj"); !errors.Is(err, disk.ErrNotFound) {
			t.Errorf("object visible: %v", err)
		}
	})

	t.Run("lost commit reply: indeterminate, then converged by rollback or scan", func(t *testing.T) {
		e := newEnv(t, "n1", "n2")
		l := e.addDrive(t, "n2", "d0")
		r := remote.New(e.client(t, "n1"), "n2", "d0", fast)
		r.MakeBucket(bg, "bucket", time.Now())
		w, _ := r.CreateStageFile(bg, "stage", ".nanoio-data-v1/part.1")
		w.Write([]byte("shard"))
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		e.net.LoseReplies("n1:9000", "n2:9000", true)
		_, err := r.CommitObject(bg, disk.CommitRequest{Bucket: "bucket", Object: "obj", StageID: "stage",
			DataDir: ".nanoio-data-v1", Version: meta.Version{Type: meta.TypeObject, ModTime: time.Now(),
				Size: 5, ETag: "e", DataDir: ".nanoio-data-v1", Erasure: &meta.Erasure{Algorithm: "reedsolomon", DataBlocks: 2, ParityBlocks: 1, BlockSize: 64, Distribution: []int{0, 1, 2}}}})
		if err == nil {
			t.Fatal("the caller saw success though the reply was lost")
		}
		e.net.LoseReplies("n1:9000", "n2:9000", false)
		// The drive did commit: the caller cannot know, which is the whole
		// point. What it must be able to do is read the truth afterwards.
		if _, err := l.ReadMeta(bg, "bucket", "obj"); err != nil {
			t.Fatalf("drive state after a lost reply: %v", err)
		}
		if _, err := r.ReadMeta(bg, "bucket", "obj"); err != nil {
			t.Errorf("remote read of the truth: %v", err)
		}
	})

	t.Run("client crash: server reclaims writers, pins and stages after the lease", func(t *testing.T) {
		e := newEnv(t, "n1", "n2")
		n := e.nodes["n2"]
		l, err := disk.NewLocal(filepath.Join(t.TempDir(), "d0"), disk.LocalOptions{})
		if err != nil {
			t.Fatal(err)
		}
		l.Open(bg, true)
		l.WriteFormat(bg, &disk.Format{Format: disk.FormatVersion, DeploymentID: "dep"})
		defer l.Close()
		n.disks["d0"] = l
		n.srv = remote.NewServer(n.disks, 100*time.Millisecond)
		n.srv.Register(n.rpc)
		defer n.srv.Close()
		r := remote.New(e.client(t, "n1"), "n2", "d0", fast)
		w, err := r.CreateStageFile(bg, "leaky", "f")
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte("abandoned"))
		// The client "crashes": nothing further is sent. The lease expires.
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if w2, err := l.CreateStageFile(bg, "leaky", "f"); err == nil {
				w2.Abort()
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal("an abandoned staged file was never reclaimed")
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func readCloser(b []byte) *nopCloser { return &nopCloser{bytes.NewReader(b)} }

type nopCloser struct{ *bytes.Reader }

func (nopCloser) Close() error { return nil }

func TestCircuitBreaker(t *testing.T) {
	e := newEnv(t, "n1", "n2")
	e.addDrive(t, "n2", "d0")
	opt := fast
	opt.DownFor = 150 * time.Millisecond
	opt.BreakerThreshold = 2
	opt.BreakerMax = time.Second
	r := remote.New(e.client(t, "n1"), "n2", "d0", opt)
	addr := "n2:9000"
	if _, err := r.ListBuckets(bg); err != nil {
		t.Fatal(err)
	}
	if r.Breaker() != "closed" {
		t.Fatalf("breaker = %s", r.Breaker())
	}

	// A dead node is tried the threshold number of times, then not at all.
	e.net.Crash(addr)
	before := e.net.Attempts(addr)
	var refused int
	for i := 0; i < 8; i++ {
		_, err := r.ListBuckets(bg)
		if !errors.Is(err, disk.ErrOffline) {
			t.Fatalf("call %d = %v, want ErrOffline", i, err)
		}
		if strings.Contains(err.Error(), "circuit breaker") {
			refused++
		}
	}
	if sent := e.net.Attempts(addr) - before; sent != 2 {
		t.Errorf("%d requests reached the dead node, want exactly the threshold (2)", sent)
	}
	if refused != 6 {
		t.Errorf("%d calls refused by the breaker, want 6", refused)
	}
	if r.Breaker() != "open" {
		t.Errorf("breaker = %s, want open", r.Breaker())
	}
	if r.Ready(bg) {
		t.Error("a drive behind an open breaker reports ready")
	}

	// A failed half-open probe re-opens it for longer.
	time.Sleep(200 * time.Millisecond)
	if r.Breaker() != "half-open" {
		t.Fatalf("breaker = %s, want half-open", r.Breaker())
	}
	before = e.net.Attempts(addr)
	r.ListBuckets(bg)
	if sent := e.net.Attempts(addr) - before; sent != 1 {
		t.Errorf("half-open let %d probes through", sent)
	}
	if r.Breaker() != "open" {
		t.Errorf("breaker = %s after a failed probe", r.Breaker())
	}

	// Recovery: when the node is back, exactly one probe goes out while
	// others are refused, and its success closes the breaker.
	e.net.Restart(addr)
	e.net.Delay("n1:9000", addr, 300*time.Millisecond)
	time.Sleep(450 * time.Millisecond) // past the doubled interval
	before = e.net.Attempts(addr)
	var wg sync.WaitGroup
	var okCalls atomic.Int32
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := r.ListBuckets(bg); err == nil {
				okCalls.Add(1)
			}
		}()
	}
	wg.Wait()
	if sent := e.net.Attempts(addr) - before; sent != 1 {
		t.Errorf("%d concurrent calls reached the recovering node, want 1 probe", sent)
	}
	if okCalls.Load() != 1 {
		t.Errorf("%d calls succeeded, want just the probe", okCalls.Load())
	}
	if r.Breaker() != "closed" {
		t.Errorf("breaker = %s after a successful probe", r.Breaker())
	}
	e.net.Heal()
	if _, err := r.ListBuckets(bg); err != nil {
		t.Errorf("call after recovery: %v", err)
	}
}

// A caller that gives up says nothing about the drive.
func TestCallerCancellationDoesNotOpenTheBreaker(t *testing.T) {
	e := newEnv(t, "n1", "n2")
	e.addDrive(t, "n2", "d0")
	opt := fast
	opt.BreakerThreshold = 1
	r := remote.New(e.client(t, "n1"), "n2", "d0", opt)
	e.net.Delay("n1:9000", "n2:9000", 500*time.Millisecond)
	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithTimeout(bg, 30*time.Millisecond)
		_, err := r.ListBuckets(ctx)
		cancel()
		if !errors.Is(err, disk.ErrCanceled) {
			t.Fatalf("err = %v, want a cancellation", err)
		}
	}
	if r.Breaker() != "closed" {
		t.Errorf("breaker = %s after only caller-side cancellations", r.Breaker())
	}
}
