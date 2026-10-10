package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"nanoio/internal/cluster/faultnet"
	"nanoio/internal/storage"
)

const testSecret = "node-test-cluster-secret-0123456789"

type clusterEnv struct {
	t     *testing.T
	net   *faultnet.Network
	nodes []*Node
	ids   []string
	addr  map[string]string
}

// drive returns the spec of drive j of node i under root.
func drive(root string, id string, j int) string {
	return fmt.Sprintf("%s:%s", id, filepath.Join(root, id, fmt.Sprintf("d%d", j)))
}

// startCluster brings up len(ids) nodes concurrently over pools built by
// mkPools.
func startCluster(t *testing.T, root string, n int, mkPools func(ids []string) []PoolSpec, tweak func(*NodeConfig)) *clusterEnv {
	t.Helper()
	e := &clusterEnv{t: t, net: faultnet.New(), addr: map[string]string{}}
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("n%d", i)
		e.ids = append(e.ids, id)
		e.addr[id] = id + ":9000"
	}
	pools := mkPools(e.ids)
	for _, id := range e.ids {
		cfg := NodeConfig{
			Self: id, Peers: e.addr, Secrets: []string{testSecret}, Pools: pools,
			Parity: 2, BlockSize: 8 << 10, HTTPClient: e.net.Client(e.addr[id]),
			Logger: discard, LockTTL: 500 * time.Millisecond, LockTimeout: 3 * time.Second,
			ListTimeout: 2 * time.Second, Heartbeat: 100 * time.Millisecond, ScanInterval: -1,
			BucketSync: -1, StartupTimeout: 20 * time.Second, StragglerGrace: time.Minute,
		}
		if tweak != nil {
			tweak(&cfg)
		}
		nd, err := NewNode(cfg)
		if err != nil {
			t.Fatal(err)
		}
		e.net.Register(e.addr[id], nd.Handler())
		e.nodes = append(e.nodes, nd)
	}
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i, nd := range e.nodes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = nd.Open(context.Background())
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("node %d: %v", i, err)
		}
	}
	t.Cleanup(func() { e.close() })
	time.Sleep(600 * time.Millisecond) // lock quarantine
	return e
}

func (e *clusterEnv) close() {
	for _, nd := range e.nodes {
		nd.Close()
	}
	e.nodes = nil
}

// onePool is a single set over two drives of each node.
func onePool(root string) func(ids []string) []PoolSpec {
	return func(ids []string) []PoolSpec {
		var set []string
		for _, id := range ids {
			set = append(set, drive(root, id, 0), drive(root, id, 1))
		}
		return []PoolSpec{{Sets: [][]string{set}}}
	}
}

func httpGet(h http.Handler, path string) (int, string) {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
	b, _ := io.ReadAll(rec.Body)
	return rec.Code, string(b)
}

func TestClusterObjectsVisibleFromEveryNode(t *testing.T) {
	root := t.TempDir()
	e := startCluster(t, root, 3, onePool(root), nil)
	s0, s1, s2 := e.nodes[0].Store(), e.nodes[1].Store(), e.nodes[2].Store()
	if err := s0.MakeBucket(bg, "shared", storage.MakeBucketOptions{}); err != nil {
		t.Fatal(err)
	}
	put(t, s0, "shared", "from-0", "zero")
	put(t, s1, "shared", "from-1", "one")
	for _, s := range []*Store{s0, s1, s2} {
		for k, want := range map[string]string{"from-0": "zero", "from-1": "one"} {
			if got, err := get(t, s, "shared", k); err != nil || got != want {
				t.Fatalf("get %s = %q, %v", k, got, err)
			}
		}
		res, err := s.ListObjects(bg, "shared", storage.ListOptions{})
		if err != nil || len(res.Objects) != 2 {
			t.Fatalf("list = %+v, %v", res, err)
		}
	}
	// Writers on different nodes contend for one key through the
	// distributed lock; the result is one of them, whole.
	var wg sync.WaitGroup
	for i, s := range []*Store{s0, s1, s2} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v := fmt.Sprintf("writer-%d", i)
			s.PutObject(bg, "shared", "contended", strings.NewReader(v), int64(len(v)), storage.PutOptions{})
		}()
	}
	wg.Wait()
	got0, err := get(t, s0, "shared", "contended")
	if err != nil || !strings.HasPrefix(got0, "writer-") {
		t.Fatalf("contended = %q, %v", got0, err)
	}
	if got1, _ := get(t, s1, "shared", "contended"); got1 != got0 {
		t.Errorf("nodes disagree: %q vs %q", got0, got1)
	}
}

func TestHealthEndpoints(t *testing.T) {
	t.Run("live touches nothing and works before the store opens", func(t *testing.T) {
		root := t.TempDir()
		fn := faultnet.New()
		nd, err := NewNode(NodeConfig{Self: "solo", Peers: map[string]string{"solo": "solo:1"},
			Secrets: []string{testSecret}, HTTPClient: fn.Client("solo:1"), Logger: discard,
			Pools: []PoolSpec{{Sets: [][]string{{"solo:" + filepath.Join(root, "a"), "solo:" + filepath.Join(root, "b")}}}}})
		if err != nil {
			t.Fatal(err)
		}
		defer nd.Close()
		h := nd.Handler()
		if code, _ := httpGet(h, "/_nanoio/health/live"); code != 200 {
			t.Errorf("live = %d before open", code)
		}
		if code, _ := httpGet(h, "/_nanoio/health/ready"); code != 503 {
			t.Errorf("ready = %d before open", code)
		}
		if code, _ := httpGet(h, "/_nanoio/health/cluster"); code != 503 {
			t.Errorf("cluster = %d before open", code)
		}
		// No drive directory was created by serving /live.
		if _, err := filepath.Glob(filepath.Join(root, "*")); err != nil {
			t.Fatal(err)
		}
		if m, _ := filepath.Glob(filepath.Join(root, "*")); len(m) != 0 {
			t.Errorf("health checks touched the drives: %v", m)
		}
	})

	t.Run("ready and cluster follow node and drive loss", func(t *testing.T) {
		root := t.TempDir()
		e := startCluster(t, root, 3, onePool(root), nil)
		h := e.nodes[0].Handler()
		waitFor := func(path string, code int, within time.Duration) string {
			t.Helper()
			deadline := time.Now().Add(within)
			for {
				c, body := httpGet(h, path)
				if c == code {
					return body
				}
				if time.Now().After(deadline) {
					t.Fatalf("%s = %d (%s), want %d", path, c, body, code)
				}
				time.Sleep(50 * time.Millisecond)
			}
		}
		body := waitFor("/_nanoio/health/cluster", 200, 3*time.Second)
		var hs HealthStatus
		json.Unmarshal([]byte(body), &hs)
		if hs.Status != "ok" || hs.Nodes.Online != 3 || hs.Drives.Online != 6 {
			t.Fatalf("healthy cluster reported %+v", hs)
		}
		for _, id := range e.ids {
			if strings.Contains(body, id) || strings.Contains(body, "/") {
				t.Errorf("the unauthenticated cluster report names internals: %s", body)
			}
		}
		waitFor("/_nanoio/health/ready", 200, time.Second)

		// One node down: 4 of 6 drives, a majority of locks: degraded.
		e.net.Crash(e.addr["n2"])
		body = waitFor("/_nanoio/health/cluster", 200, 3*time.Second)
		deadline := time.Now().Add(3 * time.Second)
		for !strings.Contains(body, "degraded") && time.Now().Before(deadline) {
			time.Sleep(50 * time.Millisecond)
			_, body = httpGet(h, "/_nanoio/health/cluster")
		}
		if !strings.Contains(body, "degraded") {
			t.Errorf("one node down reported %s", body)
		}
		// Placement is unaffected by what heartbeats saw.
		s := e.nodes[0].Store()
		if r1, r2 := s.ringSet("b", "k"), s.ringSet("b", "k"); r1 != r2 {
			t.Error("placement changed")
		}
		// Two down: no lock majority.
		e.net.Crash(e.addr["n1"])
		waitFor("/_nanoio/health/cluster", 503, 3*time.Second)
		waitFor("/_nanoio/health/ready", 503, 3*time.Second)
		if c, _ := httpGet(h, "/_nanoio/health/live"); c != 200 {
			t.Errorf("live = %d while the cluster is unavailable", c)
		}
		e.net.Heal()
		waitFor("/_nanoio/health/cluster", 200, 5*time.Second)
	})
}

func TestStartupWaitsForPeers(t *testing.T) {
	root := t.TempDir()
	fn := faultnet.New()
	addr := map[string]string{"n0": "n0:1", "n1": "n1:1", "n2": "n2:1"}
	pools := onePool(root)([]string{"n0", "n1", "n2"})
	mk := func(id string) *Node {
		nd, err := NewNode(NodeConfig{Self: id, Peers: addr, Secrets: []string{testSecret}, Pools: pools,
			Parity: 2, BlockSize: 8 << 10, HTTPClient: fn.Client(addr[id]), Logger: discard,
			LockTTL: 300 * time.Millisecond, Heartbeat: time.Second, ScanInterval: -1, BucketSync: -1,
			StartupTimeout: 15 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		fn.Register(addr[id], nd.Handler())
		t.Cleanup(func() { nd.Close() })
		return nd
	}
	n0, n1, n2 := mk("n0"), mk("n1"), mk("n2")
	fn.Crash(addr["n1"])
	fn.Crash(addr["n2"])
	done := make(chan error, 1)
	go func() { _, err := n0.Open(context.Background()); done <- err }()
	select {
	case err := <-done:
		t.Fatalf("Open returned %v with its peers down", err)
	case <-time.After(1500 * time.Millisecond):
	}
	fn.Restart(addr["n1"])
	fn.Restart(addr["n2"])
	opened := make(chan struct{}, 2)
	go func() { n1.Open(context.Background()); opened <- struct{}{} }()
	go func() { n2.Open(context.Background()); opened <- struct{}{} }()
	defer func() { <-opened; <-opened }() // let them finish before cleanup closes them
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Open after the peers came up: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Open never completed after the peers came up")
	}
}

func TestMisconfigurationIsRefused(t *testing.T) {
	base := NodeConfig{Self: "a", Peers: map[string]string{"a": "a:1", "b": "b:1"}, Secrets: []string{testSecret},
		Logger: discard, Pools: []PoolSpec{{Sets: [][]string{{"a:/x", "b:/y"}}}}, HTTPClient: faultnet.New().Client("a:1")}
	tests := []struct {
		name string
		mut  func(*NodeConfig)
		want string
	}{
		{"self missing", func(c *NodeConfig) { c.Self = "z" }, "not in the node list"},
		{"short secret", func(c *NodeConfig) { c.Secrets = []string{"short"} }, "shorter"},
		{"no secret", func(c *NodeConfig) { c.Secrets = nil }, "at least one"},
		{"unknown node in a drive", func(c *NodeConfig) { c.Pools = []PoolSpec{{Sets: [][]string{{"a:/x", "q:/y"}}}} }, "unknown node"},
		{"bad drive spec", func(c *NodeConfig) { c.Pools = []PoolSpec{{Sets: [][]string{{"nonode", "a:/y"}}}} }, "want node:/path"},
		{"set too small", func(c *NodeConfig) { c.Pools = []PoolSpec{{Sets: [][]string{{"a:/x"}}}} }, "need 2 to"},
		{"no pools", func(c *NodeConfig) { c.Pools = nil }, "no pools"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := base
			tt.mut(&c)
			_, err := NewNode(c)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want containing %q", err, tt.want)
			}
		})
	}
	t.Run("a plaintext multi-node cluster fails closed", func(t *testing.T) {
		c := base
		c.HTTPClient = nil
		c.TLS = TLSFiles{}
		_, err := NewNode(c)
		if err == nil || !strings.Contains(err.Error(), "TLS is required") {
			t.Errorf("err = %v", err)
		}
	})
}

func TestDecommissionThroughAdminRPC(t *testing.T) {
	root := t.TempDir()
	twoPools := func(draining bool) func(ids []string) []PoolSpec {
		return func(ids []string) []PoolSpec {
			var p0, p1 []string
			for _, id := range ids {
				p0 = append(p0, drive(root, id, 0), drive(root, id, 1))
				p1 = append(p1, drive(root, id, 2), drive(root, id, 3))
			}
			return []PoolSpec{{Draining: draining, Sets: [][]string{p0}}, {Sets: [][]string{p1}}}
		}
	}
	// Fill with both pools live.
	e := startCluster(t, root, 3, twoPools(false), nil)
	s := e.nodes[0].Store()
	s.MakeBucket(bg, "dec", storage.MakeBucketOptions{})
	for i := 0; i < 24; i++ {
		put(t, s, "dec", fmt.Sprintf("o%02d", i), fmt.Sprintf("v%02d", i))
	}
	if countIn(s, "dec", 0) == 0 || countIn(s, "dec", 1) == 0 {
		t.Fatalf("objects not spread: %d / %d", countIn(s, "dec", 0), countIn(s, "dec", 1))
	}
	e.close()

	// Restart with pool 0 draining on every node, as the procedure says.
	e2 := startCluster(t, root, 3, twoPools(true), nil)
	admin, err := AdminClient([]string{testSecret}, e2.addr, e2.net.Client("admin:0"), false)
	if err != nil {
		t.Fatal(err)
	}
	// A node cannot impersonate the operator.
	if _, err := e2.nodes[1].client.Do(bg, "n0", "admin.decommission", nil, []byte(`{"pool":0}`)); err == nil {
		t.Error("a peer node was allowed to run an admin operation")
	}
	var res adminRes
	if err := admin.Call(bg, "n0", "admin.decommission", adminReq{Pool: 0}, &res); err != nil {
		t.Fatal(err)
	}
	if res.Drain.Objects == 0 || res.Drain.Failed != 0 {
		t.Errorf("drain = %+v", res.Drain)
	}
	s2 := e2.nodes[2].Store()
	if n := countIn(s2, "dec", 0); n != 0 {
		t.Errorf("%d objects remain in the drained pool", n)
	}
	for i := 0; i < 24; i++ {
		k := fmt.Sprintf("o%02d", i)
		if got, err := get(t, s2, "dec", k); err != nil || got != fmt.Sprintf("v%02d", i) {
			t.Fatalf("%s = %q, %v", k, got, err)
		}
	}
	var hs HealthStatus
	if err := admin.Call(bg, "n1", "admin.status", struct{}{}, &hs); err != nil || hs.Sets.Total != 2 {
		t.Errorf("status = %+v, %v", hs, err)
	}
}
