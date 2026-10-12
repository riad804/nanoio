package cluster

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"nanoio/internal/cluster/dsync"
	"nanoio/internal/cluster/rpc"
	"nanoio/internal/cluster/rpcauth"
	"nanoio/internal/storage"
	"nanoio/internal/storage/xl"
	"nanoio/internal/storage/xl/disk"
	"nanoio/internal/storage/xl/disk/remote"
)

// PoolSpec describes a pool in configuration: each set is a list of drive
// specs "node:/absolute/path".
type PoolSpec struct {
	Draining bool       `json:"draining"`
	Sets     [][]string `json:"sets"`
}

// TLSFiles are the PEM files of inter-node TLS.
type TLSFiles struct {
	Cert string `json:"cert"`
	Key  string `json:"key"`
	CA   string `json:"ca"`
}

// NodeConfig describes this node's view of the cluster.
type NodeConfig struct {
	// Self is this node's ID; Peers maps every node ID (including Self) to
	// its host:port.
	Self  string
	Peers map[string]string
	// Secrets: the first signs, all verify (see rpcauth).
	Secrets []string
	Pools   []PoolSpec

	Parity int
	// StorageClasses maps storage class names to parity counts; see
	// xl.Options.StorageClasses.
	StorageClasses map[string]int
	BlockSize      int64

	// TLS enables HTTPS between nodes. A cluster of more than one node
	// without TLS is refused unless InsecurePlaintext is set (development
	// only). Tests supply HTTPClient instead, which carries its own
	// transport.
	TLS               TLSFiles
	InsecurePlaintext bool
	HTTPClient        *http.Client

	Logger           *slog.Logger
	LockTTL          time.Duration
	LockTimeout      time.Duration
	ListTimeout      time.Duration
	AllowPartialList bool
	Heartbeat        time.Duration
	UploadExpiry     time.Duration
	ScanInterval     time.Duration
	// StragglerGrace is passed to every set (see xl.Options).
	StragglerGrace time.Duration
	// OnTransitionFreed is passed to every set (see xl.Options).
	OnTransitionFreed func(bucket, object string, tr storage.TransitionInfo)
	StartupTimeout    time.Duration
	// BucketSync is passed to the Store; see Options.BucketSync.
	BucketSync time.Duration
}

// Node is one member of the cluster: it serves its drives and lock table to
// peers, and builds the Store over the whole cluster.
type Node struct {
	cfg    NodeConfig
	log    *slog.Logger
	client *rpc.Client
	rpc    *rpc.Server
	disks  *remote.Server
	locks  *dsync.Server
	locker *dsync.Locker
	local  map[string]disk.Disk

	store atomic.Pointer[Store]

	hbMu sync.Mutex
	seen map[string]time.Time

	mu     sync.Mutex
	closed bool
	hbStop context.CancelFunc
	hbWG   sync.WaitGroup
}

// ParseDrive splits "node:/path".
func ParseDrive(spec string) (node, path string, err error) {
	i := strings.Index(spec, ":")
	if i <= 0 || i == len(spec)-1 {
		return "", "", fmt.Errorf("drive %q: want node:/path", spec)
	}
	return spec[:i], spec[i+1:], nil
}

// NewNode validates cfg, opens this node's local drives and prepares the
// RPC endpoints. Nothing is served until Handler is mounted; call Open to
// build the Store once peers are reachable.
func NewNode(cfg NodeConfig) (*Node, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if _, ok := cfg.Peers[cfg.Self]; !ok {
		return nil, fmt.Errorf("cluster: node %q is not in the node list", cfg.Self)
	}
	if len(cfg.Pools) == 0 {
		return nil, errors.New("cluster: no pools configured")
	}
	if cfg.Heartbeat <= 0 {
		cfg.Heartbeat = 2 * time.Second
	}
	if cfg.StartupTimeout <= 0 {
		cfg.StartupTimeout = 2 * time.Minute
	}
	keys, err := rpcauth.NewKeyring(cfg.Secrets...)
	if err != nil {
		return nil, err
	}
	n := &Node{cfg: cfg, log: cfg.Logger, local: map[string]disk.Disk{}, seen: map[string]time.Time{}}
	for pi, p := range cfg.Pools {
		if len(p.Sets) == 0 {
			return nil, fmt.Errorf("cluster: pool %d has no sets", pi)
		}
		for si, set := range p.Sets {
			if len(set) < 2 || len(set) > xl.MaxDrives {
				return nil, fmt.Errorf("cluster: pool %d set %d has %d drives; need 2 to %d", pi, si, len(set), xl.MaxDrives)
			}
			for _, spec := range set {
				node, path, err := ParseDrive(spec)
				if err != nil {
					return nil, err
				}
				if _, ok := cfg.Peers[node]; !ok {
					return nil, fmt.Errorf("cluster: drive %q names unknown node %q", spec, node)
				}
				if node == cfg.Self {
					if _, dup := n.local[path]; dup {
						return nil, fmt.Errorf("cluster: drive path %s listed twice for node %s", path, node)
					}
					l, err := disk.NewLocal(path, disk.LocalOptions{})
					if err != nil {
						return nil, err
					}
					n.local[path] = l
				}
			}
		}
	}

	httpc := cfg.HTTPClient
	useTLS := cfg.TLS.Cert != ""
	if httpc == nil {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		// A node that is down should be found out in seconds, not in the
		// default 30s dial; the circuit breaker takes it from there.
		tr.DialContext = (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 15 * time.Second}).DialContext
		tr.TLSHandshakeTimeout = 5 * time.Second
		tr.MaxIdleConnsPerHost = 32
		if useTLS {
			tc, err := rpc.TLSClientConfig(cfg.TLS.Cert, cfg.TLS.Key, cfg.TLS.CA)
			if err != nil {
				return nil, err
			}
			tr.TLSClientConfig = tc
		}
		httpc = &http.Client{Transport: tr}
	}
	n.client, err = rpc.NewClient(rpc.Config{Self: cfg.Self, Keys: keys, Peers: cfg.Peers, HTTP: httpc,
		TLS: useTLS, RequireTLS: len(cfg.Peers) > 1 && !cfg.InsecurePlaintext && cfg.HTTPClient == nil})
	if err != nil {
		return nil, err
	}
	n.rpc = rpc.NewServer(rpc.ServerConfig{Self: cfg.Self, Keys: keys, Encode: remote.EncodeError,
		RequireClientCert: useTLS && cfg.TLS.CA != "",
		Known: func(id string) bool {
			_, ok := cfg.Peers[id]
			return ok || id == rpc.AdminNode
		}})
	n.disks = remote.NewServer(n.local, 0)
	n.disks.Register(n.rpc)
	n.locks = dsync.NewServer(cfg.LockTTL)
	n.locks.Register(n.rpc)
	ids := make([]string, 0, len(cfg.Peers))
	for id := range cfg.Peers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	n.locker, err = dsync.NewLocker(dsync.Options{Nodes: ids, Self: cfg.Self, Local: n.locks, Client: n.client,
		TTL: cfg.LockTTL, Timeout: cfg.LockTimeout,
		OnLost: func(res string) {
			n.log.Warn("cluster: lost a lock lease before releasing it; the generation check protects the write",
				"resource", strings.ReplaceAll(res, "\x00", "/"))
		}})
	if err != nil {
		return nil, err
	}
	n.registerAdmin()
	return n, nil
}

// TLS reports whether this node serves and speaks TLS between nodes.
func (n *Node) TLS() bool { return n.cfg.TLS.Cert != "" }

// Locker is the cluster-wide namespace lock.
func (n *Node) Locker() *dsync.Locker { return n.locker }

// Store returns the opened Store, or nil before Open succeeds.
func (n *Node) Store() *Store { return n.store.Load() }

// Open builds every set, retrying while peers come up, and starts
// heartbeats. It returns the Store.
func (n *Node) Open(ctx context.Context) (*Store, error) {
	deadline := time.Now().Add(n.cfg.StartupTimeout)
	var pools []Pool
	for pi, ps := range n.cfg.Pools {
		pool := Pool{Name: fmt.Sprintf("pool%d", pi), Draining: ps.Draining}
		for si, specs := range ps.Sets {
			var set *xl.XL
			for attempt := 0; ; attempt++ {
				var err error
				if set, err = n.openSet(ctx, specs); err == nil {
					break
				}
				if time.Now().After(deadline) || ctx.Err() != nil {
					return nil, fmt.Errorf("cluster: pool %d set %d: %w", pi, si, err)
				}
				if attempt == 0 || attempt%10 == 0 {
					n.log.Info("cluster: waiting for peers", "pool", pi, "set", si, "err", err)
				}
				select {
				case <-time.After(500 * time.Millisecond):
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			pool.Sets = append(pool.Sets, set)
		}
		pools = append(pools, pool)
	}
	s, err := New(pools, Options{Logger: n.log, ListTimeout: n.cfg.ListTimeout,
		AllowPartialList: n.cfg.AllowPartialList, BucketSync: n.cfg.BucketSync})
	if err != nil {
		return nil, err
	}
	n.store.Store(s)
	n.startHeartbeats()
	return s, nil
}

func (n *Node) openSet(ctx context.Context, specs []string) (*xl.XL, error) {
	disks := make([]disk.Disk, 0, len(specs))
	for _, spec := range specs {
		node, path, _ := ParseDrive(spec)
		if node == n.cfg.Self {
			disks = append(disks, n.local[path])
		} else {
			disks = append(disks, remote.New(n.client, node, path, remote.Options{}))
		}
	}
	sum := sha256.Sum256([]byte(strings.Join(specs, "|")))
	return xl.NewWithDisks(ctx, disks, xl.Options{
		Locker: n.locker, Logger: n.log, ParityBlocks: n.cfg.Parity, StorageClasses: n.cfg.StorageClasses, BlockSize: n.cfg.BlockSize,
		UploadExpiry: n.cfg.UploadExpiry, ScanInterval: n.cfg.ScanInterval,
		StragglerGrace: n.cfg.StragglerGrace, OnTransitionFreed: n.cfg.OnTransitionFreed,
		DeploymentID: hex.EncodeToString(sum[:16]),
	})
}

// Close stops heartbeats, the Store and the RPC server's handle tables.
func (n *Node) Close() error {
	n.mu.Lock()
	n.closed = true
	stop := n.hbStop
	n.mu.Unlock()
	if stop != nil {
		stop()
		n.hbWG.Wait()
	}
	var err error
	if s := n.store.Load(); s != nil {
		err = s.Close()
	} else {
		for _, d := range n.local {
			d.Close()
		}
	}
	n.disks.Close()
	return err
}

// --- heartbeats and health ----------------------------------------------

type pingRes struct {
	Node  string `json:"node"`
	Ready bool   `json:"ready"`
}

func (n *Node) startHeartbeats() {
	n.rpc.Handle("node.ping", rpc.JSON(func(_ context.Context, _ string, _ struct{}) (pingRes, error) {
		return pingRes{Node: n.cfg.Self, Ready: n.ready()}, nil
	}))
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	n.hbStop = cancel
	n.hbWG.Add(1)
	go func() {
		defer n.hbWG.Done()
		t := time.NewTicker(n.cfg.Heartbeat)
		defer t.Stop()
		for {
			n.beat(ctx)
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
}

func (n *Node) beat(ctx context.Context) {
	var wg sync.WaitGroup
	for id := range n.cfg.Peers {
		if id == n.cfg.Self {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, n.cfg.Heartbeat)
			defer cancel()
			var r pingRes
			if err := n.client.Call(cctx, id, "node.ping", struct{}{}, &r); err == nil {
				n.hbMu.Lock()
				n.seen[id] = time.Now()
				n.hbMu.Unlock()
			}
		}()
	}
	wg.Wait()
}

func (n *Node) nodesOnline() (online, total int) {
	total = len(n.cfg.Peers)
	online = 1 // this node
	n.hbMu.Lock()
	defer n.hbMu.Unlock()
	for id, at := range n.seen {
		if id != n.cfg.Self && time.Since(at) < 3*n.cfg.Heartbeat {
			online++
		}
	}
	return online, total
}

func (n *Node) ready() bool {
	s := n.store.Load()
	if s == nil || n.locks.Quarantined() {
		return false
	}
	for _, st := range s.Status() {
		if !st.ReadOK() {
			return false
		}
	}
	return true
}

// HealthStatus is the body of /_nanoio/health/cluster. It carries counts
// only, so it can be served without authentication.
type HealthStatus struct {
	Status string `json:"status"` // ok, degraded, unavailable
	Nodes  struct {
		Total  int `json:"total"`
		Online int `json:"online"`
	} `json:"nodes"`
	Sets struct {
		Total    int `json:"total"`
		Readable int `json:"readable"`
		Writable int `json:"writable"`
	} `json:"sets"`
	Drives struct {
		Total  int `json:"total"`
		Online int `json:"online"`
	} `json:"drives"`
}

// ClusterHealth evaluates the cluster from this node's view. Heartbeats
// only inform this report; they never influence placement or routing.
func (n *Node) ClusterHealth() HealthStatus {
	var h HealthStatus
	h.Nodes.Online, h.Nodes.Total = n.nodesOnline()
	s := n.store.Load()
	allWritable := s != nil
	if s != nil {
		for _, st := range s.Status() {
			h.Sets.Total++
			h.Drives.Total += st.Drives
			h.Drives.Online += st.Online
			if st.ReadOK() {
				h.Sets.Readable++
			}
			if st.WriteOK() {
				h.Sets.Writable++
			} else {
				allWritable = false
			}
		}
	}
	lockW, _ := n.locker.Quorums()
	switch {
	case s == nil || !allWritable || h.Nodes.Online < lockW:
		h.Status = "unavailable"
	case h.Nodes.Online < h.Nodes.Total || h.Drives.Online < h.Drives.Total:
		h.Status = "degraded"
	default:
		h.Status = "ok"
	}
	return h
}

// HealthPrefix is the reserved path namespace of internal endpoints.
const HealthPrefix = "/_nanoio/health/"

// Handler serves everything under /_nanoio/: health and RPC.
func (n *Node) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle(rpc.PathPrefix, n.rpc)
	write := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc(HealthPrefix+"live", func(w http.ResponseWriter, r *http.Request) {
		// Process liveness only: no drive, peer or lock is consulted.
		write(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc(HealthPrefix+"ready", func(w http.ResponseWriter, r *http.Request) {
		if n.ready() {
			write(w, http.StatusOK, map[string]string{"status": "ready"})
			return
		}
		write(w, http.StatusServiceUnavailable, map[string]string{"status": "not ready"})
	})
	mux.HandleFunc(HealthPrefix+"cluster", func(w http.ResponseWriter, r *http.Request) {
		h := n.ClusterHealth()
		code := http.StatusOK
		if h.Status == "unavailable" {
			code = http.StatusServiceUnavailable
		}
		write(w, code, h)
	})
	mux.HandleFunc("/_nanoio/", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	return mux
}

// --- admin ----------------------------------------------------------------

type adminReq struct {
	Pool int `json:"pool"`
}

type adminRes struct {
	Message string     `json:"message"`
	Drain   DrainStats `json:"drain"`
}

func (n *Node) registerAdmin() {
	only := func(from string) error {
		if from != rpc.AdminNode {
			return fmt.Errorf("admin operations require the admin identity, not node %q", from)
		}
		return nil
	}
	n.rpc.Handle("admin.decommission", rpc.JSON(func(ctx context.Context, from string, a adminReq) (adminRes, error) {
		if err := only(from); err != nil {
			return adminRes{}, err
		}
		s := n.store.Load()
		if s == nil {
			return adminRes{}, errors.New("node is still starting")
		}
		st, err := s.Drain(ctx, a.Pool)
		return adminRes{Message: fmt.Sprintf("pool %d drained", a.Pool), Drain: st}, err
	}))
	n.rpc.Handle("admin.scan", rpc.JSON(func(ctx context.Context, from string, a struct{ Deep bool }) (xl.ScanStats, error) {
		if err := only(from); err != nil {
			return xl.ScanStats{}, err
		}
		s := n.store.Load()
		if s == nil {
			return xl.ScanStats{}, errors.New("node is still starting")
		}
		return s.Scan(ctx, a.Deep)
	}))
	n.rpc.Handle("admin.status", rpc.JSON(func(ctx context.Context, from string, _ struct{}) (HealthStatus, error) {
		if err := only(from); err != nil {
			return HealthStatus{}, err
		}
		return n.ClusterHealth(), nil
	}))
}

// AdminClient returns a client that calls other nodes as the operator.
func AdminClient(secrets []string, peers map[string]string, httpc *http.Client, tls bool) (*rpc.Client, error) {
	keys, err := rpcauth.NewKeyring(secrets...)
	if err != nil {
		return nil, err
	}
	return rpc.NewClient(rpc.Config{Self: rpc.AdminNode, Keys: keys, Peers: peers, HTTP: httpc, TLS: tls})
}
