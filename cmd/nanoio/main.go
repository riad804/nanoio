// Command nanoio is the NanoIO S3-compatible object storage server.
//
// It serves the S3 API from the fs backend on a data directory until
// SIGINT/SIGTERM, then drains in-flight requests and shuts down. Requests
// are authenticated with AWS Signature V4 against the root credential and
// an optional IAM file; authentication can only be disabled explicitly.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"nanoio/internal/api"
	"nanoio/internal/auth"
	"nanoio/internal/bucket/nslock"
	"nanoio/internal/cluster/rpc"
	"nanoio/internal/config"
	"nanoio/internal/iam"
	"nanoio/internal/storage"
	"nanoio/internal/storage/cluster"
	"nanoio/internal/storage/fs"
	"nanoio/internal/storage/xl"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Getenv, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "nanoio: %v\n", err)
		os.Exit(1)
	}
}

// run starts the server and blocks until ctx is done, then shuts down. It
// returns nil on a clean shutdown.
func run(ctx context.Context, args []string, getenv func(string) string, stderr io.Writer) error {
	if len(args) > 0 && args[0] == "admin" {
		return runAdmin(ctx, args[1:], getenv, os.Stdout, stderr)
	}
	flags := flag.NewFlagSet("nanoio", flag.ContinueOnError)
	flags.SetOutput(stderr)
	cfgPath := flags.String("config", "", "path to a JSON config file (or set "+config.EnvConfigFile+")")
	root := flags.String("root", "", "data directory for the fs backend (or set "+config.EnvRoot+")")
	drives := flags.String("drives", "", "comma-separated drive directories for the erasure-coded xl backend (or set "+config.EnvDrives+")")
	parity := flags.Int("parity", 0, "xl: drives that may be lost; 0 means half (or set "+config.EnvParity+")")
	address := flags.String("address", "", "listen address, host:port (or set "+config.EnvAddress+")")
	insecure := flags.Bool("insecure-no-auth", false, "DISABLE authentication and authorisation (local development only)")
	nodeID := flags.String("node", "", "distributed mode: this node's ID (or set "+config.EnvNodeID+")")
	tlsCert := flags.String("tls-cert", "", "distributed mode: PEM certificate for the listener and inter-node calls (or "+config.EnvTLSCert+")")
	tlsKey := flags.String("tls-key", "", "distributed mode: PEM private key (or "+config.EnvTLSKey+")")
	tlsCA := flags.String("tls-ca", "", "distributed mode: PEM CA that verifies peers (or "+config.EnvTLSCA+")")
	interTLS := flags.String("inter-node-tls-required", "", "distributed mode: true (default) or false; false is for development clusters only")
	flags.Usage = func() {
		fmt.Fprintf(stderr, "Usage: nanoio [--config file] (--root dir | --drives d1,d2,... [--parity n] | cluster config) [--address host:port]\n")
		fmt.Fprintf(stderr, "       nanoio admin (status | scan [--deep] | decommission --pool N | rewrap [--endpoint url]) [--config file]\n\n")
		flags.PrintDefaults()
		fmt.Fprintf(stderr, "\nPrecedence: defaults < config file < NANOIO_* environment < flags.\n")
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}

	path := *cfgPath
	if path == "" {
		path = getenv(config.EnvConfigFile)
	}
	cfg, err := config.Load(path, getenv)
	if err != nil {
		return err
	}
	if *root != "" {
		cfg.Root = *root
	}
	if *drives != "" {
		cfg.Drives = nil
		for _, d := range strings.Split(*drives, ",") {
			if d = strings.TrimSpace(d); d != "" {
				cfg.Drives = append(cfg.Drives, d)
			}
		}
	}
	if *parity != 0 {
		cfg.Parity = *parity
	}
	if *address != "" {
		cfg.Address = *address
	}
	if *insecure {
		cfg.InsecureNoAuth = true
	}
	if *nodeID != "" || *tlsCert != "" || *tlsKey != "" || *tlsCA != "" || *interTLS != "" {
		if cfg.Cluster == nil {
			cfg.Cluster = &config.Cluster{}
		}
		if *nodeID != "" {
			cfg.Cluster.Node = *nodeID
		}
		if *tlsCert != "" {
			cfg.Cluster.TLS.Cert = *tlsCert
		}
		if *tlsKey != "" {
			cfg.Cluster.TLS.Key = *tlsKey
		}
		if *tlsCA != "" {
			cfg.Cluster.TLS.CA = *tlsCA
		}
		if *interTLS != "" {
			b, err := strconv.ParseBool(*interTLS)
			if err != nil {
				return fmt.Errorf("--inter-node-tls-required: %w", err)
			}
			cfg.Cluster.TLSRequired = &b
		}
	}
	if err := cfg.Finalize(); err != nil {
		return err
	}

	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.LogLevel)); err != nil {
		return fmt.Errorf("log level: %w", err)
	}
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: level}))

	for _, w := range cfg.Warnings {
		logger.Warn(w)
	}

	apiOpts := api.Options{Domains: cfg.Domains, Region: cfg.Region, Logger: logger}
	if cfg.InsecureNoAuth {
		apiOpts.InsecureNoAuth = true
		logger.Warn("AUTHENTICATION IS DISABLED: every request is served as an all-powerful caller; use only on a trusted loopback")
	} else {
		root := iam.Credential{AccessKey: cfg.RootUser, SecretKey: cfg.RootPassword}
		var store *iam.Store
		if cfg.IAMFile != "" {
			var warns []string
			store, warns, err = iam.LoadFile(cfg.IAMFile, root)
			for _, w := range warns {
				logger.Warn(w)
			}
		} else {
			store, err = iam.New(root, nil)
		}
		if err != nil {
			return err
		}
		apiOpts.Auth = &auth.Verifier{Provider: store, Region: cfg.Region}
		apiOpts.Authz = store
		logger.Info("authentication enabled", "root", cfg.RootUser, "users", store.UserCount(), "iamFile", cfg.IAMFile)
	}

	if k, err := newKMS(cfg.KMS, logger); err != nil {
		return err
	} else if k != nil {
		apiOpts.KMS, apiOpts.DefaultKMSKey = k, cfg.KMS.DefaultKey
	}
	apiOpts.AllowInsecureSSEC = cfg.AllowInsecureSSEC
	if cfg.AllowInsecureSSEC {
		logger.Warn("SSE-C keys are accepted over connections that are not TLS: an on-path observer can read them")
	}

	gcInterval := cfg.GCInterval.D()
	if gcInterval == 0 {
		gcInterval = -1 // config 0 means "off"; the backends' 0 means "default"
	}
	locker := nslock.New(cfg.LockTimeout.D())
	var backend storage.StorageAPI
	var node *cluster.Node
	switch {
	case cfg.Cluster != nil:
		node, err = newClusterNode(cfg, gcInterval, logger)
		if err != nil {
			return err
		}
	case len(cfg.Drives) > 0:
		x, err := xl.New(cfg.Drives, xl.Options{
			Locker: locker, Logger: logger, ParityBlocks: cfg.Parity,
			UploadExpiry: cfg.UploadExpiry.D(), ScanInterval: gcInterval,
		})
		if err != nil {
			return err
		}
		k, m, bs := x.Layout()
		logger.Info("erasure-coded backend", "data", k, "parity", m, "blockSize", bs,
			"drives", len(cfg.Drives), "online", x.OnlineDrives())
		if x.OnlineDrives() < len(cfg.Drives) {
			logger.Warn("starting degraded: some drives are unavailable; the scanner will repair them when they return",
				"online", x.OnlineDrives(), "configured", len(cfg.Drives))
		}
		backend = x
	default:
		f, err := fs.New(cfg.Root, fs.Options{
			Locker: locker, Logger: logger,
			UploadExpiry: cfg.UploadExpiry.D(), GCInterval: gcInterval,
		})
		if err != nil {
			return err
		}
		backend = f
	}
	closeBackend := func() error {
		if node != nil {
			return node.Close()
		}
		return backend.Close()
	}
	sw := &switchHandler{}
	if node != nil {
		sw.internal = node.Handler()
		apiOpts.Internal = sw.internal
	} else {
		apiOpts.Storage = backend
		handler, err := api.New(apiOpts)
		if err != nil {
			closeBackend()
			return err
		}
		sw.set(handler)
	}
	ln, err := net.Listen("tcp", cfg.Address)
	if err != nil {
		closeBackend()
		return err
	}
	srv := &http.Server{
		Handler: sw,
		// Uploads and downloads can be arbitrarily long, so only header
		// reads and idle keep-alives are bounded.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	serveErr := make(chan error, 1)
	if node != nil && node.TLS() {
		tc, err := rpc.TLSServerConfig(cfg.Cluster.TLS.Cert, cfg.Cluster.TLS.Key, cfg.Cluster.TLS.CA)
		if err != nil {
			closeBackend()
			return err
		}
		srv.TLSConfig = tc
		go func() { serveErr <- srv.ServeTLS(ln, "", "") }()
	} else {
		go func() { serveErr <- srv.Serve(ln) }()
	}

	if node != nil {
		// The listener is up so peers can reach this node's drives and
		// lock table while its own set waits for them.
		logger.Info("cluster node listening; waiting for peers", "node", cfg.Cluster.Node, "address", ln.Addr().String())
		store, err := node.Open(ctx)
		if err != nil {
			srv.Close()
			closeBackend()
			return err
		}
		apiOpts.Storage = store
		handler, err := api.New(apiOpts)
		if err != nil {
			srv.Close()
			closeBackend()
			return err
		}
		sw.set(handler)
		backend = store
		for _, st := range store.Status() {
			logger.Info("erasure set", "set", st.ID, "pool", st.Pool, "draining", st.Draining,
				"data", st.Data, "parity", st.Parity, "online", st.Online, "drives", st.Drives)
		}
	}

	kind, where := "fs", any(cfg.Root)
	switch {
	case node != nil:
		kind, where = "cluster", any(cfg.Cluster.Node)
	case len(cfg.Drives) > 0:
		kind, where = "xl", any(len(cfg.Drives))
	}
	logger.Info("nanoio ready", "backend", kind, "root", where, "address", ln.Addr().String(),
		"domains", cfg.Domains, "region", cfg.Region,
		"uploadExpiry", cfg.UploadExpiry.D(), "gcInterval", cfg.GCInterval.D())
	if !isLoopback(ln.Addr()) && !(node != nil && node.TLS()) {
		if cfg.InsecureNoAuth {
			logger.Warn("listening beyond loopback with NO authentication: anyone who can reach this port can read, write and delete all data",
				"address", ln.Addr().String())
		} else {
			logger.Warn("listening beyond loopback over plain HTTP: requests are signed but payloads are not encrypted; put a TLS proxy in front",
				"address", ln.Addr().String())
		}
	}

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-serveErr: // listener failed before shutdown was requested
	}
	logger.Info("shutting down", "timeout", cfg.ShutdownTimeout.D())

	shutCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout.D())
	defer cancel()
	if err := srv.Shutdown(shutCtx); err != nil {
		// In-flight requests outlived the timeout: cut them so Close can
		// finish rather than wait on them forever.
		logger.Warn("drain timed out, closing connections", "err", err)
		srv.Close()
		if runErr == nil {
			runErr = fmt.Errorf("shutdown: %w", err)
		}
	}
	if err := closeBackend(); err != nil && runErr == nil {
		runErr = fmt.Errorf("shutdown: %w", err)
	}
	if runErr == nil {
		logger.Info("stopped")
	}
	return runErr
}

// isLoopback reports whether the listener is reachable only from this host.
func isLoopback(a net.Addr) bool {
	if t, ok := a.(*net.TCPAddr); ok {
		return t.IP.IsLoopback()
	}
	return false
}

// switchHandler serves the internal namespace from the start and the S3 API
// once it is ready.
type switchHandler struct {
	api      atomic.Pointer[http.Handler]
	internal http.Handler
}

func (h *switchHandler) set(handler http.Handler) { h.api.Store(&handler) }

func (h *switchHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p := h.api.Load(); p != nil {
		(*p).ServeHTTP(w, r)
		return
	}
	if h.internal != nil && strings.HasPrefix(r.URL.Path, api.InternalPrefix) {
		h.internal.ServeHTTP(w, r)
		return
	}
	http.Error(w, "node is starting", http.StatusServiceUnavailable)
}

func newClusterNode(cfg config.Config, gcInterval time.Duration, logger *slog.Logger) (*cluster.Node, error) {
	cl := cfg.Cluster
	pools := make([]cluster.PoolSpec, len(cl.Pools))
	for i, p := range cl.Pools {
		pools[i] = cluster.PoolSpec{Draining: p.Draining, Sets: p.Sets}
	}
	tlsRequired := (cl.TLSRequired == nil || *cl.TLSRequired) && len(cl.Nodes) > 1
	if !tlsRequired && len(cl.Nodes) > 1 {
		logger.Warn("INTER-NODE TLS IS NOT REQUIRED: node traffic is signed but not encrypted; use only for development")
	}
	return cluster.NewNode(cluster.NodeConfig{
		Self: cl.Node, Peers: cl.Nodes, Secrets: cl.Secrets, Pools: pools, Parity: cfg.Parity,
		TLS:               cluster.TLSFiles{Cert: cl.TLS.Cert, Key: cl.TLS.Key, CA: cl.TLS.CA},
		InsecurePlaintext: !tlsRequired && len(cl.Nodes) > 1, Logger: logger,
		LockTTL: cl.LockTTL.D(), LockTimeout: cfg.LockTimeout.D(), ListTimeout: cl.ListTimeout.D(),
		AllowPartialList: cl.AllowPartialList, Heartbeat: cl.Heartbeat.D(), StragglerGrace: cl.StragglerGrace.D(),
		UploadExpiry: cfg.UploadExpiry.D(), ScanInterval: gcInterval, StartupTimeout: cl.StartupTimeout.D(),
	})
}

// runAdmin implements `nanoio admin ...`: signed operator calls to a node.
func runAdmin(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("nanoio admin", flag.ContinueOnError)
	flags.SetOutput(stderr)
	cfgPath := flags.String("config", "", "path to the node's JSON config file (or "+config.EnvConfigFile+")")
	target := flags.String("node", "", "node to call (default: the config's own node)")
	pool := flags.Int("pool", -1, "decommission: pool index")
	deep := flags.Bool("deep", false, "scan: verify every block's hash")
	endpoint := flags.String("endpoint", "", "rewrap: base URL of the server (default: the config's address)")
	if len(args) == 0 {
		return errors.New("admin: need a command: status, scan, decommission or rewrap")
	}
	cmd := args[0]
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	path := *cfgPath
	if path == "" {
		path = getenv(config.EnvConfigFile)
	}
	cfg, err := config.Load(path, getenv)
	if err != nil {
		return err
	}
	if cmd == "rewrap" {
		return runRewrap(ctx, cfg, *endpoint, stdout)
	}
	cl := cfg.Cluster
	if cl == nil || len(cl.Secrets) == 0 || len(cl.Nodes) == 0 {
		return errors.New("admin: the config has no cluster section with nodes and a secret")
	}
	node := *target
	if node == "" {
		node = cl.Node
	}
	if _, ok := cl.Nodes[node]; !ok {
		return fmt.Errorf("admin: unknown node %q", node)
	}
	httpc := &http.Client{}
	useTLS := cl.TLS.Cert != "" || cl.TLS.CA != ""
	if useTLS {
		tc, err := rpc.TLSClientConfig(cl.TLS.Cert, cl.TLS.Key, cl.TLS.CA)
		if err != nil {
			return err
		}
		httpc.Transport = &http.Transport{TLSClientConfig: tc}
	}
	client, err := cluster.AdminClient(cl.Secrets, cl.Nodes, httpc, useTLS)
	if err != nil {
		return err
	}
	var out any
	switch cmd {
	case "status":
		var h cluster.HealthStatus
		err, out = client.Call(ctx, node, "admin.status", struct{}{}, &h), &h
	case "scan":
		var st xl.ScanStats
		err, out = client.Call(ctx, node, "admin.scan", struct{ Deep bool }{*deep}, &st), &st
	case "decommission":
		if *pool < 0 {
			return errors.New("admin decommission: --pool is required")
		}
		var res struct {
			Message string
			Drain   cluster.DrainStats
		}
		err, out = client.Call(ctx, node, "admin.decommission", struct {
			Pool int `json:"pool"`
		}{*pool}, &res), &res
	default:
		return fmt.Errorf("admin: unknown command %q", cmd)
	}
	if err != nil {
		return err
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
