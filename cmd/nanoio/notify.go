package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"nanoio/internal/api"
	"nanoio/internal/auth"
	"nanoio/internal/cluster/rpc"
	"nanoio/internal/config"
	"nanoio/internal/event"
	"nanoio/internal/event/target/amqp"
	"nanoio/internal/event/target/elasticsearch"
	"nanoio/internal/event/target/kafka"
	"nanoio/internal/event/target/mqtt"
	"nanoio/internal/event/target/mysql"
	"nanoio/internal/event/target/nats"
	"nanoio/internal/event/target/postgresql"
	"nanoio/internal/event/target/redis"
	"nanoio/internal/event/target/webhook"
	"nanoio/internal/storage"
	"nanoio/internal/tier"
)

// targetFactories maps a configured target type to its constructor. The
// target packages (and the client libraries behind them) are linked here and
// nowhere else.
var targetFactories = map[string]event.Factory{
	webhook.Type:       webhook.Factory,
	kafka.Type:         kafka.Factory,
	amqp.Type:          amqp.Factory,
	mqtt.Type:          mqtt.Factory,
	nats.Type:          nats.Factory,
	redis.Type:         redis.Factory,
	mysql.Type:         mysql.Factory,
	postgresql.Type:    postgresql.Factory,
	elasticsearch.Type: elasticsearch.Factory,
}

// defaultQueueDir keeps queued events next to the node's own data.
func defaultQueueDir(cfg config.Config) string {
	if d := sysDir(cfg); d != "" {
		return filepath.Join(d, "events")
	}
	return ""
}

// sysDir is this node's own ".nanoio.sys" directory on its first local
// drive (or root): where node-local state that is not object data lives.
func sysDir(cfg config.Config) string {
	switch {
	case cfg.Cluster != nil:
		for _, pool := range cfg.Cluster.Pools {
			for _, set := range pool.Sets {
				for _, d := range set {
					if node, path, ok := strings.Cut(d, ":"); ok && node == cfg.Cluster.Node {
						return filepath.Join(path, ".nanoio.sys")
					}
				}
			}
		}
	case len(cfg.Drives) > 0:
		return filepath.Join(cfg.Drives[0], ".nanoio.sys")
	case cfg.Root != "":
		return filepath.Join(cfg.Root, ".nanoio.sys")
	}
	return ""
}

// newNotifier builds the event manager and its configured targets. A target
// whose configuration is invalid stops the server from starting; one whose
// destination is merely unreachable does not (its queue holds the events).
func newNotifier(cfg config.Config, logger *slog.Logger) (*event.Manager, error) {
	dir := cfg.Notify.QueueDir
	if dir == "" {
		dir = defaultQueueDir(cfg)
	}
	m, err := event.NewManager(event.Options{Dir: dir, Region: cfg.Region, Logger: logger, ReplayBytes: cfg.Notify.ReplayBytes})
	if err != nil {
		if len(cfg.Notify.Targets) > 0 {
			return nil, err
		}
		// Nothing is configured to deliver to, so an unusable queue
		// directory (a drive that is offline at start, say) must not keep
		// the server down: run without the replay log.
		logger.Warn("event replay log is unavailable; event streams cannot resume from a sequence number", "dir", dir, "err", err)
		if m, err = event.NewManager(event.Options{Region: cfg.Region, Logger: logger}); err != nil {
			return nil, err
		}
		return m, nil
	}
	types := make([]string, 0, len(cfg.Notify.Targets))
	for t := range cfg.Notify.Targets {
		types = append(types, t)
	}
	sort.Strings(types)
	for _, typ := range types {
		ids := make([]string, 0, len(cfg.Notify.Targets[typ]))
		for id := range cfg.Notify.Targets[typ] {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			spec, err := targetFactories[typ](id, cfg.Notify.Targets[typ][id])
			if err != nil {
				m.Close()
				return nil, fmt.Errorf("notify.targets.%s.%s: %w", typ, id, err)
			}
			arn, err := m.AddTarget(typ, id, spec)
			if err != nil {
				m.Close()
				return nil, fmt.Errorf("notify.targets.%s.%s: %w", typ, id, err)
			}
			logger.Info("notification target configured", "arn", arn, "queueDir", dir)
		}
	}
	return m, nil
}

// eventFlags are the flags of the notification admin commands.
type eventFlags struct {
	bucket, prefix, suffix, events, since, arn *string
	file, id, name                             *string
	force                                      *bool
	bucketR                                    *string
}

func (f *eventFlags) register(fs *flag.FlagSet) {
	f.bucket = fs.String("bucket", "", "events: only this bucket")
	f.prefix = fs.String("prefix", "", "events: only keys with this prefix")
	f.suffix = fs.String("suffix", "", "events: only keys with this suffix")
	f.events = fs.String("event", "", "events: comma-separated event names, e.g. s3:ObjectCreated:*")
	f.since = fs.String("since", "", "events: replay retained events after this sequence number (0 for all) before going live")
	f.arn = fs.String("arn", "", "dead, requeue: the target's ARN")
	f.file = fs.String("file", "", "tier-add, batch-start: the JSON/YAML document to send")
	f.id = fs.String("id", "", "batch-describe, batch-cancel: the job id")
	f.name = fs.String("name", "", "tier-rm, tier-check: the tier name")
	f.bucketR = fs.String("source-bucket", "", "replicate-*: the replicated bucket")
	f.force = fs.Bool("force", false, "tier-rm: remove even if a lifecycle rule uses the tier")
}

// runNotifyAdmin implements `nanoio admin events|notify|dead|requeue`.
func runNotifyAdmin(ctx context.Context, cmd string, cfg config.Config, endpoint string, f eventFlags, stdout io.Writer) error {
	q := url.Values{}
	method, path := http.MethodGet, ""
	var body []byte
	readFile := func() error {
		if *f.file == "" {
			return fmt.Errorf("admin %s: --file is required", cmd)
		}
		b, err := os.ReadFile(*f.file)
		if err != nil {
			return err
		}
		body = b
		return nil
	}
	switch cmd {
	case "replicate-target-add", "replicate-target-ls", "replicate-target-rm", "replicate-resync", "replicate-resync-status", "replicate-metrics":
		if cmd != "replicate-metrics" && *f.bucketR == "" {
			return fmt.Errorf("admin %s: --source-bucket is required", cmd)
		}
		q.Set("bucket", *f.bucketR)
		switch cmd {
		case "replicate-target-add":
			if err := readFile(); err != nil {
				return err
			}
			method, path = http.MethodPut, "admin/replication/target"
		case "replicate-target-ls":
			path = "admin/replication/target"
		case "replicate-target-rm":
			q.Set("arn", *f.arn)
			method, path = http.MethodDelete, "admin/replication/target"
		case "replicate-resync":
			q.Set("arn", *f.arn)
			if *f.force {
				q.Set("force", "true")
			}
			method, path = http.MethodPost, "admin/replication/resync"
		case "replicate-resync-status":
			path = "admin/replication/resync"
		case "replicate-metrics":
			path = "admin/replication/metrics"
		}
	case "site-add":
		if err := readFile(); err != nil {
			return err
		}
		method, path = http.MethodPost, "admin/site/add"
	case "site-status":
		path = "admin/site/status"
	case "site-remove":
		q.Set("id", *f.id)
		method, path = http.MethodPost, "admin/site/remove"
	case "site-resync":
		if *f.force {
			q.Set("authoritative", "true")
		}
		method, path = http.MethodPost, "admin/site/resync"
	case "iam-user-add", "iam-group-add", "iam-policy-add":
		if err := readFile(); err != nil {
			return err
		}
		method, path = http.MethodPut, "admin/iam/"+strings.TrimSuffix(strings.TrimPrefix(cmd, "iam-"), "-add")
	case "iam-user-ls", "iam-group-ls", "iam-policy-ls":
		path = "admin/iam/" + strings.TrimSuffix(strings.TrimPrefix(cmd, "iam-"), "-ls")
	case "iam-user-rm", "iam-group-rm", "iam-policy-rm":
		q.Set("name", *f.name)
		method, path = http.MethodDelete, "admin/iam/"+strings.TrimSuffix(strings.TrimPrefix(cmd, "iam-"), "-rm")
	case "tier-add":
		if err := readFile(); err != nil {
			return err
		}
		method, path = http.MethodPut, "admin/tier"
	case "tier-ls":
		path = "admin/tier"
	case "tier-check":
		q.Set("name", *f.name)
		path = "admin/tier/check"
	case "tier-rm":
		if *f.name == "" {
			return errors.New("admin tier-rm: --name is required")
		}
		q.Set("name", *f.name)
		if *f.force {
			q.Set("force", "true")
		}
		method, path = http.MethodDelete, "admin/tier"
	case "batch-start":
		if err := readFile(); err != nil {
			return err
		}
		method, path = http.MethodPost, "admin/batch/start"
	case "batch-ls":
		path = "admin/batch/list"
	case "batch-template":
		path = "admin/batch/template"
	case "batch-describe", "batch-cancel":
		if *f.id == "" {
			return fmt.Errorf("admin %s: --id is required", cmd)
		}
		q.Set("id", *f.id)
		path = "admin/batch/describe"
		if cmd == "batch-cancel" {
			method, path = http.MethodPost, "admin/batch/cancel"
		}
	case "events":
		path = "admin/events"
		for k, v := range map[string]string{"bucket": *f.bucket, "prefix": *f.prefix, "suffix": *f.suffix, "events": *f.events} {
			if v != "" {
				q.Set(k, v)
			}
		}
		if *f.since != "" {
			q.Set("since", *f.since)
		}
	case "notify":
		path = "admin/notify/targets"
	case "dead", "requeue":
		if *f.arn == "" {
			return fmt.Errorf("admin %s: --arn is required", cmd)
		}
		q.Set("arn", *f.arn)
		path = "admin/notify/dead"
		if cmd == "requeue" {
			method, path = http.MethodPost, "admin/notify/requeue"
		}
	}
	resp, err := signedAdminCall(ctx, cfg, endpoint, method, path, q, body)
	if err != nil {
		return fmt.Errorf("admin %s: %w", cmd, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		fmt.Fprintln(stdout, "ok")
		return nil
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		rb, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("admin %s: server answered %s: %s", cmd, resp.Status, strings.TrimSpace(string(rb)))
	}
	// Events stream until interrupted; the others are one document. Either
	// way the body is copied as it arrives.
	_, err = io.Copy(stdout, resp.Body)
	if err != nil && ctx.Err() != nil {
		return nil
	}
	return err
}

// signedAdminCall sends a SigV4-signed request, as the root user, to the
// server's admin namespace.
func signedAdminCall(ctx context.Context, cfg config.Config, endpoint, method, path string, q url.Values, body []byte) (*http.Response, error) {
	if cfg.RootUser == "" || cfg.RootPassword == "" {
		return nil, fmt.Errorf("root credentials are required (%s, %s)", config.EnvRootUser, config.EnvRootPassword)
	}
	if endpoint == "" {
		host, port, err := net.SplitHostPort(cfg.Address)
		if err != nil {
			return nil, fmt.Errorf("address %q: %w", cfg.Address, err)
		}
		if host == "" || host == "0.0.0.0" || host == "::" {
			host = "127.0.0.1"
		}
		scheme := "http"
		if cfg.Cluster != nil && cfg.Cluster.TLS.Cert != "" {
			scheme = "https"
		}
		endpoint = scheme + "://" + net.JoinHostPort(host, port)
	}
	target := strings.TrimRight(endpoint, "/") + api.InternalPrefix + path
	if len(q) > 0 {
		target += "?" + q.Encode()
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, rd)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	auth.Signer{AccessKey: cfg.RootUser, SecretKey: cfg.RootPassword, Region: cfg.Region}.
		Sign(req, hex.EncodeToString(sum[:]), time.Now())
	client := &http.Client{}
	if cfg.Cluster != nil && (cfg.Cluster.TLS.CA != "" || cfg.Cluster.TLS.Cert != "") {
		tc, err := rpc.TLSClientConfig(cfg.Cluster.TLS.Cert, cfg.Cluster.TLS.Key, cfg.Cluster.TLS.CA)
		if err != nil {
			return nil, err
		}
		client.Transport = &http.Transport{TLSClientConfig: tc}
	}
	return client.Do(req)
}

// lifecycleOptions builds the API's lifecycle scanner settings, or nil when
// the scanner is disabled.
func lifecycleOptions(cfg config.Config, locker storage.Locker) *api.LifecycleOptions {
	if cfg.Lifecycle.Disabled {
		return nil
	}
	rate := cfg.Lifecycle.OpsPerSecond
	if rate < 0 {
		rate = 0
	}
	return &api.LifecycleOptions{Locker: locker, Interval: cfg.Lifecycle.Interval.D(), OpsPerSecond: rate}
}

// tierOptions builds the API's tiering settings and the janitor that reclaims
// remote copies. The janitor exists before the backend so the backend's
// OnTransitionFreed callback can point at it.
func tierOptions(cfg config.Config, logger *slog.Logger) (*api.TierOptions, *tier.Janitor, error) {
	sys := sysDir(cfg)
	if sys == "" {
		return &api.TierOptions{}, nil, nil
	}
	j, err := tier.NewJanitor(filepath.Join(sys, "tier-free"), logger)
	if err != nil {
		return nil, nil, err
	}
	o := &api.TierOptions{CacheDir: cfg.Tier.CacheDir, CacheBytes: cfg.Tier.CacheBytes, CacheTTL: cfg.Tier.CacheTTL.D(), Janitor: j}
	if o.CacheDir == "" {
		o.CacheDir = filepath.Join(sys, "tier-cache")
	}
	return o, j, nil
}

// batchOptions enables the batch-job runner (on every node).
func batchOptions(cfg config.Config, locker storage.Locker) *api.BatchOptions {
	if cfg.Batch.Disabled {
		return nil
	}
	return &api.BatchOptions{Locker: locker, Workers: cfg.Batch.Workers}
}

// replicationOptions enables bucket replication, queueing under the node's
// system directory.
func replicationOptions(cfg config.Config, locker storage.Locker) *api.ReplicationOptions {
	if cfg.Replication.Disabled {
		return nil
	}
	sys := sysDir(cfg)
	if sys == "" {
		return nil
	}
	return &api.ReplicationOptions{Dir: filepath.Join(sys, "replication"), Workers: cfg.Replication.Workers,
		ScanInterval: cfg.Replication.ScanInterval.D(), Locker: locker}
}
