// Package config loads NanoIO's settings. Precedence, lowest to highest:
// built-in defaults, JSON config file, NANOIO_* environment variables, then
// command-line flags (applied by cmd/nanoio).
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Environment variable names.
const (
	EnvConfigFile      = "NANOIO_CONFIG_FILE"
	EnvRoot            = "NANOIO_ROOT"
	EnvAddress         = "NANOIO_ADDRESS"
	EnvDomains         = "NANOIO_DOMAINS"
	EnvRegion          = "NANOIO_REGION"
	EnvRootUser        = "NANOIO_ROOT_USER"
	EnvRootPassword    = "NANOIO_ROOT_PASSWORD"
	EnvIAMFile         = "NANOIO_IAM_FILE"
	EnvInsecureNoAuth  = "NANOIO_INSECURE_NO_AUTH"
	EnvDrives          = "NANOIO_DRIVES"
	EnvParity          = "NANOIO_PARITY"
	EnvUploadExpiry    = "NANOIO_UPLOAD_EXPIRY"
	EnvGCInterval      = "NANOIO_GC_INTERVAL"
	EnvLogLevel        = "NANOIO_LOG_LEVEL"
	EnvLockTimeout     = "NANOIO_LOCK_TIMEOUT"
	EnvShutdownTimeout = "NANOIO_SHUTDOWN_TIMEOUT"

	// Distributed mode.
	EnvNodeID           = "NANOIO_NODE_ID"
	EnvClusterSecret    = "NANOIO_CLUSTER_SECRET"
	EnvClusterSecretOld = "NANOIO_CLUSTER_SECRET_PREVIOUS"
	EnvTLSCert          = "NANOIO_TLS_CERT"
	EnvTLSKey           = "NANOIO_TLS_KEY"
	EnvTLSCA            = "NANOIO_TLS_CA"
	EnvInterNodeTLS     = "NANOIO_INTER_NODE_TLS_REQUIRED"
)

// Cluster configures distributed mode. It is mutually exclusive with Root
// and Drives. Pool and set order is identity and must only ever grow by
// appending.
type Cluster struct {
	// Node is this node's ID; Nodes maps every node ID to its host:port.
	Node  string            `json:"node"`
	Nodes map[string]string `json:"nodes"`
	// Secrets: the first signs inter-node requests, all verify. Prefer the
	// environment (NANOIO_CLUSTER_SECRET[_PREVIOUS]) to keep them off disk.
	Secrets []string `json:"secrets"`
	// Pools lists each pool's sets; a drive is "node:/absolute/path".
	Pools []ClusterPool `json:"pools"`
	// TLS files for the listener and inter-node calls. Cert and Key make
	// the listener HTTPS; CA verifies peers (server certificates by
	// clients, client certificates by the RPC endpoints).
	TLS TLS `json:"tls"`
	// TLSRequired defaults to true; false is for development clusters.
	TLSRequired *bool `json:"tlsRequired"`
	// Heartbeat is the peer ping period (health reporting only).
	Heartbeat Duration `json:"heartbeat"`
	// LockTTL is the lease length of namespace locks.
	LockTTL Duration `json:"lockTTL"`
	// ListTimeout bounds each set's part of a listing.
	ListTimeout Duration `json:"listTimeout"`
	// StragglerGrace is how long a write waits for slow drives once its
	// quorum has finished; they are dropped and healed afterwards. 0 means
	// the xl default (500ms).
	StragglerGrace Duration `json:"stragglerGrace"`
	// AllowPartialList lets a listing succeed, marked incomplete, when a
	// set cannot answer. Off by default.
	AllowPartialList bool `json:"allowPartialList"`
	// StartupTimeout is how long a node waits for peers at start.
	StartupTimeout Duration `json:"startupTimeout"`
}

// ClusterPool is one pool of erasure sets.
type ClusterPool struct {
	// Draining pools take no new objects (see docs/cluster-operations.md).
	Draining bool       `json:"draining"`
	Sets     [][]string `json:"sets"`
}

// TLS holds PEM file paths.
type TLS struct {
	Cert string `json:"cert"`
	Key  string `json:"key"`
	CA   string `json:"ca"`
}

// Duration is a time.Duration that reads and writes JSON as a string such as
// "30s".
type Duration time.Duration

// D returns the value as a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// MarshalJSON implements json.Marshaler.
func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(d.D().String()) }

// UnmarshalJSON implements json.Unmarshaler.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("duration must be a string like \"30s\": %w", err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// Config is the server configuration.
type Config struct {
	// Root is the data directory served by the fs backend. Set exactly one
	// of Root and Drives.
	Root string `json:"root"`
	// Drives, when set, selects the erasure-coded xl backend over these
	// directories (2 to 32), one per drive. The list order is each drive's
	// identity and must not change between runs.
	Drives []string `json:"drives"`
	// Parity is the number of drives the xl backend can lose: data blocks
	// are len(Drives)-Parity. 0 means half the drives.
	Parity int `json:"parity"`
	// Address is the host:port the S3 API listens on. The default is
	// loopback only because authentication is not implemented yet.
	Address string `json:"address"`
	// Domains are base domains for virtual-host-style requests
	// (bucket.<domain>). Hosts outside them are path-style.
	Domains []string `json:"domains"`
	// Region is reported to clients and must match the region in request
	// signatures.
	Region string `json:"region"`
	// RootUser and RootPassword are the root credential's access key and
	// secret key. Prefer the environment over the file so the secret is not
	// written to disk.
	RootUser     string `json:"rootUser"`
	RootPassword string `json:"rootPassword"`
	// Cluster, when set, selects distributed mode.
	Cluster *Cluster `json:"cluster"`
	// IAMFile is the path of the users and policies document (optional).
	IAMFile string `json:"iamFile"`
	// InsecureNoAuth disables authentication and authorisation entirely.
	// For local development only.
	InsecureNoAuth bool `json:"insecureNoAuth"`

	// Warnings are conditions worth surfacing at startup; filled by Load.
	Warnings []string `json:"-"`
	// LogLevel is one of debug, info, warn, error.
	LogLevel string `json:"logLevel"`
	// LockTimeout bounds a namespace lock wait.
	LockTimeout Duration `json:"lockTimeout"`
	// UploadExpiry is how long a multipart upload may sit without a new
	// part before the garbage collector aborts it. Go duration syntax, so
	// "168h", not "7d".
	UploadExpiry Duration `json:"uploadExpiry"`
	// GCInterval is the period of the background maintenance pass: the
	// garbage collector for fs, the heal-and-collect scanner for xl. Zero
	// disables it (xl still repairs objects that reads find damaged).
	GCInterval Duration `json:"gcInterval"`
	// ShutdownTimeout bounds graceful shutdown.
	ShutdownTimeout Duration `json:"shutdownTimeout"`
}

// Default returns the built-in defaults. Root has none and must be set.
func Default() Config {
	return Config{
		Address:         "127.0.0.1:9000",
		Domains:         []string{"localhost"},
		Region:          "us-east-1",
		LogLevel:        "info",
		LockTimeout:     Duration(30 * time.Second),
		UploadExpiry:    Duration(7 * 24 * time.Hour),
		GCInterval:      Duration(time.Hour),
		ShutdownTimeout: Duration(30 * time.Second),
	}
}

// Load merges defaults, the JSON file at path (if non-empty) and the
// environment. It does not validate; call Finalize after applying any flag
// overrides. Unknown JSON fields are an error so typos are caught.
func Load(path string, getenv func(string) string) (Config, error) {
	cfg := Default()
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return Config{}, fmt.Errorf("config: %w", err)
		}
		if st, err := os.Stat(path); err == nil && st.Mode().Perm()&0o077 != 0 && bytes.Contains(data, []byte(`"rootPassword"`)) {
			cfg.Warnings = append(cfg.Warnings, fmt.Sprintf(
				"%s holds rootPassword and is accessible to other users (mode %04o); chmod 600 it or use %s",
				path, st.Mode().Perm(), EnvRootPassword))
		}
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&cfg); err != nil {
			return Config{}, fmt.Errorf("config: %s: %w", path, err)
		}
		if _, err := dec.Token(); !errors.Is(err, io.EOF) {
			return Config{}, fmt.Errorf("config: %s: trailing data after JSON document", path)
		}
	}
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	if v := getenv(EnvRoot); v != "" {
		cfg.Root = v
	}
	if v := getenv(EnvDrives); v != "" {
		cfg.Drives = nil
		for _, d := range strings.Split(v, ",") {
			if d = strings.TrimSpace(d); d != "" {
				cfg.Drives = append(cfg.Drives, d)
			}
		}
	}
	if v := getenv(EnvNodeID); v != "" || getenv(EnvClusterSecret) != "" || getenv(EnvTLSCert) != "" ||
		getenv(EnvInterNodeTLS) != "" {
		if cfg.Cluster == nil {
			cfg.Cluster = &Cluster{}
		}
		if v != "" {
			cfg.Cluster.Node = v
		}
		if sec := getenv(EnvClusterSecret); sec != "" {
			cfg.Cluster.Secrets = []string{sec}
			for _, old := range strings.Split(getenv(EnvClusterSecretOld), ",") {
				if old = strings.TrimSpace(old); old != "" {
					cfg.Cluster.Secrets = append(cfg.Cluster.Secrets, old)
				}
			}
		}
		if v := getenv(EnvTLSCert); v != "" {
			cfg.Cluster.TLS.Cert = v
		}
		if v := getenv(EnvTLSKey); v != "" {
			cfg.Cluster.TLS.Key = v
		}
		if v := getenv(EnvTLSCA); v != "" {
			cfg.Cluster.TLS.CA = v
		}
		if v := getenv(EnvInterNodeTLS); v != "" {
			b, err := strconv.ParseBool(v)
			if err != nil {
				return Config{}, fmt.Errorf("config: %s: %w", EnvInterNodeTLS, err)
			}
			cfg.Cluster.TLSRequired = &b
		}
	}
	if v := getenv(EnvParity); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return Config{}, fmt.Errorf("config: %s: must be a non-negative integer", EnvParity)
		}
		cfg.Parity = n
	}
	if v := getenv(EnvAddress); v != "" {
		cfg.Address = v
	}
	if v := getenv(EnvRegion); v != "" {
		cfg.Region = v
	}
	if v := getenv(EnvDomains); v != "" {
		cfg.Domains = nil
		for _, d := range strings.Split(v, ",") {
			if d = strings.TrimSpace(d); d != "" {
				cfg.Domains = append(cfg.Domains, d)
			}
		}
	}
	if v := getenv(EnvRootUser); v != "" {
		cfg.RootUser = v
	}
	if v := getenv(EnvRootPassword); v != "" {
		cfg.RootPassword = v
	}
	if v := getenv(EnvIAMFile); v != "" {
		cfg.IAMFile = v
	}
	if v := getenv(EnvInsecureNoAuth); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return Config{}, fmt.Errorf("config: %s: %w", EnvInsecureNoAuth, err)
		}
		cfg.InsecureNoAuth = b
	}
	if v := getenv(EnvLogLevel); v != "" {
		cfg.LogLevel = v
	}
	for _, d := range []struct {
		env string
		dst *Duration
	}{
		{EnvLockTimeout, &cfg.LockTimeout},
		{EnvUploadExpiry, &cfg.UploadExpiry},
		{EnvGCInterval, &cfg.GCInterval},
		{EnvShutdownTimeout, &cfg.ShutdownTimeout},
	} {
		if v := getenv(d.env); v != "" {
			parsed, err := time.ParseDuration(v)
			if err != nil {
				return Config{}, fmt.Errorf("config: %s: %w", d.env, err)
			}
			*d.dst = Duration(parsed)
		}
	}
	return cfg, nil
}

// Finalize validates c and makes Root absolute.
func (c *Config) Finalize() error {
	switch {
	case c.Cluster != nil:
		if c.Root != "" || len(c.Drives) > 0 {
			return errors.New("config: cluster mode excludes root and drives")
		}
		cl := c.Cluster
		if cl.Node == "" || len(cl.Nodes) == 0 || len(cl.Pools) == 0 {
			return fmt.Errorf("config: cluster needs node (%s), nodes and pools", EnvNodeID)
		}
		if _, ok := cl.Nodes[cl.Node]; !ok {
			return fmt.Errorf("config: cluster node %q is not listed in nodes", cl.Node)
		}
		for id := range cl.Nodes {
			if id == "" || strings.HasPrefix(id, "_") || strings.ContainsAny(id, ":/ ") {
				return fmt.Errorf("config: cluster node ID %q is invalid", id)
			}
		}
		if len(cl.Secrets) == 0 {
			return fmt.Errorf("config: cluster secret is required (%s)", EnvClusterSecret)
		}
		if (cl.TLS.Cert == "") != (cl.TLS.Key == "") {
			return errors.New("config: tls cert and key must be set together")
		}
		if len(cl.Nodes) > 1 && cl.TLS.Cert == "" && (cl.TLSRequired == nil || *cl.TLSRequired) {
			return fmt.Errorf("config: inter-node TLS is required for a multi-node cluster: set tls.cert/key (and tls.ca), "+
				"or %s=false for a development cluster", EnvInterNodeTLS)
		}
		if cl.TLS.Cert == "" && len(cl.Nodes) > 1 {
			c.Warnings = append(c.Warnings, "inter-node traffic is NOT encrypted: requests are authenticated but readable on the wire; development use only")
		}
	case c.Root != "" && len(c.Drives) > 0:
		return errors.New("config: set either root (fs backend) or drives (xl backend), not both")
	case c.Root == "" && len(c.Drives) == 0:
		return fmt.Errorf("config: root, drives or cluster is required (set --root, %s, --drives, %s or the config file)", EnvRoot, EnvDrives)
	case len(c.Drives) > 0:
		n := len(c.Drives)
		if n < 2 || n > 32 {
			return fmt.Errorf("config: drives: %d given; the xl backend needs 2 to 32", n)
		}
		parity := c.Parity
		if parity == 0 {
			parity = n / 2
		}
		if parity < 1 || parity > n-parity {
			return fmt.Errorf("config: parity %d with %d drives gives %d+%d; need 1 <= parity <= data", c.Parity, n, n-parity, parity)
		}
		seen := map[string]bool{}
		for i, d := range c.Drives {
			abs, err := filepath.Abs(d)
			if err != nil {
				return fmt.Errorf("config: drives[%d]: %w", i, err)
			}
			if seen[abs] {
				return fmt.Errorf("config: drive %q listed twice", abs)
			}
			seen[abs] = true
			c.Drives[i] = abs
		}
	default:
		abs, err := filepath.Abs(c.Root)
		if err != nil {
			return fmt.Errorf("config: root: %w", err)
		}
		c.Root = abs
	}
	_, port, err := net.SplitHostPort(c.Address)
	if err != nil {
		return fmt.Errorf("config: address %q: %w", c.Address, err)
	}
	if n, perr := strconv.Atoi(port); perr != nil || n < 0 || n > 65535 {
		return fmt.Errorf("config: address %q: invalid port", c.Address)
	}
	for i, d := range c.Domains {
		d = strings.ToLower(strings.Trim(strings.TrimSpace(d), "."))
		if d == "" || strings.ContainsAny(d, "/: ") {
			return fmt.Errorf("config: domains[%d] %q: must be a bare domain name", i, c.Domains[i])
		}
		c.Domains[i] = d
	}
	if !c.InsecureNoAuth && (c.RootUser == "" || c.RootPassword == "") {
		return fmt.Errorf("config: root credentials are required: set %s and %s (or --insecure-no-auth for local development)",
			EnvRootUser, EnvRootPassword)
	}
	if c.IAMFile != "" {
		abs, err := filepath.Abs(c.IAMFile)
		if err != nil {
			return fmt.Errorf("config: iamFile: %w", err)
		}
		c.IAMFile = abs
	}
	if c.Region == "" {
		return errors.New("config: region must not be empty")
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("config: logLevel %q: must be debug, info, warn or error", c.LogLevel)
	}
	if c.LockTimeout <= 0 {
		return errors.New("config: lockTimeout must be positive")
	}
	if c.UploadExpiry <= 0 {
		return errors.New("config: uploadExpiry must be positive")
	}
	if c.GCInterval < 0 {
		return errors.New("config: gcInterval must not be negative (0 disables the collector)")
	}
	if c.ShutdownTimeout <= 0 {
		return errors.New("config: shutdownTimeout must be positive")
	}
	return nil
}
