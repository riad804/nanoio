package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// withDefaults fills the network fields a test does not care about.
func withDefaults(c Config) Config {
	d := Default()
	c.Address, c.Domains, c.Region = d.Address, d.Domains, d.Region
	c.UploadExpiry, c.GCInterval = d.UploadExpiry, d.GCInterval
	c.KMS = d.KMS
	return c
}

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	full := write("full.json", `{"root":"/from/file","logLevel":"debug","lockTimeout":"5s","shutdownTimeout":"1m"}`)
	partial := write("partial.json", `{"root":"/from/file"}`)
	typo := write("typo.json", `{"rooot":"/x"}`)
	badDur := write("bad.json", `{"lockTimeout":"soon"}`)
	numDur := write("num.json", `{"lockTimeout":30}`)
	trailing := write("trail.json", `{"root":"/x"} {"root":"/y"}`)
	notJSON := write("nj.json", `root: /x`)

	tests := []struct {
		name    string
		path    string
		env     map[string]string
		want    Config
		wantErr string
	}{
		{"defaults only", "", nil, Default(), ""},
		{"file overrides defaults", full, nil,
			withDefaults(Config{Root: "/from/file", LogLevel: "debug", LockTimeout: Duration(5 * time.Second), ShutdownTimeout: Duration(time.Minute)}), ""},
		{"partial file keeps other defaults", partial, nil,
			withDefaults(Config{Root: "/from/file", LogLevel: "info", LockTimeout: Default().LockTimeout, ShutdownTimeout: Default().ShutdownTimeout}), ""},
		{"env overrides file", full, map[string]string{EnvRoot: "/from/env", EnvLogLevel: "warn", EnvLockTimeout: "9s"},
			withDefaults(Config{Root: "/from/env", LogLevel: "warn", LockTimeout: Duration(9 * time.Second), ShutdownTimeout: Duration(time.Minute)}), ""},
		{"env without file", "", map[string]string{EnvRoot: "/r", EnvShutdownTimeout: "2s"},
			withDefaults(Config{Root: "/r", LogLevel: "info", LockTimeout: Default().LockTimeout, ShutdownTimeout: Duration(2 * time.Second)}), ""},
		{"missing file", filepath.Join(dir, "nope.json"), nil, Config{}, "no such file"},
		{"unknown field", typo, nil, Config{}, "unknown field"},
		{"bad duration in file", badDur, nil, Config{}, "invalid duration"},
		{"numeric duration in file", numDur, nil, Config{}, "duration must be a string"},
		{"trailing data", trailing, nil, Config{}, "trailing data"},
		{"not json", notJSON, nil, Config{}, "invalid character"},
		{"bad duration in env", "", map[string]string{EnvLockTimeout: "soon"}, Config{}, EnvLockTimeout},
		{"address, region and domains from env", "", map[string]string{
			EnvAddress: "0.0.0.0:9001", EnvRegion: "eu-west-1", EnvDomains: " a.example.com, b.example.com ,,"},
			func() Config {
				c := Default()
				c.Address, c.Region, c.Domains = "0.0.0.0:9001", "eu-west-1", []string{"a.example.com", "b.example.com"}
				return c
			}(), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Load(tt.path, env(tt.env))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestLoadDrivesFromEnv(t *testing.T) {
	c, err := Load("", env(map[string]string{EnvDrives: " /d/one, /d/two ,,/d/three,/d/four", EnvParity: "2"}))
	if err != nil || len(c.Drives) != 4 || c.Drives[1] != "/d/two" || c.Parity != 2 {
		t.Errorf("%+v, %v", c, err)
	}
	for _, bad := range []string{"-1", "two"} {
		if _, err := Load("", env(map[string]string{EnvParity: bad})); err == nil {
			t.Errorf("parity %q accepted", bad)
		}
	}
	c.Root = ""
	c.RootUser, c.RootPassword = "admin", "admin-secret-1"
	if err := c.Finalize(); err != nil {
		t.Fatal(err)
	}
	for _, d := range c.Drives {
		if !filepath.IsAbs(d) {
			t.Errorf("drive %q not made absolute", d)
		}
	}
}

func TestLoadCollectorSettings(t *testing.T) {
	c, err := Load("", env(map[string]string{EnvUploadExpiry: "72h", EnvGCInterval: "15m"}))
	if err != nil || c.UploadExpiry.D() != 72*time.Hour || c.GCInterval.D() != 15*time.Minute {
		t.Errorf("%+v, %v", c, err)
	}
	if d := Default(); d.UploadExpiry.D() != 7*24*time.Hour || d.GCInterval.D() != time.Hour {
		t.Errorf("defaults: %v %v", d.UploadExpiry, d.GCInterval)
	}
	if _, err := Load("", env(map[string]string{EnvUploadExpiry: "7d"})); err == nil {
		t.Error(`"7d" is not Go duration syntax and must be rejected`)
	}
}

func TestLoadAuthSettings(t *testing.T) {
	dir := t.TempDir()
	open := filepath.Join(dir, "open.json")
	os.WriteFile(open, []byte(`{"rootUser":"a","rootPassword":"secretvalue","iamFile":"/x/iam.json","insecureNoAuth":false}`), 0o644)
	os.Chmod(open, 0o644)
	private := filepath.Join(dir, "private.json")
	os.WriteFile(private, []byte(`{"rootUser":"a","rootPassword":"secretvalue"}`), 0o600)
	noSecret := filepath.Join(dir, "nosecret.json")
	os.WriteFile(noSecret, []byte(`{"region":"us-east-1"}`), 0o644)
	os.Chmod(noSecret, 0o644)

	t.Run("file fields", func(t *testing.T) {
		c, err := Load(private, env(nil))
		if err != nil || c.RootUser != "a" || c.RootPassword != "secretvalue" || len(c.Warnings) != 0 {
			t.Errorf("%+v, %v", c, err)
		}
	})
	t.Run("env overrides file", func(t *testing.T) {
		c, err := Load(private, env(map[string]string{EnvRootUser: "envuser", EnvRootPassword: "envpassword", EnvIAMFile: "/e/iam.json"}))
		if err != nil || c.RootUser != "envuser" || c.RootPassword != "envpassword" || c.IAMFile != "/e/iam.json" {
			t.Errorf("%+v, %v", c, err)
		}
	})
	t.Run("loose permissions on a file with the password warn", func(t *testing.T) {
		c, err := Load(open, env(nil))
		if err != nil || len(c.Warnings) != 1 || !strings.Contains(c.Warnings[0], "chmod 600") {
			t.Errorf("warnings = %v, %v", c.Warnings, err)
		}
		if strings.Contains(c.Warnings[0], "secretvalue") {
			t.Error("warning leaks the secret")
		}
	})
	t.Run("loose permissions without a secret do not warn", func(t *testing.T) {
		c, err := Load(noSecret, env(nil))
		if err != nil || len(c.Warnings) != 0 {
			t.Errorf("warnings = %v, %v", c.Warnings, err)
		}
	})
	t.Run("insecure flag from env", func(t *testing.T) {
		c, err := Load("", env(map[string]string{EnvInsecureNoAuth: "true"}))
		if err != nil || !c.InsecureNoAuth {
			t.Errorf("%+v, %v", c, err)
		}
		if _, err := Load("", env(map[string]string{EnvInsecureNoAuth: "maybe"})); err == nil {
			t.Error("accepted a non-boolean")
		}
	})
}

func TestFinalize(t *testing.T) {
	good := func(mut func(*Config)) Config {
		c := Default()
		c.Root = "/data"
		c.RootUser, c.RootPassword = "admin", "admin-secret-1"
		if mut != nil {
			mut(&c)
		}
		return c
	}
	tests := []struct {
		name    string
		cfg     Config
		wantErr string
		wantAbs bool
	}{
		{"valid", good(nil), "", true},
		{"relative root made absolute", good(func(c *Config) { c.Root = "data" }), "", true},
		{"missing root", good(func(c *Config) { c.Root = "" }), "root, drives or cluster is required", false},
		{"bad log level", good(func(c *Config) { c.LogLevel = "trace" }), "logLevel", false},
		{"zero lock timeout", good(func(c *Config) { c.LockTimeout = 0 }), "lockTimeout", false},
		{"negative shutdown timeout", good(func(c *Config) { c.ShutdownTimeout = -1 }), "shutdownTimeout", false},
		{"address without port", good(func(c *Config) { c.Address = "localhost" }), "address", false},
		{"address with bad port", good(func(c *Config) { c.Address = "localhost:http-alt" }), "invalid port", false},
		{"ephemeral port ok", good(func(c *Config) { c.Address = "127.0.0.1:0" }), "", true},
		{"domain with port", good(func(c *Config) { c.Domains = []string{"example.com:9000"} }), "domains[0]", false},
		{"domain with slash", good(func(c *Config) { c.Domains = []string{"a/b"} }), "domains[0]", false},
		{"empty region", good(func(c *Config) { c.Region = "" }), "region", false},
		{"no domains means path style only", good(func(c *Config) { c.Domains = nil }), "", true},
		{"missing root user", good(func(c *Config) { c.RootUser = "" }), "root credentials are required", false},
		{"missing root password", good(func(c *Config) { c.RootPassword = "" }), "NANOIO_ROOT_PASSWORD", false},
		{"no credentials needed when auth is off", good(func(c *Config) { c.RootUser, c.RootPassword, c.InsecureNoAuth = "", "", true }), "", true},
		{"drives instead of root", good(func(c *Config) { c.Root = ""; c.Drives = []string{"a", "b", "c", "d"} }), "", false},
		{"drives with explicit parity", good(func(c *Config) { c.Root = ""; c.Drives = []string{"a", "b", "c", "d"}; c.Parity = 1 }), "", false},
		{"root and drives together", good(func(c *Config) { c.Drives = []string{"a", "b"} }), "not both", false},
		{"one drive", good(func(c *Config) { c.Root = ""; c.Drives = []string{"a"} }), "2 to 32", false},
		{"33 drives", good(func(c *Config) {
			c.Root = ""
			for i := 0; i < 33; i++ {
				c.Drives = append(c.Drives, fmt.Sprintf("d%d", i))
			}
		}), "2 to 32", false},
		{"parity above data", good(func(c *Config) { c.Root = ""; c.Drives = []string{"a", "b", "c", "d"}; c.Parity = 3 }), "1 <= parity <= data", false},
		{"duplicate drive", good(func(c *Config) { c.Root = ""; c.Drives = []string{"a", "b", "a", "d"} }), "listed twice", false},
		{"zero upload expiry", good(func(c *Config) { c.UploadExpiry = 0 }), "uploadExpiry", false},
		{"negative gc interval", good(func(c *Config) { c.GCInterval = -1 }), "gcInterval", false},
		{"zero gc interval disables the collector", good(func(c *Config) { c.GCInterval = 0 }), "", true},
		{"relative iam file made absolute", good(func(c *Config) { c.IAMFile = "iam.json" }), "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := tt.cfg
			err := c.Finalize()
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tt.wantAbs && !filepath.IsAbs(c.Root) {
				t.Errorf("root %q not absolute", c.Root)
			}
		})
	}
}

func TestClusterConfig(t *testing.T) {
	base := func() Config {
		c := Default()
		c.RootUser, c.RootPassword = "u", "p"
		c.Cluster = &Cluster{
			Node:    "n1",
			Nodes:   map[string]string{"n1": "n1:9000", "n2": "n2:9000"},
			Secrets: []string{"0123456789abcdef"},
			Pools:   []ClusterPool{{Sets: [][]string{{"n1:/d1", "n2:/d1"}}}},
			TLS:     TLS{Cert: "c.pem", Key: "k.pem"},
		}
		return c
	}
	no := false
	tests := []struct {
		name string
		mut  func(*Config)
		want string // substring of the error; "" means valid
	}{
		{"valid", func(*Config) {}, ""},
		{"plaintext multi-node refused by default", func(c *Config) { c.Cluster.TLS = TLS{} }, "inter-node TLS is required"},
		{"plaintext allowed when waived", func(c *Config) { c.Cluster.TLS = TLS{}; c.Cluster.TLSRequired = &no }, ""},
		{"single node needs no TLS", func(c *Config) {
			c.Cluster.TLS = TLS{}
			c.Cluster.Nodes = map[string]string{"n1": "n1:9000"}
		}, ""},
		{"cert without key", func(c *Config) { c.Cluster.TLS.Key = "" }, "together"},
		{"excludes root", func(c *Config) { c.Root = "/x" }, "excludes root"},
		{"excludes drives", func(c *Config) { c.Drives = []string{"a", "b"} }, "excludes root"},
		{"node not listed", func(c *Config) { c.Cluster.Node = "zz" }, "not listed"},
		{"no secret", func(c *Config) { c.Cluster.Secrets = nil }, "secret is required"},
		{"no pools", func(c *Config) { c.Cluster.Pools = nil }, "needs node"},
		{"reserved node id", func(c *Config) {
			c.Cluster.Nodes["_admin"] = "x:1"
		}, "invalid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := base()
			tt.mut(&c)
			err := c.Finalize()
			switch {
			case tt.want == "" && err != nil:
				t.Errorf("unexpected error: %v", err)
			case tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)):
				t.Errorf("err = %v, want containing %q", err, tt.want)
			}
		})
	}
	t.Run("environment supplies secret rotation", func(t *testing.T) {
		env := map[string]string{
			EnvNodeID: "n1", EnvClusterSecret: "new-secret-0123456789", EnvClusterSecretOld: "old-a-0123456789, old-b-0123456789",
			EnvInterNodeTLS: "false",
		}
		c, err := Load("", func(k string) string { return env[k] })
		if err != nil {
			t.Fatal(err)
		}
		if c.Cluster == nil || c.Cluster.Node != "n1" || len(c.Cluster.Secrets) != 3 ||
			c.Cluster.Secrets[0] != "new-secret-0123456789" || c.Cluster.TLSRequired == nil || *c.Cluster.TLSRequired {
			t.Errorf("cluster = %+v", c.Cluster)
		}
	})
}

func TestKMSConfig(t *testing.T) {
	dir := t.TempDir()
	base := func(k KMS) Config {
		c := Default()
		c.Root, c.RootUser, c.RootPassword, c.KMS = dir, "u", "p", k
		return c
	}
	cfg, err := Load("", env(map[string]string{
		EnvKMSBackend: "local", EnvKMSDefaultKey: "k", EnvKMSSecretKey: "k:AAAA", EnvKMSCacheTTL: "30s",
		EnvKMSKESEndpoint: "https://kes", EnvAllowInsecureSSEC: "true",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.KMS.Backend != "local" || cfg.KMS.DefaultKey != "k" || cfg.KMS.SecretKey != "k:AAAA" ||
		cfg.KMS.CacheTTL.D() != 30*time.Second || cfg.KMS.KES.Endpoint != "https://kes" || !cfg.AllowInsecureSSEC {
		t.Errorf("env not applied: %+v", cfg.KMS)
	}
	if Default().KMS.CacheTTL.D() != 5*time.Minute {
		t.Error("default cache TTL is not 5m")
	}
	// The secret key is environment only: a file cannot carry it.
	p := filepath.Join(dir, "c.json")
	os.WriteFile(p, []byte(`{"kms":{"secretKey":"k:AAAA"}}`), 0o600)
	if _, err := Load(p, nil); err == nil {
		t.Error("secretKey accepted from the config file")
	}

	tests := []struct {
		name    string
		kms     KMS
		wantErr string
	}{
		{"none", KMS{}, ""},
		{"local with secret", KMS{Backend: "local", DefaultKey: "k", SecretKey: "k:x"}, ""},
		{"local with file", KMS{Backend: "local", DefaultKey: "k", Local: struct {
			KeyFile string `json:"keyFile"`
		}{"/keys"}}, ""},
		{"local without keys", KMS{Backend: "local", DefaultKey: "k"}, "keyFile"},
		{"no default key", KMS{Backend: "local", SecretKey: "k:x"}, "defaultKey"},
		{"unknown backend", KMS{Backend: "vault", DefaultKey: "k"}, "must be"},
		{"kes needs endpoint", KMS{Backend: "kes", DefaultKey: "k"}, "endpoint"},
		{"negative ttl", KMS{CacheTTL: -1}, "cacheTTL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := base(tt.kms)
			err := c.Finalize()
			switch {
			case tt.wantErr == "" && err != nil:
				t.Errorf("unexpected error: %v", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Errorf("err = %v, want %q", err, tt.wantErr)
			}
		})
	}
	// KES needs a credential.
	c := base(KMS{Backend: "kes", DefaultKey: "k"})
	c.KMS.KES.Endpoint = "https://kes"
	if err := c.Finalize(); err == nil || !strings.Contains(err.Error(), "client certificate or an API key") {
		t.Errorf("kes without credential: %v", err)
	}
	c.KMS.KES.APIKey = "token"
	if err := c.Finalize(); err != nil {
		t.Errorf("kes with api key: %v", err)
	}
}
