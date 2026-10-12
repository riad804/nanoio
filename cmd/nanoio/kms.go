package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"nanoio/internal/api"
	"nanoio/internal/auth"
	"nanoio/internal/cluster/rpc"
	"nanoio/internal/config"
	"nanoio/internal/kms"
)

// newKMS builds the configured key management service, wrapped in its key
// cache, and verifies that the default key exists so a typo fails at start
// rather than on the first encrypted PUT. It returns nil when none is
// configured.
func newKMS(c config.KMS, logger *slog.Logger) (kms.KMS, error) {
	var base kms.KMS
	switch c.Backend {
	case "":
		return nil, nil
	case "local":
		keys := map[string][]kms.LocalKey{}
		if c.Local.KeyFile != "" {
			l, err := kms.LoadLocalFile(c.Local.KeyFile)
			if err != nil {
				return nil, err
			}
			base = l
		}
		if c.SecretKey != "" {
			name, k, err := kms.ParseSecretKey(c.SecretKey)
			if err != nil {
				return nil, err
			}
			keys[name] = []kms.LocalKey{k}
		}
		if base == nil {
			l, err := kms.NewLocal(keys)
			if err != nil {
				return nil, err
			}
			base = l
		} else if len(keys) > 0 {
			return nil, fmt.Errorf("kms: set either kms.local.keyFile or %s, not both", config.EnvKMSSecretKey)
		}
	case "kes":
		client, err := kesHTTPClient(c)
		if err != nil {
			return nil, err
		}
		base, err = kms.NewKES(kms.KESConfig{Endpoint: c.KES.Endpoint, APIKey: c.KES.APIKey, Client: client})
		if err != nil {
			return nil, err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	info, err := base.DescribeKey(ctx, c.DefaultKey)
	if err != nil {
		return nil, fmt.Errorf("kms: default key %q: %w", c.DefaultKey, err)
	}
	logger.Info("kms ready", "backend", c.Backend, "defaultKey", info.ID, "version", info.LatestVersion,
		"cacheTTL", c.CacheTTL.D())
	return kms.NewCache(base, c.CacheTTL.D(), c.CacheSize), nil
}

func kesHTTPClient(c config.KMS) (*http.Client, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.KES.ClientCert != "" {
		cert, err := tls.LoadX509KeyPair(c.KES.ClientCert, c.KES.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("kms: kes client certificate: %w", err)
		}
		tc.Certificates = []tls.Certificate{cert}
	}
	if c.KES.CA != "" {
		pem, err := os.ReadFile(c.KES.CA)
		if err != nil {
			return nil, fmt.Errorf("kms: kes ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("kms: kes ca %s holds no certificates", c.KES.CA)
		}
		tc.RootCAs = pool
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: tc}}, nil
}

// runRewrap implements `nanoio admin rewrap`: it asks a running server,
// authenticated as the root user, to move every KMS-wrapped data key to the
// newest version of its key-encryption key. Object data is never touched.
func runRewrap(ctx context.Context, cfg config.Config, endpoint string, stdout io.Writer) error {
	if cfg.RootUser == "" || cfg.RootPassword == "" {
		return fmt.Errorf("admin rewrap: root credentials are required (%s, %s)", config.EnvRootUser, config.EnvRootPassword)
	}
	if endpoint == "" {
		host, port, err := net.SplitHostPort(cfg.Address)
		if err != nil {
			return fmt.Errorf("admin rewrap: address %q: %w", cfg.Address, err)
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
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(endpoint, "/")+api.InternalPrefix+"admin/rewrap", nil)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(nil)
	auth.Signer{AccessKey: cfg.RootUser, SecretKey: cfg.RootPassword, Region: cfg.Region}.
		Sign(req, hex.EncodeToString(sum[:]), time.Now())
	client := &http.Client{}
	if cfg.Cluster != nil && (cfg.Cluster.TLS.CA != "" || cfg.Cluster.TLS.Cert != "") {
		tc, err := rpc.TLSClientConfig(cfg.Cluster.TLS.Cert, cfg.Cluster.TLS.Key, cfg.Cluster.TLS.CA)
		if err != nil {
			return err
		}
		client.Transport = &http.Transport{TLSClientConfig: tc}
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("admin rewrap: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("admin rewrap: server answered %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	_, err = stdout.Write(body)
	return err
}
