// Package tier is the storage-tier abstraction behind ILM transitions: a
// named remote object store (S3-compatible, Azure Blob, Google Cloud
// Storage) that holds the data of transitioned object versions.
//
// A Backend is deliberately tiny: put a stream, get a range, delete, and
// check connectivity. Which object lives where, and the stub that points at
// it, are the storage layer's business; the registry here only knows tier
// names and how to reach them.
package tier

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Backend is one remote tier.
type Backend interface {
	// Put uploads exactly size bytes under name and returns the remote
	// version ID (empty when the remote does not version).
	Put(ctx context.Context, name string, r io.Reader, size int64) (versionID string, err error)
	// Get returns length bytes from offset (length < 0: to the end).
	Get(ctx context.Context, name, versionID string, offset, length int64) (io.ReadCloser, error)
	// Delete removes the object; a missing object is not an error.
	Delete(ctx context.Context, name, versionID string) error
	// Check proves the tier is reachable and writable: it writes, reads
	// back and deletes a probe object.
	Check(ctx context.Context) error
	Close() error
}

// Tier types.
const (
	TypeS3    = "s3"
	TypeAzure = "azure"
	TypeGCS   = "gcs"
)

// S3Config is an S3-compatible tier (AWS S3, MinIO, another NanoIO).
type S3Config struct {
	// Endpoint is the base URL, e.g. https://s3.amazonaws.com or
	// http://minio.example:9000.
	Endpoint  string `json:"endpoint"`
	Region    string `json:"region,omitempty"`
	Bucket    string `json:"bucket"`
	Prefix    string `json:"prefix,omitempty"`
	AccessKey string `json:"accessKey"`
	SecretKey string `json:"secretKey"`
	// StorageClass is the S3 storage class objects are written with
	// (e.g. GLACIER_IR); empty leaves the remote's default.
	StorageClass string `json:"storageClass,omitempty"`
	// VirtualHost addresses the bucket as a subdomain; the default is
	// path style, which every S3-compatible server accepts.
	VirtualHost bool `json:"virtualHost,omitempty"`
	// InsecureSkipVerify disables certificate verification: for test
	// servers only.
	InsecureSkipVerify bool `json:"insecureSkipVerify,omitempty"`
	// PartSize is the multipart part size and the object size above which a
	// multipart upload is used (default 64 MiB; S3 requires at least 5 MiB
	// per part but the last).
	PartSize int64 `json:"partSize,omitempty"`
}

// AzureConfig is an Azure Blob Storage tier.
type AzureConfig struct {
	Account    string `json:"account"`
	AccountKey string `json:"accountKey"`
	Container  string `json:"container"`
	Prefix     string `json:"prefix,omitempty"`
	// Endpoint overrides https://<account>.blob.core.windows.net (an
	// emulator such as Azurite).
	Endpoint string `json:"endpoint,omitempty"`
}

// GCSConfig is a Google Cloud Storage tier.
type GCSConfig struct {
	Bucket string `json:"bucket"`
	Prefix string `json:"prefix,omitempty"`
	// CredentialsJSON is a service-account key file's content; empty uses
	// application default credentials.
	CredentialsJSON string `json:"credentials,omitempty"`
	// Endpoint overrides the API endpoint (an emulator such as
	// fake-gcs-server).
	Endpoint string `json:"endpoint,omitempty"`
}

// Config is one named tier.
type Config struct {
	// Name is the tier's name as lifecycle rules use it (a StorageClass):
	// upper-case letters, digits, '_' and '-'.
	Name    string       `json:"name"`
	Type    string       `json:"type"`
	S3      *S3Config    `json:"s3,omitempty"`
	Azure   *AzureConfig `json:"azure,omitempty"`
	GCS     *GCSConfig   `json:"gcs,omitempty"`
	Created time.Time    `json:"created"`
}

var nameRE = regexp.MustCompile(`^[A-Z][A-Z0-9_-]{0,63}$`)

// reserved storage-class names a tier may not take, because they mean
// something to S3 clients already.
var reserved = map[string]bool{
	"STANDARD": true, "REDUCED_REDUNDANCY": true, "STANDARD_IA": true, "ONEZONE_IA": true,
	"INTELLIGENT_TIERING": true, "GLACIER": true, "DEEP_ARCHIVE": true, "GLACIER_IR": true,
}

// Validate checks the configuration without contacting the remote.
func (c *Config) Validate() error {
	if !nameRE.MatchString(c.Name) {
		return errors.New("tier name must be 1-64 upper-case letters, digits, '_' or '-', starting with a letter")
	}
	if reserved[c.Name] {
		return fmt.Errorf("tier name %q is a built-in S3 storage class", c.Name)
	}
	switch c.Type {
	case TypeS3:
		s := c.S3
		if s == nil || s.Endpoint == "" || s.Bucket == "" || s.AccessKey == "" || s.SecretKey == "" {
			return errors.New("an s3 tier needs endpoint, bucket, accessKey and secretKey")
		}
		if !strings.HasPrefix(s.Endpoint, "http://") && !strings.HasPrefix(s.Endpoint, "https://") {
			return errors.New("s3 endpoint must be an http:// or https:// URL")
		}
	case TypeAzure:
		a := c.Azure
		if a == nil || a.Account == "" || a.AccountKey == "" || a.Container == "" {
			return errors.New("an azure tier needs account, accountKey and container")
		}
	case TypeGCS:
		g := c.GCS
		if g == nil || g.Bucket == "" {
			return errors.New("a gcs tier needs a bucket")
		}
		if g.CredentialsJSON != "" && !json.Valid([]byte(g.CredentialsJSON)) {
			return errors.New("gcs credentials must be a service-account JSON document")
		}
	default:
		return fmt.Errorf("unknown tier type %q (s3, azure or gcs)", c.Type)
	}
	return nil
}

// Redacted returns a copy with secrets masked, for listings.
func (c Config) Redacted() Config {
	const mask = "*****"
	if c.S3 != nil {
		s := *c.S3
		s.SecretKey = mask
		c.S3 = &s
	}
	if c.Azure != nil {
		a := *c.Azure
		a.AccountKey = mask
		c.Azure = &a
	}
	if c.GCS != nil {
		g := *c.GCS
		if g.CredentialsJSON != "" {
			g.CredentialsJSON = mask
		}
		c.GCS = &g
	}
	return c
}

// Store persists tier configurations where every node can read them (the
// cluster's system bucket).
type Store interface {
	Put(ctx context.Context, name string, data []byte) error
	// Get returns ErrNotFound for a missing name.
	Get(ctx context.Context, name string) ([]byte, error)
	Delete(ctx context.Context, name string) error
	List(ctx context.Context, prefix string, max int) ([]string, error)
}

// Errors.
var (
	ErrNotFound = errors.New("tier: not found")
	ErrExists   = errors.New("tier: a tier with that name already exists")
	ErrInUse    = errors.New("tier: in use")
)

// Factory builds a Backend from a configuration. The default builds the real
// ones; tests substitute fakes.
type Factory func(Config) (Backend, error)

// DefaultFactory builds the S3, Azure and GCS backends.
func DefaultFactory(c Config) (Backend, error) {
	switch c.Type {
	case TypeS3:
		return NewS3(*c.S3)
	case TypeAzure:
		return NewAzure(*c.Azure)
	case TypeGCS:
		return NewGCS(*c.GCS)
	}
	return nil, fmt.Errorf("unknown tier type %q", c.Type)
}

const (
	storePrefix = "_tiers/"
	cacheTTL    = 5 * time.Second
)

type entry struct {
	cfg     Config
	be      Backend
	expires time.Time
}

// Manager is the tier registry.
type Manager struct {
	store   Store
	factory Factory

	mu    sync.Mutex
	cache map[string]*entry
}

// NewManager returns a registry over store. A nil factory is
// DefaultFactory.
func NewManager(store Store, factory Factory) *Manager {
	if factory == nil {
		factory = DefaultFactory
	}
	return &Manager{store: store, factory: factory, cache: map[string]*entry{}}
}

// Add registers a tier. check makes it prove connectivity first.
func (m *Manager) Add(ctx context.Context, c Config, check bool) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if _, err := m.store.Get(ctx, storePrefix+c.Name+".json"); err == nil {
		return ErrExists
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}
	be, err := m.factory(c)
	if err != nil {
		return err
	}
	if check {
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := be.Check(cctx)
		cancel()
		if err != nil {
			be.Close()
			return fmt.Errorf("tier %s is not usable: %w", c.Name, err)
		}
	}
	be.Close()
	c.Created = time.Now().UTC()
	data, _ := json.Marshal(c)
	if err := m.store.Put(ctx, storePrefix+c.Name+".json", data); err != nil {
		return err
	}
	m.invalidate(c.Name)
	return nil
}

// Edit replaces the credentials of an existing tier; everything that
// identifies where objects live (type, endpoint, bucket, prefix) must stay.
func (m *Manager) Edit(ctx context.Context, c Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	old, err := m.load(ctx, c.Name)
	if err != nil {
		return err
	}
	if !sameLocation(old, c) {
		return errors.New("only credentials of a tier can be changed: its type, endpoint, bucket and prefix are where its objects are")
	}
	be, err := m.factory(c)
	if err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	err = be.Check(cctx)
	cancel()
	be.Close()
	if err != nil {
		return fmt.Errorf("tier %s is not usable: %w", c.Name, err)
	}
	c.Created = old.Created
	data, _ := json.Marshal(c)
	if err := m.store.Put(ctx, storePrefix+c.Name+".json", data); err != nil {
		return err
	}
	m.invalidate(c.Name)
	return nil
}

func sameLocation(a, b Config) bool {
	if a.Type != b.Type {
		return false
	}
	switch a.Type {
	case TypeS3:
		return a.S3.Endpoint == b.S3.Endpoint && a.S3.Bucket == b.S3.Bucket && a.S3.Prefix == b.S3.Prefix
	case TypeAzure:
		return a.Azure.Account == b.Azure.Account && a.Azure.Container == b.Azure.Container && a.Azure.Prefix == b.Azure.Prefix
	case TypeGCS:
		return a.GCS.Bucket == b.GCS.Bucket && a.GCS.Prefix == b.GCS.Prefix
	}
	return false
}

// Remove deletes a tier's registration. The caller decides whether it is in
// use (the registry cannot know which objects are stubs).
func (m *Manager) Remove(ctx context.Context, name string) error {
	if _, err := m.load(ctx, name); err != nil {
		return err
	}
	if err := m.store.Delete(ctx, storePrefix+name+".json"); err != nil {
		return err
	}
	m.invalidate(name)
	return nil
}

func (m *Manager) invalidate(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e := m.cache[name]; e != nil && e.be != nil {
		e.be.Close()
	}
	delete(m.cache, name)
}

func (m *Manager) load(ctx context.Context, name string) (Config, error) {
	data, err := m.store.Get(ctx, storePrefix+name+".json")
	if err != nil {
		return Config{}, err
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return Config{}, fmt.Errorf("tier %s: stored configuration is unreadable: %w", name, err)
	}
	return c, nil
}

// Get returns a tier's backend and configuration.
func (m *Manager) Get(ctx context.Context, name string) (Backend, Config, error) {
	m.mu.Lock()
	if e := m.cache[name]; e != nil && time.Now().Before(e.expires) {
		m.mu.Unlock()
		return e.be, e.cfg, nil
	}
	m.mu.Unlock()
	c, err := m.load(ctx, name)
	if err != nil {
		return nil, Config{}, err
	}
	be, err := m.factory(c)
	if err != nil {
		return nil, Config{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if old := m.cache[name]; old != nil && old.be != nil {
		// Another goroutine filled it; keep that one (it may be in use).
		be.Close()
		old.expires = time.Now().Add(cacheTTL)
		return old.be, old.cfg, nil
	}
	m.cache[name] = &entry{cfg: c, be: be, expires: time.Now().Add(cacheTTL)}
	return be, c, nil
}

// Exists reports whether a tier is registered.
func (m *Manager) Exists(name string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := m.store.Get(ctx, storePrefix+name+".json")
	return err == nil
}

// List returns every tier, secrets masked, by name.
func (m *Manager) List(ctx context.Context) ([]Config, error) {
	names, err := m.store.List(ctx, storePrefix, 1000)
	if err != nil {
		return nil, err
	}
	var out []Config
	for _, n := range names {
		name := strings.TrimSuffix(strings.TrimPrefix(n, storePrefix), ".json")
		c, err := m.load(ctx, name)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, c.Redacted())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Close closes every cached backend.
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for n, e := range m.cache {
		if e.be != nil {
			e.be.Close()
		}
		delete(m.cache, n)
	}
}

// ObjectName builds the name a transitioned version gets in a tier:
// "<prefix><bucket>/<uuid>". The key is not part of it (keys can be longer
// than a remote allows); it is stored as object metadata where the remote
// supports that.
func ObjectName(prefix, bucket, uuid string) string {
	return prefix + bucket + "/" + uuid
}
