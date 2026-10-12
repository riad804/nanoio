// Package batch is the batch-job framework: a job is a YAML/JSON document
// (replicate, expire or keyrotate) turned into small tasks that any node of
// the cluster can claim, run with retries and a concurrency limit, and whose
// progress is reported from shared state.
//
// The package is storage-agnostic: job state lives in a Store (the system
// bucket), mutual exclusion in a Locker (the cluster lock), and what a job
// type actually does to objects is an Operation supplied by the server.
package batch

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Job types.
const (
	TypeReplicate = "replicate"
	TypeExpire    = "expire"
	TypeKeyRotate = "keyrotate"
)

// Duration is a Go duration that also accepts "d" (days) and "w" (weeks).
type Duration time.Duration

// D returns the value as a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

func parseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	for suffix, unit := range map[string]time.Duration{"d": 24 * time.Hour, "w": 7 * 24 * time.Hour} {
		if strings.HasSuffix(s, suffix) {
			n, err := strconv.ParseFloat(strings.TrimSuffix(s, suffix), 64)
			if err != nil || n < 0 {
				return 0, fmt.Errorf("bad duration %q", s)
			}
			return time.Duration(n * float64(unit)), nil
		}
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("bad duration %q", s)
	}
	return d, nil
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := parseDuration(n.Value)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := parseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// MarshalJSON implements json.Marshaler.
func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(d.D().String()) }

// Tag is a key/value tag condition.
type Tag struct {
	Key   string `yaml:"key" json:"key"`
	Value string `yaml:"value" json:"value"`
}

// Filter selects objects. Every set condition must hold.
type Filter struct {
	// OlderThan and NewerThan compare the object's age to the clock.
	OlderThan Duration `yaml:"olderThan" json:"olderThan,omitempty"`
	NewerThan Duration `yaml:"newerThan" json:"newerThan,omitempty"`
	// CreatedBefore and CreatedAfter are absolute (RFC 3339).
	CreatedBefore *time.Time `yaml:"createdBefore" json:"createdBefore,omitempty"`
	CreatedAfter  *time.Time `yaml:"createdAfter" json:"createdAfter,omitempty"`
	// Tags: the object must carry every one.
	Tags    []Tag  `yaml:"tags" json:"tags,omitempty"`
	MinSize *int64 `yaml:"minSize" json:"minSize,omitempty"`
	MaxSize *int64 `yaml:"maxSize" json:"maxSize,omitempty"`
}

// Retry says how a failed object is retried.
type Retry struct {
	Attempts int      `yaml:"attempts" json:"attempts,omitempty"`
	Delay    Duration `yaml:"delay" json:"delay,omitempty"`
}

// Credentials of a remote S3 endpoint.
type Credentials struct {
	AccessKey string `yaml:"accessKey" json:"accessKey"`
	SecretKey string `yaml:"secretKey" json:"secretKey"`
}

// Source names what a replicate job reads.
type Source struct {
	Bucket string `yaml:"bucket" json:"bucket"`
	Prefix string `yaml:"prefix" json:"prefix,omitempty"`
}

// Target is the remote S3 endpoint a replicate job writes to.
type Target struct {
	Endpoint    string      `yaml:"endpoint" json:"endpoint"`
	Region      string      `yaml:"region" json:"region,omitempty"`
	Bucket      string      `yaml:"bucket" json:"bucket"`
	Prefix      string      `yaml:"prefix" json:"prefix,omitempty"`
	Credentials Credentials `yaml:"credentials" json:"credentials"`
	// InsecureSkipVerify disables certificate verification (tests).
	InsecureSkipVerify bool `yaml:"insecureSkipVerify" json:"insecureSkipVerify,omitempty"`
}

// Common holds what every job type shares.
type Common struct {
	Filter Filter `yaml:"filter" json:"filter,omitempty"`
	Retry  Retry  `yaml:"retry" json:"retry,omitempty"`
	// Concurrency bounds how many tasks of this job run at once across the
	// whole cluster (default 2).
	Concurrency int `yaml:"concurrency" json:"concurrency,omitempty"`
}

// ReplicateSpec copies the latest version of matching objects to a remote
// S3 endpoint. Objects already present with the same source ETag are
// skipped, so a job can be restarted or repeated safely.
type ReplicateSpec struct {
	Common `yaml:",inline"`
	Source Source `yaml:"source" json:"source"`
	Target Target `yaml:"target" json:"target"`
}

// ExpireSpec deletes matching objects.
type ExpireSpec struct {
	Common `yaml:",inline"`
	Bucket string `yaml:"bucket" json:"bucket"`
	Prefix string `yaml:"prefix" json:"prefix,omitempty"`
	// Versions is "latest" (default: what DELETE does: a delete marker in a
	// versioned bucket), "noncurrent" (permanently remove older versions)
	// or "all" (permanently remove every version and marker).
	Versions string `yaml:"versions" json:"versions,omitempty"`
}

// Encryption names the target of a key rotation.
type Encryption struct {
	// Type is "sse-kms" (rotate SSE-KMS objects to Key) or "sse-s3"
	// (rotate SSE-S3 objects to the latest version of the server's key).
	Type string `yaml:"type" json:"type"`
	Key  string `yaml:"key" json:"key,omitempty"`
}

// KeyRotateSpec re-wraps the data keys of encrypted objects; object data is
// never read or rewritten.
type KeyRotateSpec struct {
	Common     `yaml:",inline"`
	Bucket     string     `yaml:"bucket" json:"bucket"`
	Prefix     string     `yaml:"prefix" json:"prefix,omitempty"`
	Encryption Encryption `yaml:"encryption" json:"encryption"`
}

// Definition is a parsed job document: exactly one of the sections is set.
type Definition struct {
	APIVersion string         `yaml:"apiVersion" json:"apiVersion"`
	Replicate  *ReplicateSpec `yaml:"replicate" json:"replicate,omitempty"`
	Expire     *ExpireSpec    `yaml:"expire" json:"expire,omitempty"`
	KeyRotate  *KeyRotateSpec `yaml:"keyrotate" json:"keyrotate,omitempty"`
}

// Parse reads a YAML (or JSON, which YAML contains) job document, rejecting
// unknown fields, and validates it.
func Parse(doc []byte) (*Definition, error) {
	if len(doc) > 1<<20 {
		return nil, errors.New("job definition is larger than 1 MiB")
	}
	dec := yaml.NewDecoder(bytes.NewReader(doc))
	dec.KnownFields(true)
	var d Definition
	if err := dec.Decode(&d); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("the job definition is empty")
		}
		return nil, fmt.Errorf("invalid job definition: %w", err)
	}
	if err := d.Validate(); err != nil {
		return nil, err
	}
	return &d, nil
}

// Type reports which job type the definition holds.
func (d *Definition) Type() string {
	switch {
	case d.Replicate != nil:
		return TypeReplicate
	case d.Expire != nil:
		return TypeExpire
	case d.KeyRotate != nil:
		return TypeKeyRotate
	}
	return ""
}

// Common returns the shared settings of whichever section is set.
func (d *Definition) Common() *Common {
	switch {
	case d.Replicate != nil:
		return &d.Replicate.Common
	case d.Expire != nil:
		return &d.Expire.Common
	case d.KeyRotate != nil:
		return &d.KeyRotate.Common
	}
	return nil
}

// Validate checks a definition and fills defaults.
func (d *Definition) Validate() error {
	if d.APIVersion != "" && d.APIVersion != "v1" {
		return fmt.Errorf("apiVersion %q is not supported (use v1)", d.APIVersion)
	}
	n := 0
	for _, set := range []bool{d.Replicate != nil, d.Expire != nil, d.KeyRotate != nil} {
		if set {
			n++
		}
	}
	if n != 1 {
		return errors.New("a job definition has exactly one of replicate, expire or keyrotate")
	}
	c := d.Common()
	if c.Concurrency < 0 || c.Concurrency > 64 {
		return errors.New("concurrency must be between 1 and 64")
	}
	if c.Concurrency == 0 {
		c.Concurrency = 2
	}
	if c.Retry.Attempts < 0 || c.Retry.Attempts > 20 {
		return errors.New("retry.attempts must be between 1 and 20")
	}
	if c.Retry.Attempts == 0 {
		c.Retry.Attempts = 3
	}
	if c.Retry.Delay == 0 {
		c.Retry.Delay = Duration(time.Second)
	}
	if err := c.Filter.validate(); err != nil {
		return err
	}
	switch {
	case d.Replicate != nil:
		r := d.Replicate
		t := r.Target
		switch {
		case r.Source.Bucket == "":
			return errors.New("replicate.source.bucket is required")
		case t.Endpoint == "" || (!strings.HasPrefix(t.Endpoint, "http://") && !strings.HasPrefix(t.Endpoint, "https://")):
			return errors.New("replicate.target.endpoint must be an http:// or https:// URL")
		case t.Bucket == "":
			return errors.New("replicate.target.bucket is required")
		case t.Credentials.AccessKey == "" || t.Credentials.SecretKey == "":
			return errors.New("replicate.target.credentials need accessKey and secretKey")
		}
	case d.Expire != nil:
		e := d.Expire
		if e.Bucket == "" {
			return errors.New("expire.bucket is required")
		}
		switch e.Versions {
		case "":
			e.Versions = "latest"
		case "latest", "noncurrent", "all":
		default:
			return fmt.Errorf("expire.versions %q must be latest, noncurrent or all", e.Versions)
		}
		if e.Prefix == "" && c.Filter.isEmpty() && e.Versions != "latest" {
			return errors.New("an expire job that removes versions permanently needs a prefix or a filter, so it cannot empty a whole bucket by accident")
		}
	case d.KeyRotate != nil:
		k := d.KeyRotate
		if k.Bucket == "" {
			return errors.New("keyrotate.bucket is required")
		}
		switch k.Encryption.Type {
		case "sse-kms":
			if k.Encryption.Key == "" {
				return errors.New("keyrotate.encryption.key is required for sse-kms")
			}
		case "sse-s3":
			if k.Encryption.Key != "" {
				return errors.New("keyrotate.encryption.key is not used with sse-s3 (the server's key is used)")
			}
		default:
			return errors.New("keyrotate.encryption.type must be sse-kms or sse-s3")
		}
	}
	return nil
}

func (f *Filter) isEmpty() bool {
	return f.OlderThan == 0 && f.NewerThan == 0 && f.CreatedBefore == nil && f.CreatedAfter == nil &&
		len(f.Tags) == 0 && f.MinSize == nil && f.MaxSize == nil
}

func (f *Filter) validate() error {
	for _, t := range f.Tags {
		if t.Key == "" {
			return errors.New("filter.tags entries need a key")
		}
	}
	if f.MinSize != nil && f.MaxSize != nil && *f.MaxSize < *f.MinSize {
		return errors.New("filter.maxSize is smaller than filter.minSize")
	}
	if f.OlderThan > 0 && f.NewerThan > 0 && f.NewerThan.D() >= f.OlderThan.D() {
		return errors.New("filter.newerThan must be smaller than filter.olderThan")
	}
	return nil
}

// Matches reports whether an object with this modification time, size and
// tags passes the filter at instant now.
func (f *Filter) Matches(mod time.Time, size int64, tags map[string]string, now time.Time) bool {
	age := now.Sub(mod)
	switch {
	case f.OlderThan > 0 && age < f.OlderThan.D():
		return false
	case f.NewerThan > 0 && age > f.NewerThan.D():
		return false
	case f.CreatedBefore != nil && !mod.Before(*f.CreatedBefore):
		return false
	case f.CreatedAfter != nil && !mod.After(*f.CreatedAfter):
		return false
	case f.MinSize != nil && size < *f.MinSize:
		return false
	case f.MaxSize != nil && size > *f.MaxSize:
		return false
	}
	for _, t := range f.Tags {
		if v, ok := tags[t.Key]; !ok || (t.Value != "" && v != t.Value) {
			return false
		}
	}
	return true
}
