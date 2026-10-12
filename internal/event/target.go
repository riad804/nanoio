package event

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"nanoio/internal/config"
)

// Target is a notification destination. Implementations hold their own
// connection and reconnect inside Send; they must not queue, retry or
// back off, which the manager's queue layer does for every target alike.
type Target interface {
	// Send delivers the events, in order, as one unit: nil means every
	// event was accepted by the destination, an error means the manager
	// will retry the same events (so a target should be idempotent where
	// its destination allows it). ctx carries the per-attempt timeout.
	Send(ctx context.Context, events []*Event) error
	// Close releases the connection.
	Close() error
}

// Checker is implemented by targets that can probe their destination
// without sending an event (the status endpoint uses it).
type Checker interface {
	Check(ctx context.Context) error
}

// Delivery holds the queue and retry settings every target shares. Target
// configuration structs embed it so the JSON keys sit beside the target's
// own.
type Delivery struct {
	// QueueLimit is the most undelivered events held on disk for the
	// target; beyond it new events are dropped and counted. Default 100000.
	QueueLimit int `json:"queueLimit"`
	// BatchSize is the most events handed to Send at once.
	BatchSize int `json:"batchSize"`
	// MaxAttempts is how many times a batch is attempted before it is
	// isolated and, if a single event still fails, dead-lettered. 0 uses
	// the default (10); -1 retries forever and never dead-letters.
	MaxAttempts int `json:"maxAttempts"`
	// RetryBase is the delay after the first failure; it doubles per
	// failure up to RetryMax. Defaults 1s and 1m.
	RetryBase config.Duration `json:"retryBase"`
	RetryMax  config.Duration `json:"retryMax"`
	// Timeout bounds one Send. Default 30s.
	Timeout config.Duration `json:"timeout"`
	// DeadLetterLimit bounds the dead-letter queue; the oldest entries are
	// evicted. Default 10000.
	DeadLetterLimit int `json:"deadLetterLimit"`
}

// Defaults fills unset fields. batch is the target type's default batch
// size.
func (d Delivery) Defaults(batch int) Delivery {
	if d.QueueLimit == 0 {
		d.QueueLimit = 100000
	}
	if d.BatchSize <= 0 {
		d.BatchSize = batch
	}
	if d.MaxAttempts == 0 {
		d.MaxAttempts = 10
	}
	if d.RetryBase <= 0 {
		d.RetryBase = config.Duration(time.Second)
	}
	if d.RetryMax <= 0 {
		d.RetryMax = config.Duration(time.Minute)
	}
	if d.Timeout <= 0 {
		d.Timeout = config.Duration(30 * time.Second)
	}
	if d.DeadLetterLimit <= 0 {
		d.DeadLetterLimit = 10000
	}
	return d
}

// Validate checks the shared fields.
func (d Delivery) Validate() error {
	switch {
	case d.QueueLimit < 0:
		return errors.New("queueLimit must not be negative")
	case d.BatchSize < 0 || d.BatchSize > 1000:
		return errors.New("batchSize must be between 1 and 1000")
	case d.MaxAttempts < -1:
		return errors.New("maxAttempts must be -1 (forever), 0 (default) or positive")
	case d.RetryBase < 0 || d.RetryMax < 0 || d.Timeout < 0:
		return errors.New("retryBase, retryMax and timeout must not be negative")
	case d.RetryMax > 0 && d.RetryBase > d.RetryMax:
		return errors.New("retryBase must not exceed retryMax")
	}
	return nil
}

// Spec is a configured target ready to run.
type Spec struct {
	Target   Target
	Delivery Delivery
}

// Factory builds a Spec from a target's JSON configuration. It validates the
// configuration but must not contact the destination: a destination that is
// down at startup is the queue's job, not a reason to refuse to start.
type Factory func(id string, raw json.RawMessage) (Spec, error)

// DecodeConfig strictly decodes a target's JSON into dst, rejecting unknown
// keys so a misspelt option is an error rather than a silent default.
func DecodeConfig(raw json.RawMessage, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data after the JSON document")
	}
	return nil
}

// TLS configures transport security for a target. Targets with a URL scheme
// that implies TLS (https, rediss, ssl, tls) enable it implicitly.
type TLS struct {
	Enable     bool   `json:"enable"`
	SkipVerify bool   `json:"skipVerify"`
	CA         string `json:"ca"`
	Cert       string `json:"cert"`
	Key        string `json:"key"`
}

// Config builds a *tls.Config, or nil when TLS is not enabled and nothing
// else in t asks for it.
func (t TLS) Config(serverName string) (*tls.Config, error) {
	if !t.Enable && t.CA == "" && t.Cert == "" {
		return nil, nil
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName, InsecureSkipVerify: t.SkipVerify}
	if t.CA != "" {
		pem, err := os.ReadFile(t.CA)
		if err != nil {
			return nil, fmt.Errorf("tls.ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("tls.ca: %s holds no certificates", t.CA)
		}
		cfg.RootCAs = pool
	}
	if (t.Cert == "") != (t.Key == "") {
		return nil, errors.New("tls.cert and tls.key must be set together")
	}
	if t.Cert != "" {
		c, err := tls.LoadX509KeyPair(t.Cert, t.Key)
		if err != nil {
			return nil, fmt.Errorf("tls: %w", err)
		}
		cfg.Certificates = []tls.Certificate{c}
	}
	return cfg, nil
}
