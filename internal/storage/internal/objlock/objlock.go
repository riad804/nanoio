// Package objlock holds the object lock logic fs and xl share: converting
// between storage and meta representations, the bucket's persisted
// configuration document, and deciding the lock a new version gets.
// Keeping it in one place is what keeps the two backends from drifting.
package objlock

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"nanoio/internal/meta"
	"nanoio/internal/storage"
)

// Info returns the storage view of a version's lock.
func Info(l *meta.Lock) (storage.Retention, bool) {
	if l.Empty() {
		return storage.Retention{}, false
	}
	var r storage.Retention
	if l.Mode != "" {
		r = storage.Retention{Mode: storage.RetentionMode(l.Mode), Until: l.RetainUntil.UTC()}
	}
	return r, l.LegalHold
}

// ToMeta builds the lock a version stores: nil when there is nothing to
// store.
func ToMeta(r storage.Retention, hold bool) *meta.Lock {
	l := &meta.Lock{Mode: meta.LockMode(r.Mode), RetainUntil: r.Until, LegalHold: hold}
	return l.Normalized()
}

// Err translates a meta lock refusal into the storage sentinel, leaving
// other errors alone. The reason travels in the wrapped text for logs; the
// API layer does not show it to clients.
func Err(err error, bucket, object string) error {
	if err == nil || !errors.Is(err, meta.ErrLocked) {
		return err
	}
	return storage.Wrap(fmt.Errorf("%w: %v", storage.ErrObjectLocked, err), bucket, object)
}

// Guard builds the guard for a change judged at now.
func Guard(now time.Time, bypass bool) meta.Guard {
	return meta.Guard{Now: now.UTC(), BypassGovernance: bypass}
}

// Resolve decides the lock a new version gets: its explicit retention and
// legal hold, or the bucket's default retention when it names none. A bucket
// without object lock accepts no lock at all.
func Resolve(cfg storage.ObjectLockConfig, o storage.PutOptions, now time.Time) (*meta.Lock, error) {
	if !cfg.Enabled {
		if !o.Retention.IsZero() || o.LegalHold {
			return nil, storage.ErrObjectLockNotEnabled
		}
		return nil, nil
	}
	if err := o.Retention.Validate(now); err != nil {
		return nil, err
	}
	r := o.Retention
	if r.IsZero() && cfg.Default != nil {
		r = storage.Retention{Mode: cfg.Default.Mode, Until: cfg.Default.Until(now)}
	}
	return ToMeta(r, o.LegalHold), nil
}

// configDoc is the persisted form of storage.ObjectLockConfig.
type configDoc struct {
	Enabled bool        `json:"enabled"`
	Default *defaultDoc `json:"default,omitempty"`
}

type defaultDoc struct {
	Mode  string `json:"mode"`
	Days  int    `json:"days,omitempty"`
	Years int    `json:"years,omitempty"`
}

// Encode returns the document stored in a bucket's marker. A bucket without
// object lock has no document ("").
func Encode(cfg storage.ObjectLockConfig) string {
	if !cfg.Enabled {
		return ""
	}
	d := configDoc{Enabled: true}
	if cfg.Default != nil {
		d.Default = &defaultDoc{Mode: string(cfg.Default.Mode), Days: cfg.Default.Days, Years: cfg.Default.Years}
	}
	b, _ := json.Marshal(d)
	return string(b)
}

// Decode parses a stored document. An unreadable one is an error rather
// than "no lock": reading a corrupt marker as an unlocked bucket would let
// writes go unprotected.
func Decode(s string) (storage.ObjectLockConfig, error) {
	if s == "" {
		return storage.ObjectLockConfig{}, nil
	}
	var d configDoc
	if err := json.Unmarshal([]byte(s), &d); err != nil {
		return storage.ObjectLockConfig{}, fmt.Errorf("%w: object lock configuration: %v", storage.ErrCorrupted, err)
	}
	cfg := storage.ObjectLockConfig{Enabled: d.Enabled}
	if d.Default != nil {
		dr := storage.DefaultRetention{Mode: storage.RetentionMode(d.Default.Mode), Days: d.Default.Days, Years: d.Default.Years}
		if err := dr.Validate(); err != nil {
			return storage.ObjectLockConfig{}, fmt.Errorf("%w: object lock configuration: %v", storage.ErrCorrupted, err)
		}
		cfg.Default = &dr
	}
	return cfg, nil
}

// CheckConfig validates a configuration a caller wants to store on a bucket
// whose current configuration is cur.
func CheckConfig(cur, next storage.ObjectLockConfig) error {
	switch {
	case !cur.Enabled:
		return fmt.Errorf("%w: object lock can only be enabled when the bucket is created", storage.ErrInvalidBucketState)
	case !next.Enabled:
		return fmt.Errorf("%w: object lock cannot be disabled", storage.ErrInvalidBucketState)
	case next.Default != nil:
		return next.Default.Validate()
	}
	return nil
}

// Requested is the lock a multipart upload was started with, as stored in
// the upload's descriptor.
type Requested struct {
	Mode      string    `json:"retentionMode,omitempty"`
	Until     time.Time `json:"retainUntil,omitzero"`
	LegalHold bool      `json:"legalHold,omitempty"`
}

// Request captures the lock asked for at initiation. It validates it
// against the bucket now, so an upload that could never complete (no object
// lock on the bucket, a date already past) is refused up front.
func Request(cfg storage.ObjectLockConfig, o storage.PutOptions, now time.Time) (Requested, error) {
	if _, err := Resolve(cfg, o, now); err != nil {
		return Requested{}, err
	}
	return Requested{Mode: string(o.Retention.Mode), Until: o.Retention.Until.UTC(), LegalHold: o.LegalHold}, nil
}

// Carry merges the lock requested at initiation into the options given at
// completion. Retention whose date passed while the parts were uploading is
// dropped: it would protect nothing, and failing then would throw away the
// upload.
func Carry(o storage.PutOptions, r Requested, now time.Time) storage.PutOptions {
	if o.Retention.IsZero() && r.Mode != "" && r.Until.After(now) {
		o.Retention = storage.Retention{Mode: storage.RetentionMode(r.Mode), Until: r.Until}
	}
	o.LegalHold = o.LegalHold || r.LegalHold
	return o
}
