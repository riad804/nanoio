// Package kms is NanoIO's key management abstraction: it generates and
// unwraps the data keys that encryption at rest seals object keys under.
//
// A KMS holds key-encryption keys (KEKs). It never sees object data. The
// API layer asks it for a fresh data key (GenerateKey), and later hands the
// stored wrapped form back (Decrypt). Rotation is a property of the KMS: a
// KEK has numbered versions, new wraps use the latest, and a wrapped key
// records which version made it, so older objects keep decrypting.
//
// This package depends on the standard library only.
package kms

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// Errors a KMS returns. Callers test with errors.Is.
var (
	// ErrKeyNotFound: the named KEK does not exist.
	ErrKeyNotFound = errors.New("kms: key not found")
	// ErrDecrypt: the ciphertext does not authenticate under the key and
	// context. A wrong context, tampered data and a wrong key all land here.
	// It is permanent; do not retry.
	ErrDecrypt = errors.New("kms: decryption failed")
	// ErrDenied: the KMS refused the caller.
	ErrDenied = errors.New("kms: request denied")
	// ErrUnavailable: transport failure or a server-side error; retryable.
	ErrUnavailable = errors.New("kms: unavailable")
)

// Context is the encryption context: string pairs authenticated, not
// encrypted, with every wrap. Decrypt must present the same context.
type Context map[string]string

// Canonical returns a deterministic encoding of c (JSON with sorted keys; a
// nil and an empty context encode alike).
func (c Context) Canonical() []byte {
	if len(c) == 0 {
		return []byte("{}")
	}
	b, _ := json.Marshal(map[string]string(c)) // maps marshal with sorted keys
	return b
}

// DataKey is a fresh 32-byte key and its wrapped form.
type DataKey struct {
	KeyID string
	// Version is the KEK version that wrapped it; 0 when the KMS does not
	// expose versions.
	Version    uint32
	Plaintext  []byte
	Ciphertext []byte
}

// Wrapped is a data key wrapped under a KEK.
type Wrapped struct {
	KeyID      string
	Version    uint32
	Ciphertext []byte
}

// KeyInfo describes a KEK.
type KeyInfo struct {
	ID            string
	LatestVersion uint32
	Created       time.Time
}

// KMS is a key management service.
type KMS interface {
	// GenerateKey returns a fresh random 32-byte data key and that key
	// wrapped under the latest version of keyID.
	GenerateKey(ctx context.Context, keyID string, kctx Context) (DataKey, error)
	// Encrypt wraps plaintext under the latest version of keyID.
	Encrypt(ctx context.Context, keyID string, plaintext []byte, kctx Context) (Wrapped, error)
	// Decrypt unwraps ciphertext, whichever KEK version produced it.
	Decrypt(ctx context.Context, keyID string, ciphertext []byte, kctx Context) ([]byte, error)
	// DescribeKey reports a KEK; ErrKeyNotFound if there is none.
	DescribeKey(ctx context.Context, keyID string) (KeyInfo, error)
}

// Zero overwrites b.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
