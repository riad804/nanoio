package sse

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"

	"nanoio/internal/kms"
)

// ARNContextKey is the encryption-context entry the server always adds:
// the object's ARN. A client may not set it to anything else.
const ARNContextKey = "aws:s3:arn"

// MaxContextSize bounds the client's JSON encryption context.
const MaxContextSize = 8 << 10

// ErrNoKMS: a KMS mode was needed and none is configured.
var ErrNoKMS = errors.New("sse: no KMS is configured")

// ErrBadContext: the encryption context is not a JSON object of strings.
var ErrBadContext = errors.New("sse: encryption context must be a JSON object of string values")

// KMSContext builds the context passed to the KMS for the object at path
// ("bucket/object") from the client's JSON context (may be empty).
func KMSContext(path string, clientJSON []byte) (kms.Context, error) {
	c := kms.Context{}
	if len(clientJSON) > 0 {
		if len(clientJSON) > MaxContextSize {
			return nil, ErrBadContext
		}
		var m map[string]string
		if err := json.Unmarshal(clientJSON, &m); err != nil {
			return nil, ErrBadContext
		}
		for k, v := range m {
			c[k] = v
		}
	}
	arn := "arn:aws:s3:::" + path
	if v, ok := c[ARNContextKey]; ok && v != arn {
		return nil, fmt.Errorf("%w: %s must be %s", ErrBadContext, ARNContextKey, arn)
	}
	c[ARNContextKey] = arn
	return c, nil
}

// Params says how to protect a new object key.
type Params struct {
	Mode Mode
	// Path is "bucket/object".
	Path string
	// KeyID and Context apply to the KMS modes.
	KeyID   string
	Context []byte // client JSON, optional
	// ClientKey is the SSE-C key.
	ClientKey []byte
}

// NewObjectKey generates a random object key and seals it as p says. The
// caller owns (and should zero) the returned key.
func NewObjectKey(ctx context.Context, k kms.KMS, p Params) (objectKey []byte, m *Meta, err error) {
	objectKey = make([]byte, KeySize)
	if _, err := rand.Read(objectKey); err != nil {
		return nil, nil, err
	}
	if m, err = Reseal(ctx, k, objectKey, p); err != nil {
		return nil, nil, err
	}
	return objectKey, m, nil
}

// OpenObjectKey recovers the object key of an encrypted object at path.
// clientKey is the SSE-C key (ignored for KMS modes). A KMS error is
// returned as is; a key that does not unseal is ErrWrongKey.
func OpenObjectKey(ctx context.Context, k kms.KMS, m *Meta, path string, clientKey []byte) ([]byte, error) {
	var d []byte
	switch m.Mode {
	case ModeC:
		if len(clientKey) != KeySize {
			return nil, ErrWrongKey
		}
		d = clientKey
	default:
		if k == nil {
			return nil, ErrNoKMS
		}
		kc, err := KMSContext(path, m.Context)
		if err != nil {
			return nil, err
		}
		if d, err = k.Decrypt(ctx, m.KeyID, m.Wrapped, kc); err != nil {
			return nil, err
		}
		defer kms.Zero(d)
	}
	return Unseal(d, m.Mode, path, m.IV, m.Sealed)
}

// Reseal produces the metadata that protects the same object key under a
// new mode, key or context, without touching the data. The object key is
// supplied (already opened from the old metadata).
func Reseal(ctx context.Context, k kms.KMS, objectKey []byte, p Params) (*Meta, error) {
	// Seal the supplied key rather than a random one.
	var d []byte
	m := &Meta{Mode: p.Mode}
	switch p.Mode {
	case ModeC:
		if len(p.ClientKey) != KeySize {
			return nil, errors.New("sse: SSE-C key must be 32 bytes")
		}
		d = p.ClientKey
	case ModeS3, ModeKMS:
		if k == nil {
			return nil, ErrNoKMS
		}
		kc, err := KMSContext(p.Path, p.Context)
		if err != nil {
			return nil, err
		}
		dk, err := k.GenerateKey(ctx, p.KeyID, kc)
		if err != nil {
			return nil, err
		}
		defer kms.Zero(dk.Plaintext)
		d = dk.Plaintext
		m.KeyID, m.KeyVersion, m.Wrapped, m.Context = p.KeyID, dk.Version, dk.Ciphertext, p.Context
	default:
		return nil, fmt.Errorf("sse: unknown mode %q", p.Mode)
	}
	var err error
	if m.IV, m.Sealed, err = Seal(d, p.Mode, p.Path, objectKey); err != nil {
		return nil, err
	}
	return m, nil
}

// RewrapKMS moves a KMS-mode object's wrapped data key to keyID's latest
// KEK version. The sealed object key, iv and data are untouched, so only
// Wrapped, KeyID and KeyVersion change. It returns a modified copy.
func RewrapKMS(ctx context.Context, k kms.KMS, m *Meta, path, keyID string) (*Meta, error) {
	if m.Mode == ModeC {
		return nil, errors.New("sse: SSE-C objects have no KMS wrap")
	}
	kc, err := KMSContext(path, m.Context)
	if err != nil {
		return nil, err
	}
	d, err := k.Decrypt(ctx, m.KeyID, m.Wrapped, kc)
	if err != nil {
		return nil, err
	}
	defer kms.Zero(d)
	w, err := k.Encrypt(ctx, keyID, d, kc)
	if err != nil {
		return nil, err
	}
	out := *m
	out.KeyID, out.KeyVersion, out.Wrapped = keyID, w.Version, w.Ciphertext
	return &out, nil
}
