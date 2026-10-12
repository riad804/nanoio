package sse

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Prefix of every reserved metadata key. User metadata is always
// "x-amz-meta-*", so the namespaces cannot collide.
const Prefix = "x-nanoio-internal-sse-"

// Algo identifies the stream format and chunk size.
const Algo = "AES-256-GCM-64K-v1"

// Reserved metadata key names.
const (
	KeyMode       = Prefix + "mode"
	KeyAlgo       = Prefix + "algo"
	KeyIV         = Prefix + "iv"
	KeySealed     = Prefix + "sealed-key"
	KeyKMSKeyID   = Prefix + "kms-key-id"
	KeyKMSVersion = Prefix + "kms-key-version"
	KeyKMSWrapped = Prefix + "kms-wrapped"
	KeyKMSContext = Prefix + "kms-context"
	KeyETag       = Prefix + "etag"
)

// Meta is the encryption description stored with an object.
type Meta struct {
	Mode       Mode
	IV, Sealed []byte
	// KMS modes only.
	KeyID      string
	KeyVersion uint32
	Wrapped    []byte
	// Context is the client's JSON encryption context (SSE-KMS), as sent.
	Context []byte
	// ETag is the sealed plaintext MD5; empty for multipart objects.
	ETag []byte
}

// IsReserved reports whether a metadata key belongs to this package.
func IsReserved(k string) bool { return strings.HasPrefix(strings.ToLower(k), Prefix) }

// Encrypted reports whether user-defined metadata describes an encrypted
// object.
func Encrypted(ud map[string]string) bool { _, ok := ud[KeyMode]; return ok }

// ModeOf returns the mode of an encrypted object, or "".
func ModeOf(ud map[string]string) Mode { return Mode(ud[KeyMode]) }

// Strip returns a copy of ud without reserved keys.
func Strip(ud map[string]string) map[string]string {
	out := make(map[string]string, len(ud))
	for k, v := range ud {
		if !IsReserved(k) {
			out[k] = v
		}
	}
	return out
}

// Put writes m's reserved keys into ud (which must be non-nil), replacing
// any already there.
func (m *Meta) Put(ud map[string]string) {
	for k := range ud {
		if IsReserved(k) {
			delete(ud, k)
		}
	}
	b64 := base64.StdEncoding.EncodeToString
	ud[KeyMode] = string(m.Mode)
	ud[KeyAlgo] = Algo
	ud[KeyIV] = b64(m.IV)
	ud[KeySealed] = b64(m.Sealed)
	if m.Mode != ModeC {
		ud[KeyKMSKeyID] = m.KeyID
		ud[KeyKMSVersion] = strconv.FormatUint(uint64(m.KeyVersion), 10)
		ud[KeyKMSWrapped] = b64(m.Wrapped)
		if len(m.Context) > 0 {
			ud[KeyKMSContext] = b64(m.Context)
		}
	}
	if len(m.ETag) > 0 {
		ud[KeyETag] = b64(m.ETag)
	}
}

// ParseMeta reads the reserved keys. ok is false for an object that is not
// encrypted; an error means the keys are present but malformed.
func ParseMeta(ud map[string]string) (m *Meta, ok bool, err error) {
	mode, has := ud[KeyMode]
	if !has {
		return nil, false, nil
	}
	m = &Meta{Mode: Mode(mode)}
	switch m.Mode {
	case ModeS3, ModeKMS, ModeC:
	default:
		return nil, true, fmt.Errorf("sse: unknown mode %q", mode)
	}
	if a := ud[KeyAlgo]; a != Algo {
		return nil, true, fmt.Errorf("sse: unsupported algorithm %q", a)
	}
	dec := func(k string, required bool) ([]byte, error) {
		v, ok := ud[k]
		if !ok {
			if required {
				return nil, errors.New("sse: metadata " + k + " missing")
			}
			return nil, nil
		}
		b, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, errors.New("sse: metadata " + k + " malformed")
		}
		return b, nil
	}
	if m.IV, err = dec(KeyIV, true); err != nil {
		return nil, true, err
	}
	if m.Sealed, err = dec(KeySealed, true); err != nil {
		return nil, true, err
	}
	if m.ETag, err = dec(KeyETag, false); err != nil {
		return nil, true, err
	}
	if m.Mode != ModeC {
		m.KeyID = ud[KeyKMSKeyID]
		if m.KeyID == "" {
			return nil, true, errors.New("sse: metadata " + KeyKMSKeyID + " missing")
		}
		v, perr := strconv.ParseUint(ud[KeyKMSVersion], 10, 32)
		if perr != nil {
			return nil, true, errors.New("sse: metadata " + KeyKMSVersion + " malformed")
		}
		m.KeyVersion = uint32(v)
		if m.Wrapped, err = dec(KeyKMSWrapped, true); err != nil {
			return nil, true, err
		}
		if m.Context, err = dec(KeyKMSContext, false); err != nil {
			return nil, true, err
		}
	}
	return m, true, nil
}
