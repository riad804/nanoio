package kms

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

const keySize = 32

// LocalKey is one version of a local KEK.
type LocalKey struct {
	Version uint32 `json:"version"`
	Key     []byte `json:"key"` // 32 bytes (base64 in JSON)
}

// Local is a KMS whose KEKs are held in this process, loaded from a file or
// the environment. It is for development and single-node setups: whoever
// can read the key material can read every object wrapped under it.
type Local struct {
	keys    map[string][]LocalKey // ascending version
	created time.Time
}

// NewLocal builds a Local from keys. Every key must be 32 bytes, versions
// must be unique and non-zero within a name.
func NewLocal(keys map[string][]LocalKey) (*Local, error) {
	l := &Local{keys: map[string][]LocalKey{}, created: time.Now().UTC()}
	for name, vs := range keys {
		if name == "" || len(vs) == 0 {
			return nil, fmt.Errorf("kms: key %q has no versions", name)
		}
		cp := append([]LocalKey(nil), vs...)
		sort.Slice(cp, func(i, j int) bool { return cp[i].Version < cp[j].Version })
		for i, k := range cp {
			if len(k.Key) != keySize {
				return nil, fmt.Errorf("kms: key %q version %d is %d bytes, want %d", name, k.Version, len(k.Key), keySize)
			}
			if k.Version == 0 || (i > 0 && cp[i-1].Version == k.Version) {
				return nil, fmt.Errorf("kms: key %q has an invalid or duplicate version %d", name, k.Version)
			}
		}
		l.keys[name] = cp
	}
	return l, nil
}

// LoadLocalFile reads a key file: {"keys": {"name": [{"version": 1,
// "key": "<base64 32 bytes>"}]}}. A file readable by group or other is
// refused.
func LoadLocalFile(path string) (*Local, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("kms: %w", err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("kms: key file %s is accessible to other users (mode %04o); chmod 600 it", path, st.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("kms: %w", err)
	}
	var doc struct {
		Keys map[string][]LocalKey `json:"keys"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("kms: key file %s: %w", path, err)
	}
	return NewLocal(doc.Keys)
}

// ParseSecretKey parses "name:base64key" (MinIO's MINIO_KMS_SECRET_KEY
// form) as version 1 of the named key.
func ParseSecretKey(s string) (name string, k LocalKey, err error) {
	name, b64, ok := strings.Cut(strings.TrimSpace(s), ":")
	if !ok || name == "" {
		return "", k, errors.New("kms: secret key must be name:base64")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) != keySize {
		return "", k, errors.New("kms: secret key must be 32 bytes of standard base64")
	}
	return name, LocalKey{Version: 1, Key: raw}, nil
}

func (l *Local) latest(keyID string) (LocalKey, error) {
	vs := l.keys[keyID]
	if len(vs) == 0 {
		return LocalKey{}, ErrKeyNotFound
	}
	return vs[len(vs)-1], nil
}

func localAAD(keyID string, kctx Context) []byte {
	return append([]byte("nanoio-kms-local-v1\x00"+keyID+"\x00"), kctx.Canonical()...)
}

func (l *Local) wrap(keyID string, plaintext []byte, kctx Context) (Wrapped, error) {
	k, err := l.latest(keyID)
	if err != nil {
		return Wrapped{}, err
	}
	blk, _ := aes.NewCipher(k.Key)
	gcm, _ := cipher.NewGCM(blk)
	out := make([]byte, 4, 4+gcm.NonceSize()+len(plaintext)+gcm.Overhead())
	binary.BigEndian.PutUint32(out, k.Version)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Wrapped{}, err
	}
	out = append(out, nonce...)
	out = gcm.Seal(out, nonce, plaintext, localAAD(keyID, kctx))
	return Wrapped{KeyID: keyID, Version: k.Version, Ciphertext: out}, nil
}

// GenerateKey implements KMS.
func (l *Local) GenerateKey(_ context.Context, keyID string, kctx Context) (DataKey, error) {
	if _, err := l.latest(keyID); err != nil {
		return DataKey{}, err
	}
	pt := make([]byte, keySize)
	if _, err := rand.Read(pt); err != nil {
		return DataKey{}, err
	}
	w, err := l.wrap(keyID, pt, kctx)
	if err != nil {
		return DataKey{}, err
	}
	return DataKey{KeyID: keyID, Version: w.Version, Plaintext: pt, Ciphertext: w.Ciphertext}, nil
}

// Encrypt implements KMS.
func (l *Local) Encrypt(_ context.Context, keyID string, plaintext []byte, kctx Context) (Wrapped, error) {
	return l.wrap(keyID, plaintext, kctx)
}

// Decrypt implements KMS.
func (l *Local) Decrypt(_ context.Context, keyID string, ciphertext []byte, kctx Context) ([]byte, error) {
	vs := l.keys[keyID]
	if len(vs) == 0 {
		return nil, ErrKeyNotFound
	}
	if len(ciphertext) < 4 {
		return nil, ErrDecrypt
	}
	ver := binary.BigEndian.Uint32(ciphertext)
	var key []byte
	for _, k := range vs {
		if k.Version == ver {
			key = k.Key
		}
	}
	if key == nil {
		return nil, ErrDecrypt
	}
	blk, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(blk)
	rest := ciphertext[4:]
	if len(rest) < gcm.NonceSize()+gcm.Overhead() {
		return nil, ErrDecrypt
	}
	pt, err := gcm.Open(nil, rest[:gcm.NonceSize()], rest[gcm.NonceSize():], localAAD(keyID, kctx))
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// DescribeKey implements KMS.
func (l *Local) DescribeKey(_ context.Context, keyID string) (KeyInfo, error) {
	k, err := l.latest(keyID)
	if err != nil {
		return KeyInfo{}, err
	}
	return KeyInfo{ID: keyID, LatestVersion: k.Version, Created: l.created}, nil
}
