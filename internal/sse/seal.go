package sse

import (
	"crypto/rand"
	"errors"
)

// Mode is how an object's key is protected.
type Mode string

// The three modes.
const (
	ModeS3  Mode = "s3"
	ModeKMS Mode = "kms"
	ModeC   Mode = "c"
)

func sealingKey(d, iv []byte, mode Mode, path string) []byte {
	return hmacSum(d, iv, []byte(domain+"seal\x00"+string(mode)+"\x00"+path))
}

func sealAAD(mode Mode, path string) []byte {
	return []byte(domain + "seal\x00" + string(mode) + "\x00" + path)
}

// Seal encrypts the object key under the data key d (the KMS data key, or
// the client's SSE-C key), bound to the mode and the object's path
// ("bucket/object"). It returns the fresh iv and the sealed key.
func Seal(d []byte, mode Mode, path string, objectKey []byte) (iv, sealed []byte, err error) {
	if len(d) != KeySize || len(objectKey) != KeySize {
		return nil, nil, errors.New("sse: keys must be 32 bytes")
	}
	iv = make([]byte, 32)
	if _, err = rand.Read(iv); err != nil {
		return nil, nil, err
	}
	g := newGCM(sealingKey(d, iv, mode, path))
	n := make([]byte, g.NonceSize())
	if _, err = rand.Read(n); err != nil {
		return nil, nil, err
	}
	return iv, g.Seal(n, n, objectKey, sealAAD(mode, path)), nil
}

// Unseal recovers the object key; ErrWrongKey if d, the mode or the path is
// not what sealed it.
func Unseal(d []byte, mode Mode, path string, iv, sealed []byte) ([]byte, error) {
	if len(d) != KeySize || len(iv) != 32 {
		return nil, ErrWrongKey
	}
	g := newGCM(sealingKey(d, iv, mode, path))
	if len(sealed) < g.NonceSize()+g.Overhead() {
		return nil, ErrWrongKey
	}
	ok, err := g.Open(nil, sealed[:g.NonceSize()], sealed[g.NonceSize():], sealAAD(mode, path))
	if err != nil {
		return nil, ErrWrongKey
	}
	return ok, nil
}

func etagKey(objectKey []byte) []byte { return hmacSum(objectKey, []byte(domain+"etag")) }

// SealETag seals a plaintext digest under the object key, bound to path.
func SealETag(objectKey []byte, path string, digest []byte) ([]byte, error) {
	g := newGCM(etagKey(objectKey))
	n := make([]byte, g.NonceSize())
	if _, err := rand.Read(n); err != nil {
		return nil, err
	}
	return g.Seal(n, n, digest, []byte(domain+"etag\x00"+path)), nil
}

// UnsealETag reverses SealETag.
func UnsealETag(objectKey []byte, path string, sealed []byte) ([]byte, error) {
	g := newGCM(etagKey(objectKey))
	if len(sealed) < g.NonceSize()+g.Overhead() {
		return nil, ErrCorrupt
	}
	d, err := g.Open(nil, sealed[:g.NonceSize()], sealed[g.NonceSize():], []byte(domain+"etag\x00"+path))
	if err != nil {
		return nil, ErrCorrupt
	}
	return d, nil
}
