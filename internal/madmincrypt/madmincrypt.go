// Package madmincrypt implements the envelope MinIO's admin API puts around
// sensitive request and response bodies (user secrets, configuration,
// service-account credentials): the body is encrypted with a key derived
// from the caller's own secret key, so neither a proxy nor a log sees it.
//
// Layout, as written by every MinIO admin client and server:
//
//	salt(32) | AEAD id(1) | nonce(8) | DARE-encrypted data
//
// The key is Argon2id(password, salt, t=1, m=64 MiB, p=4) -> 32 bytes. The
// data stream is the "sio" DARE format with AES-256-GCM or ChaCha20-Poly1305.
package madmincrypt

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"sync"

	"github.com/secure-io/sio-go"
	"golang.org/x/crypto/argon2"
)

// AEAD ids.
const (
	idArgon2idAESGCM  = 0x00
	idArgon2idChaCha  = 0x01
	argon2Time        = 1
	argon2Memory      = 64 * 1024
	argon2Threads     = 4
	headerLen         = 32 + 1 + 8
	maxEncryptedBytes = 32 << 20
)

// ErrNotAuthentic means the data does not decrypt under the password: a
// wrong secret key or tampered bytes.
var ErrNotAuthentic = errors.New("madmincrypt: the data is not authentic or the key is wrong")

// ErrFormat means the data is not in the envelope format.
var ErrFormat = errors.New("madmincrypt: unexpected header")

// argon2 is memory- and CPU-hungry; concurrent derivations gain nothing.
var argonMu sync.Mutex

func deriveKey(password string, salt []byte) []byte {
	argonMu.Lock()
	defer argonMu.Unlock()
	return argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, 32)
}

// Encrypt seals data under a key derived from password.
func Encrypt(password string, data []byte) ([]byte, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key := deriveKey(password, salt)
	// AES-GCM everywhere: every platform this server targets has AES
	// support, and the envelope id lets clients that prefer ChaCha read it
	// either way.
	stream, err := sio.AES_256_GCM.Stream(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, stream.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	out.Grow(headerLen + len(data) + int(stream.Overhead(int64(len(data)))))
	out.Write(salt)
	out.WriteByte(idArgon2idAESGCM)
	out.Write(nonce)
	w := stream.EncryptWriter(&out, nonce, nil)
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// Decrypt opens an envelope produced by Encrypt (or by MinIO's clients).
func Decrypt(password string, r io.Reader) ([]byte, error) {
	var hdr [headerLen]byte
	if _, err := io.ReadFull(io.LimitReader(r, headerLen), hdr[:]); err != nil {
		return nil, ErrFormat
	}
	salt, id, nonce := hdr[:32], hdr[32], hdr[33:41]
	key := deriveKey(password, salt)
	var (
		stream *sio.Stream
		err    error
	)
	switch id {
	case idArgon2idAESGCM:
		stream, err = sio.AES_256_GCM.Stream(key)
	case idArgon2idChaCha:
		stream, err = sio.ChaCha20Poly1305.Stream(key)
	default:
		return nil, ErrFormat
	}
	if err != nil {
		return nil, err
	}
	out, err := io.ReadAll(io.LimitReader(stream.DecryptReader(r, nonce, nil), maxEncryptedBytes))
	if err != nil {
		if errors.Is(err, sio.NotAuthentic) {
			return nil, ErrNotAuthentic
		}
		return nil, err
	}
	return out, nil
}
