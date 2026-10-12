// Package sse implements NanoIO's encryption at rest: the chunked
// AES-256-GCM stream format, key sealing, and the metadata that describes an
// encrypted object. The format is specified in docs/encryption-design.md.
//
// The package is independent of storage and HTTP; it depends on the
// standard library and internal/kms.
package sse

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	// ChunkSize is the plaintext bytes per AES-GCM chunk.
	ChunkSize = 64 << 10
	// TagSize is the GCM tag appended to each chunk.
	TagSize = 16
	// SaltSize is the random per-stream salt at the start of every part.
	SaltSize = 16
	// KeySize is the size of every key in this package.
	KeySize = 32

	chunkCipherSize = ChunkSize + TagSize

	domain = "nanoio-sse-v1/"
)

// Errors.
var (
	// ErrCorrupt: the stream is not a valid encrypted stream or failed
	// authentication (tampered, truncated, reordered, or the wrong key).
	ErrCorrupt = errors.New("sse: encrypted data is corrupt or fails authentication")
	// ErrWrongKey: the object key could not be unsealed with the key given.
	ErrWrongKey = errors.New("sse: the key does not unseal the object key")
)

// chunks returns the number of chunks of a part with the given plaintext
// size: at least one, so an empty part still carries an authenticating tag.
func chunks(plain int64) int64 {
	if plain == 0 {
		return 1
	}
	return (plain + ChunkSize - 1) / ChunkSize
}

// CipherSize is the stored size of a part whose plaintext is plain bytes.
func CipherSize(plain int64) int64 {
	return SaltSize + plain + TagSize*chunks(plain)
}

// PlainSize is the plaintext size of a stored part of cipher bytes, or
// ErrCorrupt if no plaintext size produces that length.
func PlainSize(cipher int64) (int64, error) {
	body := cipher - SaltSize
	if body < TagSize {
		return 0, ErrCorrupt
	}
	n := (body + chunkCipherSize - 1) / chunkCipherSize
	plain := body - n*TagSize
	if plain < 0 || CipherSize(plain) != cipher {
		return 0, ErrCorrupt
	}
	return plain, nil
}

func hmacSum(key []byte, parts ...[]byte) []byte {
	m := hmac.New(sha256.New, key)
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)
}

// PartKey derives the key of one part from the object key. Part numbers are
// the uploaded numbers; a single-part object is part 1.
func PartKey(objectKey []byte, partNumber int) []byte {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(partNumber))
	return hmacSum(objectKey, []byte(domain+"part"), n[:])
}

func streamKey(partKey, salt []byte) []byte {
	return hmacSum(partKey, []byte(domain+"stream"), salt)
}

func newGCM(key []byte) cipher.AEAD {
	b, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(b)
	return g
}

func nonce(i int64) []byte {
	var n [12]byte
	binary.BigEndian.PutUint64(n[4:], uint64(i))
	return n[:]
}

func chunkAAD(final bool) []byte {
	b := byte(0)
	if final {
		b = 1
	}
	return append([]byte(domain+"chunk"), b)
}

// encrypter turns a plaintext reader into one part's ciphertext stream.
type encrypter struct {
	src  io.Reader
	aead cipher.AEAD
	salt []byte
	sent bool // salt emitted

	cur, next []byte // plaintext of this chunk, read ahead of the next
	nextN     int
	haveNext  bool
	idx       int64
	out       []byte
	outPos    int
	done      bool
	err       error
}

// NewEncrypter returns a reader of the ciphertext of src, encrypted under
// partKey with a fresh random salt.
func NewEncrypter(src io.Reader, partKey []byte) io.Reader {
	salt := make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return &errReader{err}
	}
	return &encrypter{src: src, aead: newGCM(streamKey(partKey, salt)), salt: salt,
		cur: make([]byte, ChunkSize), next: make([]byte, ChunkSize)}
}

type errReader struct{ err error }

func (e *errReader) Read([]byte) (int, error) { return 0, e.err }

func (e *encrypter) Read(p []byte) (int, error) {
	for {
		if e.outPos < len(e.out) {
			n := copy(p, e.out[e.outPos:])
			e.outPos += n
			return n, nil
		}
		if e.err != nil {
			return 0, e.err
		}
		if e.done {
			return 0, io.EOF
		}
		if !e.sent {
			e.sent = true
			e.out, e.outPos = e.salt, 0
			continue
		}
		// Fill the current chunk (from read-ahead if present), then read
		// ahead one byte-run to learn whether it is the last.
		var n int
		if e.haveNext {
			e.cur, e.next = e.next, e.cur
			n = e.nextN
			e.haveNext = false
		} else {
			var err error
			n, err = io.ReadFull(e.src, e.cur)
			if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
				e.err = err
				continue
			}
		}
		final := n < ChunkSize
		if !final {
			m, err := io.ReadFull(e.src, e.next)
			if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
				e.err = err
				continue
			}
			if m == 0 {
				final = true
			} else {
				e.nextN, e.haveNext = m, true
			}
		}
		e.out = e.aead.Seal(e.out[:0], nonce(e.idx), e.cur[:n], chunkAAD(final))
		e.outPos = 0
		e.idx++
		if final {
			e.done = true
		}
	}
}

// PartLayout is one stored part of an encrypted object.
type PartLayout struct {
	Number     int   // uploaded part number (the key derivation input)
	CipherSize int64 // stored size
}

// Layout is an encrypted object's parts in storage order.
type Layout []PartLayout

// SinglePart is the layout of an object stored as one stream.
func SinglePart(cipherSize int64) Layout { return Layout{{Number: 1, CipherSize: cipherSize}} }

// PlainSize is the plaintext size of the whole object.
func (l Layout) PlainSize() (int64, error) {
	var total int64
	for _, p := range l {
		n, err := PlainSize(p.CipherSize)
		if err != nil {
			return 0, err
		}
		total += n
	}
	return total, nil
}

// PartPlainSizes returns each part's plaintext size.
func (l Layout) PartPlainSizes() ([]int64, error) {
	out := make([]int64, len(l))
	for i, p := range l {
		n, err := PlainSize(p.CipherSize)
		if err != nil {
			return nil, err
		}
		out[i] = n
	}
	return out, nil
}

// Source is what a decrypter reads ciphertext from: the object's logical
// byte stream, which starts at offset 0. If it also implements io.Seeker the
// decrypter seeks; otherwise it discards forward.
type Source io.Reader

// NewDecrypter returns a reader of plaintext bytes [off, off+length) of the
// object whose ciphertext is src and whose parts are layout, using the
// object key objectKey. A length that runs past the end is an error.
//
// Every chunk it returns data from is authenticated before any of that
// chunk's bytes are released.
func NewDecrypter(src Source, layout Layout, objectKey []byte, off, length int64) (io.Reader, error) {
	sizes, err := layout.PartPlainSizes()
	if err != nil {
		return nil, err
	}
	var total int64
	for _, s := range sizes {
		total += s
	}
	if off < 0 || length < 0 || off+length > total {
		return nil, fmt.Errorf("sse: range [%d,%d) outside object of %d bytes", off, off+length, total)
	}
	d := &decrypter{src: src, layout: layout, plain: sizes, key: objectKey, off: off, end: off + length}
	if sk, ok := src.(io.Seeker); ok {
		d.seeker = sk
	}
	d.part, d.partStart = 0, 0
	d.pos = 0
	return d, nil
}

type decrypter struct {
	src    io.Reader
	seeker io.Seeker
	layout Layout
	plain  []int64
	key    []byte
	off    int64 // next plaintext offset to produce
	end    int64

	pos       int64 // current ciphertext position of src
	part      int   // index of the part containing off
	partStart int64 // plaintext start of that part

	aead    cipher.AEAD
	curPart int // part whose aead is set, -1 if none
	buf     []byte
	bufOff  int64 // plaintext offset of buf[0]
	bufPos  int
	err     error
	inited  bool
}

func (d *decrypter) seekTo(target int64) error {
	switch {
	case target == d.pos:
		return nil
	case d.seeker != nil:
		if _, err := d.seeker.Seek(target, io.SeekStart); err != nil {
			return err
		}
	case target > d.pos:
		if _, err := io.CopyN(io.Discard, d.src, target-d.pos); err != nil {
			return err
		}
	default:
		return errors.New("sse: source cannot seek backwards")
	}
	d.pos = target
	return nil
}

func (d *decrypter) partCipherStart(i int) int64 {
	var s int64
	for _, p := range d.layout[:i] {
		s += p.CipherSize
	}
	return s
}

func (d *decrypter) Read(p []byte) (int, error) {
	if !d.inited {
		d.inited = true
		d.curPart = -1
	}
	for d.bufPos >= len(d.buf) {
		if d.err != nil {
			return 0, d.err
		}
		if d.off >= d.end {
			return 0, io.EOF
		}
		d.err = d.fill()
		if d.err != nil && d.bufPos >= len(d.buf) {
			return 0, d.err
		}
	}
	n := copy(p, d.buf[d.bufPos:])
	d.bufPos += n
	return n, nil
}

// fill decrypts the chunk containing d.off into d.buf, trimmed to the
// requested range.
func (d *decrypter) fill() error {
	// Locate the part containing d.off.
	for d.part < len(d.plain)-1 && d.off >= d.partStart+d.plain[d.part] {
		d.partStart += d.plain[d.part]
		d.part++
	}
	i := d.part
	if d.curPart != i {
		start := d.partCipherStart(i)
		if err := d.seekTo(start); err != nil {
			return err
		}
		salt := make([]byte, SaltSize)
		if _, err := io.ReadFull(d.src, salt); err != nil {
			return fmt.Errorf("%w: %v", ErrCorrupt, err)
		}
		d.pos += SaltSize
		d.aead = newGCM(streamKey(PartKey(d.key, d.layout[i].Number), salt))
		d.curPart = i
	}
	rel := d.off - d.partStart
	idx := rel / ChunkSize
	n := chunks(d.plain[i])
	plainLen := int64(ChunkSize)
	if idx == n-1 {
		plainLen = d.plain[i] - idx*ChunkSize
	}
	cs := d.partCipherStart(i) + SaltSize + idx*chunkCipherSize
	if err := d.seekTo(cs); err != nil {
		return err
	}
	ct := make([]byte, plainLen+TagSize)
	if _, err := io.ReadFull(d.src, ct); err != nil {
		return fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	d.pos += int64(len(ct))
	pt, err := d.aead.Open(ct[:0], nonce(idx), ct, chunkAAD(idx == n-1))
	if err != nil {
		return ErrCorrupt
	}
	chunkStart := d.partStart + idx*ChunkSize
	lo := d.off - chunkStart
	hi := int64(len(pt))
	if chunkStart+hi > d.end {
		hi = d.end - chunkStart
	}
	d.buf, d.bufPos = pt[lo:hi], 0
	d.off = chunkStart + hi
	// Reaching the end of a part: the next chunk is in the next part.
	return nil
}
