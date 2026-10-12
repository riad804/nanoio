package sse

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	mrand "math/rand/v2"
	"testing"

	"nanoio/internal/kms"
)

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

type noSeek struct{ r io.Reader }

func (n noSeek) Read(p []byte) (int, error) { return n.r.Read(p) }

func encryptPart(t *testing.T, ok []byte, num int, plain []byte) []byte {
	t.Helper()
	ct, err := io.ReadAll(NewEncrypter(bytes.NewReader(plain), PartKey(ok, num)))
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(ct)) != CipherSize(int64(len(plain))) {
		t.Fatalf("ciphertext %d bytes, CipherSize says %d", len(ct), CipherSize(int64(len(plain))))
	}
	return ct
}

func TestSizes(t *testing.T) {
	for _, n := range []int64{0, 1, ChunkSize - 1, ChunkSize, ChunkSize + 1, 3*ChunkSize + 7, 10 << 20} {
		got, err := PlainSize(CipherSize(n))
		if err != nil || got != n {
			t.Errorf("PlainSize(CipherSize(%d)) = %d, %v", n, got, err)
		}
	}
	// Sizes no plaintext produces.
	for _, c := range []int64{0, 15, 16, 17, 31, CipherSize(ChunkSize) + 1, CipherSize(ChunkSize) - 1} {
		if n, err := PlainSize(c); err == nil && CipherSize(n) != c {
			t.Errorf("PlainSize(%d) = %d accepted", c, n)
		} else if err == nil && c != CipherSize(n) {
			t.Errorf("round trip broken at %d", c)
		}
	}
	if _, err := PlainSize(16); err == nil {
		t.Error("16 bytes accepted")
	}
	if n, err := PlainSize(32); err != nil || n != 0 {
		t.Errorf("empty part = %d, %v", n, err)
	}
	// Property: bijective on a dense range.
	seen := map[int64]int64{}
	for p := int64(0); p < 3*ChunkSize+50; p += 37 {
		c := CipherSize(p)
		if q, dup := seen[c]; dup {
			t.Fatalf("plain %d and %d share cipher size %d", p, q, c)
		}
		seen[c] = p
	}
}

func TestRoundTrip(t *testing.T) {
	ok := randBytes(32)
	for _, n := range []int{0, 1, 100, ChunkSize - 1, ChunkSize, ChunkSize + 1, 2 * ChunkSize, 5*ChunkSize + 123} {
		plain := randBytes(n)
		ct := encryptPart(t, ok, 1, plain)
		dec, err := NewDecrypter(bytes.NewReader(ct), SinglePart(int64(len(ct))), ok, 0, int64(n))
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(dec)
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("n=%d: round trip failed: %v", n, err)
		}
		// Same, through a source that cannot seek.
		dec, _ = NewDecrypter(noSeek{bytes.NewReader(ct)}, SinglePart(int64(len(ct))), ok, 0, int64(n))
		if got, err := io.ReadAll(dec); err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("n=%d: non-seekable round trip failed: %v", n, err)
		}
	}
}

func TestEncryptionIsRandomized(t *testing.T) {
	ok := randBytes(32)
	p := randBytes(1000)
	if bytes.Equal(encryptPart(t, ok, 1, p), encryptPart(t, ok, 1, p)) {
		t.Fatal("two encryptions of the same part are identical (salt reused)")
	}
}

func TestRanges(t *testing.T) {
	ok := randBytes(32)
	parts := [][]byte{randBytes(3*ChunkSize + 11), randBytes(0), randBytes(ChunkSize), randBytes(70000)}
	nums := []int{1, 3, 4, 9}
	var ct []byte
	var layout Layout
	var plain []byte
	for i, p := range parts {
		c := encryptPart(t, ok, nums[i], p)
		ct = append(ct, c...)
		layout = append(layout, PartLayout{Number: nums[i], CipherSize: int64(len(c))})
		plain = append(plain, p...)
	}
	if n, err := layout.PlainSize(); err != nil || n != int64(len(plain)) {
		t.Fatalf("Layout.PlainSize = %d, %v", n, err)
	}
	cases := [][2]int64{{0, int64(len(plain))}, {0, 1}, {ChunkSize - 1, 2}, {3*ChunkSize + 5, 100}, {3 * ChunkSize, ChunkSize + 11 + 5},
		{int64(len(plain)) - 1, 1}, {100, 0}, {int64(len(plain)), 0}}
	for i := 0; i < 200; i++ {
		off := mrand.Int64N(int64(len(plain)))
		cases = append(cases, [2]int64{off, mrand.Int64N(int64(len(plain)) - off + 1)})
	}
	for _, c := range cases {
		for _, seek := range []bool{true, false} {
			var src io.Reader = bytes.NewReader(ct)
			if !seek {
				src = noSeek{src}
			}
			dec, err := NewDecrypter(src, layout, ok, c[0], c[1])
			if err != nil {
				t.Fatalf("range %v: %v", c, err)
			}
			got, err := io.ReadAll(dec)
			if err != nil || !bytes.Equal(got, plain[c[0]:c[0]+c[1]]) {
				t.Fatalf("range %v seek=%v: err=%v equal=%v", c, seek, err, bytes.Equal(got, plain[c[0]:c[0]+c[1]]))
			}
		}
	}
	if _, err := NewDecrypter(bytes.NewReader(ct), layout, ok, 0, int64(len(plain))+1); err == nil {
		t.Error("range past the end accepted")
	}
}

func TestTamperingDetected(t *testing.T) {
	ok := randBytes(32)
	plain := randBytes(3*ChunkSize + 5)
	ct := encryptPart(t, ok, 1, plain)
	read := func(ct []byte, key []byte) error {
		dec, err := NewDecrypter(bytes.NewReader(ct), SinglePart(int64(len(ct))), key, 0, int64(len(plain)))
		if err != nil {
			return err
		}
		_, err = io.ReadAll(dec)
		return err
	}
	if err := read(ct, ok); err != nil {
		t.Fatal(err)
	}
	for _, off := range []int{0, SaltSize, SaltSize + 100, len(ct) - 1} {
		c := append([]byte(nil), ct...)
		c[off] ^= 0x80
		if err := read(c, ok); !errors.Is(err, ErrCorrupt) {
			t.Errorf("flip at %d: %v", off, err)
		}
	}
	if err := read(ct, randBytes(32)); !errors.Is(err, ErrCorrupt) {
		t.Errorf("wrong key: %v", err)
	}
	// Reorder two full chunks.
	c := append([]byte(nil), ct...)
	a := SaltSize
	b := SaltSize + chunkCipherSize
	tmp := append([]byte(nil), c[a:a+chunkCipherSize]...)
	copy(c[a:], c[b:b+chunkCipherSize])
	copy(c[b:], tmp)
	if err := read(c, ok); !errors.Is(err, ErrCorrupt) {
		t.Errorf("reorder: %v", err)
	}
	// Truncate at a chunk boundary: the new last chunk is not marked final.
	trunc := ct[:SaltSize+2*chunkCipherSize]
	dec, err := NewDecrypter(bytes.NewReader(trunc), SinglePart(int64(len(trunc))), ok, 0, 2*ChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(dec); !errors.Is(err, ErrCorrupt) {
		t.Errorf("truncation: %v", err)
	}
	// Part number is part of the key: the same ciphertext under another
	// number does not decrypt.
	dec, _ = NewDecrypter(bytes.NewReader(ct), Layout{{Number: 2, CipherSize: int64(len(ct))}}, ok, 0, int64(len(plain)))
	if _, err := io.ReadAll(dec); !errors.Is(err, ErrCorrupt) {
		t.Errorf("wrong part number: %v", err)
	}
	// A short ciphertext is corrupt, not a panic.
	if _, err := NewDecrypter(bytes.NewReader(ct[:20]), SinglePart(20), ok, 0, 0); err == nil {
		t.Error("impossible size accepted")
	}
}

func TestSeal(t *testing.T) {
	d, ok := randBytes(32), randBytes(32)
	iv, sealed, err := Seal(d, ModeC, "b/o", ok)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Unseal(d, ModeC, "b/o", iv, sealed)
	if err != nil || !bytes.Equal(got, ok) {
		t.Fatalf("Unseal: %v", err)
	}
	for name, f := range map[string]func() error{
		"wrong key":  func() error { _, e := Unseal(randBytes(32), ModeC, "b/o", iv, sealed); return e },
		"wrong path": func() error { _, e := Unseal(d, ModeC, "b/other", iv, sealed); return e },
		"wrong mode": func() error { _, e := Unseal(d, ModeS3, "b/o", iv, sealed); return e },
		"wrong iv":   func() error { _, e := Unseal(d, ModeC, "b/o", randBytes(32), sealed); return e },
		"short":      func() error { _, e := Unseal(d, ModeC, "b/o", iv, sealed[:5]); return e },
	} {
		if err := f(); !errors.Is(err, ErrWrongKey) {
			t.Errorf("%s: %v", name, err)
		}
	}
	e, _ := SealETag(ok, "b/o", []byte("0123456789abcdef"))
	if d, err := UnsealETag(ok, "b/o", e); err != nil || string(d) != "0123456789abcdef" {
		t.Errorf("etag: %v", err)
	}
	if _, err := UnsealETag(ok, "b/x", e); err == nil {
		t.Error("etag unsealed under another path")
	}
}

func TestMetaRoundTripAndKeys(t *testing.T) {
	l, _ := kms.NewLocal(map[string][]kms.LocalKey{"k": {{Version: 1, Key: randBytes(32)}}})
	ctx := context.Background()
	for _, p := range []Params{
		{Mode: ModeS3, Path: "b/o", KeyID: "k"},
		{Mode: ModeKMS, Path: "b/o", KeyID: "k", Context: []byte(`{"team":"x"}`)},
		{Mode: ModeC, Path: "b/o", ClientKey: randBytes(32)},
	} {
		ok, m, err := NewObjectKey(ctx, l, p)
		if err != nil {
			t.Fatal(err)
		}
		ud := map[string]string{"x-amz-meta-a": "b"}
		m.Put(ud)
		if !Encrypted(ud) || ModeOf(ud) != p.Mode {
			t.Fatalf("%s: not marked encrypted", p.Mode)
		}
		if len(Strip(ud)) != 1 {
			t.Errorf("Strip left %v", Strip(ud))
		}
		pm, isEnc, err := ParseMeta(ud)
		if err != nil || !isEnc {
			t.Fatalf("ParseMeta: %v", err)
		}
		got, err := OpenObjectKey(ctx, l, pm, "b/o", p.ClientKey)
		if err != nil || !bytes.Equal(got, ok) {
			t.Fatalf("%s: OpenObjectKey: %v", p.Mode, err)
		}
		if _, err := OpenObjectKey(ctx, l, pm, "b/other", p.ClientKey); err == nil {
			t.Errorf("%s: opened under another path", p.Mode)
		}
		if p.Mode == ModeC {
			if _, err := OpenObjectKey(ctx, l, pm, "b/o", randBytes(32)); !errors.Is(err, ErrWrongKey) {
				t.Errorf("wrong SSE-C key: %v", err)
			}
		}
	}
	if _, _, err := NewObjectKey(ctx, nil, Params{Mode: ModeS3, Path: "b/o", KeyID: "k"}); !errors.Is(err, ErrNoKMS) {
		t.Errorf("no KMS: %v", err)
	}
	if _, err := KMSContext("b/o", []byte(`{"aws:s3:arn":"arn:aws:s3:::evil"}`)); !errors.Is(err, ErrBadContext) {
		t.Errorf("forged arn accepted: %v", err)
	}
	if _, err := KMSContext("b/o", []byte(`[1]`)); !errors.Is(err, ErrBadContext) {
		t.Errorf("non-object ctx accepted")
	}
}

func TestRewrapKMS(t *testing.T) {
	k1 := randBytes(32)
	v1, _ := kms.NewLocal(map[string][]kms.LocalKey{"k": {{Version: 1, Key: k1}}})
	ctx := context.Background()
	ok, m, err := NewObjectKey(ctx, v1, Params{Mode: ModeKMS, Path: "b/o", KeyID: "k", Context: []byte(`{"a":"b"}`)})
	if err != nil {
		t.Fatal(err)
	}
	k2 := randBytes(32)
	v2, _ := kms.NewLocal(map[string][]kms.LocalKey{"k": {{Version: 1, Key: k1}, {Version: 2, Key: k2}}})
	m2, err := RewrapKMS(ctx, v2, m, "b/o", "k")
	if err != nil {
		t.Fatal(err)
	}
	if m2.KeyVersion != 2 || bytes.Equal(m2.Wrapped, m.Wrapped) {
		t.Fatalf("not rewrapped: %+v", m2)
	}
	if !bytes.Equal(m2.Sealed, m.Sealed) || !bytes.Equal(m2.IV, m.IV) {
		t.Fatal("rewrap changed the sealed key")
	}
	got, err := OpenObjectKey(ctx, v2, m2, "b/o", nil)
	if err != nil || !bytes.Equal(got, ok) {
		t.Fatalf("open after rewrap: %v", err)
	}
	// Retire v1: the old wrap fails, the new one works.
	only2, _ := kms.NewLocal(map[string][]kms.LocalKey{"k": {{Version: 2, Key: k2}}})
	if _, err := OpenObjectKey(ctx, only2, m, "b/o", nil); err == nil {
		t.Error("old wrap opened without v1")
	}
	if got, err := OpenObjectKey(ctx, only2, m2, "b/o", nil); err != nil || !bytes.Equal(got, ok) {
		t.Errorf("new wrap without v1: %v", err)
	}
}

func FuzzDecrypt(f *testing.F) {
	ok := make([]byte, 32)
	ct, _ := io.ReadAll(NewEncrypter(bytes.NewReader([]byte("hello world")), PartKey(ok, 1)))
	f.Add(ct)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		l := SinglePart(int64(len(data)))
		n, err := l.PlainSize()
		if err != nil {
			return
		}
		dec, err := NewDecrypter(bytes.NewReader(data), l, ok, 0, n)
		if err != nil {
			return
		}
		io.Copy(io.Discard, dec)
	})
}
