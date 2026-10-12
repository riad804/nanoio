package madmincrypt

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	for _, n := range []int{0, 1, 100, 64 << 10, 200_000} {
		data := make([]byte, n)
		rand.Read(data)
		enc, err := Encrypt("correct horse", data)
		if err != nil {
			t.Fatal(err)
		}
		if n > 0 && bytes.Contains(enc, data[:min(n, 16)]) && n >= 16 {
			t.Errorf("%d bytes: plaintext visible in the ciphertext", n)
		}
		got, err := Decrypt("correct horse", bytes.NewReader(enc))
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("%d bytes: %v, equal=%v", n, err, bytes.Equal(got, data))
		}
	}
}

func TestWrongKeyAndTampering(t *testing.T) {
	enc, _ := Encrypt("secret", []byte(`{"a":1}`))
	if _, err := Decrypt("other", bytes.NewReader(enc)); !errors.Is(err, ErrNotAuthentic) {
		t.Errorf("wrong key = %v", err)
	}
	bad := append([]byte(nil), enc...)
	bad[len(bad)-1] ^= 1
	if _, err := Decrypt("secret", bytes.NewReader(bad)); !errors.Is(err, ErrNotAuthentic) {
		t.Errorf("tampered = %v", err)
	}
	if _, err := Decrypt("secret", bytes.NewReader(enc[:10])); !errors.Is(err, ErrFormat) {
		t.Errorf("short = %v", err)
	}
	enc[32] = 0x7f
	if _, err := Decrypt("secret", bytes.NewReader(enc)); !errors.Is(err, ErrFormat) {
		t.Errorf("unknown AEAD = %v", err)
	}
}
