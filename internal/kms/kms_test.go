package kms

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var bg = context.Background()

func key(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func newLocal(t *testing.T) *Local {
	t.Helper()
	l, err := NewLocal(map[string][]LocalKey{"k": {{Version: 1, Key: key(1)}}})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestLocalRoundTripAndContext(t *testing.T) {
	l := newLocal(t)
	ctx := Context{"a": "1", "b": "2"}
	dk, err := l.GenerateKey(bg, "k", ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(dk.Plaintext) != 32 || dk.Version != 1 || dk.KeyID != "k" {
		t.Fatalf("bad data key %+v", dk)
	}
	pt, err := l.Decrypt(bg, "k", dk.Ciphertext, Context{"b": "2", "a": "1"})
	if err != nil || !bytes.Equal(pt, dk.Plaintext) {
		t.Fatalf("Decrypt = %x, %v", pt, err)
	}
	if _, err := l.Decrypt(bg, "k", dk.Ciphertext, Context{"a": "1"}); !errors.Is(err, ErrDecrypt) {
		t.Errorf("wrong context: %v, want ErrDecrypt", err)
	}
	if _, err := l.Decrypt(bg, "other", dk.Ciphertext, ctx); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("unknown key: %v", err)
	}
	bad := append([]byte(nil), dk.Ciphertext...)
	bad[len(bad)-1] ^= 1
	if _, err := l.Decrypt(bg, "k", bad, ctx); !errors.Is(err, ErrDecrypt) {
		t.Errorf("tampered: %v", err)
	}
	if _, err := l.GenerateKey(bg, "nope", nil); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("GenerateKey unknown: %v", err)
	}
}

func TestLocalRotation(t *testing.T) {
	v1, _ := NewLocal(map[string][]LocalKey{"k": {{Version: 1, Key: key(1)}}})
	old, _ := v1.GenerateKey(bg, "k", nil)
	v2, err := NewLocal(map[string][]LocalKey{"k": {{Version: 1, Key: key(1)}, {Version: 2, Key: key(2)}}})
	if err != nil {
		t.Fatal(err)
	}
	info, _ := v2.DescribeKey(bg, "k")
	if info.LatestVersion != 2 {
		t.Fatalf("LatestVersion = %d", info.LatestVersion)
	}
	pt, err := v2.Decrypt(bg, "k", old.Ciphertext, nil)
	if err != nil || !bytes.Equal(pt, old.Plaintext) {
		t.Fatalf("old wrap under v2 = %v", err)
	}
	w, err := v2.Encrypt(bg, "k", pt, nil)
	if err != nil || w.Version != 2 {
		t.Fatalf("Encrypt = %+v, %v", w, err)
	}
	if bytes.Equal(w.Ciphertext, old.Ciphertext) {
		t.Error("rewrap produced the same ciphertext")
	}
	if got, err := v2.Decrypt(bg, "k", w.Ciphertext, nil); err != nil || !bytes.Equal(got, pt) {
		t.Errorf("rewrapped decrypt: %v", err)
	}
	// Dropping v1 makes old wraps undecryptable.
	only2, _ := NewLocal(map[string][]LocalKey{"k": {{Version: 2, Key: key(2)}}})
	if _, err := only2.Decrypt(bg, "k", old.Ciphertext, nil); !errors.Is(err, ErrDecrypt) {
		t.Errorf("v1 dropped: %v", err)
	}
}

func TestLocalValidation(t *testing.T) {
	bad := []map[string][]LocalKey{
		{"k": nil},
		{"k": {{Version: 1, Key: []byte("short")}}},
		{"k": {{Version: 0, Key: key(1)}}},
		{"k": {{Version: 1, Key: key(1)}, {Version: 1, Key: key(2)}}},
	}
	for i, m := range bad {
		if _, err := NewLocal(m); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
}

func TestLoadLocalFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "keys.json")
	doc := map[string]any{"keys": map[string]any{"k": []map[string]any{{"version": 1, "key": base64.StdEncoding.EncodeToString(key(7))}}}}
	b, _ := json.Marshal(doc)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadLocalFile(p); err == nil {
		t.Error("world-readable key file accepted")
	}
	os.Chmod(p, 0o600)
	l, err := LoadLocalFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.DescribeKey(bg, "k"); err != nil {
		t.Error(err)
	}
	name, k, err := ParseSecretKey("my:" + base64.StdEncoding.EncodeToString(key(3)))
	if err != nil || name != "my" || k.Version != 1 {
		t.Errorf("ParseSecretKey = %q %+v %v", name, k, err)
	}
	if _, _, err := ParseSecretKey("nocolon"); err == nil {
		t.Error("bad secret key accepted")
	}
}

// fakeKES enforces the documented request shape.
func fakeKES(t *testing.T, apiKey string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	l := newLocal(t)
	var decrypts atomic.Int32
	mux := http.NewServeMux()
	handler := func(op string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if apiKey != "" && r.Header.Get("Authorization") != "Bearer "+apiKey {
				http.Error(w, "no", http.StatusForbidden)
				return
			}
			name := r.URL.Path[len("/v1/key/"+op+"/"):]
			var in struct{ Plaintext, Ciphertext, Context string }
			if r.Body != nil && r.Method == http.MethodPost {
				json.NewDecoder(r.Body).Decode(&in)
			}
			ctxJSON, _ := base64.StdEncoding.DecodeString(in.Context)
			var m map[string]string
			json.Unmarshal(ctxJSON, &m)
			enc := json.NewEncoder(w)
			switch op {
			case "generate":
				dk, err := l.GenerateKey(bg, name, m)
				if err != nil {
					http.Error(w, err.Error(), http.StatusNotFound)
					return
				}
				enc.Encode(map[string]string{"plaintext": base64.StdEncoding.EncodeToString(dk.Plaintext), "ciphertext": base64.StdEncoding.EncodeToString(dk.Ciphertext)})
			case "encrypt":
				pt, _ := base64.StdEncoding.DecodeString(in.Plaintext)
				c, err := l.Encrypt(bg, name, pt, m)
				if err != nil {
					http.Error(w, err.Error(), http.StatusNotFound)
					return
				}
				enc.Encode(map[string]string{"ciphertext": base64.StdEncoding.EncodeToString(c.Ciphertext)})
			case "decrypt":
				decrypts.Add(1)
				ct, _ := base64.StdEncoding.DecodeString(in.Ciphertext)
				pt, err := l.Decrypt(bg, name, ct, m)
				switch {
				case errors.Is(err, ErrKeyNotFound):
					http.Error(w, "nf", http.StatusNotFound)
				case err != nil:
					http.Error(w, "bad", http.StatusBadRequest)
				default:
					enc.Encode(map[string]string{"plaintext": base64.StdEncoding.EncodeToString(pt)})
				}
			case "describe":
				if _, err := l.DescribeKey(bg, name); err != nil {
					http.Error(w, "nf", http.StatusNotFound)
					return
				}
				enc.Encode(map[string]any{"name": name, "created_at": time.Now()})
			}
		}
	}
	for _, op := range []string{"generate", "encrypt", "decrypt", "describe"} {
		mux.HandleFunc("/v1/key/"+op+"/", handler(op))
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &decrypts
}

func TestKES(t *testing.T) {
	srv, _ := fakeKES(t, "secret")
	k, err := NewKES(KESConfig{Endpoint: srv.URL, APIKey: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := Context{"aws:s3:arn": "arn:aws:s3:::b/o"}
	dk, err := k.GenerateKey(bg, "k", ctx)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := k.Decrypt(bg, "k", dk.Ciphertext, ctx)
	if err != nil || !bytes.Equal(pt, dk.Plaintext) {
		t.Fatalf("Decrypt: %v", err)
	}
	if _, err := k.Decrypt(bg, "k", dk.Ciphertext, Context{"x": "y"}); !errors.Is(err, ErrDecrypt) {
		t.Errorf("wrong ctx: %v", err)
	}
	if _, err := k.GenerateKey(bg, "missing", nil); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("missing key: %v", err)
	}
	if _, err := k.DescribeKey(bg, "k"); err != nil {
		t.Errorf("DescribeKey: %v", err)
	}
	w, err := k.Encrypt(bg, "k", pt, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := k.Decrypt(bg, "k", w.Ciphertext, ctx); err != nil || !bytes.Equal(got, pt) {
		t.Errorf("Encrypt/Decrypt: %v", err)
	}
	bad, _ := NewKES(KESConfig{Endpoint: srv.URL, APIKey: "wrong"})
	if _, err := bad.GenerateKey(bg, "k", nil); !errors.Is(err, ErrDenied) {
		t.Errorf("bad api key: %v", err)
	}
	srv.Close()
	if _, err := k.GenerateKey(bg, "k", nil); !errors.Is(err, ErrUnavailable) {
		t.Errorf("server down: %v", err)
	}
	if _, err := NewKES(KESConfig{Endpoint: "ftp://x"}); err == nil {
		t.Error("bad endpoint accepted")
	}
}

type countKMS struct {
	KMS
	decrypts atomic.Int32
	delay    time.Duration
}

func (c *countKMS) Decrypt(ctx context.Context, id string, ct []byte, kc Context) ([]byte, error) {
	c.decrypts.Add(1)
	time.Sleep(c.delay)
	return c.KMS.Decrypt(ctx, id, ct, kc)
}

func TestCache(t *testing.T) {
	base := &countKMS{KMS: newLocal(t), delay: 20 * time.Millisecond}
	now := time.Now()
	c := NewCache(base, time.Minute, 2)
	c.now = func() time.Time { return now }
	dk, _ := base.GenerateKey(bg, "k", nil)

	// Concurrent misses share one call.
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if pt, err := c.Decrypt(bg, "k", dk.Ciphertext, nil); err != nil || !bytes.Equal(pt, dk.Plaintext) {
				t.Errorf("Decrypt: %v", err)
			}
		}()
	}
	wg.Wait()
	if n := base.decrypts.Load(); n != 1 {
		t.Fatalf("KMS decrypts = %d, want 1", n)
	}
	// Hit; and the caller may scribble on the result.
	pt, _ := c.Decrypt(bg, "k", dk.Ciphertext, nil)
	Zero(pt)
	pt2, _ := c.Decrypt(bg, "k", dk.Ciphertext, nil)
	if !bytes.Equal(pt2, dk.Plaintext) || base.decrypts.Load() != 1 {
		t.Fatal("cache returned aliased or missing data")
	}
	// Different context is a different entry.
	if _, err := c.Decrypt(bg, "k", dk.Ciphertext, Context{"x": "y"}); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("ctx mismatch through cache: %v", err)
	}
	if c.Len() != 1 {
		t.Errorf("errors were cached: len %d", c.Len())
	}
	// TTL.
	now = now.Add(2 * time.Minute)
	c.Decrypt(bg, "k", dk.Ciphertext, nil)
	if base.decrypts.Load() != 3 { // 1 + failed ctx + refresh
		t.Errorf("decrypts after TTL = %d, want 3", base.decrypts.Load())
	}
	// LRU cap.
	for i := 0; i < 5; i++ {
		d, _ := base.GenerateKey(bg, "k", Context{"i": string(rune('a' + i))})
		c.Decrypt(bg, "k", d.Ciphertext, Context{"i": string(rune('a' + i))})
	}
	if c.Len() != 2 {
		t.Errorf("Len = %d, want 2", c.Len())
	}
	// ttl 0 passes through.
	p := NewCache(base, 0, 0)
	before := base.decrypts.Load()
	p.Decrypt(bg, "k", dk.Ciphertext, nil)
	p.Decrypt(bg, "k", dk.Ciphertext, nil)
	if base.decrypts.Load()-before != 2 {
		t.Error("ttl 0 cached")
	}
}
