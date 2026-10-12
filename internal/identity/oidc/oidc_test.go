package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// mockProvider is a minimal OpenID provider: discovery and a rotatable JWKS.
type mockProvider struct {
	srv *httptest.Server

	mu       sync.Mutex
	keys     map[string]crypto.Signer // kid -> private key
	jwksHits atomic.Int64
}

func newMock(t *testing.T) *mockProvider {
	t.Helper()
	m := &mockProvider{keys: map[string]crypto.Signer{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"issuer": m.srv.URL, "jwks_uri": m.srv.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		m.jwksHits.Add(1)
		m.mu.Lock()
		defer m.mu.Unlock()
		var ks []map[string]string
		for kid, k := range m.keys {
			switch pk := k.Public().(type) {
			case *rsa.PublicKey:
				ks = append(ks, map[string]string{"kty": "RSA", "kid": kid, "use": "sig",
					"n": base64.RawURLEncoding.EncodeToString(pk.N.Bytes()),
					"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pk.E)).Bytes())})
			case *ecdsa.PublicKey:
				ks = append(ks, map[string]string{"kty": "EC", "kid": kid, "use": "sig", "crv": "P-256",
					"x": base64.RawURLEncoding.EncodeToString(pk.X.Bytes()),
					"y": base64.RawURLEncoding.EncodeToString(pk.Y.Bytes())})
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"keys": ks})
	})
	m.srv = httptest.NewServer(mux)
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mockProvider) addRSA(t *testing.T, kid string) crypto.Signer {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	m.keys[kid] = k
	m.mu.Unlock()
	return k
}

func (m *mockProvider) addEC(t *testing.T, kid string) crypto.Signer {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	m.keys[kid] = k
	m.mu.Unlock()
	return k
}

func (m *mockProvider) drop(kid string) {
	m.mu.Lock()
	delete(m.keys, kid)
	m.mu.Unlock()
}

func seg(v any) string {
	b, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(b)
}

// sign builds a token with the given header alg and key.
func sign(t *testing.T, alg, kid string, key crypto.Signer, claims map[string]any) string {
	t.Helper()
	signed := seg(map[string]string{"alg": alg, "typ": "JWT", "kid": kid}) + "." + seg(claims)
	sum := sha256.Sum256([]byte(signed))
	var sig []byte
	switch k := key.(type) {
	case *rsa.PrivateKey:
		s, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, sum[:])
		if err != nil {
			t.Fatal(err)
		}
		sig = s
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, k, sum[:])
		if err != nil {
			t.Fatal(err)
		}
		sig = append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	}
	return signed + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func baseClaims(m *mockProvider, now time.Time) map[string]any {
	return map[string]any{"iss": m.srv.URL, "aud": "nanoio", "sub": "user-1",
		"exp": now.Add(time.Hour).Unix(), "iat": now.Unix(), "policy": "readonly"}
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newProvider(t *testing.T, m *mockProvider, clk *clock) *Provider {
	t.Helper()
	p, err := New(Config{ConfigURL: m.srv.URL + "/.well-known/openid-configuration", ClientID: "nanoio",
		Now: clk.Now, Skew: time.Second, KeyTTL: time.Hour, MinRefresh: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestVerifyValidAndClaims(t *testing.T) {
	m := newMock(t)
	rk := m.addRSA(t, "r1")
	ek := m.addEC(t, "e1")
	clk := &clock{t: time.Now()}
	p := newProvider(t, m, clk)
	for _, tc := range []struct {
		name, alg, kid string
		key            crypto.Signer
	}{{"rsa", "RS256", "r1", rk}, {"ec", "ES256", "e1", ek}} {
		c, err := p.Verify(context.Background(), sign(t, tc.alg, tc.kid, tc.key, baseClaims(m, clk.Now())))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if c.Subject() != "user-1" || len(c.Strings("policy")) != 1 {
			t.Fatalf("%s: claims %v", tc.name, c)
		}
	}
}

func TestTokenExpiry(t *testing.T) {
	m := newMock(t)
	k := m.addRSA(t, "r1")
	clk := &clock{t: time.Now()}
	p := newProvider(t, m, clk)
	tok := sign(t, "RS256", "r1", k, baseClaims(m, clk.Now()))
	if _, err := p.Verify(context.Background(), tok); err != nil {
		t.Fatal(err)
	}
	clk.Add(30 * time.Minute)
	if _, err := p.Verify(context.Background(), tok); err != nil {
		t.Fatalf("still valid half way through: %v", err)
	}
	clk.Add(31 * time.Minute) // past exp + skew
	if _, err := p.Verify(context.Background(), tok); !errors.Is(err, ErrExpired) {
		t.Fatalf("want ErrExpired, got %v", err)
	}
	// not yet valid
	c := baseClaims(m, clk.Now())
	c["nbf"] = clk.Now().Add(time.Hour).Unix()
	if _, err := p.Verify(context.Background(), sign(t, "RS256", "r1", k, c)); !errors.Is(err, ErrNotYet) {
		t.Fatalf("want ErrNotYet, got %v", err)
	}
}

func TestKeyRotation(t *testing.T) {
	m := newMock(t)
	old := m.addRSA(t, "old")
	clk := &clock{t: time.Now()}
	p := newProvider(t, m, clk)
	ctx := context.Background()
	if _, err := p.Verify(ctx, sign(t, "RS256", "old", old, baseClaims(m, clk.Now()))); err != nil {
		t.Fatal(err)
	}
	// The provider rotates: a new key signs; the old one is withdrawn.
	nk := m.addRSA(t, "new")
	m.drop("old")
	tokNew := sign(t, "RS256", "new", nk, baseClaims(m, clk.Now()))
	// Within MinRefresh of the last fetch an unknown kid is not refetched.
	hits := m.jwksHits.Load()
	if _, err := p.Verify(ctx, tokNew); !errors.Is(err, ErrKey) {
		t.Fatalf("want ErrKey inside the refresh floor, got %v", err)
	}
	if m.jwksHits.Load() != hits {
		t.Fatal("refetched inside the minimum refresh interval")
	}
	clk.Add(11 * time.Second)
	if _, err := p.Verify(ctx, tokNew); err != nil {
		t.Fatalf("new key after refresh: %v", err)
	}
	// The withdrawn key no longer verifies, even for a well-formed token.
	if _, err := p.Verify(ctx, sign(t, "RS256", "old", old, baseClaims(m, clk.Now()))); err == nil {
		t.Fatal("a withdrawn key still verifies")
	}
}

func TestRejects(t *testing.T) {
	m := newMock(t)
	k := m.addRSA(t, "r1")
	clk := &clock{t: time.Now()}
	p := newProvider(t, m, clk)
	ctx := context.Background()
	ok := baseClaims(m, clk.Now())
	mod := func(f func(map[string]any)) map[string]any {
		c := map[string]any{}
		for k, v := range ok {
			c[k] = v
		}
		f(c)
		return c
	}
	cases := map[string]struct {
		tok  string
		want error
	}{
		"wrong issuer":   {sign(t, "RS256", "r1", k, mod(func(c map[string]any) { c["iss"] = "https://evil" })), ErrIssuer},
		"wrong audience": {sign(t, "RS256", "r1", k, mod(func(c map[string]any) { c["aud"] = "other" })), ErrAudience},
		"no exp":         {sign(t, "RS256", "r1", k, mod(func(c map[string]any) { delete(c, "exp") })), ErrMalformed},
		"unknown kid":    {sign(t, "RS256", "zzz", k, ok), ErrKey},
		"garbage":        {"not.a.jwt", ErrMalformed},
		"two parts":      {"a.b", ErrMalformed},
	}
	for name, tc := range cases {
		if _, err := p.Verify(ctx, tc.tok); !errors.Is(err, tc.want) {
			t.Errorf("%s: want %v, got %v", name, tc.want, err)
		}
	}
	// alg=none and HMAC (key confusion) are refused before any key is tried.
	none := seg(map[string]string{"alg": "none", "kid": "r1"}) + "." + seg(ok) + "."
	if _, err := p.Verify(ctx, none); !errors.Is(err, ErrAlg) {
		t.Errorf("alg none: %v", err)
	}
	signed := seg(map[string]string{"alg": "HS256", "kid": "r1"}) + "." + seg(ok)
	mac := hmac.New(sha256.New, []byte("anything"))
	mac.Write([]byte(signed))
	hs := signed + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if _, err := p.Verify(ctx, hs); !errors.Is(err, ErrAlg) {
		t.Errorf("HS256: %v", err)
	}
	// A valid token with one signature byte flipped.
	good := sign(t, "RS256", "r1", k, ok)
	bad := good[:len(good)-2] + "AA"
	if _, err := p.Verify(ctx, bad); !errors.Is(err, ErrSignature) {
		t.Errorf("tampered signature: %v", err)
	}
	// A token signed by a key the provider does not publish, claiming a known kid.
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := p.Verify(ctx, sign(t, "RS256", "r1", other, ok)); !errors.Is(err, ErrSignature) {
		t.Errorf("foreign key: %v", err)
	}
}

func TestPlainHTTPOnlyForLoopback(t *testing.T) {
	if _, err := New(Config{ConfigURL: "http://idp.example.com/.well-known/openid-configuration", ClientID: "x"}); err == nil {
		t.Fatal("plain http to a remote host was accepted")
	}
	if _, err := New(Config{ConfigURL: "https://idp.example.com/.well-known/openid-configuration", ClientID: "x"}); err != nil {
		t.Fatal(err)
	}
}
