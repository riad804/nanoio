// Package oidc validates OpenID Connect ID tokens: provider discovery, JWKS
// retrieval with key rotation, and JWT signature and claim checks. It uses
// the standard library only.
//
// Only asymmetric signatures are accepted (RS256/384/512, PS256/384/512,
// ES256/384/512). "none" and the HMAC algorithms are refused outright: a
// token whose algorithm the verifier chose for it is the classic route to a
// forged identity.
package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Errors a caller may test with errors.Is.
var (
	ErrMalformed = errors.New("oidc: malformed token")
	ErrSignature = errors.New("oidc: invalid token signature")
	ErrExpired   = errors.New("oidc: token expired")
	ErrNotYet    = errors.New("oidc: token not yet valid")
	ErrIssuer    = errors.New("oidc: unexpected token issuer")
	ErrAudience  = errors.New("oidc: unexpected token audience")
	ErrAlg       = errors.New("oidc: unsupported signing algorithm")
	ErrKey       = errors.New("oidc: no key matches the token")
)

// Config configures a Provider.
type Config struct {
	// ConfigURL is the discovery document URL
	// (https://issuer/.well-known/openid-configuration). http is accepted
	// only for loopback hosts.
	ConfigURL string
	// ClientID must be among the token's audiences.
	ClientID string
	// HTTP is the client used for discovery and key fetches.
	HTTP *http.Client
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// Skew is the tolerated clock difference for exp/nbf; 0 means 30s.
	Skew time.Duration
	// KeyTTL is how long a fetched key set is trusted; 0 means 1 hour.
	KeyTTL time.Duration
	// MinRefresh is the shortest interval between key-set fetches, so a
	// stream of tokens with unknown key IDs cannot make the server hammer
	// the provider; 0 means 10 seconds.
	MinRefresh time.Duration
}

// Claims are the verified claims of an ID token.
type Claims map[string]any

// Subject returns the "sub" claim.
func (c Claims) Subject() string { s, _ := c["sub"].(string); return s }

// Expiry returns the "exp" claim.
func (c Claims) Expiry() time.Time {
	if f, ok := c["exp"].(float64); ok {
		return time.Unix(int64(f), 0)
	}
	return time.Time{}
}

// Strings returns a claim as a list: a JSON string (split on commas) or an
// array of strings.
func (c Claims) Strings(name string) []string {
	switch v := c[name].(type) {
	case string:
		var out []string
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		return out
	case []any:
		var out []string
		for _, e := range v {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// Provider verifies tokens from one OpenID provider.
type Provider struct {
	cfg Config

	mu        sync.Mutex
	issuer    string
	jwksURI   string
	keys      map[string]crypto.PublicKey // by kid ("" for keys without one)
	anyKeys   []crypto.PublicKey
	fetchedAt time.Time // last key-set fetch attempt
	validTill time.Time
}

// New returns a Provider; nothing is fetched until the first Verify.
func New(cfg Config) (*Provider, error) {
	u, err := url.Parse(cfg.ConfigURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("oidc: invalid config_url %q", cfg.ConfigURL)
	}
	if err := checkScheme(u); err != nil {
		return nil, err
	}
	if cfg.ClientID == "" {
		return nil, errors.New("oidc: client_id is required")
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 15 * time.Second}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Skew == 0 {
		cfg.Skew = 30 * time.Second
	}
	if cfg.KeyTTL == 0 {
		cfg.KeyTTL = time.Hour
	}
	if cfg.MinRefresh == 0 {
		cfg.MinRefresh = 10 * time.Second
	}
	return &Provider{cfg: cfg}, nil
}

func checkScheme(u *url.URL) error {
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		h := u.Hostname()
		if h == "localhost" {
			return nil
		}
		if ip := net.ParseIP(h); ip != nil && ip.IsLoopback() {
			return nil
		}
	}
	return fmt.Errorf("oidc: %s must be https (http is accepted only for loopback hosts)", u.Redacted())
}

func (p *Provider) get(ctx context.Context, rawurl string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawurl, nil)
	if err != nil {
		return err
	}
	resp, err := p.cfg.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("oidc: %s: %s", rawurl, resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(v)
}

// discover reads the discovery document (once; the issuer and key URL are
// part of the provider's identity).
func (p *Provider) discover(ctx context.Context) error {
	if p.jwksURI != "" {
		return nil
	}
	var d struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := p.get(ctx, p.cfg.ConfigURL, &d); err != nil {
		return err
	}
	if d.Issuer == "" || d.JWKSURI == "" {
		return errors.New("oidc: discovery document lacks issuer or jwks_uri")
	}
	ju, err := url.Parse(d.JWKSURI)
	if err != nil {
		return err
	}
	if err := checkScheme(ju); err != nil {
		return err
	}
	p.issuer, p.jwksURI = d.Issuer, d.JWKSURI
	return nil
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func b64(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

func (k jwk) key() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		n, err1 := b64(k.N)
		e, err2 := b64(k.E)
		if err1 != nil || err2 != nil || len(n) == 0 || len(e) == 0 {
			return nil, errors.New("bad RSA key")
		}
		ei := new(big.Int).SetBytes(e)
		if !ei.IsInt64() || ei.Int64() < 3 || ei.Int64() > 1<<31 {
			return nil, errors.New("bad RSA exponent")
		}
		pk := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(ei.Int64())}
		if pk.N.BitLen() < 2048 {
			return nil, errors.New("RSA key shorter than 2048 bits")
		}
		return pk, nil
	case "EC":
		var c elliptic.Curve
		switch k.Crv {
		case "P-256":
			c = elliptic.P256()
		case "P-384":
			c = elliptic.P384()
		case "P-521":
			c = elliptic.P521()
		default:
			return nil, errors.New("unsupported curve " + k.Crv)
		}
		x, err1 := b64(k.X)
		y, err2 := b64(k.Y)
		if err1 != nil || err2 != nil {
			return nil, errors.New("bad EC key")
		}
		pk := &ecdsa.PublicKey{Curve: c, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !c.IsOnCurve(pk.X, pk.Y) {
			return nil, errors.New("EC point not on curve")
		}
		return pk, nil
	}
	return nil, errors.New("unsupported key type " + k.Kty)
}

// refresh refetches the key set. The caller holds p.mu.
func (p *Provider) refresh(ctx context.Context) error {
	if err := p.discover(ctx); err != nil {
		return err
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	p.fetchedAt = p.cfg.Now()
	if err := p.get(ctx, p.jwksURI, &set); err != nil {
		return err
	}
	keys := map[string]crypto.PublicKey{}
	var anon []crypto.PublicKey
	for _, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		pk, err := k.key()
		if err != nil {
			continue // one unusable key must not hide the others
		}
		if k.Kid == "" {
			anon = append(anon, pk)
		} else {
			keys[k.Kid] = pk
		}
	}
	if len(keys)+len(anon) == 0 {
		return errors.New("oidc: the provider published no usable signing keys")
	}
	// The replacement is wholesale: a key the provider withdrew stops
	// verifying at once.
	p.keys, p.anyKeys = keys, anon
	p.validTill = p.cfg.Now().Add(p.cfg.KeyTTL)
	return nil
}

// keyFor returns candidate keys for a token header.
func (p *Provider) keyFor(ctx context.Context, kid string) ([]crypto.PublicKey, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.cfg.Now()
	find := func() []crypto.PublicKey {
		if kid != "" {
			if k, ok := p.keys[kid]; ok {
				return []crypto.PublicKey{k}
			}
			return nil
		}
		out := append([]crypto.PublicKey(nil), p.anyKeys...)
		for _, k := range p.keys {
			out = append(out, k)
		}
		return out
	}
	if p.keys == nil || !now.Before(p.validTill) {
		if p.keys == nil || now.Sub(p.fetchedAt) >= p.cfg.MinRefresh {
			if err := p.refresh(ctx); err != nil && p.keys == nil {
				return nil, err
			}
		}
	}
	if ks := find(); len(ks) > 0 {
		return ks, nil
	}
	// Unknown key ID: the provider may have rotated. Refetch, but not more
	// often than MinRefresh.
	if now.Sub(p.fetchedAt) >= p.cfg.MinRefresh {
		if err := p.refresh(ctx); err != nil {
			return nil, err
		}
		if ks := find(); len(ks) > 0 {
			return ks, nil
		}
	}
	return nil, ErrKey
}

func hashFor(alg string) (crypto.Hash, bool) {
	switch alg[len(alg)-3:] {
	case "256":
		return crypto.SHA256, true
	case "384":
		return crypto.SHA384, true
	case "512":
		return crypto.SHA512, true
	}
	return 0, false
}

func verifySig(alg string, key crypto.PublicKey, signed, sig []byte) bool {
	h, ok := hashFor(alg)
	if !ok {
		return false
	}
	hh := h.New()
	hh.Write(signed)
	sum := hh.Sum(nil)
	switch {
	case strings.HasPrefix(alg, "RS"):
		pk, ok := key.(*rsa.PublicKey)
		return ok && rsa.VerifyPKCS1v15(pk, h, sum, sig) == nil
	case strings.HasPrefix(alg, "PS"):
		pk, ok := key.(*rsa.PublicKey)
		return ok && rsa.VerifyPSS(pk, h, sum, sig, nil) == nil
	case strings.HasPrefix(alg, "ES"):
		pk, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return false
		}
		size := (pk.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*size {
			return false
		}
		r := new(big.Int).SetBytes(sig[:size])
		s := new(big.Int).SetBytes(sig[size:])
		return ecdsa.Verify(pk, sum, r, s)
	}
	return false
}

var algs = map[string]bool{"RS256": true, "RS384": true, "RS512": true, "PS256": true, "PS384": true, "PS512": true,
	"ES256": true, "ES384": true, "ES512": true}

// Verify checks the token's signature, issuer, audience and validity
// period, and returns its claims.
func (p *Provider) Verify(ctx context.Context, raw string) (Claims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, ErrMalformed
	}
	hb, err1 := b64(parts[0])
	pb, err2 := b64(parts[1])
	sb, err3 := b64(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, ErrMalformed
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return nil, ErrMalformed
	}
	if !algs[hdr.Alg] {
		return nil, fmt.Errorf("%w: %q", ErrAlg, hdr.Alg)
	}
	keys, err := p.keyFor(ctx, hdr.Kid)
	if err != nil {
		return nil, err
	}
	signed := []byte(parts[0] + "." + parts[1])
	okSig := false
	for _, k := range keys {
		if verifySig(hdr.Alg, k, signed, sb) {
			okSig = true
			break
		}
	}
	if !okSig {
		return nil, ErrSignature
	}
	var c Claims
	dec := json.NewDecoder(strings.NewReader(string(pb)))
	if err := dec.Decode(&c); err != nil {
		return nil, ErrMalformed
	}
	p.mu.Lock()
	issuer := p.issuer
	p.mu.Unlock()
	if iss, _ := c["iss"].(string); iss == "" || iss != issuer {
		return nil, ErrIssuer
	}
	if !audienceOK(c, p.cfg.ClientID) {
		return nil, ErrAudience
	}
	now := p.cfg.Now()
	exp, ok := c["exp"].(float64)
	if !ok {
		return nil, fmt.Errorf("%w: no exp claim", ErrMalformed)
	}
	if !now.Before(time.Unix(int64(exp), 0).Add(p.cfg.Skew)) {
		return nil, ErrExpired
	}
	if nbf, ok := c["nbf"].(float64); ok && now.Add(p.cfg.Skew).Before(time.Unix(int64(nbf), 0)) {
		return nil, ErrNotYet
	}
	if c.Subject() == "" {
		return nil, fmt.Errorf("%w: no sub claim", ErrMalformed)
	}
	return c, nil
}

func audienceOK(c Claims, clientID string) bool {
	switch a := c["aud"].(type) {
	case string:
		return a == clientID
	case []any:
		for _, v := range a {
			if s, _ := v.(string); s == clientID {
				return true
			}
		}
	}
	return false
}
