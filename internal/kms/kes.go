package kms

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// KES is a client of a MinIO Key Encryption Service. KES holds the KEKs and
// authenticates callers by TLS client certificate (configure it on Client's
// transport) or an API key.
type KES struct {
	endpoint string
	apiKey   string
	client   *http.Client
}

// KESConfig configures NewKES.
type KESConfig struct {
	// Endpoint is the base URL, e.g. https://kes.example:7373.
	Endpoint string
	// APIKey, if set, is sent as a bearer token.
	APIKey string
	// Client carries the TLS configuration (client certificate, CA). Nil
	// uses a client with a 10 s timeout.
	Client *http.Client
}

// NewKES returns a KES client.
func NewKES(cfg KESConfig) (*KES, error) {
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("kms: invalid KES endpoint %q", cfg.Endpoint)
	}
	c := cfg.Client
	if c == nil {
		c = &http.Client{Timeout: 10 * time.Second}
	}
	return &KES{endpoint: strings.TrimRight(cfg.Endpoint, "/"), apiKey: cfg.APIKey, client: c}, nil
}

func (k *KES) do(ctx context.Context, method, op, keyID string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, k.endpoint+"/v1/key/"+op+"/"+url.PathEscape(keyID), rd)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if k.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+k.apiKey)
	}
	resp, err := k.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	switch {
	case resp.StatusCode == http.StatusOK:
		if out == nil {
			return nil
		}
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("%w: malformed response: %v", ErrUnavailable, err)
		}
		return nil
	case resp.StatusCode == http.StatusNotFound:
		return ErrKeyNotFound
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return ErrDenied
	case resp.StatusCode == http.StatusBadRequest:
		// KES reports a failed authentication of ciphertext or context as 400.
		return ErrDecrypt
	default:
		return fmt.Errorf("%w: KES answered %d", ErrUnavailable, resp.StatusCode)
	}
}

func kesContext(c Context) string {
	return base64.StdEncoding.EncodeToString(c.Canonical())
}

// GenerateKey implements KMS.
func (k *KES) GenerateKey(ctx context.Context, keyID string, kctx Context) (DataKey, error) {
	var out struct{ Plaintext, Ciphertext string }
	if err := k.do(ctx, http.MethodPost, "generate", keyID, map[string]string{"context": kesContext(kctx)}, &out); err != nil {
		return DataKey{}, err
	}
	pt, e1 := base64.StdEncoding.DecodeString(out.Plaintext)
	ct, e2 := base64.StdEncoding.DecodeString(out.Ciphertext)
	if e1 != nil || e2 != nil || len(pt) != keySize || len(ct) == 0 {
		return DataKey{}, fmt.Errorf("%w: malformed generate response", ErrUnavailable)
	}
	return DataKey{KeyID: keyID, Plaintext: pt, Ciphertext: ct}, nil
}

// Encrypt implements KMS.
func (k *KES) Encrypt(ctx context.Context, keyID string, plaintext []byte, kctx Context) (Wrapped, error) {
	var out struct{ Ciphertext string }
	body := map[string]string{"plaintext": base64.StdEncoding.EncodeToString(plaintext), "context": kesContext(kctx)}
	if err := k.do(ctx, http.MethodPost, "encrypt", keyID, body, &out); err != nil {
		return Wrapped{}, err
	}
	ct, err := base64.StdEncoding.DecodeString(out.Ciphertext)
	if err != nil || len(ct) == 0 {
		return Wrapped{}, fmt.Errorf("%w: malformed encrypt response", ErrUnavailable)
	}
	return Wrapped{KeyID: keyID, Ciphertext: ct}, nil
}

// Decrypt implements KMS.
func (k *KES) Decrypt(ctx context.Context, keyID string, ciphertext []byte, kctx Context) ([]byte, error) {
	var out struct{ Plaintext string }
	body := map[string]string{"ciphertext": base64.StdEncoding.EncodeToString(ciphertext), "context": kesContext(kctx)}
	if err := k.do(ctx, http.MethodPost, "decrypt", keyID, body, &out); err != nil {
		return nil, err
	}
	pt, err := base64.StdEncoding.DecodeString(out.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("%w: malformed decrypt response", ErrUnavailable)
	}
	return pt, nil
}

// DescribeKey implements KMS. KES does not expose KEK versions, so
// LatestVersion is 0.
func (k *KES) DescribeKey(ctx context.Context, keyID string) (KeyInfo, error) {
	var out struct {
		Name      string    `json:"name"`
		CreatedAt time.Time `json:"created_at"`
	}
	if err := k.do(ctx, http.MethodGet, "describe", keyID, nil, &out); err != nil {
		if errors.Is(err, ErrDecrypt) {
			return KeyInfo{}, fmt.Errorf("%w: describe rejected", ErrUnavailable)
		}
		return KeyInfo{}, err
	}
	return KeyInfo{ID: keyID, Created: out.CreatedAt}, nil
}
