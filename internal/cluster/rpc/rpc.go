// Package rpc is the authenticated request/response layer between nodes.
//
// Every call is an HTTP POST to /_nanoio/rpc/v1/<op>, signed by
// rpcauth. Arguments travel in the signed X-Nanoio-Args header or as the
// body; the response is signed too. There are no automatic retries: a
// failed call is a failed call, and the layers above (quorum logic,
// lock quorum) decide what that means. Connection reuse is the standard
// library's.
package rpc

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"nanoio/internal/cluster/rpcauth"
)

// PathPrefix is where every internal RPC lives. The whole /_nanoio/
// namespace is reserved: no valid bucket name starts with an underscore.
const PathPrefix = "/_nanoio/rpc/v1/"

// MaxBody bounds a request or response body.
const MaxBody = 64 << 20

// AdminNode is the reserved sender identity of operator tooling.
const AdminNode = "_admin"

// Error is an error reported by the remote application, as opposed to a
// transport or authentication failure.
type Error struct {
	Status int
	Code   string
	Msg    string
}

func (e *Error) Error() string { return fmt.Sprintf("remote %s: %s", e.Code, e.Msg) }

// Config configures a Client.
type Config struct {
	// Self is this node's ID. Required.
	Self string
	// Keys signs requests and verifies responses. Required.
	Keys *rpcauth.Keyring
	// Peers maps node ID to host:port.
	Peers map[string]string
	// HTTP carries the requests; nil means a default client. Tests install
	// a fault-injecting transport here.
	HTTP *http.Client
	// TLS makes the client use https. RequireTLS makes a client without TLS
	// a construction error: the cluster fails closed rather than sending
	// signed-but-readable traffic.
	TLS, RequireTLS bool
}

// Client calls other nodes.
type Client struct {
	cfg    Config
	scheme string
}

// NewClient validates cfg and returns a Client.
func NewClient(cfg Config) (*Client, error) {
	if cfg.Self == "" || cfg.Keys == nil {
		return nil, errors.New("rpc: Self and Keys are required")
	}
	if cfg.RequireTLS && !cfg.TLS {
		return nil, errors.New("rpc: inter-node TLS is required but not enabled; configure a certificate or pass --inter-node-tls-required=false for a development cluster")
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Transport: http.DefaultTransport}
	}
	c := &Client{cfg: cfg, scheme: "http"}
	if cfg.TLS {
		c.scheme = "https"
	}
	return c, nil
}

// Self is this node's ID.
func (c *Client) Self() string { return c.cfg.Self }

// Do calls op on node. args, if non-nil, is the JSON argument document sent
// in the signed header; body is the raw payload. It returns the response
// body.
func (c *Client) Do(ctx context.Context, node, op string, args, body []byte) ([]byte, error) {
	addr, ok := c.cfg.Peers[node]
	if !ok {
		return nil, fmt.Errorf("rpc: unknown node %q", node)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.scheme+"://"+addr+PathPrefix+op, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if args != nil {
		req.Header.Set(rpcauth.HeaderArgs, rpcauth.EncodeArgs(args))
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	if err := c.cfg.Keys.Sign(req, c.cfg.Self, body); err != nil {
		return nil, err
	}
	nonce, keyID := req.Header.Get(rpcauth.HeaderNonce), req.Header.Get(rpcauth.HeaderKey)
	resp, err := c.cfg.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxBody {
		return nil, errors.New("rpc: response too large")
	}
	if err := c.cfg.Keys.VerifyResponse(resp.Header, node, nonce, keyID, resp.StatusCode, data); err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		var e struct{ Code, Msg string }
		if json.Unmarshal(data, &e) != nil {
			e.Code, e.Msg = "internal", string(data)
		}
		return nil, &Error{Status: resp.StatusCode, Code: e.Code, Msg: e.Msg}
	}
	return data, nil
}

// Call is Do with JSON in and out.
func (c *Client) Call(ctx context.Context, node, op string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	data, err := c.Do(ctx, node, op, nil, body)
	if err != nil {
		return err
	}
	if out == nil || len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, out)
}

// Handler serves one op. from is the authenticated sender.
type Handler func(ctx context.Context, from string, args, body []byte) ([]byte, error)

// ErrorEncoder maps a handler error to a status and code.
type ErrorEncoder func(err error) (status int, code string)

// ServerConfig configures a Server.
type ServerConfig struct {
	Self string
	Keys *rpcauth.Keyring
	// Known reports whether a sender ID is a member of the cluster.
	Known func(node string) bool
	// RequireClientCert makes the server refuse requests that did not
	// arrive over TLS with a verified client certificate.
	RequireClientCert bool
	// Encode maps application errors to codes; nil means "internal".
	Encode ErrorEncoder
}

// Server dispatches authenticated requests to handlers.
type Server struct {
	cfg    ServerConfig
	replay *rpcauth.ReplayCache
	mu     sync.RWMutex
	ops    map[string]Handler
}

// NewServer returns a Server.
func NewServer(cfg ServerConfig) *Server {
	return &Server{cfg: cfg, replay: rpcauth.NewReplayCache(), ops: map[string]Handler{}}
}

// Handle registers op.
func (s *Server) Handle(op string, h Handler) {
	s.mu.Lock()
	s.ops[op] = h
	s.mu.Unlock()
}

// ServeHTTP implements http.Handler for paths under PathPrefix.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	reply := func(nonce, keyID string, status int, body []byte) {
		if nonce != "" {
			s.cfg.Keys.SignResponse(w.Header(), s.cfg.Self, nonce, keyID, status, body)
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(status)
		w.Write(body)
	}
	fail := func(nonce, keyID string, status int, code, msg string) {
		b, _ := json.Marshal(map[string]string{"code": code, "msg": msg})
		reply(nonce, keyID, status, b)
	}
	nonce, keyID := r.Header.Get(rpcauth.HeaderNonce), r.Header.Get(rpcauth.HeaderKey)
	if r.Method != http.MethodPost || !strings.HasPrefix(r.URL.Path, PathPrefix) {
		fail("", "", http.StatusNotFound, "notfound", "no such endpoint")
		return
	}
	if s.cfg.RequireClientCert && (r.TLS == nil || len(r.TLS.VerifiedChains) == 0) {
		fail("", "", http.StatusForbidden, "denied", "a verified client certificate is required")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBody+1))
	if err != nil || len(body) > MaxBody {
		fail("", "", http.StatusBadRequest, "badrequest", "unreadable or oversized body")
		return
	}
	from, err := s.cfg.Keys.Verify(r, body, s.replay, s.cfg.Known)
	if err != nil {
		fail("", "", http.StatusUnauthorized, "denied", err.Error())
		return
	}
	var args []byte
	if h := r.Header.Get(rpcauth.HeaderArgs); h != "" {
		if args, err = rpcauth.DecodeArgs(h); err != nil {
			fail(nonce, keyID, http.StatusBadRequest, "badrequest", "bad arguments")
			return
		}
	}
	op := strings.TrimPrefix(r.URL.Path, PathPrefix)
	s.mu.RLock()
	h := s.ops[op]
	s.mu.RUnlock()
	if h == nil {
		fail(nonce, keyID, http.StatusNotFound, "notfound", "unknown op "+op)
		return
	}
	out, err := h(r.Context(), from, args, body)
	if err != nil {
		status, code := http.StatusInternalServerError, "internal"
		if s.cfg.Encode != nil {
			status, code = s.cfg.Encode(err)
		}
		fail(nonce, keyID, status, code, err.Error())
		return
	}
	reply(nonce, keyID, http.StatusOK, out)
}

// JSON adapts a typed JSON handler.
func JSON[A, R any](f func(ctx context.Context, from string, a A) (R, error)) Handler {
	return func(ctx context.Context, from string, _, body []byte) ([]byte, error) {
		var a A
		if len(body) > 0 {
			if err := json.Unmarshal(body, &a); err != nil {
				return nil, fmt.Errorf("bad arguments: %w", err)
			}
		}
		r, err := f(ctx, from, a)
		if err != nil {
			return nil, err
		}
		return json.Marshal(r)
	}
}

// TLSClientConfig builds the client side of inter-node TLS: servers must
// present a certificate chaining to caFile, and the client presents
// certFile/keyFile when given.
func TLSClientConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("rpc: no certificates in %s", caFile)
		}
		cfg.RootCAs = pool
	}
	if certFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}

// TLSServerConfig builds the server side: the node's certificate, and
// client certificates verified against caFile when one is presented (S3
// clients need not have one; the RPC endpoints demand one).
func TLSServerConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("rpc: no certificates in %s", caFile)
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.VerifyClientCertIfGiven
	}
	return cfg, nil
}

// DefaultTimeout is the bound applied to calls whose caller has no
// deadline.
const DefaultTimeout = 30 * time.Second
