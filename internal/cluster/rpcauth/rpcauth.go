// Package rpcauth authenticates node-to-node requests.
//
// Every internal request carries an HMAC-SHA256 over
//
//	method ‖ path ‖ query ‖ args ‖ SHA-256(body) ‖ nodeID ‖ timestamp ‖ nonce ‖ keyID
//
// computed with a per-node key derived (HKDF-SHA256) from a cluster root
// secret and the sender's node ID. A receiver rejects timestamps outside
// ±Window, remembers (nodeID, nonce) for as long as a timestamp could still
// be accepted, and so refuses replays. Responses are signed too, bound to
// the request's nonce, so a plaintext transport cannot splice answers.
//
// Every node holds the root secret (it must be able to derive the keys of
// its peers), so this authenticates and attributes requests and defeats
// replay and cross-node reuse of captured signatures; it does not make a
// compromised node harmless. Confidentiality and peer identity come from
// TLS, which the cluster requires unless explicitly waived.
//
// Rotation: a Keyring holds several root secrets. The first signs; every
// one verifies, selected by the key ID in the request. See
// docs/cluster-operations.md for the procedure.
package rpcauth

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Window is how far a timestamp may differ from the receiver's clock.
const Window = 30 * time.Second

// MinSecretLen is the shortest accepted root secret.
const MinSecretLen = 16

// Header names.
const (
	HeaderNode     = "X-Nanoio-Node"
	HeaderKey      = "X-Nanoio-Key"
	HeaderTime     = "X-Nanoio-Time"
	HeaderNonce    = "X-Nanoio-Nonce"
	HeaderBodySum  = "X-Nanoio-Body-Sha256"
	HeaderSig      = "X-Nanoio-Sig"
	HeaderArgs     = "X-Nanoio-Args"
	HeaderRespSig  = "X-Nanoio-Resp-Sig"
	HeaderRespNode = "X-Nanoio-Resp-Node"
)

// Errors. All authentication failures wrap ErrDenied.
var (
	ErrDenied   = errors.New("rpcauth: request denied")
	ErrReplayed = fmt.Errorf("%w: replayed request", ErrDenied)
	ErrSkew     = fmt.Errorf("%w: timestamp outside the accepted window", ErrDenied)
)

// Keyring derives per-node keys from root secrets.
type Keyring struct {
	secrets [][]byte
	ids     []string
	now     func() time.Time
}

// NewKeyring returns a keyring whose first secret signs and whose secrets
// all verify.
func NewKeyring(secrets ...string) (*Keyring, error) {
	if len(secrets) == 0 {
		return nil, errors.New("rpcauth: at least one cluster secret is required")
	}
	k := &Keyring{now: time.Now}
	for i, s := range secrets {
		if len(s) < MinSecretLen {
			return nil, fmt.Errorf("rpcauth: cluster secret %d is shorter than %d bytes", i, MinSecretLen)
		}
		id, err := hkdf.Key(sha256.New, []byte(s), []byte("nanoio-rpc-v1"), "key-id", 6)
		if err != nil {
			return nil, err
		}
		kid := hex.EncodeToString(id)
		for _, have := range k.ids {
			if have == kid {
				return nil, errors.New("rpcauth: duplicate cluster secret")
			}
		}
		k.secrets = append(k.secrets, []byte(s))
		k.ids = append(k.ids, kid)
	}
	return k, nil
}

// SetClock replaces the clock (tests).
func (k *Keyring) SetClock(now func() time.Time) { k.now = now }

// CurrentKeyID is the ID of the signing secret.
func (k *Keyring) CurrentKeyID() string { return k.ids[0] }

func (k *Keyring) nodeKey(idx int, nodeID string) []byte {
	key, err := hkdf.Key(sha256.New, k.secrets[idx], []byte("nanoio-rpc-v1"), "node:"+nodeID, sha256.Size)
	if err != nil {
		panic(err) // only for an out-of-range length
	}
	return key
}

func (k *Keyring) indexOf(keyID string) int {
	for i, id := range k.ids {
		if id == keyID {
			return i
		}
	}
	return -1
}

func mac(key []byte, parts ...string) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte("NANOIO-RPC-V1"))
	for _, p := range parts {
		h.Write([]byte{'\n'})
		h.Write([]byte(p))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func bodySum(body []byte) string {
	s := sha256.Sum256(body)
	return hex.EncodeToString(s[:])
}

// Sign adds the authentication headers to r on behalf of nodeID. body is
// the exact request body.
func (k *Keyring) Sign(r *http.Request, nodeID string, body []byte) error {
	var nb [16]byte
	if _, err := io.ReadFull(rand.Reader, nb[:]); err != nil {
		return err
	}
	nonce := base64.RawURLEncoding.EncodeToString(nb[:])
	ts := strconv.FormatInt(k.now().UnixMilli(), 10)
	sum := bodySum(body)
	h := r.Header
	h.Set(HeaderNode, nodeID)
	h.Set(HeaderKey, k.ids[0])
	h.Set(HeaderTime, ts)
	h.Set(HeaderNonce, nonce)
	h.Set(HeaderBodySum, sum)
	h.Set(HeaderSig, mac(k.nodeKey(0, nodeID),
		r.Method, r.URL.Path, r.URL.RawQuery, h.Get(HeaderArgs), sum, nodeID, ts, nonce, k.ids[0]))
	return nil
}

// Verify authenticates r against body and returns the sender's node ID.
// replay may be nil to skip replay detection (only for tests).
func (k *Keyring) Verify(r *http.Request, body []byte, replay *ReplayCache, known func(nodeID string) bool) (string, error) {
	h := r.Header
	node, keyID, ts, nonce, sum, sig := h.Get(HeaderNode), h.Get(HeaderKey), h.Get(HeaderTime),
		h.Get(HeaderNonce), h.Get(HeaderBodySum), h.Get(HeaderSig)
	if node == "" || keyID == "" || ts == "" || nonce == "" || sum == "" || sig == "" {
		return "", fmt.Errorf("%w: missing authentication headers", ErrDenied)
	}
	if known != nil && !known(node) {
		return "", fmt.Errorf("%w: unknown node %q", ErrDenied, node)
	}
	idx := k.indexOf(keyID)
	if idx < 0 {
		return "", fmt.Errorf("%w: unknown key", ErrDenied)
	}
	if bodySum(body) != sum {
		return "", fmt.Errorf("%w: body does not match its digest", ErrDenied)
	}
	want := mac(k.nodeKey(idx, node), r.Method, r.URL.Path, r.URL.RawQuery, h.Get(HeaderArgs), sum, node, ts, nonce, keyID)
	if !hmac.Equal([]byte(want), []byte(sig)) {
		return "", fmt.Errorf("%w: bad signature", ErrDenied)
	}
	ms, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return "", fmt.Errorf("%w: bad timestamp", ErrDenied)
	}
	now := k.now()
	if d := now.Sub(time.UnixMilli(ms)); d > Window || d < -Window {
		return "", ErrSkew
	}
	// Only a request that is otherwise valid may occupy replay-cache space.
	if replay != nil && replay.Seen(node, nonce, now) {
		return "", ErrReplayed
	}
	return node, nil
}

// SignResponse authenticates a response to the request carrying reqNonce.
func (k *Keyring) SignResponse(w http.Header, self, reqNonce, keyID string, status int, body []byte) {
	idx := k.indexOf(keyID)
	if idx < 0 {
		idx = 0
		keyID = k.ids[0]
	}
	w.Set(HeaderRespNode, self)
	w.Set(HeaderRespSig, mac(k.nodeKey(idx, self), "RESP", reqNonce, keyID, self, strconv.Itoa(status), bodySum(body)))
}

// VerifyResponse checks a response signed by peer for the request that
// carried reqNonce under keyID.
func (k *Keyring) VerifyResponse(h http.Header, peer, reqNonce, keyID string, status int, body []byte) error {
	idx := k.indexOf(keyID)
	if idx < 0 || h.Get(HeaderRespNode) != peer {
		return fmt.Errorf("%w: response from the wrong node", ErrDenied)
	}
	want := mac(k.nodeKey(idx, peer), "RESP", reqNonce, keyID, peer, strconv.Itoa(status), bodySum(body))
	if !hmac.Equal([]byte(want), []byte(h.Get(HeaderRespSig))) {
		return fmt.Errorf("%w: bad response signature", ErrDenied)
	}
	return nil
}

// ReplayCache remembers (node, nonce) pairs for as long as a replay could
// still carry an acceptable timestamp.
type ReplayCache struct {
	mu    sync.Mutex
	seen  map[string]time.Time
	order []entry
}

type entry struct {
	key    string
	expiry time.Time
}

// NewReplayCache returns an empty cache.
func NewReplayCache() *ReplayCache { return &ReplayCache{seen: map[string]time.Time{}} }

// Seen records the pair and reports whether it had already been seen.
func (c *ReplayCache) Seen(node, nonce string, now time.Time) bool {
	key := node + "\x00" + nonce
	c.mu.Lock()
	defer c.mu.Unlock()
	// Entries expire in arrival order, so pruning only looks at the head.
	i := 0
	for ; i < len(c.order) && now.After(c.order[i].expiry); i++ {
		delete(c.seen, c.order[i].key)
	}
	c.order = c.order[i:]
	if _, dup := c.seen[key]; dup {
		return true
	}
	exp := now.Add(2*Window + time.Second)
	c.seen[key] = exp
	c.order = append(c.order, entry{key, exp})
	return false
}

// Len is the number of remembered nonces.
func (c *ReplayCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.seen)
}

// EncodeArgs is the header form of JSON arguments.
func EncodeArgs(jsonArgs []byte) string { return base64.RawURLEncoding.EncodeToString(jsonArgs) }

// DecodeArgs reverses EncodeArgs.
func DecodeArgs(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
