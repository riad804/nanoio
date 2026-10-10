// Package faultnet is an in-process network for tests. Handlers register
// under an address; each node gets a RoundTripper that delivers requests
// straight to the destination's handler unless a fault rule says
// otherwise. Faults are explicit and deterministic: partitions, one-way
// blocks, node crashes, added latency, and "processed but the response was
// lost", which is the case that makes distributed writes indeterminate.
package faultnet

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"
)

// ErrUnreachable is what a blocked or crashed destination looks like to the
// caller: a connection-level failure.
var ErrUnreachable = errors.New("faultnet: connection failed")

// Network routes requests between registered handlers.
type Network struct {
	mu        sync.Mutex
	handlers  map[string]http.Handler
	down      map[string]bool
	blocked   map[[2]string]bool // [from,to] dropped before delivery
	lostReply map[[2]string]bool // [from,to] delivered, response dropped
	delay     map[[2]string]time.Duration
	sent      map[string]int // per destination, deliveries made
	attempts  map[string]int // per destination, every request including refused ones
	opDelays  []*opDelay
}

type opDelay struct {
	from, to, substr string
	d                time.Duration
	left             int // remaining applications; <0 means unlimited
}

// New returns an empty network.
func New() *Network {
	return &Network{handlers: map[string]http.Handler{}, down: map[string]bool{},
		blocked: map[[2]string]bool{}, lostReply: map[[2]string]bool{},
		delay: map[[2]string]time.Duration{}, sent: map[string]int{}, attempts: map[string]int{}}
}

// Register attaches a handler at addr.
func (n *Network) Register(addr string, h http.Handler) {
	n.mu.Lock()
	n.handlers[addr] = h
	n.mu.Unlock()
}

// Crash makes addr refuse every connection; Restart undoes it.
func (n *Network) Crash(addr string)   { n.set(func() { n.down[addr] = true }) }
func (n *Network) Restart(addr string) { n.set(func() { delete(n.down, addr) }) }

// Partition splits the listed groups from one another: an address can reach
// only members of its own group. Addresses in no group are unaffected.
func (n *Network) Partition(groups ...[]string) {
	n.set(func() {
		for i, a := range groups {
			for j, b := range groups {
				if i == j {
					continue
				}
				for _, x := range a {
					for _, y := range b {
						n.blocked[[2]string{x, y}] = true
					}
				}
			}
		}
	})
}

// BlockOneWay drops requests from -> to only.
func (n *Network) BlockOneWay(from, to string) {
	n.set(func() { n.blocked[[2]string{from, to}] = true })
}

// LoseReplies lets requests from -> to be processed but drops the
// responses, so the sender cannot know whether its request took effect.
func (n *Network) LoseReplies(from, to string, on bool) {
	n.set(func() {
		if on {
			n.lostReply[[2]string{from, to}] = true
		} else {
			delete(n.lostReply, [2]string{from, to})
		}
	})
}

// Delay adds latency to from -> to.
func (n *Network) Delay(from, to string, d time.Duration) {
	n.set(func() { n.delay[[2]string{from, to}] = d })
}

// DelayMatching adds latency d to requests from -> to whose path contains
// substr, for the next times matching requests (times <= 0 means all of
// them). It lets a test slow one phase of an operation, such as commits,
// while the rest of the traffic to the node stays fast.
func (n *Network) DelayMatching(from, to, substr string, d time.Duration, times int) {
	if times <= 0 {
		times = -1
	}
	n.set(func() { n.opDelays = append(n.opDelays, &opDelay{from, to, substr, d, times}) })
}

// Attempts is how many requests were sent toward addr, delivered or not.
func (n *Network) Attempts(addr string) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.attempts[addr]
}

// Heal removes every partition, block, delay and lost-reply rule and
// restarts crashed nodes.
func (n *Network) Heal() {
	n.set(func() {
		n.down = map[string]bool{}
		n.blocked = map[[2]string]bool{}
		n.lostReply = map[[2]string]bool{}
		n.delay = map[[2]string]time.Duration{}
		n.opDelays = nil
	})
}

// Sent is how many requests were delivered to addr's handler.
func (n *Network) Sent(addr string) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.sent[addr]
}

func (n *Network) set(f func()) {
	n.mu.Lock()
	f()
	n.mu.Unlock()
}

// Transport returns the RoundTripper used by the node at address from.
func (n *Network) Transport(from string) http.RoundTripper { return &transport{n: n, from: from} }

// Client returns an http.Client over Transport(from).
func (n *Network) Client(from string) *http.Client {
	return &http.Client{Transport: n.Transport(from)}
}

type transport struct {
	n    *Network
	from string
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	to := req.URL.Host
	key := [2]string{t.from, to}
	t.n.mu.Lock()
	h := t.n.handlers[to]
	down := t.n.down[to] || t.n.down[t.from]
	blocked := t.n.blocked[key]
	lost := t.n.lostReply[key]
	delay := t.n.delay[key]
	t.n.attempts[to]++
	for _, od := range t.n.opDelays {
		if od.from == t.from && od.to == to && od.left != 0 && strings.Contains(req.URL.Path, od.substr) {
			delay += od.d
			if od.left > 0 {
				od.left--
			}
		}
	}
	t.n.mu.Unlock()
	if req.Body != nil {
		defer req.Body.Close()
	}
	if h == nil || down || blocked {
		return nil, wrap(req, ErrUnreachable)
	}
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	}
	if err := req.Context().Err(); err != nil {
		return nil, err
	}
	body := []byte(nil)
	if req.Body != nil {
		var err error
		if body, err = io.ReadAll(req.Body); err != nil {
			return nil, err
		}
	}
	inner := req.Clone(req.Context())
	inner.Body = io.NopCloser(bytes.NewReader(body))
	inner.RequestURI = req.URL.RequestURI()
	inner.RemoteAddr = t.from
	rec := httptest.NewRecorder()
	t.n.mu.Lock()
	t.n.sent[to]++
	t.n.mu.Unlock()
	h.ServeHTTP(rec, inner)
	if lost {
		return nil, wrap(req, ErrUnreachable)
	}
	// A crash or partition that began while the handler ran also eats the
	// response.
	t.n.mu.Lock()
	gone := t.n.down[to] || t.n.blocked[[2]string{to, t.from}]
	t.n.mu.Unlock()
	if gone {
		return nil, wrap(req, ErrUnreachable)
	}
	resp := rec.Result()
	resp.Request = req
	return resp, nil
}

func wrap(req *http.Request, err error) error {
	return &urlError{op: req.Method, url: req.URL.String(), err: err}
}

type urlError struct {
	op, url string
	err     error
}

func (e *urlError) Error() string { return e.op + " " + e.url + ": " + e.err.Error() }
func (e *urlError) Unwrap() error { return e.err }
