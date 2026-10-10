package rpcauth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func signed(t *testing.T, k *Keyring, node, body string, mut func(*http.Request)) *http.Request {
	t.Helper()
	r := httptest.NewRequest("POST", "/_nanoio/rpc/v1/disk.read?x=1", strings.NewReader(body))
	r.Header.Set(HeaderArgs, EncodeArgs([]byte(`{"a":1}`)))
	if err := k.Sign(r, node, []byte(body)); err != nil {
		t.Fatal(err)
	}
	if mut != nil {
		mut(r)
	}
	return r
}

func TestVerify(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	k, _ := NewKeyring("0123456789abcdef-current")
	k.SetClock(func() time.Time { return now })
	known := func(n string) bool { return n == "n1" || n == "n2" }

	tests := []struct {
		name    string
		node    string
		mut     func(*http.Request)
		clock   time.Duration
		wantErr bool
	}{
		{"valid", "n1", nil, 0, false},
		{"within window", "n1", nil, 29 * time.Second, false},
		{"future within window", "n1", nil, -29 * time.Second, false},
		{"too old", "n1", nil, 31 * time.Second, true},
		{"too new", "n1", nil, -31 * time.Second, true},
		{"unknown node", "n9", nil, 0, true},
		{"path tampered", "n1", func(r *http.Request) { r.URL.Path = "/_nanoio/rpc/v1/disk.delete" }, 0, true},
		{"query tampered", "n1", func(r *http.Request) { r.URL.RawQuery = "x=2" }, 0, true},
		{"method tampered", "n1", func(r *http.Request) { r.Method = "PUT" }, 0, true},
		{"args tampered", "n1", func(r *http.Request) { r.Header.Set(HeaderArgs, EncodeArgs([]byte(`{"a":2}`))) }, 0, true},
		{"node swapped", "n1", func(r *http.Request) { r.Header.Set(HeaderNode, "n2") }, 0, true},
		{"nonce swapped", "n1", func(r *http.Request) { r.Header.Set(HeaderNonce, "other") }, 0, true},
		{"time swapped", "n1", func(r *http.Request) { r.Header.Set(HeaderTime, "1") }, 0, true},
		{"sig stripped", "n1", func(r *http.Request) { r.Header.Del(HeaderSig) }, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := signed(t, k, tt.node, "payload", tt.mut)
			v, _ := NewKeyring("0123456789abcdef-current")
			v.SetClock(func() time.Time { return now.Add(tt.clock) })
			_, err := v.Verify(r, []byte("payload"), NewReplayCache(), known)
			if (err != nil) != tt.wantErr {
				t.Errorf("err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}

	t.Run("body tampered", func(t *testing.T) {
		r := signed(t, k, "n1", "payload", nil)
		if _, err := k.Verify(r, []byte("payloaX"), nil, known); err == nil {
			t.Error("accepted a different body")
		}
	})
	t.Run("another cluster's secret", func(t *testing.T) {
		other, _ := NewKeyring("zzzzzzzzzzzzzzzz-other")
		other.SetClock(func() time.Time { return now })
		r := signed(t, other, "n1", "payload", nil)
		if _, err := k.Verify(r, []byte("payload"), nil, known); err == nil {
			t.Error("accepted a request signed with a foreign secret")
		}
	})
}

func TestPerNodeKeys(t *testing.T) {
	k, _ := NewKeyring("0123456789abcdef-current")
	if string(k.nodeKey(0, "n1")) == string(k.nodeKey(0, "n2")) {
		t.Fatal("two nodes share a key")
	}
	// A signature made for n1 is not valid when presented as n2's.
	r := signed(t, k, "n1", "b", nil)
	r.Header.Set(HeaderNode, "n2")
	if _, err := k.Verify(r, []byte("b"), nil, nil); err == nil {
		t.Error("a request signed as n1 verified as n2")
	}
}

func TestReplay(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	k, _ := NewKeyring("0123456789abcdef-current")
	k.SetClock(func() time.Time { return now })
	rc := NewReplayCache()
	r := signed(t, k, "n1", "b", nil)
	if _, err := k.Verify(r, []byte("b"), rc, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Verify(r, []byte("b"), rc, nil); err == nil || !strings.Contains(err.Error(), "replayed") {
		t.Errorf("replay accepted: %v", err)
	}
	// The cache forgets only once the timestamp would be rejected anyway.
	k.SetClock(func() time.Time { return now.Add(Window + 5*time.Second) })
	if _, err := k.Verify(r, []byte("b"), rc, nil); err == nil {
		t.Error("an expired request was accepted after the cache pruned it")
	}
	if rc.Len() != 1 {
		t.Errorf("replay cache holds %d entries", rc.Len())
	}
	k.SetClock(func() time.Time { return now.Add(3 * Window) })
	rc.Seen("n1", "fresh", now.Add(3*Window))
	if rc.Len() != 1 {
		t.Errorf("replay cache did not prune: %d entries", rc.Len())
	}
}

func TestRotation(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }
	oldK, _ := NewKeyring("old-secret-0123456789")
	newK, _ := NewKeyring("new-secret-0123456789")
	// Phase 1: new secret added as a verify-only secondary.
	overlap, _ := NewKeyring("old-secret-0123456789", "new-secret-0123456789")
	// Phase 2: new secret promoted, old kept for verification.
	promoted, _ := NewKeyring("new-secret-0123456789", "old-secret-0123456789")
	for _, k := range []*Keyring{oldK, newK, overlap, promoted} {
		k.SetClock(clock)
	}
	check := func(name string, sender, receiver *Keyring, ok bool) {
		t.Helper()
		r := signed(t, sender, "n1", "b", nil)
		_, err := receiver.Verify(r, []byte("b"), nil, nil)
		if (err == nil) != ok {
			t.Errorf("%s: err = %v, want ok=%v", name, err, ok)
		}
	}
	check("old->old", oldK, oldK, true)
	check("old->overlap (phase 1 receiver)", oldK, overlap, true)
	check("new->overlap (phase 1 receiver)", newK, overlap, true)
	check("old->promoted (phase 2 receiver)", oldK, promoted, true)
	check("new->promoted", newK, promoted, true)
	check("new->old (not yet rolled out)", newK, oldK, false)
	// Phase 3: old removed.
	check("old->new only", oldK, newK, false)
}

func TestResponseSigning(t *testing.T) {
	k, _ := NewKeyring("0123456789abcdef-current")
	h := http.Header{}
	k.SignResponse(h, "n2", "nonce1", k.CurrentKeyID(), 200, []byte("data"))
	if err := k.VerifyResponse(h, "n2", "nonce1", k.CurrentKeyID(), 200, []byte("data")); err != nil {
		t.Fatal(err)
	}
	for name, f := range map[string]func() error{
		"other body":   func() error { return k.VerifyResponse(h, "n2", "nonce1", k.CurrentKeyID(), 200, []byte("datb")) },
		"other nonce":  func() error { return k.VerifyResponse(h, "n2", "nonce2", k.CurrentKeyID(), 200, []byte("data")) },
		"other status": func() error { return k.VerifyResponse(h, "n2", "nonce1", k.CurrentKeyID(), 500, []byte("data")) },
		"other peer":   func() error { return k.VerifyResponse(h, "n3", "nonce1", k.CurrentKeyID(), 200, []byte("data")) },
	} {
		if f() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestShortSecretRefused(t *testing.T) {
	if _, err := NewKeyring("short"); err == nil {
		t.Error("a short secret was accepted")
	}
	if _, err := NewKeyring(); err == nil {
		t.Error("an empty keyring was accepted")
	}
	if _, err := NewKeyring("0123456789abcdef", "0123456789abcdef"); err == nil {
		t.Error("a duplicate secret was accepted")
	}
}
