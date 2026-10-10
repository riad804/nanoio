package faultnet

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func echo(name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Write([]byte(name + ":" + string(b)))
	})
}

func call(n *Network, from, to string) (string, error) {
	req, _ := http.NewRequest("POST", "http://"+to+"/x", strings.NewReader("hi"))
	resp, err := n.Client(from).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b), nil
}

func TestFaults(t *testing.T) {
	setup := func() *Network {
		n := New()
		for _, a := range []string{"a", "b", "c"} {
			n.Register(a, echo(a))
		}
		return n
	}
	tests := []struct {
		name  string
		apply func(*Network)
		from  string
		to    string
		fail  bool
	}{
		{"healthy", func(*Network) {}, "a", "b", false},
		{"crashed destination", func(n *Network) { n.Crash("b") }, "a", "b", true},
		{"crashed source", func(n *Network) { n.Crash("a") }, "a", "b", true},
		{"partition across groups", func(n *Network) { n.Partition([]string{"a"}, []string{"b", "c"}) }, "a", "b", true},
		{"partition within a group", func(n *Network) { n.Partition([]string{"a"}, []string{"b", "c"}) }, "b", "c", false},
		{"one-way block, blocked direction", func(n *Network) { n.BlockOneWay("a", "b") }, "a", "b", true},
		// b's request reaches a, but a's reply travels the blocked direction.
		{"one-way block eats replies on the reverse path", func(n *Network) { n.BlockOneWay("a", "b") }, "b", "a", true},
		{"lost reply is a failure to the caller", func(n *Network) { n.LoseReplies("a", "b", true) }, "a", "b", true},
		{"unknown destination", func(*Network) {}, "a", "nowhere", true},
		{"heal removes everything", func(n *Network) {
			n.Crash("b")
			n.Partition([]string{"a"}, []string{"c"})
			n.Heal()
		}, "a", "b", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := setup()
			tt.apply(n)
			got, err := call(n, tt.from, tt.to)
			if (err != nil) != tt.fail {
				t.Fatalf("err = %v, want failure=%v", err, tt.fail)
			}
			if err != nil && !errors.Is(err, ErrUnreachable) && tt.to != "nowhere" {
				t.Errorf("failure is not ErrUnreachable: %v", err)
			}
			if err == nil && got != tt.to+":hi" {
				t.Errorf("body = %q", got)
			}
		})
	}

	t.Run("a lost reply is still processed", func(t *testing.T) {
		n := setup()
		n.LoseReplies("a", "b", true)
		call(n, "a", "b")
		if n.Sent("b") != 1 {
			t.Errorf("destination saw %d requests, want 1", n.Sent("b"))
		}
	})
	t.Run("delay honours the caller's deadline", func(t *testing.T) {
		n := setup()
		n.Delay("a", "b", 5*time.Second)
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, "POST", "http://b/x", nil)
		start := time.Now()
		_, err := n.Client("a").Do(req)
		if err == nil || time.Since(start) > time.Second {
			t.Errorf("err = %v after %v", err, time.Since(start))
		}
		if n.Sent("b") != 0 {
			t.Error("a request delayed past its deadline was still delivered")
		}
	})
}
