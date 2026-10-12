package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"nanoio/internal/event"
)

// startRedis runs a real redis-server on a free port, or skips.
func startRedis(t *testing.T) string {
	t.Helper()
	bin, err := exec.LookPath("redis-server")
	if err != nil {
		t.Skip("redis-server is not installed")
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	cmd := exec.Command(bin, "--port", fmt.Sprint(port), "--bind", "127.0.0.1", "--save", "", "--appendonly", "no", "--dir", t.TempDir())
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	for i := 0; i < 100; i++ {
		if c, err := net.DialTimeout("tcp", addr, 50*time.Millisecond); err == nil {
			c.Close()
			return addr
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("redis-server did not start")
	return ""
}

func ev(name, key string) *event.Event {
	return &event.Event{Name: name, Bucket: "b", Key: key, Time: time.Now().UTC(), Size: 1}
}

func TestNamespaceAndAccessAgainstRealRedis(t *testing.T) {
	addr := startRedis(t)
	rc := goredis.NewClient(&goredis.Options{Addr: addr})
	defer rc.Close()
	ctx := context.Background()

	ns, err := Factory("r", json.RawMessage(`{"address":"`+addr+`","key":"ns"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Target.Close()
	if err := ns.Target.(event.Checker).Check(ctx); err != nil {
		t.Fatal(err)
	}
	send := func(s event.Spec, evs ...*event.Event) {
		t.Helper()
		if err := s.Target.Send(ctx, evs); err != nil {
			t.Fatal(err)
		}
	}
	send(ns, ev(event.ObjectCreatedPut, "a"), ev(event.ObjectCreatedPut, "c"))
	send(ns, ev(event.ObjectAccessedGet, "a"), ev(event.ObjectRemovedDelete, "c"))
	keys, _ := rc.HKeys(ctx, "ns").Result()
	if len(keys) != 1 || keys[0] != "b/a" {
		t.Fatalf("namespace hash fields = %v, want [b/a]", keys)
	}
	val, _ := rc.HGet(ctx, "ns", "b/a").Result()
	var doc struct{ Records []struct{ EventName string } }
	if err := json.Unmarshal([]byte(val), &doc); err != nil || doc.Records[0].EventName != event.ObjectCreatedPut {
		t.Errorf("stored value = %s (%v)", val, err)
	}

	ac, err := Factory("r2", json.RawMessage(`{"address":"`+addr+`","key":"log","format":"access","batchSize":10}`))
	if err != nil {
		t.Fatal(err)
	}
	defer ac.Target.Close()
	send(ac, ev(event.ObjectCreatedPut, "a"), ev(event.ObjectAccessedGet, "a"), ev(event.ObjectRemovedDelete, "a"))
	n, _ := rc.LLen(ctx, "log").Result()
	if n != 3 {
		t.Fatalf("access list has %d entries, want 3", n)
	}
	first, _ := rc.LIndex(ctx, "log", 0).Result()
	if !json.Valid([]byte(first)) {
		t.Errorf("entry %q is not JSON", first)
	}
}

func TestDownServerFailsAndConfigIsValidated(t *testing.T) {
	spec, err := Factory("r", json.RawMessage(`{"address":"127.0.0.1:1","key":"k","timeout":"500ms"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer spec.Target.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := spec.Target.Send(ctx, []*event.Event{ev(event.ObjectCreatedPut, "a")}); err == nil {
		t.Error("sending to a closed port must fail")
	}
	for name, cfg := range map[string]string{
		"no address": `{"key":"k"}`, "address without port": `{"address":"localhost","key":"k"}`,
		"no key": `{"address":"h:1"}`, "bad db": `{"address":"h:1","key":"k","db":-1}`, "bad format": `{"address":"h:1","key":"k","format":"z"}`,
	} {
		if _, err := Factory("r", json.RawMessage(cfg)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
