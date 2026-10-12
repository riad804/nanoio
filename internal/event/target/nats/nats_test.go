package nats

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	natsgo "github.com/nats-io/nats.go"

	"nanoio/internal/event"
)

// fakeNATS speaks enough of the NATS text protocol for a client to connect,
// publish and flush.
type fakeNATS struct {
	l    net.Listener
	mu   sync.Mutex
	pubs map[string][]string // subject -> payloads
	auth string
}

func startFake(t *testing.T) *fakeNATS {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeNATS{l: l, pubs: map[string][]string{}}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeNATS) serve(c net.Conn) {
	defer c.Close()
	fmt.Fprintf(c, "INFO {\"server_id\":\"fake\",\"version\":\"2.10.0\",\"proto\":1,\"max_payload\":1048576,\"headers\":true}\r\n")
	br := bufio.NewReader(c)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		switch {
		case strings.HasPrefix(line, "CONNECT "):
			f.mu.Lock()
			f.auth = line
			f.mu.Unlock()
		case line == "PING":
			io.WriteString(c, "PONG\r\n")
		case strings.HasPrefix(line, "PUB "):
			parts := strings.Fields(line)
			n, _ := strconv.Atoi(parts[len(parts)-1])
			buf := make([]byte, n+2)
			if _, err := io.ReadFull(br, buf); err != nil {
				return
			}
			f.mu.Lock()
			f.pubs[parts[1]] = append(f.pubs[parts[1]], string(buf[:n]))
			f.mu.Unlock()
		}
	}
}

func (f *fakeNATS) addr() string { return "nats://" + f.l.Addr().String() }

func ev(key string) *event.Event {
	return &event.Event{Name: event.ObjectCreatedPut, Bucket: "b", Key: key, Time: time.Now().UTC()}
}

func TestPublishesInOrderAndFlushes(t *testing.T) {
	f := startFake(t)
	spec, err := Factory("n", json.RawMessage(`{"address":"`+f.addr()+`","subject":"events.nanoio","username":"u","password":"p"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer spec.Target.Close()
	if err := spec.Target.(event.Checker).Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := spec.Target.Send(context.Background(), []*event.Event{ev("1"), ev("2"), ev("3")}); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	got := f.pubs["events.nanoio"]
	if len(got) != 3 {
		t.Fatalf("got %d messages", len(got))
	}
	for i, body := range got {
		var p event.Payload
		if err := json.Unmarshal([]byte(body), &p); err != nil || p.Key != fmt.Sprintf("b/%d", i+1) {
			t.Errorf("message %d = %s (%v)", i, body, err)
		}
	}
	if !strings.Contains(f.auth, `"user":"u"`) {
		t.Errorf("CONNECT = %s", f.auth)
	}
}

func TestReconnectsAfterTheServerDrops(t *testing.T) {
	f := startFake(t)
	spec, _ := Factory("n", json.RawMessage(`{"address":"`+f.addr()+`","subject":"s"}`))
	defer spec.Target.Close()
	if err := spec.Target.Send(context.Background(), []*event.Event{ev("1")}); err != nil {
		t.Fatal(err)
	}
	f.l.Close() // the broker goes away
	tgt := spec.Target.(*Target)
	tgt.mu.Lock()
	tgt.nc.Close()
	tgt.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := spec.Target.Send(ctx, []*event.Event{ev("2")}); err == nil {
		t.Error("sending to a dead server must fail")
	}
}

func TestConfigValidation(t *testing.T) {
	for name, cfg := range map[string]string{
		"no address": `{"subject":"s"}`, "bad scheme": `{"address":"http://h:4222","subject":"s"}`,
		"no subject": `{"address":"nats://h:4222"}`, "bad creds": `{"address":"nats://h:4222","subject":"s","tls":{"ca":"/nope"}}`,
	} {
		if _, err := Factory("n", json.RawMessage(cfg)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// TestAgainstRealNATS runs only when NANOIO_TEST_NATS names a server, e.g.
// nats://127.0.0.1:4222 (docker run -d -p 4222:4222 nats:latest).
func TestAgainstRealNATS(t *testing.T) {
	addr := os.Getenv("NANOIO_TEST_NATS")
	if addr == "" {
		t.Skip("NANOIO_TEST_NATS is not set")
	}
	nc, err := natsgo.Connect(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	sub, err := nc.SubscribeSync("nanoio.test.events")
	if err != nil {
		t.Fatal(err)
	}
	nc.Flush()
	spec, err := Factory("n", json.RawMessage(`{"address":"`+addr+`","subject":"nanoio.test.events"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer spec.Target.Close()
	if err := spec.Target.(event.Checker).Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := spec.Target.Send(context.Background(), []*event.Event{ev("1"), ev("2")}); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 2; i++ {
		m, err := sub.NextMsg(5 * time.Second)
		if err != nil || !strings.Contains(string(m.Data), fmt.Sprintf(`"Key":"b/%d"`, i)) {
			t.Fatalf("message %d: %v %v", i, m, err)
		}
	}
}
