package amqp

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	amqp091 "github.com/rabbitmq/amqp091-go"

	"nanoio/internal/event"
)

// fakeBroker is a minimal AMQP 0-9-1 server: it completes the connection
// handshake, accepts exchange.declare and confirm.select, and answers each
// basic.publish with an ack, a nack, a basic.return followed by an ack, or
// nothing, as configured.
type fakeBroker struct {
	l  net.Listener
	mu sync.Mutex
	// published messages, as "exchange|routingKey|body"; declared exchanges
	// as "name:type".
	published []string
	declared  []string
	mode      string // "ack" (default), "nack", "return", "silent"
	conns     int
}

func startBroker(t *testing.T) *fakeBroker {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b := &fakeBroker{l: l, mode: "ack"}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go b.serve(c)
		}
	}()
	return b
}

func (b *fakeBroker) setMode(m string) {
	b.mu.Lock()
	b.mode = m
	b.mu.Unlock()
}

func frame(typ byte, ch uint16, payload []byte) []byte {
	var buf bytes.Buffer
	buf.WriteByte(typ)
	binary.Write(&buf, binary.BigEndian, ch)
	binary.Write(&buf, binary.BigEndian, uint32(len(payload)))
	buf.Write(payload)
	buf.WriteByte(0xCE)
	return buf.Bytes()
}

func method(class, meth uint16, args ...byte) []byte {
	p := make([]byte, 4, 4+len(args))
	binary.BigEndian.PutUint16(p, class)
	binary.BigEndian.PutUint16(p[2:], meth)
	return append(p, args...)
}

func shortstr(s string) []byte { return append([]byte{byte(len(s))}, s...) }

func longstr(s string) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(len(s)))
	return append(b, s...)
}

func (b *fakeBroker) serve(c net.Conn) {
	defer c.Close()
	b.mu.Lock()
	b.conns++
	b.mu.Unlock()
	hdr := make([]byte, 8)
	if _, err := io.ReadFull(c, hdr); err != nil || string(hdr[:4]) != "AMQP" {
		return
	}
	// Connection.Start
	start := method(10, 10, 0, 9)
	start = append(start, 0, 0, 0, 0) // empty server-properties table
	start = append(start, longstr("PLAIN")...)
	start = append(start, longstr("en_US")...)
	c.Write(frame(1, 0, start))

	var (
		tag      uint64
		curEx    string
		curKey   string
		bodyLeft uint64
		body     []byte
	)
	for {
		var h [7]byte
		if _, err := io.ReadFull(c, h[:]); err != nil {
			return
		}
		typ, ch, size := h[0], binary.BigEndian.Uint16(h[1:]), binary.BigEndian.Uint32(h[3:])
		payload := make([]byte, size+1)
		if _, err := io.ReadFull(c, payload); err != nil {
			return
		}
		payload = payload[:size]
		switch typ {
		case 8: // heartbeat
		case 1:
			class, meth := binary.BigEndian.Uint16(payload), binary.BigEndian.Uint16(payload[2:])
			args := payload[4:]
			switch {
			case class == 10 && meth == 11: // Start-Ok
				tune := method(10, 30)
				tune = append(tune, 0, 0, 0, 0, 0x20, 0, 0, 0) // channel-max 0, frame-max 8192, heartbeat 0
				c.Write(frame(1, 0, tune))
			case class == 10 && meth == 31: // Tune-Ok
			case class == 10 && meth == 40: // Open
				c.Write(frame(1, 0, append(method(10, 41), shortstr("")...)))
			case class == 10 && meth == 50: // Close
				c.Write(frame(1, 0, method(10, 51)))
				return
			case class == 20 && meth == 10: // Channel.Open
				c.Write(frame(1, ch, append(method(20, 11), longstr("")...)))
			case class == 20 && meth == 40: // Channel.Close
				c.Write(frame(1, ch, method(20, 41)))
			case class == 40 && meth == 10: // Exchange.Declare
				exch := args[2 : 3+int(args[2])]
				rest := args[3+int(args[2]):]
				typ := rest[1 : 1+int(rest[0])]
				b.mu.Lock()
				b.declared = append(b.declared, string(exch[1:])+":"+string(typ))
				b.mu.Unlock()
				c.Write(frame(1, ch, method(40, 11)))
			case class == 85 && meth == 10: // Confirm.Select
				c.Write(frame(1, ch, method(85, 11)))
			case class == 60 && meth == 40: // Basic.Publish
				n := int(args[2])
				curEx = string(args[3 : 3+n])
				k := 3 + n
				curKey = string(args[k+1 : k+1+int(args[k])])
				tag++
			}
		case 2: // content header
			bodyLeft = binary.BigEndian.Uint64(payload[4:])
			body = nil
			if bodyLeft == 0 {
				b.finish(c, ch, tag, curEx, curKey, body)
			}
		case 3: // content body
			body = append(body, payload...)
			bodyLeft -= uint64(len(payload))
			if bodyLeft == 0 {
				b.finish(c, ch, tag, curEx, curKey, body)
			}
		}
	}
}

func (b *fakeBroker) finish(c net.Conn, ch uint16, tag uint64, ex, key string, body []byte) {
	b.mu.Lock()
	mode := b.mode
	b.published = append(b.published, ex+"|"+key+"|"+string(body))
	b.mu.Unlock()
	tagBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(tagBytes, tag)
	switch mode {
	case "silent":
	case "nack":
		c.Write(frame(1, ch, method(60, 120, append(tagBytes, 0)...)))
	case "return":
		ret := method(60, 50, 0x01, 0x87) // 391 NO_ROUTE
		ret = append(ret, shortstr("NO_ROUTE")...)
		ret = append(ret, shortstr(ex)...)
		ret = append(ret, shortstr(key)...)
		c.Write(frame(1, ch, ret))
		hdr := make([]byte, 14)
		binary.BigEndian.PutUint16(hdr, 60)
		binary.BigEndian.PutUint64(hdr[4:], uint64(len(body)))
		c.Write(frame(2, ch, hdr))
		c.Write(frame(3, ch, body))
		c.Write(frame(1, ch, method(60, 80, append(tagBytes, 0)...)))
	default:
		c.Write(frame(1, ch, method(60, 80, append(tagBytes, 0)...)))
	}
}

func (b *fakeBroker) url() string { return "amqp://guest:guest@" + b.l.Addr().String() + "/" }

func ev(key string) *event.Event {
	return &event.Event{Name: event.ObjectCreatedPut, Bucket: "b", Key: key, Time: time.Now().UTC()}
}

func TestPublishWithConfirms(t *testing.T) {
	b := startBroker(t)
	spec, err := Factory("a", json.RawMessage(`{"url":"`+b.url()+`","exchange":"nanoio","exchangeType":"topic","routingKey":"s3.events","durable":true}`))
	if err != nil {
		t.Fatal(err)
	}
	defer spec.Target.Close()
	if err := spec.Target.Send(context.Background(), []*event.Event{ev("1"), ev("2"), ev("3")}); err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.declared) != 1 || b.declared[0] != "nanoio:topic" {
		t.Errorf("declared = %v", b.declared)
	}
	if len(b.published) != 3 || !strings.HasPrefix(b.published[0], "nanoio|s3.events|") || !strings.Contains(b.published[2], `"Key":"b/3"`) {
		t.Fatalf("published = %v", b.published)
	}
}

func TestNackUnroutableAndSilenceFail(t *testing.T) {
	for _, mode := range []string{"nack", "return"} {
		t.Run(mode, func(t *testing.T) {
			b := startBroker(t)
			b.setMode(mode)
			spec, err := Factory("a", json.RawMessage(`{"url":"`+b.url()+`","exchange":"x","timeout":"2s"}`))
			if err != nil {
				t.Fatal(err)
			}
			defer spec.Target.Close()
			err = spec.Target.Send(context.Background(), []*event.Event{ev("1")})
			if err == nil {
				t.Fatalf("%s: Send succeeded", mode)
			}
			// The target recovers once the broker accepts messages again.
			b.setMode("ack")
			if err := spec.Target.Send(context.Background(), []*event.Event{ev("1")}); err != nil {
				t.Errorf("after %s, the next send failed: %v", mode, err)
			}
		})
	}
	t.Run("silent", func(t *testing.T) {
		b := startBroker(t)
		b.setMode("silent")
		spec, _ := Factory("a", json.RawMessage(`{"url":"`+b.url()+`"}`))
		defer spec.Target.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		if err := spec.Target.Send(ctx, []*event.Event{ev("1")}); err == nil {
			t.Error("a message the broker never confirms must not count as delivered")
		}
	})
}

func TestUnreachableBroker(t *testing.T) {
	spec, err := Factory("a", json.RawMessage(`{"url":"amqp://u:p@127.0.0.1:1/","timeout":"500ms"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer spec.Target.Close()
	if err := spec.Target.Send(context.Background(), []*event.Event{ev("1")}); err == nil {
		t.Error("send to a closed port must fail")
	}
	if err := spec.Target.(event.Checker).Check(context.Background()); err == nil {
		t.Error("Check of a closed port must fail")
	}
}

func TestConfigValidation(t *testing.T) {
	for name, cfg := range map[string]string{
		"no url": `{}`, "bad scheme": `{"url":"http://h"}`,
		"bad type": `{"url":"amqp://h","exchangeType":"x"}`, "bad mode": `{"url":"amqp://h","deliveryMode":3}`,
	} {
		if _, err := Factory("a", json.RawMessage(cfg)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// TestAgainstRealRabbitMQ runs only when NANOIO_TEST_AMQP names a broker URL,
// e.g. amqp://guest:guest@127.0.0.1:5672/ (docker run -d -p 5672:5672
// rabbitmq:3-alpine).
func TestAgainstRealRabbitMQ(t *testing.T) {
	url := os.Getenv("NANOIO_TEST_AMQP")
	if url == "" {
		t.Skip("NANOIO_TEST_AMQP is not set")
	}
	name := fmt.Sprintf("nanoio-test-%d", time.Now().UnixNano())
	conn, err := amqp091.Dial(url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ch, err := conn.Channel()
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.ExchangeDeclare(name, "direct", false, true, false, false, nil); err != nil {
		t.Fatal(err)
	}
	q, err := ch.QueueDeclare("", false, true, true, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.QueueBind(q.Name, "events", name, false, nil); err != nil {
		t.Fatal(err)
	}
	spec, err := Factory("a", json.RawMessage(fmt.Sprintf(`{"url":%q,"exchange":%q,"exchangeType":"direct","routingKey":"events","autoDeleted":true}`, url, name)))
	if err != nil {
		t.Fatal(err)
	}
	defer spec.Target.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := spec.Target.Send(ctx, []*event.Event{ev("1"), ev("2")}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	for i := 1; i <= 2; i++ {
		var msg amqp091.Delivery
		var ok bool
		for tries := 0; tries < 50 && !ok; tries++ {
			msg, ok, err = ch.Get(q.Name, true)
			if err != nil {
				t.Fatal(err)
			}
			if !ok {
				time.Sleep(100 * time.Millisecond)
			}
		}
		if !ok || !strings.Contains(string(msg.Body), fmt.Sprintf(`"Key":"b/%d"`, i)) {
			t.Fatalf("message %d: %v %s", i, ok, msg.Body)
		}
	}
	// Publishing to an exchange nobody bound a queue to is unroutable: with
	// mandatory publishing that is a failure, not a silent drop.
	spec2, _ := Factory("a2", json.RawMessage(fmt.Sprintf(`{"url":%q,"exchange":%q,"exchangeType":"direct","routingKey":"nobody","autoDeleted":true}`, url, name)))
	defer spec2.Target.Close()
	if err := spec2.Target.Send(ctx, []*event.Event{ev("3")}); err == nil || !strings.Contains(err.Error(), "unroutable") {
		t.Errorf("unroutable publish = %v", err)
	}
}
