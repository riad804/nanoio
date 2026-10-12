package mqtt

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	paho "github.com/eclipse/paho.mqtt.golang"
	"github.com/eclipse/paho.mqtt.golang/packets"

	"nanoio/internal/event"
)

// fakeBroker accepts MQTT connections and records PUBLISH packets. ack
// decides whether QoS>0 publishes are acknowledged.
type fakeBroker struct {
	l      net.Listener
	mu     sync.Mutex
	topics []string
	bodies []string
	qos    []byte
	user   string
	ack    bool
	conns  int
}

func startBroker(t *testing.T) *fakeBroker {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b := &fakeBroker{l: l, ack: true}
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

func (b *fakeBroker) serve(c net.Conn) {
	defer c.Close()
	for {
		pkt, err := packets.ReadPacket(c)
		if err != nil {
			return
		}
		switch p := pkt.(type) {
		case *packets.ConnectPacket:
			b.mu.Lock()
			b.user = p.Username
			b.conns++
			b.mu.Unlock()
			ack := packets.NewControlPacket(packets.Connack).(*packets.ConnackPacket)
			ack.ReturnCode = packets.Accepted
			ack.Write(c)
		case *packets.PublishPacket:
			b.mu.Lock()
			b.topics = append(b.topics, p.TopicName)
			b.bodies = append(b.bodies, string(p.Payload))
			b.qos = append(b.qos, p.Qos)
			ack := b.ack
			b.mu.Unlock()
			if p.Qos == 1 && ack {
				pa := packets.NewControlPacket(packets.Puback).(*packets.PubackPacket)
				pa.MessageID = p.MessageID
				pa.Write(c)
			}
		case *packets.PingreqPacket:
			packets.NewControlPacket(packets.Pingresp).Write(c)
		case *packets.DisconnectPacket:
			return
		}
	}
}

func (b *fakeBroker) url() string { return "tcp://" + b.l.Addr().String() }

func ev(key string) *event.Event {
	return &event.Event{Name: event.ObjectCreatedPut, Bucket: "b", Key: key, Time: time.Now().UTC()}
}

func TestPublishesWithAcknowledgement(t *testing.T) {
	b := startBroker(t)
	spec, err := Factory("m", json.RawMessage(`{"broker":"`+b.url()+`","topic":"nanoio/events","username":"u","password":"p"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer spec.Target.Close()
	if err := spec.Target.Send(context.Background(), []*event.Event{ev("1"), ev("2")}); err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.bodies) != 2 || b.topics[0] != "nanoio/events" || b.qos[0] != 1 || b.user != "u" {
		t.Fatalf("broker saw topics=%v qos=%v user=%q", b.topics, b.qos, b.user)
	}
	if !strings.Contains(b.bodies[1], `"Key":"b/2"`) {
		t.Errorf("second body = %s", b.bodies[1])
	}
}

func TestUnacknowledgedPublishFails(t *testing.T) {
	b := startBroker(t)
	b.ack = false
	spec, err := Factory("m", json.RawMessage(`{"broker":"`+b.url()+`","topic":"t","timeout":"300ms"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer spec.Target.Close()
	err = spec.Target.Send(context.Background(), []*event.Event{ev("1")})
	if err == nil || !strings.Contains(err.Error(), "not acknowledged") {
		t.Fatalf("err = %v, want a missing-acknowledgement failure", err)
	}
	// The next attempt starts from a fresh connection.
	b.mu.Lock()
	b.ack = true
	b.mu.Unlock()
	if err := spec.Target.Send(context.Background(), []*event.Event{ev("1")}); err != nil {
		t.Fatalf("after the broker recovered: %v", err)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conns != 2 {
		t.Errorf("broker saw %d connections, want 2 (reconnect after the failure)", b.conns)
	}
}

func TestConfigValidation(t *testing.T) {
	for name, cfg := range map[string]string{
		"no broker": `{"topic":"t"}`, "bad scheme": `{"broker":"http://h:1","topic":"t"}`,
		"no topic": `{"broker":"tcp://h:1883"}`, "bad qos": `{"broker":"tcp://h:1883","topic":"t","qos":3}`,
	} {
		if _, err := Factory("m", json.RawMessage(cfg)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	spec, err := Factory("m", json.RawMessage(`{"broker":"tcp://h:1883","topic":"t","qos":0}`))
	if err != nil {
		t.Fatal(err)
	}
	if spec.Target.(*Target).qos != 0 || spec.Delivery.BatchSize != 1 {
		t.Error("qos 0 must be honoured and batch default is 1")
	}
}

// TestAgainstRealMosquitto runs only when NANOIO_TEST_MQTT names a broker URL
// that allows anonymous clients, e.g. tcp://127.0.0.1:1883 (docker run -d
// -p 1883:1883 eclipse-mosquitto:2 mosquitto -c /mosquitto-no-auth.conf).
func TestAgainstRealMosquitto(t *testing.T) {
	url := os.Getenv("NANOIO_TEST_MQTT")
	if url == "" {
		t.Skip("NANOIO_TEST_MQTT is not set")
	}
	got := make(chan string, 4)
	sub := paho.NewClient(paho.NewClientOptions().AddBroker(url).SetClientID("nanoio-test-sub"))
	if tok := sub.Connect(); !tok.WaitTimeout(5*time.Second) || tok.Error() != nil {
		t.Fatalf("subscriber connect: %v", tok.Error())
	}
	defer sub.Disconnect(100)
	if tok := sub.Subscribe("nanoio/test", 1, func(_ paho.Client, m paho.Message) { got <- string(m.Payload()) }); !tok.WaitTimeout(5*time.Second) || tok.Error() != nil {
		t.Fatalf("subscribe: %v", tok.Error())
	}
	spec, err := Factory("m", json.RawMessage(`{"broker":"`+url+`","topic":"nanoio/test","qos":1}`))
	if err != nil {
		t.Fatal(err)
	}
	defer spec.Target.Close()
	if err := spec.Target.Send(context.Background(), []*event.Event{ev("1"), ev("2")}); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 2; i++ {
		select {
		case m := <-got:
			if !strings.Contains(m, fmt.Sprintf(`"Key":"b/%d"`, i)) {
				t.Errorf("message %d = %s", i, m)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("message %d never arrived", i)
		}
	}
}
