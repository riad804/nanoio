package kafka

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	kafkago "github.com/segmentio/kafka-go"

	"nanoio/internal/event"
)

type fakeProducer struct {
	got    [][]kafkago.Message
	err    error
	closed bool
}

func (f *fakeProducer) WriteMessages(ctx context.Context, msgs ...kafkago.Message) error {
	if f.err != nil {
		return f.err
	}
	f.got = append(f.got, msgs)
	return nil
}

func (f *fakeProducer) Close() error { f.closed = true; return nil }

func ev(key string) *event.Event {
	return &event.Event{Name: event.ObjectCreatedPut, Bucket: "photos", Key: key, Time: time.Now().UTC()}
}

func TestMessagesAreKeyedByObject(t *testing.T) {
	spec, err := Factory("k", json.RawMessage(`{"brokers":["localhost:9092"],"topic":"nanoio","batchSize":50}`))
	if err != nil {
		t.Fatal(err)
	}
	tgt := spec.Target.(*Target)
	fp := &fakeProducer{}
	tgt.w.Close() // the real writer is replaced below
	tgt.w = fp
	if err := tgt.Send(context.Background(), []*event.Event{ev("a"), ev("b"), ev("a")}); err != nil {
		t.Fatal(err)
	}
	if len(fp.got) != 1 || len(fp.got[0]) != 3 {
		t.Fatalf("writes = %v", fp.got)
	}
	m := fp.got[0]
	// Same key twice: kafka-go's Hash balancer sends equal keys to one
	// partition, which is what keeps one object's events in order.
	if string(m[0].Key) != "photos/a" || string(m[2].Key) != "photos/a" || string(m[1].Key) != "photos/b" {
		t.Errorf("keys = %s %s %s", m[0].Key, m[1].Key, m[2].Key)
	}
	var p event.Payload
	if err := json.Unmarshal(m[1].Value, &p); err != nil || p.Records[0].S3.Object.Key != "b" {
		t.Errorf("value = %s (%v)", m[1].Value, err)
	}
	if spec.Delivery.BatchSize != 50 {
		t.Errorf("batchSize = %d", spec.Delivery.BatchSize)
	}
	fp.err = errors.New("leader not available")
	if err := tgt.Send(context.Background(), []*event.Event{ev("a")}); err == nil {
		t.Error("a producer error must fail the send")
	}
	tgt.Close()
	if !fp.closed {
		t.Error("Close must close the producer")
	}
}

func TestWriterIsConfiguredForQueueLayerRetries(t *testing.T) {
	spec, err := Factory("k", json.RawMessage(`{"brokers":["a:9092","b:9092"],"topic":"t","requiredAcks":"one","sasl":{"mechanism":"scram-sha-512","username":"u","password":"p"}}`))
	if err != nil {
		t.Fatal(err)
	}
	w := spec.Target.(*Target).w.(*kafkago.Writer)
	defer w.Close()
	if w.MaxAttempts != 1 || w.RequiredAcks != kafkago.RequireOne || w.AllowAutoTopicCreation {
		t.Errorf("writer = attempts %d acks %v autocreate %v", w.MaxAttempts, w.RequiredAcks, w.AllowAutoTopicCreation)
	}
	if _, ok := w.Balancer.(*kafkago.Hash); !ok {
		t.Errorf("balancer = %T, want *kafka.Hash", w.Balancer)
	}
	if w.Transport.(*kafkago.Transport).SASL == nil {
		t.Error("SASL was not configured")
	}
}

func TestUnreachableBrokerFailsQuickly(t *testing.T) {
	spec, err := Factory("k", json.RawMessage(`{"brokers":["127.0.0.1:1"],"topic":"t","timeout":"1s"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer spec.Target.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	if err := spec.Target.Send(ctx, []*event.Event{ev("a")}); err == nil {
		t.Fatal("send to a closed port succeeded")
	}
	if d := time.Since(start); d > 4*time.Second {
		t.Errorf("failure took %v; the queue layer's timeout must bound it", d)
	}
	if err := spec.Target.(event.Checker).Check(ctx); err == nil {
		t.Error("Check of a closed port must fail")
	}
}

func TestConfigValidation(t *testing.T) {
	for name, cfg := range map[string]string{
		"no brokers": `{"topic":"t"}`, "broker without port": `{"brokers":["h"],"topic":"t"}`,
		"no topic": `{"brokers":["h:9092"]}`, "bad acks": `{"brokers":["h:9092"],"topic":"t","requiredAcks":"most"}`,
		"bad sasl":      `{"brokers":["h:9092"],"topic":"t","sasl":{"mechanism":"gssapi"}}`,
		"user no mech":  `{"brokers":["h:9092"],"topic":"t","sasl":{"username":"u"}}`,
		"unknown field": `{"brokers":["h:9092"],"topic":"t","partition":3}`,
	} {
		if _, err := Factory("k", json.RawMessage(cfg)); err == nil {
			t.Errorf("%s accepted (%s)", name, strings.TrimSpace(cfg))
		}
	}
}

// TestAgainstRealKafka runs only when NANOIO_TEST_KAFKA names a broker
// (host:port); the test creates its own topic. No Kafka broker exists in the
// default test environment, so the wire path of this target is otherwise
// unexercised. With Docker:
//
//	docker run -d --rm -p 127.0.0.1:9092:9092 apache/kafka:latest
//	NANOIO_TEST_KAFKA=127.0.0.1:9092 go test -run AgainstReal ./internal/event/target/kafka
func TestAgainstRealKafka(t *testing.T) {
	addr := os.Getenv("NANOIO_TEST_KAFKA")
	if addr == "" {
		t.Skip("NANOIO_TEST_KAFKA is not set")
	}
	topic := fmt.Sprintf("nanoio-test-%d", time.Now().UnixNano())
	admin := &kafkago.Client{Addr: kafkago.TCP(addr), Timeout: 20 * time.Second}
	cr, err := admin.CreateTopics(context.Background(), &kafkago.CreateTopicsRequest{
		Topics: []kafkago.TopicConfig{{Topic: topic, NumPartitions: 1, ReplicationFactor: 1}}})
	if err != nil {
		t.Fatalf("create topic: %v", err)
	}
	if e := cr.Errors[topic]; e != nil {
		t.Fatalf("create topic: %v", e)
	}
	spec, err := Factory("k", json.RawMessage(`{"brokers":["`+addr+`"],"topic":"`+topic+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer spec.Target.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := spec.Target.(event.Checker).Check(ctx); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if err := spec.Target.Send(ctx, []*event.Event{ev("a"), ev("b")}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	r := kafkago.NewReader(kafkago.ReaderConfig{Brokers: []string{addr}, Topic: topic, Partition: 0, MinBytes: 1, MaxBytes: 1 << 20})
	defer r.Close()
	r.SetOffsetAt(ctx, time.Now().Add(-time.Minute))
	m, err := r.ReadMessage(ctx)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !strings.HasPrefix(string(m.Key), "photos/") {
		t.Errorf("key = %q", m.Key)
	}
}
