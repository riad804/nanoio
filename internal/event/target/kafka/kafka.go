// Package kafka produces notifications to an Apache Kafka topic.
//
// Configuration:
//
//	brokers      ["host:port", ...], required
//	topic        required
//	clientId     defaults to "nanoio"
//	requiredAcks "all" (default), "one" or "none". Only "all" survives the
//	             loss of a leader without losing an acknowledged event.
//	sasl         {mechanism: plain|scram-sha-256|scram-sha-512,
//	              username, password}
//	tls          {enable, skipVerify, ca, cert, key}
//	+ the shared delivery keys
//
// The message key is "bucket/key" and the value is the S3 event JSON, so
// all events for one object land in one partition, in order.
package kafka

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	kafkago "github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl"
	"github.com/segmentio/kafka-go/sasl/plain"
	"github.com/segmentio/kafka-go/sasl/scram"

	"nanoio/internal/event"
)

// Type is the target type name.
const Type = "kafka"

// SASL configures authentication.
type SASL struct {
	Mechanism string `json:"mechanism"`
	Username  string `json:"username"`
	Password  string `json:"password"`
}

// Config is the target's configuration.
type Config struct {
	event.Delivery
	Brokers      []string  `json:"brokers"`
	Topic        string    `json:"topic"`
	ClientID     string    `json:"clientId"`
	RequiredAcks string    `json:"requiredAcks"`
	SASL         SASL      `json:"sasl"`
	TLS          event.TLS `json:"tls"`
}

// producer is the part of kafka-go's Writer the target uses; tests
// substitute it.
type producer interface {
	WriteMessages(ctx context.Context, msgs ...kafkago.Message) error
	Close() error
}

// Target produces to one topic.
type Target struct {
	w       producer
	brokers []string
	topic   string
	client  *kafkago.Client
}

// Factory builds the target from its JSON configuration.
func Factory(id string, raw json.RawMessage) (event.Spec, error) {
	var c Config
	if err := event.DecodeConfig(raw, &c); err != nil {
		return event.Spec{}, err
	}
	if err := c.Delivery.Validate(); err != nil {
		return event.Spec{}, err
	}
	if len(c.Brokers) == 0 {
		return event.Spec{}, errors.New("brokers is required")
	}
	for _, b := range c.Brokers {
		if _, _, err := net.SplitHostPort(b); err != nil {
			return event.Spec{}, fmt.Errorf("broker %q: %w", b, err)
		}
	}
	if c.Topic == "" {
		return event.Spec{}, errors.New("topic is required")
	}
	acks := kafkago.RequireAll
	switch c.RequiredAcks {
	case "", "all":
	case "one":
		acks = kafkago.RequireOne
	case "none":
		acks = kafkago.RequireNone
	default:
		return event.Spec{}, fmt.Errorf("requiredAcks %q: must be all, one or none", c.RequiredAcks)
	}
	mech, err := saslMechanism(c.SASL)
	if err != nil {
		return event.Spec{}, err
	}
	d := c.Delivery.Defaults(100)
	host, _, _ := net.SplitHostPort(c.Brokers[0])
	tlsCfg, err := c.TLS.Config(host)
	if err != nil {
		return event.Spec{}, err
	}
	tr := newTransport(c, mech, tlsCfg, d.Timeout.D())
	w := &kafkago.Writer{
		Addr:                   kafkago.TCP(c.Brokers...),
		Topic:                  c.Topic,
		Balancer:               &kafkago.Hash{}, // same key, same partition
		RequiredAcks:           acks,
		MaxAttempts:            1, // the queue layer retries
		BatchTimeout:           5 * time.Millisecond,
		WriteTimeout:           d.Timeout.D(),
		ReadTimeout:            d.Timeout.D(),
		AllowAutoTopicCreation: false,
		Transport:              tr,
	}
	return event.Spec{Target: &Target{w: w, brokers: c.Brokers, topic: c.Topic,
		client: &kafkago.Client{Addr: kafkago.TCP(c.Brokers...), Timeout: d.Timeout.D(), Transport: tr}}, Delivery: d}, nil
}

func newTransport(c Config, mech sasl.Mechanism, tlsCfg *tls.Config, timeout time.Duration) *kafkago.Transport {
	id := c.ClientID
	if id == "" {
		id = "nanoio"
	}
	return &kafkago.Transport{
		ClientID: id, SASL: mech, TLS: tlsCfg, DialTimeout: timeout, IdleTimeout: 30 * time.Second,
		Dial: (&net.Dialer{Timeout: timeout}).DialContext,
	}
}

func saslMechanism(s SASL) (sasl.Mechanism, error) {
	switch s.Mechanism {
	case "":
		if s.Username != "" || s.Password != "" {
			return nil, errors.New("sasl.mechanism is required with a username")
		}
		return nil, nil
	case "plain":
		return plain.Mechanism{Username: s.Username, Password: s.Password}, nil
	case "scram-sha-256":
		return scram.Mechanism(scram.SHA256, s.Username, s.Password)
	case "scram-sha-512":
		return scram.Mechanism(scram.SHA512, s.Username, s.Password)
	}
	return nil, fmt.Errorf("sasl.mechanism %q: must be plain, scram-sha-256 or scram-sha-512", s.Mechanism)
}

func messages(events []*event.Event) []kafkago.Message {
	msgs := make([]kafkago.Message, len(events))
	for i, e := range events {
		msgs[i] = kafkago.Message{Key: []byte(e.ObjectPath()), Value: e.JSON(), Time: e.Time}
	}
	return msgs
}

// Send produces the events as one write.
func (t *Target) Send(ctx context.Context, events []*event.Event) error {
	return t.w.WriteMessages(ctx, messages(events)...)
}

// Check asks the cluster for the topic's metadata.
func (t *Target) Check(ctx context.Context) error {
	if t.client == nil {
		return nil
	}
	resp, err := t.client.Metadata(ctx, &kafkago.MetadataRequest{Topics: []string{t.topic}})
	if err != nil {
		return err
	}
	for _, tp := range resp.Topics {
		if tp.Name == t.topic && tp.Error != nil {
			return fmt.Errorf("topic %s: %w", t.topic, tp.Error)
		}
	}
	return nil
}

// Close closes the producer.
func (t *Target) Close() error { return t.w.Close() }
