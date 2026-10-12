// Package amqp publishes notifications to an AMQP 0-9-1 broker (RabbitMQ).
//
// Configuration:
//
//	url           amqp:// or amqps:// URL including credentials and vhost,
//	              required
//	exchange      exchange to publish to ("" is the default exchange, which
//	              routes by queue name through routingKey)
//	exchangeType  fanout (default), direct, topic or headers; used when
//	              the exchange is declared
//	routingKey    routing key (default "")
//	declare       declare the exchange on connect (default true)
//	durable, autoDeleted, internal   exchange declaration flags
//	mandatory     ask the broker to return unroutable messages, which then
//	              fail the delivery (default true)
//	deliveryMode  1 transient or 2 persistent (default 2)
//	tls           {enable, skipVerify, ca, cert, key}
//	+ the shared delivery keys
//
// Messages are published with publisher confirms: a batch succeeds only
// when the broker has acknowledged every message in it.
package amqp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"

	amqp091 "github.com/rabbitmq/amqp091-go"

	"nanoio/internal/event"
)

// Type is the target type name.
const Type = "amqp"

// Config is the target's configuration.
type Config struct {
	event.Delivery
	URL          string    `json:"url"`
	Exchange     string    `json:"exchange"`
	ExchangeType string    `json:"exchangeType"`
	RoutingKey   string    `json:"routingKey"`
	Declare      *bool     `json:"declare"`
	Durable      bool      `json:"durable"`
	AutoDeleted  bool      `json:"autoDeleted"`
	Internal     bool      `json:"internal"`
	Mandatory    *bool     `json:"mandatory"`
	DeliveryMode uint8     `json:"deliveryMode"`
	TLS          event.TLS `json:"tls"`
}

// Target publishes to one broker.
type Target struct {
	url      string
	cfg      Config
	declare  bool
	required bool
	mode     uint8
	timeout  time.Duration
	dial     func(url string, c amqp091.Config) (*amqp091.Connection, error)
	tlsCfg   func() amqp091.Config

	mu   sync.Mutex
	conn *amqp091.Connection
	ch   *amqp091.Channel
	conf <-chan amqp091.Confirmation
	ret  <-chan amqp091.Return
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
	u, err := url.Parse(c.URL)
	if err != nil || u.Host == "" || (u.Scheme != "amqp" && u.Scheme != "amqps") {
		return event.Spec{}, errors.New("url must be an amqp:// or amqps:// URL")
	}
	switch c.ExchangeType {
	case "":
		c.ExchangeType = "fanout"
	case "fanout", "direct", "topic", "headers":
	default:
		return event.Spec{}, fmt.Errorf("exchangeType %q: must be fanout, direct, topic or headers", c.ExchangeType)
	}
	if c.DeliveryMode == 0 {
		c.DeliveryMode = 2
	}
	if c.DeliveryMode != 1 && c.DeliveryMode != 2 {
		return event.Spec{}, errors.New("deliveryMode must be 1 or 2")
	}
	d := c.Delivery.Defaults(100)
	tc := c.TLS
	tc.Enable = tc.Enable || u.Scheme == "amqps"
	tlsCfg, err := tc.Config(u.Hostname())
	if err != nil {
		return event.Spec{}, err
	}
	t := &Target{url: c.URL, cfg: c, declare: c.Declare == nil || *c.Declare,
		required: c.Mandatory == nil || *c.Mandatory, mode: c.DeliveryMode, timeout: d.Timeout.D(),
		dial: amqp091.DialConfig}
	t.tlsCfg = func() amqp091.Config {
		return amqp091.Config{TLSClientConfig: tlsCfg, Dial: amqp091.DefaultDial(d.Timeout.D()),
			Heartbeat: 10 * time.Second, Properties: amqp091.Table{"connection_name": "nanoio"}}
	}
	return event.Spec{Target: t, Delivery: d}, nil
}

// connect (re)establishes the connection and channel, in confirm mode.
func (t *Target) connect() error {
	if t.conn != nil && !t.conn.IsClosed() && t.ch != nil {
		return nil
	}
	t.closeLocked()
	conn, err := t.dial(t.url, t.tlsCfg())
	if err != nil {
		return err
	}
	ch, err := conn.Channel()
	if err != nil {
		conn.Close()
		return err
	}
	if t.declare && t.cfg.Exchange != "" {
		err = ch.ExchangeDeclare(t.cfg.Exchange, t.cfg.ExchangeType, t.cfg.Durable, t.cfg.AutoDeleted, t.cfg.Internal, false, nil)
		if err != nil {
			conn.Close()
			return err
		}
	}
	if err := ch.Confirm(false); err != nil {
		conn.Close()
		return err
	}
	t.conn, t.ch = conn, ch
	t.conf = ch.NotifyPublish(make(chan amqp091.Confirmation, 1024))
	t.ret = ch.NotifyReturn(make(chan amqp091.Return, 64))
	return nil
}

func (t *Target) closeLocked() {
	if t.conn != nil {
		t.conn.Close()
	}
	t.conn, t.ch, t.conf, t.ret = nil, nil, nil, nil
}

// Send publishes the events and waits for the broker's confirmation of each.
func (t *Target) Send(ctx context.Context, events []*event.Event) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.connect(); err != nil {
		return err
	}
	for _, e := range events {
		err := t.ch.PublishWithContext(ctx, t.cfg.Exchange, t.cfg.RoutingKey, t.required, false, amqp091.Publishing{
			ContentType: "application/json", DeliveryMode: t.mode, Timestamp: e.Time, Body: e.JSON(),
		})
		if err != nil {
			t.closeLocked()
			return err
		}
	}
	for range events {
		select {
		case c, ok := <-t.conf:
			if !ok {
				t.closeLocked()
				return errors.New("amqp: connection closed before the broker confirmed the message")
			}
			if !c.Ack {
				t.closeLocked()
				return errors.New("amqp: the broker refused (nacked) a message")
			}
			// A mandatory message nobody can receive is returned before
			// its ack, so a return is already waiting if there was one.
			// It is a failure: retried or dead-lettered, not dropped.
			select {
			case r := <-t.ret:
				t.closeLocked()
				return fmt.Errorf("amqp: message returned as unroutable (%d %s)", r.ReplyCode, r.ReplyText)
			default:
			}
		case <-ctx.Done():
			t.closeLocked()
			return ctx.Err()
		}
	}
	return nil
}

// Check connects (and declares the exchange) if needed.
func (t *Target) Check(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.connect()
}

// Close closes the connection.
func (t *Target) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closeLocked()
	return nil
}
