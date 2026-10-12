// Package nats publishes notifications to a NATS subject.
//
// Configuration:
//
//	address    nats://host:port (or tls://), required
//	subject    subject to publish to, required
//	jetstream  publish through JetStream and wait for its acknowledgement
//	           (the subject must belong to an existing stream). Without it
//	           the event is published to core NATS and the delivery is
//	           confirmed once the server has received it: core NATS does
//	           not tell the publisher whether any subscriber took the
//	           message, so use JetStream where that matters.
//	username, password, token, credentialsFile
//	tls        {enable, skipVerify, ca, cert, key}
//	+ the shared delivery keys
package nats

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"

	natsgo "github.com/nats-io/nats.go"

	"nanoio/internal/event"
)

// Type is the target type name.
const Type = "nats"

// Config is the target's configuration.
type Config struct {
	event.Delivery
	Address         string    `json:"address"`
	Subject         string    `json:"subject"`
	JetStream       bool      `json:"jetstream"`
	Username        string    `json:"username"`
	Password        string    `json:"password"`
	Token           string    `json:"token"`
	CredentialsFile string    `json:"credentialsFile"`
	TLS             event.TLS `json:"tls"`
}

// Target publishes to one subject.
type Target struct {
	opts    []natsgo.Option
	address string
	subject string
	js      bool
	timeout time.Duration

	mu sync.Mutex
	nc *natsgo.Conn
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
	u, err := url.Parse(c.Address)
	if err != nil || u.Host == "" || (u.Scheme != "nats" && u.Scheme != "tls") {
		return event.Spec{}, errors.New("address must be a nats:// or tls:// URL")
	}
	if c.Subject == "" {
		return event.Spec{}, errors.New("subject is required")
	}
	d := c.Delivery.Defaults(100)
	tlsCfg, err := c.TLS.Config(u.Hostname())
	if err != nil {
		return event.Spec{}, err
	}
	opts := []natsgo.Option{
		natsgo.Name("nanoio"),
		natsgo.Timeout(d.Timeout.D()),
		natsgo.NoReconnect(), // reconnection is the queue layer's job
		natsgo.MaxReconnects(0),
	}
	if c.Username != "" {
		opts = append(opts, natsgo.UserInfo(c.Username, c.Password))
	}
	if c.Token != "" {
		opts = append(opts, natsgo.Token(c.Token))
	}
	if c.CredentialsFile != "" {
		opts = append(opts, natsgo.UserCredentials(c.CredentialsFile))
	}
	if tlsCfg != nil {
		opts = append(opts, natsgo.Secure(tlsCfg))
	}
	return event.Spec{Target: &Target{opts: opts, address: c.Address, subject: c.Subject, js: c.JetStream,
		timeout: d.Timeout.D()}, Delivery: d}, nil
}

func (t *Target) conn() (*natsgo.Conn, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.nc != nil && t.nc.IsConnected() {
		return t.nc, nil
	}
	if t.nc != nil {
		t.nc.Close()
		t.nc = nil
	}
	nc, err := natsgo.Connect(t.address, t.opts...)
	if err != nil {
		return nil, err
	}
	t.nc = nc
	return nc, nil
}

func (t *Target) drop(nc *natsgo.Conn) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.nc == nc {
		nc.Close()
		t.nc = nil
	}
}

// Send publishes one message per event, in order.
func (t *Target) Send(ctx context.Context, events []*event.Event) error {
	nc, err := t.conn()
	if err != nil {
		return err
	}
	var js natsgo.JetStreamContext
	if t.js {
		if js, err = nc.JetStream(natsgo.Context(ctx)); err != nil {
			t.drop(nc)
			return err
		}
	}
	for _, e := range events {
		body := e.JSON()
		if js != nil {
			_, err = js.Publish(t.subject, body, natsgo.Context(ctx))
		} else {
			err = nc.Publish(t.subject, body)
		}
		if err != nil {
			t.drop(nc)
			return err
		}
	}
	if js == nil {
		// A PING/PONG round trip: once the server answers, it has read
		// every message published before the PING.
		if err := nc.FlushTimeout(t.timeout); err != nil {
			t.drop(nc)
			return fmt.Errorf("nats: %w", err)
		}
	}
	return nil
}

// Check connects (if not connected) and round-trips a PING.
func (t *Target) Check(ctx context.Context) error {
	nc, err := t.conn()
	if err != nil {
		return err
	}
	if err := nc.FlushTimeout(5 * time.Second); err != nil {
		t.drop(nc)
		return err
	}
	return nil
}

// Close closes the connection.
func (t *Target) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.nc != nil {
		t.nc.Close()
		t.nc = nil
	}
	return nil
}
