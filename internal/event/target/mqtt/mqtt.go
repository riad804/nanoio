// Package mqtt publishes notifications to an MQTT broker.
//
// Configuration:
//
//	broker     tcp://host:port, ssl://host:port or ws://host:port, required
//	topic      topic to publish to, required
//	qos        0, 1 (default) or 2. At QoS 0 the broker does not
//	           acknowledge, so a lost event is not noticed; keep 1 or 2
//	           when delivery matters.
//	clientId   defaults to "nanoio-<target id>"
//	username, password
//	keepAlive  e.g. "30s"
//	tls        {enable, skipVerify, ca, cert, key} (implied by ssl://)
//	+ the shared delivery keys
package mqtt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"

	paho "github.com/eclipse/paho.mqtt.golang"

	"nanoio/internal/config"
	"nanoio/internal/event"
)

// Type is the target type name.
const Type = "mqtt"

// Config is the target's configuration.
type Config struct {
	event.Delivery
	Broker    string          `json:"broker"`
	Topic     string          `json:"topic"`
	QoS       *int            `json:"qos"`
	ClientID  string          `json:"clientId"`
	Username  string          `json:"username"`
	Password  string          `json:"password"`
	KeepAlive config.Duration `json:"keepAlive"`
	TLS       event.TLS       `json:"tls"`
}

// Target publishes to one broker.
type Target struct {
	opts    *paho.ClientOptions
	topic   string
	qos     byte
	timeout time.Duration

	mu sync.Mutex
	c  paho.Client
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
	u, err := url.Parse(c.Broker)
	if err != nil || u.Host == "" {
		return event.Spec{}, errors.New("broker must be a tcp://, ssl://, ws:// or wss:// URL")
	}
	switch u.Scheme {
	case "tcp", "ssl", "tls", "ws", "wss", "mqtt", "mqtts":
	default:
		return event.Spec{}, fmt.Errorf("broker scheme %q is not supported", u.Scheme)
	}
	if c.Topic == "" {
		return event.Spec{}, errors.New("topic is required")
	}
	qos := 1
	if c.QoS != nil {
		qos = *c.QoS
	}
	if qos < 0 || qos > 2 {
		return event.Spec{}, errors.New("qos must be 0, 1 or 2")
	}
	d := c.Delivery.Defaults(1)
	cid := c.ClientID
	if cid == "" {
		cid = "nanoio-" + id
	}
	o := paho.NewClientOptions().AddBroker(c.Broker).SetClientID(cid).
		SetUsername(c.Username).SetPassword(c.Password).
		SetAutoReconnect(false).SetConnectRetry(false).SetCleanSession(true).
		SetConnectTimeout(d.Timeout.D()).SetWriteTimeout(d.Timeout.D())
	if c.KeepAlive > 0 {
		o.SetKeepAlive(c.KeepAlive.D())
	}
	secure := u.Scheme == "ssl" || u.Scheme == "tls" || u.Scheme == "wss" || u.Scheme == "mqtts"
	tc := c.TLS
	tc.Enable = tc.Enable || secure
	tlsCfg, err := tc.Config(u.Hostname())
	if err != nil {
		return event.Spec{}, err
	}
	if tlsCfg != nil {
		o.SetTLSConfig(tlsCfg)
	}
	return event.Spec{Target: &Target{opts: o, topic: c.Topic, qos: byte(qos), timeout: d.Timeout.D()}, Delivery: d}, nil
}

func (t *Target) client() (paho.Client, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.c != nil && t.c.IsConnectionOpen() {
		return t.c, nil
	}
	if t.c != nil {
		t.c.Disconnect(0)
	}
	c := paho.NewClient(t.opts)
	tok := c.Connect()
	if !tok.WaitTimeout(t.timeout) {
		return nil, errors.New("mqtt: connect timed out")
	}
	if err := tok.Error(); err != nil {
		return nil, err
	}
	t.c = c
	return c, nil
}

func (t *Target) drop(c paho.Client) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.c == c {
		c.Disconnect(0)
		t.c = nil
	}
}

// Send publishes one message per event, in order, waiting for each
// acknowledgement the QoS level calls for.
func (t *Target) Send(ctx context.Context, events []*event.Event) error {
	c, err := t.client()
	if err != nil {
		return err
	}
	for _, e := range events {
		tok := c.Publish(t.topic, t.qos, false, e.JSON())
		wait := t.timeout
		if dl, ok := ctx.Deadline(); ok {
			if r := time.Until(dl); r < wait {
				wait = r
			}
		}
		if !tok.WaitTimeout(wait) {
			t.drop(c)
			return errors.New("mqtt: publish was not acknowledged in time")
		}
		if err := tok.Error(); err != nil {
			t.drop(c)
			return err
		}
	}
	return nil
}

// Check connects if needed and reports whether the broker is reachable.
func (t *Target) Check(ctx context.Context) error {
	_, err := t.client()
	return err
}

// Close disconnects.
func (t *Target) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.c != nil {
		t.c.Disconnect(250)
		t.c = nil
	}
	return nil
}
