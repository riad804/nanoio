// Package redis writes notifications to Redis.
//
// Configuration:
//
//	address    host:port, required
//	key        the Redis key, required (a hash in namespace format, a list
//	           in access format)
//	format     "namespace" (default) or "access"
//	username, password, db
//	tls        {enable, skipVerify, ca, cert, key}
//	+ the shared delivery keys
//
// Namespace: HSET key "bucket/key" <record JSON> on create, HDEL on removal.
// Access: RPUSH key <entry JSON> for every event.
package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"nanoio/internal/event"
	"nanoio/internal/event/target/targetutil"
)

// Type is the target type name.
const Type = "redis"

// Config is the target's configuration.
type Config struct {
	event.Delivery
	Address  string    `json:"address"`
	Key      string    `json:"key"`
	Format   string    `json:"format"`
	Username string    `json:"username"`
	Password string    `json:"password"`
	DB       int       `json:"db"`
	TLS      event.TLS `json:"tls"`
}

// Target writes to one Redis server.
type Target struct {
	client goredis.UniversalClient
	key    string
	format targetutil.Format
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
	host, _, err := net.SplitHostPort(c.Address)
	if err != nil {
		return event.Spec{}, fmt.Errorf("address %q: %w", c.Address, err)
	}
	if c.Key == "" {
		return event.Spec{}, errors.New("key is required")
	}
	if c.DB < 0 {
		return event.Spec{}, errors.New("db must not be negative")
	}
	f, err := targetutil.ParseFormat(c.Format)
	if err != nil {
		return event.Spec{}, err
	}
	tlsCfg, err := c.TLS.Config(host)
	if err != nil {
		return event.Spec{}, err
	}
	d := c.Delivery.Defaults(100)
	cl := goredis.NewClient(&goredis.Options{
		Addr: c.Address, Username: c.Username, Password: c.Password, DB: c.DB, TLSConfig: tlsCfg,
		MaxRetries:   -1, // the queue layer owns retries
		DialTimeout:  d.Timeout.D(),
		ReadTimeout:  d.Timeout.D(),
		WriteTimeout: d.Timeout.D(),
	})
	return event.Spec{Target: &Target{client: cl, key: c.Key, format: f}, Delivery: d}, nil
}

// Send applies the events in one pipeline.
func (t *Target) Send(ctx context.Context, events []*event.Event) error {
	pipe := t.client.TxPipeline()
	n := 0
	if t.format == targetutil.Access {
		for _, e := range events {
			pipe.RPush(ctx, t.key, targetutil.AccessEntry(e))
			n++
		}
	} else {
		for _, op := range targetutil.NamespaceOps(events) {
			if op.Delete {
				pipe.HDel(ctx, t.key, op.Key)
			} else {
				pipe.HSet(ctx, t.key, op.Key, op.Value)
			}
			n++
		}
	}
	if n == 0 {
		return nil
	}
	_, err := pipe.Exec(ctx)
	return err
}

// Check sends PING.
func (t *Target) Check(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return t.client.Ping(ctx).Err()
}

// Close closes the connection pool.
func (t *Target) Close() error { return t.client.Close() }
