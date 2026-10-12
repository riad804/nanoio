// Package webhook delivers notifications by HTTP POST of the S3 event JSON.
//
// Configuration (all keys of "notify.targets.webhook.<id>"):
//
//	endpoint   URL to POST to (http or https), required
//	authToken  sent verbatim as the Authorization header, e.g. "Bearer abc"
//	headers    extra request headers
//	tls        {enable, skipVerify, ca, cert, key} for https endpoints
//	+ the shared delivery keys (batchSize, maxAttempts, ...)
//
// Every 2xx response is a success; anything else (including a redirect) is
// a failure and is retried. With batchSize > 1 one request carries several
// records in "Records".
package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"nanoio/internal/event"
)

// Type is the target type name used in ARNs and configuration.
const Type = "webhook"

// Config is the target's configuration.
type Config struct {
	event.Delivery
	Endpoint  string            `json:"endpoint"`
	AuthToken string            `json:"authToken"`
	Headers   map[string]string `json:"headers"`
	TLS       event.TLS         `json:"tls"`
}

// Target is a webhook destination.
type Target struct {
	endpoint string
	token    string
	headers  map[string]string
	client   *http.Client
}

// Factory builds a webhook target from its JSON configuration.
func Factory(id string, raw json.RawMessage) (event.Spec, error) {
	var c Config
	if err := event.DecodeConfig(raw, &c); err != nil {
		return event.Spec{}, err
	}
	if err := c.Delivery.Validate(); err != nil {
		return event.Spec{}, err
	}
	u, err := url.Parse(c.Endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return event.Spec{}, errors.New("endpoint must be an http:// or https:// URL")
	}
	tlsCfg, err := c.TLS.Config(u.Hostname())
	if err != nil {
		return event.Spec{}, err
	}
	t := &Target{endpoint: c.Endpoint, token: c.AuthToken, headers: c.Headers,
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig:     tlsCfg,
				MaxIdleConnsPerHost: 2,
				IdleConnTimeout:     90 * time.Second,
				Proxy:               http.ProxyFromEnvironment,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}}
	return event.Spec{Target: t, Delivery: c.Delivery.Defaults(1)}, nil
}

// Send POSTs the events.
func (t *Target) Send(ctx context.Context, events []*event.Event) error {
	body, err := json.Marshal(event.NewPayload(events))
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "NanoIO")
	for k, v := range t.headers {
		req.Header.Set(k, v)
	}
	if t.token != "" {
		req.Header.Set("Authorization", t.token)
	}
	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("endpoint answered %s: %s", resp.Status, bytes.TrimSpace(snippet))
	}
	return nil
}

// Check reports whether the endpoint answers HTTP at all; any response
// below 500 counts (an endpoint that only accepts POST answers HEAD with
// 405, which still proves it is up).
func (t *Target) Check(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, t.endpoint, nil)
	if err != nil {
		return err
	}
	if t.token != "" {
		req.Header.Set("Authorization", t.token)
	}
	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 500 {
		return fmt.Errorf("endpoint answered %s", resp.Status)
	}
	return nil
}

// Close releases idle connections.
func (t *Target) Close() error {
	t.client.CloseIdleConnections()
	return nil
}
