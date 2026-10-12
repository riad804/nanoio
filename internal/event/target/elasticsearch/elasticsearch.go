// Package elasticsearch indexes notifications into Elasticsearch (or
// OpenSearch) over its HTTP API using the _bulk endpoint.
//
// Configuration:
//
//	url       base URL of the cluster, required
//	index     index name, required (lower case, as Elasticsearch requires)
//	format    "namespace" (default) or "access", see targetutil.Format
//	username, password   basic authentication
//	tls       {enable, skipVerify, ca, cert, key}
//	+ the shared delivery keys
//
// In the namespace format a document's _id is the SHA-256 of "bucket/key"
// (Elasticsearch limits ids to 512 bytes, S3 keys are up to 1024) and the
// document carries the original key in "Key". In the access format each
// event is a new auto-id document.
package elasticsearch

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"nanoio/internal/event"
	"nanoio/internal/event/target/targetutil"
)

// Type is the target type name.
const Type = "elasticsearch"

// Config is the target's configuration.
type Config struct {
	event.Delivery
	URL      string    `json:"url"`
	Index    string    `json:"index"`
	Format   string    `json:"format"`
	Username string    `json:"username"`
	Password string    `json:"password"`
	TLS      event.TLS `json:"tls"`
}

var indexName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,254}$`)

// Target indexes into one Elasticsearch index.
type Target struct {
	base     string
	index    string
	format   targetutil.Format
	user     string
	password string
	client   *http.Client
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
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return event.Spec{}, errors.New("url must be an http:// or https:// URL")
	}
	if !indexName.MatchString(c.Index) {
		return event.Spec{}, errors.New("index must be a lower-case Elasticsearch index name")
	}
	f, err := targetutil.ParseFormat(c.Format)
	if err != nil {
		return event.Spec{}, err
	}
	tlsCfg, err := c.TLS.Config(u.Hostname())
	if err != nil {
		return event.Spec{}, err
	}
	t := &Target{base: strings.TrimRight(c.URL, "/"), index: c.Index, format: f, user: c.Username, password: c.Password,
		client: &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg, MaxIdleConnsPerHost: 2,
			IdleConnTimeout: 90 * time.Second, Proxy: http.ProxyFromEnvironment}}}
	return event.Spec{Target: t, Delivery: c.Delivery.Defaults(100)}, nil
}

func docID(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// bulkBody renders the NDJSON _bulk request for the events and the number of
// actions in it.
func (t *Target) bulkBody(events []*event.Event) ([]byte, int) {
	var buf bytes.Buffer
	n := 0
	line := func(v any) {
		b, _ := json.Marshal(v)
		buf.Write(b)
		buf.WriteByte('\n')
	}
	type meta map[string]map[string]string
	if t.format == targetutil.Access {
		for _, e := range events {
			line(meta{"index": {"_index": t.index}})
			buf.Write(targetutil.AccessEntry(e))
			buf.WriteByte('\n')
			n++
		}
		return buf.Bytes(), n
	}
	for _, op := range targetutil.NamespaceOps(events) {
		id := docID(op.Key)
		if op.Delete {
			line(meta{"delete": {"_index": t.index, "_id": id}})
		} else {
			line(meta{"index": {"_index": t.index, "_id": id}})
			// The document is {"Key": ..., "Records": [...]}.
			var doc map[string]json.RawMessage
			json.Unmarshal(op.Value, &doc)
			k, _ := json.Marshal(op.Key)
			doc["Key"] = k
			line(doc)
		}
		n++
	}
	return buf.Bytes(), n
}

func (t *Target) request(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, t.base+path, rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/x-ndjson")
	}
	if t.user != "" {
		req.SetBasicAuth(t.user, t.password)
	}
	return t.client.Do(req)
}

// Send indexes the events with one _bulk request. Any item the cluster
// rejects fails the whole batch (the retry is idempotent in the namespace
// format; in the access format a retry may duplicate the accepted items).
func (t *Target) Send(ctx context.Context, events []*event.Event) error {
	body, n := t.bulkBody(events)
	if n == 0 {
		return nil
	}
	resp, err := t.request(ctx, http.MethodPost, "/_bulk", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("elasticsearch answered %s: %s", resp.Status, snippet(raw))
	}
	var out struct {
		Errors bool `json:"errors"`
		Items  []map[string]struct {
			Status int `json:"status"`
			Error  *struct {
				Type   string `json:"type"`
				Reason string `json:"reason"`
			} `json:"error"`
		} `json:"items"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return fmt.Errorf("elasticsearch: unreadable bulk response: %w", err)
	}
	if out.Errors {
		for _, it := range out.Items {
			for action, r := range it {
				// Deleting a document that is not there is not a failure.
				if r.Status == http.StatusNotFound && action == "delete" {
					continue
				}
				if r.Error != nil || r.Status >= 300 {
					reason := ""
					if r.Error != nil {
						reason = r.Error.Type + ": " + r.Error.Reason
					}
					return fmt.Errorf("elasticsearch rejected a %s (status %d) %s", action, r.Status, reason)
				}
			}
		}
	}
	return nil
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return s
}

// Check asks the cluster for its root document.
func (t *Target) Check(ctx context.Context) error {
	resp, err := t.request(ctx, http.MethodGet, "/", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, bufio.NewReader(io.LimitReader(resp.Body, 1<<16)))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("elasticsearch answered %s", resp.Status)
	}
	return nil
}

// Close releases idle connections.
func (t *Target) Close() error {
	t.client.CloseIdleConnections()
	return nil
}
