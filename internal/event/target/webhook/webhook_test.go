package webhook

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"nanoio/internal/event"
)

func newEvent(key string) *event.Event {
	return &event.Event{Name: event.ObjectCreatedPut, Bucket: "photos", Key: key, Size: 9, ETag: "abc",
		Time: time.Now().UTC(), Principal: "AK", Region: "us-east-1"}
}

func build(t *testing.T, cfg string) event.Spec {
	t.Helper()
	spec, err := Factory("hook", json.RawMessage(cfg))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { spec.Target.Close() })
	return spec
}

func TestSendsS3PayloadWithAuth(t *testing.T) {
	var mu sync.Mutex
	var gotBody []byte
	var gotHdr http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		gotBody, gotHdr = b, r.Header.Clone()
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	spec := build(t, `{"endpoint":"`+srv.URL+`","authToken":"Bearer s3cr3t","headers":{"X-Env":"test"},"batchSize":2}`)
	if err := spec.Target.Send(context.Background(), []*event.Event{newEvent("a b.txt"), newEvent("c")}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if gotHdr.Get("Authorization") != "Bearer s3cr3t" || gotHdr.Get("X-Env") != "test" || gotHdr.Get("Content-Type") != "application/json" {
		t.Errorf("headers = %v", gotHdr)
	}
	var p event.Payload
	if err := json.Unmarshal(gotBody, &p); err != nil || p.EventName != "s3:ObjectCreated:Put" || p.Key != "photos/a b.txt" || len(p.Records) != 2 {
		t.Fatalf("payload = %s (%v)", gotBody, err)
	}
	if p.Records[0].S3.Object.Key != "a+b.txt" || p.Records[0].S3.Bucket.Name != "photos" || p.Records[1].S3.Object.Key != "c" {
		t.Errorf("records = %+v", p.Records)
	}
	if spec.Delivery.BatchSize != 2 {
		t.Errorf("batchSize = %d", spec.Delivery.BatchSize)
	}
}

func TestFailuresAreErrors(t *testing.T) {
	var status int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status == 302 {
			http.Redirect(w, r, "/elsewhere", status)
			return
		}
		w.WriteHeader(status)
		io.WriteString(w, "nope: "+strings.Repeat("x", 2000))
	}))
	defer srv.Close()
	spec := build(t, `{"endpoint":"`+srv.URL+`"}`)
	for _, st := range []int{400, 500, 302} {
		status = st
		err := spec.Target.Send(context.Background(), []*event.Event{newEvent("a")})
		if err == nil || !strings.Contains(err.Error(), http.StatusText(st)) {
			t.Errorf("status %d: err = %v", st, err)
		}
		if err != nil && len(err.Error()) > 700 {
			t.Errorf("error message is %d bytes; the response snippet must be bounded", len(err.Error()))
		}
	}
	status = 204
	if err := spec.Target.Send(context.Background(), []*event.Event{newEvent("a")}); err != nil {
		t.Errorf("204 must succeed: %v", err)
	}
}

func TestUnreachableAndCheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusMethodNotAllowed) // POST-only endpoint
	}))
	spec := build(t, `{"endpoint":"`+srv.URL+`"}`)
	chk := spec.Target.(event.Checker)
	if err := chk.Check(context.Background()); err != nil {
		t.Errorf("a live endpoint answering 405 is online: %v", err)
	}
	srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := chk.Check(ctx); err == nil {
		t.Error("a closed endpoint must fail Check")
	}
	if err := spec.Target.Send(ctx, []*event.Event{newEvent("a")}); err == nil {
		t.Error("a closed endpoint must fail Send")
	}
}

func TestConfigValidation(t *testing.T) {
	for name, cfg := range map[string]string{
		"no endpoint":    `{}`,
		"bad scheme":     `{"endpoint":"ftp://x"}`,
		"unknown key":    `{"endpoint":"http://x","endpiont":"y"}`,
		"bad batch":      `{"endpoint":"http://x","batchSize":5000}`,
		"bad attempts":   `{"endpoint":"http://x","maxAttempts":-5}`,
		"bad tls ca":     `{"endpoint":"https://x","tls":{"ca":"/nonexistent/ca.pem"}}`,
		"cert without k": `{"endpoint":"https://x","tls":{"enable":true,"cert":"/x"}}`,
		"bad duration":   `{"endpoint":"http://x","timeout":"soon"}`,
	} {
		if _, err := Factory("h", json.RawMessage(cfg)); err == nil {
			t.Errorf("%s: config %s was accepted", name, cfg)
		}
	}
	spec, err := Factory("h", json.RawMessage(`{"endpoint":"http://localhost:1/x"}`))
	if err != nil {
		t.Fatal(err)
	}
	d := spec.Delivery
	if d.BatchSize != 1 || d.MaxAttempts != 10 || d.QueueLimit != 100000 || d.RetryBase.D() != time.Second || d.Timeout.D() != 30*time.Second {
		t.Errorf("defaults = %+v", d)
	}
}
