package elasticsearch

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

func ev(name, key string) *event.Event {
	return &event.Event{Name: name, Bucket: "b", Key: key, Time: time.Unix(1700000000, 0).UTC(), Size: 1}
}

type fakeES struct {
	mu     sync.Mutex
	bulks  []string
	auth   string
	reply  string
	status int
}

func (f *fakeES) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path == "/_bulk" && r.Method == http.MethodPost {
		f.bulks = append(f.bulks, string(b))
		f.auth = r.Header.Get("Authorization")
		if f.status != 0 {
			w.WriteHeader(f.status)
		}
		io.WriteString(w, f.reply)
		return
	}
	io.WriteString(w, `{"name":"es"}`)
}

func lines(s string) []string { return strings.Split(strings.TrimSpace(s), "\n") }

func TestNamespaceBulk(t *testing.T) {
	f := &fakeES{reply: `{"errors":false,"items":[]}`}
	srv := httptest.NewServer(f)
	defer srv.Close()
	spec, err := Factory("es", json.RawMessage(`{"url":"`+srv.URL+`","index":"nanoio-events","username":"u","password":"p"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer spec.Target.Close()
	err = spec.Target.Send(context.Background(), []*event.Event{
		ev(event.ObjectCreatedPut, "a"), ev(event.ObjectAccessedGet, "a"), ev(event.ObjectRemovedDelete, "a")})
	if err != nil {
		t.Fatal(err)
	}
	ls := lines(f.bulks[0])
	// index action, document, delete action; the GET is not a namespace change.
	if len(ls) != 3 || !strings.HasPrefix(ls[0], `{"index":{"_id":"`) || !strings.HasPrefix(ls[2], `{"delete":{"_id":"`) {
		t.Fatalf("bulk body:\n%s", f.bulks[0])
	}
	var doc struct {
		Key     string
		Records []map[string]any
	}
	if err := json.Unmarshal([]byte(ls[1]), &doc); err != nil || doc.Key != "b/a" || len(doc.Records) != 1 {
		t.Errorf("document = %s (%v)", ls[1], err)
	}
	var idx, del map[string]map[string]string
	json.Unmarshal([]byte(ls[0]), &idx)
	json.Unmarshal([]byte(ls[2]), &del)
	if idx["index"]["_id"] != del["delete"]["_id"] || idx["index"]["_index"] != "nanoio-events" || len(idx["index"]["_id"]) != 64 {
		t.Errorf("ids: %v vs %v", idx, del)
	}
	if f.auth == "" {
		t.Error("basic auth was not sent")
	}
}

func TestAccessFormatAndRejections(t *testing.T) {
	f := &fakeES{reply: `{"errors":false}`}
	srv := httptest.NewServer(f)
	defer srv.Close()
	spec, _ := Factory("es", json.RawMessage(`{"url":"`+srv.URL+`","index":"i","format":"access"}`))
	defer spec.Target.Close()
	if err := spec.Target.Send(context.Background(), []*event.Event{ev(event.ObjectAccessedGet, "a"), ev(event.ObjectCreatedPut, "b")}); err != nil {
		t.Fatal(err)
	}
	ls := lines(f.bulks[0])
	if len(ls) != 4 || ls[0] != `{"index":{"_index":"i"}}` || !strings.Contains(ls[1], `"EventTime":"2023-11-14T22:13:20.000Z"`) {
		t.Fatalf("access bulk:\n%s", f.bulks[0])
	}

	// A rejected item fails the batch; a delete of a missing document does not.
	f.reply = `{"errors":true,"items":[{"delete":{"status":404}},{"index":{"status":400,"error":{"type":"mapper_parsing_exception","reason":"bad"}}}]}`
	err := spec.Target.Send(context.Background(), []*event.Event{ev(event.ObjectCreatedPut, "b")})
	if err == nil || !strings.Contains(err.Error(), "mapper_parsing_exception") {
		t.Errorf("rejected item: err = %v", err)
	}
	f.reply = `{"errors":true,"items":[{"delete":{"status":404}}]}`
	if err := spec.Target.Send(context.Background(), []*event.Event{ev(event.ObjectRemovedDelete, "b")}); err != nil {
		t.Errorf("delete of a missing document: %v", err)
	}
	f.status, f.reply = 503, "unavailable"
	if err := spec.Target.Send(context.Background(), []*event.Event{ev(event.ObjectCreatedPut, "b")}); err == nil {
		t.Error("a 503 must fail")
	}
	if err := spec.Target.(event.Checker).Check(context.Background()); err != nil {
		t.Errorf("Check: %v", err)
	}
}

func TestConfigValidation(t *testing.T) {
	for name, cfg := range map[string]string{
		"no url":      `{"index":"i"}`,
		"bad url":     `{"url":"es:9200","index":"i"}`,
		"no index":    `{"url":"http://x"}`,
		"upper index": `{"url":"http://x","index":"Events"}`,
		"bad format":  `{"url":"http://x","index":"i","format":"x"}`,
	} {
		if _, err := Factory("e", json.RawMessage(cfg)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
