package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"nanoio/internal/event"
)

// receiver is a webhook endpoint that can be switched between refusing and
// accepting events.
type receiver struct {
	srv  *httptest.Server
	down atomic.Bool
	mu   sync.Mutex
	keys []string
}

func newReceiver(t *testing.T) *receiver {
	t.Helper()
	r := &receiver{}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		if r.down.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		var p event.Payload
		if err := json.Unmarshal(b, &p); err == nil {
			r.mu.Lock()
			for _, rec := range p.Records {
				r.keys = append(r.keys, rec.EventName+" "+rec.S3.Object.Key)
			}
			r.mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *receiver) got() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.keys...)
}

// The whole path through the real server: S3 requests produce events, a
// webhook that is down cannot lose them, and a restart of the server picks
// the queue up where it left off.
func TestNotificationsSurviveWebhookOutageAndRestart(t *testing.T) {
	rcv := newReceiver(t)
	rcv.down.Store(true)
	root := filepath.Join(t.TempDir(), "data")
	cfgPath := filepath.Join(t.TempDir(), "nanoio.json")
	cfg := fmt.Sprintf(`{"root":%q,"notify":{"targets":{"webhook":{"primary":{
		"endpoint":%q,"retryBase":"10ms","retryMax":"40ms","maxAttempts":-1,"timeout":"2s"}}}}}`, root, rcv.srv.URL)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	out, stop := runUntilReady(t, []string{"--config", cfgPath}, nil)
	base := "http://" + addrRE.FindStringSubmatch(out.String())[1]
	do := func(method, path, body string) (int, string) {
		t.Helper()
		return signedDo(t, base, testUser, testSecret, method, path, body)
	}
	if st, b := do("PUT", "/photos", ""); st != 200 {
		t.Fatalf("create bucket: %d %s", st, b)
	}
	notif := `<NotificationConfiguration><QueueConfiguration><Queue>arn:minio:sqs::primary:webhook</Queue>
		<Event>s3:ObjectCreated:*</Event><Event>s3:ObjectRemoved:*</Event></QueueConfiguration></NotificationConfiguration>`
	if st, b := do("PUT", "/photos?notification", notif); st != 200 {
		t.Fatalf("put notification: %d %s", st, b)
	}
	if st, b := do("PUT", "/photos?notification", strings.Replace(notif, "primary", "nope", 1)); st != 400 || !strings.Contains(b, "InvalidArgument") {
		t.Fatalf("unknown ARN: %d %s", st, b)
	}

	start := time.Now()
	for i := 0; i < 5; i++ {
		if st, b := do("PUT", fmt.Sprintf("/photos/obj-%d", i), "data"); st != 200 {
			t.Fatalf("put %d: %d %s", i, st, b)
		}
	}
	if st, _ := do("DELETE", "/photos/obj-0", ""); st != 204 {
		t.Fatalf("delete: %d", st)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("six requests took %v with the webhook down", d)
	}

	// Status endpoint: the queue holds the six events and the target is
	// reported offline.
	deadline := time.Now().Add(5 * time.Second)
	var status string
	for {
		_, status = do("GET", "/_nanoio/admin/notify/targets", "")
		if strings.Contains(status, `"queueLength": 6`) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("status never showed 6 queued events:\n%s", status)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(status, `"online": false`) || !strings.Contains(status, "503") {
		t.Errorf("status does not show the failing target:\n%s", status)
	}
	if got := rcv.got(); len(got) != 0 {
		t.Fatalf("a down webhook received %v", got)
	}
	if err := stop(); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	// Restart with the webhook back: nothing is lost, order is kept.
	rcv.down.Store(false)
	out2, stop2 := runUntilReady(t, []string{"--config", cfgPath}, nil)
	defer stop2()
	_ = out2
	want := []string{
		"s3:ObjectCreated:Put obj-0", "s3:ObjectCreated:Put obj-1", "s3:ObjectCreated:Put obj-2",
		"s3:ObjectCreated:Put obj-3", "s3:ObjectCreated:Put obj-4", "s3:ObjectRemoved:Delete obj-0",
	}
	deadline = time.Now().Add(10 * time.Second)
	for len(rcv.got()) < len(want) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := rcv.got(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("after restart the webhook received:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestBadNotifyTargetConfigurationStopsStartup(t *testing.T) {
	for name, notify := range map[string]string{
		"unknown type":  `{"targets":{"carrierpigeon":{"x":{}}}}`,
		"bad webhook":   `{"targets":{"webhook":{"x":{"endpoint":"nope"}}}}`,
		"unknown field": `{"targets":{"webhook":{"x":{"endpoint":"http://h/","bogus":1}}}}`,
		"bad id":        `{"targets":{"webhook":{"a/b":{"endpoint":"http://h/"}}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			cfg := filepath.Join(t.TempDir(), "c.json")
			os.WriteFile(cfg, []byte(fmt.Sprintf(`{"root":%q,"notify":%s}`, t.TempDir(), notify)), 0o600)
			var out syncBuf
			err := run(t.Context(), []string{"--config", cfg}, env(nil), &out)
			if err == nil || !strings.Contains(err.Error(), "notify") {
				t.Fatalf("err = %v\n%s", err, out.String())
			}
		})
	}
}
