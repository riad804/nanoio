package api

import (
	"strings"
	"sync"
	"testing"
	"time"

	"nanoio/internal/bucket/nslock"
	"nanoio/internal/config"
	"nanoio/internal/event"
	"nanoio/internal/storage/fs"
)

type manualClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *manualClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *manualClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func lcXML(rules ...string) string {
	return `<LifecycleConfiguration>` + strings.Join(rules, "") + `</LifecycleConfiguration>`
}

const expireLogs30 = `<Rule><ID>logs</ID><Status>Enabled</Status><Filter><Prefix>logs/</Prefix></Filter><Expiration><Days>30</Days></Expiration></Rule>`

func TestBucketLifecycleConfigRoundTrip(t *testing.T) {
	e := newEnv(t)
	e.mb("lcbucket")
	resp, b := e.do("GET", "/lcbucket?lifecycle", nil, nil)
	wantError(t, resp, b, 404, "NoSuchLifecycleConfiguration")

	for name, tt := range map[string]struct {
		doc    string
		status int
		code   string
	}{
		"malformed":    {"<LifecycleConfiguration><Rule>", 400, "MalformedXML"},
		"no rules":     {lcXML(), 400, "MalformedXML"},
		"duplicate id": {lcXML(expireLogs30, expireLogs30), 400, "InvalidArgument"},
		"unknown tier": {lcXML(`<Rule><ID>t</ID><Status>Enabled</Status><Filter/><Transition><Days>1</Days><StorageClass>GLACIER</StorageClass></Transition></Rule>`), 400, "InvalidArgument"},
		"valid":        {lcXML(expireLogs30), 200, ""},
	} {
		t.Run(name, func(t *testing.T) {
			resp, b := e.do("PUT", "/lcbucket?lifecycle", strings.NewReader(tt.doc), nil)
			if resp.StatusCode != tt.status {
				t.Fatalf("status %d, want %d: %s", resp.StatusCode, tt.status, b)
			}
			if tt.code != "" {
				wantError(t, resp, b, tt.status, tt.code)
			}
		})
	}
	resp, b = e.do("GET", "/lcbucket?lifecycle", nil, nil)
	for _, want := range []string{"<ID>logs</ID>", "<Status>Enabled</Status>", "<Days>30</Days>", "<Prefix>logs/</Prefix>"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("GET lacks %s:\n%s", want, b)
		}
	}
	resp, b = e.doAs("nobody", "GET", "/lcbucket?lifecycle", nil, nil)
	wantError(t, resp, b, 403, "AccessDenied")
	resp, b = e.doAs("nobody", "PUT", "/lcbucket?lifecycle", strings.NewReader(lcXML(expireLogs30)), nil)
	wantError(t, resp, b, 403, "AccessDenied")
	resp, b = e.do("PUT", "/nosuchbkt?lifecycle", strings.NewReader(lcXML(expireLogs30)), nil)
	wantError(t, resp, b, 404, "NoSuchBucket")
	if resp, _ := e.do("DELETE", "/lcbucket?lifecycle", nil, nil); resp.StatusCode != 204 {
		t.Errorf("DELETE ?lifecycle = %d", resp.StatusCode)
	}
	if resp, _ := e.do("HEAD", "/lcbucket", nil, nil); resp.StatusCode != 200 {
		t.Errorf("bucket gone after DELETE ?lifecycle: %d", resp.StatusCode)
	}
	resp, b = e.do("GET", "/lcbucket?lifecycle", nil, nil)
	wantError(t, resp, b, 404, "NoSuchLifecycleConfiguration")
}

// A real server with the scanner on and a fake clock: an object is gone
// after "30 days", and the deletion is announced as a Phase 11 event.
func TestLifecycleExpiresAndEmitsEvent(t *testing.T) {
	be, err := fs.New(t.TempDir(), fs.Options{Locker: nslock.New(5 * time.Second), Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { be.Close() })
	tgt := &capture{}
	mgr, err := event.NewManager(event.Options{Dir: t.TempDir(), Region: "us-east-1", Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	arn, err := mgr.AddTarget("webhook", "hook", event.Spec{Target: tgt, Delivery: event.Delivery{
		BatchSize: 1, MaxAttempts: 3, RetryBase: config.Duration(time.Millisecond), RetryMax: config.Duration(5 * time.Millisecond),
		Timeout: config.Duration(5 * time.Second)}})
	if err != nil {
		t.Fatal(err)
	}
	clk := &manualClock{t: time.Now()}
	e := serve(t, be, be, func(o *Options) {
		o.Events = mgr
		o.Lifecycle = &LifecycleOptions{Locker: nslock.New(time.Second), Interval: time.Millisecond,
			Tick: 20 * time.Millisecond, Clock: clk}
	})
	t.Cleanup(func() { mgr.Close() })

	e.mb("agedata")
	e.setNotifyRaw("agedata", `<NotificationConfiguration><QueueConfiguration><Queue>`+arn+`</Queue>
		<Event>s3:LifecycleExpiration:*</Event></QueueConfiguration></NotificationConfiguration>`)
	e.put("/agedata/logs/old.txt", "old", nil)
	e.put("/agedata/keep.txt", "keep", nil)
	if resp, b := e.do("PUT", "/agedata?lifecycle", strings.NewReader(lcXML(expireLogs30)), nil); resp.StatusCode != 200 {
		t.Fatalf("lifecycle: %d %s", resp.StatusCode, b)
	}

	time.Sleep(150 * time.Millisecond) // several scans at day 0
	if resp, _ := e.do("HEAD", "/agedata/logs/old.txt", nil, nil); resp.StatusCode != 200 {
		t.Fatalf("object expired at day 0: %d", resp.StatusCode)
	}
	clk.Advance(31 * 24 * time.Hour)
	deadline := time.Now().Add(10 * time.Second)
	for {
		resp, _ := e.do("HEAD", "/agedata/logs/old.txt", nil, nil)
		if resp.StatusCode == 404 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the object was not expired after 31 fake days")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if resp, _ := e.do("HEAD", "/agedata/keep.txt", nil, nil); resp.StatusCode != 200 {
		t.Errorf("an object outside the rule's prefix was removed: %d", resp.StatusCode)
	}
	got := (&eventEnv{testEnv: e, mgr: mgr, tgt: tgt, arn: arn}).want("lifecycle event", 1)
	ev := got[0]
	if ev.Name != event.LifecycleExpirationDelete || ev.Key != "logs/old.txt" || ev.Bucket != "agedata" ||
		ev.Principal != "nanoio:lifecycle" || ev.RequestID != "logs" {
		t.Errorf("event = %+v", ev)
	}
}
