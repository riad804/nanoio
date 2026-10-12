package api

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"nanoio/internal/auth"
	"nanoio/internal/bucket/nslock"
	"nanoio/internal/config"
	"nanoio/internal/event"
	"nanoio/internal/storage"
	"nanoio/internal/storage/fs"
)

// capture is a notification target that records events; hold, when
// non-nil, makes every Send wait on it (a target that is down or hung).
type capture struct {
	mu   sync.Mutex
	got  []*event.Event
	hold chan struct{}
}

func (c *capture) Send(ctx context.Context, evs []*event.Event) error {
	if c.hold != nil {
		select {
		case <-c.hold:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	c.mu.Lock()
	c.got = append(c.got, evs...)
	c.mu.Unlock()
	return nil
}

func (c *capture) Close() error { return nil }

func (c *capture) events() []*event.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*event.Event(nil), c.got...)
}

// names are the event names received so far, "name key" each.
func (c *capture) summary() []string {
	var out []string
	for _, e := range c.events() {
		out = append(out, strings.TrimPrefix(e.Name, "s3:")+" "+e.Key)
	}
	return out
}

type eventEnv struct {
	*testEnv
	mgr *event.Manager
	tgt *capture
	arn string
}

func newEventEnv(t *testing.T, tgt *capture) *eventEnv {
	t.Helper()
	be, err := fs.New(t.TempDir(), fs.Options{Locker: nslock.New(5 * time.Second), Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { be.Close() })
	mgr, err := event.NewManager(event.Options{Dir: t.TempDir(), Region: "us-east-1", Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	arn, err := mgr.AddTarget("webhook", "hook", event.Spec{Target: tgt, Delivery: event.Delivery{
		BatchSize: 1, MaxAttempts: 3, RetryBase: config.Duration(time.Millisecond), RetryMax: config.Duration(5 * time.Millisecond),
		Timeout: config.Duration(5 * time.Second),
	}})
	if err != nil {
		t.Fatal(err)
	}
	e := serve(t, be, be, func(o *Options) { o.Events = mgr })
	t.Cleanup(func() { mgr.Close() })
	return &eventEnv{testEnv: e, mgr: mgr, tgt: tgt, arn: arn}
}

func notifyXML(arn, events, filter string) string {
	return `<NotificationConfiguration><QueueConfiguration><Id>q</Id><Queue>` + arn + `</Queue>` + events + filter +
		`</QueueConfiguration></NotificationConfiguration>`
}

func prefixFilter(p string) string {
	return `<Filter><S3Key><FilterRule><Name>prefix</Name><Value>` + p + `</Value></FilterRule></S3Key></Filter>`
}

func (e *testEnv) setNotifyRaw(bucket, doc string) {
	e.t.Helper()
	resp, b := e.do("PUT", "/"+bucket+"?notification", strings.NewReader(doc), nil)
	if resp.StatusCode != 200 {
		e.t.Fatalf("PUT ?notification: %d %s", resp.StatusCode, b)
	}
}

func (e *eventEnv) setNotify(bucket, doc string) {
	e.t.Helper()
	resp, b := e.do("PUT", "/"+bucket+"?notification", strings.NewReader(doc), nil)
	if resp.StatusCode != 200 {
		e.t.Fatalf("PUT ?notification: %d %s", resp.StatusCode, b)
	}
}

func (e *eventEnv) want(what string, n int) []*event.Event {
	e.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if got := e.tgt.events(); len(got) >= n {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
	e.t.Fatalf("%s: got %v, want %d events", what, e.tgt.summary(), n)
	return nil
}

func TestBucketNotificationConfigRoundTrip(t *testing.T) {
	e := newEventEnv(t, &capture{})
	e.mb("nbk")
	any := `<Event>s3:ObjectCreated:*</Event>`

	// Nothing configured: an empty document.
	resp, b := e.do("GET", "/nbk?notification", nil, nil)
	if resp.StatusCode != 200 || strings.Contains(string(b), "QueueConfiguration") {
		t.Fatalf("GET empty = %d %s", resp.StatusCode, b)
	}
	for name, tt := range map[string]struct {
		doc    string
		status int
		code   string
	}{
		"malformed":     {`<NotificationConfiguration><Queue>`, 400, "MalformedXML"},
		"unknown arn":   {notifyXML("arn:minio:sqs::nope:webhook", any, ""), 400, "InvalidArgument"},
		"bad event":     {notifyXML(e.arn, `<Event>s3:Nope:*</Event>`, ""), 400, "InvalidArgument"},
		"no events":     {notifyXML(e.arn, "", ""), 400, "MalformedXML"},
		"bad filter":    {notifyXML(e.arn, any, `<Filter><S3Key><FilterRule><Name>middle</Name><Value>x</Value></FilterRule></S3Key></Filter>`), 400, "InvalidArgument"},
		"valid":         {notifyXML(e.arn, any+`<Event>s3:ObjectRemoved:*</Event>`, prefixFilter("img/")), 200, ""},
		"region-less":   {notifyXML("arn:minio:sqs::hook:webhook", any, ""), 200, ""},
		"empty removes": {`<NotificationConfiguration/>`, 200, ""},
	} {
		t.Run(name, func(t *testing.T) {
			resp, b := e.do("PUT", "/nbk?notification", strings.NewReader(tt.doc), nil)
			if resp.StatusCode != tt.status {
				t.Fatalf("status %d, want %d: %s", resp.StatusCode, tt.status, b)
			}
			if tt.code != "" {
				wantError(t, resp, b, tt.status, tt.code)
			}
		})
	}

	e.setNotify("nbk", notifyXML("arn:minio:sqs::hook:webhook", any, prefixFilter("img/")))
	resp, b = e.do("GET", "/nbk?notification", nil, nil)
	for _, want := range []string{"<QueueConfiguration>", "<Id>q</Id>", "<Queue>" + e.arn + "</Queue>",
		"<Event>s3:ObjectCreated:*</Event>", "<Name>prefix</Name>", "<Value>img/</Value>"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("GET ?notification lacks %s:\n%s", want, b)
		}
	}
	// No such bucket, and no permission.
	resp, b = e.do("PUT", "/nosuch?notification", strings.NewReader(notifyXML(e.arn, any, "")), nil)
	wantError(t, resp, b, 404, "NoSuchBucket")
	resp, b = e.doAs("nobody", "GET", "/nbk?notification", nil, nil)
	wantError(t, resp, b, 403, "AccessDenied")
	resp, _ = e.doAnon("PUT", "/nbk?notification", strings.NewReader(notifyXML(e.arn, any, "")), nil)
	if resp.StatusCode != 403 {
		t.Errorf("anonymous PUT ?notification = %d", resp.StatusCode)
	}
	// The configuration goes away with the bucket.
	if resp, b := e.do("DELETE", "/nbk", nil, nil); resp.StatusCode != 204 {
		t.Fatalf("delete bucket: %d %s", resp.StatusCode, b)
	}
	e.mb("nbk")
	resp, b = e.do("GET", "/nbk?notification", nil, nil)
	if strings.Contains(string(b), "QueueConfiguration") {
		t.Errorf("a new bucket of the same name inherited a notification configuration: %s", b)
	}
}

func TestEventsForObjectOperations(t *testing.T) {
	tgt := &capture{}
	e := newEventEnv(t, tgt)
	e.mb("evt")
	e.setNotify("evt", notifyXML(e.arn, `<Event>s3:ObjectCreated:*</Event><Event>s3:ObjectRemoved:*</Event><Event>s3:ObjectAccessed:*</Event>`, ""))

	e.put("/evt/a.txt", "hello", hdr{"Content-Type": "text/plain", "x-amz-meta-color": "blue"})
	e.get("/evt/a.txt")
	if resp, _ := e.do("HEAD", "/evt/a.txt", nil, nil); resp.StatusCode != 200 {
		t.Fatalf("HEAD = %d", resp.StatusCode)
	}
	e.put("/evt/copy.txt", "", hdr{"x-amz-copy-source": "/evt/a.txt"})
	if resp, b := e.do("DELETE", "/evt/a.txt", nil, nil); resp.StatusCode != 204 {
		t.Fatalf("DELETE = %d %s", resp.StatusCode, b)
	}

	// Multipart.
	resp, b := e.do("POST", "/evt/big?uploads", nil, nil)
	var init initiateMultipartUploadResult
	if err := xml.Unmarshal(b, &init); err != nil || resp.StatusCode != 200 {
		t.Fatalf("create multipart: %d %s", resp.StatusCode, b)
	}
	part := strings.Repeat("p", 5<<20)
	pr := e.put("/evt/big?partNumber=1&uploadId="+init.UploadID, part, nil)
	complete := `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>` + pr.Header.Get("ETag") + `</ETag></Part></CompleteMultipartUpload>`
	if resp, b := e.do("POST", "/evt/big?uploadId="+init.UploadID, strings.NewReader(complete), nil); resp.StatusCode != 200 {
		t.Fatalf("complete: %d %s", resp.StatusCode, b)
	}

	got := e.want("object operations", 6)
	wantNames := []string{"ObjectCreated:Put a.txt", "ObjectAccessed:Get a.txt", "ObjectAccessed:Head a.txt",
		"ObjectCreated:Copy copy.txt", "ObjectRemoved:Delete a.txt", "ObjectCreated:CompleteMultipartUpload big"}
	if fmt.Sprint(tgt.summary()) != fmt.Sprint(wantNames) {
		t.Fatalf("events:\n got %v\nwant %v", tgt.summary(), wantNames)
	}
	put := got[0]
	if put.Bucket != "evt" || put.Size != 5 || put.ETag != md5hex("hello") || put.Principal != rootAK ||
		put.ContentType != "text/plain" || put.RequestID == "" || put.Region != "us-east-1" || put.Sequencer == "" {
		t.Errorf("Put event = %+v", put)
	}
	if put.UserMetadata["X-Amz-Meta-Color"] != "blue" {
		t.Errorf("user metadata = %v", put.UserMetadata)
	}
	if got[5].Size != int64(len(part)) {
		t.Errorf("multipart size = %d, want %d", got[5].Size, len(part))
	}
	for i := 1; i < len(got); i++ {
		if got[i].Seq <= got[i-1].Seq {
			t.Errorf("sequence numbers are not increasing at %d", i)
		}
	}
}

func TestEventFiltersAndOnlyWhatIsConfigured(t *testing.T) {
	tgt := &capture{}
	e := newEventEnv(t, tgt)
	e.mb("flt")
	e.setNotify("flt", notifyXML(e.arn, `<Event>s3:ObjectCreated:Put</Event>`, prefixFilter("in/")))
	e.put("/flt/in/yes", "1", nil)
	e.put("/flt/out/no", "2", nil)
	e.get("/flt/in/yes") // Accessed is not configured
	e.do("DELETE", "/flt/in/yes", nil, nil)
	e.put("/flt/in/yes2", "3", nil)
	e.want("filtered events", 2)
	time.Sleep(100 * time.Millisecond)
	if fmt.Sprint(tgt.summary()) != "[ObjectCreated:Put in/yes ObjectCreated:Put in/yes2]" {
		t.Fatalf("events = %v", tgt.summary())
	}
}

func TestVersionedDeleteEvents(t *testing.T) {
	tgt := &capture{}
	e := newEventEnv(t, tgt)
	e.mb("vev")
	enableVersioning(t, e.testEnv, "vev", "Enabled")
	e.setNotify("vev", notifyXML(e.arn, `<Event>s3:ObjectCreated:*</Event><Event>s3:ObjectRemoved:*</Event>`, ""))
	r := e.put("/vev/k", "v1", nil)
	v1 := r.Header.Get("x-amz-version-id")
	// Plain delete adds a marker; deleting a named version removes it.
	resp, _ := e.do("DELETE", "/vev/k", nil, nil)
	marker := resp.Header.Get("x-amz-version-id")
	e.do("DELETE", "/vev/k?versionId="+v1, nil, nil)
	got := e.want("versioned events", 3)
	if got[0].Name != event.ObjectCreatedPut || got[0].VersionID != v1 {
		t.Errorf("put event = %s version %q, want version %q", got[0].Name, got[0].VersionID, v1)
	}
	if got[1].Name != event.ObjectRemovedDeleteMarkerCreated || got[1].VersionID != marker || marker == "" {
		t.Errorf("marker event = %s version %q, want %q", got[1].Name, got[1].VersionID, marker)
	}
	if got[2].Name != event.ObjectRemovedDelete || got[2].VersionID != v1 {
		t.Errorf("delete event = %s version %q, want %q", got[2].Name, got[2].VersionID, v1)
	}
}

func TestMultiDeleteEvents(t *testing.T) {
	tgt := &capture{}
	e := newEventEnv(t, tgt)
	e.mb("mdel")
	e.put("/mdel/a", "1", nil)
	e.put("/mdel/b", "2", nil)
	e.setNotify("mdel", notifyXML(e.arn, `<Event>s3:ObjectRemoved:*</Event>`, ""))
	body := `<Delete><Object><Key>a</Key></Object><Object><Key>b</Key></Object></Delete>`
	resp, b := e.do("POST", "/mdel?delete", strings.NewReader(body), hdr{"Content-MD5": md5b64(body)})
	if resp.StatusCode != 200 {
		t.Fatalf("multi-delete: %d %s", resp.StatusCode, b)
	}
	e.want("multi-delete events", 2)
	if fmt.Sprint(tgt.summary()) != "[ObjectRemoved:Delete a ObjectRemoved:Delete b]" {
		t.Errorf("events = %v", tgt.summary())
	}
}

func TestTagFilter(t *testing.T) {
	tgt := &capture{}
	e := newEventEnv(t, tgt)
	e.mb("tagb")
	tagFilter := `<Filter><S3Tag><FilterRule><Name>tier</Name><Value>gold</Value></FilterRule></S3Tag></Filter>`
	e.setNotify("tagb", notifyXML(e.arn, `<Event>s3:ObjectCreated:*</Event><Event>s3:ObjectRemoved:*</Event>`, tagFilter))
	e.put("/tagb/gold", "1", hdr{"x-amz-tagging": "tier=gold&x=y"})
	e.put("/tagb/tin", "2", hdr{"x-amz-tagging": "tier=tin"})
	e.put("/tagb/untagged", "3", nil)
	// The removal of a tagged object carries the tags it had.
	e.do("DELETE", "/tagb/gold", nil, nil)
	e.do("DELETE", "/tagb/tin", nil, nil)
	e.want("tag-filtered events", 2)
	time.Sleep(100 * time.Millisecond)
	if fmt.Sprint(tgt.summary()) != "[ObjectCreated:Put gold ObjectRemoved:Delete gold]" {
		t.Fatalf("events = %v", tgt.summary())
	}
}

// A target that never answers must not slow, fail or reorder S3 requests.
func TestRequestsUnaffectedByHungTarget(t *testing.T) {
	tgt := &capture{hold: make(chan struct{})}
	e := newEventEnv(t, tgt)
	e.mb("hung")
	e.setNotify("hung", notifyXML(e.arn, `<Event>s3:ObjectCreated:*</Event><Event>s3:ObjectAccessed:*</Event>`, ""))
	var worst time.Duration
	for i := 0; i < 60; i++ {
		start := time.Now()
		resp, b := e.do("PUT", fmt.Sprintf("/hung/o%d", i), strings.NewReader("x"), nil)
		if resp.StatusCode != 200 {
			t.Fatalf("PUT %d: %d %s", i, resp.StatusCode, b)
		}
		if body, _ := e.get(fmt.Sprintf("/hung/o%d", i)); body != "x" {
			t.Fatalf("GET %d = %q", i, body)
		}
		if d := time.Since(start); d > worst {
			worst = d
		}
	}
	if worst > 2*time.Second {
		t.Errorf("slowest PUT+GET with a hung target took %v", worst)
	}
	// The events are safely queued, not lost.
	deadline := time.Now().Add(5 * time.Second)
	for {
		st := e.mgr.Status(context.Background(), false)[0]
		if st.QueueLength >= 100 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("queue length = %d, want >= 100 (60 puts + 60 gets, one in flight)", st.QueueLength)
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(tgt.hold)
	e.want("delivery after recovery", 120)
}

func TestAdminSurfaceIsAuthorised(t *testing.T) {
	e := newEventEnv(t, &capture{})
	for _, p := range []string{"/_nanoio/admin/events", "/_nanoio/admin/notify/targets", "/_nanoio/admin/notify/dead?arn=" + e.arn} {
		if resp, _ := e.doAnon("GET", p, nil, nil); resp.StatusCode != 403 {
			t.Errorf("anonymous GET %s = %d, want 403", p, resp.StatusCode)
		}
		resp, b := e.doAs("nobody", "GET", p, nil, nil)
		wantError(t, resp, b, 403, "AccessDenied")
	}
	resp, b := e.doAs("nobody", "POST", "/_nanoio/admin/notify/requeue?arn="+e.arn, nil, nil)
	wantError(t, resp, b, 403, "AccessDenied")
}

func TestAdminTargetStatus(t *testing.T) {
	e := newEventEnv(t, &capture{})
	resp, b := e.do("GET", "/_nanoio/admin/notify/targets", nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d %s", resp.StatusCode, b)
	}
	var out struct {
		Targets []struct {
			ARN, Type, ID string
			Online        bool
			QueueLength   int
		}
		Pipeline struct{ ReplayEnabled bool }
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Targets) != 1 || out.Targets[0].ARN != e.arn || out.Targets[0].Type != "webhook" || !out.Targets[0].Online || !out.Pipeline.ReplayEnabled {
		t.Fatalf("status = %s", b)
	}
	resp, b = e.do("GET", "/_nanoio/admin/notify/dead?arn=arn:minio:sqs::nope:webhook", nil, nil)
	wantError(t, resp, b, 400, "InvalidArgument")
	resp, b = e.do("POST", "/_nanoio/admin/notify/requeue?arn="+e.arn, nil, nil)
	if resp.StatusCode != 200 || !strings.Contains(string(b), `"requeued": 0`) {
		t.Errorf("requeue = %d %s", resp.StatusCode, b)
	}
}

// The NDJSON stream replays history from ?since and then goes live.
func TestAdminEventStreamNDJSON(t *testing.T) {
	e := newEventEnv(t, &capture{})
	e.mb("strm")
	e.put("/strm/old", "1", nil)
	e.put("/strm/old2", "2", nil)

	req, _ := http.NewRequest("GET", e.srv.URL+"/_nanoio/admin/events?since=0&bucket=strm", nil)
	signAdmin(e.testEnv, req)
	resp, err := e.srv.Client().Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("stream: %v %v", resp, err)
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	read := func() streamFrame {
		t.Helper()
		done := make(chan streamFrame, 1)
		go func() {
			if !sc.Scan() {
				done <- streamFrame{}
				return
			}
			var f streamFrame
			json.Unmarshal(sc.Bytes(), &f)
			done <- f
		}()
		select {
		case f := <-done:
			return f
		case <-time.After(5 * time.Second):
			t.Fatal("no frame within 5s")
			return streamFrame{}
		}
	}
	a, b := read(), read()
	if a.Key != "strm/old" || b.Key != "strm/old2" || b.Seq <= a.Seq || a.EventName != "s3:ObjectCreated:Put" {
		t.Fatalf("replayed frames = %+v %+v", a, b)
	}
	e.put("/strm/live", "3", nil)
	if c := read(); c.Key != "strm/live" || c.Seq <= b.Seq {
		t.Fatalf("live frame = %+v", c)
	}
}

func TestAdminEventStreamWebSocket(t *testing.T) {
	e := newEventEnv(t, &capture{})
	e.mb("wsb")
	conn, err := net.Dial("tcp", e.host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	req, _ := http.NewRequest("GET", e.srv.URL+"/_nanoio/admin/events?events=s3:ObjectCreated:*", nil)
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", key)
	signAdmin(e.testEnv, req)
	if err := req.Write(conn); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	if resp.StatusCode != 101 || resp.Header.Get("Sec-WebSocket-Accept") != base64.StdEncoding.EncodeToString(sum[:]) {
		t.Fatalf("handshake = %d %v", resp.StatusCode, resp.Header)
	}

	e.put("/wsb/skipped-delete-first", "1", nil)
	e.do("DELETE", "/wsb/skipped-delete-first", nil, nil) // filtered out by events=
	e.put("/wsb/second", "2", nil)

	readFrame := func() []byte {
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		var h [2]byte
		if _, err := io.ReadFull(br, h[:]); err != nil {
			t.Fatal(err)
		}
		if h[0]&0x0f != 0x1 {
			t.Fatalf("opcode %x, want text", h[0]&0x0f)
		}
		l := int(h[1] & 0x7f)
		switch l {
		case 126:
			var b [2]byte
			io.ReadFull(br, b[:])
			l = int(binary.BigEndian.Uint16(b[:]))
		case 127:
			var b [8]byte
			io.ReadFull(br, b[:])
			l = int(binary.BigEndian.Uint64(b[:]))
		}
		buf := make([]byte, l)
		if _, err := io.ReadFull(br, buf); err != nil {
			t.Fatal(err)
		}
		return buf
	}
	var f1, f2 streamFrame
	json.Unmarshal(readFrame(), &f1)
	json.Unmarshal(readFrame(), &f2)
	if f1.Key != "wsb/skipped-delete-first" || f2.Key != "wsb/second" || f2.Seq <= f1.Seq {
		t.Fatalf("frames = %+v %+v", f1, f2)
	}
}

// signAdmin signs a hand-built request as the root user.
func signAdmin(e *testEnv, req *http.Request) {
	s := e.root
	s.Sign(req, sha256hex(""), time.Now())
}

var _ = auth.Signer{}

// With a locker the queues are replicated in the backend: events written
// through one server are delivered by a different server after the first
// one is gone, with the first one's local disk irrelevant.
func TestReplicatedQueueThroughBackend(t *testing.T) {
	be, err := fs.New(t.TempDir(), fs.Options{Locker: nslock.New(5 * time.Second), Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { be.Close() })
	locker := nslock.New(5 * time.Second)
	delivery := event.Delivery{BatchSize: 10, MaxAttempts: -1, RetryBase: config.Duration(time.Millisecond),
		RetryMax: config.Duration(5 * time.Millisecond), Timeout: config.Duration(2 * time.Second)}
	node := func(name string, tgt event.Target) (*event.Manager, string) {
		mgr, err := event.NewManager(event.Options{Dir: t.TempDir(), Region: "us-east-1", Logger: quiet})
		if err != nil {
			t.Fatal(err)
		}
		arn, err := mgr.AddTarget("webhook", "hook", event.Spec{Target: tgt, Delivery: delivery})
		if err != nil {
			t.Fatal(err)
		}
		return mgr, arn
	}

	down := &capture{hold: make(chan struct{})} // never answers
	mgrA, arn := node("A", down)
	e := serve(t, be, nil, func(o *Options) {
		o.Events, o.EventLocker, o.EventNodeID = mgrA, locker, "node-a"
	})
	e.mb("repl")
	doc := notifyXML(arn, `<Event>s3:ObjectCreated:*</Event>`, "")
	if resp, b := e.do("PUT", "/repl?notification", strings.NewReader(doc), nil); resp.StatusCode != 200 {
		t.Fatalf("notification: %d %s", resp.StatusCode, b)
	}
	for i := 0; i < 12; i++ {
		e.put(fmt.Sprintf("/repl/o%02d", i), "x", nil)
	}
	// The events reach the system bucket although nothing could deliver.
	listShared := func() int {
		res, err := be.ListObjects(context.Background(), sysBucket, storage.ListOptions{Prefix: "_events/", MaxKeys: 1000})
		if err != nil {
			return 0
		}
		return len(res.Objects)
	}
	deadline := time.Now().Add(10 * time.Second)
	for listShared() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no replicated queue objects appeared in the backend")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Wait until everything is replicated, then node A disappears with its
	// local queue directory. (Events still only on A's disk would be lost
	// with it: replication closes that window in milliseconds, not never.)
	deadline = time.Now().Add(10 * time.Second)
	for mgrA.Status(context.Background(), false)[0].Shipped < 12 {
		if time.Now().After(deadline) {
			t.Fatal("events were not replicated")
		}
		time.Sleep(10 * time.Millisecond)
	}
	mgrA.Close()

	up := &capture{}
	mgrB, _ := node("B", up)
	if _, err := New(Options{Storage: be, InsecureNoAuth: true, Logger: quiet, Events: mgrB,
		EventLocker: locker, EventNodeID: "node-b"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mgrB.Close() })
	deadline = time.Now().Add(15 * time.Second)
	for len(up.events()) < 12 {
		if time.Now().After(deadline) {
			t.Fatalf("node B delivered %d of 12 events", len(up.events()))
		}
		time.Sleep(20 * time.Millisecond)
	}
	got := up.summary()
	for i := 0; i < 12; i++ {
		if want := fmt.Sprintf("ObjectCreated:Put o%02d", i); got[i] != want {
			t.Fatalf("event %d = %q, want %q", i, got[i], want)
		}
	}
	deadline = time.Now().Add(5 * time.Second)
	for listShared() != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := listShared(); n != 0 {
		t.Errorf("%d queue objects remain after delivery", n)
	}
}
