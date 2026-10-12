package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"nanoio/internal/auth"
	"nanoio/internal/bucket/nslock"
	"nanoio/internal/iam"
	"nanoio/internal/replication"
	"nanoio/internal/storage"
	"nanoio/internal/storage/fs"
	"nanoio/internal/storage/xl"
)

// testSite is one NanoIO deployment (own backend, own queue directory) that
// can be stopped and started again on the same address, as a restarted node.
type testSite struct {
	t       *testing.T
	be      storage.StorageAPI
	fsb     *fs.FS
	replDir string
	addr    string
	api     *Server
	srv     *httptest.Server
	env     *testEnv
	gate    atomic.Pointer[chan struct{}] // when set, requests wait on it (a stalled destination)
	// partition makes the site refuse every request that carries a site
	// service credential: its own clients are unaffected, its peers cannot
	// reach it (and it cannot be reached by their replication either).
	partition atomic.Bool
	reqs      atomic.Int64
	order     chan string // keys of PUT requests in arrival order
	opts      func(*Options)
}

func newSite(t *testing.T, mut ...func(*Options)) *testSite {
	t.Helper()
	be, err := fs.New(t.TempDir(), fs.Options{Locker: nslock.New(5 * time.Second), Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { be.Close() })
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &testSite{t: t, be: be, fsb: be, replDir: t.TempDir(), addr: l.Addr().String(), order: make(chan string, 4096)}
	l.Close()
	s.opts = func(o *Options) {
		for _, m := range mut {
			m(o)
		}
	}
	s.start()
	t.Cleanup(s.stop)
	return s
}

// newSiteXL is a site on the erasure-coded backend.
func newSiteXL(t *testing.T, mut ...func(*Options)) *testSite {
	t.Helper()
	dirs := make([]string, 4)
	for i := range dirs {
		dirs[i] = t.TempDir()
	}
	x, err := xl.New(dirs, xl.Options{Locker: nslock.New(5 * time.Second), Logger: quiet, ParityBlocks: 2, ScanInterval: -1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { x.Close() })
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &testSite{t: t, be: x, replDir: t.TempDir(), addr: l.Addr().String(), order: make(chan string, 4096)}
	l.Close()
	s.opts = func(o *Options) {
		for _, m := range mut {
			m(o)
		}
	}
	s.start()
	t.Cleanup(s.stop)
	return s
}

func (s *testSite) start() {
	s.t.Helper()
	store, err := iam.New(iam.Credential{AccessKey: rootAK, SecretKey: rootSK}, testIAMFile)
	if err != nil {
		s.t.Fatal(err)
	}
	opts := Options{
		Storage: s.be, Auth: &auth.Verifier{Provider: store, Region: "us-east-1"}, Authz: store, IAM: store,
		Domains: []string{"localhost"}, Region: "us-east-1", Logger: quiet,
		Replication: &ReplicationOptions{Dir: s.replDir, Workers: 4, ScanInterval: time.Hour, Locker: nslock.New(time.Second),
			RetryBase: 20 * time.Millisecond, RetryMax: 200 * time.Millisecond, MaxAttempts: 8},
	}
	s.opts(&opts)
	h, err := New(opts)
	if err != nil {
		s.t.Fatal(err)
	}
	s.api = h
	var l net.Listener
	for i := 0; i < 50; i++ {
		if l, err = net.Listen("tcp", s.addr); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		s.t.Fatal(err)
	}
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.reqs.Add(1)
		if s.partition.Load() && strings.Contains(r.Header.Get("Authorization"), "Credential=nanoio-site-") {
			http.Error(w, "partitioned", http.StatusServiceUnavailable)
			return
		}
		if g := s.gate.Load(); g != nil {
			<-*g
		}
		if r.Method == http.MethodPut && r.Header.Get(replication.HdrRequest) != "" && r.URL.RawQuery == "" {
			select {
			case s.order <- strings.TrimPrefix(r.URL.Path, "/"):
			default:
			}
		}
		h.ServeHTTP(w, r)
	})
	s.srv = httptest.NewUnstartedServer(wrapped)
	s.srv.Listener.Close()
	s.srv.Listener = l
	s.srv.Start()
	u, _ := url.Parse(s.srv.URL)
	s.env = &testEnv{t: s.t, srv: s.srv, st: s.be, fs: s.fsb, host: u.Host, root: signerFor(rootAK)}
}

func (s *testSite) stop() {
	if s.api != nil {
		s.api.Close()
		s.api = nil
	}
	if s.srv != nil {
		s.srv.CloseClientConnections()
		s.srv.Close()
		s.srv = nil
	}
}

func (s *testSite) url() string { return "http://" + s.addr }

// versioned creates a bucket with versioning enabled.
func (s *testSite) versioned(bucket string) {
	s.t.Helper()
	s.env.mb(bucket)
	enableVersioning(s.t, s.env, bucket, "Enabled")
}

// target registers dst's bucket as a remote target of src and returns its ARN.
func (s *testSite) target(bucket string, dst *testSite, dstBucket string) string {
	s.t.Helper()
	doc, _ := json.Marshal(map[string]any{"endpoint": dst.url(), "bucket": dstBucket, "accessKey": rootAK, "secretKey": rootSK})
	resp, b := s.env.do("PUT", "/_nanoio/admin/replication/target?bucket="+bucket, strings.NewReader(string(doc)), nil)
	if resp.StatusCode != 200 {
		s.t.Fatalf("add target: %d %s", resp.StatusCode, b)
	}
	var out struct{ ARN string }
	if err := json.Unmarshal(b, &out); err != nil || out.ARN == "" {
		s.t.Fatalf("target response %s", b)
	}
	return out.ARN
}

type ruleSpec struct {
	id, prefix, arn            string
	priority                   int
	markers, existing, replica bool
	enabled                    string
}

func replXML(rules ...ruleSpec) string {
	var b strings.Builder
	b.WriteString(`<ReplicationConfiguration><Role>arn:aws:iam::nanoio:role/replication</Role>`)
	for _, r := range rules {
		en := r.enabled
		if en == "" {
			en = "Enabled"
		}
		st := func(v bool) string {
			if v {
				return "Enabled"
			}
			return "Disabled"
		}
		fmt.Fprintf(&b, `<Rule><ID>%s</ID><Status>%s</Status><Priority>%d</Priority><Filter><Prefix>%s</Prefix></Filter>`+
			`<DeleteMarkerReplication><Status>%s</Status></DeleteMarkerReplication>`+
			`<SourceSelectionCriteria><ReplicaModifications><Status>%s</Status></ReplicaModifications></SourceSelectionCriteria>`+
			`<ExistingObjectReplication><Status>%s</Status></ExistingObjectReplication>`+
			`<Destination><Bucket>%s</Bucket></Destination></Rule>`,
			r.id, en, r.priority, r.prefix, st(r.markers), st(r.replica), st(r.existing), r.arn)
	}
	b.WriteString(`</ReplicationConfiguration>`)
	return b.String()
}

func (s *testSite) setReplication(bucket, doc string) {
	s.t.Helper()
	resp, b := s.env.do("PUT", "/"+bucket+"?replication", strings.NewReader(doc), nil)
	if resp.StatusCode != 200 {
		s.t.Fatalf("PUT ?replication: %d %s", resp.StatusCode, b)
	}
}

// versions lists a bucket's versions as "key|versionID|marker|modtime".
func (s *testSite) versions(bucket string) []string {
	s.t.Helper()
	res, err := s.be.ListObjectVersions(context.Background(), bucket, storage.ListOptions{})
	if err != nil {
		s.t.Fatal(err)
	}
	var out []string
	for _, v := range res.Versions {
		out = append(out, fmt.Sprintf("%s|%s|%v|%d", v.Name, v.VersionID, v.DeleteMarker, v.ModTime.UnixNano()))
	}
	sort.Strings(out)
	return out
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func (s *testSite) metrics(bucket string) (completed, failed, enqueued, retried uint64) {
	resp, b := s.env.do("GET", "/_nanoio/admin/replication/metrics?bucket="+bucket, nil, nil)
	if resp.StatusCode != 200 {
		s.t.Fatalf("metrics: %d %s", resp.StatusCode, b)
	}
	var out struct {
		Targets []struct{ Completed, Failed, Enqueued, Retried uint64 }
	}
	json.Unmarshal(b, &out)
	for _, t := range out.Targets {
		completed += t.Completed
		failed += t.Failed
		enqueued += t.Enqueued
		retried += t.Retried
	}
	return
}

func TestReplicationConfigValidation(t *testing.T) {
	a, b := newSite(t), newSite(t)
	a.versioned("src")
	b.versioned("dst")
	arn := a.target("src", b, "dst")
	ok := replXML(ruleSpec{id: "r", prefix: "", arn: arn})

	// Round trip.
	a.setReplication("src", ok)
	resp, body := a.env.do("GET", "/src?replication", nil, nil)
	for _, want := range []string{"<ID>r</ID>", "<Status>Enabled</Status>", arn, "<Priority>0</Priority>"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("GET ?replication lacks %s:\n%s", want, body)
		}
	}
	// An unversioned source is refused.
	a.env.mb("plainsrc")
	resp, body = a.env.do("PUT", "/plainsrc?replication", strings.NewReader(ok), nil)
	wantError(t, resp, body, 400, "InvalidRequest")
	// An unversioned destination cannot be registered as a target.
	b.env.mb("plaindst")
	doc, _ := json.Marshal(map[string]any{"endpoint": b.url(), "bucket": "plaindst", "accessKey": rootAK, "secretKey": rootSK})
	resp, body = a.env.do("PUT", "/_nanoio/admin/replication/target?bucket=src", strings.NewReader(string(doc)), nil)
	wantError(t, resp, body, 400, "InvalidArgument")
	if !strings.Contains(string(body), "versioning") {
		t.Errorf("message = %s", body)
	}
	// An unreachable destination likewise.
	doc, _ = json.Marshal(map[string]any{"endpoint": "http://127.0.0.1:1", "bucket": "x", "accessKey": rootAK, "secretKey": rootSK})
	resp, body = a.env.do("PUT", "/_nanoio/admin/replication/target?bucket=src", strings.NewReader(string(doc)), nil)
	wantError(t, resp, body, 400, "InvalidArgument")

	for name, doc := range map[string]string{
		"unknown arn":     replXML(ruleSpec{id: "r", arn: "arn:minio:replication::nope:dst"}),
		"duplicate prio":  replXML(ruleSpec{id: "a", priority: 1, arn: arn}, ruleSpec{id: "b", priority: 1, prefix: "x/", arn: arn}),
		"duplicate id":    replXML(ruleSpec{id: "a", priority: 1, arn: arn}, ruleSpec{id: "a", priority: 2, prefix: "x/", arn: arn}),
		"malformed":       "<ReplicationConfiguration>",
		"permanent delet": strings.Replace(ok, "<ExistingObjectReplication>", "<DeleteReplication><Status>Enabled</Status></DeleteReplication><ExistingObjectReplication>", 1),
	} {
		resp, body := a.env.do("PUT", "/src?replication", strings.NewReader(doc), nil)
		if resp.StatusCode < 400 {
			t.Errorf("%s accepted: %s", name, body)
		}
	}
	// Versioning cannot be suspended under a replication configuration.
	resp, body = a.env.do("PUT", "/src?versioning", strings.NewReader(vcfg("Suspended")), nil)
	wantError(t, resp, body, 409, "InvalidBucketState")
	// A target in use cannot be removed.
	resp, body = a.env.do("DELETE", "/_nanoio/admin/replication/target?bucket=src&arn="+arn, nil, nil)
	wantError(t, resp, body, 409, "TargetInUse")
	// Not for everyone.
	resp, body = a.env.doAs("nobody", "PUT", "/src?replication", strings.NewReader(ok), nil)
	wantError(t, resp, body, 403, "AccessDenied")
	resp, body = a.env.doAs("nobody", "GET", "/_nanoio/admin/replication/target?bucket=src", nil, nil)
	wantError(t, resp, body, 403, "AccessDenied")
	if resp, b := a.env.do("GET", "/_nanoio/admin/replication/target?bucket=src", nil, nil); strings.Contains(string(b), rootSK) {
		t.Errorf("target listing exposes the secret key: %d %s", resp.StatusCode, b)
	}
	// Deleting the configuration works and then GET is 404.
	if resp, _ := a.env.do("DELETE", "/src?replication", nil, nil); resp.StatusCode != 204 {
		t.Errorf("DELETE ?replication = %d", resp.StatusCode)
	}
	resp, body = a.env.do("GET", "/src?replication", nil, nil)
	wantError(t, resp, body, 404, "ReplicationConfigurationNotFoundError")
}

func TestReplicationPutMarkerAndMetadata(t *testing.T) {
	a, b := newSite(t), newSite(t)
	a.versioned("src")
	b.versioned("dst")
	arn := a.target("src", b, "dst")
	a.setReplication("src", replXML(ruleSpec{id: "all", arn: arn, markers: true}))

	body := strings.Repeat("replicate me ", 5000)
	r := a.env.put("/src/docs/a.txt", body, hdr{"Content-Type": "text/plain", "x-amz-meta-owner": "alice", "x-amz-tagging": "tier=gold"})
	vid := r.Header.Get("x-amz-version-id")
	if vid == "" {
		t.Fatal("no version id")
	}
	waitUntil(t, "replica", func() bool {
		resp, _ := b.env.do("HEAD", "/dst/docs/a.txt?versionId="+vid, nil, nil)
		return resp.StatusCode == 200
	})
	got, resp := b.env.get("/dst/docs/a.txt?versionId=" + vid)
	if got != body || resp.Header.Get("Content-Type") != "text/plain" || resp.Header.Get("x-amz-meta-owner") != "alice" ||
		resp.Header.Get("x-amz-version-id") != vid || resp.Header.Get("x-amz-replication-status") != "REPLICA" ||
		resp.Header.Get("x-amz-tagging-count") != "1" {
		t.Fatalf("replica: %d bytes, headers %v", len(got), resp.Header)
	}
	// Same version identity and time on both sites.
	if av, bv := a.versions("src"), b.versions("dst"); len(av) != 1 || fmt.Sprint(av) != fmt.Sprint(bv) {
		t.Errorf("histories differ:\n a=%v\n b=%v", av, bv)
	}
	// The source reports COMPLETED once the destination has acknowledged.
	waitUntil(t, "COMPLETED", func() bool {
		r, _ := a.env.do("HEAD", "/src/docs/a.txt", nil, nil)
		return r.Header.Get("x-amz-replication-status") == "COMPLETED"
	})

	// A tag change replicates as a metadata update on the same version.
	if resp, b2 := a.env.do("PUT", "/src/docs/a.txt?tagging&versionId="+vid,
		strings.NewReader(`<Tagging><TagSet><Tag><Key>tier</Key><Value>silver</Value></Tag><Tag><Key>x</Key><Value>y</Value></Tag></TagSet></Tagging>`), nil); resp.StatusCode != 200 {
		t.Fatalf("put tagging: %d %s", resp.StatusCode, b2)
	}
	waitUntil(t, "tag replication", func() bool {
		_, b3 := b.env.do("GET", "/dst/docs/a.txt?tagging&versionId="+vid, nil, nil)
		return strings.Contains(string(b3), "silver") && strings.Contains(string(b3), "<Key>x</Key>")
	})

	// A delete marker carries over with its own ID.
	resp2, _ := a.env.do("DELETE", "/src/docs/a.txt", nil, nil)
	mid := resp2.Header.Get("x-amz-version-id")
	if resp2.StatusCode != 204 || mid == "" || resp2.Header.Get("x-amz-delete-marker") != "true" {
		t.Fatalf("delete = %d %v", resp2.StatusCode, resp2.Header)
	}
	waitUntil(t, "delete marker", func() bool {
		r, _ := b.env.do("GET", "/dst/docs/a.txt", nil, nil)
		return r.StatusCode == 404 && r.Header.Get("x-amz-version-id") == mid
	})
	if av, bv := a.versions("src"), b.versions("dst"); fmt.Sprint(av) != fmt.Sprint(bv) {
		t.Errorf("histories differ after the delete:\n a=%v\n b=%v", av, bv)
	}
	// The old version is still there on both (a marker deletes nothing).
	if g, _ := b.env.get("/dst/docs/a.txt?versionId=" + vid); g != body {
		t.Error("the replica's data vanished with the marker")
	}
	// Metrics saw it all.
	if c, f, _, _ := a.metrics("src"); c < 3 || f != 0 {
		t.Errorf("metrics completed=%d failed=%d, want >=3 and 0", c, f)
	}
}

func TestReplicationDoesNotLoop(t *testing.T) {
	a, b := newSite(t), newSite(t)
	a.versioned("both")
	b.versioned("both")
	arnAB := a.target("both", b, "both")
	arnBA := b.target("both", a, "both")
	a.setReplication("both", replXML(ruleSpec{id: "ab", arn: arnAB, markers: true, replica: true}))
	b.setReplication("both", replXML(ruleSpec{id: "ba", arn: arnBA, markers: true, replica: true}))

	r := a.env.put("/both/k", "from a", nil)
	vidA := r.Header.Get("x-amz-version-id")
	waitUntil(t, "a->b", func() bool {
		resp, _ := b.env.do("HEAD", "/both/k?versionId="+vidA, nil, nil)
		return resp.StatusCode == 200
	})
	// Give a loop every chance: the replica must not come back.
	time.Sleep(600 * time.Millisecond)
	if _, _, enq, _ := b.metrics("both"); enq != 0 {
		t.Errorf("the destination queued %d tasks for a replica it just received", enq)
	}
	if av, bv := a.versions("both"), b.versions("both"); len(av) != 1 || fmt.Sprint(av) != fmt.Sprint(bv) {
		t.Errorf("a=%v b=%v: a replica went around", av, bv)
	}
	// Writes on the other side travel back, and also stop there.
	r = b.env.put("/both/k", "from b", nil)
	vidB := r.Header.Get("x-amz-version-id")
	waitUntil(t, "b->a", func() bool {
		resp, _ := a.env.do("HEAD", "/both/k?versionId="+vidB, nil, nil)
		return resp.StatusCode == 200
	})
	time.Sleep(600 * time.Millisecond)
	av, bv := a.versions("both"), b.versions("both")
	if len(av) != 2 || fmt.Sprint(av) != fmt.Sprint(bv) {
		t.Errorf("a=%v b=%v", av, bv)
	}
	for _, s := range []*testSite{a, b} {
		got, _ := s.env.get("/both/k")
		if got != "from b" {
			t.Errorf("latest = %q, want %q", got, "from b")
		}
	}
	// A metadata change on a replica goes back only because ReplicaModifications is on.
	if resp, _ := a.env.do("PUT", "/both/k?tagging&versionId="+vidB,
		strings.NewReader(`<Tagging><TagSet><Tag><Key>edited</Key><Value>on-a</Value></Tag></TagSet></Tagging>`), nil); resp.StatusCode != 200 {
		t.Fatalf("tagging on the replica: %d", resp.StatusCode)
	}
	waitUntil(t, "replica modification back to its origin", func() bool {
		_, tb := b.env.do("GET", "/both/k?tagging&versionId="+vidB, nil, nil)
		return strings.Contains(string(tb), "on-a")
	})
}

func TestReplicationConvergesUnderConcurrentWrites(t *testing.T) {
	a, b := newSite(t), newSite(t)
	a.versioned("conv")
	b.versioned("conv")
	arnAB := a.target("conv", b, "conv")
	arnBA := b.target("conv", a, "conv")
	a.setReplication("conv", replXML(ruleSpec{id: "ab", arn: arnAB, markers: true}))
	b.setReplication("conv", replXML(ruleSpec{id: "ba", arn: arnBA, markers: true}))

	var wg sync.WaitGroup
	write := func(s *testSite, who string) {
		defer wg.Done()
		for i := 0; i < 15; i++ {
			key := fmt.Sprintf("/conv/k%d", i%4) // 4 hot keys contended by both sites
			s.env.put(key, fmt.Sprintf("%s-%d", who, i), nil)
			if i%5 == 4 {
				s.env.do("DELETE", key, nil, nil)
			}
		}
	}
	wg.Add(2)
	go write(a, "a")
	go write(b, "b")
	wg.Wait()

	waitUntil(t, "convergence", func() bool {
		av, bv := a.versions("conv"), b.versions("conv")
		return len(av) == len(bv) && fmt.Sprint(av) == fmt.Sprint(bv) && len(av) >= 30
	})
	// Same history means the same latest version of every key.
	for i := 0; i < 4; i++ {
		key := fmt.Sprintf("/conv/k%d", i)
		ra, _ := a.env.do("GET", key, nil, nil)
		rb, _ := b.env.do("GET", key, nil, nil)
		if ra.StatusCode != rb.StatusCode || ra.Header.Get("x-amz-version-id") != rb.Header.Get("x-amz-version-id") {
			t.Errorf("%s: a=%d/%s b=%d/%s", key, ra.StatusCode, ra.Header.Get("x-amz-version-id"), rb.StatusCode, rb.Header.Get("x-amz-version-id"))
		}
	}
	// And everything stops: no version multiplies.
	n := len(a.versions("conv"))
	time.Sleep(700 * time.Millisecond)
	if m := len(a.versions("conv")); m != n {
		t.Errorf("history kept growing: %d -> %d", n, m)
	}
}

func TestReplicationSurvivesADeadDestinationAndRestart(t *testing.T) {
	a, b := newSite(t), newSite(t)
	a.versioned("dur")
	b.versioned("dur")
	arn := a.target("dur", b, "dur")
	a.setReplication("dur", replXML(ruleSpec{id: "r", arn: arn, markers: true}))

	b.stop() // the destination is down
	var ids []string
	for i := 0; i < 8; i++ {
		r := a.env.put(fmt.Sprintf("/dur/o%d", i), fmt.Sprintf("body %d", i), nil)
		ids = append(ids, r.Header.Get("x-amz-version-id"))
	}
	waitUntil(t, "retries", func() bool { _, _, _, retried := a.metrics("dur"); return retried >= 3 })
	r, _ := a.env.do("HEAD", "/dur/o0", nil, nil)
	if st := r.Header.Get("x-amz-replication-status"); st != "PENDING" {
		t.Errorf("status while the destination is down = %q", st)
	}

	// The source node restarts too: the queue is on disk, the PENDING status
	// is in the objects.
	a.stop()
	a.start()
	b.start()
	waitUntil(t, "delivery after both restarted", func() bool {
		for i := range ids {
			resp, _ := b.env.do("HEAD", fmt.Sprintf("/dur/o%d?versionId=%s", i, ids[i]), nil, nil)
			if resp.StatusCode != 200 {
				return false
			}
		}
		return true
	})
	waitUntil(t, "COMPLETED", func() bool {
		r, _ := a.env.do("HEAD", "/dur/o7", nil, nil)
		return r.Header.Get("x-amz-replication-status") == "COMPLETED"
	})
	for i := 0; i < 8; i++ {
		if got, _ := b.env.get(fmt.Sprintf("/dur/o%d", i)); got != fmt.Sprintf("body %d", i) {
			t.Errorf("o%d = %q", i, got)
		}
	}
}

func TestReplicationResyncBackfills(t *testing.T) {
	a, b := newSite(t), newSite(t)
	a.versioned("old")
	b.versioned("old")
	a.env.put("/old/before1", "1", nil)
	a.env.put("/old/before2", "2", nil)
	a.env.do("DELETE", "/old/before2", nil, nil) // a marker, too
	arn := a.target("old", b, "old")
	a.setReplication("old", replXML(ruleSpec{id: "r", arn: arn, markers: true})) // existing: Disabled
	a.env.put("/old/after", "3", nil)
	waitUntil(t, "new object", func() bool {
		resp, _ := b.env.do("HEAD", "/old/after", nil, nil)
		return resp.StatusCode == 200
	})
	if resp, _ := b.env.do("HEAD", "/old/before1", nil, nil); resp.StatusCode != 404 {
		t.Fatalf("an object written before the rule was replicated without a resync: %d", resp.StatusCode)
	}
	resp, body := a.env.do("POST", "/_nanoio/admin/replication/resync?bucket=old", nil, nil)
	if resp.StatusCode != 202 {
		t.Fatalf("resync: %d %s", resp.StatusCode, body)
	}
	waitUntil(t, "resync", func() bool {
		return fmt.Sprint(a.versions("old")) == fmt.Sprint(b.versions("old"))
	})
	_, sb := a.env.do("GET", "/_nanoio/admin/replication/resync?bucket=old", nil, nil)
	if !strings.Contains(string(sb), `"scanned"`) {
		t.Errorf("resync status = %s", sb)
	}
	// ExistingObjectReplication on does it by itself.
	a.versioned("old2")
	b.versioned("old2")
	a.env.put("/old2/e1", "x", nil)
	arn2 := a.target("old2", b, "old2")
	a.setReplication("old2", replXML(ruleSpec{id: "r", arn: arn2, existing: true}))
	waitUntil(t, "existing-object replication", func() bool {
		resp, _ := b.env.do("HEAD", "/old2/e1", nil, nil)
		return resp.StatusCode == 200
	})
}

func TestReplicationHonorsPriority(t *testing.T) {
	a := newSite(t, func(o *Options) { o.Replication.Workers = 1 })
	b := newSite(t)
	a.versioned("prio")
	b.versioned("prio")
	arn := a.target("prio", b, "prio")
	// Two rules to the same destination: "hot/" is more important.
	a.setReplication("prio", replXML(
		ruleSpec{id: "low", priority: 1, arn: arn},
		ruleSpec{id: "high", priority: 9, prefix: "hot/", arn: arn},
	))
	// A stalled destination lets tasks pile up behind the first.
	gate := make(chan struct{})
	b.gate.Store(&gate)
	a.env.put("/prio/first", "x", nil)
	waitUntil(t, "first task in flight", func() bool { return b.reqs.Load() > 0 })
	for i := 0; i < 6; i++ {
		a.env.put(fmt.Sprintf("/prio/low%d", i), "x", nil)
	}
	a.env.put("/prio/hot/urgent", "x", nil)
	time.Sleep(100 * time.Millisecond)
	b.gate.Store(nil)
	close(gate)
	var order []string
	deadline := time.After(20 * time.Second)
	for len(order) < 8 {
		select {
		case k := <-b.order:
			order = append(order, k)
		case <-deadline:
			t.Fatalf("only saw %v", order)
		}
	}
	pos := func(k string) int {
		for i, o := range order {
			if o == k {
				return i
			}
		}
		return -1
	}
	// "first" was already in flight; the urgent object overtakes the six
	// low-priority ones queued before it.
	if pos("prio/hot/urgent") != 1 {
		t.Errorf("replication order = %v; the high-priority rule's object should be second", order)
	}
}

func TestReplicationEncryptedAndMultipart(t *testing.T) {
	enc := func(o *Options) { o.KMS, o.DefaultKMSKey = defaultKMS(t), "default" }
	a, b := newSite(t, enc), newSite(t, enc)
	a.versioned("mpbkt")
	b.versioned("mpbkt")
	arn := a.target("mpbkt", b, "mpbkt")
	a.setReplication("mpbkt", replXML(ruleSpec{id: "r", arn: arn}))

	secret := strings.Repeat("sealed ", 4000)
	a.env.put("/mpbkt/secret", secret, hdr{"x-amz-server-side-encryption": "AES256"})
	// A multipart object.
	uid := a.env.initiate("mpbkt", "big", nil)
	p1 := strings.Repeat("A", 5<<20)
	e1 := a.env.uploadPart("mpbkt", "big", uid, 1, []byte(p1))
	resp, b2 := a.env.do("POST", "/mpbkt/big?uploadId="+uid, strings.NewReader(
		`<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>`+e1+`</ETag></Part></CompleteMultipartUpload>`), nil)
	if resp.StatusCode != 200 {
		t.Fatalf("complete: %d %s", resp.StatusCode, b2)
	}
	waitUntil(t, "both replicated", func() bool {
		for _, k := range []string{"secret", "big"} {
			r, _ := b.env.do("HEAD", "/mpbkt/"+k, nil, nil)
			if r.StatusCode != 200 {
				return false
			}
		}
		return true
	})
	if got, _ := b.env.get("/mpbkt/secret"); got != secret {
		t.Error("an encrypted object was not replicated as its plaintext")
	}
	if got, _ := b.env.get("/mpbkt/big"); got != p1 {
		t.Errorf("multipart object differs (%d bytes)", len(got))
	}
}

// The same flow on the erasure-coded backend: import keeps version identity
// there too, and two sites of different backends converge.
func TestReplicationBetweenErasureCodedAndFSSites(t *testing.T) {
	a, b := newSiteXL(t), newSite(t)
	a.versioned("mixed")
	b.versioned("mixed")
	arnAB := a.target("mixed", b, "mixed")
	arnBA := b.target("mixed", a, "mixed")
	a.setReplication("mixed", replXML(ruleSpec{id: "ab", arn: arnAB, markers: true}))
	b.setReplication("mixed", replXML(ruleSpec{id: "ba", arn: arnBA, markers: true}))
	var wg sync.WaitGroup
	for _, w := range []struct {
		s   *testSite
		tag string
	}{{a, "xl"}, {b, "fs"}} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				w.s.env.put(fmt.Sprintf("/mixed/k%d", i%3), fmt.Sprintf("%s-%d", w.tag, i), nil)
			}
			w.s.env.do("DELETE", "/mixed/k0", nil, nil)
		}()
	}
	wg.Wait()
	waitUntil(t, "convergence across backends", func() bool {
		av, bv := a.versions("mixed"), b.versions("mixed")
		return len(av) == len(bv) && fmt.Sprint(av) == fmt.Sprint(bv) && len(av) >= 20
	})
	ra, _ := a.env.do("GET", "/mixed/k1", nil, nil)
	rb, _ := b.env.do("GET", "/mixed/k1", nil, nil)
	if ra.Header.Get("x-amz-version-id") != rb.Header.Get("x-amz-version-id") {
		t.Errorf("latest of k1 differs: %s vs %s", ra.Header.Get("x-amz-version-id"), rb.Header.Get("x-amz-version-id"))
	}
}
