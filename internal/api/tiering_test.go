package api

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"nanoio/internal/bucket/nslock"
	"nanoio/internal/storage/xl"
	"nanoio/internal/tier"
)

type tierEnv struct {
	local   *testEnv
	remote  *testEnv
	clock   *manualClock
	janitor *tier.Janitor
	dirs    []string
}

// newTierEnv is a NanoIO server on the erasure-coded backend, with the
// lifecycle scanner on a fake clock, whose COLD tier is a second NanoIO
// server speaking S3 (a local S3 mock that is a real S3 implementation).
func newTierEnv(t *testing.T) *tierEnv {
	t.Helper()
	remote := newEnv(t)
	remote.mb("coldstore")
	j, err := tier.NewJanitor(t.TempDir(), quiet)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(j.Close)
	dirs := make([]string, 4)
	for i := range dirs {
		dirs[i] = t.TempDir()
	}
	x, err := xl.New(dirs, xl.Options{Locker: nslock.New(5 * time.Second), Logger: quiet, ParityBlocks: 2, ScanInterval: -1,
		OnTransitionFreed: j.Freed})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { x.Close() })
	clk := &manualClock{t: time.Now()}
	local := serve(t, x, nil, func(o *Options) {
		o.Tier = &TierOptions{CacheDir: t.TempDir(), CacheBytes: 8 << 20, CacheTTL: time.Hour, Janitor: j}
		o.Lifecycle = &LifecycleOptions{Locker: nslock.New(time.Second), Interval: time.Millisecond, Tick: 20 * time.Millisecond, Clock: clk}
	})
	local.drives = dirs
	return &tierEnv{local: local, remote: remote, clock: clk, janitor: j, dirs: dirs}
}

func (e *tierEnv) addTier(t *testing.T, name string) {
	t.Helper()
	cfg := tier.Config{Name: name, Type: tier.TypeS3, S3: &tier.S3Config{
		Endpoint: e.remote.srv.URL, Bucket: "coldstore", Prefix: "ilm/", AccessKey: rootAK, SecretKey: rootSK}}
	b, _ := json.Marshal(cfg)
	resp, body := e.local.do("PUT", "/_nanoio/admin/tier", strings.NewReader(string(b)), nil)
	if resp.StatusCode != 204 {
		t.Fatalf("add tier: %d %s", resp.StatusCode, body)
	}
}

func (e *tierEnv) remoteKeys() []string {
	resp, b := e.remote.do("GET", "/coldstore?list-type=2", nil, nil)
	if resp.StatusCode != 200 {
		e.local.t.Fatalf("list remote: %d %s", resp.StatusCode, b)
	}
	var keys []string
	for _, part := range strings.Split(string(b), "<Key>")[1:] {
		keys = append(keys, part[:strings.Index(part, "</Key>")])
	}
	return keys
}

func (e *tierEnv) waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

const transitionRule = `<Rule><ID>cool</ID><Status>Enabled</Status><Filter><Prefix>cold/</Prefix></Filter>` +
	`<Transition><Days>7</Days><StorageClass>COLD</StorageClass></Transition></Rule>`

func TestTierAdministration(t *testing.T) {
	e := newTierEnv(t)
	l := e.local
	resp, b := l.do("GET", "/_nanoio/admin/tier", nil, nil)
	if resp.StatusCode != 200 || strings.TrimSpace(string(b)) != "[]" {
		t.Fatalf("empty list = %d %s", resp.StatusCode, b)
	}
	e.addTier(t, "COLD")
	// Duplicate, bad name, reserved name, unreachable tier.
	post := func(c tier.Config, q string) (int, string) {
		raw, _ := json.Marshal(c)
		r, b := l.do("PUT", "/_nanoio/admin/tier"+q, strings.NewReader(string(raw)), nil)
		return r.StatusCode, string(b)
	}
	good := tier.S3Config{Endpoint: e.remote.srv.URL, Bucket: "coldstore", AccessKey: rootAK, SecretKey: rootSK}
	if st, body := post(tier.Config{Name: "COLD", Type: "s3", S3: &good}, ""); st != 409 || !strings.Contains(body, "TierAlreadyExists") {
		t.Errorf("duplicate = %d %s", st, body)
	}
	if st, _ := post(tier.Config{Name: "lower", Type: "s3", S3: &good}, ""); st != 400 {
		t.Errorf("lower-case name = %d", st)
	}
	if st, _ := post(tier.Config{Name: "GLACIER", Type: "s3", S3: &good}, ""); st != 400 {
		t.Errorf("reserved name = %d", st)
	}
	dead := good
	dead.Endpoint = "http://127.0.0.1:1"
	if st, body := post(tier.Config{Name: "DEAD", Type: "s3", S3: &dead}, ""); st != 400 || !strings.Contains(body, "not usable") {
		t.Errorf("unreachable tier = %d %s", st, body)
	}
	// ...unless explicitly not checked.
	if st, _ := post(tier.Config{Name: "DEAD", Type: "s3", S3: &dead}, "?check=false"); st != 204 {
		t.Errorf("unchecked add = %d", st)
	}

	// Listings never reveal the secret key.
	resp, b = l.do("GET", "/_nanoio/admin/tier", nil, nil)
	if strings.Contains(string(b), rootSK) || !strings.Contains(string(b), `"name": "COLD"`) || !strings.Contains(string(b), "*****") {
		t.Errorf("list = %s", b)
	}
	resp, b = l.do("GET", "/_nanoio/admin/tier/check?name=COLD", nil, nil)
	if !strings.Contains(string(b), `"online": true`) {
		t.Errorf("check = %s", b)
	}
	resp, b = l.do("GET", "/_nanoio/admin/tier/check?name=DEAD", nil, nil)
	if !strings.Contains(string(b), `"online": false`) {
		t.Errorf("check dead = %s", b)
	}

	// Only the root credential manages tiers.
	resp, b = l.doAs("nobody", "GET", "/_nanoio/admin/tier", nil, nil)
	wantError(t, resp, b, 403, "AccessDenied")
	resp, b = l.doAs("nobody", "PUT", "/_nanoio/admin/tier", strings.NewReader("{}"), nil)
	wantError(t, resp, b, 403, "AccessDenied")

	// A tier a lifecycle rule uses cannot be removed (without force).
	l.mb("tiered")
	if resp, b := l.do("PUT", "/tiered?lifecycle", strings.NewReader(lcXML(transitionRule)), nil); resp.StatusCode != 200 {
		t.Fatalf("lifecycle: %d %s", resp.StatusCode, b)
	}
	resp, b = l.do("DELETE", "/_nanoio/admin/tier?name=COLD", nil, nil)
	wantError(t, resp, b, 409, "TierInUse")
	if resp, _ := l.do("DELETE", "/_nanoio/admin/tier?name=DEAD", nil, nil); resp.StatusCode != 204 {
		t.Errorf("remove unused = %d", resp.StatusCode)
	}
	// A rule naming a tier that does not exist is refused.
	bad := strings.Replace(transitionRule, "COLD", "NOPE", 1)
	resp, b = l.do("PUT", "/tiered?lifecycle", strings.NewReader(lcXML(bad)), nil)
	wantError(t, resp, b, 400, "InvalidArgument")
}

func TestTiersAreRefusedOnTheFSBackend(t *testing.T) {
	e := newEnv(t)
	cfg := `{"name":"COLD","type":"s3","s3":{"endpoint":"http://127.0.0.1:1","bucket":"b","accessKey":"a","secretKey":"s"}}`
	resp, b := e.do("PUT", "/_nanoio/admin/tier?check=false", strings.NewReader(cfg), nil)
	wantError(t, resp, b, 501, "NotImplemented")
	e.mb("fsb")
	resp, b = e.do("PUT", "/fsb?lifecycle", strings.NewReader(lcXML(transitionRule)), nil)
	if resp.StatusCode != 400 {
		t.Errorf("transition rule on fs = %d %s", resp.StatusCode, b)
	}
}

// The scenario the feature exists for: an object ages past its transition
// rule, moves to the remote, and keeps being served — with the right
// headers, ranges, caching, restore, and cleanup of the remote copy.
func TestTransitionServesFromTierEndToEnd(t *testing.T) {
	e := newTierEnv(t)
	l := e.local
	e.addTier(t, "COLD")
	l.mb("archive")
	body := strings.Repeat("0123456789abcdef", 8192) // 128 KiB
	l.put("/archive/cold/big.bin", body, hdr{"Content-Type": "application/x-test", "x-amz-meta-origin": "unit"})
	l.put("/archive/warm/stay.txt", "stays", nil)
	if resp, b := l.do("PUT", "/archive?lifecycle", strings.NewReader(lcXML(transitionRule)), nil); resp.StatusCode != 200 {
		t.Fatalf("lifecycle: %d %s", resp.StatusCode, b)
	}

	time.Sleep(150 * time.Millisecond)
	if n := len(e.remoteKeys()); n != 0 {
		t.Fatalf("object moved before it was due: %v", e.remoteKeys())
	}
	e.clock.Advance(8 * 24 * time.Hour)
	e.waitFor(t, "the remote copy", func() bool { return len(e.remoteKeys()) == 1 })
	remoteKey := e.remoteKeys()[0]
	if !strings.HasPrefix(remoteKey, "ilm/archive/") {
		t.Errorf("remote object name = %q", remoteKey)
	}
	// Eventually the stub is committed.
	e.waitFor(t, "stub", func() bool {
		r, _ := l.do("HEAD", "/archive/cold/big.bin", nil, nil)
		return r.Header.Get("x-amz-storage-class") == "COLD"
	})

	// HEAD: the original metadata and the tier as the storage class.
	r, _ := l.do("HEAD", "/archive/cold/big.bin", nil, nil)
	if r.StatusCode != 200 || r.Header.Get("Content-Length") != fmt.Sprint(len(body)) ||
		r.Header.Get("Content-Type") != "application/x-test" || r.Header.Get("x-amz-meta-origin") != "unit" {
		t.Errorf("HEAD = %d %v", r.StatusCode, r.Header)
	}
	if r.Header.Get("x-amz-restore") != "" {
		t.Errorf("x-amz-restore set before any restore: %q", r.Header.Get("x-amz-restore"))
	}
	// The local data is gone from every drive.
	for i, d := range e.dirs {
		if p := shardFilesOn(d, "archive", "cold/big.bin"); p != 0 {
			t.Errorf("drive %d still has %d data dirs", i, p)
		}
	}
	// The object outside the rule did not move.
	if r, _ := l.do("HEAD", "/archive/warm/stay.txt", nil, nil); r.Header.Get("x-amz-storage-class") != "" {
		t.Errorf("an object outside the rule was transitioned")
	}
	// Listings report the tier as the class.
	_, lb := l.do("GET", "/archive?list-type=2&prefix=cold/", nil, nil)
	if !strings.Contains(string(lb), "<StorageClass>COLD</StorageClass>") {
		t.Errorf("listing = %s", lb)
	}

	// GET streams from the tier; ranges are honoured.
	got, resp := l.get("/archive/cold/big.bin")
	if resp.StatusCode != 200 || got != body {
		t.Fatalf("GET = %d, %d bytes (want %d)", resp.StatusCode, len(got), len(body))
	}
	rr, rb := l.do("GET", "/archive/cold/big.bin", nil, hdr{"Range": "bytes=70000-70099"})
	if rr.StatusCode != 206 || string(rb) != body[70000:70100] {
		t.Errorf("range GET = %d %q", rr.StatusCode, rb)
	}

	// The read filled the cache: the remote object can vanish and the
	// object is still served.
	if resp, b := e.remote.do("DELETE", "/coldstore/"+remoteKey, nil, nil); resp.StatusCode != 204 {
		t.Fatalf("remote delete: %d %s", resp.StatusCode, b)
	}
	if got, resp := l.get("/archive/cold/big.bin"); resp.StatusCode != 200 || got != body {
		t.Errorf("GET from the local cache = %d", resp.StatusCode)
	}

	// Server-side copy of a transitioned object works (reads via the tier cache).
	if resp, b := l.do("PUT", "/archive/copy.bin", nil, hdr{"x-amz-copy-source": "/archive/cold/big.bin"}); resp.StatusCode != 200 {
		t.Errorf("copy = %d %s", resp.StatusCode, b)
	}
	if got, _ := l.get("/archive/copy.bin"); got != body {
		t.Error("copy of a transitioned object differs")
	}

	// RestoreObject reports itself with x-amz-restore.
	resp, b := l.do("POST", "/archive/cold/big.bin?restore", strings.NewReader(`<RestoreRequest><Days>3</Days></RestoreRequest>`), nil)
	if resp.StatusCode != 202 {
		t.Fatalf("restore = %d %s", resp.StatusCode, b)
	}
	r, _ = l.do("HEAD", "/archive/cold/big.bin", nil, nil)
	if h := r.Header.Get("x-amz-restore"); !strings.Contains(h, `ongoing-request="false"`) || !strings.Contains(h, "expiry-date=") {
		t.Errorf("x-amz-restore = %q", h)
	}
	resp, b = l.do("POST", "/archive/warm/stay.txt?restore", strings.NewReader(`<RestoreRequest><Days>1</Days></RestoreRequest>`), nil)
	wantError(t, resp, b, 403, "InvalidObjectState")

	// Deleting the object reclaims whatever the tier still holds: put a
	// fresh remote copy scenario via a second object, then delete it.
	l.put("/archive/cold/second.bin", "second object", nil)
	e.clock.Advance(24 * time.Hour)
	e.waitFor(t, "second remote copy", func() bool { return len(e.remoteKeys()) == 1 })
	e.waitFor(t, "second stub", func() bool {
		r, _ := l.do("HEAD", "/archive/cold/second.bin", nil, nil)
		return r.Header.Get("x-amz-storage-class") == "COLD"
	})
	if resp, _ := l.do("DELETE", "/archive/cold/second.bin", nil, nil); resp.StatusCode != 204 {
		t.Fatalf("delete stub = %d", resp.StatusCode)
	}
	e.waitFor(t, "remote copy reclaimed", func() bool { return len(e.remoteKeys()) == 0 })
}

// shardFilesOn counts object data directories under a drive's object dir.
func shardFilesOn(drive, bucket, key string) int {
	return countDataDirs(drive + "/" + bucket + "/" + key)
}

func countDataDirs(dir string) int {
	ents, err := osReadDir(dir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range ents {
		if e.IsDir() {
			n++
		}
	}
	return n
}

var osReadDir = os.ReadDir

func TestLifecycleChainMovesWarmToCold(t *testing.T) {
	e := newTierEnv(t)
	l := e.local
	e.addTier(t, "WARM")
	e.addTier(t, "COLD")
	l.mb("chain")
	l.put("/chain/obj", strings.Repeat("c", 5000), nil)
	chain := `<Rule><ID>c</ID><Status>Enabled</Status><Filter/>` +
		`<Transition><Days>10</Days><StorageClass>WARM</StorageClass></Transition>` +
		`<Transition><Days>30</Days><StorageClass>COLD</StorageClass></Transition></Rule>`
	if resp, b := l.do("PUT", "/chain?lifecycle", strings.NewReader(lcXML(chain)), nil); resp.StatusCode != 200 {
		t.Fatalf("lifecycle: %d %s", resp.StatusCode, b)
	}
	classNow := func() string {
		r, _ := l.do("HEAD", "/chain/obj", nil, nil)
		return r.Header.Get("x-amz-storage-class")
	}
	e.clock.Advance(11 * 24 * time.Hour)
	e.waitFor(t, "WARM", func() bool { return classNow() == "WARM" })
	e.clock.Advance(25 * 24 * time.Hour)
	e.waitFor(t, "COLD", func() bool { return classNow() == "COLD" })
	if got, _ := l.get("/chain/obj"); got != strings.Repeat("c", 5000) {
		t.Errorf("object unreadable after two moves")
	}
	// The WARM copy was reclaimed: only the COLD copy is left remotely.
	e.waitFor(t, "WARM copy reclaimed", func() bool { return len(e.remoteKeys()) == 1 })
}
