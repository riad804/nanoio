package lifecycle

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"nanoio/internal/bucket/nslock"
	"nanoio/internal/storage"
	"nanoio/internal/storage/fs"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

const day = 24 * time.Hour

func tiers(names ...string) ParseOptions {
	return ParseOptions{TierExists: func(n string) bool {
		for _, x := range names {
			if x == n {
				return true
			}
		}
		return false
	}}
}

func mustParse(t *testing.T, doc string, opt ...ParseOptions) *Config {
	t.Helper()
	o := ParseOptions{}
	if len(opt) > 0 {
		o = opt[0]
	}
	c, err := Parse([]byte(doc), o)
	if err != nil {
		t.Fatalf("Parse: %v\n%s", err, doc)
	}
	return c
}

func rule(id, status, filter, actions string) string {
	return `<Rule><ID>` + id + `</ID><Status>` + status + `</Status>` + filter + actions + `</Rule>`
}

func cfgDoc(rules ...string) string {
	return `<LifecycleConfiguration>` + strings.Join(rules, "") + `</LifecycleConfiguration>`
}

const (
	all      = `<Filter></Filter>`
	exp30    = `<Expiration><Days>30</Days></Expiration>`
	prefixed = `<Filter><Prefix>logs/</Prefix></Filter>`
)

func TestParseValidAndRoundTrip(t *testing.T) {
	doc := cfgDoc(
		rule("a", "Enabled", prefixed, exp30),
		rule("b", "Disabled", `<Filter><Tag><Key>k</Key><Value>v</Value></Tag></Filter>`,
			`<NoncurrentVersionExpiration><NoncurrentDays>7</NoncurrentDays><NewerNoncurrentVersions>3</NewerNoncurrentVersions></NoncurrentVersionExpiration>`),
		rule("c", "Enabled", `<Filter><And><Prefix>p/</Prefix><Tag><Key>a</Key><Value>1</Value></Tag><Tag><Key>b</Key><Value>2</Value></Tag><ObjectSizeGreaterThan>100</ObjectSizeGreaterThan></And></Filter>`,
			`<Transition><Days>10</Days><StorageClass>COLD</StorageClass></Transition><Expiration><Days>400</Days></Expiration>`),
		`<Rule><ID>legacy</ID><Status>Enabled</Status><Prefix>old/</Prefix><AbortIncompleteMultipartUpload><DaysAfterInitiation>2</DaysAfterInitiation></AbortIncompleteMultipartUpload></Rule>`,
		rule("d", "Enabled", all, `<Expiration><ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker></Expiration>`),
		rule("e", "Enabled", all, `<Expiration><Date>2030-01-01T00:00:00.000Z</Date></Expiration>`),
	)
	c := mustParse(t, doc, tiers("COLD"))
	if len(c.Rules) != 6 || !c.Rules[0].Enabled || c.Rules[1].Enabled || !c.Rules[3].LegacyPrefix || c.Rules[3].Filter.Prefix != "old/" {
		t.Fatalf("rules = %+v", c.Rules)
	}
	if f := c.Rules[2].Filter; f.Prefix != "p/" || len(f.Tags) != 2 || f.SizeGreaterThan != 100 || f.SizeLessThan != -1 {
		t.Errorf("And filter = %+v", f)
	}
	out, err := c.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	c2, err := Parse(out, tiers("COLD"))
	if err != nil {
		t.Fatalf("canonical form does not parse: %v\n%s", err, out)
	}
	out2, _ := c2.Marshal()
	if !bytes.Equal(out, out2) {
		t.Errorf("rendering is not stable:\n%s\n%s", out, out2)
	}
	if got := c.Tiers(); len(got) != 1 || got[0] != "COLD" || !c.UsesTransitions() {
		t.Errorf("tiers = %v", got)
	}
}

func TestParseRefusals(t *testing.T) {
	for name, tt := range map[string]struct{ doc, code string }{
		"not xml":            {"nope", "MalformedXML"},
		"no rules":           {cfgDoc(), "MalformedXML"},
		"no status":          {`<LifecycleConfiguration><Rule><ID>x</ID><Filter/>` + exp30 + `</Rule></LifecycleConfiguration>`, "MalformedXML"},
		"bad status":         {cfgDoc(rule("a", "On", all, exp30)), "MalformedXML"},
		"no filter nor pfx":  {cfgDoc(`<Rule><ID>a</ID><Status>Enabled</Status>` + exp30 + `</Rule>`), "MalformedXML"},
		"filter and prefix":  {cfgDoc(`<Rule><ID>a</ID><Status>Enabled</Status><Prefix>x</Prefix><Filter/>` + exp30 + `</Rule>`), "MalformedXML"},
		"no action":          {cfgDoc(rule("a", "Enabled", all, "")), "MalformedXML"},
		"duplicate id":       {cfgDoc(rule("a", "Enabled", all, exp30), rule("a", "Enabled", prefixed, exp30)), "InvalidArgument"},
		"zero days":          {cfgDoc(rule("a", "Enabled", all, `<Expiration><Days>0</Days></Expiration>`)), "InvalidArgument"},
		"days and date":      {cfgDoc(rule("a", "Enabled", all, `<Expiration><Days>1</Days><Date>2030-01-01T00:00:00Z</Date></Expiration>`)), "MalformedXML"},
		"date not midnight":  {cfgDoc(rule("a", "Enabled", all, `<Expiration><Date>2030-01-01T10:00:00Z</Date></Expiration>`)), "InvalidArgument"},
		"marker with days":   {cfgDoc(rule("a", "Enabled", all, `<Expiration><Days>1</Days><ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker></Expiration>`)), "MalformedXML"},
		"marker with tag":    {cfgDoc(rule("a", "Enabled", `<Filter><Tag><Key>k</Key><Value>v</Value></Tag></Filter>`, `<Expiration><ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker></Expiration>`)), "InvalidArgument"},
		"abort with tag":     {cfgDoc(rule("a", "Enabled", `<Filter><Tag><Key>k</Key><Value>v</Value></Tag></Filter>`, `<AbortIncompleteMultipartUpload><DaysAfterInitiation>1</DaysAfterInitiation></AbortIncompleteMultipartUpload>`)), "InvalidArgument"},
		"two filter parts":   {cfgDoc(rule("a", "Enabled", `<Filter><Prefix>a</Prefix><Tag><Key>k</Key><Value>v</Value></Tag></Filter>`, exp30)), "MalformedXML"},
		"unknown tier":       {cfgDoc(rule("a", "Enabled", all, `<Transition><Days>1</Days><StorageClass>NOPE</StorageClass></Transition>`)), "InvalidArgument"},
		"expire before move": {cfgDoc(rule("a", "Enabled", all, `<Transition><Days>30</Days><StorageClass>COLD</StorageClass></Transition><Expiration><Days>10</Days></Expiration>`)), "InvalidArgument"},
		"newer too big":      {cfgDoc(rule("a", "Enabled", all, `<NoncurrentVersionExpiration><NewerNoncurrentVersions>101</NewerNoncurrentVersions></NoncurrentVersionExpiration>`)), "InvalidArgument"},
		"size order":         {cfgDoc(rule("a", "Enabled", `<Filter><And><ObjectSizeGreaterThan>10</ObjectSizeGreaterThan><ObjectSizeLessThan>5</ObjectSizeLessThan></And></Filter>`, exp30)), "InvalidArgument"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(tt.doc), tiers("COLD"))
			le, ok := err.(*Error)
			if !ok || le.Code != tt.code {
				t.Fatalf("err = %v, want code %s", err, tt.code)
			}
		})
	}
}

func TestEvalExpirationAndRounding(t *testing.T) {
	c := mustParse(t, cfgDoc(rule("r", "Enabled", prefixed, exp30)))
	mod := time.Date(2026, 1, 1, 15, 30, 0, 0, time.UTC)
	o := ObjectOpts{Name: "logs/a", IsLatest: true, ModTime: mod, NumVersions: 1}
	// 30 days after 15:30 is Jan 31 15:30; S3 rounds up to Feb 1 00:00.
	for _, tt := range []struct {
		now  time.Time
		want Action
	}{
		{time.Date(2026, 1, 31, 15, 31, 0, 0, time.UTC), ActionNone},
		{time.Date(2026, 1, 31, 23, 59, 59, 0, time.UTC), ActionNone},
		{time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC), ActionDelete},
	} {
		if got := c.Eval(o, false, tt.now).Action; got != tt.want {
			t.Errorf("now=%v: %v, want %v", tt.now, got, tt.want)
		}
	}
	// Versioned: expiry adds a marker instead.
	if got := c.Eval(o, true, mod.Add(40*day)).Action; got != ActionDeleteMarker {
		t.Errorf("versioned = %v", got)
	}
	// A different prefix and a disabled rule do nothing.
	o.Name = "data/a"
	if got := c.Eval(o, false, mod.Add(40*day)).Action; got != ActionNone {
		t.Errorf("non-matching prefix = %v", got)
	}
	d := mustParse(t, cfgDoc(rule("r", "Disabled", all, exp30)))
	o.Name = "x"
	if got := d.Eval(o, false, mod.Add(40*day)).Action; got != ActionNone {
		t.Errorf("disabled rule = %v", got)
	}
}

func TestEvalNoncurrentAndMarkers(t *testing.T) {
	c := mustParse(t, cfgDoc(rule("n", "Enabled", all,
		`<NoncurrentVersionExpiration><NoncurrentDays>10</NoncurrentDays><NewerNoncurrentVersions>2</NewerNoncurrentVersions></NoncurrentVersionExpiration>`),
		rule("m", "Enabled", prefixed, `<Expiration><ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker></Expiration>`)))
	base := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	now := base.Add(20 * day)
	nc := func(idx int, successorAge time.Duration) ObjectOpts {
		return ObjectOpts{Name: "k", NoncurrentIndex: idx, SuccessorModTime: now.Add(-successorAge), NumVersions: 5}
	}
	// Index 1 and 2 are kept (the two newest noncurrent); index 3 is old enough.
	for _, tt := range []struct {
		idx  int
		age  time.Duration
		want Action
	}{{1, 30 * day, ActionNone}, {2, 30 * day, ActionNone}, {3, 30 * day, ActionDelete}, {3, 5 * day, ActionNone}} {
		if got := c.Eval(nc(tt.idx, tt.age), true, now).Action; got != tt.want {
			t.Errorf("noncurrent idx %d age %v: %v, want %v", tt.idx, tt.age, got, tt.want)
		}
	}
	// A delete marker is removed only when it is alone, and only under the
	// rule whose filter it matches.
	m := ObjectOpts{Name: "logs/x", IsLatest: true, DeleteMarker: true, NumVersions: 1}
	if got := c.Eval(m, true, now).Action; got != ActionDelete {
		t.Errorf("lone marker = %v", got)
	}
	m.NumVersions = 2
	if got := c.Eval(m, true, now).Action; got != ActionNone {
		t.Errorf("marker with versions behind it = %v", got)
	}
	m.Name, m.NumVersions = "other/x", 1
	if got := c.Eval(m, true, now).Action; got != ActionNone {
		t.Errorf("marker outside the rule's prefix = %v", got)
	}
}

func TestEvalOverlapPrecedence(t *testing.T) {
	c := mustParse(t, cfgDoc(
		rule("expire", "Enabled", prefixed, `<Expiration><Days>60</Days></Expiration>`),
		rule("warm", "Enabled", all, `<Transition><Days>10</Days><StorageClass>WARM</StorageClass></Transition>`),
		rule("cold", "Enabled", all, `<Transition><Days>30</Days><StorageClass>COLD</StorageClass></Transition>`),
	), tiers("WARM", "COLD"))
	mod := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	o := ObjectOpts{Name: "logs/a", IsLatest: true, ModTime: mod, NumVersions: 1}
	check := func(age time.Duration, versioned Versioned, want Action, tier string) {
		t.Helper()
		d := c.Eval(o, versioned, mod.Add(age))
		if d.Action != want || d.Tier != tier {
			t.Errorf("age %v versioned=%v: %+v, want %v/%s", age, versioned, d, want, tier)
		}
	}
	check(5*day, false, ActionNone, "")
	check(15*day, false, ActionTransition, "WARM")
	check(40*day, false, ActionTransition, "COLD") // the colder of the due transitions
	check(61*day, false, ActionDelete, "")         // deletion outranks transition
	check(61*day, true, ActionTransition, "COLD")  // transition outranks a delete marker
	// Moves only go forward along the chain: WARM -> COLD yes, never back.
	o.Tier = "WARM"
	check(40*day, false, ActionTransition, "COLD")
	o.Tier = "COLD"
	check(40*day, false, ActionNone, "")
	o.Tier = "UNKNOWN" // a tier no rule mentions is left alone
	check(40*day, false, ActionNone, "")
}

// ----- scanner ---------------------------------------------------------

type memState struct {
	mu sync.Mutex
	m  map[string][]byte
}

func (s *memState) GetState(_ context.Context, n string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[n], nil
}

func (s *memState) PutState(_ context.Context, n string, d []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string][]byte{}
	}
	s.m[n] = d
	return nil
}

type env struct {
	t     *testing.T
	st    *fs.FS
	clock *fakeClock
	cfg   *Config
	sc    *Scanner
	state *memState

	mu      sync.Mutex
	results []Result
}

func newEnv(t *testing.T, cfg string, tweak ...func(*Options)) *env {
	t.Helper()
	st, err := fs.New(t.TempDir(), fs.Options{Locker: nslock.New(5 * time.Second), Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	e := &env{t: t, st: st, clock: &fakeClock{t: time.Now()}, state: &memState{}}
	if cfg != "" {
		e.cfg = mustParse(t, cfg, tiers("COLD"))
	}
	o := Options{
		Store: st, Clock: e.clock, State: e.state, Locker: nslock.New(time.Second), LockBucket: "sys-bucket",
		Configs: func(context.Context, string) (*Config, error) { return e.cfg, nil },
		Result:  func(r Result) { e.mu.Lock(); e.results = append(e.results, r); e.mu.Unlock() },
		Log:     quiet,
		TagsOf: func(ud map[string]string) map[string]string {
			var m map[string]string
			json.Unmarshal([]byte(ud["x-nanoio-internal-tags"]), &m)
			return m
		},
	}
	for _, f := range tweak {
		f(&o)
	}
	e.sc, err = NewScanner(o)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) bucket(name string, versioning bool) {
	e.t.Helper()
	ctx := context.Background()
	if err := e.st.MakeBucket(ctx, name, storage.MakeBucketOptions{}); err != nil {
		e.t.Fatal(err)
	}
	if versioning {
		if err := e.st.SetBucketVersioning(ctx, name, storage.VersioningEnabled); err != nil {
			e.t.Fatal(err)
		}
	}
}

func (e *env) put(bucket, key, body string, tags map[string]string) storage.ObjectInfo {
	e.t.Helper()
	opts := storage.PutOptions{}
	if tags != nil {
		b, _ := json.Marshal(tags)
		opts.UserDefined = map[string]string{"x-nanoio-internal-tags": string(b)}
	}
	info, err := e.st.PutObject(context.Background(), bucket, key, strings.NewReader(body), int64(len(body)), opts)
	if err != nil {
		e.t.Fatal(err)
	}
	return info
}

func (e *env) keys(bucket string) []string {
	e.t.Helper()
	res, err := e.st.ListObjects(context.Background(), bucket, storage.ListOptions{})
	if err != nil {
		e.t.Fatal(err)
	}
	var out []string
	for _, o := range res.Objects {
		out = append(out, o.Name)
	}
	return out
}

func (e *env) scan(bucket string) Stats {
	e.t.Helper()
	st, err := e.sc.ScanBucket(context.Background(), bucket)
	if err != nil {
		e.t.Fatal(err)
	}
	return st
}

func TestScannerExpiresAfter30DaysWithFakeClock(t *testing.T) {
	e := newEnv(t, cfgDoc(rule("r", "Enabled", prefixed, exp30)))
	e.bucket("lc-unversioned", false)
	e.put("lc-unversioned", "logs/old", "1", nil)
	e.put("lc-unversioned", "logs/older", "2", nil)
	e.put("lc-unversioned", "data/keep", "3", nil)

	e.clock.Advance(29 * day)
	if st := e.scan("lc-unversioned"); st.Expired != 0 || len(e.keys("lc-unversioned")) != 3 {
		t.Fatalf("day 29: %+v, keys %v", st, e.keys("lc-unversioned"))
	}
	e.clock.Advance(2 * day) // day 31: past 30 days plus midnight rounding
	st := e.scan("lc-unversioned")
	if st.Expired != 2 || fmt.Sprint(e.keys("lc-unversioned")) != "[data/keep]" {
		t.Fatalf("day 31: %+v, keys %v", st, e.keys("lc-unversioned"))
	}
	// Every deletion is reported for the audit trail (Phase 11 events).
	if len(e.results) != 2 || e.results[0].Action != ActionDelete || e.results[0].RuleID != "r" || e.results[0].Time.Before(e.clock.Now().Add(-time.Second)) {
		t.Errorf("results = %+v", e.results)
	}
}

func TestScannerVersionedBucket(t *testing.T) {
	e := newEnv(t, cfgDoc(
		rule("cur", "Enabled", `<Filter><Prefix>cur/</Prefix></Filter>`, `<Expiration><Days>5</Days></Expiration>`),
		rule("old", "Enabled", `<Filter><Prefix>old/</Prefix></Filter>`,
			`<NoncurrentVersionExpiration><NoncurrentDays>5</NoncurrentDays><NewerNoncurrentVersions>1</NewerNoncurrentVersions></NoncurrentVersionExpiration>`),
		rule("markers", "Enabled", `<Filter><Prefix>gone/</Prefix></Filter>`, `<Expiration><ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker></Expiration>`),
	))
	e.bucket("lc-versioned", true)
	ctx := context.Background()
	e.put("lc-versioned", "cur/a", "a", nil)
	for i := 0; i < 4; i++ {
		e.put("lc-versioned", "old/k", fmt.Sprint(i), nil)
	}
	e.put("lc-versioned", "gone/m", "x", nil)

	e.clock.Advance(10 * day)
	st := e.scan("lc-versioned")
	// cur/a gets a delete marker; old/k keeps the newest current + 1 noncurrent
	// and loses 2 noncurrent versions.
	if st.Markers != 1 || st.Expired != 2 {
		t.Fatalf("stats = %+v", st)
	}
	vers, err := e.st.ListObjectVersions(ctx, "lc-versioned", storage.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	count := map[string]int{}
	marker := map[string]bool{}
	for _, v := range vers.Versions {
		count[v.Name]++
		if v.DeleteMarker && v.IsLatest {
			marker[v.Name] = true
		}
	}
	if count["old/k"] != 2 || count["cur/a"] != 2 || !marker["cur/a"] {
		t.Fatalf("versions = %v markers = %v", count, marker)
	}

	// Delete gone/m (marker created), then expire the lone marker once the
	// object version behind it has itself been removed by noncurrent rules.
	if _, err := e.st.DeleteObject(ctx, "lc-versioned", "gone/m", storage.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if st := e.scan("lc-versioned"); st.Expired != 0 {
		t.Errorf("a marker with a version behind it must stay: %+v", st)
	}
	vs, _ := e.st.ListObjectVersions(ctx, "lc-versioned", storage.ListOptions{Prefix: "gone/"})
	for _, v := range vs.Versions {
		if !v.DeleteMarker {
			e.st.DeleteObject(ctx, "lc-versioned", v.Name, storage.DeleteOptions{VersionID: v.VersionID})
		}
	}
	if st := e.scan("lc-versioned"); st.Expired != 1 {
		t.Errorf("a lone delete marker must be removed: %+v", st)
	}
}

func TestScannerTagsAndSizeFilters(t *testing.T) {
	e := newEnv(t, cfgDoc(rule("t", "Enabled",
		`<Filter><And><Tag><Key>tier</Key><Value>tmp</Value></Tag><ObjectSizeGreaterThan>3</ObjectSizeGreaterThan></And></Filter>`, exp30)))
	e.bucket("lc-filters", false)
	e.put("lc-filters", "match", "12345", map[string]string{"tier": "tmp"})
	e.put("lc-filters", "small", "1", map[string]string{"tier": "tmp"})
	e.put("lc-filters", "other-tag", "12345", map[string]string{"tier": "prod"})
	e.put("lc-filters", "untagged", "12345", nil)
	e.clock.Advance(40 * day)
	e.scan("lc-filters")
	if got := fmt.Sprint(e.keys("lc-filters")); got != "[other-tag small untagged]" {
		t.Errorf("keys = %s", got)
	}
}

func TestScannerAbortsIncompleteUploads(t *testing.T) {
	e := newEnv(t, cfgDoc(rule("a", "Enabled", `<Filter><Prefix>up/</Prefix></Filter>`,
		`<AbortIncompleteMultipartUpload><DaysAfterInitiation>7</DaysAfterInitiation></AbortIncompleteMultipartUpload>`)))
	e.bucket("lc-mpu", false)
	ctx := context.Background()
	for _, k := range []string{"up/a", "other/b"} {
		if _, err := e.st.NewMultipartUpload(ctx, "lc-mpu", k, storage.PutOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	e.clock.Advance(5 * day)
	if st := e.scan("lc-mpu"); st.Aborted != 0 {
		t.Fatalf("day 5: %+v", st)
	}
	e.clock.Advance(5 * day)
	if st := e.scan("lc-mpu"); st.Aborted != 1 {
		t.Fatalf("day 10: %+v", st)
	}
	left, _ := e.st.ListMultipartUploads(ctx, "lc-mpu", storage.ListUploadsOptions{})
	if len(left.Uploads) != 1 || left.Uploads[0].Object != "other/b" {
		t.Errorf("uploads left = %+v", left.Uploads)
	}
}

func TestScannerRespectsObjectLock(t *testing.T) {
	e := newEnv(t, cfgDoc(rule("r", "Enabled", all, exp30)))
	ctx := context.Background()
	if err := e.st.MakeBucket(ctx, "lc-locked", storage.MakeBucketOptions{ObjectLock: true}); err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(365 * day)
	_, err := e.st.PutObject(ctx, "lc-locked", "held", strings.NewReader("x"), 1,
		storage.PutOptions{Retention: storage.Retention{Mode: storage.RetentionCompliance, Until: until}})
	if err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(40 * day)
	st := e.scan("lc-locked")
	// A versioned (object lock) bucket gets a delete marker, which lock
	// permits; the locked version itself is never removed.
	vers, _ := e.st.ListObjectVersions(ctx, "lc-locked", storage.ListOptions{})
	locked := 0
	for _, v := range vers.Versions {
		if !v.DeleteMarker {
			locked++
		}
	}
	if locked != 1 || st.Markers != 1 {
		t.Errorf("stats %+v, object versions left %d", st, locked)
	}
}

func TestOnlyOneScannerLeadsABucket(t *testing.T) {
	shared := nslock.New(2 * time.Second)
	var (
		mu       sync.Mutex
		inFlight int
		maxSeen  int
		started  = make(chan struct{})
		release  = make(chan struct{})
		once     sync.Once
	)
	hook := func(*Options) {}
	e1 := newEnv(t, cfgDoc(rule("r", "Enabled", all, exp30)), hook, func(o *Options) { o.Locker = shared })
	e1.bucket("lc-leader", false)
	e1.put("lc-leader", "k", "v", nil)
	e1.clock.Advance(40 * day)
	// A second node over the same store and lock.
	o2 := e1.sc.o
	o2.Result = func(Result) {}
	sc2, _ := NewScanner(o2)
	// Node 1 blocks inside its scan (via the Result callback) while holding
	// the lock; node 2 must find the bucket led and do nothing.
	o1 := e1.sc.o
	o1.Result = func(r Result) {
		mu.Lock()
		inFlight++
		if inFlight > maxSeen {
			maxSeen = inFlight
		}
		mu.Unlock()
		once.Do(func() { close(started) })
		<-release
		mu.Lock()
		inFlight--
		mu.Unlock()
	}
	sc1, _ := NewScanner(o1)
	done := make(chan Stats, 1)
	go func() {
		st, _ := sc1.ScanBucket(context.Background(), "lc-leader")
		done <- st
	}()
	<-started
	st2, err := sc2.ScanBucket(context.Background(), "lc-leader")
	if err != nil || st2.Versions != 0 || st2.Expired != 0 {
		t.Errorf("second node scanned while the first led: %+v, %v", st2, err)
	}
	close(release)
	if st1 := <-done; st1.Expired != 1 {
		t.Errorf("leader stats = %+v", st1)
	}
	if maxSeen > 1 {
		t.Errorf("%d concurrent scans of one bucket", maxSeen)
	}
}

func TestIntervalSkipsRecentlyScannedBuckets(t *testing.T) {
	e := newEnv(t, cfgDoc(rule("r", "Enabled", all, exp30)), func(o *Options) { o.Interval = 6 * time.Hour })
	e.bucket("lc-interval", false)
	e.put("lc-interval", "k", "v", nil)
	ctx := context.Background()
	if err := e.sc.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	e.put("lc-interval", "k2", "v", nil)
	e.clock.Advance(40 * day)
	// Not yet an interval since the last completed scan of this bucket?
	// 40 days passed on the clock, so the scan runs.
	e.sc.RunOnce(ctx)
	if len(e.keys("lc-interval")) != 0 {
		t.Fatalf("keys = %v", e.keys("lc-interval"))
	}
	e.put("lc-interval", "k3", "v", nil)
	e.clock.Advance(time.Hour) // one hour later: inside the interval
	e.sc.RunOnce(ctx)
	if len(e.keys("lc-interval")) != 1 {
		t.Errorf("a bucket scanned an hour ago was scanned again: keys %v", e.keys("lc-interval"))
	}
}

func TestRateLimitSpacesOperations(t *testing.T) {
	e := newEnv(t, cfgDoc(rule("r", "Enabled", all, exp30)), func(o *Options) { o.OpsPerSecond = 50 })
	e.bucket("lc-rate", false)
	for i := 0; i < 10; i++ {
		e.put("lc-rate", fmt.Sprintf("k%d", i), "v", nil)
	}
	e.clock.Advance(40 * day)
	start := time.Now()
	st := e.scan("lc-rate")
	// 10 versions listed + 10 deletions at 50/s: about 0.4s.
	if d := time.Since(start); st.Expired != 10 || d < 300*time.Millisecond {
		t.Errorf("expired %d in %v; the limiter did not pace the scan", st.Expired, d)
	}
}
