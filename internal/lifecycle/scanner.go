package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"time"

	"nanoio/internal/storage"
)

// StateStore keeps small per-bucket scanner state (the time of the last
// completed scan) where every node can see it: the cluster's system bucket.
type StateStore interface {
	GetState(ctx context.Context, name string) ([]byte, error) // nil, nil if absent
	PutState(ctx context.Context, name string, data []byte) error
}

// Transitioner moves one version's data to a tier and leaves a stub. It is
// implemented by the tiering layer; the scanner only decides when.
type Transitioner interface {
	Transition(ctx context.Context, bucket, key, versionID, tier string, size int64) error
}

// Result is reported for every action the scanner took or tried.
type Result struct {
	Bucket    string
	Key       string
	VersionID string // as listed ("" or "null" for the null version)
	Action    Action
	RuleID    string
	Tier      string
	Info      storage.ObjectInfo
	Aborted   bool // an incomplete multipart upload was aborted
	UploadID  string
	Time      time.Time
	Err       error
}

// Stats counts what one bucket scan did.
type Stats struct {
	Versions     int `json:"versions"`
	Expired      int `json:"expired"`
	Markers      int `json:"deleteMarkers"`
	Transitioned int `json:"transitioned"`
	Aborted      int `json:"abortedUploads"`
	Locked       int `json:"skippedLocked"`
	Errors       int `json:"errors"`
}

// Options configures a Scanner.
type Options struct {
	Store   storage.StorageAPI
	Configs func(ctx context.Context, bucket string) (*Config, error)
	Locker  storage.Locker
	// LockBucket is the system bucket the leader locks and state live in.
	LockBucket string
	State      StateStore
	Clock      Clock
	// Interval is the minimum time between two scans of one bucket,
	// whichever node performs them. Default 1 hour.
	Interval time.Duration
	// OpsPerSecond bounds listing entries examined plus actions taken, so a
	// scan trickles along beside foreground traffic. 0 is unlimited.
	OpsPerSecond float64
	// LockWait is how long a node waits for a bucket's leader lock before
	// deciding another node is leading (default 200ms).
	LockWait     time.Duration
	Transitioner Transitioner
	// TagsOf decodes an object's tags from its stored user metadata.
	TagsOf func(map[string]string) map[string]string
	// TierOf returns the tier a version's data already lives in.
	TierOf func(storage.ObjectInfo) string
	// Skip excludes buckets (the system bucket).
	Skip   func(bucket string) bool
	Result func(Result)
	Log    *slog.Logger
}

// Scanner applies lifecycle configurations.
type Scanner struct {
	o   Options
	lim *limiter
	mu  sync.Mutex // serialises RunOnce within a process
}

// NewScanner validates o and returns a scanner.
func NewScanner(o Options) (*Scanner, error) {
	switch {
	case o.Store == nil, o.Configs == nil:
		return nil, errors.New("lifecycle: Store and Configs are required")
	}
	if o.Clock == nil {
		o.Clock = RealClock{}
	}
	if o.Interval <= 0 {
		o.Interval = time.Hour
	}
	if o.LockWait <= 0 {
		o.LockWait = 200 * time.Millisecond
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.TagsOf == nil {
		o.TagsOf = func(map[string]string) map[string]string { return nil }
	}
	if o.TierOf == nil {
		o.TierOf = func(storage.ObjectInfo) string { return "" }
	}
	return &Scanner{o: o, lim: newLimiter(o.OpsPerSecond)}, nil
}

// Run scans until ctx ends, looking for work every tick. Real time paces the
// loop; the clock only decides what is due.
func (s *Scanner) Run(ctx context.Context, tick time.Duration) {
	if tick <= 0 {
		tick = time.Minute
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		if err := s.RunOnce(ctx); err != nil && ctx.Err() == nil {
			s.o.Log.Warn("lifecycle: scan failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

type bucketState struct {
	LastRun time.Time `json:"lastRun"`
}

// RunOnce visits every bucket once. For each bucket with a lifecycle
// configuration the node first takes the bucket's cluster-wide lock; a node
// that cannot get it in LockWait moves on, so exactly one node scans a
// bucket at a time. The leader skips the bucket if it was completed less
// than Interval ago (by anyone).
func (s *Scanner) RunOnce(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	buckets, err := s.o.Store.ListBuckets(ctx)
	if err != nil {
		return err
	}
	for _, b := range buckets {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if s.o.Skip != nil && s.o.Skip(b.Name) {
			continue
		}
		if _, err := s.scanIfLeader(ctx, b.Name, false); err != nil && ctx.Err() == nil {
			s.o.Log.Warn("lifecycle: bucket scan failed", "bucket", b.Name, "err", err)
		}
	}
	return nil
}

// ScanBucket scans one bucket now, regardless of the interval (it still
// takes the leader lock).
func (s *Scanner) ScanBucket(ctx context.Context, bucket string) (Stats, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.scanIfLeader(ctx, bucket, true)
}

func (s *Scanner) scanIfLeader(ctx context.Context, bucket string, force bool) (Stats, error) {
	var st Stats
	cfg, err := s.o.Configs(ctx, bucket)
	if err != nil || cfg == nil {
		return st, err
	}
	if s.o.Locker != nil {
		lctx, cancel := context.WithTimeout(ctx, s.o.LockWait)
		unlock, err := s.o.Locker.Lock(lctx, s.o.LockBucket, "_lifecycle/"+bucket)
		cancel()
		if err != nil {
			return st, nil // another node leads this bucket
		}
		defer unlock()
	}
	if !force && s.o.State != nil {
		if raw, _ := s.o.State.GetState(ctx, "_lifecycle/"+bucket+"/state"); raw != nil {
			var bs bucketState
			if json.Unmarshal(raw, &bs) == nil && s.o.Clock.Now().Sub(bs.LastRun) < s.o.Interval {
				return st, nil
			}
		}
	}
	st, err = s.scan(ctx, bucket, cfg)
	if err == nil && s.o.State != nil {
		raw, _ := json.Marshal(bucketState{LastRun: s.o.Clock.Now().UTC()})
		s.o.State.PutState(ctx, "_lifecycle/"+bucket+"/state", raw)
	}
	return st, err
}

func (s *Scanner) report(r Result) {
	if s.o.Result != nil {
		r.Time = s.o.Clock.Now()
		s.o.Result(r)
	}
}

func (s *Scanner) scan(ctx context.Context, bucket string, cfg *Config) (Stats, error) {
	var st Stats
	vcfg, err := s.o.Store.GetBucketVersioning(ctx, bucket)
	if err != nil {
		return st, err
	}
	versioned := Versioned(vcfg.State != storage.VersioningUnversioned)
	now := s.o.Clock.Now()

	opts := storage.ListOptions{MaxKeys: 1000}
	var group []storage.ObjectInfo
	flush := func() error {
		if len(group) > 0 {
			err := s.applyGroup(ctx, bucket, cfg, group, versioned, now, &st)
			group = group[:0]
			return err
		}
		return nil
	}
	for {
		page, err := s.o.Store.ListObjectVersions(ctx, bucket, opts)
		if err != nil {
			return st, err
		}
		for _, v := range page.Versions {
			if len(group) > 0 && group[0].Name != v.Name {
				if err := flush(); err != nil {
					return st, err
				}
			}
			group = append(group, v)
			st.Versions++
			if err := s.lim.wait(ctx); err != nil {
				return st, err
			}
		}
		if !page.IsTruncated {
			break
		}
		opts.Marker, opts.VersionIDMarker = page.NextMarker, page.NextVersionIDMarker
	}
	if err := flush(); err != nil {
		return st, err
	}
	if cfg.HasAbortRules() {
		if err := s.abortUploads(ctx, bucket, cfg, now, &st); err != nil {
			return st, err
		}
	}
	return st, nil
}

// applyGroup evaluates every version of one key (given newest first).
func (s *Scanner) applyGroup(ctx context.Context, bucket string, cfg *Config, group []storage.ObjectInfo,
	versioned Versioned, now time.Time, st *Stats) error {
	noncurrent := 0
	for i, v := range group {
		o := ObjectOpts{
			Name: v.Name, VersionID: v.VersionID, IsLatest: i == 0, DeleteMarker: v.DeleteMarker,
			ModTime: v.ModTime, Size: v.Size, Tags: s.o.TagsOf(v.UserDefined), NumVersions: len(group),
			Tier: s.o.TierOf(v),
		}
		if i > 0 {
			noncurrent++
			o.NoncurrentIndex = noncurrent
			o.SuccessorModTime = group[i-1].ModTime
		}
		d := cfg.Eval(o, versioned, now)
		if d.Action == ActionNone {
			continue
		}
		if err := s.lim.wait(ctx); err != nil {
			return err
		}
		if err := s.act(ctx, bucket, v, d, st); err != nil {
			return err
		}
	}
	return nil
}

func (s *Scanner) act(ctx context.Context, bucket string, v storage.ObjectInfo, d Decision, st *Stats) error {
	res := Result{Bucket: bucket, Key: v.Name, VersionID: v.VersionID, Action: d.Action, RuleID: d.RuleID, Tier: d.Tier, Info: v}
	var err error
	switch d.Action {
	case ActionDelete:
		_, err = s.o.Store.DeleteObject(ctx, bucket, v.Name, storage.DeleteOptions{VersionID: v.VersionID})
	case ActionDeleteMarker:
		_, err = s.o.Store.DeleteObject(ctx, bucket, v.Name, storage.DeleteOptions{})
	case ActionTransition:
		if s.o.Transitioner == nil {
			return nil
		}
		err = s.o.Transitioner.Transition(ctx, bucket, v.Name, v.VersionID, d.Tier, v.Size)
	}
	switch {
	case err == nil:
		switch d.Action {
		case ActionDelete:
			st.Expired++
		case ActionDeleteMarker:
			st.Markers++
		case ActionTransition:
			st.Transitioned++
		}
		s.report(res)
	case errors.Is(err, storage.ErrObjectLocked):
		st.Locked++ // object lock outranks lifecycle
	case errors.Is(err, storage.ErrObjectNotFound), errors.Is(err, storage.ErrVersionNotFound),
		errors.Is(err, storage.ErrAlreadyTransitioned), errors.Is(err, storage.ErrPreconditionFailed):
		// Changed since it was listed; the next scan sees the new state.
	case ctx.Err() != nil:
		return ctx.Err()
	default:
		st.Errors++
		res.Err = err
		s.report(res)
		s.o.Log.Warn("lifecycle: action failed", "bucket", bucket, "key", v.Name, "action", d.Action, "err", err)
	}
	return nil
}

func (s *Scanner) abortUploads(ctx context.Context, bucket string, cfg *Config, now time.Time, st *Stats) error {
	opts := storage.ListUploadsOptions{MaxUploads: 1000}
	for {
		page, err := s.o.Store.ListMultipartUploads(ctx, bucket, opts)
		if err != nil {
			return err
		}
		for _, u := range page.Uploads {
			if err := s.lim.wait(ctx); err != nil {
				return err
			}
			id, ok := cfg.AbortAfter(u.Object, u.Initiated, now)
			if !ok {
				continue
			}
			err := s.o.Store.AbortMultipartUpload(ctx, bucket, u.Object, u.UploadID)
			switch {
			case err == nil:
				st.Aborted++
				s.report(Result{Bucket: bucket, Key: u.Object, RuleID: id, Aborted: true, UploadID: u.UploadID})
			case ctx.Err() != nil:
				return ctx.Err()
			case errors.Is(err, storage.ErrNoSuchUpload):
			default:
				st.Errors++
			}
		}
		if !page.IsTruncated {
			return nil
		}
		opts.KeyMarker, opts.UploadIDMarker = page.NextKeyMarker, page.NextUploadIDMarker
	}
}

// limiter spaces operations so that at most rate happen per second. The
// zero rate never waits. It uses real time: it exists to protect real
// foreground latency, not to model the clock.
type limiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

func newLimiter(rate float64) *limiter {
	if rate <= 0 {
		return &limiter{}
	}
	return &limiter{interval: time.Duration(float64(time.Second) / rate)}
}

func (l *limiter) wait(ctx context.Context) error {
	if l.interval == 0 {
		return ctx.Err()
	}
	l.mu.Lock()
	now := time.Now()
	if l.next.Before(now) {
		l.next = now
	}
	at := l.next
	l.next = l.next.Add(l.interval)
	l.mu.Unlock()
	if d := time.Until(at); d > 0 {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-t.C:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return ctx.Err()
}
