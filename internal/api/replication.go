package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"nanoio/internal/event"
	"nanoio/internal/replication"
	"nanoio/internal/storage"
	"nanoio/internal/tier"
)

const (
	confReplication  = "replication"
	confReplTargets  = "replication-targets"
	replMaxAttempts  = 8
	replScanInterval = 10 * time.Minute
)

var (
	errNoSuchReplication = &APIError{"ReplicationConfigurationNotFoundError", "The replication configuration was not found", http.StatusNotFound}
	errReplBadVersioning = &APIError{"InvalidRequest", "Versioning must be 'Enabled' on the bucket to apply a replication configuration", http.StatusBadRequest}
)

// ReplicationOptions turns on bucket replication on this node.
type ReplicationOptions struct {
	// Dir holds the durable task queues (node-local). Required.
	Dir string
	// Workers is how many objects this node replicates at once (default 4).
	Workers int
	// ScanInterval is how often a bucket is scanned for versions still
	// PENDING (default 10m); the scan is what recovers tasks lost with a
	// crashed node.
	ScanInterval time.Duration
	// Locker elects the node that scans a bucket.
	Locker storage.Locker
	// RetryBase and RetryMax shape the exponential backoff of a failed
	// task (defaults 5s and 10m); MaxAttempts is how many tries before a
	// version is marked FAILED (default 8; resync tries again).
	RetryBase, RetryMax time.Duration
	MaxAttempts         int
}

// replTarget is a registered remote bucket a source bucket replicates to.
type replTarget struct {
	ID                 string    `json:"id"`
	Endpoint           string    `json:"endpoint"`
	Bucket             string    `json:"bucket"`
	Region             string    `json:"region,omitempty"`
	AccessKey          string    `json:"accessKey"`
	SecretKey          string    `json:"secretKey"`
	InsecureSkipVerify bool      `json:"insecureSkipVerify,omitempty"`
	Created            time.Time `json:"created"`
	// ARN is derived: arn:minio:replication::<id>:<bucket>.
	ARN string `json:"arn,omitempty"`
}

func (t replTarget) redacted() replTarget {
	t.SecretKey = "*****"
	t.ARN = replication.ARN(t.ID, t.Bucket)
	return t
}

// ----- configuration documents -----------------------------------------------------

func (s *Server) replicationConfig(ctx context.Context, bucket string) (*replication.Config, error) {
	v, err := s.confParsed(ctx, bucket, confReplication, func(b []byte) (any, error) {
		return replication.Parse(b, nil)
	})
	if err != nil || v == nil {
		return nil, err
	}
	return v.(*replication.Config), nil
}

func (s *Server) replTargets(ctx context.Context, bucket string) ([]replTarget, error) {
	raw, err := s.confRaw(ctx, bucket, confReplTargets)
	if err != nil || raw == nil {
		return nil, err
	}
	var ts []replTarget
	if err := json.Unmarshal(raw, &ts); err != nil {
		return nil, err
	}
	for i := range ts {
		ts[i].ARN = replication.ARN(ts[i].ID, ts[i].Bucket)
	}
	return ts, nil
}

func (s *Server) replTarget(ctx context.Context, bucket, arn string) (*replTarget, error) {
	ts, err := s.replTargets(ctx, bucket)
	if err != nil {
		return nil, err
	}
	for i := range ts {
		if ts[i].ARN == arn {
			return &ts[i], nil
		}
	}
	return nil, nil
}

// ----- S3 handlers -------------------------------------------------------------------------

func (s *Server) bucketReplicationOp(q *request) {
	switch q.r.Method {
	case http.MethodPut:
		s.putBucketReplication(q)
	case http.MethodGet:
		s.getBucketReplication(q)
	case http.MethodDelete:
		s.deleteBucketReplication(q)
	default:
		s.fail(q, errBadMethod)
	}
}

func (s *Server) putBucketReplication(q *request) {
	if !s.authorize(q, "s3:PutReplicationConfiguration", q.bucket, "", nil) {
		return
	}
	body, err := s.readBody(q, replication.MaxXMLSize+1)
	if err != nil {
		s.fail(q, err)
		return
	}
	if !s.requireBucket(q) {
		return
	}
	vcfg, err := s.st.GetBucketVersioning(q.ctx(), q.bucket)
	if err != nil {
		s.fail(q, err)
		return
	}
	if vcfg.State != storage.VersioningEnabled {
		s.fail(q, errReplBadVersioning)
		return
	}
	targets, err := s.replTargets(q.ctx(), q.bucket)
	if err != nil {
		s.fail(q, err)
		return
	}
	cfg, perr := replication.Parse(body, func(arn string) error {
		for _, t := range targets {
			if t.ARN == arn {
				return nil
			}
		}
		return fmt.Errorf("the destination %q is not a registered remote target of this bucket", arn)
	})
	if perr != nil {
		re, _ := perr.(*replication.Error)
		switch {
		case re == nil || re.Code == "MalformedXML":
			s.fail(q, errMalformedXML)
		case re.Code == "EntityTooLarge":
			s.fail(q, errEntityLarge)
		case re.Code == "NotImplemented":
			s.fail(q, notImplemented(re.Message))
		default:
			s.fail(q, invalidArgument(re.Message))
		}
		return
	}
	doc, merr := cfg.Marshal()
	if merr != nil {
		s.fail(q, merr)
		return
	}
	if err := s.confPut(q.ctx(), q.bucket, confReplication, doc); err != nil {
		s.fail(q, err)
		return
	}
	if s.repl != nil && cfg.WantsExisting() {
		s.repl.startResync(q.bucket, "", false)
	}
	q.w.WriteHeader(http.StatusOK)
}

func (s *Server) getBucketReplication(q *request) {
	if !s.authorize(q, "s3:GetReplicationConfiguration", q.bucket, "", nil) || !s.requireBucket(q) {
		return
	}
	cfg, err := s.replicationConfig(q.ctx(), q.bucket)
	if err != nil {
		s.fail(q, err)
		return
	}
	if cfg == nil {
		s.fail(q, errNoSuchReplication)
		return
	}
	s.writeXML(q, http.StatusOK, cfg.Render())
}

func (s *Server) deleteBucketReplication(q *request) {
	if !s.authorize(q, "s3:PutReplicationConfiguration", q.bucket, "", nil) || !s.requireBucket(q) {
		return
	}
	s.confDrop(q.ctx(), q.bucket, confReplication)
	q.w.WriteHeader(http.StatusNoContent)
}

// ----- remote targets (admin) --------------------------------------------------------

func newTargetID() string {
	var b [6]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (s *Server) adminReplTarget(q *request) {
	bucket := q.query.Get("bucket")
	if bucket == "" {
		s.fail(q, invalidArgument("bucket is required"))
		return
	}
	switch q.r.Method {
	case http.MethodGet:
		if !s.authorize(q, "nanoio:ListReplicationTargets", "", "", nil) {
			return
		}
		ts, err := s.replTargets(q.ctx(), bucket)
		if err != nil {
			s.fail(q, err)
			return
		}
		out := []replTarget{}
		for _, t := range ts {
			out = append(out, t.redacted())
		}
		writeJSON(q.w, out)
	case http.MethodPut, http.MethodPost:
		if !s.authorize(q, "nanoio:ManageReplicationTargets", "", "", nil) {
			return
		}
		s.addReplTarget(q, bucket)
	case http.MethodDelete:
		if !s.authorize(q, "nanoio:ManageReplicationTargets", "", "", nil) {
			return
		}
		arn := q.query.Get("arn")
		cfg, _ := s.replicationConfig(q.ctx(), bucket)
		if cfg != nil {
			for _, d := range cfg.Destinations() {
				if d == arn {
					s.fail(q, &APIError{"TargetInUse", "A replication rule uses this target; remove the rule first.", http.StatusConflict})
					return
				}
			}
		}
		ts, err := s.replTargets(q.ctx(), bucket)
		if err != nil {
			s.fail(q, err)
			return
		}
		var keep []replTarget
		found := false
		for _, t := range ts {
			if t.ARN == arn {
				found = true
				continue
			}
			keep = append(keep, t)
		}
		if !found {
			s.fail(q, &APIError{"NoSuchTarget", "No such remote target.", http.StatusNotFound})
			return
		}
		data, _ := json.Marshal(keep)
		if err := s.confPut(q.ctx(), bucket, confReplTargets, data); err != nil {
			s.fail(q, err)
			return
		}
		q.w.WriteHeader(http.StatusNoContent)
	default:
		s.fail(q, errBadMethod)
	}
}

func (s *Server) addReplTarget(q *request, bucket string) {
	body, err := s.readBody(q, 64<<10)
	if err != nil {
		s.fail(q, err)
		return
	}
	var t replTarget
	if err := json.Unmarshal(body, &t); err != nil {
		s.fail(q, invalidArgument("invalid target document: "+err.Error()))
		return
	}
	if t.Endpoint == "" || t.Bucket == "" || t.AccessKey == "" || t.SecretKey == "" {
		s.fail(q, invalidArgument("a target needs endpoint, bucket, accessKey and secretKey"))
		return
	}
	if ok, err := s.st.BucketExists(q.ctx(), bucket); err != nil || !ok {
		s.fail(q, storage.ErrBucketNotFound)
		return
	}
	// The destination must be reachable and versioned: replicas keep their
	// version IDs, which an unversioned bucket cannot hold.
	if err := checkRemoteVersioned(q.ctx(), t); err != nil {
		s.fail(q, invalidArgument(err.Error()))
		return
	}
	t.ID, t.Created = newTargetID(), time.Now().UTC()
	ts, err := s.replTargets(q.ctx(), bucket)
	if err != nil {
		s.fail(q, err)
		return
	}
	ts = append(ts, t)
	for i := range ts {
		ts[i].ARN = ""
	}
	data, _ := json.Marshal(ts)
	if err := s.confPut(q.ctx(), bucket, confReplTargets, data); err != nil {
		s.fail(q, err)
		return
	}
	writeJSON(q.w, map[string]string{"arn": replication.ARN(t.ID, t.Bucket), "id": t.ID})
}

func s3ClientFor(t replTarget) (*tier.S3Client, error) {
	return tier.NewS3Client(tier.S3Config{Endpoint: t.Endpoint, Region: t.Region, Bucket: t.Bucket,
		AccessKey: t.AccessKey, SecretKey: t.SecretKey, InsecureSkipVerify: t.InsecureSkipVerify})
}

func checkRemoteVersioned(ctx context.Context, t replTarget) error {
	cl, err := s3ClientFor(t)
	if err != nil {
		return err
	}
	defer cl.Close()
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	resp, err := cl.Do(cctx, http.MethodGet, "", "versioning=", nil, nil)
	if err != nil {
		return fmt.Errorf("cannot reach the remote bucket: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the remote bucket answered %s (does it exist, and do the credentials allow s3:GetBucketVersioning?)", resp.Status)
	}
	var v struct {
		Status string `xml:"Status"`
	}
	if xml.Unmarshal(b, &v) != nil || v.Status != "Enabled" {
		return errors.New("versioning must be enabled on the remote bucket")
	}
	return nil
}

// ----- write path: status stamping and enqueue --------------------------------------------

// replPrepare returns ud with the replication status of a new version of
// key: PENDING for every destination a rule selects. It is called before
// the write, so the status commits atomically with the version and survives
// whatever happens to the queue.
func (s *Server) replPrepare(ctx context.Context, bucket, key string, ud map[string]string) map[string]string {
	if s.repl == nil {
		return ud
	}
	cfg, err := s.replicationConfig(ctx, bucket)
	if err != nil || cfg == nil {
		return ud
	}
	rules := cfg.Select(key, decodeTags(ud), replication.KindPut, false)
	if len(rules) == 0 {
		return ud
	}
	targets := map[string]string{}
	for _, r := range rules {
		targets[r.Destination] = replication.StatusPending
	}
	out := make(map[string]string, len(ud)+2)
	for k, v := range ud {
		out[k] = v
	}
	b, _ := json.Marshal(targets)
	out[replication.StatusKey] = replication.StatusPending
	out[replication.TargetsKey] = string(b)
	return out
}

// replAfterPut enqueues the replication of a version just written.
func (s *Server) replAfterPut(ctx context.Context, bucket, key, versionID string, ud map[string]string) {
	if s.repl == nil || ud[replication.StatusKey] != replication.StatusPending {
		return
	}
	var targets map[string]string
	json.Unmarshal([]byte(ud[replication.TargetsKey]), &targets)
	cfg, err := s.replicationConfig(ctx, bucket)
	if err != nil || cfg == nil {
		return
	}
	for _, r := range cfg.Select(key, decodeTags(ud), replication.KindPut, false) {
		if targets[r.Destination] == replication.StatusPending {
			s.repl.enqueue(replTask{Bucket: bucket, Key: key, VersionID: versionID, Op: opPut, ARN: r.Destination, Priority: r.Priority})
		}
	}
}

// replAfterMarker enqueues the replication of a delete marker. The marker's
// time is read back (a replica must carry the source's, or histories would
// order differently on the two sites).
func (s *Server) replAfterMarker(ctx context.Context, bucket, key, versionID string) {
	if s.repl == nil || versionID == "" {
		return
	}
	cfg, err := s.replicationConfig(ctx, bucket)
	if err != nil || cfg == nil {
		return
	}
	rules := cfg.Select(key, nil, replication.KindMarker, false)
	if len(rules) == 0 {
		return
	}
	mod, ok := s.markerTime(ctx, bucket, key, versionID)
	if !ok {
		return
	}
	for _, r := range rules {
		s.repl.enqueue(replTask{Bucket: bucket, Key: key, VersionID: versionID, Op: opMarker, ARN: r.Destination,
			Priority: r.Priority, ModTime: mod})
	}
}

// markerTime reads a delete marker's modification time.
func (s *Server) markerTime(ctx context.Context, bucket, key, versionID string) (time.Time, bool) {
	_, err := s.st.StatObject(ctx, bucket, key, storage.GetOptions{VersionID: versionID})
	var dm *storage.DeleteMarkerError
	if errors.As(err, &dm) {
		return dm.ModTime, true
	}
	return time.Time{}, false
}

// replAfterMeta is called after tags, retention or legal hold of a version
// changed: it marks the version PENDING again for the destinations that
// should hear about it and enqueues the metadata replication.
func (s *Server) replAfterMeta(ctx context.Context, bucket, key, versionID string) {
	if s.repl == nil {
		return
	}
	cfg, err := s.replicationConfig(ctx, bucket)
	if err != nil || cfg == nil {
		return
	}
	info, err := s.st.StatObject(ctx, bucket, key, storage.GetOptions{VersionID: versionID})
	if err != nil || info.DeleteMarker {
		return
	}
	status := info.UserDefined[replication.StatusKey]
	rules := cfg.Select(key, decodeTags(info.UserDefined), replication.KindMeta, status == replication.StatusReplica)
	if len(rules) == 0 {
		return
	}
	targets := map[string]string{}
	json.Unmarshal([]byte(info.UserDefined[replication.TargetsKey]), &targets)
	for _, r := range rules {
		targets[r.Destination] = replication.StatusPending
	}
	if err := s.setReplStatus(ctx, info, targets, status == replication.StatusReplica); err != nil {
		s.log.Warn("replication: cannot mark metadata change pending", "bucket", bucket, "key", key, "err", err)
		return
	}
	for _, r := range rules {
		s.repl.enqueue(replTask{Bucket: bucket, Key: key, VersionID: info.VersionID, Op: opMeta, ARN: r.Destination, Priority: r.Priority})
	}
}

// setReplStatus writes the targets map (and the aggregate) into the
// version's metadata, conditionally on its ETag. A REPLICA keeps that
// aggregate: it is a replica whatever it is also doing.
func (s *Server) setReplStatus(ctx context.Context, info storage.ObjectInfo, targets map[string]string, keepReplica bool) error {
	ud := make(map[string]string, len(info.UserDefined)+2)
	for k, v := range info.UserDefined {
		ud[k] = v
	}
	b, _ := json.Marshal(targets)
	ud[replication.TargetsKey] = string(b)
	if !keepReplica {
		ud[replication.StatusKey] = replication.Aggregate(targets)
	}
	_, err := s.st.UpdateObjectMetadata(ctx, info.Bucket, info.Name, storage.UpdateMetaOptions{
		VersionID: info.VersionID, UserDefined: ud, IfETag: info.ETag,
	})
	return err
}

// ----- replica writes (the destination side) ------------------------------------------------

// replicaIn describes a request that carries a replicated write.
type replicaIn struct {
	cluster   string
	versionID string
	modTime   time.Time
}

// replicaRequest recognises a replication request, authorises it and parses
// its identity headers. ok is false for an ordinary request; an error
// response has already been written when err is true.
func (s *Server) replicaRequest(q *request) (ri *replicaIn, bad bool) {
	h := q.r.Header
	if h.Get(replication.HdrRequest) == "" {
		return nil, false
	}
	if !s.authorize(q, "s3:ReplicateObject", q.bucket, q.key, nil) {
		return nil, true
	}
	ri = &replicaIn{cluster: h.Get(replication.HdrSource), versionID: h.Get(replication.HdrVersionID)}
	if t := h.Get(replication.HdrModTime); t != "" {
		mt, err := time.Parse(time.RFC3339Nano, t)
		if err != nil {
			s.fail(q, invalidArgument("invalid "+replication.HdrModTime))
			return nil, true
		}
		ri.modTime = mt
	}
	return ri, false
}

// applyReplica turns a replica request into the storage import and marks the
// version as a replica of its source cluster.
func (s *Server) applyReplica(ri *replicaIn, opts *storage.PutOptions) error {
	if ri.versionID == "" || ri.modTime.IsZero() {
		return errors.New("a replicated write needs " + replication.HdrVersionID + " and " + replication.HdrModTime)
	}
	opts.Import = &storage.VersionImport{VersionID: ri.versionID, ModTime: ri.modTime}
	ud := make(map[string]string, len(opts.UserDefined)+2)
	for k, v := range opts.UserDefined {
		ud[k] = v
	}
	ud[replication.StatusKey] = replication.StatusReplica
	ud[replication.SourceKey] = ri.cluster
	opts.UserDefined = ud
	return nil
}

// ----- engine -------------------------------------------------------------------------------------

const (
	opPut    = "put"
	opMarker = "marker"
	opMeta   = "meta"
)

type replTask struct {
	Bucket    string    `json:"bucket"`
	Key       string    `json:"key"`
	VersionID string    `json:"versionId"`
	Op        string    `json:"op"`
	ARN       string    `json:"arn"`
	Priority  int       `json:"priority"`
	Attempt   int       `json:"attempt,omitempty"`
	NotBefore time.Time `json:"notBefore,omitempty"`
	ModTime   time.Time `json:"modTime,omitempty"`
	Enqueued  time.Time `json:"enqueued"`
	// Force re-sends a version already COMPLETE (resync).
	Force bool `json:"force,omitempty"`
}

// replMetrics are the counters of one (bucket, destination).
type replMetrics struct {
	enqueued, completed, failed, retried, bytes atomic.Uint64
	latencyNanos, latencyCount, latencyMax      atomic.Int64
}

type replEngine struct {
	s    *Server
	o    ReplicationOptions
	qdir string

	mu      sync.Mutex
	queues  map[string]*event.Queue // "<bucket>\x00<priority>"
	metrics map[string]*replMetrics // "<bucket>\x00<arn>"
	clients map[string]*tier.S3Client
	wake    chan struct{}
	resyncs map[string]*resyncState

	inflight atomic.Int64
	wg       sync.WaitGroup
	stop     chan struct{}
}

type resyncState struct {
	Bucket   string
	ARN      string
	Force    bool
	Started  time.Time
	scanned  atomic.Int64
	queued   atomic.Int64
	mu       sync.Mutex
	running  bool
	finished time.Time
	err      string
}

type resyncView struct {
	Bucket   string    `json:"bucket"`
	ARN      string    `json:"arn,omitempty"`
	Force    bool      `json:"force,omitempty"`
	Running  bool      `json:"running"`
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished,omitempty"`
	Scanned  int64     `json:"scanned"`
	Queued   int64     `json:"queued"`
	Error    string    `json:"error,omitempty"`
}

func (r *resyncState) view() resyncView {
	r.mu.Lock()
	defer r.mu.Unlock()
	return resyncView{Bucket: r.Bucket, ARN: r.ARN, Force: r.Force, Running: r.running, Started: r.Started,
		Finished: r.finished, Scanned: r.scanned.Load(), Queued: r.queued.Load(), Error: r.err}
}

func (s *Server) startReplication(o *ReplicationOptions) error {
	if o.Dir == "" {
		return errors.New("api: ReplicationOptions.Dir is required")
	}
	opt := *o
	if opt.Workers <= 0 {
		opt.Workers = 4
	}
	if opt.ScanInterval <= 0 {
		opt.ScanInterval = replScanInterval
	}
	if opt.RetryBase <= 0 {
		opt.RetryBase = 5 * time.Second
	}
	if opt.RetryMax <= 0 {
		opt.RetryMax = 10 * time.Minute
	}
	if opt.MaxAttempts <= 0 {
		opt.MaxAttempts = replMaxAttempts
	}
	e := &replEngine{s: s, o: opt, qdir: opt.Dir, queues: map[string]*event.Queue{}, metrics: map[string]*replMetrics{},
		clients: map[string]*tier.S3Client{}, wake: make(chan struct{}, 1), resyncs: map[string]*resyncState{}, stop: make(chan struct{})}
	s.repl = e
	ctx, cancel := context.WithCancel(context.Background())
	s.stop = append(s.stop, func() {
		cancel()
		close(e.stop)
		e.wg.Wait()
		e.close()
	})
	e.openExisting()
	for i := 0; i < opt.Workers; i++ {
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			e.worker(ctx)
		}()
	}
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		e.scanLoop(ctx)
	}()
	return nil
}

// openExisting reopens the queues a previous run left on disk.
func (e *replEngine) openExisting() {
	// Directory layout: <dir>/<bucket>/<priority>/. Opened lazily by enqueue
	// and by the worker's sweep; nothing to do eagerly beyond waking.
	e.signal()
}

func (e *replEngine) close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for k, q := range e.queues {
		q.Close()
		delete(e.queues, k)
	}
	for _, c := range e.clients {
		c.Close()
	}
}

func (e *replEngine) signal() {
	select {
	case e.wake <- struct{}{}:
	default:
	}
}

func (e *replEngine) queue(bucket string, prio int) (*event.Queue, error) {
	k := bucket + "\x00" + strconv.Itoa(prio)
	e.mu.Lock()
	defer e.mu.Unlock()
	if q := e.queues[k]; q != nil {
		return q, nil
	}
	q, err := event.OpenQueue(e.qdir+"/"+bucket+"/"+strconv.Itoa(prio), 0, 0)
	if err != nil {
		return nil, err
	}
	e.queues[k] = q
	return q, nil
}

func (e *replEngine) metric(bucket, arn string) *replMetrics {
	k := bucket + "\x00" + arn
	e.mu.Lock()
	defer e.mu.Unlock()
	m := e.metrics[k]
	if m == nil {
		m = &replMetrics{}
		e.metrics[k] = m
	}
	return m
}

func (e *replEngine) enqueue(t replTask) {
	if t.Enqueued.IsZero() {
		t.Enqueued = time.Now()
	}
	q, err := e.queue(t.Bucket, t.Priority)
	if err != nil {
		e.s.log.Error("replication: cannot open the queue", "bucket", t.Bucket, "err", err)
		return
	}
	b, _ := json.Marshal(t)
	if err := q.Append(b); err != nil {
		e.s.log.Error("replication: cannot queue a task", "bucket", t.Bucket, "key", t.Key, "err", err)
		return
	}
	q.Sync()
	if t.Attempt == 0 {
		e.metric(t.Bucket, t.ARN).enqueued.Add(1)
	}
	e.signal()
}

// next claims the highest-priority ready task, if any. A task that is not
// yet due is rotated to the tail so it does not block the ones behind it.
func (e *replEngine) next() (replTask, bool, time.Duration) {
	type qk struct {
		bucket string
		prio   int
		q      *event.Queue
	}
	e.mu.Lock()
	var all []qk
	for k, q := range e.queues {
		i := strings.LastIndexByte(k, 0)
		p, _ := strconv.Atoi(k[i+1:])
		all = append(all, qk{k[:i], p, q})
	}
	e.mu.Unlock()
	sort.Slice(all, func(i, j int) bool { return all[i].prio > all[j].prio })
	wait := time.Duration(0)
	for _, c := range all {
		for tries := 0; tries < 32; tries++ {
			e.mu.Lock()
			items, err := c.q.Peek(1)
			if err != nil || len(items) == 0 {
				e.mu.Unlock()
				break
			}
			var t replTask
			if json.Unmarshal(items[0].Data, &t) != nil {
				c.q.Ack(items)
				e.mu.Unlock()
				continue
			}
			if d := time.Until(t.NotBefore); d > 0 {
				// Not due: rotate behind the others.
				c.q.Ack(items)
				c.q.Append(items[0].Data)
				c.q.Sync()
				e.mu.Unlock()
				if wait == 0 || d < wait {
					wait = d
				}
				continue
			}
			c.q.Ack(items)
			e.mu.Unlock()
			return t, true, 0
		}
	}
	return replTask{}, false, wait
}

func (e *replEngine) worker(ctx context.Context) {
	for ctx.Err() == nil {
		t, ok, wait := e.next()
		if !ok {
			if wait <= 0 || wait > time.Second {
				wait = time.Second
			}
			select {
			case <-ctx.Done():
				return
			case <-e.wake:
			case <-time.After(wait):
			}
			continue
		}
		e.inflight.Add(1)
		e.process(ctx, t)
		e.inflight.Add(-1)
	}
}

func (e *replEngine) client(t *replTarget) (*tier.S3Client, error) {
	k := t.ID + "\x00" + t.AccessKey + "\x00" + t.SecretKey + "\x00" + t.Endpoint
	e.mu.Lock()
	defer e.mu.Unlock()
	if c := e.clients[k]; c != nil {
		return c, nil
	}
	c, err := s3ClientFor(*t)
	if err != nil {
		return nil, err
	}
	e.clients[k] = c
	return c, nil
}

// retry re-queues a failed task with exponential backoff, or gives up.
func (e *replEngine) retry(t replTask, cause error, final bool) {
	m := e.metric(t.Bucket, t.ARN)
	t.Attempt++
	if final || t.Attempt >= e.o.MaxAttempts {
		m.failed.Add(1)
		e.s.log.Warn("replication: giving up on a version", "bucket", t.Bucket, "key", t.Key, "version", t.VersionID,
			"target", t.ARN, "attempts", t.Attempt, "err", cause)
		e.finish(context.Background(), t, replication.StatusFailed)
		return
	}
	m.retried.Add(1)
	d := e.o.RetryBase << (t.Attempt - 1)
	if d > e.o.RetryMax || d <= 0 {
		d = e.o.RetryMax
	}
	t.NotBefore = time.Now().Add(d)
	e.s.log.Debug("replication: will retry", "bucket", t.Bucket, "key", t.Key, "in", d, "err", cause)
	e.enqueue(t)
}

// finish records the outcome of one destination on the version.
func (e *replEngine) finish(ctx context.Context, t replTask, status string) {
	if t.Op == opMarker {
		return // markers carry no metadata to record on
	}
	for attempt := 0; attempt < 3; attempt++ {
		info, err := e.s.st.StatObject(ctx, t.Bucket, t.Key, storage.GetOptions{VersionID: t.VersionID})
		if err != nil {
			return
		}
		targets := map[string]string{}
		json.Unmarshal([]byte(info.UserDefined[replication.TargetsKey]), &targets)
		targets[t.ARN] = status
		err = e.s.setReplStatus(ctx, info, targets, info.UserDefined[replication.StatusKey] == replication.StatusReplica)
		if err == nil || !errors.Is(err, storage.ErrPreconditionFailed) {
			return
		}
	}
}

func (e *replEngine) process(ctx context.Context, t replTask) {
	s := e.s
	cfg, err := s.replicationConfig(ctx, t.Bucket)
	if err != nil {
		e.retry(t, err, false)
		return
	}
	if cfg == nil {
		return // replication was removed
	}
	tg, err := s.replTarget(ctx, t.Bucket, t.ARN)
	if err != nil {
		e.retry(t, err, false)
		return
	}
	if tg == nil {
		return // the target was removed
	}
	cl, err := e.client(tg)
	if err != nil {
		e.retry(t, err, true)
		return
	}
	start := time.Now()
	var bytesSent int64
	switch t.Op {
	case opPut:
		bytesSent, err = e.replicatePut(ctx, cl, cfg, t)
	case opMarker:
		err = e.replicateMarker(ctx, cl, t)
	case opMeta:
		err = e.replicateMeta(ctx, cl, t)
	}
	switch {
	case err == nil:
		m := e.metric(t.Bucket, t.ARN)
		m.completed.Add(1)
		m.bytes.Add(uint64(bytesSent))
		lat := time.Since(t.Enqueued).Nanoseconds()
		m.latencyNanos.Add(lat)
		m.latencyCount.Add(1)
		for {
			cur := m.latencyMax.Load()
			if lat <= cur || m.latencyMax.CompareAndSwap(cur, lat) {
				break
			}
		}
		_ = start
		e.finish(ctx, t, replication.StatusComplete)
	case errors.Is(err, errReplGone):
		// The version was removed or rewritten; nothing to do.
	case errors.Is(err, errReplPermanent):
		e.retry(t, err, true)
	case ctx.Err() != nil:
		e.enqueue(t) // shutting down: keep it
	default:
		e.retry(t, err, false)
	}
}

var (
	errReplGone      = errors.New("version no longer exists")
	errReplPermanent = errors.New("replication cannot succeed for this version")
)

func (e *replEngine) replicatePut(ctx context.Context, cl *tier.S3Client, cfg *replication.Config, t replTask) (int64, error) {
	s := e.s
	rd, info, size, etag, err := s.openPlain(ctx, t.Bucket, t.Key, t.VersionID)
	switch {
	case errors.Is(err, storage.ErrObjectNotFound), errors.Is(err, storage.ErrVersionNotFound):
		return 0, errReplGone
	case err != nil && strings.Contains(err.Error(), "customer-provided key"):
		return 0, fmt.Errorf("%w: %v", errReplPermanent, err)
	case err != nil:
		return 0, err
	}
	defer rd.Close()
	if info.DeleteMarker {
		return 0, errReplGone
	}
	if !t.Force {
		targets := map[string]string{}
		json.Unmarshal([]byte(info.UserDefined[replication.TargetsKey]), &targets)
		if targets[t.ARN] == replication.StatusComplete {
			return 0, nil
		}
	}
	h := map[string]string{
		replication.HdrRequest:   "true",
		replication.HdrSource:    s.clusterID(ctx),
		replication.HdrVersionID: info.VersionID,
		replication.HdrModTime:   info.ModTime.UTC().Format(time.RFC3339Nano),
		replication.HdrSourceTag: etag,
	}
	if info.VersionID == "" {
		h[replication.HdrVersionID] = storage.NullVersionID
	}
	for k, v := range info.UserDefined {
		if strings.HasPrefix(k, userMetaPrefix) && k != replication.HdrSourceTag {
			h[k] = v
		}
	}
	for _, sh := range systemHeaders {
		if v := info.UserDefined[strings.ToLower(sh)]; v != "" {
			h[sh] = v
		}
	}
	if r := info.Retention; !r.IsZero() && r.Until.After(time.Now()) {
		h["x-amz-object-lock-mode"] = string(r.Mode)
		h["x-amz-object-lock-retain-until-date"] = r.Until.UTC().Format(time.RFC3339)
	}
	if info.LegalHold {
		h["x-amz-object-lock-legal-hold"] = "ON"
	}
	if rule := ruleFor(cfg, t.ARN, t.Key, info.UserDefined); rule != nil && rule.StorageClass != "" {
		h["x-amz-storage-class"] = rule.StorageClass
	}
	meta := tier.ObjectMeta{ContentType: info.ContentType, Headers: h}
	if tags := decodeTags(info.UserDefined); len(tags) > 0 {
		q := url.Values{}
		for k, v := range tags {
			q.Set(k, v)
		}
		meta.Tagging = q.Encode()
	}
	if _, _, err := cl.PutObject(ctx, t.Key, rd, size, meta); err != nil {
		return 0, err
	}
	return size, nil
}

func ruleFor(cfg *replication.Config, arn, key string, ud map[string]string) *replication.Rule {
	for _, r := range cfg.Select(key, decodeTags(ud), replication.KindPut, false) {
		if r.Destination == arn {
			return r
		}
	}
	return nil
}

func (e *replEngine) replicateMarker(ctx context.Context, cl *tier.S3Client, t replTask) error {
	mt := t.ModTime
	if mt.IsZero() {
		var ok bool
		if mt, ok = e.s.markerTime(ctx, t.Bucket, t.Key, t.VersionID); !ok {
			return errReplGone
		}
	}
	resp, err := cl.Do(ctx, http.MethodDelete, t.Key, "", nil, map[string]string{
		replication.HdrRequest:   "true",
		replication.HdrSource:    e.s.clusterID(ctx),
		replication.HdrVersionID: t.VersionID,
		replication.HdrModTime:   mt.UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("the destination answered %s to a delete-marker replication", resp.Status)
	}
	return nil
}

func (e *replEngine) replicateMeta(ctx context.Context, cl *tier.S3Client, t replTask) error {
	s := e.s
	info, err := s.st.StatObject(ctx, t.Bucket, t.Key, storage.GetOptions{VersionID: t.VersionID})
	if errors.Is(err, storage.ErrObjectNotFound) || errors.Is(err, storage.ErrVersionNotFound) {
		return errReplGone
	}
	if err != nil {
		return err
	}
	if info.DeleteMarker {
		return errReplGone
	}
	vid := info.VersionID
	if vid == "" {
		vid = storage.NullVersionID
	}
	q := "versionId=" + url.QueryEscape(vid)
	hdr := map[string]string{replication.HdrRequest: "true", replication.HdrSource: s.clusterID(ctx)}
	send := func(sub string, body string) error {
		h := map[string]string{"Content-Type": "application/xml"}
		for k, v := range hdr {
			h[k] = v
		}
		resp, err := cl.Do(ctx, http.MethodPut, t.Key, sub+"&"+q, []byte(body), h)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		if resp.StatusCode == http.StatusNotFound {
			return errReplGone // the destination does not have the version (yet)
		}
		if resp.StatusCode/100 != 2 {
			return fmt.Errorf("the destination answered %s to a %s replication", resp.Status, sub)
		}
		return nil
	}
	var tagXML strings.Builder
	tagXML.WriteString("<Tagging><TagSet>")
	tags := decodeTags(info.UserDefined)
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		tagXML.WriteString("<Tag><Key>" + xmlEscape(k) + "</Key><Value>" + xmlEscape(tags[k]) + "</Value></Tag>")
	}
	tagXML.WriteString("</TagSet></Tagging>")
	if err := send("tagging=", tagXML.String()); err != nil {
		return err
	}
	if r := info.Retention; !r.IsZero() {
		doc := "<Retention><Mode>" + string(r.Mode) + "</Mode><RetainUntilDate>" + r.Until.UTC().Format(time.RFC3339) + "</RetainUntilDate></Retention>"
		if err := send("retention=", doc); err != nil {
			return err
		}
	}
	hold := "OFF"
	if info.LegalHold {
		hold = "ON"
	}
	// Legal hold is only meaningful on a lock-enabled bucket; a destination
	// that is not one answers with an error we do not want to retry forever.
	if info.LegalHold {
		if err := send("legal-hold=", "<LegalHold><Status>"+hold+"</Status></LegalHold>"); err != nil {
			return err
		}
	}
	return nil
}

func xmlEscape(s string) string {
	var b bytes.Buffer
	xml.EscapeText(&b, []byte(s))
	return b.String()
}

// ----- scan and resync -------------------------------------------------------------------------

func (e *replEngine) scanLoop(ctx context.Context) {
	t := time.NewTimer(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		e.scanAll(ctx)
		t.Reset(e.o.ScanInterval)
	}
}

func (e *replEngine) scanAll(ctx context.Context) {
	buckets, err := e.s.st.ListBuckets(ctx)
	if err != nil {
		return
	}
	for _, b := range buckets {
		if b.Name == sysBucket || ctx.Err() != nil {
			continue
		}
		cfg, err := e.s.replicationConfig(ctx, b.Name)
		if err != nil || cfg == nil {
			continue
		}
		e.scanBucket(ctx, b.Name, cfg, scanOpts{}, nil)
	}
}

// scanOpts says what a scan queues. The default queues only versions whose
// status is PENDING (crash recovery). all adds every version a rule selects
// that is not COMPLETE and every delete marker (resync); force re-sends
// COMPLETE versions too; arn limits it to one destination.
type scanOpts struct {
	arn   string
	all   bool
	force bool
}

// scanBucket walks a bucket's versions and queues what needs replicating.
// Only one node scans a bucket at a time.
func (e *replEngine) scanBucket(ctx context.Context, bucket string, cfg *replication.Config, so scanOpts, st *resyncState) {
	if e.o.Locker != nil {
		lctx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
		unlock, err := e.o.Locker.Lock(lctx, sysBucket, "_replication/"+bucket+"/scan")
		cancel()
		if err != nil {
			return
		}
		defer unlock()
	}
	count := func(scanned, queued int64) {
		if st != nil {
			st.scanned.Add(scanned)
			st.queued.Add(queued)
		}
	}
	opts := storage.ListOptions{MaxKeys: 1000}
	for {
		page, err := e.s.st.ListObjectVersions(ctx, bucket, opts)
		if err != nil {
			if st != nil {
				st.mu.Lock()
				st.err = err.Error()
				st.mu.Unlock()
			}
			return
		}
		for _, v := range page.Versions {
			if ctx.Err() != nil {
				return
			}
			count(1, 0)
			if v.DeleteMarker {
				if !so.all {
					continue
				}
				for _, r := range cfg.Select(v.Name, nil, replication.KindMarker, false) {
					if so.arn == "" || so.arn == r.Destination {
						e.enqueue(replTask{Bucket: bucket, Key: v.Name, VersionID: v.VersionID, Op: opMarker, ARN: r.Destination,
							Priority: r.Priority, ModTime: v.ModTime})
						count(0, 1)
					}
				}
				continue
			}
			if v.UserDefined[replication.StatusKey] == replication.StatusReplica {
				continue
			}
			targets := map[string]string{}
			json.Unmarshal([]byte(v.UserDefined[replication.TargetsKey]), &targets)
			var send []*replication.Rule
			for _, r := range cfg.Select(v.Name, decodeTags(v.UserDefined), replication.KindPut, false) {
				if so.arn != "" && so.arn != r.Destination {
					continue
				}
				cur := targets[r.Destination]
				switch {
				case cur == replication.StatusPending:
				case so.all && (cur != replication.StatusComplete || so.force):
				default:
					continue
				}
				targets[r.Destination] = replication.StatusPending
				send = append(send, r)
			}
			if len(send) == 0 {
				continue
			}
			if so.all {
				if err := e.s.setReplStatus(ctx, v, targets, false); err != nil {
					continue
				}
			}
			for _, r := range send {
				e.enqueue(replTask{Bucket: bucket, Key: v.Name, VersionID: v.VersionID, Op: opPut, ARN: r.Destination,
					Priority: r.Priority, Force: so.force})
				count(0, 1)
			}
		}
		if !page.IsTruncated {
			return
		}
		opts.Marker, opts.VersionIDMarker = page.NextMarker, page.NextVersionIDMarker
	}
}

// startResync begins a resync of bucket in the background (`mc replicate
// resync`): every version a rule selects that is not COMPLETE is marked
// PENDING and queued again, and every delete marker is re-sent; with force
// the COMPLETE ones too. Starting one while another runs returns the
// running one.
func (e *replEngine) startResync(bucket, arn string, force bool) *resyncState {
	e.mu.Lock()
	if old := e.resyncs[bucket]; old != nil {
		old.mu.Lock()
		running := old.running
		old.mu.Unlock()
		if running {
			e.mu.Unlock()
			return old
		}
	}
	st := &resyncState{Bucket: bucket, ARN: arn, Force: force, Started: time.Now().UTC(), running: true}
	e.resyncs[bucket] = st
	e.mu.Unlock()
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		defer func() {
			st.mu.Lock()
			st.running, st.finished = false, time.Now().UTC()
			st.mu.Unlock()
		}()
		ctx := context.Background()
		cfg, err := e.s.replicationConfig(ctx, bucket)
		if err != nil || cfg == nil {
			st.mu.Lock()
			st.err = "the bucket has no replication configuration"
			st.mu.Unlock()
			return
		}
		e.scanBucket(ctx, bucket, cfg, scanOpts{arn: arn, all: true, force: force}, st)
	}()
	return st
}

// ----- metrics ----------------------------------------------------------------------------------------

type replMetricsView struct {
	Bucket        string  `json:"bucket"`
	Target        string  `json:"target"`
	Queued        int     `json:"queued"`
	InFlight      int64   `json:"inFlight,omitempty"`
	Enqueued      uint64  `json:"enqueued"`
	Completed     uint64  `json:"completed"`
	Failed        uint64  `json:"failed"`
	Retried       uint64  `json:"retried"`
	Bytes         uint64  `json:"bytes"`
	AvgLatencyMs  float64 `json:"avgLatencyMs"`
	MaxLatencyMs  float64 `json:"maxLatencyMs"`
	PendingStatus *int64  `json:"pendingVersions,omitempty"`
}

func (s *Server) adminReplMetrics(q *request) {
	if q.r.Method != http.MethodGet {
		s.fail(q, errBadMethod)
		return
	}
	if !s.authorize(q, "nanoio:ListReplication", "", "", nil) {
		return
	}
	if s.repl == nil {
		s.fail(q, notImplemented("replication is not enabled"))
		return
	}
	bucket := q.query.Get("bucket")
	e := s.repl
	e.mu.Lock()
	keys := make([]string, 0, len(e.metrics))
	for k := range e.metrics {
		keys = append(keys, k)
	}
	queued := map[string]int{}
	for k, qu := range e.queues {
		i := strings.LastIndexByte(k, 0)
		queued[k[:i]] += qu.Len()
	}
	e.mu.Unlock()
	sort.Strings(keys)
	out := []replMetricsView{}
	for _, k := range keys {
		i := strings.IndexByte(k, 0)
		b, arn := k[:i], k[i+1:]
		if bucket != "" && b != bucket {
			continue
		}
		m := e.metric(b, arn)
		v := replMetricsView{Bucket: b, Target: arn, Queued: queued[b], Enqueued: m.enqueued.Load(), Completed: m.completed.Load(),
			Failed: m.failed.Load(), Retried: m.retried.Load(), Bytes: m.bytes.Load()}
		if n := m.latencyCount.Load(); n > 0 {
			v.AvgLatencyMs = float64(m.latencyNanos.Load()) / float64(n) / 1e6
		}
		v.MaxLatencyMs = float64(m.latencyMax.Load()) / 1e6
		out = append(out, v)
	}
	writeJSON(q.w, struct {
		Targets  []replMetricsView `json:"targets"`
		InFlight int64             `json:"inFlight"`
	}{out, e.inflight.Load()})
}

func (s *Server) adminReplResync(q *request) {
	if s.repl == nil {
		s.fail(q, notImplemented("replication is not enabled"))
		return
	}
	bucket := q.query.Get("bucket")
	switch q.r.Method {
	case http.MethodPost:
		if !s.authorize(q, "nanoio:ManageReplication", "", "", nil) {
			return
		}
		cfg, err := s.replicationConfig(q.ctx(), bucket)
		if err != nil {
			s.fail(q, err)
			return
		}
		if cfg == nil {
			s.fail(q, errNoSuchReplication)
			return
		}
		st := s.repl.startResync(bucket, q.query.Get("arn"), q.query.Get("force") == "true")
		q.w.Header().Set("Content-Type", "application/json")
		q.w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(q.w).Encode(st.view())
	case http.MethodGet:
		if !s.authorize(q, "nanoio:ListReplication", "", "", nil) {
			return
		}
		s.repl.mu.Lock()
		st := s.repl.resyncs[bucket]
		s.repl.mu.Unlock()
		if st == nil {
			s.fail(q, &APIError{"NoSuchResync", "No resync was started for this bucket on this node.", http.StatusNotFound})
			return
		}
		writeJSON(q.w, st.view())
	default:
		s.fail(q, errBadMethod)
	}
}
