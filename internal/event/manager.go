package event

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// ConfigSource returns a bucket's parsed notification configuration, or nil
// when it has none. It is called from the dispatcher goroutine, never from a
// request, so it may do storage I/O (it is expected to cache).
type ConfigSource func(ctx context.Context, bucket string) (*Config, error)

// Options configures a Manager.
type Options struct {
	// Dir holds the replay log and the targets' queues. Empty keeps
	// everything in memory only: no replay, and no targets may be added.
	Dir    string
	Region string
	Logger *slog.Logger
	// ReplayBytes bounds the replay log: 0 selects DefaultReplayBytes and a
	// negative value disables it.
	ReplayBytes int64
	// SegmentBytes is the queue segment size (default 4 MiB); tests shrink
	// it to exercise rotation.
	SegmentBytes int64
	// DispatchBuffer is the bus buffer of the dispatcher (default 16384).
	DispatchBuffer int
	// DrainTimeout bounds how long Close waits for already-published
	// events to be written to the queues (default 10s). Events still in
	// flight after it are lost; this only happens when the configuration
	// source is hung.
	DrainTimeout time.Duration
}

var idPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// Manager owns the bus, the replay log and the delivery pipeline.
type Manager struct {
	opts Options
	log  *slog.Logger
	bus  *Bus

	replay    *ReplayLog
	replaySub *Subscription
	replayed  atomic.Uint64 // highest seq the replay writer has handled
	replayAt  atomic.Int64  // unix nano of its last progress

	dispatchSub *Subscription

	mu      sync.RWMutex
	runners map[string]*runner // by canonical ARN
	order   []string

	src     atomic.Pointer[ConfigSource]
	started bool
	pipeWG  sync.WaitGroup // dispatcher and replay writer
	runWG   sync.WaitGroup // target workers
	ctx     context.Context
	cancel  context.CancelFunc

	listeners    atomic.Int64
	shared       SharedStore
	nodeID       string
	configErrors atomic.Uint64
	unmatched    atomic.Uint64 // events matched to an ARN no target serves
	closeOnce    sync.Once
	closeErr     error
}

// NewManager opens the replay log (if enabled) and the bus.
func NewManager(o Options) (*Manager, error) {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.DispatchBuffer <= 0 {
		o.DispatchBuffer = 16384
	}
	if o.DrainTimeout <= 0 {
		o.DrainTimeout = 10 * time.Second
	}
	m := &Manager{opts: o, log: o.Logger, runners: map[string]*runner{}}
	m.ctx, m.cancel = context.WithCancel(context.Background())
	var start uint64
	if o.Dir != "" && o.ReplayBytes >= 0 {
		r, err := OpenReplayLog(filepath.Join(o.Dir, "replay"), o.ReplayBytes)
		if err != nil {
			return nil, fmt.Errorf("event: replay log: %w", err)
		}
		m.replay = r
		start = r.LastSeq()
	}
	m.bus = NewBus(start)
	// Subscribe now, so events published before Start are buffered rather
	// than lost.
	m.dispatchSub = m.bus.Subscribe(o.DispatchBuffer, nil)
	if m.replay != nil {
		m.replaySub = m.bus.Subscribe(o.DispatchBuffer, nil)
	}
	return m, nil
}

// SetShared turns on queue replication: every target's events are written to
// store as soon as they are on this node's disk, and the target is delivered
// from the shared copy by whichever node holds its lease. nodeID names this
// node in shared object names. It must be called before Start.
func (m *Manager) SetShared(store SharedStore, nodeID string) {
	if m.started {
		return
	}
	m.shared, m.nodeID = store, nodeID
}

// Bus returns the manager's bus, for publishers and extra subscribers.
func (m *Manager) Bus() *Bus { return m.bus }

// Publish offers an event to the pipeline. It never blocks or fails.
func (m *Manager) Publish(e *Event) { m.bus.Publish(e) }

// Listeners is the number of streams currently attached.
func (m *Manager) Listeners() int { return int(m.listeners.Load()) }

// ReplayEnabled reports whether Stream can resume from a sequence number.
func (m *Manager) ReplayEnabled() bool { return m.replay != nil }

// AddTarget registers a target of type typ with the given ID. It must be
// called before Start. It returns the target's ARN.
func (m *Manager) AddTarget(typ, id string, spec Spec) (string, error) {
	if m.started {
		return "", errors.New("event: AddTarget after Start")
	}
	if !idPattern.MatchString(typ) || !idPattern.MatchString(id) {
		return "", fmt.Errorf("event: invalid target type/id %q/%q", typ, id)
	}
	if m.opts.Dir == "" {
		return "", errors.New("event: targets need a queue directory")
	}
	if err := spec.Delivery.Validate(); err != nil {
		return "", err
	}
	arn := ARN(m.opts.Region, id, typ)
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, dup := m.runners[arn]; dup {
		return "", fmt.Errorf("event: duplicate target %s", arn)
	}
	d := spec.Delivery
	base := filepath.Join(m.opts.Dir, "targets", typ+"-"+id)
	q, err := OpenQueue(filepath.Join(base, "queue"), d.QueueLimit, m.opts.SegmentBytes)
	if err != nil {
		return "", fmt.Errorf("event: %s queue: %w", arn, err)
	}
	dead, err := OpenQueue(filepath.Join(base, "dead"), d.DeadLetterLimit, m.opts.SegmentBytes)
	if err != nil {
		q.Close()
		return "", fmt.Errorf("event: %s dead-letter queue: %w", arn, err)
	}
	r := &runner{m: m, arn: arn, typ: typ, id: id, t: spec.Target, d: d, q: q,
		kick: make(chan struct{}, 1), shipKick: make(chan struct{}, 1), src: q, dead: dead, localDead: dead,
		key: typ + "-" + id, done: make(chan struct{}), log: m.log.With("target", arn)}
	m.runners[arn] = r
	m.order = append(m.order, arn)
	sort.Strings(m.order)
	return arn, nil
}

// Resolve canonicalises an ARN from a configuration and reports whether a
// target serves it. An empty region means "the server's region".
func (m *Manager) Resolve(arn string) (string, bool) {
	region, id, typ, ok := ParseARN(arn)
	if !ok || (region != "" && region != m.opts.Region) {
		return "", false
	}
	canon := ARN(m.opts.Region, id, typ)
	m.mu.RLock()
	_, ok = m.runners[canon]
	m.mu.RUnlock()
	return canon, ok
}

// Start begins dispatching and delivering. src resolves bucket
// configurations.
func (m *Manager) Start(src ConfigSource) {
	if m.started {
		return
	}
	m.started = true
	m.src.Store(&src)
	m.pipeWG.Add(1)
	go m.dispatch()
	if m.replay != nil {
		m.pipeWG.Add(1)
		go m.writeReplay()
	}
	m.mu.RLock()
	for _, r := range m.runners {
		if m.shared != nil {
			r.enableShared(m.ctx, m.shared, m.nodeID)
		}
		m.runWG.Add(1)
		go func(r *runner) {
			defer m.runWG.Done()
			r.run()
		}(r)
	}
	m.mu.RUnlock()
}

// dispatch moves events from the bus onto the durable queue of every target
// their bucket's configuration selects. It is the single goroutine that
// appends to the queues, so each queue receives events in sequence order:
// that is what makes delivery ordered per object.
func (m *Manager) dispatch() {
	defer m.pipeWG.Done()
	touched := map[*runner]struct{}{}
	flush := func() {
		for r := range touched {
			r.flushAppends()
			delete(touched, r)
		}
	}
	for {
		e, ok := <-m.dispatchSub.C()
		if !ok {
			flush()
			return
		}
		m.route(e, touched)
	drain:
		for {
			select {
			case e, ok := <-m.dispatchSub.C():
				if !ok {
					flush()
					return
				}
				m.route(e, touched)
			default:
				break drain
			}
		}
		flush()
	}
}

func (m *Manager) route(e *Event, touched map[*runner]struct{}) {
	src := m.src.Load()
	if src == nil || *src == nil {
		return
	}
	cfg, err := m.loadConfig(*src, e.Bucket)
	if err != nil {
		m.configErrors.Add(1)
		m.log.Warn("notification: cannot read bucket configuration; event not routed",
			"bucket", e.Bucket, "key", e.Key, "event", e.Name, "err", err)
		return
	}
	arns := cfg.Match(e.Name, e.Key, e.Tags)
	if len(arns) == 0 {
		return
	}
	body, err := json.Marshal(e)
	if err != nil {
		return
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, arn := range arns {
		r := m.runners[arn]
		if r == nil {
			m.unmatched.Add(1)
			continue
		}
		if r.enqueue(body) {
			touched[r] = struct{}{}
		}
	}
}

func (m *Manager) loadConfig(src ConfigSource, bucket string) (*Config, error) {
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(time.Duration(attempt) * 100 * time.Millisecond):
			case <-m.ctx.Done():
				return nil, m.ctx.Err()
			}
		}
		ctx, cancel := context.WithTimeout(m.ctx, 3*time.Second)
		var cfg *Config
		cfg, err = src(ctx, bucket)
		cancel()
		if err == nil {
			return cfg, nil
		}
	}
	return nil, err
}

func (m *Manager) writeReplay() {
	defer m.pipeWG.Done()
	n := 0
	sync := func() {
		if n > 0 {
			if err := m.replay.Sync(); err != nil {
				m.log.Warn("notification: replay log sync failed", "err", err)
			}
			n = 0
		}
	}
	for {
		e, ok := <-m.replaySub.C()
		if !ok {
			sync()
			return
		}
		for {
			if err := m.replay.Append(e); err != nil {
				m.log.Warn("notification: replay log append failed", "err", err)
			}
			n++
			m.replayed.Store(e.Seq)
			if n >= 256 {
				sync()
			}
			select {
			case e, ok = <-m.replaySub.C():
				if !ok {
					sync()
					return
				}
				continue
			default:
			}
			break
		}
		sync()
		m.replayAt.Store(time.Now().UnixNano())
	}
}

// StreamItem is one element of a stream: an event, or a notice that the
// consumer was too slow and Dropped events were skipped after the last one
// delivered.
type StreamItem struct {
	Event   *Event
	Dropped uint64
}

// StreamOptions selects a stream.
type StreamOptions struct {
	// Since asks for retained events with a sequence number greater than
	// this before live ones; Replay must be set for it to apply.
	Since  uint64
	Replay bool
	Filter func(*Event) bool
	Buffer int
}

// Stream sends matching events to send until ctx ends or send fails: first
// the retained history when asked, then live events, without gaps or repeats
// between the two. It returns ErrReplayDisabled if history is asked for and
// not kept.
func (m *Manager) Stream(ctx context.Context, o StreamOptions, send func(StreamItem) error) error {
	if o.Replay && m.replay == nil {
		return ErrReplayDisabled
	}
	m.listeners.Add(1)
	defer m.listeners.Add(-1)
	// Subscribe first so nothing published during the replay is missed.
	sub := m.bus.Subscribe(o.Buffer, o.Filter)
	defer sub.Close()
	var last uint64
	if o.Replay {
		m.waitReplayCaughtUp(ctx)
		var sendErr error
		err := m.replay.Read(o.Since, func(e *Event) bool {
			if ctx.Err() != nil {
				return false
			}
			if o.Filter != nil && !o.Filter(e) {
				return true
			}
			if sendErr = send(StreamItem{Event: e}); sendErr != nil {
				return false
			}
			last = e.Seq
			return true
		})
		if sendErr != nil {
			return sendErr
		}
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	var reported uint64
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e, ok := <-sub.C():
			if !ok {
				return nil
			}
			if e.Seq <= last {
				continue
			}
			if d := sub.Dropped(); d != reported {
				if err := send(StreamItem{Dropped: d - reported}); err != nil {
					return err
				}
				reported = d
			}
			if err := send(StreamItem{Event: e}); err != nil {
				return err
			}
		}
	}
}

// ErrReplayDisabled is returned by Stream when history is requested but no
// replay log is kept.
var ErrReplayDisabled = errReplayDisabled

// waitReplayCaughtUp blocks (briefly) until the replay writer has handled
// everything published before the call, so a stream's history includes it.
func (m *Manager) waitReplayCaughtUp(ctx context.Context) {
	target := m.bus.Seq()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		if m.replayed.Load() >= target {
			return
		}
		if m.replaySub.Pending() == 0 && time.Since(time.Unix(0, m.replayAt.Load())) > 50*time.Millisecond {
			return // idle: what is missing was dropped, not pending
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// ManagerStats are pipeline-wide counters.
type ManagerStats struct {
	Published      uint64 `json:"published"`
	LastSeq        uint64 `json:"lastSeq"`
	DispatchDrops  uint64 `json:"dispatchDropped"`
	ReplayDrops    uint64 `json:"replayDropped"`
	ConfigErrors   uint64 `json:"configErrors"`
	UnknownTargets uint64 `json:"unknownTargetMatches"`
	ReplayBytes    int64  `json:"replayBytes"`
	ReplayOldest   uint64 `json:"replayOldestSeq"`
	ReplayEnabled  bool   `json:"replayEnabled"`
}

// Stats returns pipeline-wide counters.
func (m *Manager) Stats() ManagerStats {
	s := ManagerStats{Published: m.bus.Published(), LastSeq: m.bus.Seq(),
		ConfigErrors: m.configErrors.Load(), UnknownTargets: m.unmatched.Load(), ReplayEnabled: m.replay != nil}
	if m.dispatchSub != nil {
		s.DispatchDrops = m.dispatchSub.Dropped()
	}
	if m.replaySub != nil {
		s.ReplayDrops = m.replaySub.Dropped()
	}
	if m.replay != nil {
		s.ReplayBytes = m.replay.Size()
		s.ReplayOldest = m.replay.OldestSeq()
	}
	return s
}

// TargetStatus reports one target's health and counters.
type TargetStatus struct {
	ARN  string `json:"arn"`
	Type string `json:"type"`
	ID   string `json:"id"`
	// Online is the result of a live probe when the target supports one and
	// one was requested; otherwise it reflects the outcome of the last send
	// (true before any send). Checked says which.
	Online     bool   `json:"online"`
	Checked    bool   `json:"checked"`
	CheckError string `json:"checkError,omitempty"`

	QueueLength      int    `json:"queueLength"`
	QueueBytes       int64  `json:"queueBytes"`
	DeadLetterLength int    `json:"deadLetterLength"`
	Delivered        uint64 `json:"delivered"`
	SendFailures     uint64 `json:"sendFailures"`
	Retries          uint64 `json:"retries"`
	DeadLettered     uint64 `json:"deadLettered"`
	Dropped          uint64 `json:"dropped"`
	Corrupt          uint64 `json:"corrupt"`

	ConsecutiveFailures int        `json:"consecutiveFailures"`
	LastSuccess         *time.Time `json:"lastSuccess,omitempty"`
	LastFailure         *time.Time `json:"lastFailure,omitempty"`
	LastError           string     `json:"lastError,omitempty"`

	// Replication (cluster queues). In this mode QueueLength is the tail
	// not yet written to the shared store, SharedPending the (capped at
	// 1000 objects) shared batches waiting for delivery.
	Replicated    bool   `json:"replicated"`
	Leader        bool   `json:"leader"`
	SharedPending int    `json:"sharedPending,omitempty"`
	Shipped       uint64 `json:"shipped,omitempty"`
	ShipFailures  uint64 `json:"shipFailures,omitempty"`
	LastShipError string `json:"lastShipError,omitempty"`
}

// Status lists every target. With probe set, targets that implement Checker
// are asked whether their destination is reachable now (concurrently,
// bounded by ctx).
func (m *Manager) Status(ctx context.Context, probe bool) []TargetStatus {
	m.mu.RLock()
	rs := make([]*runner, 0, len(m.order))
	for _, arn := range m.order {
		rs = append(rs, m.runners[arn])
	}
	m.mu.RUnlock()
	out := make([]TargetStatus, len(rs))
	var wg sync.WaitGroup
	for i, r := range rs {
		out[i] = r.status()
		if !probe {
			continue
		}
		c, ok := r.t.(Checker)
		if !ok {
			continue
		}
		wg.Add(1)
		go func(i int, c Checker) {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			out[i].Checked = true
			if err := c.Check(cctx); err != nil {
				out[i].Online, out[i].CheckError = false, err.Error()
			} else {
				out[i].Online = true
			}
		}(i, c)
	}
	wg.Wait()
	return out
}

// DeadLetter is one event a target gave up on.
type DeadLetter struct {
	Time     time.Time       `json:"time"`
	Attempts int             `json:"attempts"`
	Error    string          `json:"error"`
	Event    json.RawMessage `json:"event"`
}

// DeadLetters returns up to max of a target's oldest dead-lettered events.
func (m *Manager) DeadLetters(arn string, max int) ([]DeadLetter, error) {
	r := m.runner(arn)
	if r == nil {
		return nil, ErrNoSuchTarget
	}
	items, err := r.dead.Peek(max)
	out := make([]DeadLetter, 0, len(items))
	for _, it := range items {
		var d DeadLetter
		if json.Unmarshal(it.Data, &d) == nil {
			out = append(out, d)
		}
	}
	return out, err
}

// ErrNoSuchTarget is returned for an ARN no target serves.
var ErrNoSuchTarget = errors.New("event: no such notification target")

// Requeue moves a target's dead-lettered events back onto its queue (at the
// tail: they are delivered after events queued since, so per-object order
// across a requeue is not preserved). It returns how many moved.
func (m *Manager) Requeue(arn string) (int, error) {
	r := m.runner(arn)
	if r == nil {
		return 0, ErrNoSuchTarget
	}
	return r.requeue()
}

func (m *Manager) runner(arn string) *runner {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.runners[arn]
}

// Close stops accepting events, writes everything already published to the
// durable queues, stops the workers (undelivered events stay queued for the
// next start) and closes the targets.
func (m *Manager) Close() error {
	m.closeOnce.Do(func() {
		// 1. No new events; the dispatcher and replay writer drain what
		//    was already published onto the durable queues and exit.
		m.bus.Close()
		drained := make(chan struct{})
		go func() { m.pipeWG.Wait(); close(drained) }()
		select {
		case <-drained:
		case <-time.After(m.opts.DrainTimeout):
			m.log.Warn("notification: shutdown could not drain published events in time; some may be lost",
				"timeout", m.opts.DrainTimeout)
			m.cancel()
			<-drained
		}
		// 2. Stop the workers. Undelivered events stay queued on disk.
		m.mu.RLock()
		for _, r := range m.runners {
			close(r.stopOnce())
		}
		m.mu.RUnlock()
		m.cancel()
		m.runWG.Wait()
		// 3. Close queues and targets.
		var errs []error
		m.mu.RLock()
		for _, r := range m.runners {
			errs = append(errs, r.close())
		}
		m.mu.RUnlock()
		if m.replay != nil {
			errs = append(errs, m.replay.Close())
		}
		m.closeErr = errors.Join(errs...)
	})
	return m.closeErr
}

// ----- per-target worker ----------------------------------------------

type runner struct {
	m   *Manager
	arn string
	typ string
	id  string
	t   Target
	d   Delivery
	q   *Queue // local landing queue; in replicated mode only the not-yet-shipped tail
	// src is where the delivery worker reads from: q, or the shared feed.
	src  feed
	dead deadStore
	// localDead is the node-local dead-letter queue (kept so entries from
	// before replication was enabled can be migrated).
	localDead             *Queue
	shared                SharedStore
	node                  string
	key                   string
	shipKick              chan struct{}
	leader                atomic.Bool
	shipped, shipFailures atomic.Uint64
	lastShipErr           atomic.Value // string
	log                   *slog.Logger
	kick                  chan struct{}
	done                  chan struct{}

	stopMu sync.Mutex
	stop   chan struct{}

	delivered, sendFailures, retries, deadLettered, dropped, corrupt atomic.Uint64

	mu          sync.Mutex
	lastOK      time.Time
	lastFail    time.Time
	lastErr     string
	consecutive int
	dropLogged  time.Time
}

// stopOnce lazily creates and returns the stop channel; closing it (once,
// by Manager.Close) tells the worker to exit.
func (r *runner) stopOnce() chan struct{} {
	r.stopMu.Lock()
	defer r.stopMu.Unlock()
	if r.stop == nil {
		r.stop = make(chan struct{})
	}
	return r.stop
}

// enqueue appends an event body to the target's queue; the caller flushes.
func (r *runner) enqueue(body []byte) bool {
	err := r.q.Append(body)
	switch {
	case err == nil:
		return true
	case errors.Is(err, ErrQueueFull):
		r.dropped.Add(1)
		r.mu.Lock()
		if time.Since(r.dropLogged) > 30*time.Second {
			r.dropLogged = time.Now()
			r.log.Warn("notification queue is full; dropping new events", "limit", r.d.QueueLimit)
		}
		r.mu.Unlock()
	default:
		r.dropped.Add(1)
		r.log.Error("notification queue write failed; event dropped", "err", err)
	}
	return false
}

func (r *runner) flushAppends() {
	if err := r.q.Sync(); err != nil {
		r.log.Error("notification queue sync failed", "err", err)
	}
	select {
	case r.kick <- struct{}{}:
	default:
	}
	select {
	case r.shipKick <- struct{}{}:
	default:
	}
}

// run is the worker. Locally it just delivers from the node's queue. When
// replicated it also ships the local tail to the shared store, and delivers
// only while it holds the target's cluster-wide lease, so exactly one node
// sends from the shared queue at a time and order is preserved.
func (r *runner) run() {
	defer close(r.done)
	stop := r.stopOnce()
	if r.shared == nil {
		r.deliver(stop)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-stop:
			cancel()
		case <-ctx.Done():
		}
	}()
	r.m.runWG.Add(1)
	go func() {
		defer r.m.runWG.Done()
		r.ship(ctx, stop)
	}()
	for {
		release, err := r.shared.Lead(ctx, r.key)
		if err != nil {
			select {
			case <-stop:
				return
			default:
			}
			if !r.sleep(stop, time.Second) {
				return
			}
			continue
		}
		r.leader.Store(true)
		r.log.Info("this node now delivers the replicated queue")
		r.deliver(stop)
		r.leader.Store(false)
		release()
		return
	}
}

func (r *runner) deliver(stop <-chan struct{}) {
	attempts := 0
	isolate := false
	for {
		n := r.d.BatchSize
		if isolate {
			n = 1
		}
		items, err := r.src.Peek(n)
		if err != nil {
			r.log.Error("notification queue read failed", "err", err)
			if !r.sleep(stop, r.d.RetryMax.D()) {
				return
			}
			continue
		}
		if len(items) == 0 {
			var poll <-chan time.Time
			if r.shared != nil {
				// Another node ships into the shared queue without
				// kicking us.
				t := time.NewTimer(500 * time.Millisecond)
				defer t.Stop()
				poll = t.C
			}
			select {
			case <-r.kick:
			case <-poll:
			case <-stop:
				return
			}
			continue
		}
		events := make([]*Event, 0, len(items))
		good := make([]Item, 0, len(items))
		for _, it := range items {
			var e Event
			if json.Unmarshal(it.Data, &e) != nil {
				r.corrupt.Add(1)
				continue
			}
			events = append(events, &e)
			good = append(good, it)
		}
		if len(events) == 0 {
			r.src.Ack(items)
			continue
		}
		err = r.send(events)
		if err == nil {
			r.noteSuccess(len(events))
			if err := r.src.Ack(items); err != nil {
				r.log.Error("notification queue ack failed", "err", err)
			}
			attempts, isolate = 0, false
			continue
		}
		r.noteFailure(err)
		attempts++
		if r.d.MaxAttempts < 0 || attempts < r.d.MaxAttempts {
			r.retries.Add(1)
			if !r.sleep(stop, r.backoff(attempts)) {
				return
			}
			continue
		}
		if len(items) > 1 {
			// Give each event its own attempts, in order, so one bad event
			// cannot take its batch-mates with it.
			r.log.Warn("notification batch failed; delivering its events one at a time",
				"events", len(items), "attempts", attempts, "err", err)
			isolate, attempts = true, 0
			continue
		}
		r.deadLetter(items[0], err, attempts)
		attempts, isolate = 0, false
	}
}

// send runs Target.Send under the per-attempt timeout and converts a panic
// in a target into an error.
func (r *runner) send(events []*Event) (err error) {
	ctx, cancel := context.WithTimeout(r.m.ctx, r.d.Timeout.D())
	defer cancel()
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("target panicked: %v", p)
		}
	}()
	return r.t.Send(ctx, events)
}

func (r *runner) sleep(stop <-chan struct{}, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-stop:
		return false
	}
}

func (r *runner) backoff(attempt int) time.Duration {
	d := r.d.RetryBase.D()
	for i := 1; i < attempt && d < r.d.RetryMax.D(); i++ {
		d *= 2
	}
	if d > r.d.RetryMax.D() {
		d = r.d.RetryMax.D()
	}
	// +-20% jitter so a fleet of queues does not retry in lockstep.
	return time.Duration(float64(d) * (0.8 + 0.4*rand.Float64()))
}

func (r *runner) noteSuccess(n int) {
	r.delivered.Add(uint64(n))
	r.mu.Lock()
	r.lastOK = time.Now()
	r.consecutive = 0
	r.mu.Unlock()
}

func (r *runner) noteFailure(err error) {
	r.sendFailures.Add(1)
	r.mu.Lock()
	r.lastFail = time.Now()
	r.lastErr = err.Error()
	r.consecutive++
	c := r.consecutive
	r.mu.Unlock()
	if c == 1 || c%10 == 0 {
		r.log.Warn("notification delivery failed", "consecutiveFailures", c, "err", err)
	}
}

func (r *runner) deadLetter(it Item, cause error, attempts int) {
	body, _ := json.Marshal(DeadLetter{Time: time.Now().UTC(), Attempts: attempts, Error: cause.Error(), Event: it.Data})
	if _, err := r.dead.AppendEvicting(body); err != nil {
		r.log.Error("cannot dead-letter an event; keeping it queued", "err", err)
		return
	}
	r.dead.Sync()
	r.deadLettered.Add(1)
	r.log.Error("notification dead-lettered after repeated failures", "attempts", attempts, "err", cause)
	if err := r.src.Ack([]Item{it}); err != nil {
		r.log.Error("notification queue ack failed", "err", err)
	}
}

func (r *runner) requeue() (int, error) {
	moved := 0
	for {
		items, err := r.dead.Peek(256)
		if err != nil || len(items) == 0 {
			return moved, err
		}
		done := 0
		for _, it := range items {
			var d DeadLetter
			if json.Unmarshal(it.Data, &d) != nil {
				done++
				continue
			}
			if err := r.q.Append(d.Event); err != nil {
				break
			}
			done++
			moved++
		}
		r.q.Sync()
		r.dead.Ack(items[:done])
		select {
		case r.kick <- struct{}{}:
		default:
		}
		if done < len(items) {
			return moved, ErrQueueFull
		}
	}
}

func (r *runner) status() TargetStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := TargetStatus{
		ARN: r.arn, Type: r.typ, ID: r.id,
		Online:      r.consecutive == 0,
		QueueLength: r.q.Len(), QueueBytes: r.q.Bytes(), DeadLetterLength: r.dead.Len(),
		Replicated: r.shared != nil, Leader: r.leader.Load(), Shipped: r.shipped.Load(), ShipFailures: r.shipFailures.Load(),
		Delivered: r.delivered.Load(), SendFailures: r.sendFailures.Load(), Retries: r.retries.Load(),
		DeadLettered: r.deadLettered.Load(), Dropped: r.dropped.Load(),
		Corrupt:             r.corrupt.Load() + r.q.Corrupt(),
		ConsecutiveFailures: r.consecutive, LastError: r.lastErr,
	}
	if e, ok := r.lastShipErr.Load().(string); ok {
		st.LastShipError = e
	}
	if r.shared != nil {
		st.SharedPending = r.sharedPending()
	}
	if !r.lastOK.IsZero() {
		t := r.lastOK
		st.LastSuccess = &t
	}
	if !r.lastFail.IsZero() {
		t := r.lastFail
		st.LastFailure = &t
	}
	return st
}

func (r *runner) close() error {
	// The worker has exited (Manager.Close waited for it); an unstarted
	// runner has no worker to wait for.
	var errs []error
	if err := r.t.Close(); err != nil {
		errs = append(errs, err)
	}
	errs = append(errs, r.q.Close(), r.localDead.Close())
	return errors.Join(errs...)
}
