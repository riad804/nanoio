package batch

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sort"
	"strings"
	"sync"
	"time"
)

// Store is where job state lives, visible to every node.
type Store interface {
	Put(ctx context.Context, name string, data []byte) error
	// Get returns ErrNotFound for a missing name.
	Get(ctx context.Context, name string) ([]byte, error)
	Delete(ctx context.Context, name string) error
	// List returns up to max names with the prefix, ascending.
	List(ctx context.Context, prefix string, max int) ([]string, error)
}

// ErrNotFound is returned by Store.Get and for an unknown job.
var ErrNotFound = errors.New("batch: not found")

// Locker gives cluster-wide mutual exclusion without waiting.
type Locker interface {
	// TryLock returns ok=false (and no error) if another holder has the
	// lock. The lock lives until unlock is called or its holder dies.
	TryLock(ctx context.Context, name string) (unlock func(), ok bool, err error)
}

// Clock supplies "now" to filters and bookkeeping.
type Clock interface{ Now() time.Time }

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// Item is one unit of work: an object (version).
type Item struct {
	Bucket    string `json:"bucket"`
	Key       string `json:"key"`
	VersionID string `json:"versionId,omitempty"`
	Size      int64  `json:"size,omitempty"`
}

// ItemResult is what doing one item reports.
type ItemResult struct {
	Bytes int64
	// Skipped means nothing needed doing (already replicated, not
	// encrypted with the key being rotated, ...).
	Skipped bool
}

// Operation implements one job type against the server.
type Operation interface {
	// Enumerate returns the next page of at most max matching items after
	// cursor ("" starts) and the cursor to continue with ("" when done).
	// It must be deterministic for a given cursor: a coordinator that
	// takes over re-enumerates from the last committed cursor.
	Enumerate(ctx context.Context, def *Definition, cursor string, max int, now time.Time) (items []Item, next string, err error)
	// Do performs one item. It must be idempotent: tasks are at-least-once.
	Do(ctx context.Context, def *Definition, it Item) (ItemResult, error)
}

// Job states.
const (
	StateRunning   = "running"
	StateCompleted = "completed"
	StateFailed    = "failed"
	StateCanceled  = "canceled"
)

// Failure is one object a job could not process.
type Failure struct {
	Bucket    string `json:"bucket"`
	Key       string `json:"key"`
	VersionID string `json:"versionId,omitempty"`
	Error     string `json:"error"`
}

// Progress is a job's counters.
type Progress struct {
	Tasks      int       `json:"tasks"`
	TasksDone  int       `json:"tasksDone"`
	Enumerated bool      `json:"enumerated"`
	Succeeded  int64     `json:"succeeded"`
	Skipped    int64     `json:"skipped"`
	Failed     int64     `json:"failed"`
	Bytes      int64     `json:"bytes"`
	Failures   []Failure `json:"failures,omitempty"`
}

// Job is a job's record.
type Job struct {
	ID         string          `json:"id"`
	Type       string          `json:"type"`
	Definition json.RawMessage `json:"definition"`
	Owner      string          `json:"owner,omitempty"`
	State      string          `json:"state"`
	Error      string          `json:"error,omitempty"`
	Created    time.Time       `json:"created"`
	Finished   *time.Time      `json:"finished,omitempty"`
	// Final holds the counters once the job has finished and its task
	// bookkeeping was cleaned up.
	Final *Progress `json:"final,omitempty"`
}

// Status is a job with its live progress.
type Status struct {
	Job
	Progress Progress `json:"progress"`
}

type enumState struct {
	Cursor string `json:"cursor"`
	Tasks  int    `json:"tasks"`
	Done   bool   `json:"done"`
}

type task struct {
	Seq   int    `json:"seq"`
	Items []Item `json:"items"`
}

type taskResult struct {
	Seq       int       `json:"seq"`
	Succeeded int64     `json:"succeeded"`
	Skipped   int64     `json:"skipped"`
	Failed    int64     `json:"failed"`
	Bytes     int64     `json:"bytes"`
	Failures  []Failure `json:"failures,omitempty"`
	Node      string    `json:"node,omitempty"`
}

// Options configures a Manager.
type Options struct {
	Store  Store
	Locker Locker
	// Ops maps a job type to its implementation.
	Ops   map[string]Operation
	Clock Clock
	// Node identifies this node in task results.
	Node string
	// Workers is how many tasks this node runs at once (default 2).
	Workers int
	// TaskItems is the objects per task (default 200).
	TaskItems int
	// Tick is how often idle loops look for work (default 1s).
	Tick time.Duration
	Log  *slog.Logger
}

// Manager runs jobs on this node and gives the admin view of all of them.
type Manager struct {
	o Options

	mu    sync.Mutex
	coord map[string]bool // jobs this node coordinates
}

const maxFailuresKept = 50

// NewManager validates o.
func NewManager(o Options) (*Manager, error) {
	if o.Store == nil || o.Locker == nil || len(o.Ops) == 0 {
		return nil, errors.New("batch: Store, Locker and Ops are required")
	}
	if o.Clock == nil {
		o.Clock = realClock{}
	}
	if o.Workers <= 0 {
		o.Workers = 2
	}
	if o.TaskItems <= 0 {
		o.TaskItems = 200
	}
	if o.Tick <= 0 {
		o.Tick = time.Second
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	return &Manager{o: o, coord: map[string]bool{}}, nil
}

func jobKey(id, name string) string { return "_batch/" + id + "/" + name }

func newID() string {
	var b [8]byte
	cryptorand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (m *Manager) putJSON(ctx context.Context, name string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return m.o.Store.Put(ctx, name, b)
}

func (m *Manager) getJSON(ctx context.Context, name string, v any) error {
	b, err := m.o.Store.Get(ctx, name)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// Start records a job; any node's loops will pick it up.
func (m *Manager) Start(ctx context.Context, def *Definition, owner string) (string, error) {
	if _, ok := m.o.Ops[def.Type()]; !ok {
		return "", fmt.Errorf("job type %q is not available", def.Type())
	}
	raw, err := json.Marshal(def)
	if err != nil {
		return "", err
	}
	j := Job{ID: newID(), Type: def.Type(), Definition: raw, Owner: owner, State: StateRunning, Created: m.o.Clock.Now().UTC()}
	if err := m.putJSON(ctx, jobKey(j.ID, "enum.json"), enumState{}); err != nil {
		return "", err
	}
	if err := m.putJSON(ctx, jobKey(j.ID, "job.json"), j); err != nil {
		return "", err
	}
	return j.ID, nil
}

func (m *Manager) loadJob(ctx context.Context, id string) (*Job, error) {
	var j Job
	if err := m.getJSON(ctx, jobKey(id, "job.json"), &j); err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &j, nil
}

func (m *Manager) jobIDs(ctx context.Context) ([]string, error) {
	names, err := m.o.Store.List(ctx, "_batch/", 10000)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var ids []string
	for _, n := range names {
		rest := strings.TrimPrefix(n, "_batch/")
		if i := strings.IndexByte(rest, '/'); i > 0 {
			if id := rest[:i]; !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	return ids, nil
}

// Describe returns one job with its progress.
func (m *Manager) Describe(ctx context.Context, id string) (*Status, error) {
	j, err := m.loadJob(ctx, id)
	if err != nil {
		return nil, err
	}
	st := &Status{Job: *j}
	if j.Final != nil {
		st.Progress = *j.Final
		return st, nil
	}
	var e enumState
	m.getJSON(ctx, jobKey(id, "enum.json"), &e)
	st.Progress.Tasks, st.Progress.Enumerated = e.Tasks, e.Done
	names, err := m.o.Store.List(ctx, jobKey(id, "done/"), 100000)
	if err != nil {
		return nil, err
	}
	for _, n := range names {
		var r taskResult
		if m.getJSON(ctx, n, &r) != nil {
			continue
		}
		st.Progress.TasksDone++
		st.Progress.Succeeded += r.Succeeded
		st.Progress.Skipped += r.Skipped
		st.Progress.Failed += r.Failed
		st.Progress.Bytes += r.Bytes
		for _, f := range r.Failures {
			if len(st.Progress.Failures) < maxFailuresKept {
				st.Progress.Failures = append(st.Progress.Failures, f)
			}
		}
	}
	return st, nil
}

// List returns every job, newest first.
func (m *Manager) List(ctx context.Context) ([]Status, error) {
	ids, err := m.jobIDs(ctx)
	if err != nil {
		return nil, err
	}
	var out []Status
	for _, id := range ids {
		st, err := m.Describe(ctx, id)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		// Listings carry counters, not the failure samples.
		st.Progress.Failures = nil
		out = append(out, *st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return out, nil
}

// Cancel stops a running job: no new tasks start and the remaining ones are
// discarded. Work already done is not undone.
func (m *Manager) Cancel(ctx context.Context, id string) error {
	j, err := m.loadJob(ctx, id)
	if err != nil {
		return err
	}
	if j.State != StateRunning {
		return fmt.Errorf("job %s is already %s", id, j.State)
	}
	return m.o.Store.Put(ctx, jobKey(id, "cancel"), []byte("1"))
}

func (m *Manager) canceled(ctx context.Context, id string) bool {
	_, err := m.o.Store.Get(ctx, jobKey(id, "cancel"))
	return err == nil
}

// Run drives coordination and task execution on this node until ctx ends.
func (m *Manager) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for i := 0; i < m.o.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.workerLoop(ctx)
		}()
	}
	t := time.NewTicker(m.o.Tick)
	defer t.Stop()
	for {
		m.adopt(ctx, &wg)
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case <-t.C:
		}
	}
}

// adopt starts a coordinator goroutine for every running job this node can
// get the coordinator lock of.
func (m *Manager) adopt(ctx context.Context, wg *sync.WaitGroup) {
	ids, err := m.jobIDs(ctx)
	if err != nil {
		return
	}
	for _, id := range ids {
		m.mu.Lock()
		have := m.coord[id]
		m.mu.Unlock()
		if have {
			continue
		}
		j, err := m.loadJob(ctx, id)
		if err != nil || j.State != StateRunning {
			continue
		}
		unlock, ok, err := m.o.Locker.TryLock(ctx, jobKey(id, "coord"))
		if err != nil || !ok {
			continue
		}
		m.mu.Lock()
		m.coord[id] = true
		m.mu.Unlock()
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			defer unlock()
			defer func() {
				m.mu.Lock()
				delete(m.coord, id)
				m.mu.Unlock()
			}()
			m.coordinate(ctx, id)
		}(id)
	}
}

func (m *Manager) finish(ctx context.Context, j *Job, state, errMsg string) {
	// Aggregate the markers, store the totals in the job record and drop the
	// bookkeeping.
	st, err := m.Describe(ctx, j.ID)
	if err == nil {
		fin := st.Progress
		fin.Enumerated = true
		j.Final = &fin
	}
	now := m.o.Clock.Now().UTC()
	j.State, j.Error, j.Finished = state, errMsg, &now
	if err := m.putJSON(ctx, jobKey(j.ID, "job.json"), j); err != nil {
		m.o.Log.Warn("batch: cannot record the end of a job", "job", j.ID, "err", err)
		return
	}
	for _, prefix := range []string{"done/", "tasks/"} {
		names, _ := m.o.Store.List(ctx, jobKey(j.ID, prefix), 100000)
		for _, n := range names {
			m.o.Store.Delete(ctx, n)
		}
	}
	m.o.Log.Info("batch job finished", "job", j.ID, "type", j.Type, "state", state)
}

// coordinate enumerates a job's work into tasks, a bounded window ahead of
// the workers, and closes the job when every task is done.
func (m *Manager) coordinate(ctx context.Context, id string) {
	j, err := m.loadJob(ctx, id)
	if err != nil || j.State != StateRunning {
		return
	}
	var def Definition
	if err := json.Unmarshal(j.Definition, &def); err != nil {
		m.finish(ctx, j, StateFailed, "stored definition is unreadable: "+err.Error())
		return
	}
	op := m.o.Ops[j.Type]
	if op == nil {
		m.finish(ctx, j, StateFailed, "this server cannot run "+j.Type+" jobs")
		return
	}
	failures := 0
	for ctx.Err() == nil {
		if m.canceled(ctx, id) {
			m.finish(ctx, j, StateCanceled, "")
			return
		}
		var e enumState
		if err := m.getJSON(ctx, jobKey(id, "enum.json"), &e); err != nil && !errors.Is(err, ErrNotFound) {
			time.Sleep(m.o.Tick)
			continue
		}
		pending, err := m.o.Store.List(ctx, jobKey(id, "tasks/"), 100)
		if err != nil {
			time.Sleep(m.o.Tick)
			continue
		}
		switch {
		case !e.Done && len(pending) < 32:
			items, next, err := op.Enumerate(ctx, &def, e.Cursor, m.o.TaskItems, m.o.Clock.Now())
			if err != nil {
				failures++
				if failures >= 5 {
					m.finish(ctx, j, StateFailed, "listing failed: "+err.Error())
					return
				}
				m.sleep(ctx, time.Duration(failures)*m.o.Tick)
				continue
			}
			failures = 0
			if len(items) > 0 {
				t := task{Seq: e.Tasks, Items: items}
				if err := m.putJSON(ctx, jobKey(id, fmt.Sprintf("tasks/%08d.json", t.Seq)), t); err != nil {
					m.sleep(ctx, m.o.Tick)
					continue
				}
				e.Tasks++
			}
			e.Cursor, e.Done = next, next == ""
			if err := m.putJSON(ctx, jobKey(id, "enum.json"), e); err != nil {
				m.sleep(ctx, m.o.Tick)
			}
		case e.Done && len(pending) == 0:
			st, _ := m.Describe(ctx, id)
			if st != nil && st.Progress.TasksDone >= e.Tasks {
				m.finish(ctx, j, StateCompleted, "")
				return
			}
			m.sleep(ctx, m.o.Tick/2)
		default:
			m.sleep(ctx, m.o.Tick/2)
		}
	}
}

func (m *Manager) sleep(ctx context.Context, d time.Duration) {
	if d <= 0 {
		d = time.Millisecond
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// workerLoop claims and runs tasks of any running job.
func (m *Manager) workerLoop(ctx context.Context) {
	for ctx.Err() == nil {
		if !m.workOnce(ctx) {
			m.sleep(ctx, m.o.Tick/2)
		}
	}
}

func (m *Manager) workOnce(ctx context.Context) bool {
	ids, err := m.jobIDs(ctx)
	if err != nil {
		return false
	}
	rand.Shuffle(len(ids), func(i, j int) { ids[i], ids[j] = ids[j], ids[i] })
	for _, id := range ids {
		j, err := m.loadJob(ctx, id)
		if err != nil || j.State != StateRunning {
			continue
		}
		var def Definition
		if json.Unmarshal(j.Definition, &def) != nil {
			continue
		}
		op := m.o.Ops[j.Type]
		if op == nil {
			continue
		}
		names, err := m.o.Store.List(ctx, jobKey(id, "tasks/"), 32)
		if err != nil || len(names) == 0 {
			continue
		}
		for _, n := range names {
			seq := strings.TrimSuffix(n[strings.LastIndexByte(n, '/')+1:], ".json")
			releaseSlot, ok := m.claimSlot(ctx, id, def.Common().Concurrency)
			if !ok {
				break // the job is at its concurrency limit
			}
			releaseTask, ok, _ := m.o.Locker.TryLock(ctx, jobKey(id, "task/"+seq))
			if !ok {
				releaseSlot()
				continue
			}
			did := m.runTask(ctx, id, n, op, &def)
			releaseTask()
			releaseSlot()
			if did {
				return true
			}
		}
	}
	return false
}

// claimSlot takes one of the job's concurrency slots, cluster-wide.
func (m *Manager) claimSlot(ctx context.Context, id string, n int) (func(), bool) {
	order := rand.Perm(n)
	for _, s := range order {
		unlock, ok, err := m.o.Locker.TryLock(ctx, jobKey(id, fmt.Sprintf("slot/%d", s)))
		if err == nil && ok {
			return unlock, true
		}
	}
	return nil, false
}

// runTask executes one task and records its result. It reports whether it
// did any work.
func (m *Manager) runTask(ctx context.Context, id, name string, op Operation, def *Definition) bool {
	var t task
	if err := m.getJSON(ctx, name, &t); err != nil {
		return false // finished by someone else meanwhile
	}
	doneName := jobKey(id, fmt.Sprintf("done/%08d.json", t.Seq))
	if _, err := m.o.Store.Get(ctx, doneName); err == nil {
		m.o.Store.Delete(ctx, name) // finished, only the cleanup was missed
		return true
	}
	res := taskResult{Seq: t.Seq, Node: m.o.Node}
	retry := def.Common().Retry
	for i, it := range t.Items {
		if ctx.Err() != nil {
			return true // leave the task; another claim redoes it
		}
		if i%10 == 0 && m.canceled(ctx, id) {
			return true
		}
		var r ItemResult
		var err error
		delay := retry.Delay.D()
		for attempt := 1; ; attempt++ {
			r, err = op.Do(ctx, def, it)
			if err == nil || attempt >= retry.Attempts || ctx.Err() != nil {
				break
			}
			m.sleep(ctx, delay)
			if delay < 30*time.Second {
				delay *= 2
			}
		}
		switch {
		case err != nil:
			res.Failed++
			if len(res.Failures) < 20 {
				res.Failures = append(res.Failures, Failure{Bucket: it.Bucket, Key: it.Key, VersionID: it.VersionID, Error: err.Error()})
			}
		case r.Skipped:
			res.Skipped++
		default:
			res.Succeeded++
			res.Bytes += r.Bytes
		}
	}
	if ctx.Err() != nil {
		return true
	}
	if err := m.putJSON(ctx, doneName, res); err != nil {
		m.o.Log.Warn("batch: cannot record a task result; it will be redone", "job", id, "task", t.Seq, "err", err)
		return true
	}
	m.o.Store.Delete(ctx, name)
	return true
}
