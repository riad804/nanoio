package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"nanoio/internal/storage"
)

// Maintainer is what the storage layer offers for healing, scanning and pool
// administration. It is implemented outside this package (cmd/nanoio) so
// the API never links the erasure-coded backend.
type Maintainer interface {
	Scan(ctx context.Context, deep bool) (MaintScan, error)
	HealObject(ctx context.Context, bucket, object string, deep bool) (MaintHeal, error)
	HealBucket(ctx context.Context, bucket string) (drives []int, err error)
	// Layout is the erasure geometry of a set: data and parity shards.
	Layout() (data, parity int)
	// Pools is nil for a single (non-clustered) backend.
	Pools() []MaintPool
	// Drain moves every object out of a pool that is configured draining.
	Drain(ctx context.Context, pool int) (MaintDrain, error)
}

type MaintScan struct {
	DrivesFormatted, Buckets, BucketsHealed, Objects, ShardsHealed int
	Dangling, Unrecoverable, ExpiredUploads, OrphanDirs, Staging   int
}

type MaintHeal struct {
	Healed   []int
	Dangling bool
	Skipped  string
}

type MaintPool struct {
	Index                int
	Sets, Drives, Online int
	Draining             bool
}

type MaintDrain struct {
	Objects, Skipped, Failed int
	Bytes                    int64
}

func init() {
	r := madminRegister
	r("heal/", "POST", "admin:Heal", (*Server).madminHeal)
	r("background-heal/status", "POST GET", "admin:Heal", (*Server).madminBgHealStatus)
	r("pools/list", "GET", "admin:Decommission", (*Server).madminPoolsList)
	r("pools/status", "GET", "admin:Decommission", (*Server).madminPoolStatus)
	r("pools/decommission", "POST", "admin:Decommission", (*Server).madminPoolDecommission)
	r("pools/cancel", "POST", "admin:Decommission", (*Server).madminPoolCancel)
	r("rebalance/start", "POST", "admin:Rebalance", (*Server).madminRebalance)
	r("rebalance/status", "GET", "admin:Rebalance", (*Server).madminRebalance)
	r("rebalance/stop", "POST", "admin:Rebalance", (*Server).madminRebalance)
}

// ----- healing ---------------------------------------------------------------------------------

type healOpts struct {
	Recursive bool `json:"recursive"`
	DryRun    bool `json:"dryRun"`
	Remove    bool `json:"remove"`
	Recreate  bool `json:"recreate"`
	ScanMode  int  `json:"scanMode"`
	UpdatePar bool `json:"updateParity"`
	NoLock    bool `json:"nolock"`
}

type healDrive struct {
	UUID     string `json:"uuid"`
	Endpoint string `json:"endpoint"`
	State    string `json:"state"`
}

type healItem struct {
	ResultIndex int64  `json:"resultId"`
	Type        string `json:"type"`
	Bucket      string `json:"bucket"`
	Object      string `json:"object"`
	VersionID   string `json:"versionId"`
	Detail      string `json:"detail"`
	DiskCount   int    `json:"diskCount"`
	SetCount    int    `json:"setCount"`
	Before      struct {
		Drives []healDrive `json:"drives"`
	} `json:"before"`
	After struct {
		Drives []healDrive `json:"drives"`
	} `json:"after"`
	ObjectSize   int64 `json:"objectSize"`
	ParityBlocks int   `json:"parityBlocks,omitempty"`
	DataBlocks   int   `json:"dataBlocks,omitempty"`
}

type healJob struct {
	token, path string
	started     time.Time
	opts        healOpts
	cancel      context.CancelFunc

	mu      sync.Mutex
	items   []healItem
	next    int64
	state   string // running, finished, stopped
	failure string
	updated time.Time
}

type healJobs struct {
	mu   sync.Mutex
	byID map[string]*healJob
	// byPath enforces one sequence per path, as the admin API does.
	byPath map[string]*healJob
}

func (j *healJob) add(it healItem) {
	j.mu.Lock()
	j.next++
	it.ResultIndex = j.next
	j.items = append(j.items, it)
	j.updated = time.Now()
	j.mu.Unlock()
}

func (j *healJob) finish(state, failure string) {
	j.mu.Lock()
	if j.state == "running" {
		j.state, j.failure = state, failure
	}
	j.updated = time.Now()
	j.mu.Unlock()
}

func (s *Server) madminHeal(q *request) {
	if s.maint == nil {
		s.madminFail(q, http.StatusNotImplemented, "XMinioAdminNotImplemented", "healing needs the erasure-coded (xl or cluster) backend")
		return
	}
	rest := strings.TrimPrefix(strings.TrimPrefix(q.r.URL.Path, madminPrefix), "heal/")
	bucket, prefix, _ := strings.Cut(rest, "/")
	path := bucket
	if prefix != "" {
		path += "/" + prefix
	}
	hj := &s.healJobs
	hj.mu.Lock()
	if hj.byID == nil {
		hj.byID, hj.byPath = map[string]*healJob{}, map[string]*healJob{}
	}
	// Forget finished sequences after a while.
	for id, j := range hj.byID {
		j.mu.Lock()
		old := j.state != "running" && time.Since(j.updated) > 10*time.Minute
		j.mu.Unlock()
		if old {
			delete(hj.byID, id)
			if hj.byPath[j.path] == j {
				delete(hj.byPath, j.path)
			}
		}
	}
	hj.mu.Unlock()

	if tok := q.query.Get("clientToken"); tok != "" {
		hj.mu.Lock()
		j := hj.byID[tok]
		hj.mu.Unlock()
		if j == nil || j.path != path {
			s.madminFail(q, http.StatusNotFound, "XMinioHealNoSuchProcess", "No such heal process is running on the server")
			return
		}
		j.mu.Lock()
		items := j.items
		j.items = nil
		out := map[string]any{"summary": j.state, "detail": j.failure, "startTime": j.started, "settings": j.opts, "items": items}
		j.mu.Unlock()
		s.writeJSONOK(q, out)
		return
	}
	if q.query.Get("forceStop") == "true" {
		hj.mu.Lock()
		j := hj.byPath[path]
		hj.mu.Unlock()
		if j == nil {
			s.madminFail(q, http.StatusNotFound, "XMinioHealNoSuchProcess", "No such heal process is running on the server")
			return
		}
		j.cancel()
		j.finish("stopped", "")
		s.writeJSONOK(q, map[string]any{"clientToken": j.token, "clientAddress": q.r.RemoteAddr, "startTime": j.started})
		return
	}
	var o healOpts
	if body, err := readAllLimited(q, 1<<16); err != nil {
		s.madminErr(q, err)
		return
	} else if len(body) > 0 {
		if err := json.Unmarshal(body, &o); err != nil {
			s.madminErr(q, madminBad("invalid heal options"))
			return
		}
	}
	if o.DryRun {
		s.madminFail(q, http.StatusBadRequest, "XMinioAdminInvalidArgument",
			"dry-run healing is not supported: NanoIO's healer cannot inspect an object without repairing it")
		return
	}
	if o.Remove || o.Recreate || o.UpdatePar {
		s.madminFail(q, http.StatusBadRequest, "XMinioAdminInvalidArgument",
			"the remove, recreate and update-parity heal options are not supported")
		return
	}
	hj.mu.Lock()
	if cur := hj.byPath[path]; cur != nil {
		cur.mu.Lock()
		running := cur.state == "running"
		cur.mu.Unlock()
		if running && q.query.Get("forceStart") != "true" {
			hj.mu.Unlock()
			s.madminFail(q, http.StatusConflict, "XMinioHealAlreadyRunning", "A heal sequence is already running for this path")
			return
		}
		cur.cancel()
		cur.finish("stopped", "")
	}
	var tb [16]byte
	rand.Read(tb[:])
	ctx, cancel := context.WithCancel(context.Background())
	j := &healJob{token: hex.EncodeToString(tb[:]), path: path, started: time.Now().UTC(), opts: o, cancel: cancel,
		state: "running", updated: time.Now()}
	hj.byID[j.token], hj.byPath[path] = j, j
	hj.mu.Unlock()
	s.stop = append(s.stop, cancel)
	s.bg.Add(1)
	go func() {
		defer s.bg.Done()
		defer cancel()
		s.runHeal(ctx, j, bucket, prefix)
	}()
	s.writeJSONOK(q, map[string]any{"clientToken": j.token, "clientAddress": q.r.RemoteAddr, "startTime": j.started})
}

func (s *Server) runHeal(ctx context.Context, j *healJob, bucket, prefix string) {
	defer func() {
		if r := recover(); r != nil {
			j.finish("finished", fmt.Sprint("panic: ", r))
		}
	}()
	deep := j.opts.ScanMode == 2
	drives := func(n int, healed []int) (before, after []healDrive) {
		bad := map[int]bool{}
		for _, h := range healed {
			bad[h] = true
		}
		for i := 0; i < n; i++ {
			st := "ok"
			if bad[i] {
				st = "missing"
			}
			before = append(before, healDrive{Endpoint: "drive-" + strconv.Itoa(i), State: st})
			after = append(after, healDrive{Endpoint: "drive-" + strconv.Itoa(i), State: "ok"})
		}
		return
	}
	info, _ := s.st.Info(ctx)
	n := info.Disks
	data, parity := s.maint.Layout()
	healBucket := func(b string) bool {
		healed, err := s.maint.HealBucket(ctx, b)
		it := healItem{Type: "bucket", Bucket: b, DiskCount: n, SetCount: 1, DataBlocks: data, ParityBlocks: parity}
		it.Before.Drives, it.After.Drives = drives(n, healed)
		if err != nil {
			it.Detail = "failed: " + err.Error()
		}
		j.add(it)
		return err == nil
	}
	healObjects := func(b, pfx string) {
		tok := ""
		for ctx.Err() == nil {
			res, err := s.st.ListObjects(ctx, b, storage.ListOptions{Prefix: pfx, Marker: tok, MaxKeys: 500})
			if err != nil {
				j.finish("finished", err.Error())
				return
			}
			for _, o := range res.Objects {
				if ctx.Err() != nil {
					return
				}
				h, err := s.maint.HealObject(ctx, b, o.Name, deep)
				it := healItem{Type: "object", Bucket: b, Object: o.Name, DiskCount: n, SetCount: 1, ObjectSize: o.Size,
					DataBlocks: data, ParityBlocks: parity}
				it.Before.Drives, it.After.Drives = drives(n, h.Healed)
				switch {
				case err != nil:
					it.Detail = "failed: " + err.Error()
				case len(h.Healed) > 0:
					it.Detail = "healed"
				case h.Dangling:
					it.Detail = "dangling shards removed"
				case h.Skipped == "healthy" || h.Skipped == "":
					// Nothing to report: clients print a non-empty detail as a problem.
				default:
					it.Detail = h.Skipped
				}
				j.add(it)
			}
			if !res.IsTruncated {
				return
			}
			tok = res.NextMarker
		}
	}
	switch {
	case bucket == "":
		st, err := s.maint.Scan(ctx, deep)
		it := healItem{Type: "metadata", Detail: fmt.Sprintf("scanned %d buckets, %d objects; rebuilt %d object copies, removed %d dangling",
			st.Buckets, st.Objects, st.ShardsHealed, st.Dangling), DiskCount: n, SetCount: 1}
		if err != nil {
			j.finish("finished", err.Error())
			return
		}
		j.add(it)
	default:
		if !healBucket(bucket) {
			break
		}
		if j.opts.Recursive || prefix != "" {
			healObjects(bucket, prefix)
		}
	}
	j.finish("finished", "")
}

func (s *Server) madminBgHealStatus(q *request) {
	out := map[string]any{"offline_nodes": []string{}, "ScannedItemsCount": 0, "HealDisks": []string{},
		"sets": []any{}, "mrf": map[string]any{}, "sc_parity": map[string]int{}}
	if s.maint != nil {
		var sets []map[string]any
		for _, p := range s.maint.Pools() {
			sets = append(sets, map[string]any{"pool": p.Index, "drives": p.Drives, "online": p.Online})
		}
		if sets != nil {
			out["sets"] = sets
		}
	}
	s.writeJSONOK(q, out)
}

// ----- pools / decommission ----------------------------------------------------------------------

type decomJob struct {
	started time.Time
	cancel  context.CancelFunc
	done    bool
	failed  bool
	cancled bool
	stats   MaintDrain
	err     string
}

type decomState struct {
	mu   sync.Mutex
	jobs map[int]*decomJob
}

func poolName(i int) string { return "pool-" + strconv.Itoa(i) }

func (s *Server) poolArg(q *request) (int, bool) {
	arg := q.query.Get("pool")
	arg = strings.TrimPrefix(arg, "pool-")
	i, err := strconv.Atoi(arg)
	if err != nil || s.maint == nil {
		s.madminFail(q, http.StatusBadRequest, "XMinioAdminInvalidArgument", "unknown pool "+strconv.Quote(q.query.Get("pool")))
		return 0, false
	}
	for _, p := range s.maint.Pools() {
		if p.Index == i {
			return i, true
		}
	}
	s.madminFail(q, http.StatusBadRequest, "XMinioAdminInvalidArgument", "unknown pool "+strconv.Quote(q.query.Get("pool")))
	return 0, false
}

func (s *Server) poolStatus(p MaintPool) map[string]any {
	st := map[string]any{"id": p.Index, "cmdline": poolName(p.Index), "lastUpdate": time.Now().UTC()}
	s.decom.mu.Lock()
	j := s.decom.jobs[p.Index]
	s.decom.mu.Unlock()
	if j != nil {
		st["decommissionInfo"] = map[string]any{
			"startTime": j.started, "complete": j.done && !j.failed && !j.cancled,
			"failed": j.failed, "canceled": j.cancled,
			"objectsDecommissioned": j.stats.Objects, "objectsDecommissionedFailed": j.stats.Failed,
			"bytesDecommissioned": j.stats.Bytes,
		}
	} else if p.Draining {
		st["decommissionInfo"] = map[string]any{"startTime": time.Time{}, "complete": false, "failed": false, "canceled": false}
	}
	return st
}

func (s *Server) madminPoolsList(q *request) {
	out := []map[string]any{}
	if s.maint != nil {
		for _, p := range s.maint.Pools() {
			out = append(out, s.poolStatus(p))
		}
	}
	s.writeJSONOK(q, out)
}

func (s *Server) madminPoolStatus(q *request) {
	i, ok := s.poolArg(q)
	if !ok {
		return
	}
	for _, p := range s.maint.Pools() {
		if p.Index == i {
			s.writeJSONOK(q, s.poolStatus(p))
			return
		}
	}
}

func (s *Server) madminPoolDecommission(q *request) {
	i, ok := s.poolArg(q)
	if !ok {
		return
	}
	var pool MaintPool
	for _, p := range s.maint.Pools() {
		if p.Index == i {
			pool = p
		}
	}
	if !pool.Draining {
		s.madminFail(q, http.StatusBadRequest, "XMinioAdminDecommissionNotConfigured",
			"pool "+poolName(i)+" is not configured as draining; set it draining on every node and restart, then start the decommission")
		return
	}
	s.decom.mu.Lock()
	if s.decom.jobs == nil {
		s.decom.jobs = map[int]*decomJob{}
	}
	if j := s.decom.jobs[i]; j != nil && !j.done {
		s.decom.mu.Unlock()
		s.madminFail(q, http.StatusConflict, "XMinioAdminDecommissionAlreadyRunning", "the pool is already being decommissioned")
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	j := &decomJob{started: time.Now().UTC(), cancel: cancel}
	s.decom.jobs[i] = j
	s.decom.mu.Unlock()
	s.stop = append(s.stop, cancel)
	s.bg.Add(1)
	go func() {
		defer s.bg.Done()
		defer cancel()
		st, err := s.maint.Drain(ctx, i)
		s.decom.mu.Lock()
		j.stats, j.done = st, true
		if err != nil {
			j.err = err.Error()
			j.cancled = ctx.Err() != nil
			j.failed = !j.cancled
		}
		s.decom.mu.Unlock()
		s.log.Info("decommission finished", "pool", i, "objects", st.Objects, "failed", st.Failed, "err", err)
	}()
	q.w.WriteHeader(http.StatusOK)
}

func (s *Server) madminPoolCancel(q *request) {
	i, ok := s.poolArg(q)
	if !ok {
		return
	}
	s.decom.mu.Lock()
	j := s.decom.jobs[i]
	s.decom.mu.Unlock()
	if j == nil || j.done {
		s.madminFail(q, http.StatusBadRequest, "XMinioAdminDecommissionNotRunning", "the pool is not being decommissioned")
		return
	}
	j.cancel()
	q.w.WriteHeader(http.StatusOK)
}

// madminRebalance: NanoIO places objects by consistent hashing and moves
// them only when a pool is decommissioned; there is no rebalance job.
func (s *Server) madminRebalance(q *request) {
	switch {
	case strings.HasSuffix(q.r.URL.Path, "/status"):
		s.madminFail(q, http.StatusBadRequest, "XMinioAdminRebalanceNotStarted", "No rebalance is in progress: NanoIO does not implement rebalancing")
	default:
		s.madminFail(q, http.StatusNotImplemented, "XMinioAdminNotImplemented", "NanoIO does not implement rebalancing; objects move only when a pool is decommissioned")
	}
}
