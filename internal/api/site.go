package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"nanoio/internal/auth"
	"nanoio/internal/event"
	"nanoio/internal/iam"
	"nanoio/internal/replication"
	"nanoio/internal/storage"
)

// Site replication keeps N NanoIO deployments ("sites") in step: their
// users, groups and policies, their buckets and bucket configuration
// (policy, ACL, CORS, tags, encryption, lifecycle, versioning, object lock),
// and — by configuring bucket replication between every pair for each site
// bucket — their objects. See docs/site-replication.md for the semantics and
// for what happens in a partition.
//
// The moving parts:
//
//   - membership: _site/config.json lists the peers (endpoint plus the
//     credential this site uses on that peer). Peers are introduced to each
//     other by an operator calling `site add` on one site with the new
//     site's admin credential; each pair of sites gets its own service
//     account on both sides, issued by the side that will be called.
//   - changes: every local change to a replicated entity is stamped with
//     (time, origin site) and put on a durable queue per peer; a sender
//     posts it to the peer's /_nanoio/admin/site/apply. The receiver keeps
//     the change only if its stamp beats what it has (last writer wins,
//     ties broken by the larger site ID) and does not forward it.
//   - anti-entropy: periodically each site fetches every peer's list of
//     entity stamps and pushes whatever it has that is newer or missing,
//     which is what heals a partition or a lost queue.

const (
	siteConfigName   = "_site/config.json"
	siteStampPrefix  = "_site/stamp/"
	siteReplicatorID = "nanoio-site-replicator"
)

type sitePeer struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Endpoint  string    `json:"endpoint"`
	AccessKey string    `json:"accessKey"` // the credential THIS site uses on the peer
	SecretKey string    `json:"secretKey"`
	Added     time.Time `json:"added"`
}

type siteConfig struct {
	ID       string     `json:"id"`
	Name     string     `json:"name"`
	Endpoint string     `json:"endpoint"`
	Peers    []sitePeer `json:"peers"`
	Updated  int64      `json:"updated"`
}

// siteChange is one replicated change.
type siteChange struct {
	Kind    string          `json:"kind"` // iam, bucket, bconf
	Name    string          `json:"name"`
	Updated int64           `json:"updated"`
	Origin  string          `json:"origin"`
	Deleted bool            `json:"deleted,omitempty"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (c *siteChange) stamp() siteStamp {
	return siteStamp{Updated: c.Updated, Origin: c.Origin, Deleted: c.Deleted}
}

type siteStamp struct {
	Updated int64  `json:"updated"`
	Origin  string `json:"origin"`
	Deleted bool   `json:"deleted,omitempty"`
}

// beats reports whether st wins over other: the later time, then the
// larger origin ID.
func (st siteStamp) beats(other siteStamp) bool {
	if st.Updated != other.Updated {
		return st.Updated > other.Updated
	}
	return st.Origin > other.Origin
}

// bucketDoc is the replicated part of a bucket.
type bucketDoc struct {
	ObjectLock bool                      `json:"objectLock,omitempty"`
	Versioning string                    `json:"versioning,omitempty"`
	LockMode   string                    `json:"lockMode,omitempty"`
	LockDays   int                       `json:"lockDays,omitempty"`
	LockYears  int                       `json:"lockYears,omitempty"`
	Default    *storage.DefaultRetention `json:"-"`
}

// siteConflict records a change that lost: what was overwritten and by whom.
type siteConflict struct {
	Time    time.Time `json:"time"`
	Kind    string    `json:"kind"`
	Name    string    `json:"name"`
	Winner  siteStamp `json:"winner"`
	Loser   siteStamp `json:"loser"`
	Applied bool      `json:"applied"` // true: the incoming change replaced local state
}

type siteRuntime struct {
	s   *Server
	dir string
	es  *eventStore

	mu        sync.Mutex
	cfg       *siteConfig
	cfgLoaded time.Time
	queues    map[string]*event.Queue
	conflicts []siteConflict
	lastErr   map[string]string
	lastOK    map[string]time.Time
	clients   *http.Client
	wake      chan struct{}
	kick      chan struct{}
	sendWG    sync.WaitGroup
	senders   map[string]context.CancelFunc
	rootCtx   context.Context
}

type siteApplyKey struct{}

// siteApplying marks a context as applying a change that came from a peer,
// so the hooks it triggers do not send it onward.
func siteApplying(ctx context.Context) context.Context {
	return context.WithValue(ctx, siteApplyKey{}, true)
}

func isSiteApplying(ctx context.Context) bool { return ctx.Value(siteApplyKey{}) != nil }

func (s *Server) initSite(o *ReplicationOptions) {
	if o == nil || o.Dir == "" {
		return
	}
	rt := &siteRuntime{s: s, dir: o.Dir + "/_site", es: &eventStore{st: s.st}, queues: map[string]*event.Queue{},
		lastErr: map[string]string{}, lastOK: map[string]time.Time{}, senders: map[string]context.CancelFunc{},
		clients: &http.Client{Timeout: 60 * time.Second}, wake: make(chan struct{}, 1), kick: make(chan struct{}, 1)}
	s.site = rt
	ctx, cancel := context.WithCancel(context.Background())
	rt.rootCtx = ctx
	s.stop = append(s.stop, func() {
		cancel()
		rt.sendWG.Wait()
		rt.mu.Lock()
		for _, q := range rt.queues {
			q.Close()
		}
		rt.mu.Unlock()
	})
	s.bg.Add(1)
	go func() {
		defer s.bg.Done()
		rt.supervise(ctx)
	}()
}

// ----- identity and configuration ------------------------------------------------------

const clusterIDName = "_site/cluster-id"

// clusterID is this cluster's permanent identity: what a replica records as
// its source, and the tie-breaker when two sites changed the same entity at
// the same instant. It is created on first use and kept in the system
// bucket. (Two nodes of a brand-new cluster racing to create it can briefly
// use different IDs; the last write wins and every node converges on it at
// its next read.)
func (s *Server) clusterID(ctx context.Context) string {
	if p := s.clusterIDv.Load(); p != nil {
		return *p
	}
	es := &eventStore{st: s.st}
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	b, err := es.Get(cctx, clusterIDName)
	if err == event.ErrSharedNotFound {
		var r [8]byte
		rand.Read(r[:])
		id := hex.EncodeToString(r[:])
		if perr := es.Put(cctx, clusterIDName, []byte(id)); perr != nil {
			return id
		}
		if b2, gerr := es.Get(cctx, clusterIDName); gerr == nil {
			b = b2
		} else {
			b = []byte(id)
		}
	} else if err != nil {
		return "unknown"
	}
	id := string(b)
	s.clusterIDv.Store(&id)
	return id
}

// siteID is the identity used in IAM and site documents: the cluster ID.
func (s *Server) siteID() string { return s.clusterID(context.Background()) }

// clone returns an independent copy: a caller may modify what config returns.
func (c *siteConfig) clone() *siteConfig {
	if c == nil {
		return nil
	}
	n := *c
	n.Peers = append([]sitePeer(nil), c.Peers...)
	return &n
}

func (rt *siteRuntime) config(ctx context.Context) *siteConfig {
	rt.mu.Lock()
	if rt.cfg != nil && time.Since(rt.cfgLoaded) < 2*time.Second {
		c := rt.cfg.clone()
		rt.mu.Unlock()
		return c
	}
	rt.mu.Unlock()
	b, err := rt.es.Get(ctx, siteConfigName)
	var c *siteConfig
	if err == nil {
		var v siteConfig
		if json.Unmarshal(b, &v) == nil {
			c = &v
		}
	}
	rt.mu.Lock()
	rt.cfg, rt.cfgLoaded = c, time.Now()
	rt.mu.Unlock()
	return c.clone()
}

func (rt *siteRuntime) saveConfig(ctx context.Context, c *siteConfig) error {
	c.Updated = time.Now().UnixNano()
	b, _ := json.Marshal(c)
	if err := rt.es.Put(ctx, siteConfigName, b); err != nil {
		return err
	}
	rt.mu.Lock()
	rt.cfg, rt.cfgLoaded = c.clone(), time.Now()
	rt.mu.Unlock()
	return nil
}

// enabled reports whether this site is part of a site-replication group.
func (s *Server) siteEnabled(ctx context.Context) bool {
	if s.site == nil {
		return false
	}
	c := s.site.config(ctx)
	return c != nil && len(c.Peers) > 0
}

// ----- stamps ----------------------------------------------------------------------------

func stampName(kind, name string) string { return siteStampPrefix + kind + "/" + name }

func (rt *siteRuntime) stampOf(ctx context.Context, kind, name string) (siteStamp, bool) {
	b, err := rt.es.Get(ctx, stampName(kind, name))
	if err != nil {
		return siteStamp{}, false
	}
	var st siteStamp
	if json.Unmarshal(b, &st) != nil {
		return siteStamp{}, false
	}
	return st, true
}

func (rt *siteRuntime) putStamp(ctx context.Context, kind, name string, st siteStamp) error {
	b, _ := json.Marshal(st)
	return rt.es.Put(ctx, stampName(kind, name), b)
}

// ----- change hooks ----------------------------------------------------------------------

// siteChanged is called for a locally originated IAM change (doc is the
// stored iamDoc).
func (s *Server) siteChanged(kind, name string, doc []byte) {
	if s.site == nil || !s.siteEnabled(context.Background()) {
		return
	}
	var d iamDoc
	if json.Unmarshal(doc, &d) != nil {
		return
	}
	if strings.HasPrefix(d.Name, "nanoio-site-") {
		return // service accounts are per site pair, never replicated
	}
	s.site.enqueueAll(&siteChange{Kind: "iam", Name: name, Updated: d.Updated, Origin: d.Origin, Deleted: d.Deleted, Data: doc})
}

// siteBucketChanged records and sends a bucket-level change (creation,
// deletion, versioning, object lock).
func (s *Server) siteBucketChanged(ctx context.Context, bucket string, deleted bool) {
	if s.site == nil || isSiteApplying(ctx) || !s.siteEnabled(ctx) {
		return
	}
	ch := &siteChange{Kind: "bucket", Name: bucket, Updated: time.Now().UnixNano(), Origin: s.siteID(), Deleted: deleted}
	if !deleted {
		doc, err := s.bucketDocOf(ctx, bucket)
		if err != nil {
			s.log.Warn("site: cannot read the bucket to replicate", "bucket", bucket, "err", err)
			return
		}
		ch.Data, _ = json.Marshal(doc)
	}
	s.site.recordAndSend(ctx, ch)
	s.site.kickReconcile()
}

// siteConfChanged records and sends a change to one bucket configuration
// document.
func (s *Server) siteConfChanged(ctx context.Context, bucket, kind string, data []byte, deleted bool) {
	if s.site == nil || isSiteApplying(ctx) || !siteConfKinds[kind] || !s.siteEnabled(ctx) {
		return
	}
	ch := &siteChange{Kind: "bconf", Name: bucket + "/" + kind, Updated: time.Now().UnixNano(), Origin: s.siteID(), Deleted: deleted}
	if !deleted {
		ch.Data, _ = json.Marshal(data)
	}
	s.site.recordAndSend(ctx, ch)
}

// siteConfKinds are the bucket documents that follow the bucket around.
// Notification targets and replication rules are site-specific and do not.
var siteConfKinds = map[string]bool{confPolicy: true, confACL: true, confCORS: true, confTagging: true,
	confEncryption: true, confLifecycle: true}

func (s *Server) bucketDocOf(ctx context.Context, bucket string) (*bucketDoc, error) {
	d := &bucketDoc{}
	v, err := s.st.GetBucketVersioning(ctx, bucket)
	if err != nil {
		return nil, err
	}
	d.Versioning = string(v.State)
	lk, err := s.st.GetBucketObjectLock(ctx, bucket)
	if err != nil {
		return nil, err
	}
	d.ObjectLock = lk.Enabled
	if lk.Default != nil {
		d.LockMode, d.LockDays, d.LockYears = string(lk.Default.Mode), lk.Default.Days, lk.Default.Years
	}
	return d, nil
}

func (rt *siteRuntime) recordAndSend(ctx context.Context, ch *siteChange) {
	cctx := context.WithoutCancel(ctx)
	if err := rt.putStamp(cctx, ch.Kind, ch.Name, ch.stamp()); err != nil {
		rt.s.log.Warn("site: cannot record a change stamp", "kind", ch.Kind, "name", ch.Name, "err", err)
	}
	rt.enqueueAll(ch)
}

func (rt *siteRuntime) queueFor(peerID string) (*event.Queue, error) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if q := rt.queues[peerID]; q != nil {
		return q, nil
	}
	q, err := event.OpenQueue(rt.dir+"/"+peerID, 200000, 0)
	if err != nil {
		return nil, err
	}
	rt.queues[peerID] = q
	return q, nil
}

func (rt *siteRuntime) enqueueAll(ch *siteChange) {
	c := rt.config(context.Background())
	if c == nil {
		return
	}
	b, _ := json.Marshal(ch)
	for _, p := range c.Peers {
		q, err := rt.queueFor(p.ID)
		if err != nil {
			rt.s.log.Error("site: cannot open a peer queue", "peer", p.ID, "err", err)
			continue
		}
		if err := q.Append(b); err != nil {
			rt.s.log.Error("site: cannot queue a change", "peer", p.ID, "err", err)
			continue
		}
		q.Sync()
	}
	select {
	case rt.wake <- struct{}{}:
	default:
	}
}

// ----- sending ---------------------------------------------------------------------------

// supervise starts a sender per peer and runs the anti-entropy pass: every
// 10 seconds, and again soon after anything that may need follow-up (a new
// bucket whose peers have not all applied it yet).
func (rt *siteRuntime) supervise(ctx context.Context) {
	next := time.NewTimer(500 * time.Millisecond)
	defer next.Stop()
	for {
		rt.syncSenders(ctx)
		select {
		case <-ctx.Done():
			return
		case <-rt.wake:
			continue
		case <-rt.kick:
		case <-next.C:
		case <-time.After(2 * time.Second):
			continue
		}
		again := rt.reconcile(ctx)
		d := 10 * time.Second
		if again {
			d = time.Second
		}
		if !next.Stop() {
			select {
			case <-next.C:
			default:
			}
		}
		next.Reset(d)
	}
}

// kickReconcile asks for an anti-entropy pass soon.
func (rt *siteRuntime) kickReconcile() {
	select {
	case rt.kick <- struct{}{}:
	default:
	}
}

func (rt *siteRuntime) syncSenders(ctx context.Context) {
	c := rt.config(ctx)
	want := map[string]sitePeer{}
	if c != nil {
		for _, p := range c.Peers {
			want[p.ID] = p
		}
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	for id, cancel := range rt.senders {
		if _, ok := want[id]; !ok {
			cancel()
			delete(rt.senders, id)
		}
	}
	for id, p := range want {
		if _, ok := rt.senders[id]; ok {
			continue
		}
		pctx, cancel := context.WithCancel(ctx)
		rt.senders[id] = cancel
		rt.sendWG.Add(1)
		go func(p sitePeer) {
			defer rt.sendWG.Done()
			rt.sender(pctx, p.ID)
		}(p)
	}
}

func (rt *siteRuntime) peer(ctx context.Context, id string) *sitePeer {
	c := rt.config(ctx)
	if c == nil {
		return nil
	}
	for i := range c.Peers {
		if c.Peers[i].ID == id {
			p := c.Peers[i]
			return &p
		}
	}
	return nil
}

func (rt *siteRuntime) sender(ctx context.Context, peerID string) {
	q, err := rt.queueFor(peerID)
	if err != nil {
		return
	}
	backoff := 200 * time.Millisecond
	for ctx.Err() == nil {
		items, err := q.Peek(1)
		if err != nil || len(items) == 0 {
			select {
			case <-ctx.Done():
				return
			case <-rt.wake:
			case <-time.After(time.Second):
			}
			continue
		}
		p := rt.peer(ctx, peerID)
		if p == nil {
			return
		}
		err = rt.post(ctx, p, "/_nanoio/admin/site/apply", items[0].Data)
		if err != nil {
			rt.mu.Lock()
			rt.lastErr[peerID] = err.Error()
			rt.mu.Unlock()
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = 200 * time.Millisecond
		rt.mu.Lock()
		delete(rt.lastErr, peerID)
		rt.lastOK[peerID] = time.Now()
		rt.mu.Unlock()
		q.Ack(items)
	}
}

// do sends a signed request to a peer as this site's service account on it.
func (rt *siteRuntime) do(ctx context.Context, p *sitePeer, method, path string, body []byte) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(p.Endpoint, "/")+path, rd)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	auth.Signer{AccessKey: p.AccessKey, SecretKey: p.SecretKey, Region: rt.s.region}.
		Sign(req, hex.EncodeToString(sum[:]), time.Now())
	return rt.clients.Do(req)
}

func (rt *siteRuntime) post(ctx context.Context, p *sitePeer, path string, body []byte) error {
	resp, err := rt.do(ctx, p, http.MethodPost, path, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("peer %s answered %s: %s", p.Name, resp.Status, strings.TrimSpace(string(b)))
	}
	return nil
}

// ----- applying a peer's change -----------------------------------------------------------

var errSiteStale = errors.New("a newer change is already applied")

// applyChange makes a peer's change the local state if it wins.
func (s *Server) applyChange(ctx context.Context, ch *siteChange) error {
	ctx = siteApplying(ctx)
	rt := s.site
	if ch.Kind == "iam" {
		var d iamDoc
		if err := json.Unmarshal(ch.Data, &d); err != nil {
			return err
		}
		if s.iamrt == nil {
			return nil
		}
		applied, err := s.iamrt.apply(ctx, &d, true)
		if err == nil && !applied {
			rt.noteConflict(ch, siteStamp{}, false)
		}
		return err
	}
	cur, have := rt.stampOf(ctx, ch.Kind, ch.Name)
	if have && !ch.stamp().beats(cur) {
		rt.noteConflict(ch, cur, false)
		return nil
	}
	switch ch.Kind {
	case "bucket":
		if err := s.applyBucket(ctx, ch); err != nil {
			return err
		}
		defer rt.kickReconcile()
	case "bconf":
		bucket, kind, ok := strings.Cut(ch.Name, "/")
		if !ok || !siteConfKinds[kind] {
			return fmt.Errorf("unknown bucket configuration %q", ch.Name)
		}
		if exists, _ := s.st.BucketExists(ctx, bucket); !exists {
			// Not applied and not stamped: the bucket's own change is on
			// its way (or the bucket is gone), and the anti-entropy pass
			// pushes this again when it matters.
			return nil
		}
		if ch.Deleted {
			s.confDrop(ctx, bucket, kind)
		} else {
			var data []byte
			if err := json.Unmarshal(ch.Data, &data); err != nil {
				return err
			}
			if err := s.confPut(ctx, bucket, kind, data); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unknown change kind %q", ch.Kind)
	}
	if have {
		rt.noteConflict(ch, cur, true)
	}
	return rt.putStamp(ctx, ch.Kind, ch.Name, ch.stamp())
}

func (s *Server) applyBucket(ctx context.Context, ch *siteChange) error {
	bucket := ch.Name
	exists, err := s.st.BucketExists(ctx, bucket)
	if err != nil {
		return err
	}
	if ch.Deleted {
		if !exists {
			return nil
		}
		err := s.st.DeleteBucket(ctx, bucket, storage.DeleteBucketOptions{})
		if err != nil {
			// A bucket that still holds objects here is kept; the stamp
			// says deleted and the anti-entropy pass retries.
			s.log.Warn("site: cannot delete a bucket deleted on a peer", "bucket", bucket, "err", err)
			return nil
		}
		s.confDropAll(ctx, bucket)
		return nil
	}
	var d bucketDoc
	if err := json.Unmarshal(ch.Data, &d); err != nil {
		return err
	}
	if !exists {
		if err := s.st.MakeBucket(ctx, bucket, storage.MakeBucketOptions{ObjectLock: d.ObjectLock}); err != nil && !errors.Is(err, storage.ErrBucketExists) {
			return err
		}
		s.confDropAll(ctx, bucket)
	}
	// Site buckets are always versioned: replicas keep version IDs.
	if err := s.st.SetBucketVersioning(ctx, bucket, storage.VersioningEnabled); err != nil {
		return err
	}
	if d.ObjectLock && d.LockMode != "" {
		cfg := storage.ObjectLockConfig{Enabled: true, Default: &storage.DefaultRetention{
			Mode: storage.RetentionMode(d.LockMode), Days: d.LockDays, Years: d.LockYears}}
		if err := s.st.SetBucketObjectLock(ctx, bucket, cfg); err != nil {
			return err
		}
	}
	return nil
}

func (rt *siteRuntime) noteConflict(ch *siteChange, local siteStamp, applied bool) {
	c := siteConflict{Time: time.Now().UTC(), Kind: ch.Kind, Name: ch.Name, Applied: applied}
	if applied {
		c.Winner, c.Loser = ch.stamp(), local
	} else {
		c.Winner, c.Loser = local, ch.stamp()
	}
	if c.Winner.Updated == c.Loser.Updated && c.Winner.Origin == c.Loser.Origin {
		return // the same change arrived twice
	}
	rt.mu.Lock()
	rt.conflicts = append(rt.conflicts, c)
	if len(rt.conflicts) > 100 {
		rt.conflicts = rt.conflicts[len(rt.conflicts)-100:]
	}
	rt.mu.Unlock()
	rt.s.log.Warn("site: concurrent change resolved by last-writer-wins", "kind", c.Kind, "name", c.Name,
		"winner", c.Winner.Origin, "loser", c.Loser.Origin)
}

// ----- state and anti-entropy ----------------------------------------------------------------

type stateEntry struct {
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	Updated int64  `json:"updated"`
	Origin  string `json:"origin"`
	Deleted bool   `json:"deleted,omitempty"`
}

// localState lists the stamp of every replicated entity.
func (rt *siteRuntime) localState(ctx context.Context) ([]stateEntry, error) {
	var out []stateEntry
	names, err := rt.es.List(ctx, siteStampPrefix, 1000000)
	if err != nil {
		return nil, err
	}
	for _, n := range names {
		rest := strings.TrimPrefix(n, siteStampPrefix)
		kind, name, ok := strings.Cut(rest, "/")
		if !ok {
			continue
		}
		st, ok := rt.stampOf(ctx, kind, name)
		if !ok {
			continue
		}
		out = append(out, stateEntry{kind, name, st.Updated, st.Origin, st.Deleted})
	}
	iamNames, err := rt.es.List(ctx, iamPrefix, 1000000)
	if err != nil {
		return nil, err
	}
	for _, n := range iamNames {
		if n == iamVersionKey || !strings.HasSuffix(n, ".json") {
			continue
		}
		d, err := rt.s.iamrt.readDoc(ctx, n)
		if err != nil || d == nil || strings.HasPrefix(d.Name, "nanoio-site-") {
			continue
		}
		out = append(out, stateEntry{"iam", n, d.Updated, d.Origin, d.Deleted})
	}
	rank := map[string]int{"iam": 0, "bucket": 1, "bconf": 2}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return rank[out[i].Kind] < rank[out[j].Kind]
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// loadChange builds the change for an entity from current local state.
func (s *Server) loadChange(ctx context.Context, e stateEntry) (*siteChange, error) {
	ch := &siteChange{Kind: e.Kind, Name: e.Name, Updated: e.Updated, Origin: e.Origin, Deleted: e.Deleted}
	if e.Deleted {
		return ch, nil
	}
	switch e.Kind {
	case "iam":
		b, err := s.site.es.Get(ctx, e.Name)
		if err != nil {
			return nil, err
		}
		ch.Data = b
	case "bucket":
		d, err := s.bucketDocOf(ctx, e.Name)
		if err != nil {
			return nil, err
		}
		ch.Data, _ = json.Marshal(d)
	case "bconf":
		bucket, kind, _ := strings.Cut(e.Name, "/")
		raw, err := s.confRaw(ctx, bucket, kind)
		if err != nil {
			return nil, err
		}
		if raw == nil {
			ch.Deleted = true
			return ch, nil
		}
		ch.Data, _ = json.Marshal(raw)
	}
	return ch, nil
}

// reconcile is the anti-entropy pass: it makes sure every site bucket has
// replication to every peer, retries bucket deletions that were blocked, and
// pushes to each peer whatever it is missing or has older.
func (rt *siteRuntime) reconcile(ctx context.Context) (again bool) {
	c := rt.config(ctx)
	if c == nil || len(c.Peers) == 0 {
		return false
	}
	s := rt.s
	local, err := rt.localState(ctx)
	if err != nil {
		return true
	}
	for _, e := range local {
		if e.Kind == "bucket" && e.Deleted {
			if ok, _ := s.st.BucketExists(ctx, e.Name); ok {
				s.applyBucket(siteApplying(ctx), &siteChange{Kind: "bucket", Name: e.Name, Deleted: true})
			}
		}
	}
	again = s.siteEnsureReplication(ctx, c)
	for _, p := range c.Peers {
		if ctx.Err() != nil {
			return again
		}
		if rt.s.siteLocker != nil {
			lctx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
			unlock, err := rt.s.siteLocker.Lock(lctx, sysBucket, "_site/reconcile/"+p.ID)
			cancel()
			if err != nil {
				continue
			}
			rt.pushDiff(ctx, &p, local)
			unlock()
		} else {
			rt.pushDiff(ctx, &p, local)
		}
	}
	return again
}

func (rt *siteRuntime) pushDiff(ctx context.Context, p *sitePeer, local []stateEntry) {
	resp, err := rt.do(ctx, p, http.MethodGet, "/_nanoio/admin/site/state", nil)
	if err != nil {
		rt.mu.Lock()
		rt.lastErr[p.ID] = err.Error()
		rt.mu.Unlock()
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	var remote []stateEntry
	if json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&remote) != nil {
		return
	}
	have := map[string]stateEntry{}
	for _, e := range remote {
		have[e.Kind+"\x00"+e.Name] = e
	}
	for _, e := range local {
		r, ok := have[e.Kind+"\x00"+e.Name]
		if ok {
			rs := siteStamp{r.Updated, r.Origin, r.Deleted}
			if !(siteStamp{e.Updated, e.Origin, e.Deleted}).beats(rs) {
				continue
			}
		}
		ch, err := rt.s.loadChange(ctx, e)
		if err != nil {
			continue
		}
		b, _ := json.Marshal(ch)
		if err := rt.post(ctx, p, "/_nanoio/admin/site/apply", b); err != nil {
			return
		}
	}
}

// siteEnsureReplication makes every site bucket replicate to every peer: a
// remote target per (bucket, peer) and one rule per target, ahead of any
// other rule.
func (s *Server) siteEnsureReplication(ctx context.Context, c *siteConfig) (again bool) {
	if s.repl == nil {
		return false
	}
	buckets, err := s.st.ListBuckets(ctx)
	if err != nil {
		return true
	}
	for _, b := range buckets {
		if b.Name == sysBucket {
			continue
		}
		if st, ok := s.site.stampOf(ctx, "bucket", b.Name); !ok || st.Deleted {
			continue
		}
		if !s.ensureBucketReplication(ctx, b.Name, c) {
			again = true
		}
	}
	return again
}

// ensureBucketReplication reports whether the bucket is fully set up.
func (s *Server) ensureBucketReplication(ctx context.Context, bucket string, c *siteConfig) bool {
	if v, err := s.st.GetBucketVersioning(ctx, bucket); err != nil || v.State != storage.VersioningEnabled {
		return false
	}
	targets, err := s.replTargets(ctx, bucket)
	if err != nil {
		return false
	}
	complete := true
	changed := false
	arns := map[string]string{} // peer ID -> ARN
	for _, p := range c.Peers {
		var found *replTarget
		for i := range targets {
			if targets[i].Endpoint == p.Endpoint && targets[i].Bucket == bucket && strings.HasPrefix(targets[i].ID, "site-"+p.ID) {
				found = &targets[i]
			}
		}
		if found != nil && (found.AccessKey != p.AccessKey || found.SecretKey != p.SecretKey) {
			found.AccessKey, found.SecretKey = p.AccessKey, p.SecretKey
			changed = true
		}
		if found == nil {
			t := replTarget{ID: "site-" + p.ID, Endpoint: p.Endpoint, Bucket: bucket, AccessKey: p.AccessKey,
				SecretKey: p.SecretKey, Created: time.Now().UTC()}
			if err := checkRemoteVersioned(ctx, t); err != nil {
				complete = false
				continue // the peer has not applied the bucket yet; next pass
			}
			targets = append(targets, t)
			found = &targets[len(targets)-1]
			changed = true
		}
		arns[p.ID] = replication.ARN(found.ID, found.Bucket)
	}
	if changed {
		for i := range targets {
			targets[i].ARN = ""
		}
		data, _ := json.Marshal(targets)
		if err := s.confPut(siteApplying(ctx), bucket, confReplTargets, data); err != nil {
			return false
		}
	}
	cfg, _ := s.replicationConfig(ctx, bucket)
	var rules []replication.Rule
	if cfg != nil {
		rules = cfg.Rules
	}
	have := map[string]bool{}
	for _, r := range rules {
		have[r.Destination] = true
	}
	added := false
	prio := 0
	for _, r := range rules {
		if r.Priority >= prio {
			prio = r.Priority + 1
		}
	}
	ids := make([]string, 0, len(arns))
	for id := range arns {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		arn := arns[id]
		if have[arn] {
			continue
		}
		rules = append(rules, replication.Rule{ID: "site-" + id, Enabled: true, Priority: prio, DeleteMarkers: true,
			ReplicaModifications: true, Existing: true, Destination: arn})
		prio++
		added = true
	}
	if !added {
		return complete
	}
	doc, err := (&replication.Config{Rules: rules}).Marshal()
	if err != nil {
		return false
	}
	if err := s.confPut(siteApplying(ctx), bucket, confReplication, doc); err != nil {
		return false
	}
	if s.repl != nil {
		s.repl.startResync(bucket, "", false)
	}
	return complete
}

// ----- admin endpoints -----------------------------------------------------------------------

type siteInfo struct {
	ID       string         `json:"id"`
	Name     string         `json:"name"`
	Endpoint string         `json:"endpoint,omitempty"`
	Peers    []siteInfoPeer `json:"peers"`
	Empty    bool           `json:"empty"`
}

type siteInfoPeer struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Endpoint string `json:"endpoint"`
}

func (s *Server) adminSite(q *request, sub string) {
	if s.site == nil {
		s.fail(q, notImplemented("site replication needs the replication runtime (a queue directory)"))
		return
	}
	switch sub {
	case "info":
		s.siteInfoHandler(q)
	case "add":
		s.siteAdd(q)
	case "issue":
		s.siteIssue(q)
	case "peer":
		s.sitePeerHandler(q)
	case "remove":
		s.siteRemove(q)
	case "status":
		s.siteStatus(q)
	case "apply":
		s.siteApply(q)
	case "state":
		s.siteState(q)
	case "resync":
		s.siteResync(q)
	}
}

func (s *Server) siteSelfEmpty(ctx context.Context) bool {
	bs, err := s.st.ListBuckets(ctx)
	if err != nil {
		return false
	}
	for _, b := range bs {
		if b.Name != sysBucket {
			return false
		}
	}
	if s.iamrt != nil {
		names, _ := s.iamrt.es.List(ctx, iamPrefix, 10)
		for _, n := range names {
			if n != iamVersionKey {
				if d, _ := s.iamrt.readDoc(ctx, n); d != nil && !d.Deleted && !strings.HasPrefix(d.Name, "nanoio-site-") {
					return false
				}
			}
		}
	}
	return true
}

func (s *Server) siteInfoHandler(q *request) {
	if q.r.Method != http.MethodGet {
		s.fail(q, errBadMethod)
		return
	}
	if !s.authorize(q, "nanoio:SiteReplicate", "", "", nil) {
		return
	}
	c := s.site.config(q.ctx())
	info := siteInfo{ID: s.clusterID(q.ctx()), Empty: s.siteSelfEmpty(q.ctx()), Peers: []siteInfoPeer{}}
	if c != nil {
		info.Name, info.Endpoint = c.Name, c.Endpoint
		for _, p := range c.Peers {
			info.Peers = append(info.Peers, siteInfoPeer{p.ID, p.Name, p.Endpoint})
		}
	}
	writeJSON(q.w, info)
}

type siteAddRequest struct {
	Self struct {
		Name     string `json:"name"`
		Endpoint string `json:"endpoint"`
	} `json:"self"`
	Site struct {
		Name      string `json:"name"`
		Endpoint  string `json:"endpoint"`
		AccessKey string `json:"accessKey"`
		SecretKey string `json:"secretKey"`
	} `json:"site"`
	Force bool `json:"force,omitempty"`
}

// remoteAdmin calls another site with its admin (or service) credential.
func (s *Server) remoteAdmin(ctx context.Context, endpoint, ak, sk, method, path string, body []byte) ([]byte, int, error) {
	p := &sitePeer{Endpoint: endpoint, AccessKey: ak, SecretKey: sk}
	resp, err := s.site.do(ctx, p, method, path, body)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	return b, resp.StatusCode, nil
}

func (s *Server) callJSON(ctx context.Context, endpoint, ak, sk, path string, in, out any) error {
	var body []byte
	method := http.MethodGet
	if in != nil {
		body, _ = json.Marshal(in)
		method = http.MethodPost
	}
	b, st, err := s.remoteAdmin(ctx, endpoint, ak, sk, method, path, body)
	if err != nil {
		return err
	}
	if st/100 != 2 {
		return fmt.Errorf("%s answered %d: %s", path, st, strings.TrimSpace(string(b)))
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

// siteAdd joins a new site to this site's group (the operator calls it on
// any one member). It exchanges service credentials between the new site and
// every member, so that all pairs can talk.
func (s *Server) siteAdd(q *request) {
	if q.r.Method != http.MethodPost {
		s.fail(q, errBadMethod)
		return
	}
	if !s.authorize(q, "nanoio:SiteManage", "", "", nil) {
		return
	}
	body, err := s.readBody(q, 64<<10)
	if err != nil {
		s.fail(q, err)
		return
	}
	var req siteAddRequest
	if err := json.Unmarshal(body, &req); err != nil {
		s.fail(q, invalidArgument("invalid request: "+err.Error()))
		return
	}
	if req.Site.Endpoint == "" || req.Site.AccessKey == "" || req.Site.SecretKey == "" || req.Self.Endpoint == "" {
		s.fail(q, invalidArgument("site.endpoint, site.accessKey, site.secretKey and self.endpoint are required"))
		return
	}
	if _, err := url.Parse(req.Site.Endpoint); err != nil {
		s.fail(q, invalidArgument("site.endpoint is not a URL"))
		return
	}
	ctx := q.ctx()
	if err := s.siteJoin(ctx, &req); err != nil {
		var he *APIError
		if errors.As(err, &he) {
			s.fail(q, he)
		} else {
			s.fail(q, invalidArgument(err.Error()))
		}
		return
	}
	s.site.signal()
	q.w.WriteHeader(http.StatusNoContent)
}

func (rt *siteRuntime) signal() {
	select {
	case rt.wake <- struct{}{}:
	default:
	}
}

func (s *Server) siteJoin(ctx context.Context, req *siteAddRequest) error {
	rt := s.site
	selfID := s.clusterID(ctx)
	c := rt.config(ctx)
	if c == nil {
		c = &siteConfig{ID: selfID}
	}
	if req.Self.Name != "" {
		c.Name = req.Self.Name
	}
	if c.Name == "" {
		c.Name = "site-" + selfID[:6]
	}
	c.Endpoint = req.Self.Endpoint
	c.ID = selfID

	var info siteInfo
	if err := s.callJSON(ctx, req.Site.Endpoint, req.Site.AccessKey, req.Site.SecretKey, "/_nanoio/admin/site/info", nil, &info); err != nil {
		return fmt.Errorf("cannot reach the new site with the credentials given: %w", err)
	}
	if info.ID == selfID {
		return errors.New("that endpoint is this site")
	}
	for _, p := range c.Peers {
		if p.ID == info.ID {
			return errors.New("that site is already a member")
		}
	}
	if len(info.Peers) > 0 {
		return errors.New("that site already belongs to a site-replication group; remove it from there first")
	}
	if !info.Empty && !req.Force {
		return errors.New("the new site already holds buckets or IAM entries; a site joins empty (or pass force to accept last-writer-wins merging of what is there)")
	}
	name := req.Site.Name
	if name == "" {
		name = info.Name
	}
	if name == "" {
		name = "site-" + info.ID[:6]
	}

	// The new site issues the credential this site uses on it...
	var credOnNew struct{ AccessKey, SecretKey string }
	if err := s.callJSON(ctx, req.Site.Endpoint, req.Site.AccessKey, req.Site.SecretKey, "/_nanoio/admin/site/issue",
		map[string]string{"peerID": selfID, "peerName": c.Name}, &credOnNew); err != nil {
		return err
	}
	// ...and this site issues the one the new site uses on it.
	credOnSelf, err := s.siteIssueCredential(ctx, info.ID)
	if err != nil {
		return err
	}
	// Tell the new site about this one and about the existing members.
	if err := s.callJSON(ctx, req.Site.Endpoint, req.Site.AccessKey, req.Site.SecretKey, "/_nanoio/admin/site/peer", map[string]any{
		"id": selfID, "name": c.Name, "endpoint": c.Endpoint,
		"accessKey": credOnSelf.AccessKey, "secretKey": credOnSelf.SecretKey, "selfName": name, "selfEndpoint": req.Site.Endpoint,
	}, nil); err != nil {
		return err
	}
	newPeer := sitePeer{ID: info.ID, Name: name, Endpoint: req.Site.Endpoint,
		AccessKey: credOnNew.AccessKey, SecretKey: credOnNew.SecretKey, Added: time.Now().UTC()}

	// Every existing member and the new site must also be able to call each
	// other: each issues a credential for the other.
	for _, m := range c.Peers {
		var forMember, forNew struct{ AccessKey, SecretKey string }
		if err := s.callJSON(ctx, newPeer.Endpoint, newPeer.AccessKey, newPeer.SecretKey, "/_nanoio/admin/site/issue",
			map[string]string{"peerID": m.ID, "peerName": m.Name}, &forMember); err != nil {
			return err
		}
		if err := s.callJSON(ctx, m.Endpoint, m.AccessKey, m.SecretKey, "/_nanoio/admin/site/issue",
			map[string]string{"peerID": info.ID, "peerName": name}, &forNew); err != nil {
			return err
		}
		if err := s.callJSON(ctx, m.Endpoint, m.AccessKey, m.SecretKey, "/_nanoio/admin/site/peer", map[string]any{
			"id": info.ID, "name": name, "endpoint": newPeer.Endpoint,
			"accessKey": forMember.AccessKey, "secretKey": forMember.SecretKey}, nil); err != nil {
			return err
		}
		if err := s.callJSON(ctx, newPeer.Endpoint, newPeer.AccessKey, newPeer.SecretKey, "/_nanoio/admin/site/peer", map[string]any{
			"id": m.ID, "name": m.Name, "endpoint": m.Endpoint,
			"accessKey": forNew.AccessKey, "secretKey": forNew.SecretKey}, nil); err != nil {
			return err
		}
	}
	c.Peers = append(c.Peers, newPeer)
	return rt.saveConfig(ctx, c)
}

// siteIssueCredential creates (or rotates) the service account a peer uses
// on this site.
func (s *Server) siteIssueCredential(ctx context.Context, peerID string) (struct{ AccessKey, SecretKey string }, error) {
	var out struct{ AccessKey, SecretKey string }
	if s.iamrt == nil {
		return out, errors.New("site replication needs runtime IAM")
	}
	var r [24]byte
	rand.Read(r[:])
	ak := "nanoio-site-" + peerID
	sk := hex.EncodeToString(r[:])
	now := time.Now().UnixNano()
	pol := &iamDoc{Kind: "policy", Name: siteReplicatorID, Updated: now, Origin: s.clusterID(ctx),
		Policy: json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:*","nanoio:SiteReplicate"],"Resource":["*"]}]}`)}
	if _, err := s.iamrt.apply(siteApplying(ctx), pol, true); err != nil {
		return out, err
	}
	u := &iamDoc{Kind: "user", Name: ak, Updated: now, Origin: s.clusterID(ctx),
		User: &iam.UserEntry{AccessKey: ak, SecretKey: sk, Policies: []string{siteReplicatorID}}}
	if _, err := s.iamrt.apply(siteApplying(ctx), u, true); err != nil {
		return out, err
	}
	// Wait for this node's store to serve the new credential before it is
	// handed out.
	return struct{ AccessKey, SecretKey string }{ak, sk}, nil
}

func (s *Server) siteIssue(q *request) {
	if q.r.Method != http.MethodPost {
		s.fail(q, errBadMethod)
		return
	}
	if !s.siteAuthorized(q, "nanoio:SiteManage") {
		return
	}
	body, err := s.readBody(q, 16<<10)
	if err != nil {
		s.fail(q, err)
		return
	}
	var in struct {
		PeerID string `json:"peerID"`
	}
	if json.Unmarshal(body, &in) != nil || in.PeerID == "" {
		s.fail(q, invalidArgument("peerID is required"))
		return
	}
	cred, err := s.siteIssueCredential(q.ctx(), in.PeerID)
	if err != nil {
		s.fail(q, err)
		return
	}
	writeJSON(q.w, cred)
}

// siteAuthorized allows the root credential, or a site service account for
// the replication verbs. It writes the refusal.
func (s *Server) siteAuthorized(q *request, action string) bool {
	if s.allowed(q, action, "", "") || s.allowed(q, "nanoio:SiteReplicate", "", "") {
		return true
	}
	s.fail(q, errAccessDenied)
	return false
}

func (s *Server) sitePeerHandler(q *request) {
	if q.r.Method != http.MethodPost {
		s.fail(q, errBadMethod)
		return
	}
	if !s.siteAuthorized(q, "nanoio:SiteManage") {
		return
	}
	body, err := s.readBody(q, 16<<10)
	if err != nil {
		s.fail(q, err)
		return
	}
	var in struct {
		sitePeer
		SelfName     string `json:"selfName"`
		SelfEndpoint string `json:"selfEndpoint"`
	}
	if json.Unmarshal(body, &in) != nil || in.ID == "" || in.Endpoint == "" || in.AccessKey == "" {
		s.fail(q, invalidArgument("id, endpoint and accessKey are required"))
		return
	}
	ctx := q.ctx()
	c := s.site.config(ctx)
	if c == nil {
		c = &siteConfig{ID: s.clusterID(ctx)}
	}
	if in.SelfName != "" {
		c.Name = in.SelfName
	}
	if in.SelfEndpoint != "" {
		c.Endpoint = in.SelfEndpoint
	}
	p := in.sitePeer
	p.Added = time.Now().UTC()
	replaced := false
	for i := range c.Peers {
		if c.Peers[i].ID == p.ID {
			c.Peers[i] = p
			replaced = true
		}
	}
	if !replaced {
		c.Peers = append(c.Peers, p)
	}
	if err := s.site.saveConfig(ctx, c); err != nil {
		s.fail(q, err)
		return
	}
	s.site.signal()
	q.w.WriteHeader(http.StatusNoContent)
}

func (s *Server) siteRemove(q *request) {
	if q.r.Method != http.MethodPost && q.r.Method != http.MethodDelete {
		s.fail(q, errBadMethod)
		return
	}
	if !s.siteAuthorized(q, "nanoio:SiteManage") {
		return
	}
	id := q.query.Get("id")
	ctx := q.ctx()
	c := s.site.config(ctx)
	if c == nil {
		s.fail(q, &APIError{"NoSuchSite", "This site is not part of a group.", http.StatusNotFound})
		return
	}
	// A call that came from a peer is the other members hearing about it;
	// an operator's call is relayed to everyone.
	fromPeer := strings.HasPrefix(q.who, "nanoio-site-")
	var keep []sitePeer
	var gone *sitePeer
	for i := range c.Peers {
		if c.Peers[i].ID == id {
			gone = &c.Peers[i]
			continue
		}
		keep = append(keep, c.Peers[i])
	}
	if gone == nil && id != "" {
		s.fail(q, &APIError{"NoSuchSite", "No such member.", http.StatusNotFound})
		return
	}
	if id == "" { // leave the group entirely
		keep = nil
	}
	if !fromPeer {
		for _, m := range c.Peers {
			if m.ID == id || id == "" {
				continue
			}
			s.site.post(ctx, &m, "/_nanoio/admin/site/remove?id="+url.QueryEscape(id), nil)
		}
		if gone != nil {
			s.site.post(ctx, gone, "/_nanoio/admin/site/remove?id="+url.QueryEscape(c.ID), nil)
		}
	}
	c.Peers = keep
	if err := s.site.saveConfig(ctx, c); err != nil {
		s.fail(q, err)
		return
	}
	if gone != nil {
		s.iamrt.apply(siteApplying(ctx), &iamDoc{Kind: "user", Name: "nanoio-site-" + gone.ID, Deleted: true,
			Updated: time.Now().UnixNano(), Origin: c.ID}, true)
	}
	s.site.signal()
	q.w.WriteHeader(http.StatusNoContent)
}

func (s *Server) siteApply(q *request) {
	if q.r.Method != http.MethodPost {
		s.fail(q, errBadMethod)
		return
	}
	if !s.authorize(q, "nanoio:SiteReplicate", "", "", nil) {
		return
	}
	body, err := s.readBody(q, 32<<20)
	if err != nil {
		s.fail(q, err)
		return
	}
	var ch siteChange
	if err := json.Unmarshal(body, &ch); err != nil || ch.Kind == "" || ch.Name == "" {
		s.fail(q, invalidArgument("invalid change"))
		return
	}
	if err := s.applyChange(q.ctx(), &ch); err != nil {
		s.log.Warn("site: cannot apply a peer's change", "kind", ch.Kind, "name", ch.Name, "err", err)
		s.fail(q, &APIError{"InternalError", err.Error(), http.StatusInternalServerError})
		return
	}
	q.w.WriteHeader(http.StatusNoContent)
}

func (s *Server) siteState(q *request) {
	if q.r.Method != http.MethodGet {
		s.fail(q, errBadMethod)
		return
	}
	if !s.authorize(q, "nanoio:SiteReplicate", "", "", nil) {
		return
	}
	st, err := s.site.localState(q.ctx())
	if err != nil {
		s.fail(q, err)
		return
	}
	if st == nil {
		st = []stateEntry{}
	}
	writeJSON(q.w, st)
}

type sitePeerStatus struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Endpoint  string    `json:"endpoint"`
	Online    bool      `json:"online"`
	Queued    int       `json:"queued"`
	LastOK    time.Time `json:"lastSuccess,omitempty"`
	LastError string    `json:"lastError,omitempty"`
}

func (s *Server) siteStatus(q *request) {
	if q.r.Method != http.MethodGet {
		s.fail(q, errBadMethod)
		return
	}
	if !s.authorize(q, "nanoio:SiteReplicate", "", "", nil) {
		return
	}
	ctx := q.ctx()
	c := s.site.config(ctx)
	out := struct {
		ID        string           `json:"id"`
		Name      string           `json:"name"`
		Enabled   bool             `json:"enabled"`
		Peers     []sitePeerStatus `json:"peers"`
		Conflicts []siteConflict   `json:"conflicts"`
	}{ID: s.clusterID(ctx), Peers: []sitePeerStatus{}, Conflicts: []siteConflict{}}
	if c != nil {
		out.Name, out.Enabled = c.Name, len(c.Peers) > 0
		for _, p := range c.Peers {
			st := sitePeerStatus{ID: p.ID, Name: p.Name, Endpoint: p.Endpoint}
			if q, err := s.site.queueFor(p.ID); err == nil {
				st.Queued = q.Len()
			}
			pc, cancel := context.WithTimeout(ctx, 5*time.Second)
			var info siteInfo
			err := s.callJSON(pc, p.Endpoint, p.AccessKey, p.SecretKey, "/_nanoio/admin/site/info", nil, &info)
			cancel()
			st.Online = err == nil
			s.site.mu.Lock()
			st.LastOK, st.LastError = s.site.lastOK[p.ID], s.site.lastErr[p.ID]
			s.site.mu.Unlock()
			if err != nil && st.LastError == "" {
				st.LastError = err.Error()
			}
			out.Peers = append(out.Peers, st)
		}
	}
	s.site.mu.Lock()
	out.Conflicts = append(out.Conflicts, s.site.conflicts...)
	s.site.mu.Unlock()
	writeJSON(q.w, out)
}

// siteResync pushes this site's state to every peer now. With
// ?authoritative=true every entity is re-stamped with the present time
// first, so that this site's version wins everywhere: the operator's tool
// for declaring one site correct after a split brain.
func (s *Server) siteResync(q *request) {
	if q.r.Method != http.MethodPost {
		s.fail(q, errBadMethod)
		return
	}
	if !s.authorize(q, "nanoio:SiteManage", "", "", nil) {
		return
	}
	ctx := q.ctx()
	if q.query.Get("authoritative") == "true" {
		n, err := s.siteRestamp(ctx)
		if err != nil {
			s.fail(q, err)
			return
		}
		s.site.reconcile(ctx)
		writeJSON(q.w, map[string]any{"restamped": n})
		return
	}
	s.site.reconcile(ctx)
	writeJSON(q.w, map[string]any{"restamped": 0})
}

// siteRestamp gives every replicated entity a fresh stamp from this site.
func (s *Server) siteRestamp(ctx context.Context) (int, error) {
	rt := s.site
	st, err := rt.localState(ctx)
	if err != nil {
		return 0, err
	}
	id, now := s.clusterID(ctx), time.Now().UnixNano()
	n := 0
	for i, e := range st {
		ts := now + int64(i)
		switch e.Kind {
		case "iam":
			d, err := rt.s.iamrt.readDoc(ctx, e.Name)
			if err != nil || d == nil {
				continue
			}
			d.Updated, d.Origin = ts, id
			if b, err := json.Marshal(d); err == nil {
				rt.es.Put(ctx, e.Name, b)
			}
		default:
			rt.putStamp(ctx, e.Kind, e.Name, siteStamp{Updated: ts, Origin: id, Deleted: e.Deleted})
		}
		n++
	}
	if s.iamrt != nil {
		rt.es.Put(ctx, iamVersionKey, []byte(fmt.Sprint(now)))
	}
	return n, nil
}
