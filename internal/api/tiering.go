package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"nanoio/internal/event"
	"nanoio/internal/lifecycle"
	"nanoio/internal/storage"
	"nanoio/internal/tier"
)

// TierOptions configures transitions to remote tiers.
type TierOptions struct {
	// Factory builds tier backends (default: the real S3/Azure/GCS ones).
	Factory tier.Factory
	// CacheDir enables the node-local read-through cache of transitioned
	// objects; CacheBytes bounds it (default 1 GiB) and CacheTTL is how
	// long a read-through entry stays (default 24h).
	CacheDir   string
	CacheBytes int64
	CacheTTL   time.Duration
	// Janitor, if set, deletes remote copies of removed stubs. It is
	// shared with the storage backend's OnTransitionFreed callback, which
	// is wired before the API exists.
	Janitor *tier.Janitor
}

var (
	errInvalidObjectState = &APIError{"InvalidObjectState", "The operation is not valid for the object's storage class", http.StatusForbidden}
	errRestoreNotAllowed  = &APIError{"InvalidObjectState", "Restore is not allowed for the object's current storage class", http.StatusForbidden}
)

// tierStore adapts the system-bucket store to tier.Store.
type tierStore struct{ es *eventStore }

func (t tierStore) Put(ctx context.Context, name string, data []byte) error {
	return t.es.Put(ctx, name, data)
}

func (t tierStore) Get(ctx context.Context, name string) ([]byte, error) {
	b, err := t.es.Get(ctx, name)
	if errors.Is(err, event.ErrSharedNotFound) {
		return nil, tier.ErrNotFound
	}
	return b, err
}

func (t tierStore) Delete(ctx context.Context, name string) error { return t.es.Delete(ctx, name) }

func (t tierStore) List(ctx context.Context, prefix string, max int) ([]string, error) {
	return t.es.List(ctx, prefix, max)
}

func (s *Server) initTiers(o *TierOptions) error {
	var factory tier.Factory
	if o != nil {
		factory = o.Factory
	}
	s.tiers = tier.NewManager(tierStore{&eventStore{st: s.st}}, factory)
	s.tierTTL = 24 * time.Hour
	if o == nil {
		return nil
	}
	if o.CacheTTL > 0 {
		s.tierTTL = o.CacheTTL
	}
	if o.CacheDir != "" {
		max := o.CacheBytes
		if max <= 0 {
			max = 1 << 30
		}
		c, err := tier.NewCache(o.CacheDir, max)
		if err != nil {
			return fmt.Errorf("api: tier cache: %w", err)
		}
		s.tcache = c
	}
	if o.Janitor != nil {
		s.janitor = o.Janitor
		o.Janitor.Start(s.tiers)
	}
	return nil
}

func (s *Server) supportsTransition() bool {
	_, ok := s.st.(storage.Transitioner)
	return ok
}

func (s *Server) tierExists(name string) bool { return s.tiers != nil && s.tiers.Exists(name) }

func (s *Server) transitioner() lifecycle.Transitioner {
	if !s.supportsTransition() {
		return nil
	}
	return apiTransitioner{s}
}

// tierOf is the tier a listed version's data lives in.
func tierOf(info storage.ObjectInfo) string {
	if info.Transition != nil {
		return info.Transition.Tier
	}
	return ""
}

// storageClassOf is the class a listing or HEAD reports: the tier name for a
// transitioned version (as S3 reports GLACIER), else the stored class.
func storageClassOf(info storage.ObjectInfo) string {
	if info.Transition != nil {
		return info.Transition.Tier
	}
	return classOrStandard(info.StorageClass)
}

// ----- transition ---------------------------------------------------------

type apiTransitioner struct{ s *Server }

// Transition uploads one version's data to the tier and replaces it with a
// stub. The upload happens first; the stub is committed only if the version
// is still the one that was uploaded, so a concurrent overwrite wins and the
// orphaned remote copy is deleted.
func (t apiTransitioner) Transition(ctx context.Context, bucket, key, versionID, tierName string, size int64) error {
	return t.s.transition(ctx, bucket, key, versionID, tierName)
}

func newUUID() string {
	var b [16]byte
	rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

func (s *Server) transition(ctx context.Context, bucket, key, versionID, tierName string) error {
	tr, ok := s.st.(storage.Transitioner)
	if !ok {
		return storage.ErrNotImplemented
	}
	be, _, err := s.tiers.Get(ctx, tierName)
	if err != nil {
		return fmt.Errorf("tier %s: %w", tierName, err)
	}
	opts := storage.GetOptions{VersionID: versionID}
	// openObject follows an existing stub, so moving a version between tiers
	// is the same upload from a different source.
	rc, info, err := s.openObject(ctx, bucket, key, opts)
	if err != nil {
		return err
	}
	defer rc.Close()
	if info.Transition != nil && info.Transition.Tier == tierName {
		return storage.ErrAlreadyTransitioned
	}
	if info.DeleteMarker {
		return storage.ErrObjectNotFound
	}
	name := tier.ObjectName("", bucket, newUUID())
	vid, err := be.Put(ctx, name, rc, info.Size)
	if err != nil {
		return fmt.Errorf("upload to tier %s: %w", tierName, err)
	}
	ref := storage.ObjectRef{Bucket: bucket, Object: key, VersionID: versionID}
	_, err = tr.TransitionObject(ctx, ref, storage.TransitionInfo{Tier: tierName, Object: name, VersionID: vid, Time: time.Now()}, info.ETag)
	if err != nil {
		// The stub did not land; the uploaded copy is garbage.
		dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		be.Delete(dctx, name, vid)
		cancel()
		return err
	}
	return nil
}

// ----- reading a stub -----------------------------------------------------

// openObject is GetObject that follows a stub to its tier. The returned
// info has Transition set for a stub. The reader supports Seek.
func (s *Server) openObject(ctx context.Context, bucket, key string, opts storage.GetOptions) (io.ReadCloser, storage.ObjectInfo, error) {
	rc, info, err := s.st.GetObject(ctx, bucket, key, opts)
	var te *storage.TransitionedError
	if !errors.As(err, &te) {
		return rc, info, err
	}
	return s.openRemote(ctx, te.Info, opts)
}

func (s *Server) cacheKey(info storage.ObjectInfo) string {
	return tier.Key(info.Bucket, info.Name, info.VersionID, info.ETag)
}

func (s *Server) openRemote(ctx context.Context, info storage.ObjectInfo, opts storage.GetOptions) (io.ReadCloser, storage.ObjectInfo, error) {
	key := s.cacheKey(info)
	var rd io.ReadCloser
	if s.tcache != nil {
		if f, ok := s.tcache.Open(key); ok {
			rd = f
		}
	}
	if rd == nil {
		be, _, err := s.tiers.Get(ctx, info.Transition.Tier)
		if err != nil {
			return nil, storage.ObjectInfo{}, fmt.Errorf("%w: tier %s: %v", storage.ErrBackendUnavailable, info.Transition.Tier, err)
		}
		rr := &remoteReader{ctx: ctx, be: be, tr: info.Transition, size: info.Size}
		if s.tcache != nil && opts.Range == nil && info.Size > 0 && info.Size <= s.tcache.Max()/2 {
			if w, err := s.tcache.Create(key, time.Now().Add(s.tierTTL), false); err == nil {
				rr.cache = w
			}
		}
		rd = rr
	}
	if rg := opts.Range; rg != nil {
		if rg.Start < 0 || rg.Length <= 0 || rg.Start+rg.Length > info.Size {
			rd.Close()
			return nil, storage.ObjectInfo{}, storage.Wrap(storage.ErrInvalidRange, info.Bucket, info.Name)
		}
		sk := rd.(io.Seeker)
		if _, err := sk.Seek(rg.Start, io.SeekStart); err != nil {
			rd.Close()
			return nil, storage.ObjectInfo{}, err
		}
		return struct {
			io.Reader
			io.Closer
		}{io.LimitReader(rd, rg.Length), rd}, info, nil
	}
	return rd, info, nil
}

// remoteReader streams a transitioned object from its tier. It opens the
// remote range lazily at the current position, so a Seek (a range request,
// or a decrypter skipping to a chunk) costs one new request, not a download
// of the skipped bytes. A read of the whole object from the start is teed
// into the local cache.
type remoteReader struct {
	ctx  context.Context
	be   tier.Backend
	tr   *storage.TransitionInfo
	size int64

	pos   int64
	body  io.ReadCloser
	cache *tier.Writer
}

func (r *remoteReader) Read(p []byte) (int, error) {
	if r.pos >= r.size {
		r.finishCache()
		return 0, io.EOF
	}
	if r.body == nil {
		b, err := r.be.Get(r.ctx, r.tr.Object, r.tr.VersionID, r.pos, r.size-r.pos)
		if err != nil {
			return 0, err
		}
		r.body = b
	}
	n, err := r.body.Read(p)
	if n > 0 {
		if r.cache != nil {
			if _, werr := r.cache.Write(p[:n]); werr != nil {
				r.abortCache()
			}
		}
		r.pos += int64(n)
	}
	if err == io.EOF {
		if r.pos < r.size {
			return n, io.ErrUnexpectedEOF
		}
		r.finishCache()
	}
	return n, err
}

func (r *remoteReader) Seek(offset int64, whence int) (int64, error) {
	var abs int64
	switch whence {
	case io.SeekStart:
		abs = offset
	case io.SeekCurrent:
		abs = r.pos + offset
	case io.SeekEnd:
		abs = r.size + offset
	default:
		return 0, errors.New("tier: bad whence")
	}
	if abs < 0 {
		return 0, errors.New("tier: negative seek")
	}
	if abs != r.pos {
		r.abortCache() // only a straight read from byte 0 is cached
		if r.body != nil {
			r.body.Close()
			r.body = nil
		}
		r.pos = abs
	}
	return abs, nil
}

func (r *remoteReader) finishCache() {
	if r.cache != nil {
		w := r.cache
		r.cache = nil
		if err := w.Commit(); err != nil {
			w.Abort()
		}
	}
}

func (r *remoteReader) abortCache() {
	if r.cache != nil {
		r.cache.Abort()
		r.cache = nil
	}
}

func (r *remoteReader) Close() error {
	r.abortCache()
	if r.body != nil {
		return r.body.Close()
	}
	return nil
}

// restoreHeaders sets x-amz-storage-class and, when a local copy exists
// from a restore request, x-amz-restore.
func (s *Server) restoreHeaders(h http.Header, info storage.ObjectInfo) {
	if info.Transition == nil {
		return
	}
	h.Set("x-amz-storage-class", info.Transition.Tier)
	if s.tcache == nil {
		return
	}
	if exp, restored := s.tcache.RestoreExpiry(s.cacheKey(info)); restored {
		h.Set("x-amz-restore", fmt.Sprintf(`ongoing-request="false", expiry-date="%s"`, exp.UTC().Format(http.TimeFormat)))
	}
}

// ----- RestoreObject ----------------------------------------------------------

type restoreRequest struct {
	XMLName xml.Name `xml:"RestoreRequest"`
	Days    int      `xml:"Days"`
}

// restoreObject implements POST /bucket/key?restore: it brings a
// transitioned object's data into the local cache for Days days. NanoIO
// restores synchronously; the answer is 202 when a restore was done and
// 200 when a still-valid one was merely extended, as S3 does.
func (s *Server) restoreObject(q *request) {
	if q.r.Method != http.MethodPost {
		s.fail(q, errBadMethod)
		return
	}
	if !s.authorize(q, "s3:RestoreObject", q.bucket, q.key, nil) {
		return
	}
	body, err := s.readBody(q, 64<<10)
	if err != nil {
		s.fail(q, err)
		return
	}
	days := 1
	if len(body) > 0 {
		var req restoreRequest
		if err := xml.Unmarshal(body, &req); err != nil || req.Days < 1 || req.Days > 365 {
			s.fail(q, errMalformedXML)
			return
		}
		days = req.Days
	}
	ctx := q.ctx()
	info, err := s.st.StatObject(ctx, q.bucket, q.key, storage.GetOptions{VersionID: q.query.Get("versionId")})
	if err != nil {
		s.fail(q, err)
		return
	}
	if info.Transition == nil || info.DeleteMarker {
		s.fail(q, errRestoreNotAllowed)
		return
	}
	if s.tcache == nil || info.Size > s.tcache.Max() {
		s.fail(q, &APIError{"InvalidRequest", "This server has no restore cache large enough for the object.", http.StatusBadRequest})
		return
	}
	key := s.cacheKey(info)
	expiry := time.Now().Add(time.Duration(days) * 24 * time.Hour)
	status := http.StatusAccepted
	if _, restored := s.tcache.RestoreExpiry(key); restored {
		status = http.StatusOK
	}
	s.notify(q, event.ObjectRestorePost, objectFromInfo(info, q.key, ""))
	// The source is the local copy if a read already cached one, else the
	// tier.
	var rc io.ReadCloser
	if f, ok := s.tcache.Open(key); ok {
		rc = f
	} else {
		be, _, err := s.tiers.Get(ctx, info.Transition.Tier)
		if err != nil {
			s.fail(q, fmt.Errorf("%w: tier %s: %v", storage.ErrBackendUnavailable, info.Transition.Tier, err))
			return
		}
		if rc, err = be.Get(ctx, info.Transition.Object, info.Transition.VersionID, 0, -1); err != nil {
			s.fail(q, fmt.Errorf("%w: reading from tier %s: %v", storage.ErrBackendUnavailable, info.Transition.Tier, err))
			return
		}
	}
	defer rc.Close()
	w, err := s.tcache.Create(key, expiry, true)
	if err != nil {
		s.fail(q, err)
		return
	}
	n, err := io.Copy(w, rc)
	if err == nil && n != info.Size {
		err = io.ErrUnexpectedEOF
	}
	if err != nil {
		w.Abort()
		s.fail(q, fmt.Errorf("%w: restoring from tier %s: %v", storage.ErrBackendUnavailable, info.Transition.Tier, err))
		return
	}
	if err := w.Commit(); err != nil {
		s.fail(q, err)
		return
	}
	s.notify(q, event.ObjectRestoreCompleted, objectFromInfo(info, q.key, ""))
	q.w.WriteHeader(status)
}

// ----- admin: tiers --------------------------------------------------------

func (s *Server) adminTier(q *request) {
	switch q.r.Method {
	case http.MethodGet:
		s.adminTierList(q)
	case http.MethodPut, http.MethodPost:
		s.adminTierAdd(q)
	case http.MethodDelete:
		s.adminTierRemove(q)
	default:
		s.fail(q, errBadMethod)
	}
}

func (s *Server) adminTierList(q *request) {
	if !s.authorize(q, "nanoio:ListTiers", "", "", nil) {
		return
	}
	list, err := s.tiers.List(q.ctx())
	if err != nil {
		s.fail(q, err)
		return
	}
	if list == nil {
		list = []tier.Config{}
	}
	writeJSON(q.w, list)
}

// adminTierAdd registers (PUT) or, with ?update=true, changes the
// credentials of (the equivalent of `mc ilm tier edit`) a tier. The body is
// a tier.Config JSON document. The tier is verified (write, read, delete of
// a probe object) unless ?check=false.
func (s *Server) adminTierAdd(q *request) {
	if !s.authorize(q, "nanoio:ManageTiers", "", "", nil) {
		return
	}
	if !s.supportsTransition() {
		s.fail(q, &APIError{"NotImplemented", "This storage backend cannot hold transitioned objects (use the erasure-coded or cluster backend).", http.StatusNotImplemented})
		return
	}
	body, err := s.readBody(q, 256<<10)
	if err != nil {
		s.fail(q, err)
		return
	}
	var cfg tier.Config
	if err := json.Unmarshal(body, &cfg); err != nil {
		s.fail(q, invalidArgument("The tier configuration is not valid JSON: "+err.Error()))
		return
	}
	check := q.query.Get("check") != "false"
	if q.query.Get("update") == "true" {
		err = s.tiers.Edit(q.ctx(), cfg)
	} else {
		err = s.tiers.Add(q.ctx(), cfg, check)
	}
	switch {
	case err == nil:
		q.w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, tier.ErrExists):
		s.fail(q, &APIError{"TierAlreadyExists", err.Error(), http.StatusConflict})
	case errors.Is(err, tier.ErrNotFound):
		s.fail(q, &APIError{"NoSuchTier", "No tier with that name exists.", http.StatusNotFound})
	default:
		s.fail(q, invalidArgument(err.Error()))
	}
}

func (s *Server) adminTierRemove(q *request) {
	if !s.authorize(q, "nanoio:ManageTiers", "", "", nil) {
		return
	}
	name := q.query.Get("name")
	if name == "" {
		s.fail(q, invalidArgument("name is required"))
		return
	}
	if q.query.Get("force") != "true" {
		// Refuse while a lifecycle rule still transitions to it. Stubs
		// already written cannot be counted cheaply; force overrides.
		buckets, err := s.st.ListBuckets(q.ctx())
		if err != nil {
			s.fail(q, err)
			return
		}
		for _, b := range buckets {
			if b.Name == sysBucket {
				continue
			}
			cfg, err := s.lifecycleConfig(q.ctx(), b.Name)
			if err != nil {
				s.fail(q, err)
				return
			}
			if cfg == nil {
				continue
			}
			for _, t := range cfg.Tiers() {
				if t == name {
					s.fail(q, &APIError{"TierInUse", "Bucket " + b.Name + " has a lifecycle rule that transitions to tier " + name +
						". Remove the rule first, or pass force=true (objects already transitioned become unreadable).", http.StatusConflict})
					return
				}
			}
		}
	}
	switch err := s.tiers.Remove(q.ctx(), name); {
	case err == nil:
		q.w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, tier.ErrNotFound):
		s.fail(q, &APIError{"NoSuchTier", "No tier with that name exists.", http.StatusNotFound})
	default:
		s.fail(q, err)
	}
}

// adminTierCheck serves GET /_nanoio/admin/tier/check?name=: a live probe.
func (s *Server) adminTierCheck(q *request) {
	if q.r.Method != http.MethodGet {
		s.fail(q, errBadMethod)
		return
	}
	if !s.authorize(q, "nanoio:ListTiers", "", "", nil) {
		return
	}
	ctx, cancel := context.WithTimeout(q.ctx(), 30*time.Second)
	defer cancel()
	be, _, err := s.tiers.Get(ctx, q.query.Get("name"))
	if errors.Is(err, tier.ErrNotFound) {
		s.fail(q, &APIError{"NoSuchTier", "No tier with that name exists.", http.StatusNotFound})
		return
	}
	if err != nil {
		s.fail(q, err)
		return
	}
	out := struct {
		Name   string `json:"name"`
		Online bool   `json:"online"`
		Error  string `json:"error,omitempty"`
	}{Name: q.query.Get("name"), Online: true}
	if err := be.Check(ctx); err != nil {
		out.Online, out.Error = false, err.Error()
	}
	writeJSON(q.w, out)
}
