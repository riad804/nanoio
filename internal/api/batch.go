package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"nanoio/internal/batch"
	"nanoio/internal/event"
	"nanoio/internal/kms"
	"nanoio/internal/sse"
	"nanoio/internal/storage"
	"nanoio/internal/tier"
)

// BatchOptions turns on the batch-job runner on this node.
type BatchOptions struct {
	// Locker is the cluster lock tasks and coordinators are claimed with.
	Locker storage.Locker
	// Workers is the tasks this node runs at once (default 2); TaskItems
	// the objects per task (default 200); Tick the idle poll (default 1s).
	Workers   int
	TaskItems int
	Tick      time.Duration
	Clock     batch.Clock
}

// batchStore adapts the system-bucket store to batch.Store.
type batchStore struct{ es *eventStore }

func (b batchStore) Put(ctx context.Context, name string, data []byte) error {
	return b.es.Put(ctx, name, data)
}

func (b batchStore) Get(ctx context.Context, name string) ([]byte, error) {
	d, err := b.es.Get(ctx, name)
	if errors.Is(err, event.ErrSharedNotFound) {
		return nil, batch.ErrNotFound
	}
	return d, err
}

func (b batchStore) Delete(ctx context.Context, name string) error { return b.es.Delete(ctx, name) }

func (b batchStore) List(ctx context.Context, prefix string, max int) ([]string, error) {
	return b.es.List(ctx, prefix, max)
}

// tryLocker turns the blocking namespace lock into the non-blocking claim
// the batch runner wants: a lock that cannot be had within a moment is
// someone else's.
type tryLocker struct {
	l storage.Locker
}

func (t tryLocker) TryLock(ctx context.Context, name string) (func(), bool, error) {
	cctx, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
	defer cancel()
	unlock, err := t.l.Lock(cctx, sysBucket, "_batchlock/"+name)
	if err != nil {
		if ctx.Err() != nil {
			return nil, false, ctx.Err()
		}
		return nil, false, nil
	}
	return unlock, true, nil
}

func (s *Server) startBatch(o *BatchOptions) error {
	ops := map[string]batch.Operation{
		batch.TypeExpire:    &expireOp{s},
		batch.TypeKeyRotate: &keyRotateOp{s},
		batch.TypeReplicate: &replicateOp{s: s, clients: map[string]*tier.S3Client{}},
	}
	m, err := batch.NewManager(batch.Options{
		Store: batchStore{&eventStore{st: s.st}}, Locker: tryLocker{o.Locker}, Ops: ops, Clock: o.Clock,
		Node: s.nodeName(), Workers: o.Workers, TaskItems: o.TaskItems, Tick: o.Tick, Log: s.log,
	})
	if err != nil {
		return err
	}
	s.batch = m
	ctx, cancel := context.WithCancel(context.Background())
	s.stop = append(s.stop, cancel)
	s.bg.Add(1)
	go func() {
		defer s.bg.Done()
		m.Run(ctx)
	}()
	return nil
}

func (s *Server) nodeName() string {
	if s.nodeID != "" {
		return s.nodeID
	}
	return "node"
}

// ----- shared helpers ----------------------------------------------------

// cursor is the position in a version listing.
type cursor struct {
	Marker  string `json:"m,omitempty"`
	Version string `json:"v,omitempty"`
}

func (c cursor) String() string {
	if c.Marker == "" && c.Version == "" {
		return ""
	}
	b, _ := json.Marshal(c)
	return string(b)
}

func parseCursor(s string) (cursor, error) {
	var c cursor
	if s == "" {
		return c, nil
	}
	return c, json.Unmarshal([]byte(s), &c)
}

// maxPagesPerEnumerate bounds one Enumerate call when a filter rejects most
// of what it lists, so a sparse match still makes steady progress.
const maxPagesPerEnumerate = 20

// scanVersions walks a bucket's version listing from cur, handing each entry
// to take until max items are collected, the listing ends, or the page
// budget is spent. It returns the cursor to resume from ("" at the end).
func (s *Server) scanVersions(ctx context.Context, bucket, prefix string, cur cursor, max int,
	take func(v storage.ObjectInfo) (batch.Item, bool)) ([]batch.Item, string, error) {
	var items []batch.Item
	opts := storage.ListOptions{Prefix: prefix, Marker: cur.Marker, VersionIDMarker: cur.Version, MaxKeys: 1000}
	for pages := 0; pages < maxPagesPerEnumerate; pages++ {
		page, err := s.st.ListObjectVersions(ctx, bucket, opts)
		if err != nil {
			return nil, "", err
		}
		for i, v := range page.Versions {
			if it, ok := take(v); ok {
				items = append(items, it)
				if len(items) >= max {
					// Resume right after this entry.
					if i == len(page.Versions)-1 && !page.IsTruncated {
						return items, "", nil
					}
					return items, cursor{Marker: v.Name, Version: v.VersionID}.String(), nil
				}
			}
		}
		if !page.IsTruncated {
			return items, "", nil
		}
		opts.Marker, opts.VersionIDMarker = page.NextMarker, page.NextVersionIDMarker
	}
	return items, cursor{Marker: opts.Marker, Version: opts.VersionIDMarker}.String(), nil
}

// batchEvent publishes an event for a change a batch job made.
func (s *Server) batchEvent(name, bucket string, info storage.ObjectInfo, version string) {
	if s.events == nil {
		return
	}
	s.events.Publish(&event.Event{Name: name, Bucket: bucket, Key: info.Name, VersionID: version, ETag: info.ETag,
		Size: info.Size, Principal: "nanoio:batch", Region: s.region, Time: time.Now().UTC()})
}

// ----- expire ------------------------------------------------------------------

type expireOp struct{ s *Server }

func (o *expireOp) Enumerate(ctx context.Context, def *batch.Definition, cur string, max int, now time.Time) ([]batch.Item, string, error) {
	e := def.Expire
	c, err := parseCursor(cur)
	if err != nil {
		return nil, "", err
	}
	// Collect each key's versions together, because "latest" and
	// "noncurrent" are properties of a version within its key.
	return o.s.scanVersions(ctx, e.Bucket, e.Prefix, c, max, func(v storage.ObjectInfo) (batch.Item, bool) {
		switch e.Versions {
		case "latest":
			if !v.IsLatest || v.DeleteMarker {
				return batch.Item{}, false
			}
		case "noncurrent":
			if v.IsLatest {
				return batch.Item{}, false
			}
		}
		if !e.Filter.Matches(v.ModTime, v.Size, decodeTags(v.UserDefined), now) {
			return batch.Item{}, false
		}
		return batch.Item{Bucket: e.Bucket, Key: v.Name, VersionID: v.VersionID, Size: v.Size}, true
	})
}

func (o *expireOp) Do(ctx context.Context, def *batch.Definition, it batch.Item) (batch.ItemResult, error) {
	e := def.Expire
	opts := storage.DeleteOptions{}
	name := event.ObjectRemovedDelete
	if e.Versions != "latest" {
		opts.VersionID = it.VersionID
	}
	res, err := o.s.st.DeleteObject(ctx, it.Bucket, it.Key, opts)
	switch {
	case err == nil:
	case errors.Is(err, storage.ErrObjectNotFound), errors.Is(err, storage.ErrVersionNotFound):
		return batch.ItemResult{Skipped: true}, nil
	case errors.Is(err, storage.ErrObjectLocked):
		return batch.ItemResult{Skipped: true}, nil // object lock outranks a batch job
	default:
		return batch.ItemResult{}, err
	}
	version := opts.VersionID
	if opts.VersionID == "" && res.DeleteMarker {
		name, version = event.ObjectRemovedDeleteMarkerCreated, res.VersionID
	}
	o.s.batchEvent(name, it.Bucket, storage.ObjectInfo{Name: it.Key, Size: it.Size}, version)
	return batch.ItemResult{Bytes: it.Size}, nil
}

// ----- key rotation --------------------------------------------------------

type keyRotateOp struct{ s *Server }

func (o *keyRotateOp) wantMode(def *batch.Definition) sse.Mode {
	if def.KeyRotate.Encryption.Type == "sse-s3" {
		return sse.ModeS3
	}
	return sse.ModeKMS
}

func (o *keyRotateOp) Enumerate(ctx context.Context, def *batch.Definition, cur string, max int, now time.Time) ([]batch.Item, string, error) {
	k := def.KeyRotate
	if o.s.kms == nil {
		return nil, "", errors.New("this server has no KMS configured, so there is nothing to rotate")
	}
	c, err := parseCursor(cur)
	if err != nil {
		return nil, "", err
	}
	want := o.wantMode(def)
	return o.s.scanVersions(ctx, k.Bucket, k.Prefix, c, max, func(v storage.ObjectInfo) (batch.Item, bool) {
		if v.DeleteMarker {
			return batch.Item{}, false
		}
		m, enc, err := sse.ParseMeta(v.UserDefined)
		if err != nil || !enc || m.Mode != want {
			return batch.Item{}, false
		}
		if !k.Filter.Matches(v.ModTime, v.Size, decodeTags(v.UserDefined), now) {
			return batch.Item{}, false
		}
		return batch.Item{Bucket: k.Bucket, Key: v.Name, VersionID: v.VersionID, Size: v.Size}, true
	})
}

func (o *keyRotateOp) Do(ctx context.Context, def *batch.Definition, it batch.Item) (batch.ItemResult, error) {
	k := def.KeyRotate
	s := o.s
	info, err := s.st.StatObject(ctx, it.Bucket, it.Key, storage.GetOptions{VersionID: it.VersionID})
	switch {
	case errors.Is(err, storage.ErrObjectNotFound), errors.Is(err, storage.ErrVersionNotFound):
		return batch.ItemResult{Skipped: true}, nil
	case err != nil:
		return batch.ItemResult{}, err
	}
	m, enc, err := sse.ParseMeta(info.UserDefined)
	if err != nil {
		return batch.ItemResult{}, err
	}
	if !enc || m.Mode != o.wantMode(def) {
		return batch.ItemResult{Skipped: true}, nil
	}
	target := k.Encryption.Key
	if m.Mode == sse.ModeS3 {
		target = s.defaultKey
	}
	desc, err := s.kms.DescribeKey(ctx, target)
	if err != nil {
		return batch.ItemResult{}, err
	}
	if m.KeyID == target && (desc.LatestVersion == 0 || m.KeyVersion == desc.LatestVersion) {
		return batch.ItemResult{Skipped: true}, nil
	}
	nm, err := sse.RewrapKMS(ctx, s.kms, m, it.Bucket+"/"+it.Key, target)
	if err != nil {
		return batch.ItemResult{}, err
	}
	ud := make(map[string]string, len(info.UserDefined))
	for k, v := range info.UserDefined {
		ud[k] = v
	}
	nm.Put(ud)
	_, err = s.st.UpdateObjectMetadata(ctx, it.Bucket, it.Key, storage.UpdateMetaOptions{
		VersionID: it.VersionID, UserDefined: ud, IfETag: info.ETag,
	})
	switch {
	case errors.Is(err, storage.ErrPreconditionFailed), errors.Is(err, storage.ErrObjectNotFound), errors.Is(err, storage.ErrVersionNotFound):
		return batch.ItemResult{Skipped: true}, nil // rewritten or removed meanwhile
	case err != nil:
		return batch.ItemResult{}, err
	}
	return batch.ItemResult{}, nil
}

// ----- replicate ----------------------------------------------------------------

type replicateOp struct {
	s       *Server
	mu      sync.Mutex
	clients map[string]*tier.S3Client
}

func (o *replicateOp) client(t batch.Target) (*tier.S3Client, error) {
	sum := sha256.Sum256([]byte(t.Endpoint + "\x00" + t.Bucket + "\x00" + t.Prefix + "\x00" + t.Region + "\x00" +
		t.Credentials.AccessKey + "\x00" + t.Credentials.SecretKey))
	key := hex.EncodeToString(sum[:8])
	o.mu.Lock()
	defer o.mu.Unlock()
	if c := o.clients[key]; c != nil {
		return c, nil
	}
	c, err := tier.NewS3Client(tier.S3Config{Endpoint: t.Endpoint, Region: t.Region, Bucket: t.Bucket, Prefix: t.Prefix,
		AccessKey: t.Credentials.AccessKey, SecretKey: t.Credentials.SecretKey, InsecureSkipVerify: t.InsecureSkipVerify})
	if err != nil {
		return nil, err
	}
	o.clients[key] = c
	return c, nil
}

func (o *replicateOp) Enumerate(ctx context.Context, def *batch.Definition, cur string, max int, now time.Time) ([]batch.Item, string, error) {
	r := def.Replicate
	c, err := parseCursor(cur)
	if err != nil {
		return nil, "", err
	}
	return o.s.scanVersions(ctx, r.Source.Bucket, r.Source.Prefix, c, max, func(v storage.ObjectInfo) (batch.Item, bool) {
		if !v.IsLatest || v.DeleteMarker {
			return batch.Item{}, false
		}
		if !r.Filter.Matches(v.ModTime, plainSize(v), decodeTags(v.UserDefined), now) {
			return batch.Item{}, false
		}
		return batch.Item{Bucket: r.Source.Bucket, Key: v.Name, VersionID: v.VersionID, Size: plainSize(v)}, true
	})
}

const sourceETagHeader = "x-amz-meta-nanoio-source-etag"

func (o *replicateOp) Do(ctx context.Context, def *batch.Definition, it batch.Item) (batch.ItemResult, error) {
	r := def.Replicate
	cl, err := o.client(r.Target)
	if err != nil {
		return batch.ItemResult{}, err
	}
	rd, info, size, etag, err := o.s.openPlain(ctx, it.Bucket, it.Key, it.VersionID)
	switch {
	case errors.Is(err, storage.ErrObjectNotFound), errors.Is(err, storage.ErrVersionNotFound):
		return batch.ItemResult{Skipped: true}, nil
	case err != nil:
		return batch.ItemResult{}, err
	}
	defer rd.Close()

	// Skip what the target already holds from this exact source version.
	head, err := cl.Head(ctx, it.Key)
	if err != nil {
		return batch.ItemResult{}, err
	}
	if head.Exists && head.Size == size && head.Headers.Get(sourceETagHeader) == etag {
		return batch.ItemResult{Skipped: true}, nil
	}
	meta := tier.ObjectMeta{ContentType: info.ContentType, Headers: map[string]string{sourceETagHeader: etag}}
	for k, v := range info.UserDefined {
		if strings.HasPrefix(k, userMetaPrefix) {
			meta.Headers[k] = v
		}
	}
	for _, h := range systemHeaders {
		if v := info.UserDefined[strings.ToLower(h)]; v != "" {
			meta.Headers[h] = v
		}
	}
	if tags := decodeTags(info.UserDefined); len(tags) > 0 {
		q := url.Values{}
		for k, v := range tags {
			q.Set(k, v)
		}
		meta.Tagging = q.Encode()
	}
	if _, _, err := cl.PutObject(ctx, it.Key, rd, size, meta); err != nil {
		return batch.ItemResult{}, err
	}
	return batch.ItemResult{Bytes: size}, nil
}

// openPlain opens a version's plaintext: through its tier if transitioned,
// decrypting SSE-S3 and SSE-KMS (SSE-C objects cannot be read without the
// client's key and are refused).
func (s *Server) openPlain(ctx context.Context, bucket, key, versionID string) (io.ReadCloser, storage.ObjectInfo, int64, string, error) {
	rc, info, err := s.openObject(ctx, bucket, key, storage.GetOptions{VersionID: versionID})
	if err != nil {
		return nil, info, 0, "", err
	}
	m, enc, err := sse.ParseMeta(info.UserDefined)
	if err != nil {
		rc.Close()
		return nil, info, 0, "", err
	}
	if !enc {
		return rc, info, info.Size, info.ETag, nil
	}
	if m.Mode == sse.ModeC {
		rc.Close()
		return nil, info, 0, "", errors.New("the object is encrypted with a customer-provided key and cannot be replicated")
	}
	if s.kms == nil {
		rc.Close()
		return nil, info, 0, "", sse.ErrNoKMS
	}
	path := bucket + "/" + key
	objKey, err := sse.OpenObjectKey(ctx, s.kms, m, path, nil)
	if err != nil {
		rc.Close()
		return nil, info, 0, "", err
	}
	layout := layoutOf(info)
	size, err := layout.PlainSize()
	if err != nil {
		kms.Zero(objKey)
		rc.Close()
		return nil, info, 0, "", err
	}
	etag := info.ETag
	if len(m.ETag) > 0 {
		d, err := sse.UnsealETag(objKey, path, m.ETag)
		if err != nil {
			kms.Zero(objKey)
			rc.Close()
			return nil, info, 0, "", err
		}
		etag = hex.EncodeToString(d)
	}
	dec, err := sse.NewDecrypter(rc, layout, objKey, 0, size)
	if err != nil {
		kms.Zero(objKey)
		rc.Close()
		return nil, info, 0, "", err
	}
	return struct {
		io.Reader
		io.Closer
	}{dec, closerFunc(func() error { kms.Zero(objKey); return rc.Close() })}, info, size, etag, nil
}

type closerFunc func() error

func (f closerFunc) Close() error { return f() }

// ----- admin endpoints -------------------------------------------------------------

const batchTemplates = `# NanoIO batch job templates. Start one with: nanoio admin batch-start FILE
#
# replicate: copy the latest version of matching objects to a remote S3 endpoint.
#
# apiVersion: v1
# replicate:
#   source: {bucket: photos, prefix: "2024/"}
#   target:
#     endpoint: https://s3.example.com
#     bucket: photos-backup
#     credentials: {accessKey: AKIA..., secretKey: ...}
#   filter: {olderThan: 7d, tags: [{key: tier, value: gold}]}
#   retry: {attempts: 3, delay: 1s}
#   concurrency: 4
#
# expire: delete matching objects (versions: latest | noncurrent | all).
#
# apiVersion: v1
# expire:
#   bucket: logs
#   prefix: app/
#   versions: latest
#   filter: {olderThan: 90d}
#
# keyrotate: re-wrap data keys of encrypted objects under a new key.
#
# apiVersion: v1
# keyrotate:
#   bucket: secrets
#   encryption: {type: sse-kms, key: new-key-id}
`

func (s *Server) adminBatch(q *request, sub string) {
	if s.batch == nil {
		s.fail(q, notImplemented("batch jobs are not enabled"))
		return
	}
	switch sub {
	case "start":
		s.adminBatchStart(q)
	case "list":
		s.adminBatchList(q)
	case "describe":
		s.adminBatchDescribe(q)
	case "cancel":
		s.adminBatchCancel(q)
	case "template":
		if q.r.Method != http.MethodGet {
			s.fail(q, errBadMethod)
			return
		}
		if !s.authorize(q, "nanoio:ListBatch", "", "", nil) {
			return
		}
		q.w.Header().Set("Content-Type", "text/yaml")
		io.WriteString(q.w, batchTemplates)
	}
}

func (s *Server) adminBatchStart(q *request) {
	if q.r.Method != http.MethodPost && q.r.Method != http.MethodPut {
		s.fail(q, errBadMethod)
		return
	}
	if !s.authorize(q, "nanoio:ManageBatch", "", "", nil) {
		return
	}
	body, err := s.readBody(q, 1<<20+1)
	if err != nil {
		s.fail(q, err)
		return
	}
	def, err := batch.Parse(body)
	if err != nil {
		s.fail(q, invalidArgument(err.Error()))
		return
	}
	// The job reads and changes buckets as the server, so the caller must
	// be allowed to do to them what the job will do.
	if aerr := s.authorizeBatch(q, def); aerr {
		return
	}
	id, err := s.batch.Start(q.ctx(), def, q.who)
	if err != nil {
		s.fail(q, err)
		return
	}
	s.log.Info("batch job started", "job", id, "type", def.Type(), "by", q.who)
	q.w.WriteHeader(http.StatusAccepted)
	writeJSON(q.w, map[string]string{"id": id, "type": def.Type()})
}

// authorizeBatch checks, before a job is accepted, the S3 actions it will
// perform on behalf of its owner. It reports true after writing a refusal.
func (s *Server) authorizeBatch(q *request, def *batch.Definition) bool {
	check := func(action, bucket string) bool {
		if s.allowed(q, action, bucket, "") {
			return true
		}
		s.fail(q, errAccessDenied)
		return false
	}
	switch {
	case def.Replicate != nil:
		return !(check("s3:ListBucket", def.Replicate.Source.Bucket) && check("s3:GetObject", def.Replicate.Source.Bucket))
	case def.Expire != nil:
		b := def.Expire.Bucket
		action := "s3:DeleteObject"
		if def.Expire.Versions != "latest" {
			action = "s3:DeleteObjectVersion"
		}
		return !(check("s3:ListBucket", b) && check(action, b))
	case def.KeyRotate != nil:
		b := def.KeyRotate.Bucket
		return !(check("s3:ListBucket", b) && check("s3:PutObject", b))
	}
	return true
}

func (s *Server) adminBatchList(q *request) {
	if q.r.Method != http.MethodGet {
		s.fail(q, errBadMethod)
		return
	}
	if !s.authorize(q, "nanoio:ListBatch", "", "", nil) {
		return
	}
	list, err := s.batch.List(q.ctx())
	if err != nil {
		s.fail(q, err)
		return
	}
	if list == nil {
		list = []batch.Status{}
	}
	writeJSON(q.w, redactJobs(list))
}

func (s *Server) adminBatchDescribe(q *request) {
	if q.r.Method != http.MethodGet {
		s.fail(q, errBadMethod)
		return
	}
	if !s.authorize(q, "nanoio:ListBatch", "", "", nil) {
		return
	}
	st, err := s.batch.Describe(q.ctx(), q.query.Get("id"))
	switch {
	case errors.Is(err, batch.ErrNotFound):
		s.fail(q, &APIError{"NoSuchJob", "No batch job with that id exists.", http.StatusNotFound})
	case err != nil:
		s.fail(q, err)
	default:
		writeJSON(q.w, redactJobs([]batch.Status{*st})[0])
	}
}

func (s *Server) adminBatchCancel(q *request) {
	if q.r.Method != http.MethodPost && q.r.Method != http.MethodPut {
		s.fail(q, errBadMethod)
		return
	}
	if !s.authorize(q, "nanoio:ManageBatch", "", "", nil) {
		return
	}
	err := s.batch.Cancel(q.ctx(), q.query.Get("id"))
	switch {
	case errors.Is(err, batch.ErrNotFound):
		s.fail(q, &APIError{"NoSuchJob", "No batch job with that id exists.", http.StatusNotFound})
	case err != nil:
		s.fail(q, invalidRequest(err.Error()))
	default:
		q.w.WriteHeader(http.StatusNoContent)
	}
}

// redactJobs hides target secrets from job definitions in listings.
func redactJobs(in []batch.Status) []batch.Status {
	out := make([]batch.Status, len(in))
	copy(out, in)
	for i := range out {
		var def batch.Definition
		if json.Unmarshal(out[i].Definition, &def) != nil || def.Replicate == nil {
			continue
		}
		def.Replicate.Target.Credentials.SecretKey = "*****"
		if b, err := json.Marshal(def); err == nil {
			out[i].Definition = b
		}
	}
	return out
}
