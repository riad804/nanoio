// Package cluster composes erasure sets into one storage.StorageAPI: it
// places objects on sets with a consistent-hash ring, routes multipart
// calls to the set that owns the upload, merges listings across sets under
// an explicit timeout and partial-result policy, and drains pools.
//
// See docs/cluster-operations.md for the contract this implements.
package cluster

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"nanoio/internal/storage"
	"nanoio/internal/storage/internal/listing"
	"nanoio/internal/storage/xl"
)

// Set is one erasure set as the Store sees it; *xl.XL implements it.
type Set interface {
	storage.StorageAPI
	Scan(ctx context.Context, deep bool) (xl.ScanStats, error)
	OnlineDrives() int
	Layout() (data, parity int, blockSize int64)
}

// Pool is a group of sets added together. A draining pool takes no new
// objects.
type Pool struct {
	Name     string
	Draining bool
	Sets     []Set
}

// Options configures a Store.
type Options struct {
	Logger *slog.Logger
	// ListTimeout bounds each set's part of a LIST. 0 means 10 seconds.
	ListTimeout time.Duration
	// AllowPartialList returns what the answering sets have, marked
	// Incomplete, instead of failing the LIST when a set cannot answer.
	AllowPartialList bool
	// VirtualPoints per set on the ring; 0 means DefaultVirtualPoints.
	VirtualPoints int
	// BucketSync is the period of the pass that creates buckets missing on
	// some set (a newly added pool). 0 means one minute; negative disables
	// the background pass (EnsureBuckets can still be called).
	BucketSync time.Duration
}

// Store is a storage.StorageAPI over every set of every pool.
type Store struct {
	sets    []Set
	setPool []int
	setID   []string
	pools   []Pool
	opts    Options
	log     *slog.Logger

	ring     *Ring
	ringSets []int // ring index -> global set index (sets of non-draining pools)
	multi    bool  // more than one pool: objects may not be where the ring says

	stop chan struct{}
	done chan struct{}
	once sync.Once
}

var _ storage.StorageAPI = (*Store)(nil)

// ErrNoPlacement means every pool is draining, so nothing can take writes.
var ErrNoPlacement = errors.New("cluster: no pool accepts new objects")

// New builds a Store. Pool and set order is identity: pools may be appended,
// never reordered or removed.
func New(pools []Pool, opts Options) (*Store, error) {
	if len(pools) == 0 {
		return nil, errors.New("cluster: no pools")
	}
	if opts.ListTimeout <= 0 {
		opts.ListTimeout = 10 * time.Second
	}
	if opts.BucketSync == 0 {
		opts.BucketSync = time.Minute
	}
	s := &Store{pools: pools, opts: opts, log: opts.Logger, multi: len(pools) > 1,
		stop: make(chan struct{}), done: make(chan struct{})}
	if s.log == nil {
		s.log = slog.Default()
	}
	var ringIDs []string
	for pi, p := range pools {
		if len(p.Sets) == 0 {
			return nil, fmt.Errorf("cluster: pool %d has no sets", pi)
		}
		for si, set := range p.Sets {
			g := len(s.sets)
			s.sets = append(s.sets, set)
			s.setPool = append(s.setPool, pi)
			id := fmt.Sprintf("p%ds%d", pi, si)
			s.setID = append(s.setID, id)
			if !p.Draining {
				ringIDs = append(ringIDs, id)
				s.ringSets = append(s.ringSets, g)
			}
		}
	}
	s.ring = NewRing(ringIDs, opts.VirtualPoints)
	go s.background()
	return s, nil
}

func (s *Store) background() {
	defer close(s.done)
	if s.opts.BucketSync < 0 {
		<-s.stop
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { <-s.stop; cancel() }()
	// A first pass soon after start covers a pool that was just added.
	t := time.NewTimer(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.EnsureBuckets(ctx); err != nil && ctx.Err() == nil {
				s.log.Warn("cluster: bucket sync incomplete", "err", err)
			}
			t.Reset(s.opts.BucketSync)
		}
	}
}

// Close stops background work and closes every set.
func (s *Store) Close() error {
	var first error
	s.once.Do(func() {
		close(s.stop)
		<-s.done
		for _, set := range s.sets {
			if err := set.Close(); err != nil && first == nil {
				first = err
			}
		}
	})
	return first
}

// Sets is the number of sets across all pools.
func (s *Store) Sets() int { return len(s.sets) }

// SetStatus describes one set's availability.
type SetStatus struct {
	ID       string
	Pool     int
	Draining bool
	Drives   int
	Online   int
	Data     int
	Parity   int
}

// ReadOK reports a read quorum of drives.
func (st SetStatus) ReadOK() bool { return st.Online >= st.Data }

// WriteOK reports a write quorum of drives.
func (st SetStatus) WriteOK() bool {
	need := st.Data
	if st.Data == st.Parity {
		need++
	}
	return st.Online >= need
}

// Status reports every set's drive availability.
func (s *Store) Status() []SetStatus {
	out := make([]SetStatus, len(s.sets))
	for i, set := range s.sets {
		k, m, _ := set.Layout()
		out[i] = SetStatus{ID: s.setID[i], Pool: s.setPool[i], Draining: s.pools[s.setPool[i]].Draining,
			Drives: k + m, Online: set.OnlineDrives(), Data: k, Parity: m}
	}
	return out
}

// ringSet returns the global index of the set the ring places an object on,
// or -1 when every pool is draining.
func (s *Store) ringSet(bucket, object string) int {
	i := s.ring.Locate(bucket, object)
	if i < 0 {
		return -1
	}
	return s.ringSets[i]
}

func (s *Store) draining(set int) bool { return s.pools[s.setPool[set]].Draining }

type found struct {
	set  int
	info storage.ObjectInfo
}

// find locates an object: on the ring's set first, then, when pools have
// been added, on every other set. A set that cannot answer makes absence
// unprovable, so its error is returned rather than "not found".
func (s *Store) find(ctx context.Context, bucket, object string) (found, bool, error) {
	first := s.ringSet(bucket, object)
	if first >= 0 {
		info, err := s.sets[first].StatObject(ctx, bucket, object, storage.GetOptions{})
		switch {
		case err == nil:
			return found{first, info}, true, nil
		case !errors.Is(err, storage.ErrObjectNotFound):
			return found{}, false, err
		}
	}
	if !s.multi {
		return found{}, false, nil
	}
	type res struct {
		set  int
		info storage.ObjectInfo
		err  error
	}
	var wg sync.WaitGroup
	results := make([]res, len(s.sets))
	for i, set := range s.sets {
		if i == first {
			results[i].err = storage.ErrObjectNotFound
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			info, err := set.StatObject(ctx, bucket, object, storage.GetOptions{})
			results[i] = res{i, info, err}
		}()
	}
	wg.Wait()
	var best *found
	var firstErr error
	for i, r := range results {
		switch {
		case r.err == nil:
			if best == nil || r.info.ModTime.After(best.info.ModTime) {
				best = &found{i, r.info}
			}
		case !errors.Is(r.err, storage.ErrObjectNotFound) && firstErr == nil:
			firstErr = r.err
		}
	}
	if best != nil {
		return *best, true, nil
	}
	return found{}, false, firstErr
}

// target picks the set a write of bucket/object goes to, and the set (or
// -1) holding a copy that must be removed afterwards.
func (s *Store) target(ctx context.Context, bucket, object string) (target, stale int, cur *storage.ObjectInfo, err error) {
	ringSet := s.ringSet(bucket, object)
	if !s.multi {
		if ringSet < 0 {
			return 0, 0, nil, ErrNoPlacement
		}
		return ringSet, -1, nil, nil
	}
	f, ok, err := s.find(ctx, bucket, object)
	if err != nil {
		return 0, 0, nil, err
	}
	switch {
	case ok && !s.draining(f.set):
		return f.set, -1, &f.info, nil
	case ringSet < 0:
		return 0, 0, nil, ErrNoPlacement
	case ok: // only in a draining pool: write to the ring's set, drop the old copy
		return ringSet, f.set, &f.info, nil
	}
	return ringSet, -1, nil, nil
}

// MakeBucket creates the bucket on every set. It fails, undoing what it
// created, if any set cannot take it.
func (s *Store) MakeBucket(ctx context.Context, bucket string, opts storage.MakeBucketOptions) error {
	if err := storage.ValidateBucketName(bucket); err != nil {
		return err
	}
	errs := s.fanOut(func(i int) error { return s.sets[i].MakeBucket(ctx, bucket, opts) })
	created, existed := 0, 0
	var hard error
	for _, err := range errs {
		switch {
		case err == nil:
			created++
		case errors.Is(err, storage.ErrBucketExists):
			existed++
		case hard == nil:
			hard = err
		}
	}
	if hard != nil {
		for i, err := range errs {
			if err == nil {
				s.sets[i].DeleteBucket(context.Background(), bucket, storage.DeleteBucketOptions{})
			}
		}
		return hard
	}
	if created == 0 {
		return storage.Wrap(storage.ErrBucketExists, bucket, "")
	}
	return nil // sets that already had it are a partial create being completed
}

func (s *Store) fanOut(f func(set int) error) []error {
	errs := make([]error, len(s.sets))
	var wg sync.WaitGroup
	for i := range s.sets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = f(i)
		}()
	}
	wg.Wait()
	return errs
}

func firstErr(errs []error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

// GetBucketInfo reports the bucket if any set has it; absence needs every
// set's word.
func (s *Store) GetBucketInfo(ctx context.Context, bucket string) (storage.BucketInfo, error) {
	if err := storage.ValidateBucketName(bucket); err != nil {
		return storage.BucketInfo{}, err
	}
	infos := make([]storage.BucketInfo, len(s.sets))
	errs := s.fanOut(func(i int) error {
		var err error
		infos[i], err = s.sets[i].GetBucketInfo(ctx, bucket)
		return err
	})
	var best storage.BucketInfo
	have := false
	var hard error
	for i, err := range errs {
		switch {
		case err == nil:
			if !have || infos[i].Created.Before(best.Created) {
				best, have = infos[i], true
			}
		case errors.Is(err, storage.ErrBucketNotFound):
		case hard == nil:
			hard = err
		}
	}
	switch {
	case have:
		return best, nil
	case hard != nil:
		return storage.BucketInfo{}, hard
	}
	return storage.BucketInfo{}, storage.Wrap(storage.ErrBucketNotFound, bucket, "")
}

// BucketExists reports whether any set has the bucket.
func (s *Store) BucketExists(ctx context.Context, bucket string) (bool, error) {
	if _, err := s.GetBucketInfo(ctx, bucket); err != nil {
		if errors.Is(err, storage.ErrBucketNotFound) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// ListBuckets is the union of the sets' buckets; every set must answer.
func (s *Store) ListBuckets(ctx context.Context) ([]storage.BucketInfo, error) {
	lists := make([][]storage.BucketInfo, len(s.sets))
	errs := s.fanOut(func(i int) error {
		var err error
		lists[i], err = s.sets[i].ListBuckets(ctx)
		return err
	})
	if err := firstErr(errs); err != nil {
		return nil, err
	}
	byName := map[string]storage.BucketInfo{}
	for _, l := range lists {
		for _, b := range l {
			if cur, ok := byName[b.Name]; !ok || b.Created.Before(cur.Created) {
				byName[b.Name] = b
			}
		}
	}
	out := make([]storage.BucketInfo, 0, len(byName))
	for _, b := range byName {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// DeleteBucket removes the bucket from every set. A set that turns out not
// to be empty stops the operation and the bucket is restored on the sets
// that had already dropped it.
func (s *Store) DeleteBucket(ctx context.Context, bucket string, opts storage.DeleteBucketOptions) error {
	if err := storage.ValidateBucketName(bucket); err != nil {
		return err
	}
	if ok, err := s.BucketExists(ctx, bucket); err != nil {
		return err
	} else if !ok {
		return storage.Wrap(storage.ErrBucketNotFound, bucket, "")
	}
	var deleted []int
	for i, set := range s.sets {
		err := set.DeleteBucket(ctx, bucket, opts)
		switch {
		case err == nil:
			deleted = append(deleted, i)
		case errors.Is(err, storage.ErrBucketNotFound):
		default:
			for _, j := range deleted {
				s.sets[j].MakeBucket(context.Background(), bucket, storage.MakeBucketOptions{})
			}
			return err
		}
	}
	return nil
}

// EnsureBuckets creates, on every set, the buckets that exist on another:
// what brings a newly added pool in line.
func (s *Store) EnsureBuckets(ctx context.Context) error {
	buckets, err := s.ListBuckets(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for _, b := range buckets {
		for i, set := range s.sets {
			if err := ctx.Err(); err != nil {
				return err
			}
			ok, err := set.BucketExists(ctx, b.Name)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", s.setID[i], err))
				continue
			}
			if ok {
				continue
			}
			if err := set.MakeBucket(ctx, b.Name, storage.MakeBucketOptions{}); err != nil && !errors.Is(err, storage.ErrBucketExists) {
				errs = append(errs, fmt.Errorf("%s: %w", s.setID[i], err))
			}
		}
	}
	return errors.Join(errs...)
}

// PutObject writes to the set that already holds the key (unless it is
// draining), else to the ring's set.
func (s *Store) PutObject(ctx context.Context, bucket, object string, r io.Reader, size int64, opts storage.PutOptions) (storage.ObjectInfo, error) {
	if err := validate(bucket, object); err != nil {
		return storage.ObjectInfo{}, err
	}
	target, stale, cur, err := s.target(ctx, bucket, object)
	if err != nil {
		return storage.ObjectInfo{}, err
	}
	if stale >= 0 && cur != nil {
		// The precondition's subject lives in the draining pool, not on
		// the set that will take the write.
		if opts.IfNoneMatch == "*" {
			return storage.ObjectInfo{}, storage.Wrap(storage.ErrPreconditionFailed, bucket, object)
		}
		if m := strings.Trim(opts.IfMatch, `"`); m != "" && m != "*" && m != cur.ETag {
			return storage.ObjectInfo{}, storage.Wrap(storage.ErrPreconditionFailed, bucket, object)
		}
		opts.IfMatch, opts.IfNoneMatch = "", ""
	}
	info, err := s.sets[target].PutObject(ctx, bucket, object, r, size, opts)
	if err != nil {
		return info, err
	}
	if stale >= 0 {
		if _, derr := s.sets[stale].DeleteObject(ctx, bucket, object, storage.DeleteOptions{}); derr != nil {
			s.log.Warn("cluster: could not remove the superseded copy in a draining pool",
				"bucket", bucket, "object", object, "set", s.setID[stale], "err", derr)
		}
	}
	return info, nil
}

func validate(bucket, object string) error {
	if err := storage.ValidateBucketName(bucket); err != nil {
		return err
	}
	return storage.ValidateObjectName(object)
}

// GetObject reads from the set that holds the object.
func (s *Store) GetObject(ctx context.Context, bucket, object string, opts storage.GetOptions) (io.ReadCloser, storage.ObjectInfo, error) {
	if err := validate(bucket, object); err != nil {
		return nil, storage.ObjectInfo{}, err
	}
	first := s.ringSet(bucket, object)
	if first >= 0 {
		rc, info, err := s.sets[first].GetObject(ctx, bucket, object, opts)
		if err == nil || !errors.Is(err, storage.ErrObjectNotFound) || !s.multi {
			return rc, info, err
		}
	} else if !s.multi {
		return nil, storage.ObjectInfo{}, ErrNoPlacement
	}
	f, ok, err := s.find(ctx, bucket, object)
	switch {
	case err != nil:
		return nil, storage.ObjectInfo{}, err
	case !ok:
		return nil, storage.ObjectInfo{}, storage.Wrap(storage.ErrObjectNotFound, bucket, object)
	}
	return s.sets[f.set].GetObject(ctx, bucket, object, opts)
}

// StatObject describes the object on the set that holds it.
func (s *Store) StatObject(ctx context.Context, bucket, object string, opts storage.GetOptions) (storage.ObjectInfo, error) {
	if err := validate(bucket, object); err != nil {
		return storage.ObjectInfo{}, err
	}
	if opts.VersionID != "" {
		return storage.ObjectInfo{}, storage.Wrap(storage.ErrVersionNotFound, bucket, object)
	}
	f, ok, err := s.find(ctx, bucket, object)
	switch {
	case err != nil:
		return storage.ObjectInfo{}, err
	case !ok:
		if exists, berr := s.BucketExists(ctx, bucket); berr == nil && !exists {
			return storage.ObjectInfo{}, storage.Wrap(storage.ErrBucketNotFound, bucket, "")
		}
		return storage.ObjectInfo{}, storage.Wrap(storage.ErrObjectNotFound, bucket, object)
	}
	return f.info, nil
}

// DeleteObject removes the object from every set that has it.
func (s *Store) DeleteObject(ctx context.Context, bucket, object string, opts storage.DeleteOptions) (storage.DeleteResult, error) {
	if err := validate(bucket, object); err != nil {
		return storage.DeleteResult{}, err
	}
	if !s.multi {
		first := s.ringSet(bucket, object)
		if first < 0 {
			return storage.DeleteResult{}, ErrNoPlacement
		}
		return s.sets[first].DeleteObject(ctx, bucket, object, opts)
	}
	errs := s.fanOut(func(i int) error {
		_, err := s.sets[i].DeleteObject(ctx, bucket, object, opts)
		return err
	})
	if err := firstErr(errs); err != nil {
		return storage.DeleteResult{}, err
	}
	return storage.DeleteResult{}, nil
}

// CopyObject and the other operations the sets do not implement report
// that, exactly as the sets do.
func (s *Store) CopyObject(context.Context, storage.ObjectRef, storage.ObjectRef, storage.CopyOptions) (storage.ObjectInfo, error) {
	return storage.ObjectInfo{}, fmt.Errorf("cluster: CopyObject: %w", storage.ErrNotImplemented)
}

func (s *Store) UpdateObjectMetadata(context.Context, string, string, storage.UpdateMetaOptions) (storage.ObjectInfo, error) {
	return storage.ObjectInfo{}, fmt.Errorf("cluster: UpdateObjectMetadata: %w", storage.ErrNotImplemented)
}

func (s *Store) ListObjectVersions(context.Context, string, storage.ListOptions) (storage.ListVersionsResult, error) {
	return storage.ListVersionsResult{}, fmt.Errorf("cluster: ListObjectVersions: %w", storage.ErrNotImplemented)
}

// ListObjects merges one page from every set. See the package contract for
// the timeout and partial-result rules.
func (s *Store) ListObjects(ctx context.Context, bucket string, opts storage.ListOptions) (storage.ListResult, error) {
	if err := storage.ValidateBucketName(bucket); err != nil {
		return storage.ListResult{}, err
	}
	limit := opts.MaxKeys
	if limit <= 0 || limit > listing.MaxKeys {
		limit = listing.MaxKeys
	}
	pageOpts := opts
	pageOpts.MaxKeys = limit
	pages := make([]storage.ListResult, len(s.sets))
	errs := s.fanOut(func(i int) error {
		cctx, cancel := context.WithTimeout(ctx, s.opts.ListTimeout)
		defer cancel()
		var err error
		pages[i], err = s.sets[i].ListObjects(cctx, bucket, pageOpts)
		if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
			err = fmt.Errorf("%w: set %s did not answer within %v", storage.ErrBackendUnavailable, s.setID[i], s.opts.ListTimeout)
		}
		return err
	})
	var missing, failed []int
	for i, err := range errs {
		switch {
		case err == nil:
		case errors.Is(err, storage.ErrBucketNotFound):
			missing = append(missing, i)
		default:
			failed = append(failed, i)
		}
	}
	if err := ctx.Err(); err != nil {
		return storage.ListResult{}, err
	}
	if len(missing) == len(s.sets) {
		return storage.ListResult{}, storage.Wrap(storage.ErrBucketNotFound, bucket, "")
	}
	incomplete := false
	if len(failed) > 0 {
		for _, i := range failed {
			s.log.Warn("cluster: list could not use a set", "bucket", bucket, "set", s.setID[i], "err", errs[i])
		}
		if !s.opts.AllowPartialList || len(failed) == len(s.sets)-len(missing) {
			return storage.ListResult{}, storage.Wrap(
				fmt.Errorf("%w: %d of %d sets could not be listed", storage.ErrBackendUnavailable, len(failed), len(s.sets)),
				bucket, "")
		}
		incomplete = true
	}
	res := mergePages(pages, errs, limit)
	res.Incomplete = incomplete
	return res, nil
}

// mergePages merges sorted per-set pages into one page of at most limit
// entries. Pages whose error is set are skipped.
func mergePages(pages []storage.ListResult, errs []error, limit int) storage.ListResult {
	type entry struct {
		name   string
		prefix bool
		obj    storage.ObjectInfo
	}
	byName := map[string]entry{}
	truncated := false
	for i, p := range pages {
		if errs[i] != nil {
			continue
		}
		truncated = truncated || p.IsTruncated
		for _, pre := range p.Prefixes {
			byName[pre] = entry{name: pre, prefix: true}
		}
		for _, o := range p.Objects {
			if cur, ok := byName[o.Name]; !ok || cur.prefix || o.ModTime.After(cur.obj.ModTime) {
				byName[o.Name] = entry{name: o.Name, obj: o}
			}
		}
	}
	all := make([]entry, 0, len(byName))
	for _, e := range byName {
		all = append(all, e)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].name < all[j].name })
	var res storage.ListResult
	if len(all) > limit {
		all, truncated = all[:limit], true
	}
	for _, e := range all {
		if e.prefix {
			res.Prefixes = append(res.Prefixes, e.name)
		} else {
			res.Objects = append(res.Objects, e.obj)
		}
	}
	res.IsTruncated = truncated
	if truncated && len(all) > 0 {
		res.NextMarker = all[len(all)-1].name
	}
	return res
}

// Multipart upload IDs carry the owning set: "<set>.<id>".
func encodeUploadID(set int, id string) string { return strconv.Itoa(set) + "." + id }

func (s *Store) decodeUploadID(bucket, object, id string) (set int, inner string, err error) {
	i := strings.IndexByte(id, '.')
	if i <= 0 {
		return 0, "", storage.Wrap(storage.ErrNoSuchUpload, bucket, object)
	}
	n, err := strconv.Atoi(id[:i])
	if err != nil || n < 0 || n >= len(s.sets) {
		return 0, "", storage.Wrap(storage.ErrNoSuchUpload, bucket, object)
	}
	return n, id[i+1:], nil
}

// NewMultipartUpload starts the upload on the set that will own the object.
func (s *Store) NewMultipartUpload(ctx context.Context, bucket, object string, opts storage.PutOptions) (string, error) {
	if err := validate(bucket, object); err != nil {
		return "", err
	}
	target, _, _, err := s.target(ctx, bucket, object)
	if err != nil {
		return "", err
	}
	id, err := s.sets[target].NewMultipartUpload(ctx, bucket, object, opts)
	if err != nil {
		return "", err
	}
	return encodeUploadID(target, id), nil
}

// PutObjectPart routes to the upload's set.
func (s *Store) PutObjectPart(ctx context.Context, bucket, object, uploadID string, n int, r io.Reader, size int64, opts storage.PartOptions) (storage.PartInfo, error) {
	set, id, err := s.decodeUploadID(bucket, object, uploadID)
	if err != nil {
		return storage.PartInfo{}, err
	}
	return s.sets[set].PutObjectPart(ctx, bucket, object, id, n, r, size, opts)
}

// ListObjectParts routes to the upload's set.
func (s *Store) ListObjectParts(ctx context.Context, bucket, object, uploadID string, opts storage.ListPartsOptions) (storage.ListPartsResult, error) {
	set, id, err := s.decodeUploadID(bucket, object, uploadID)
	if err != nil {
		return storage.ListPartsResult{}, err
	}
	return s.sets[set].ListObjectParts(ctx, bucket, object, id, opts)
}

// CompleteMultipartUpload routes to the upload's set.
func (s *Store) CompleteMultipartUpload(ctx context.Context, bucket, object, uploadID string, parts []storage.CompletePart, opts storage.PutOptions) (storage.ObjectInfo, error) {
	set, id, err := s.decodeUploadID(bucket, object, uploadID)
	if err != nil {
		return storage.ObjectInfo{}, err
	}
	return s.sets[set].CompleteMultipartUpload(ctx, bucket, object, id, parts, opts)
}

// AbortMultipartUpload routes to the upload's set.
func (s *Store) AbortMultipartUpload(ctx context.Context, bucket, object, uploadID string) error {
	set, id, err := s.decodeUploadID(bucket, object, uploadID)
	if err != nil {
		return err
	}
	return s.sets[set].AbortMultipartUpload(ctx, bucket, object, id)
}

// ListMultipartUploads gathers every set's uploads and pages the union.
func (s *Store) ListMultipartUploads(ctx context.Context, bucket string, opts storage.ListUploadsOptions) (storage.ListUploadsResult, error) {
	if err := storage.ValidateBucketName(bucket); err != nil {
		return storage.ListUploadsResult{}, err
	}
	lists := make([][]storage.UploadInfo, len(s.sets))
	errs := s.fanOut(func(i int) error {
		cctx, cancel := context.WithTimeout(ctx, s.opts.ListTimeout)
		defer cancel()
		var marker storage.ListUploadsOptions
		marker.Prefix = opts.Prefix
		marker.MaxUploads = listing.MaxKeys
		for {
			res, err := s.sets[i].ListMultipartUploads(cctx, bucket, marker)
			if err != nil {
				return err
			}
			for _, u := range res.Uploads {
				u.UploadID = encodeUploadID(i, u.UploadID)
				lists[i] = append(lists[i], u)
			}
			if !res.IsTruncated {
				return nil
			}
			marker.KeyMarker, marker.UploadIDMarker = res.NextKeyMarker, res.NextUploadIDMarker
		}
	})
	var all []storage.UploadInfo
	missing := 0
	for i, err := range errs {
		switch {
		case err == nil:
			all = append(all, lists[i]...)
		case errors.Is(err, storage.ErrBucketNotFound):
			missing++
		default:
			return storage.ListUploadsResult{}, err
		}
	}
	if missing == len(s.sets) {
		return storage.ListUploadsResult{}, storage.Wrap(storage.ErrBucketNotFound, bucket, "")
	}
	return listing.PageUploads(all, opts), nil
}

// Info sums the sets.
func (s *Store) Info(ctx context.Context) (storage.BackendInfo, error) {
	out := storage.BackendInfo{Kind: "cluster", Healthy: true}
	for _, set := range s.sets {
		info, err := set.Info(ctx)
		if err != nil {
			return out, err
		}
		out.Disks += info.Disks
		out.TotalBytes += info.TotalBytes
		out.FreeBytes += info.FreeBytes
		out.Corrupted += info.Corrupted
		out.Healthy = out.Healthy && info.Healthy
	}
	return out, nil
}

// Scan runs a maintenance pass on every set and sums the results.
func (s *Store) Scan(ctx context.Context, deep bool) (xl.ScanStats, error) {
	var sum xl.ScanStats
	for i, set := range s.sets {
		st, err := set.Scan(ctx, deep)
		if err != nil {
			return sum, fmt.Errorf("%s: %w", s.setID[i], err)
		}
		sum.DrivesFormatted += st.DrivesFormatted
		sum.Buckets += st.Buckets
		sum.BucketsHealed += st.BucketsHealed
		sum.Objects += st.Objects
		sum.ShardsHealed += st.ShardsHealed
		sum.Dangling += st.Dangling
		sum.Unrecoverable += st.Unrecoverable
		sum.ExpiredUploads += st.ExpiredUploads
		sum.OrphanDirs += st.OrphanDirs
		sum.Staging += st.Staging
	}
	return sum, nil
}
