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
	"nanoio/internal/storage/internal/objlock"
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
	// dm is set when the version the lookup resolved to is a delete marker.
	dm *storage.DeleteMarkerError
}

// absent reports whether err means "this set does not have it": no such
// object, or no such version. A delete marker is not absence.
func absent(err error) bool {
	var dm *storage.DeleteMarkerError
	if errors.As(err, &dm) {
		return false
	}
	return errors.Is(err, storage.ErrObjectNotFound) || errors.Is(err, storage.ErrVersionNotFound)
}

// find locates an object (or the version in opts): on the ring's set first,
// then, when pools have been added, on every other set. A set that cannot
// answer makes absence unprovable, so its error is returned rather than
// "not found". A delete marker counts as found: the key's history is there.
func (s *Store) find(ctx context.Context, bucket, object string, opts storage.GetOptions) (found, bool, error) {
	try := func(i int) (found, bool, error) {
		info, err := s.sets[i].StatObject(ctx, bucket, object, opts)
		var dm *storage.DeleteMarkerError
		switch {
		case err == nil:
			return found{set: i, info: info}, true, nil
		case errors.As(err, &dm):
			return found{set: i, dm: dm}, true, nil
		case absent(err):
			return found{}, false, nil
		}
		return found{}, false, err
	}
	first := s.ringSet(bucket, object)
	if first >= 0 {
		f, ok, err := try(first)
		if ok || err != nil {
			return f, ok, err
		}
	}
	if !s.multi {
		return found{}, false, nil
	}
	type res struct {
		f   found
		ok  bool
		err error
	}
	var wg sync.WaitGroup
	results := make([]res, len(s.sets))
	for i := range s.sets {
		if i == first {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			f, ok, err := try(i)
			results[i] = res{f, ok, err}
		}()
	}
	wg.Wait()
	var best *found
	var firstErr error
	for i := range results {
		r := results[i]
		switch {
		case r.err != nil && firstErr == nil:
			firstErr = r.err
		case r.ok:
			if best == nil || foundTime(r.f).After(foundTime(*best)) {
				c := r.f
				best = &c
			}
		}
	}
	if best != nil {
		return *best, true, nil
	}
	return found{}, false, firstErr
}

func foundTime(f found) time.Time {
	if f.dm != nil {
		return f.dm.ModTime
	}
	return f.info.ModTime
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
	f, ok, err := s.find(ctx, bucket, object, storage.GetOptions{})
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
	// What a restored bucket must look like: one that had object lock comes
	// back with it, never as an unprotected bucket.
	lockCfg, err := s.GetBucketObjectLock(ctx, bucket)
	if err != nil {
		return err
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
				bg := context.Background()
				s.sets[j].MakeBucket(bg, bucket, storage.MakeBucketOptions{ObjectLock: lockCfg.Enabled})
				if lockCfg.Enabled && lockCfg.Default != nil {
					s.sets[j].SetBucketObjectLock(bg, bucket, lockCfg)
				}
			}
			return err
		}
	}
	return nil
}

// GetBucketObjectLock reports the bucket's object lock configuration. Every
// set holds it; if they have drifted (a change that reached only some sets)
// the newest wins. Every set must answer, so an unreachable set can never
// make a locked bucket read as unlocked.
func (s *Store) GetBucketObjectLock(ctx context.Context, bucket string) (storage.ObjectLockConfig, error) {
	if err := storage.ValidateBucketName(bucket); err != nil {
		return storage.ObjectLockConfig{}, err
	}
	cfgs := make([]storage.ObjectLockConfig, len(s.sets))
	errs := s.fanOut(func(i int) error {
		var err error
		cfgs[i], err = s.sets[i].GetBucketObjectLock(ctx, bucket)
		return err
	})
	missing := 0
	for _, err := range errs {
		switch {
		case err == nil:
		case errors.Is(err, storage.ErrBucketNotFound):
			missing++
		default:
			return storage.ObjectLockConfig{}, err
		}
	}
	if missing == len(s.sets) {
		return storage.ObjectLockConfig{}, storage.Wrap(storage.ErrBucketNotFound, bucket, "")
	}
	var best storage.ObjectLockConfig
	have := false
	for i, c := range cfgs {
		if errs[i] != nil {
			continue
		}
		// A set that has object lock beats one that does not at equal
		// sequence: the unprotected reading is the dangerous one.
		if !have || c.Seq > best.Seq || c.Seq == best.Seq && c.Enabled && !best.Enabled {
			best, have = c, true
		}
	}
	return best, nil
}

// SetBucketObjectLock changes the default retention on every set. A set
// that fails leaves the sets ahead of it: the call reports the error and
// EnsureBuckets brings the lagging sets to the newest configuration.
func (s *Store) SetBucketObjectLock(ctx context.Context, bucket string, cfg storage.ObjectLockConfig) error {
	cur, err := s.GetBucketObjectLock(ctx, bucket)
	if err != nil {
		return err
	}
	if err := objlock.CheckConfig(cur, cfg); err != nil {
		return storage.Wrap(err, bucket, "")
	}
	errs := s.fanOut(func(i int) error { return s.sets[i].SetBucketObjectLock(ctx, bucket, cfg) })
	return firstErr(errs)
}

// reconcileObjectLock moves every set whose object lock configuration lags
// the newest onto it.
func (s *Store) reconcileObjectLock(ctx context.Context, bucket string) error {
	best, err := s.GetBucketObjectLock(ctx, bucket)
	if err != nil || !best.Enabled {
		return err
	}
	var out []error
	for i, set := range s.sets {
		cur, err := set.GetBucketObjectLock(ctx, bucket)
		switch {
		case errors.Is(err, storage.ErrBucketNotFound):
			continue
		case err != nil:
			out = append(out, fmt.Errorf("%s: %w", s.setID[i], err))
			continue
		case cur.Seq >= best.Seq && cur.Enabled:
			continue
		}
		if err := set.SetBucketObjectLock(ctx, bucket, best); err != nil {
			out = append(out, fmt.Errorf("%s: %w", s.setID[i], err))
		}
	}
	return errors.Join(out...)
}

// setVersioning reads the bucket's versioning state on every set.
func (s *Store) setVersioning(ctx context.Context, bucket string) ([]storage.VersioningConfig, []error) {
	cfgs := make([]storage.VersioningConfig, len(s.sets))
	errs := s.fanOut(func(i int) error {
		var err error
		cfgs[i], err = s.sets[i].GetBucketVersioning(ctx, bucket)
		return err
	})
	return cfgs, errs
}

// newest picks the configuration that wins among sets: the highest change
// sequence, and for equal sequences the more "active" state.
func newest(cfgs []storage.VersioningConfig, errs []error) (storage.VersioningConfig, bool) {
	rank := func(s storage.VersioningState) int {
		switch s {
		case storage.VersioningEnabled:
			return 2
		case storage.VersioningSuspended:
			return 1
		}
		return 0
	}
	var best storage.VersioningConfig
	have := false
	for i, c := range cfgs {
		if errs[i] != nil {
			continue
		}
		if !have || c.Seq > best.Seq || c.Seq == best.Seq && rank(c.State) > rank(best.State) {
			best, have = c, true
		}
	}
	return best, have
}

// GetBucketVersioning reports the state of the bucket: every set holds it,
// and if they have drifted (a change that reached only some sets) the
// newest change wins. Every set must answer.
func (s *Store) GetBucketVersioning(ctx context.Context, bucket string) (storage.VersioningConfig, error) {
	if err := storage.ValidateBucketName(bucket); err != nil {
		return storage.VersioningConfig{}, err
	}
	cfgs, errs := s.setVersioning(ctx, bucket)
	missing := 0
	for _, err := range errs {
		switch {
		case err == nil:
		case errors.Is(err, storage.ErrBucketNotFound):
			missing++
		default:
			return storage.VersioningConfig{}, err
		}
	}
	if missing == len(s.sets) {
		return storage.VersioningConfig{}, storage.Wrap(storage.ErrBucketNotFound, bucket, "")
	}
	cfg, _ := newest(cfgs, errs)
	return cfg, nil
}

// SetBucketVersioning changes the state on every set. A set that fails
// leaves the sets ahead of it: the call reports the error, and the periodic
// reconciliation (EnsureBuckets) brings the lagging sets to the newest
// state.
func (s *Store) SetBucketVersioning(ctx context.Context, bucket string, state storage.VersioningState) error {
	cur, err := s.GetBucketVersioning(ctx, bucket)
	if err != nil {
		return err
	}
	if !state.Valid() {
		return storage.Wrap(storage.ErrIllegalVersioning, bucket, "")
	}
	if err := storage.CheckVersioningTransition(cur.State, state); err != nil {
		return storage.Wrap(err, bucket, "")
	}
	if state != storage.VersioningEnabled {
		lock, err := s.GetBucketObjectLock(ctx, bucket)
		if err != nil {
			return err
		}
		if lock.Enabled {
			return storage.Wrap(fmt.Errorf("%w: versioning cannot be suspended on a bucket with object lock", storage.ErrInvalidBucketState), bucket, "")
		}
	}
	errs := s.fanOut(func(i int) error {
		return s.sets[i].SetBucketVersioning(ctx, bucket, state)
	})
	return firstErr(errs)
}

// reconcileVersioning moves every set that lags the newest versioning
// state of bucket onto it.
func (s *Store) reconcileVersioning(ctx context.Context, bucket string) error {
	cfgs, errs := s.setVersioning(ctx, bucket)
	best, ok := newest(cfgs, errs)
	if !ok {
		return firstErr(errs)
	}
	var out []error
	for i := range s.sets {
		if errs[i] != nil || cfgs[i].State == best.State {
			continue
		}
		if err := s.sets[i].SetBucketVersioning(ctx, bucket, best.State); err != nil {
			out = append(out, fmt.Errorf("%s: %w", s.setID[i], err))
		}
	}
	return errors.Join(out...)
}

// EnsureBuckets creates, on every set, the buckets that exist on another,
// and brings their versioning state in line: what makes a newly added pool,
// or a set that missed a change, consistent with the rest.
func (s *Store) EnsureBuckets(ctx context.Context) error {
	buckets, err := s.ListBuckets(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for _, b := range buckets {
		// A set that lacks the bucket must get it with object lock if it
		// has it elsewhere; creating it bare would accept unprotected
		// writes. If that is not known the bucket is left alone.
		lock, lerr := s.GetBucketObjectLock(ctx, b.Name)
		if lerr != nil {
			errs = append(errs, fmt.Errorf("bucket %s: %w", b.Name, lerr))
			continue
		}
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
			if err := set.MakeBucket(ctx, b.Name, storage.MakeBucketOptions{ObjectLock: lock.Enabled}); err != nil && !errors.Is(err, storage.ErrBucketExists) {
				errs = append(errs, fmt.Errorf("%s: %w", s.setID[i], err))
			}
		}
		if err := s.reconcileVersioning(ctx, b.Name); err != nil {
			errs = append(errs, err)
		}
		if err := s.reconcileObjectLock(ctx, b.Name); err != nil {
			errs = append(errs, err)
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
		if err == nil || !absent(err) || !s.multi {
			return rc, info, err
		}
	} else if !s.multi {
		return nil, storage.ObjectInfo{}, ErrNoPlacement
	}
	f, ok, err := s.find(ctx, bucket, object, opts)
	switch {
	case err != nil:
		return nil, storage.ObjectInfo{}, err
	case !ok:
		if opts.VersionID != "" {
			return nil, storage.ObjectInfo{}, storage.Wrap(storage.ErrVersionNotFound, bucket, object)
		}
		return nil, storage.ObjectInfo{}, storage.Wrap(storage.ErrObjectNotFound, bucket, object)
	case f.dm != nil:
		return nil, storage.ObjectInfo{}, f.dm
	}
	return s.sets[f.set].GetObject(ctx, bucket, object, opts)
}

// StatObject describes the object on the set that holds it.
func (s *Store) StatObject(ctx context.Context, bucket, object string, opts storage.GetOptions) (storage.ObjectInfo, error) {
	if err := validate(bucket, object); err != nil {
		return storage.ObjectInfo{}, err
	}
	f, ok, err := s.find(ctx, bucket, object, opts)
	switch {
	case err != nil:
		return storage.ObjectInfo{}, err
	case !ok:
		if exists, berr := s.BucketExists(ctx, bucket); berr == nil && !exists {
			return storage.ObjectInfo{}, storage.Wrap(storage.ErrBucketNotFound, bucket, "")
		}
		if opts.VersionID != "" {
			return storage.ObjectInfo{}, storage.Wrap(storage.ErrVersionNotFound, bucket, object)
		}
		return storage.ObjectInfo{}, storage.Wrap(storage.ErrObjectNotFound, bucket, object)
	case f.dm != nil:
		return storage.ObjectInfo{}, f.dm
	}
	return f.info, nil
}

// DeleteObject removes an object, adds a delete marker, or removes one
// version, on the set that holds the key:
//
//   - a named version is looked for on every set when there is more than
//     one pool (it is wherever it was written), and removed there;
//   - without a version, an unversioned bucket loses the object from every
//     set that has it (as before versioning), while a versioned bucket gets
//     its delete marker on the one set that holds the key, or on the ring's
//     set for a key that has no history yet.
func (s *Store) DeleteObject(ctx context.Context, bucket, object string, opts storage.DeleteOptions) (storage.DeleteResult, error) {
	if err := validate(bucket, object); err != nil {
		return storage.DeleteResult{}, err
	}
	first := s.ringSet(bucket, object)
	if !s.multi {
		if first < 0 {
			return storage.DeleteResult{}, ErrNoPlacement
		}
		return s.sets[first].DeleteObject(ctx, bucket, object, opts)
	}
	versioned := opts.VersionID != ""
	if !versioned && first >= 0 {
		cfg, err := s.sets[first].GetBucketVersioning(ctx, bucket)
		if err != nil {
			return storage.DeleteResult{}, err
		}
		versioned = cfg.State != storage.VersioningUnversioned
	}
	if versioned && opts.VersionID == "" {
		target, _, _, err := s.target(ctx, bucket, object)
		if err != nil {
			return storage.DeleteResult{}, err
		}
		return s.sets[target].DeleteObject(ctx, bucket, object, opts)
	}
	results := make([]storage.DeleteResult, len(s.sets))
	errs := s.fanOut(func(i int) error {
		var err error
		results[i], err = s.sets[i].DeleteObject(ctx, bucket, object, opts)
		return err
	})
	if err := firstErr(errs); err != nil {
		return storage.DeleteResult{}, err
	}
	var out storage.DeleteResult
	for _, r := range results {
		if out.VersionID == "" {
			out.VersionID = r.VersionID
		}
		out.DeleteMarker = out.DeleteMarker || r.DeleteMarker
	}
	return out, nil
}

// CopyObject and the other operations the sets do not implement report
// that, exactly as the sets do.
func (s *Store) CopyObject(context.Context, storage.ObjectRef, storage.ObjectRef, storage.CopyOptions) (storage.ObjectInfo, error) {
	return storage.ObjectInfo{}, fmt.Errorf("cluster: CopyObject: %w", storage.ErrNotImplemented)
}

// UpdateObjectMetadata changes a version's metadata on the set that holds
// it.
func (s *Store) UpdateObjectMetadata(ctx context.Context, bucket, object string, opts storage.UpdateMetaOptions) (storage.ObjectInfo, error) {
	set, err := s.setOf(ctx, storage.ObjectRef{Bucket: bucket, Object: object, VersionID: opts.VersionID})
	if err != nil {
		return storage.ObjectInfo{}, err
	}
	return s.sets[set].UpdateObjectMetadata(ctx, bucket, object, opts)
}

// ListObjectVersions merges one page of versions from every set, under the
// same per-set deadline and failure policy as ListObjects. Entries order by
// key, then newest first (a key's versions live on one set; the order of
// the rare key that has history on two is by modification time).
func (s *Store) ListObjectVersions(ctx context.Context, bucket string, opts storage.ListOptions) (storage.ListVersionsResult, error) {
	if err := storage.ValidateBucketName(bucket); err != nil {
		return storage.ListVersionsResult{}, err
	}
	limit := opts.MaxKeys
	if limit <= 0 || limit > listing.MaxKeys {
		limit = listing.MaxKeys
	}
	pageOpts := opts
	pageOpts.MaxKeys = limit
	pages := make([]storage.ListVersionsResult, len(s.sets))
	errs := s.fanOut(func(i int) error {
		cctx, cancel := context.WithTimeout(ctx, s.opts.ListTimeout)
		defer cancel()
		var err error
		pages[i], err = s.sets[i].ListObjectVersions(cctx, bucket, pageOpts)
		if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
			err = fmt.Errorf("%w: set %s did not answer within %v", storage.ErrBackendUnavailable, s.setID[i], s.opts.ListTimeout)
		}
		return err
	})
	if err := ctx.Err(); err != nil {
		return storage.ListVersionsResult{}, err
	}
	missing, failed := 0, 0
	for i, err := range errs {
		switch {
		case err == nil:
		case errors.Is(err, storage.ErrBucketNotFound):
			missing++
		default:
			failed++
			s.log.Warn("cluster: version list could not use a set", "bucket", bucket, "set", s.setID[i], "err", err)
		}
	}
	if missing == len(s.sets) {
		return storage.ListVersionsResult{}, storage.Wrap(storage.ErrBucketNotFound, bucket, "")
	}
	if failed > 0 {
		return storage.ListVersionsResult{}, storage.Wrap(
			fmt.Errorf("%w: %d of %d sets could not be listed", storage.ErrBackendUnavailable, failed, len(s.sets)), bucket, "")
	}
	type entry struct {
		key    string
		prefix bool
		v      storage.ObjectInfo
	}
	var all []entry
	seenPrefix := map[string]bool{}
	truncated := false
	for _, p := range pages {
		truncated = truncated || p.IsTruncated
		for _, pre := range p.Prefixes {
			if !seenPrefix[pre] {
				seenPrefix[pre] = true
				all = append(all, entry{key: pre, prefix: true})
			}
		}
		for _, v := range p.Versions {
			all = append(all, entry{key: v.Name, v: v})
		}
	}
	sort.SliceStable(all, func(i, j int) bool {
		a, b := all[i], all[j]
		switch {
		case a.key != b.key:
			return a.key < b.key
		case a.prefix != b.prefix:
			return a.prefix
		case !a.v.ModTime.Equal(b.v.ModTime):
			return a.v.ModTime.After(b.v.ModTime)
		}
		return a.v.VersionID > b.v.VersionID
	})
	var res storage.ListVersionsResult
	if len(all) > limit {
		all, truncated = all[:limit], true
	}
	for i, e := range all {
		if e.prefix {
			res.Prefixes = append(res.Prefixes, e.key)
			continue
		}
		// Only the first entry of a key is its latest.
		if i > 0 && !all[i-1].prefix && all[i-1].key == e.key {
			e.v.IsLatest = false
		}
		res.Versions = append(res.Versions, e.v)
	}
	res.IsTruncated = truncated
	if truncated && len(all) > 0 {
		last := all[len(all)-1]
		res.NextMarker = last.key
		if !last.prefix {
			res.NextVersionIDMarker = last.v.VersionID
		}
	}
	return res, nil
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

// setOf finds the set holding one version of an object, with the errors a
// read of it would give.
func (s *Store) setOf(ctx context.Context, ref storage.ObjectRef) (int, error) {
	if err := validate(ref.Bucket, ref.Object); err != nil {
		return 0, err
	}
	f, ok, err := s.find(ctx, ref.Bucket, ref.Object, storage.GetOptions{VersionID: ref.VersionID})
	switch {
	case err != nil:
		return 0, err
	case !ok:
		if exists, berr := s.BucketExists(ctx, ref.Bucket); berr == nil && !exists {
			return 0, storage.Wrap(storage.ErrBucketNotFound, ref.Bucket, "")
		}
		if ref.VersionID != "" {
			return 0, storage.Wrap(storage.ErrVersionNotFound, ref.Bucket, ref.Object)
		}
		return 0, storage.Wrap(storage.ErrObjectNotFound, ref.Bucket, ref.Object)
	case f.dm != nil:
		return 0, f.dm
	}
	return f.set, nil
}

// SetObjectRetention changes the retention on the set that holds the
// version.
func (s *Store) SetObjectRetention(ctx context.Context, ref storage.ObjectRef, r storage.Retention, opts storage.RetentionOptions) (storage.ObjectInfo, error) {
	set, err := s.setOf(ctx, ref)
	if err != nil {
		return storage.ObjectInfo{}, err
	}
	return s.sets[set].SetObjectRetention(ctx, ref, r, opts)
}

// SetObjectLegalHold changes the legal hold on the set that holds the
// version.
func (s *Store) SetObjectLegalHold(ctx context.Context, ref storage.ObjectRef, on bool) (storage.ObjectInfo, error) {
	set, err := s.setOf(ctx, ref)
	if err != nil {
		return storage.ObjectInfo{}, err
	}
	return s.sets[set].SetObjectLegalHold(ctx, ref, on)
}
