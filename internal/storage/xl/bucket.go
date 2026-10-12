package xl

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"nanoio/internal/storage"
	"nanoio/internal/storage/internal/objlock"
	"nanoio/internal/storage/xl/disk"
)

// bucketVote counts what the drives say about a bucket directory.
type bucketVote struct {
	present, absent, unavailable int
}

func (x *XL) voteBucket(ctx context.Context, bucket string) bucketVote {
	_, errs := scatter(ctx, x, x.k, 0, true, false, func(ctx context.Context, d *drive) (struct{}, error) {
		exists, _, err := d.StatBucket(ctx, bucket)
		if err == nil && !exists {
			return struct{}{}, disk.ErrNotFound
		}
		return struct{}{}, err
	}, nil)
	var v bucketVote
	for _, err := range errs {
		switch {
		case err == nil:
			v.present++
		case errors.Is(err, errStraggler):
			// not asked, in effect: says nothing either way
		case errors.Is(err, disk.ErrNotFound):
			v.absent++
		default:
			v.unavailable++
		}
	}
	return v
}

// bucketExists applies read quorum to the bucket directory: it exists if at
// least K drives have it, does not if so many lack it that K is impossible,
// and is otherwise undecidable (too many drives unavailable).
func (x *XL) bucketExists(ctx context.Context, bucket string) (bool, error) {
	v := x.voteBucket(ctx, bucket)
	switch {
	case v.present >= x.k:
		return true, nil
	case v.absent > len(x.drives)-x.k:
		return false, nil
	}
	return false, storage.Wrap(storage.ErrBackendUnavailable, bucket, "")
}

func (x *XL) requireBucket(ctx context.Context, bucket string) error {
	ok, err := x.bucketExists(ctx, bucket)
	if err != nil {
		return err
	}
	if !ok {
		return storage.Wrap(storage.ErrBucketNotFound, bucket, "")
	}
	return nil
}

// MakeBucket creates the bucket directory, with its marker, on every drive.
// A bucket created with object lock is also made versioned and locked before
// the exclusive bucket lock is released, so no write can see it half made;
// if the settings do not reach a write quorum the bucket is removed again.
func (x *XL) MakeBucket(ctx context.Context, bucket string, mopts storage.MakeBucketOptions) error {
	if err := storage.ValidateBucketName(bucket); err != nil {
		return err
	}
	if err := x.enter(ctx); err != nil {
		return err
	}
	defer x.leave()
	unlock, err := x.locker.Lock(ctx, bucket, "")
	if err != nil {
		return err
	}
	defer unlock()

	if v := x.voteBucket(ctx, bucket); v.present >= x.k {
		return storage.Wrap(storage.ErrBucketExists, bucket, "")
	}
	created := time.Now().UTC()
	made := make([]bool, len(x.drives))
	errs := x.each(ctx, func(d *drive) error {
		// A directory left by an earlier partial create is adopted.
		m, err := d.MakeBucket(ctx, bucket, created)
		made[d.idx] = m
		return err
	})
	if countNil(errs) < x.writeQuorum() {
		dctx, cancel := detached(ctx)
		defer cancel()
		for i, d := range x.drives {
			if made[i] {
				d.DeleteBucket(dctx, bucket)
			}
		}
		return quorumError(bucket, "", countNil(errs), x.writeQuorum(), errs)
	}
	if mopts.ObjectLock {
		errs := x.each(ctx, func(d *drive) error {
			if err := d.WriteBucketVersioning(ctx, bucket, string(storage.VersioningEnabled), 1); err != nil {
				return err
			}
			return d.WriteBucketObjectLock(ctx, bucket, objlock.Encode(storage.ObjectLockConfig{Enabled: true}), 1)
		})
		if countNil(errs) < x.writeQuorum() {
			dctx, cancel := detached(ctx)
			defer cancel()
			for _, d := range x.drives {
				d.DeleteBucket(dctx, bucket)
			}
			return quorumError(bucket, "", countNil(errs), x.writeQuorum(), errs)
		}
		x.noteVersioning(bucket, storage.VersioningConfig{State: storage.VersioningEnabled, Seq: 1})
	}
	return nil
}

// bucketCreated is the earliest creation time any drive recorded.
func (x *XL) bucketCreated(ctx context.Context, bucket string) time.Time {
	var best time.Time
	for _, d := range x.drives {
		exists, t, err := d.StatBucket(ctx, bucket)
		if err != nil || !exists || t.IsZero() {
			continue
		}
		if best.IsZero() || t.Before(best) {
			best = t
		}
	}
	return best
}

// GetBucketInfo returns the bucket's name and creation time.
func (x *XL) GetBucketInfo(ctx context.Context, bucket string) (storage.BucketInfo, error) {
	if err := storage.ValidateBucketName(bucket); err != nil {
		return storage.BucketInfo{}, err
	}
	if err := x.enter(ctx); err != nil {
		return storage.BucketInfo{}, err
	}
	defer x.leave()
	if err := x.requireBucket(ctx, bucket); err != nil {
		return storage.BucketInfo{}, err
	}
	return storage.BucketInfo{Name: bucket, Created: x.bucketCreated(ctx, bucket)}, nil
}

// BucketExists reports whether bucket exists on a read quorum of drives.
func (x *XL) BucketExists(ctx context.Context, bucket string) (bool, error) {
	if err := storage.ValidateBucketName(bucket); err != nil {
		return false, err
	}
	if err := x.enter(ctx); err != nil {
		return false, err
	}
	defer x.leave()
	return x.bucketExists(ctx, bucket)
}

// ListBuckets lists buckets present on at least a read quorum of drives.
func (x *XL) ListBuckets(ctx context.Context) ([]storage.BucketInfo, error) {
	if err := x.enter(ctx); err != nil {
		return nil, err
	}
	defer x.leave()
	counts := map[string]int{}
	for _, d := range x.drives {
		names, err := d.ListBuckets(ctx)
		if err != nil {
			continue
		}
		for _, name := range names {
			counts[name]++
		}
	}
	var out []storage.BucketInfo
	for name, c := range counts {
		if c >= x.k {
			out = append(out, storage.BucketInfo{Name: name, Created: x.bucketCreated(ctx, name)})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// DeleteBucket removes the bucket from every drive. Without Force it fails
// if any object or in-progress upload exists.
func (x *XL) DeleteBucket(ctx context.Context, bucket string, opts storage.DeleteBucketOptions) error {
	if err := storage.ValidateBucketName(bucket); err != nil {
		return err
	}
	if err := x.enter(ctx); err != nil {
		return err
	}
	defer x.leave()
	unlock, err := x.locker.Lock(ctx, bucket, "")
	if err != nil {
		return err
	}
	defer unlock()
	if err := x.requireBucket(ctx, bucket); err != nil {
		return err
	}
	if opts.Force {
		if err := x.checkForceDelete(ctx, bucket); err != nil {
			return err
		}
	}
	if !opts.Force {
		has, err := x.hasObjects(ctx, bucket)
		if err != nil {
			return mapErr(err, bucket, "")
		}
		if has || x.hasUploads(ctx, bucket) {
			return storage.Wrap(storage.ErrBucketNotEmpty, bucket, "")
		}
	}
	errs := x.each(ctx, func(d *drive) error { return d.DeleteBucket(ctx, bucket) })
	if countNil(errs) < x.writeQuorum() {
		return quorumError(bucket, "", countNil(errs), x.writeQuorum(), errs)
	}
	return nil
}

// listKeys returns the union of keys under bucket/prefix from enough
// drives to be certain of seeing every committed object: an object lives on
// at least K drives, so any M+1 drives include one of them.
func (x *XL) listKeys(ctx context.Context, bucket, prefix string) ([]string, error) {
	need := x.m + 1
	var chosen []*drive
	for _, d := range x.drives {
		if d.Ready(ctx) {
			chosen = append(chosen, d)
			if len(chosen) == need {
				break
			}
		}
	}
	if len(chosen) < need && len(chosen) < x.k {
		return nil, storage.Wrap(storage.ErrBackendUnavailable, bucket, "")
	}
	results := make([][]string, len(chosen))
	errs := make([]error, len(chosen))
	var wg syncWG
	for i, d := range chosen {
		wg.Go(func() {
			results[i], errs[i] = d.ListKeys(ctx, bucket, prefix)
		})
	}
	wg.Wait()
	seen := map[string]bool{}
	var keys []string
	ok := 0
	for i, r := range results {
		if errs[i] != nil {
			if errors.Is(errs[i], context.Canceled) || errors.Is(errs[i], context.DeadlineExceeded) {
				return nil, errs[i]
			}
			continue
		}
		ok++
		for _, k := range r {
			if !seen[k] {
				seen[k] = true
				keys = append(keys, k)
			}
		}
	}
	if ok == 0 {
		return nil, storage.Wrap(storage.ErrBackendUnavailable, bucket, "")
	}
	return keys, nil
}

// hasObjects reports whether any committed object exists in bucket.
func (x *XL) hasObjects(ctx context.Context, bucket string) (bool, error) {
	keys, err := x.listKeys(ctx, bucket, "")
	if err != nil {
		return false, err
	}
	for _, k := range keys {
		if st := x.stateOf(ctx, bucket, k); st.found(x.k) {
			return true, nil
		}
	}
	return false, nil
}

// versioningView is what the drives say about a bucket's settings: the
// versioning state and the object lock configuration, each with the
// sequence number of the change that wrote it.
type versioningView struct {
	cfg  storage.VersioningConfig
	lock lockView
	// laggards are drives whose versioning answer differs from the agreed
	// one; lockLaggards likewise for object lock.
	laggards, lockLaggards []int
}

// lockView is a bucket's object lock configuration and its change sequence.
type lockView struct {
	cfg storage.ObjectLockConfig
	seq uint64
}

// versioning returns the settings a read quorum of drives agrees on: for
// each of the two documents, the (value, sequence) pair held by at least K
// drives, the highest sequence winning if several qualify. The fast path
// returns when K drives have answered and agree; a disagreement (a drive
// that missed a change, or a change that reached fewer than K) falls back to
// hearing every drive.
func (x *XL) versioning(ctx context.Context, bucket string) (versioningView, error) {
	collect := func(answers []disk.BucketSettings, errs []error) (versioningView, error) {
		type vpair struct {
			state string
			seq   uint64
		}
		type lpair struct {
			doc string
			seq uint64
		}
		vcount, lcount := map[vpair]int{}, map[lpair]int{}
		absent := 0
		for i, err := range errs {
			switch {
			case err == nil:
				a := answers[i]
				vcount[vpair{a.Versioning, a.VersioningSeq}]++
				lcount[lpair{a.ObjectLock, a.ObjectLockSeq}]++
			case errors.Is(err, disk.ErrNotFound):
				absent++
			}
		}
		var vbest vpair
		vok := false
		for p, n := range vcount {
			if n >= x.k && (!vok || p.seq > vbest.seq) {
				vbest, vok = p, true
			}
		}
		var lbest lpair
		lok := false
		for p, n := range lcount {
			if n >= x.k && (!lok || p.seq > lbest.seq) {
				lbest, lok = p, true
			}
		}
		if !vok || !lok {
			if absent > len(x.drives)-x.k {
				return versioningView{}, storage.Wrap(storage.ErrBucketNotFound, bucket, "")
			}
			return versioningView{}, errNoVersioningQuorum
		}
		lcfg, err := objlock.Decode(lbest.doc)
		if err != nil {
			return versioningView{}, storage.Wrap(err, bucket, "")
		}
		v := versioningView{
			cfg:  storage.VersioningConfig{State: storage.VersioningState(vbest.state), Seq: vbest.seq},
			lock: lockView{cfg: lcfg, seq: lbest.seq},
		}
		for i, err := range errs {
			if err != nil {
				continue
			}
			if a := answers[i]; a.Versioning != vbest.state || a.VersioningSeq != vbest.seq {
				v.laggards = append(v.laggards, i)
			}
			if a := answers[i]; a.ObjectLock != lbest.doc || a.ObjectLockSeq != lbest.seq {
				v.lockLaggards = append(v.lockLaggards, i)
			}
		}
		return v, nil
	}
	answers, errs := scatter(ctx, x, x.k, x.stragglerGrace, true, false,
		func(ctx context.Context, d *drive) (disk.BucketSettings, error) {
			return d.ReadBucketSettings(ctx, bucket)
		}, nil)
	v, err := collect(answers, errs)
	if err != errNoVersioningQuorum {
		return v, err
	}
	// Full pass.
	answers = make([]disk.BucketSettings, len(x.drives))
	errs = x.each(ctx, func(d *drive) error {
		var err error
		answers[d.idx], err = d.ReadBucketSettings(ctx, bucket)
		return err
	})
	if v, err = collect(answers, errs); err == errNoVersioningQuorum {
		return v, storage.Wrap(fmt.Errorf("%w: no read quorum agrees on the bucket settings", storage.ErrBackendUnavailable), bucket, "")
	}
	return v, err
}

var errNoVersioningQuorum = errors.New("xl: no agreed versioning state")

// GetBucketVersioning implements storage.StorageAPI.
func (x *XL) GetBucketVersioning(ctx context.Context, bucket string) (storage.VersioningConfig, error) {
	if err := storage.ValidateBucketName(bucket); err != nil {
		return storage.VersioningConfig{}, err
	}
	if err := x.enter(ctx); err != nil {
		return storage.VersioningConfig{}, err
	}
	defer x.leave()
	unlock, err := x.locker.RLock(ctx, bucket, "")
	if err != nil {
		return storage.VersioningConfig{}, err
	}
	defer unlock()
	v, err := x.versioning(ctx, bucket)
	return v.cfg, mapErr(err, bucket, "")
}

// SetBucketVersioning implements storage.StorageAPI. The bucket lock is
// taken exclusively, so object writes (which hold it shared) see the state
// before or after the change, never a mixture; the change itself must reach
// a write quorum of drives.
func (x *XL) SetBucketVersioning(ctx context.Context, bucket string, state storage.VersioningState) error {
	if err := storage.ValidateBucketName(bucket); err != nil {
		return err
	}
	if !state.Valid() {
		return storage.Wrap(storage.ErrIllegalVersioning, bucket, "")
	}
	if err := x.enter(ctx); err != nil {
		return err
	}
	defer x.leave()
	unlock, err := x.locker.Lock(ctx, bucket, "")
	if err != nil {
		return err
	}
	defer unlock()
	if err := x.requireBucket(ctx, bucket); err != nil {
		return err
	}
	cur, err := x.versioning(ctx, bucket)
	if err != nil {
		return mapErr(err, bucket, "")
	}
	if err := storage.CheckVersioningTransition(cur.cfg.State, state); err != nil {
		return storage.Wrap(err, bucket, "")
	}
	if state == cur.cfg.State {
		return nil
	}
	if state != storage.VersioningEnabled && cur.lock.cfg.Enabled {
		return storage.Wrap(fmt.Errorf("%w: versioning cannot be suspended on a bucket with object lock", storage.ErrInvalidBucketState), bucket, "")
	}
	seq := cur.cfg.Seq + 1
	errs := x.each(ctx, func(d *drive) error {
		return d.WriteBucketVersioning(ctx, bucket, string(state), seq)
	})
	if countNil(errs) < x.writeQuorum() {
		// Those that took it are put back, so a minority does not hold a
		// state the quorum does not.
		dctx, cancel := detached(ctx)
		defer cancel()
		for i, err := range errs {
			if err == nil {
				x.drives[i].WriteBucketVersioning(dctx, bucket, string(cur.cfg.State), cur.cfg.Seq)
			}
		}
		return quorumError(bucket, "", countNil(errs), x.writeQuorum(), errs)
	}
	if countNil(errs) < len(x.drives) {
		x.log.Warn("xl: versioning change did not reach every drive; heal will converge them", "bucket", bucket)
	}
	x.noteVersioning(bucket, storage.VersioningConfig{State: state, Seq: seq})
	return nil
}

// GetBucketObjectLock implements storage.StorageAPI.
func (x *XL) GetBucketObjectLock(ctx context.Context, bucket string) (storage.ObjectLockConfig, error) {
	if err := storage.ValidateBucketName(bucket); err != nil {
		return storage.ObjectLockConfig{}, err
	}
	if err := x.enter(ctx); err != nil {
		return storage.ObjectLockConfig{}, err
	}
	defer x.leave()
	unlock, err := x.locker.RLock(ctx, bucket, "")
	if err != nil {
		return storage.ObjectLockConfig{}, err
	}
	defer unlock()
	v, err := x.versioning(ctx, bucket)
	v.lock.cfg.Seq = v.lock.seq
	return v.lock.cfg, mapErr(err, bucket, "")
}

// SetBucketObjectLock implements storage.StorageAPI. Like a versioning
// change it runs under the exclusive bucket lock and must reach a write
// quorum, so a write sees the default retention from before or after it.
func (x *XL) SetBucketObjectLock(ctx context.Context, bucket string, cfg storage.ObjectLockConfig) error {
	if err := storage.ValidateBucketName(bucket); err != nil {
		return err
	}
	if err := x.enter(ctx); err != nil {
		return err
	}
	defer x.leave()
	unlock, err := x.locker.Lock(ctx, bucket, "")
	if err != nil {
		return err
	}
	defer unlock()
	if err := x.requireBucket(ctx, bucket); err != nil {
		return err
	}
	cur, err := x.versioning(ctx, bucket)
	if err != nil {
		return mapErr(err, bucket, "")
	}
	if err := objlock.CheckConfig(cur.lock.cfg, cfg); err != nil {
		return storage.Wrap(err, bucket, "")
	}
	doc, seq := objlock.Encode(cfg), cur.lock.seq+1
	prevDoc := objlock.Encode(cur.lock.cfg)
	errs := x.each(ctx, func(d *drive) error { return d.WriteBucketObjectLock(ctx, bucket, doc, seq) })
	if countNil(errs) < x.writeQuorum() {
		dctx, cancel := detached(ctx)
		defer cancel()
		for i, err := range errs {
			if err == nil {
				x.drives[i].WriteBucketObjectLock(dctx, bucket, prevDoc, cur.lock.seq)
			}
		}
		return quorumError(bucket, "", countNil(errs), x.writeQuorum(), errs)
	}
	if countNil(errs) < len(x.drives) {
		x.log.Warn("xl: object lock change did not reach every drive; heal will converge them", "bucket", bucket)
	}
	return nil
}

// checkForceDelete refuses a forced bucket deletion that would destroy a
// version object lock protects. Keys are confirmed by a metadata read
// quorum; one that cannot be read cannot be shown unprotected, so it blocks
// the deletion as well.
func (x *XL) checkForceDelete(ctx context.Context, bucket string) error {
	v, err := x.versioning(ctx, bucket)
	if err != nil {
		return mapErr(err, bucket, "")
	}
	if !v.lock.cfg.Enabled {
		return nil
	}
	keys, err := x.listKeys(ctx, bucket, "")
	if err != nil {
		return mapErr(err, bucket, "")
	}
	guard := objlock.Guard(time.Now(), false)
	for _, k := range keys {
		st := x.stateOf(ctx, bucket, k)
		if !st.found(x.k) {
			if st.missing(len(x.drives), x.k) {
				continue
			}
			return storage.Wrap(fmt.Errorf("%w: cannot verify that %q is unprotected", storage.ErrObjectLocked, k), bucket, "")
		}
		if err := st.file.Protected(guard); err != nil {
			return objlock.Err(err, bucket, k)
		}
	}
	return nil
}
