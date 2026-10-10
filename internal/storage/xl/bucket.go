package xl

import (
	"context"
	"errors"
	"sort"
	"time"

	"nanoio/internal/storage"
	"nanoio/internal/storage/xl/disk"
)

// bucketVote counts what the drives say about a bucket directory.
type bucketVote struct {
	present, absent, unavailable int
}

func (x *XL) voteBucket(ctx context.Context, bucket string) bucketVote {
	var v bucketVote
	errs := x.each(ctx, func(d *drive) error {
		exists, _, err := d.StatBucket(ctx, bucket)
		if err == nil && !exists {
			return disk.ErrNotFound
		}
		return err
	})
	for _, err := range errs {
		switch {
		case err == nil:
			v.present++
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
func (x *XL) MakeBucket(ctx context.Context, bucket string, _ storage.MakeBucketOptions) error {
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
