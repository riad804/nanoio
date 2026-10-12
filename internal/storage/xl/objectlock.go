package xl

import (
	"context"
	"time"

	"nanoio/internal/meta"
	"nanoio/internal/storage"
	"nanoio/internal/storage/internal/objlock"
	"nanoio/internal/storage/xl/disk"
)

// SetObjectRetention implements storage.StorageAPI.
func (x *XL) SetObjectRetention(ctx context.Context, ref storage.ObjectRef, r storage.Retention, opts storage.RetentionOptions) (storage.ObjectInfo, error) {
	return x.setLock(ctx, ref, func(cur *meta.Lock, now time.Time) (*meta.Lock, error) {
		if err := r.Validate(now); err != nil {
			return nil, err
		}
		next := &meta.Lock{Mode: meta.LockMode(r.Mode), RetainUntil: r.Until}
		if cur != nil {
			next.LegalHold = cur.LegalHold
		}
		return next, nil
	}, opts.BypassGovernance)
}

// SetObjectLegalHold implements storage.StorageAPI.
func (x *XL) SetObjectLegalHold(ctx context.Context, ref storage.ObjectRef, on bool) (storage.ObjectInfo, error) {
	return x.setLock(ctx, ref, func(cur *meta.Lock, _ time.Time) (*meta.Lock, error) {
		next := &meta.Lock{LegalHold: on}
		if cur != nil {
			next.Mode, next.RetainUntil = cur.Mode, cur.RetainUntil
		}
		return next, nil
	}, false)
}

// setLock replaces the lock of one version with what change returns for its
// current lock. It takes the locks a delete takes (bucket shared, key
// exclusive), judges the change on the quorum-agreed version list, and sends
// it to every drive as a generation-conditional operation, which each drive
// judges again.
func (x *XL) setLock(ctx context.Context, ref storage.ObjectRef, change func(cur *meta.Lock, now time.Time) (*meta.Lock, error), bypass bool) (storage.ObjectInfo, error) {
	var zero storage.ObjectInfo
	bucket, object := ref.Bucket, ref.Object
	if err := validate(bucket, object); err != nil {
		return zero, err
	}
	if _, err := storage.StoredVersionID(ref.VersionID); err != nil {
		return zero, storage.Wrap(err, bucket, object)
	}
	if err := x.enter(ctx); err != nil {
		return zero, err
	}
	defer x.leave()
	unlockBucket, err := x.locker.RLock(ctx, bucket, "")
	if err != nil {
		return zero, err
	}
	defer unlockBucket()
	unlockKey, err := x.locker.Lock(ctx, bucket, object)
	if err != nil {
		return zero, err
	}
	defer unlockKey()
	if err := x.requireBucket(ctx, bucket); err != nil {
		return zero, err
	}
	cfg, err := x.versioning(ctx, bucket)
	if err != nil {
		return zero, mapErr(err, bucket, object)
	}
	if !cfg.lock.cfg.Enabled {
		return zero, storage.Wrap(storage.ErrObjectLockNotEnabled, bucket, object)
	}
	st, err := x.lookup(ctx, bucket, object)
	if err != nil {
		return zero, err
	}
	v, latest, state, err := x.resolve(ctx, bucket, object, ref.VersionID, st)
	if err != nil {
		return zero, err
	}
	now := time.Now().UTC()
	next, err := change(v.Lock, now)
	if err != nil {
		return zero, storage.Wrap(err, bucket, object)
	}
	next = next.Normalized()
	guard := objlock.Guard(now, bypass)
	if err := meta.CheckLockChange(v.VersionID, v.Lock, next, guard); err != nil {
		return zero, objlock.Err(err, bucket, object)
	}
	prev := st.generation()
	spec := commitSpec{bucket: bucket, object: object, op: disk.OpSetLock, removeID: v.VersionID,
		lock: next, guard: guard, checkGen: true, prevGen: prev, need: x.writeQuorum(),
		participants: make([]bool, len(x.drives))}
	spec.tmpl.Seq = prev + 1
	for i, d := range x.drives {
		spec.participants[i] = d.Ready(ctx)
	}
	res := x.commit(ctx, spec)
	if err := x.finishCommit(ctx, spec, res); err != nil {
		return zero, mapErr(err, bucket, object)
	}
	nv := *v
	nv.Lock = next
	return toInfo(bucket, object, &nv, latest, state), nil
}
