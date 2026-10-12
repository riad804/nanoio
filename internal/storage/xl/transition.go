package xl

import (
	"context"
	"errors"
	"time"

	"nanoio/internal/meta"
	"nanoio/internal/storage"
	"nanoio/internal/storage/xl/disk"
)

// noteFreed reports a removed or overwritten stub to the owner of the tier.
func (x *XL) noteFreed(bucket, object string, v *meta.Version) {
	if x.onFreed == nil || v == nil || v.Transition == nil {
		return
	}
	t := v.Transition
	x.onFreed(bucket, object, storage.TransitionInfo{Tier: t.Tier, Object: t.Object, VersionID: t.VersionID, Time: t.Time})
}

var _ storage.Transitioner = (*XL)(nil)

// TransitionObject implements storage.Transitioner (a stub may be moved to a
// different tier, which frees its old remote copy): it commits, on every
// drive and under the key's exclusive lock, a stub in place of the version's
// data, conditional on the version still being the one whose bytes were
// uploaded (ifETag).
func (x *XL) TransitionObject(ctx context.Context, ref storage.ObjectRef, tr storage.TransitionInfo, ifETag string) (storage.ObjectInfo, error) {
	var zero storage.ObjectInfo
	bucket, object := ref.Bucket, ref.Object
	if err := validate(bucket, object); err != nil {
		return zero, err
	}
	if _, err := storage.StoredVersionID(ref.VersionID); err != nil {
		return zero, storage.Wrap(err, bucket, object)
	}
	if tr.Tier == "" || tr.Object == "" {
		return zero, storage.Wrap(errors.New("transition needs a tier and an object name"), bucket, object)
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
	st, err := x.lookup(ctx, bucket, object)
	if err != nil {
		return zero, err
	}
	v, latest, state, err := x.resolve(ctx, bucket, object, ref.VersionID, st)
	if err != nil {
		return zero, err
	}
	if v.Type != meta.TypeObject {
		return zero, storage.Wrap(storage.ErrObjectNotFound, bucket, object)
	}
	old := v.Transition
	if old != nil && old.Tier == tr.Tier {
		return zero, storage.Wrap(storage.ErrAlreadyTransitioned, bucket, object)
	}
	if ifETag != "" && v.ETag != ifETag {
		return zero, storage.Wrap(storage.ErrPreconditionFailed, bucket, object)
	}
	if tr.Time.IsZero() {
		tr.Time = time.Now()
	}
	mt := &meta.Transition{Tier: tr.Tier, Object: tr.Object, VersionID: tr.VersionID, Time: tr.Time.UTC()}
	prev := st.generation()
	spec := commitSpec{bucket: bucket, object: object, op: disk.OpTransition, removeID: v.VersionID,
		transition: mt, checkGen: true, prevGen: prev, need: x.writeQuorum(),
		participants: make([]bool, len(x.drives))}
	spec.tmpl.Seq = prev + 1
	for i, d := range x.drives {
		spec.participants[i] = d.Ready(ctx)
	}
	res := x.commit(ctx, spec)
	if err := x.finishCommit(ctx, spec, res); err != nil {
		return zero, mapErr(err, bucket, object)
	}
	if old != nil {
		x.noteFreed(bucket, object, &meta.Version{Transition: old}) // the replaced stub's remote copy
	}
	nv := *v
	nv.Transition, nv.DataDir, nv.Erasure = mt, "", nil
	return toInfo(bucket, object, &nv, latest, state), nil
}
