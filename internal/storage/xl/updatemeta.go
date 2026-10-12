package xl

import (
	"context"
	"time"

	"nanoio/internal/meta"
	"nanoio/internal/storage"
	"nanoio/internal/storage/xl/disk"
)

// UpdateObjectMetadata implements storage.StorageAPI. It changes one
// version's metadata on every drive without touching its data: the same
// locks as a delete (bucket shared, key exclusive) and a
// generation-conditional OpSetMeta that each drive applies to its own
// xl.meta.
func (x *XL) UpdateObjectMetadata(ctx context.Context, bucket, object string, opts storage.UpdateMetaOptions) (storage.ObjectInfo, error) {
	var zero storage.ObjectInfo
	if err := validate(bucket, object); err != nil {
		return zero, err
	}
	if _, err := storage.StoredVersionID(opts.VersionID); err != nil {
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
	st, err := x.lookup(ctx, bucket, object)
	if err != nil {
		return zero, err
	}
	v, latest, state, err := x.resolve(ctx, bucket, object, opts.VersionID, st)
	if err != nil {
		return zero, err
	}
	if opts.IfETag != "" && v.ETag != opts.IfETag {
		return zero, storage.Wrap(storage.ErrPreconditionFailed, bucket, object)
	}
	upd := &meta.MetaUpdate{}
	if opts.UserDefined != nil {
		upd.UserMeta = copyMap(opts.UserDefined)
		upd.ClearUserMeta = len(opts.UserDefined) == 0
	}
	if opts.ContentType != "" {
		ct := opts.ContentType
		upd.ContentType = &ct
	}
	if opts.Touch {
		now := time.Now().UTC()
		upd.ModTime = &now
	}
	prev := st.generation()
	spec := commitSpec{bucket: bucket, object: object, op: disk.OpSetMeta, removeID: v.VersionID,
		metaUpd: upd, checkGen: true, prevGen: prev, need: x.writeQuorum(),
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
	if upd.UserMeta != nil || upd.ClearUserMeta {
		nv.UserMeta = upd.UserMeta
	}
	if upd.ContentType != nil {
		nv.ContentType = *upd.ContentType
	}
	if upd.ModTime != nil {
		nv.ModTime = *upd.ModTime
	}
	return toInfo(bucket, object, &nv, latest, state), nil
}
