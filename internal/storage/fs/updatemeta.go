package fs

import (
	"context"
	"time"

	"nanoio/internal/meta"
	"nanoio/internal/storage"
)

// UpdateObjectMetadata implements storage.StorageAPI: it rewrites one
// version's metadata in place under the locks a delete takes, leaving the
// data untouched.
func (f *FS) UpdateObjectMetadata(ctx context.Context, bucket, object string, opts storage.UpdateMetaOptions) (storage.ObjectInfo, error) {
	var zero storage.ObjectInfo
	if err := validate(bucket, object); err != nil {
		return zero, err
	}
	if _, err := storage.StoredVersionID(opts.VersionID); err != nil {
		return zero, storage.Wrap(err, bucket, object)
	}
	if err := f.enter(); err != nil {
		return zero, err
	}
	defer f.leave()
	unlockBucket, err := f.locker.RLock(ctx, bucket, "")
	if err != nil {
		return zero, err
	}
	defer unlockBucket()
	unlockKey, err := f.locker.Lock(ctx, bucket, object)
	if err != nil {
		return zero, err
	}
	defer unlockKey()
	if err := f.requireBucket(bucket); err != nil {
		return zero, err
	}
	v, _, keyDir, _, err := f.lookup(bucket, object, opts.VersionID)
	if err != nil {
		return zero, err
	}
	cfg, err := f.versioningOf(bucket)
	if err != nil {
		return zero, err
	}
	file, err := f.readMeta(keyDir)
	if err != nil || file == nil {
		return zero, storage.Wrap(storage.ErrObjectNotFound, bucket, object)
	}
	if opts.IfETag != "" && v.ETag != opts.IfETag {
		return zero, storage.Wrap(storage.ErrPreconditionFailed, bucket, object)
	}
	upd := meta.MetaUpdate{}
	if opts.UserDefined != nil {
		upd.UserMeta = make(map[string]string, len(opts.UserDefined))
		for k, val := range opts.UserDefined {
			upd.UserMeta[k] = val
		}
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
	if err := file.ApplySetMeta(v.VersionID, file.Generation()+1, upd); err != nil {
		return zero, storage.Wrap(err, bucket, object)
	}
	if err := f.persist(bucket, object, keyDir, file, nil); err != nil {
		return zero, err
	}
	nv := file.Find(v.VersionID)
	return toInfo(bucket, object, nv, nv == file.Latest(), cfg.State), nil
}
