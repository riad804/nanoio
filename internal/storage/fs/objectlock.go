package fs

import (
	"context"
	"errors"
	iofs "io/fs"
	"os"
	"path/filepath"
	"time"

	"nanoio/internal/meta"
	"nanoio/internal/storage"
	"nanoio/internal/storage/internal/objlock"
)

// checkForceDelete refuses a forced bucket deletion that would destroy a
// version object lock protects. A metadata file that cannot be read cannot
// be shown to be unprotected, so it blocks the deletion too.
func (f *FS) checkForceDelete(ctx context.Context, bucket, dir string) error {
	lock, err := f.objectLockOf(bucket)
	if err != nil {
		return err
	}
	if !lock.cfg.Enabled {
		return nil
	}
	guard := objlock.Guard(time.Now(), false)
	err = filepath.WalkDir(dir, func(p string, d iofs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if d.IsDir() || d.Name() != storage.MetaFileName {
			return nil
		}
		data, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		file, derr := meta.Decode(data)
		if derr != nil {
			return storage.ErrCorrupted
		}
		return file.Protected(guard)
	})
	switch {
	case err == nil:
		return nil
	case errors.Is(err, storage.ErrCorrupted):
		return storage.Wrap(storage.ErrObjectLocked, bucket, "")
	}
	return objlock.Err(err, bucket, "")
}

// SetObjectRetention implements storage.StorageAPI.
func (f *FS) SetObjectRetention(ctx context.Context, ref storage.ObjectRef, r storage.Retention, opts storage.RetentionOptions) (storage.ObjectInfo, error) {
	return f.setLock(ctx, ref, func(cur *meta.Lock) (*meta.Lock, error) {
		now := time.Now()
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
func (f *FS) SetObjectLegalHold(ctx context.Context, ref storage.ObjectRef, on bool) (storage.ObjectInfo, error) {
	return f.setLock(ctx, ref, func(cur *meta.Lock) (*meta.Lock, error) {
		next := &meta.Lock{LegalHold: on}
		if cur != nil {
			next.Mode, next.RetainUntil = cur.Mode, cur.RetainUntil
		}
		return next, nil
	}, false)
}

// setLock replaces the lock of one version with what change returns for its
// current lock. It takes the same locks as a delete (bucket shared, key
// exclusive) and judges the change with the same meta rules.
func (f *FS) setLock(ctx context.Context, ref storage.ObjectRef, change func(cur *meta.Lock) (*meta.Lock, error), bypass bool) (storage.ObjectInfo, error) {
	var zero storage.ObjectInfo
	bucket, object := ref.Bucket, ref.Object
	if err := validate(bucket, object); err != nil {
		return zero, err
	}
	if _, err := storage.StoredVersionID(ref.VersionID); err != nil {
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
	lock, err := f.objectLockOf(bucket)
	if err != nil {
		return zero, err
	}
	if !lock.cfg.Enabled {
		return zero, storage.Wrap(storage.ErrObjectLockNotEnabled, bucket, object)
	}
	v, _, keyDir, _, err := f.lookup(bucket, object, ref.VersionID)
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
	next, err := change(v.Lock)
	if err != nil {
		return zero, storage.Wrap(err, bucket, object)
	}
	if err := file.ApplySetLock(v.VersionID, file.Generation()+1, next, objlock.Guard(time.Now(), bypass)); err != nil {
		return zero, objlock.Err(err, bucket, object)
	}
	if err := f.persist(bucket, object, keyDir, file, nil); err != nil {
		return zero, err
	}
	nv := file.Find(v.VersionID)
	return toInfo(bucket, object, nv, nv == file.Latest(), cfg.State), nil
}
