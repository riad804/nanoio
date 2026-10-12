package fs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	iofs "io/fs"
	"os"
	"path/filepath"

	"nanoio/internal/meta"
	"nanoio/internal/storage"
	"nanoio/internal/storage/internal/fsutil"
	"nanoio/internal/storage/internal/objlock"
)

// readBucketDoc loads the bucket marker. A missing or unreadable marker
// reads as an unversioned bucket created at the directory's mtime, the same
// fallback bucketInfo uses.
func (f *FS) readBucketDoc(dir string) bucketDoc {
	var doc bucketDoc
	if data, err := os.ReadFile(filepath.Join(dir, bucketMarker)); err == nil {
		_ = json.Unmarshal(data, &doc)
	}
	return doc
}

// versioningOf reads the bucket's versioning state.
func (f *FS) versioningOf(bucket string) (storage.VersioningConfig, error) {
	dir, err := f.path(bucket)
	if err != nil {
		return storage.VersioningConfig{}, err
	}
	doc := f.readBucketDoc(dir)
	st := storage.VersioningState(doc.Versioning)
	if !st.Valid() {
		return storage.VersioningConfig{}, storage.Wrap(storage.ErrCorrupted, bucket, "")
	}
	return storage.VersioningConfig{State: st, Seq: doc.VersioningSeq}, nil
}

// metaVersioning converts a bucket state to what the meta functions use.
func metaVersioning(s storage.VersioningState) meta.Versioning {
	switch s {
	case storage.VersioningEnabled:
		return meta.Enabled
	case storage.VersioningSuspended:
		return meta.Suspended
	}
	return meta.Unversioned
}

// GetBucketVersioning implements storage.StorageAPI.
func (f *FS) GetBucketVersioning(ctx context.Context, bucket string) (storage.VersioningConfig, error) {
	if err := storage.ValidateBucketName(bucket); err != nil {
		return storage.VersioningConfig{}, err
	}
	if err := f.enter(); err != nil {
		return storage.VersioningConfig{}, err
	}
	defer f.leave()
	unlock, err := f.locker.RLock(ctx, bucket, "")
	if err != nil {
		return storage.VersioningConfig{}, err
	}
	defer unlock()
	if err := f.requireBucket(bucket); err != nil {
		return storage.VersioningConfig{}, err
	}
	return f.versioningOf(bucket)
}

// SetBucketVersioning implements storage.StorageAPI. It takes the bucket
// lock exclusively, so a write that holds the shared lock sees either the
// state before the change or the one after, never a mixture.
func (f *FS) SetBucketVersioning(ctx context.Context, bucket string, state storage.VersioningState) error {
	if err := storage.ValidateBucketName(bucket); err != nil {
		return err
	}
	if !state.Valid() {
		return storage.Wrap(storage.ErrIllegalVersioning, bucket, "")
	}
	if err := f.enter(); err != nil {
		return err
	}
	defer f.leave()
	unlock, err := f.locker.Lock(ctx, bucket, "")
	if err != nil {
		return err
	}
	defer unlock()
	if err := f.requireBucket(bucket); err != nil {
		return err
	}
	dir, err := f.path(bucket)
	if err != nil {
		return err
	}
	cur, err := f.versioningOf(bucket)
	if err != nil {
		return err
	}
	if err := storage.CheckVersioningTransition(cur.State, state); err != nil {
		return storage.Wrap(err, bucket, "")
	}
	if state == cur.State {
		return nil
	}
	if state != storage.VersioningEnabled {
		lock, err := f.objectLockOf(bucket)
		if err != nil {
			return err
		}
		if lock.cfg.Enabled {
			return storage.Wrap(fmt.Errorf("%w: versioning cannot be suspended on a bucket with object lock", storage.ErrInvalidBucketState), bucket, "")
		}
	}
	doc := f.readBucketDoc(dir)
	if doc.Created.IsZero() {
		// A marker that was lost or never written: keep the best creation
		// time available so the bucket's listing does not change.
		if st, serr := os.Stat(dir); serr == nil {
			doc.Created = st.ModTime().UTC()
		}
	}
	doc.Versioning, doc.VersioningSeq = string(state), cur.Seq+1
	return f.writeBucketDoc(bucket, dir, doc)
}

// writeBucketDoc replaces the bucket marker atomically.
func (f *FS) writeBucketDoc(bucket, dir string, doc bucketDoc) error {
	data, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	id, err := meta.NewVersionID()
	if err != nil {
		return err
	}
	staged := filepath.Join(f.tmp, "bucketdoc-"+id)
	defer f.holdStage(staged)()
	if err := fsutil.WriteFileSync(staged, data, filePerm); err != nil {
		os.Remove(staged)
		return mapErr(err, bucket, "")
	}
	if err := os.Rename(staged, filepath.Join(dir, bucketMarker)); err != nil {
		os.Remove(staged)
		if errors.Is(err, iofs.ErrNotExist) {
			return storage.Wrap(storage.ErrBucketNotFound, bucket, "")
		}
		return mapErr(err, bucket, "")
	}
	return mapErr(fsutil.SyncDir(dir), bucket, "")
}

// lockView is a bucket's object lock configuration and its change sequence.
type lockView struct {
	cfg storage.ObjectLockConfig
	seq uint64
}

// objectLockOf reads the bucket's object lock configuration. A marker that
// exists but cannot be parsed is corruption, never "no lock": reading it as
// unlocked would let writes go unprotected.
func (f *FS) objectLockOf(bucket string) (lockView, error) {
	dir, err := f.path(bucket)
	if err != nil {
		return lockView{}, err
	}
	data, err := os.ReadFile(filepath.Join(dir, bucketMarker))
	switch {
	case errors.Is(err, iofs.ErrNotExist):
		return lockView{}, nil
	case err != nil:
		return lockView{}, mapErr(err, bucket, "")
	}
	var doc bucketDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return lockView{}, storage.Wrap(storage.ErrCorrupted, bucket, "")
	}
	cfg, err := objlock.Decode(doc.ObjectLock)
	if err != nil {
		return lockView{}, storage.Wrap(err, bucket, "")
	}
	return lockView{cfg: cfg, seq: doc.ObjectLockSeq}, nil
}

// GetBucketObjectLock implements storage.StorageAPI.
func (f *FS) GetBucketObjectLock(ctx context.Context, bucket string) (storage.ObjectLockConfig, error) {
	if err := storage.ValidateBucketName(bucket); err != nil {
		return storage.ObjectLockConfig{}, err
	}
	if err := f.enter(); err != nil {
		return storage.ObjectLockConfig{}, err
	}
	defer f.leave()
	unlock, err := f.locker.RLock(ctx, bucket, "")
	if err != nil {
		return storage.ObjectLockConfig{}, err
	}
	defer unlock()
	if err := f.requireBucket(bucket); err != nil {
		return storage.ObjectLockConfig{}, err
	}
	v, err := f.objectLockOf(bucket)
	v.cfg.Seq = v.seq
	return v.cfg, err
}

// SetBucketObjectLock implements storage.StorageAPI. Only the default
// retention can change; the bucket's lock cannot be switched on or off.
func (f *FS) SetBucketObjectLock(ctx context.Context, bucket string, cfg storage.ObjectLockConfig) error {
	if err := storage.ValidateBucketName(bucket); err != nil {
		return err
	}
	if err := f.enter(); err != nil {
		return err
	}
	defer f.leave()
	unlock, err := f.locker.Lock(ctx, bucket, "")
	if err != nil {
		return err
	}
	defer unlock()
	if err := f.requireBucket(bucket); err != nil {
		return err
	}
	dir, err := f.path(bucket)
	if err != nil {
		return err
	}
	cur, err := f.objectLockOf(bucket)
	if err != nil {
		return err
	}
	if err := objlock.CheckConfig(cur.cfg, cfg); err != nil {
		return storage.Wrap(err, bucket, "")
	}
	doc := f.readBucketDoc(dir)
	doc.ObjectLock, doc.ObjectLockSeq = objlock.Encode(cfg), cur.seq+1
	return f.writeBucketDoc(bucket, dir, doc)
}
