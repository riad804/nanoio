package fs

import (
	"context"
	"encoding/json"
	"errors"
	iofs "io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	"nanoio/internal/meta"
	"nanoio/internal/storage"
	"nanoio/internal/storage/internal/fsutil"
	"nanoio/internal/storage/internal/objlock"
)

type bucketDoc struct {
	Created time.Time `json:"created"`
	// Versioning is "", "Enabled" or "Suspended"; VersioningSeq counts the
	// changes. Both are absent in a bucket that never had versioning.
	Versioning    string `json:"versioning,omitempty"`
	VersioningSeq uint64 `json:"versioningSeq,omitempty"`
	// ObjectLock is the object lock configuration document (see package
	// objlock); empty for a bucket created without object lock.
	ObjectLock    string `json:"objectLock,omitempty"`
	ObjectLockSeq uint64 `json:"objectLockSeq,omitempty"`
}

// MakeBucket creates bucket. The directory appears atomically with its
// marker file already inside it, via a rename from staging.
//
// A bucket created with object lock is born versioned (Enabled) and locked
// in the same marker, so there is no moment at which it accepts unprotected
// writes.
func (f *FS) MakeBucket(ctx context.Context, bucket string, mopts storage.MakeBucketOptions) error {
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

	dir, err := f.path(bucket)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(dir); err == nil {
		return storage.Wrap(storage.ErrBucketExists, bucket, "")
	} else if !errors.Is(err, iofs.ErrNotExist) {
		return err
	}
	id, err := meta.NewVersionID()
	if err != nil {
		return err
	}
	stage := filepath.Join(f.tmp, id)
	if err := os.Mkdir(stage, dirPerm); err != nil {
		return mapErr(err, bucket, "")
	}
	defer f.holdStage(stage)()
	defer os.RemoveAll(stage)
	bd := bucketDoc{Created: time.Now().UTC()}
	if mopts.ObjectLock {
		bd.Versioning, bd.VersioningSeq = string(storage.VersioningEnabled), 1
		bd.ObjectLock, bd.ObjectLockSeq = objlock.Encode(storage.ObjectLockConfig{Enabled: true}), 1
	}
	doc, err := json.Marshal(bd)
	if err != nil {
		return err
	}
	if err := fsutil.WriteFileSync(filepath.Join(stage, bucketMarker), doc, filePerm); err != nil {
		return mapErr(err, bucket, "")
	}
	if err := fsutil.SyncDir(stage); err != nil {
		return mapErr(err, bucket, "")
	}
	if err := os.Rename(stage, dir); err != nil {
		return mapErr(err, bucket, "")
	}
	return mapErr(fsutil.SyncDir(f.root), bucket, "")
}

// bucketInfo reads the marker, falling back to the directory mtime for a
// bucket whose marker is missing or unreadable.
func (f *FS) bucketInfo(bucket, dir string, st os.FileInfo) storage.BucketInfo {
	info := storage.BucketInfo{Name: bucket, Created: st.ModTime().UTC()}
	if data, err := os.ReadFile(filepath.Join(dir, bucketMarker)); err == nil {
		var doc bucketDoc
		if json.Unmarshal(data, &doc) == nil && !doc.Created.IsZero() {
			info.Created = doc.Created.UTC()
		}
	}
	return info
}

// GetBucketInfo returns bucket's name and creation time.
func (f *FS) GetBucketInfo(ctx context.Context, bucket string) (storage.BucketInfo, error) {
	if err := storage.ValidateBucketName(bucket); err != nil {
		return storage.BucketInfo{}, err
	}
	if err := f.enter(); err != nil {
		return storage.BucketInfo{}, err
	}
	defer f.leave()
	if err := f.requireBucket(bucket); err != nil {
		return storage.BucketInfo{}, err
	}
	dir, _ := f.path(bucket)
	st, err := os.Stat(dir)
	if err != nil {
		return storage.BucketInfo{}, mapErr(err, bucket, "")
	}
	return f.bucketInfo(bucket, dir, st), nil
}

// BucketExists reports whether bucket exists.
func (f *FS) BucketExists(ctx context.Context, bucket string) (bool, error) {
	if err := storage.ValidateBucketName(bucket); err != nil {
		return false, err
	}
	if err := f.enter(); err != nil {
		return false, err
	}
	defer f.leave()
	err := f.requireBucket(bucket)
	if errors.Is(err, storage.ErrBucketNotFound) {
		return false, nil
	}
	return err == nil, err
}

// ListBuckets returns all buckets sorted by name.
func (f *FS) ListBuckets(ctx context.Context) ([]storage.BucketInfo, error) {
	if err := f.enter(); err != nil {
		return nil, err
	}
	defer f.leave()
	entries, err := os.ReadDir(f.root)
	if err != nil {
		return nil, err
	}
	out := make([]storage.BucketInfo, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() || storage.ValidateBucketName(e.Name()) != nil {
			continue // files, symlinks, .nanoio.sys, strays
		}
		st, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, f.bucketInfo(e.Name(), filepath.Join(f.root, e.Name()), st))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// DeleteBucket removes bucket. Without Force it fails with ErrBucketNotEmpty
// if any object exists. The directory is renamed into staging first so the
// bucket disappears atomically.
func (f *FS) DeleteBucket(ctx context.Context, bucket string, opts storage.DeleteBucketOptions) error {
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
	dir, _ := f.path(bucket)
	if opts.Force {
		// Forced deletion removes every version at once; it must not be a
		// way around object lock.
		if err := f.checkForceDelete(ctx, bucket, dir); err != nil {
			return err
		}
	}
	if !opts.Force {
		has, err := hasObjects(ctx, dir)
		if err != nil {
			return mapErr(err, bucket, "")
		}
		// Like S3, a bucket with incomplete multipart uploads is not empty.
		if has || f.hasUploads(bucket) {
			return storage.Wrap(storage.ErrBucketNotEmpty, bucket, "")
		}
	}
	if opts.Force {
		if err := f.removeUploads(bucket); err != nil {
			return mapErr(err, bucket, "")
		}
	}
	id, err := meta.NewVersionID()
	if err != nil {
		return err
	}
	trash := filepath.Join(f.tmp, id)
	if err := os.Rename(dir, trash); err != nil {
		return mapErr(err, bucket, "")
	}
	if err := fsutil.SyncDir(f.root); err != nil {
		return mapErr(err, bucket, "")
	}
	return os.RemoveAll(trash)
}

var errFound = errors.New("found")

// hasObjects reports whether any xl.meta exists under a bucket directory.
func hasObjects(ctx context.Context, dir string) (bool, error) {
	err := filepath.WalkDir(dir, func(p string, d iofs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if !d.IsDir() && d.Name() == storage.MetaFileName {
			return errFound
		}
		return nil
	})
	if errors.Is(err, errFound) {
		return true, nil
	}
	return false, err
}
