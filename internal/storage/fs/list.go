package fs

import (
	"context"

	"nanoio/internal/meta"
	"nanoio/internal/storage"
	"nanoio/internal/storage/internal/listing"
)

// ListObjects lists keys in UTF-8 byte order. It reads directories without
// taking object locks: renames are atomic, so each xl.meta read sees an old
// or a new state, never a torn one.
//
// Every matching key is collected and sorted before paging, so a list is
// O(matching keys); see TODO.md.
func (f *FS) ListObjects(ctx context.Context, bucket string, opts storage.ListOptions) (storage.ListResult, error) {
	if err := storage.ValidateBucketName(bucket); err != nil {
		return storage.ListResult{}, err
	}
	if err := f.enter(); err != nil {
		return storage.ListResult{}, err
	}
	defer f.leave()
	if err := f.requireBucket(bucket); err != nil {
		return storage.ListResult{}, err
	}
	bucketDir, _ := f.path(bucket)
	keys, err := listing.CollectKeys(ctx, bucketDir, opts.Prefix)
	if err != nil {
		return storage.ListResult{}, mapErr(err, bucket, "")
	}
	return listing.Page(keys, opts, func(key string) (storage.ObjectInfo, bool) {
		return f.loadInfo(bucket, key)
	}), nil
}

// ListObjectVersions lists every version and delete marker, keys ascending
// and each key's versions newest first, resuming after
// (opts.Marker, opts.VersionIDMarker). Like ListObjects it reads without
// object locks; each key's version list is one file, so it is internally
// consistent, but the listing as a whole is not a snapshot.
func (f *FS) ListObjectVersions(ctx context.Context, bucket string, opts storage.ListOptions) (storage.ListVersionsResult, error) {
	if err := storage.ValidateBucketName(bucket); err != nil {
		return storage.ListVersionsResult{}, err
	}
	if err := f.enter(); err != nil {
		return storage.ListVersionsResult{}, err
	}
	defer f.leave()
	if err := f.requireBucket(bucket); err != nil {
		return storage.ListVersionsResult{}, err
	}
	cfg, err := f.versioningOf(bucket)
	if err != nil {
		return storage.ListVersionsResult{}, err
	}
	bucketDir, _ := f.path(bucket)
	keys, err := listing.CollectKeys(ctx, bucketDir, opts.Prefix)
	if err != nil {
		return storage.ListVersionsResult{}, mapErr(err, bucket, "")
	}
	return listing.PageVersions(keys, opts, func(key string) ([]storage.ObjectInfo, bool) {
		keyDir, err := f.keyDir(bucket, key)
		if err != nil {
			return nil, false
		}
		file, err := f.readMeta(keyDir)
		if err != nil {
			f.corrupted.Add(1)
			f.log.Error("fs: skipping corrupt metadata in version listing", "bucket", bucket, "object", key, "err", err)
			return nil, false
		}
		if file == nil || len(file.Versions) == 0 {
			return nil, false
		}
		out := make([]storage.ObjectInfo, 0, len(file.Versions))
		for i := range file.Versions {
			out = append(out, toInfo(bucket, key, &file.Versions[i], i == 0, cfg.State))
		}
		return out, true
	}), nil
}

// loadInfo reads one key's latest version for listing. Corrupt metadata,
// delete markers and keys removed mid-list are skipped.
func (f *FS) loadInfo(bucket, key string) (storage.ObjectInfo, bool) {
	keyDir, err := f.keyDir(bucket, key)
	if err != nil {
		return storage.ObjectInfo{}, false
	}
	file, err := f.readMeta(keyDir)
	if err != nil {
		f.corrupted.Add(1)
		f.log.Error("fs: skipping corrupt metadata in listing", "bucket", bucket, "object", key, "err", err)
		return storage.ObjectInfo{}, false
	}
	if file == nil {
		return storage.ObjectInfo{}, false
	}
	v := file.Latest()
	if v == nil || v.Type != meta.TypeObject {
		return storage.ObjectInfo{}, false
	}
	return toInfo(bucket, key, v, true, storage.VersioningUnversioned), true
}
