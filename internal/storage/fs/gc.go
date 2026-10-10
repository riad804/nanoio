package fs

import (
	"context"
	"encoding/json"
	"errors"
	iofs "io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"nanoio/internal/storage"
)

// GCStats counts what one collection pass removed.
type GCStats struct {
	// StagingEntries are leftovers of interrupted writes in .nanoio.sys/tmp
	// older than the staging age limit.
	StagingEntries int
	// ExpiredUploads are multipart uploads with no activity for longer
	// than the upload expiry, or whose bucket no longer exists.
	ExpiredUploads int
	// OrphanPartFiles are part data files inside a live upload that no
	// part metadata references (a part replaced or interrupted mid-commit).
	OrphanPartFiles int
	// OrphanDataDirs are object data directories that no xl.meta
	// references (a crash between moving the data and committing).
	OrphanDataDirs int
	// EmptyDirs are key directories left empty by crashes or deletes.
	EmptyDirs int
}

// Total is the number of items removed.
func (s GCStats) Total() int {
	return s.StagingEntries + s.ExpiredUploads + s.OrphanPartFiles + s.OrphanDataDirs + s.EmptyDirs
}

// gcLoop runs a collection pass every interval until ctx is cancelled.
func (f *FS) gcLoop(ctx context.Context, interval time.Duration) {
	defer close(f.gcDone)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		stats, err := f.gc(ctx)
		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, storage.ErrBackendUnavailable):
			return
		case err != nil:
			f.log.Warn("fs: garbage collection failed", "err", err)
		case stats.Total() > 0:
			f.log.Info("fs: garbage collection", "staging", stats.StagingEntries,
				"expiredUploads", stats.ExpiredUploads, "orphanParts", stats.OrphanPartFiles,
				"orphanDataDirs", stats.OrphanDataDirs, "emptyDirs", stats.EmptyDirs)
		}
	}
}

// GC runs one collection pass now and reports what it removed.
//
// The collector is conservative by construction. It deletes an object data
// directory or an upload part file only after taking the same lock the
// writer holds while it publishes that item and re-reading the metadata
// under it, so anything unreferenced at that point is garbage, never a
// commit in progress. It never deletes anything next to metadata it cannot
// read: a corrupt xl.meta is reported, not "cleaned".
func (f *FS) GC(ctx context.Context) (GCStats, error) {
	if err := f.enter(); err != nil {
		return GCStats{}, err
	}
	defer f.leave()
	return f.gc(ctx)
}

func (f *FS) gc(ctx context.Context) (GCStats, error) {
	var st GCStats
	st.StagingEntries = f.sweepTmp(f.tmpMaxAge)
	if err := f.gcUploads(ctx, &st); err != nil {
		return st, err
	}
	if err := f.gcObjects(ctx, &st); err != nil {
		return st, err
	}
	return st, nil
}

// gcUploads expires abandoned uploads and removes orphaned part files.
func (f *FS) gcUploads(ctx context.Context, st *GCStats) error {
	root, err := f.path(sysDirName, multipartDirName)
	if err != nil {
		return err
	}
	buckets, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, b := range buckets {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !b.IsDir() || storage.ValidateBucketName(b.Name()) != nil {
			continue
		}
		bucket := b.Name()
		bdir := filepath.Join(root, bucket)
		uploads, err := os.ReadDir(bdir)
		if err != nil {
			continue
		}
		for _, u := range uploads {
			if err := ctx.Err(); err != nil {
				return err
			}
			if !u.IsDir() || !uploadIDRE.MatchString(u.Name()) {
				continue
			}
			f.gcUpload(ctx, st, bucket, u.Name())
		}
		os.Remove(bdir) // only succeeds when no upload is left
	}
	return nil
}

func (f *FS) gcUpload(ctx context.Context, st *GCStats, bucket, id string) {
	dir, err := f.uploadDir(bucket, id)
	if err != nil {
		return
	}
	info, err := os.Stat(dir)
	if err != nil {
		return
	}
	bucketGone := f.requireBucket(bucket) != nil
	if !bucketGone && time.Since(info.ModTime()) <= f.uploadExpiry {
		f.gcOrphanParts(ctx, st, bucket, id, dir)
		return
	}
	// Expired (or its bucket vanished). Re-check under the locks: a part
	// may have just been committed.
	unlockBucket, err := f.locker.RLock(ctx, bucket, "")
	if err != nil {
		return
	}
	defer unlockBucket()
	unlock, err := f.locker.Lock(ctx, bucket, uploadLockKey(id))
	if err != nil {
		return
	}
	defer unlock()
	info, err = os.Stat(dir)
	if err != nil {
		return
	}
	if !bucketGone && f.requireBucket(bucket) == nil && time.Since(info.ModTime()) <= f.uploadExpiry {
		return
	}
	if err := f.discardDir(dir); err != nil {
		f.log.Warn("fs: could not remove expired upload", "bucket", bucket, "upload", id, "err", err)
		return
	}
	st.ExpiredUploads++
}

// gcOrphanParts removes part data files of a live upload that no part
// metadata names.
func (f *FS) gcOrphanParts(ctx context.Context, st *GCStats, bucket, id, dir string) {
	orphans := func() []string {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil
		}
		referenced := map[string]bool{}
		for _, e := range entries {
			if partMetaRE.MatchString(e.Name()) {
				if pd, ok := readPartDoc(filepath.Join(dir, e.Name())); ok {
					referenced[pd.File] = true
				} else {
					return nil // unreadable metadata: touch nothing
				}
			}
		}
		var out []string
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".data") && !referenced[e.Name()] {
				out = append(out, e.Name())
			}
		}
		return out
	}
	if len(orphans()) == 0 {
		return
	}
	unlockBucket, err := f.locker.RLock(ctx, bucket, "")
	if err != nil {
		return
	}
	defer unlockBucket()
	unlock, err := f.locker.Lock(ctx, bucket, uploadLockKey(id))
	if err != nil {
		return
	}
	defer unlock()
	for _, name := range orphans() { // re-evaluated under the lock
		if os.Remove(filepath.Join(dir, name)) == nil {
			st.OrphanPartFiles++
		}
	}
}

// gcObjects walks every bucket for unreferenced data directories and empty
// key directories.
func (f *FS) gcObjects(ctx context.Context, st *GCStats) error {
	entries, err := os.ReadDir(f.root)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !e.IsDir() || storage.ValidateBucketName(e.Name()) != nil {
			continue
		}
		bucket := e.Name()
		bdir := filepath.Join(f.root, bucket)
		var empties []string
		err := filepath.WalkDir(bdir, func(p string, d iofs.DirEntry, err error) error {
			if err != nil {
				if errors.Is(err, iofs.ErrNotExist) {
					return nil
				}
				return err
			}
			if cerr := ctx.Err(); cerr != nil {
				return cerr
			}
			if !d.IsDir() || p == bdir {
				return nil
			}
			if strings.HasPrefix(d.Name(), storage.DataDirPrefix) {
				return filepath.SkipDir
			}
			children, rerr := os.ReadDir(p)
			if rerr != nil {
				return nil
			}
			if len(children) == 0 {
				empties = append(empties, p)
				return nil
			}
			for _, c := range children {
				if c.IsDir() && strings.HasPrefix(c.Name(), storage.DataDirPrefix+"data-") {
					f.gcKeyDir(ctx, st, bucket, bdir, p)
					break
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
		for _, d := range empties {
			f.pruneEmpty(st, bdir, d)
		}
	}
	return nil
}

// pruneEmpty removes d if it is empty, then any parent that became empty.
// A concurrent writer that needs the directory recreates it (its commit
// retries on exactly this race).
func (f *FS) pruneEmpty(st *GCStats, bucketDir, d string) {
	for d != bucketDir && strings.HasPrefix(d, bucketDir) {
		if os.Remove(d) != nil {
			return
		}
		st.EmptyDirs++
		d = filepath.Dir(d)
	}
}

// keyOfDir recovers the object key a key directory holds.
func keyOfDir(bucketDir, dir string) string {
	rel, err := filepath.Rel(bucketDir, dir)
	if err != nil {
		return ""
	}
	key := filepath.ToSlash(rel)
	if strings.HasSuffix(key, storage.DirObjectSuffix) {
		key = strings.TrimSuffix(key, storage.DirObjectSuffix) + "/"
	}
	return key
}

// gcKeyDir removes data directories under dir that its xl.meta does not
// reference.
func (f *FS) gcKeyDir(ctx context.Context, st *GCStats, bucket, bucketDir, dir string) {
	unreferenced := func() ([]string, bool) {
		file, err := f.readMeta(dir)
		if err != nil {
			f.log.Warn("fs: not collecting next to unreadable metadata", "dir", dir, "err", err)
			return nil, false
		}
		keep := map[string]bool{}
		if file != nil {
			for _, v := range file.Versions {
				if v.DataDir != "" {
					keep[v.DataDir] = true
				}
			}
		}
		children, err := os.ReadDir(dir)
		if err != nil {
			return nil, false
		}
		var out []string
		for _, c := range children {
			if c.IsDir() && strings.HasPrefix(c.Name(), storage.DataDirPrefix+"data-") && !keep[c.Name()] {
				out = append(out, c.Name())
			}
		}
		return out, true
	}
	if orphans, ok := unreferenced(); !ok || len(orphans) == 0 {
		return
	}
	key := keyOfDir(bucketDir, dir)
	if key == "" {
		return
	}
	unlockBucket, err := f.locker.RLock(ctx, bucket, "")
	if err != nil {
		return
	}
	defer unlockBucket()
	unlock, err := f.locker.Lock(ctx, bucket, key)
	if err != nil {
		return
	}
	defer unlock()
	orphans, ok := unreferenced() // re-read under the key lock
	if !ok {
		return
	}
	for _, name := range orphans {
		path := filepath.Join(dir, name)
		if f.pins.Pinned(path) {
			continue // a reader is still streaming from the replaced version
		}
		if err := os.RemoveAll(path); err != nil {
			f.log.Warn("fs: could not remove orphaned data dir", "dir", dir, "name", name, "err", err)
			continue
		}
		st.OrphanDataDirs++
	}
	if len(orphans) > 0 {
		f.pruneEmpty(st, bucketDir, dir)
	}
}

func readPartDoc(path string) (partDoc, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return partDoc{}, false
	}
	var pd partDoc
	if err := json.Unmarshal(data, &pd); err != nil || pd.File == "" {
		return partDoc{}, false
	}
	return pd, true
}
