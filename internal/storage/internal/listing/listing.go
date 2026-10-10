// Package listing holds the parts of S3 listing semantics that are
// independent of how objects are stored: walking a bucket directory for
// keys, and turning a key set into a correctly ordered, delimited and
// paginated page. The fs and xl backends share it so their listings agree.
package listing

import (
	"context"
	"errors"
	iofs "io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"nanoio/internal/storage"
)

// MaxKeys is S3's page size cap.
const MaxKeys = 1000

// CollectKeys returns every key under bucketDir with the given prefix that
// has an xl.meta on disk, in no particular order. Directories that cannot
// hold a match are pruned.
func CollectKeys(ctx context.Context, bucketDir, prefix string) ([]string, error) {
	var keys []string
	err := filepath.WalkDir(bucketDir, func(p string, d iofs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, iofs.ErrNotExist) {
				return nil // removed while walking
			}
			return err
		}
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if !d.IsDir() || p == bucketDir {
			return nil
		}
		name := d.Name()
		if strings.HasPrefix(name, storage.DataDirPrefix) {
			return filepath.SkipDir
		}
		rel, rerr := filepath.Rel(bucketDir, p)
		if rerr != nil {
			return rerr
		}
		kd := filepath.ToSlash(rel)
		if strings.HasSuffix(name, storage.DirObjectSuffix) {
			// "folder/" placeholder: a leaf holding only its xl.meta.
			key := strings.TrimSuffix(kd, storage.DirObjectSuffix) + "/"
			if strings.HasPrefix(key, prefix) && HasMeta(p) {
				keys = append(keys, key)
			}
			return filepath.SkipDir
		}
		if !strings.HasPrefix(kd, prefix) && !strings.HasPrefix(prefix, kd+"/") {
			return filepath.SkipDir
		}
		if strings.HasPrefix(kd, prefix) && HasMeta(p) {
			keys = append(keys, kd)
		}
		return nil
	})
	return keys, err
}

// HasMeta reports whether dir holds a regular xl.meta file.
func HasMeta(dir string) bool {
	st, err := os.Stat(filepath.Join(dir, storage.MetaFileName))
	return err == nil && st.Mode().IsRegular()
}

// Page builds one ListObjects page from keys (unique, any order). load
// returns the ObjectInfo of a key, or false to skip it (corrupt, deleted
// meanwhile, a delete marker). Entries, whether keys or common prefixes,
// are compared in UTF-8 byte order against the marker, which is the greater
// of opts.Marker and opts.StartAfter and is exclusive.
func Page(keys []string, opts storage.ListOptions, load func(key string) (storage.ObjectInfo, bool)) storage.ListResult {
	limit := opts.MaxKeys
	if limit <= 0 || limit > MaxKeys {
		limit = MaxKeys
	}
	marker := max(opts.Marker, opts.StartAfter)
	sorted := append([]string(nil), keys...)
	sort.Strings(sorted)

	var res storage.ListResult
	lastPrefix, havePrefix := "", false
	for _, key := range sorted {
		name, isPrefix := key, false
		if opts.Delimiter != "" && strings.HasPrefix(key, opts.Prefix) {
			rest := key[len(opts.Prefix):]
			if i := strings.Index(rest, opts.Delimiter); i >= 0 {
				name, isPrefix = opts.Prefix+rest[:i+len(opts.Delimiter)], true
			}
		}
		if name <= marker {
			continue
		}
		if isPrefix && havePrefix && name == lastPrefix {
			continue
		}
		var info storage.ObjectInfo
		if !isPrefix {
			var ok bool
			if info, ok = load(key); !ok {
				continue
			}
		}
		if len(res.Objects)+len(res.Prefixes) == limit {
			res.IsTruncated = true
			break
		}
		if isPrefix {
			res.Prefixes = append(res.Prefixes, name)
			lastPrefix, havePrefix = name, true
		} else {
			res.Objects = append(res.Objects, info)
		}
		res.NextMarker = name
	}
	if !res.IsTruncated {
		res.NextMarker = ""
	}
	return res
}

// PageUploads orders in-progress uploads by key, then initiation time, then
// ID, resumes strictly after (KeyMarker, UploadIDMarker), applies the
// delimiter and returns one page.
func PageUploads(all []storage.UploadInfo, opts storage.ListUploadsOptions) storage.ListUploadsResult {
	uploads := make([]storage.UploadInfo, 0, len(all))
	for _, u := range all {
		if strings.HasPrefix(u.Object, opts.Prefix) {
			uploads = append(uploads, u)
		}
	}
	sort.Slice(uploads, func(i, j int) bool {
		a, b := uploads[i], uploads[j]
		if a.Object != b.Object {
			return a.Object < b.Object
		}
		if !a.Initiated.Equal(b.Initiated) {
			return a.Initiated.Before(b.Initiated)
		}
		return a.UploadID < b.UploadID
	})

	start := 0
	afterKey := func() int {
		return sort.Search(len(uploads), func(i int) bool { return uploads[i].Object > opts.KeyMarker })
	}
	switch {
	case opts.KeyMarker == "":
	case opts.UploadIDMarker != "":
		idx := -1
		for i, u := range uploads {
			if u.Object == opts.KeyMarker && u.UploadID == opts.UploadIDMarker {
				idx = i
				break
			}
		}
		if idx >= 0 {
			start = idx + 1
		} else {
			start = afterKey()
		}
	default:
		start = afterKey()
	}

	limit := opts.MaxUploads
	if limit <= 0 || limit > MaxKeys {
		limit = MaxKeys
	}
	var res storage.ListUploadsResult
	lastPrefix, havePrefix := "", false
	count := 0
	var lastKey, lastID string
	for _, u := range uploads[start:] {
		if opts.Delimiter != "" {
			rest := u.Object[len(opts.Prefix):]
			if i := strings.Index(rest, opts.Delimiter); i >= 0 {
				cp := opts.Prefix + rest[:i+len(opts.Delimiter)]
				if havePrefix && cp == lastPrefix {
					continue
				}
				if count == limit {
					res.IsTruncated = true
					break
				}
				res.Prefixes = append(res.Prefixes, cp)
				lastPrefix, havePrefix = cp, true
				lastKey, lastID = cp, ""
				count++
				continue
			}
		}
		if count == limit {
			res.IsTruncated = true
			break
		}
		res.Uploads = append(res.Uploads, u)
		lastKey, lastID = u.Object, u.UploadID
		count++
	}
	if res.IsTruncated {
		res.NextKeyMarker, res.NextUploadIDMarker = lastKey, lastID
	}
	return res
}
