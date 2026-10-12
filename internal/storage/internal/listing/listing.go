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

// PageVersions builds one ListObjectVersions page from keys (unique, any
// order). load returns every version and delete marker of a key, newest
// first, with IDs as reported to clients, or false to skip the key. Entries
// are ordered by key (UTF-8 bytes) and, within a key, as load returned them.
//
// Resumption is strictly after (opts.Marker, opts.VersionIDMarker): with no
// version marker the whole marker key is skipped; with one, the versions
// that follow it are listed, and if it no longer exists the key is skipped
// (the listing resumes at the next key, as S3 does). A common prefix and a
// version each count one toward the page size. NextMarker and
// NextVersionIDMarker name the last entry returned when the page is
// truncated.
func PageVersions(keys []string, opts storage.ListOptions, load func(key string) ([]storage.ObjectInfo, bool)) storage.ListVersionsResult {
	limit := opts.MaxKeys
	if limit <= 0 || limit > MaxKeys {
		limit = MaxKeys
	}
	marker := max(opts.Marker, opts.StartAfter)
	sorted := append([]string(nil), keys...)
	sort.Strings(sorted)

	var res storage.ListVersionsResult
	var lastKey, lastVID string
	count := 0
	lastPrefix, havePrefix := "", false
	full := func() bool { return count == limit }
	for _, key := range sorted {
		name, isPrefix := key, false
		if opts.Delimiter != "" && strings.HasPrefix(key, opts.Prefix) {
			rest := key[len(opts.Prefix):]
			if i := strings.Index(rest, opts.Delimiter); i >= 0 {
				name, isPrefix = opts.Prefix+rest[:i+len(opts.Delimiter)], true
			}
		}
		if isPrefix {
			if name <= marker || havePrefix && name == lastPrefix {
				continue
			}
			if full() {
				res.IsTruncated = true
				break
			}
			res.Prefixes = append(res.Prefixes, name)
			lastPrefix, havePrefix = name, true
			lastKey, lastVID = name, ""
			count++
			continue
		}
		if key < marker {
			continue
		}
		versions, ok := load(key)
		if !ok || len(versions) == 0 {
			continue
		}
		if key == marker {
			if opts.VersionIDMarker == "" {
				continue
			}
			rest := versionsAfter(versions, opts.VersionIDMarker)
			if len(rest) == 0 {
				continue
			}
			versions = rest
		}
		for _, v := range versions {
			if full() {
				res.IsTruncated = true
				break
			}
			res.Versions = append(res.Versions, v)
			lastKey, lastVID = key, v.VersionID
			count++
		}
		if res.IsTruncated {
			break
		}
	}
	if res.IsTruncated {
		res.NextMarker, res.NextVersionIDMarker = lastKey, lastVID
	}
	return res
}

// versionsAfter returns the versions that follow the one with the given
// reported ID, or nil when it is not among them.
func versionsAfter(vs []storage.ObjectInfo, id string) []storage.ObjectInfo {
	for i, v := range vs {
		if v.VersionID == id {
			return vs[i+1:]
		}
	}
	return nil
}
