package disk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	iofs "io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"nanoio/internal/meta"
	"nanoio/internal/storage"
	"nanoio/internal/storage/internal/fsutil"
)

// Multipart state lives on every drive under
//
//	<drive>/.nanoio.sys/multipart/<bucket>/<uploadID>/
//	    upload.json         the descriptor the coordinator wrote
//	    <N>.json            this drive's PartRecord of part N
//	    <N>.<token>.data    this drive's shard stream of part N
//
// A part is replaced by writing a new, uniquely named data file and then
// atomically switching <N>.json to name it.

var (
	uploadIDRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	partMetaRE = regexp.MustCompile(`^([0-9]+)\.json$`)
)

func (d *Local) uploadsRoot(bucket string) (string, error) {
	return d.path(sysDirName, multipartDirName, bucket)
}

// uploadDirPath validates the upload ID before it can reach a path.
func (d *Local) uploadDirPath(bucket, id string) (string, error) {
	if !uploadIDRE.MatchString(id) {
		return "", ErrNotFound
	}
	return d.path(sysDirName, multipartDirName, bucket, id)
}

// CreateUpload implements Disk.
func (d *Local) createUpload(bucket, uploadID string, doc []byte) error {
	if err := d.check(); err != nil {
		return err
	}
	dest, err := d.uploadDirPath(bucket, uploadID)
	if err != nil {
		return err
	}
	stage := filepath.Join(d.tmp(), "mpu-"+uploadID)
	if err := os.Mkdir(stage, dirPerm); err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	if err := fsutil.WriteFileSync(filepath.Join(stage, uploadMetaFile), doc, filePerm); err != nil {
		return err
	}
	parent := filepath.Dir(dest)
	for attempt := 0; ; attempt++ {
		err = fsutil.MkdirAllSync(d.root, parent, dirPerm)
		if err == nil {
			err = os.Rename(stage, dest)
		}
		if err == nil {
			return fsutil.SyncDir(parent)
		}
		if fsutil.IsPruneRace(err) && attempt < 20 {
			continue
		}
		return err
	}
}

// ReadUpload implements Disk.
func (d *Local) readUpload(bucket, uploadID string) ([]byte, error) {
	if err := d.check(); err != nil {
		return nil, err
	}
	dir, err := d.uploadDirPath(bucket, uploadID)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(dir, uploadMetaFile))
	if err != nil {
		if errors.Is(err, iofs.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return data, nil
}

// ListUploadIDs implements Disk.
func (d *Local) listUploadIDs(bucket string) ([]string, error) {
	if err := d.check(); err != nil {
		return nil, err
	}
	root, err := d.uploadsRoot(bucket)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		if errors.Is(err, iofs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var ids []string
	for _, e := range entries {
		if e.IsDir() && uploadIDRE.MatchString(e.Name()) {
			ids = append(ids, e.Name())
		}
	}
	return ids, nil
}

// ListParts implements Disk. A part whose record is unreadable, or whose
// shard file is missing or the wrong size, is treated as not uploaded.
func (d *Local) listParts(bucket, uploadID string) ([]PartRecord, error) {
	if err := d.check(); err != nil {
		return nil, err
	}
	dir, err := d.uploadDirPath(bucket, uploadID)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, iofs.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	var out []PartRecord
	for _, e := range entries {
		m := partMetaRE.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var pr PartRecord
		n, _ := strconv.Atoi(m[1])
		if json.Unmarshal(data, &pr) != nil || pr.Number != n || pr.File == "" || pr.File != filepath.Base(pr.File) {
			continue
		}
		if st, err := os.Stat(filepath.Join(dir, pr.File)); err != nil || st.Size() != pr.ShardSize {
			continue
		}
		out = append(out, pr)
	}
	return out, nil
}

// CommitPart implements Disk. The superseded data file of a replaced part
// is only removed by Finish, so a rolled-back commit leaves the previous
// part whole.
func (d *Local) commitPart(pc PartCommit) (Commit, error) {
	if err := d.check(); err != nil {
		return nil, err
	}
	dir, err := d.uploadDirPath(pc.Bucket, pc.UploadID)
	if err != nil {
		return nil, err
	}
	if pc.DataFile != filepath.Base(pc.DataFile) {
		return nil, fmt.Errorf("disk: invalid data file name %q", pc.DataFile)
	}
	stage, err := d.stagePath(pc.StageID)
	if err != nil {
		return nil, err
	}
	jsonName := fmt.Sprintf("%d.json", pc.Number)
	oldJSON, _ := os.ReadFile(filepath.Join(dir, jsonName))
	newData := filepath.Join(dir, pc.DataFile)
	if err := os.Rename(filepath.Join(stage, pc.DataFile), newData); err != nil {
		if errors.Is(err, iofs.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	stagedJSON := filepath.Join(stage, jsonName)
	os.Remove(stagedJSON)
	if err := fsutil.WriteFileSync(stagedJSON, pc.Record, filePerm); err != nil {
		os.Remove(newData)
		return nil, err
	}
	if err := os.Rename(stagedJSON, filepath.Join(dir, jsonName)); err != nil {
		os.Remove(newData)
		return nil, err
	}
	fsutil.SyncDir(dir)

	oldFile := ""
	var old PartRecord
	if json.Unmarshal(oldJSON, &old) == nil {
		oldFile = old.File
	}
	return &localCommit{
		undo: func() {
			os.Remove(newData)
			if len(oldJSON) > 0 {
				os.WriteFile(filepath.Join(dir, jsonName), oldJSON, filePerm)
			} else {
				os.Remove(filepath.Join(dir, jsonName))
			}
		},
		finish: func() {
			if oldFile != "" && oldFile != pc.DataFile && oldFile == filepath.Base(oldFile) {
				os.Remove(filepath.Join(dir, oldFile))
			}
		},
	}, nil
}

// DiscardUpload implements Disk.
func (d *Local) discardUpload(bucket, uploadID string) error {
	if err := d.check(); err != nil {
		return err
	}
	dir, err := d.uploadDirPath(bucket, uploadID)
	if err != nil {
		return nil // not a valid ID: there is nothing of that name to remove
	}
	token, err := newToken()
	if err != nil {
		return err
	}
	trash := filepath.Join(d.tmp(), "trash-"+token)
	if err := os.Rename(dir, trash); err != nil {
		if errors.Is(err, iofs.ErrNotExist) {
			return nil
		}
		return err
	}
	os.Remove(filepath.Dir(dir)) // the bucket's upload dir, if now empty
	return os.RemoveAll(trash)
}

// SweepStaging implements Disk.
func (d *Local) sweepStaging(maxAge time.Duration) int {
	entries, err := os.ReadDir(d.tmp())
	if err != nil {
		return 0
	}
	removed := 0
	for _, e := range entries {
		if d.held(e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if maxAge < 0 || time.Since(info.ModTime()) > maxAge {
			if os.RemoveAll(filepath.Join(d.tmp(), e.Name())) == nil {
				removed++
			}
		}
	}
	return removed
}

// StaleUploads implements Disk.
func (d *Local) staleUploads(maxAge time.Duration) ([]StaleUpload, error) {
	if err := d.check(); err != nil {
		return nil, err
	}
	root, err := d.path(sysDirName, multipartDirName)
	if err != nil {
		return nil, err
	}
	buckets, err := os.ReadDir(root)
	if err != nil {
		return nil, nil
	}
	var out []StaleUpload
	for _, b := range buckets {
		if !b.IsDir() || storage.ValidateBucketName(b.Name()) != nil {
			continue
		}
		gone := d.bucketGone(b.Name())
		uploads, err := os.ReadDir(filepath.Join(root, b.Name()))
		if err != nil {
			continue
		}
		for _, u := range uploads {
			if !u.IsDir() || !uploadIDRE.MatchString(u.Name()) {
				continue
			}
			info, err := os.Stat(filepath.Join(root, b.Name(), u.Name()))
			if err != nil {
				continue
			}
			if gone || time.Since(info.ModTime()) > maxAge {
				out = append(out, StaleUpload{Bucket: b.Name(), ID: u.Name(), BucketGone: gone})
			}
		}
	}
	return out, nil
}

func (d *Local) bucketGone(bucket string) bool {
	dir, err := d.path(bucket)
	if err != nil {
		return false
	}
	_, err = os.Stat(dir)
	return err != nil
}

// DiscardUploadIfStale implements Disk.
func (d *Local) discardUploadIfStale(bucket, uploadID string, maxAge time.Duration) (bool, error) {
	if err := d.check(); err != nil {
		return false, err
	}
	dir, err := d.uploadDirPath(bucket, uploadID)
	if err != nil {
		return false, nil
	}
	info, err := os.Stat(dir)
	if err != nil {
		return false, nil
	}
	if !d.bucketGone(bucket) && time.Since(info.ModTime()) <= maxAge {
		return false, nil
	}
	if err := d.discardUpload(bucket, uploadID); err != nil {
		return false, err
	}
	return true, nil
}

// referenced returns the data directory names an object directory's
// xl.meta names. ok is false if the metadata exists but is unreadable, in
// which case nothing next to it may be touched.
func referenced(dir string) (keep map[string]bool, ok bool) {
	keep = map[string]bool{}
	data, err := os.ReadFile(filepath.Join(dir, storage.MetaFileName))
	if err != nil {
		return keep, errors.Is(err, iofs.ErrNotExist)
	}
	f, err := meta.Decode(data)
	if err != nil {
		return nil, false
	}
	for _, v := range f.Versions {
		keep[v.DataDir] = true
	}
	return keep, true
}

func isDataDir(name string) bool {
	return strings.HasPrefix(name, storage.DataDirPrefix+"data-") && name == filepath.Base(name)
}

// FindOrphans implements Disk.
func (d *Local) findOrphans(ctx context.Context, bucket string) ([]Orphan, error) {
	if err := d.check(); err != nil {
		return nil, err
	}
	bdir, err := d.path(bucket)
	if err != nil {
		return nil, err
	}
	var out []Orphan
	err = filepath.WalkDir(bdir, func(p string, de iofs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, iofs.ErrNotExist) {
				return nil
			}
			return err
		}
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if !de.IsDir() || p == bdir {
			return nil
		}
		if strings.HasPrefix(de.Name(), storage.DataDirPrefix) {
			return filepath.SkipDir
		}
		children, rerr := os.ReadDir(p)
		if rerr != nil {
			return nil
		}
		var datas []string
		for _, c := range children {
			if c.IsDir() && isDataDir(c.Name()) {
				datas = append(datas, c.Name())
			}
		}
		if len(datas) == 0 {
			return nil
		}
		keep, ok := referenced(p)
		if !ok {
			return nil
		}
		var orphans []string
		for _, n := range datas {
			if !keep[n] {
				orphans = append(orphans, n)
			}
		}
		if len(orphans) > 0 {
			out = append(out, Orphan{Object: keyOfDir(bdir, p), DataDirs: orphans})
		}
		return nil
	})
	return out, err
}

// RemoveOrphans implements Disk.
func (d *Local) removeOrphans(bucket, object string, dataDirs []string) (int, error) {
	if err := d.check(); err != nil {
		return 0, err
	}
	dir, err := d.objDir(bucket, object)
	if err != nil {
		return 0, err
	}
	keep, ok := referenced(dir) // re-read now: the caller holds the key lock
	if !ok {
		return 0, nil
	}
	removed := 0
	for _, n := range dataDirs {
		if !isDataDir(n) || keep[n] {
			continue
		}
		p := filepath.Join(dir, n)
		if d.pins.Pinned(p) {
			continue
		}
		if os.RemoveAll(p) == nil {
			removed++
		}
	}
	return removed, nil
}

// keyOfDir recovers an object key from its directory under a bucket.
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
