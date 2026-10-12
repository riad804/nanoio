package fs

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	iofs "io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"nanoio/internal/meta"
	"nanoio/internal/storage"
	"nanoio/internal/storage/internal/fsutil"
	"nanoio/internal/storage/internal/listing"
	"nanoio/internal/storage/internal/objlock"
)

// Multipart upload state lives under
//
//	<root>/.nanoio.sys/multipart/<bucket>/<uploadID>/
//	    upload.json            bucket, key, initiation time, content type, metadata
//	    <N>.json               the committed state of part N: data file, size, ETag
//	    <N>.<token>.data       the bytes of part N
//
// A part is replaced by writing a new, uniquely named data file and then
// atomically switching <N>.json to name it, so a reader or a crash never
// sees a part whose metadata and bytes disagree. Data files that no
// <N>.json names are garbage, removed by the collector.
const (
	multipartDirName = "multipart"
	uploadMetaFile   = "upload.json"

	// MaxParts is S3's limit on the part number and on parts per upload.
	MaxParts = 10000
	// DefaultMinPartSize is S3's minimum size of every part but the last.
	DefaultMinPartSize int64 = 5 << 20
	// MaxPartSize is S3's maximum part size.
	MaxPartSize int64 = 5 << 30
)

var uploadIDRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

type uploadDoc struct {
	Bucket      string            `json:"bucket"`
	Object      string            `json:"object"`
	Initiated   time.Time         `json:"initiated"`
	ContentType string            `json:"contentType,omitempty"`
	UserDefined map[string]string `json:"userDefined,omitempty"`
	// Lock is the object lock requested when the upload was started.
	Lock objlock.Requested `json:"lock,omitzero"`
}

type partDoc struct {
	Number  int       `json:"number"`
	File    string    `json:"file"`
	Size    int64     `json:"size"`
	ETag    string    `json:"etag"`
	ModTime time.Time `json:"modTime"`
}

func (f *FS) uploadsRoot(bucket string) (string, error) {
	return f.path(sysDirName, multipartDirName, bucket)
}

func (f *FS) uploadDir(bucket, id string) (string, error) {
	return f.path(sysDirName, multipartDirName, bucket, id)
}

// uploadLockKey is the namespace-lock object name of an upload. Names with
// the reserved ".nanoio-" prefix can never be real object keys.
func uploadLockKey(id string) string { return storage.DataDirPrefix + "upload-" + id }

// checkUploadID rejects anything that is not a generated upload ID, which
// also keeps hostile IDs from ever reaching a path.
func checkUploadID(bucket, object, id string) error {
	if !uploadIDRE.MatchString(id) {
		return storage.Wrap(storage.ErrNoSuchUpload, bucket, object)
	}
	return nil
}

// readUpload loads an upload's descriptor and checks it belongs to
// bucket/object, so an ID cannot be used against a different key.
func (f *FS) readUpload(bucket, object, id string) (*uploadDoc, string, error) {
	dir, err := f.uploadDir(bucket, id)
	if err != nil {
		return nil, "", err
	}
	data, err := os.ReadFile(filepath.Join(dir, uploadMetaFile))
	if err != nil {
		if errors.Is(err, iofs.ErrNotExist) {
			return nil, "", storage.Wrap(storage.ErrNoSuchUpload, bucket, object)
		}
		return nil, "", err
	}
	var doc uploadDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, "", fmt.Errorf("%w: %s: %v", storage.ErrCorrupted, dir, err)
	}
	if doc.Bucket != bucket || (object != "" && doc.Object != object) {
		return nil, "", storage.Wrap(storage.ErrNoSuchUpload, bucket, object)
	}
	return &doc, dir, nil
}

var partMetaRE = regexp.MustCompile(`^([0-9]+)\.json$`)

// readParts loads the committed parts of an upload. A part whose metadata
// is unreadable or whose data file is missing is treated as not uploaded.
func (f *FS) readParts(dir string) (map[int]partDoc, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	parts := map[int]partDoc{}
	for _, e := range entries {
		m := partMetaRE.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var pd partDoc
		n, _ := strconv.Atoi(m[1])
		if json.Unmarshal(data, &pd) != nil || pd.Number != n || pd.File == "" ||
			pd.File != filepath.Base(pd.File) {
			f.log.Warn("fs: ignoring unreadable part metadata", "dir", dir, "file", e.Name())
			continue
		}
		if st, err := os.Stat(filepath.Join(dir, pd.File)); err != nil || st.Size() != pd.Size {
			f.log.Warn("fs: ignoring part whose data is missing or the wrong size", "dir", dir, "part", n)
			continue
		}
		parts[n] = pd
	}
	return parts, nil
}

func newToken() (string, error) {
	id, err := meta.NewVersionID()
	if err != nil {
		return "", err
	}
	return strings.ReplaceAll(id, "-", ""), nil
}

// NewMultipartUpload starts an upload and returns its ID.
func (f *FS) NewMultipartUpload(ctx context.Context, bucket, object string, opts storage.PutOptions) (string, error) {
	if err := validate(bucket, object); err != nil {
		return "", err
	}
	if err := f.enter(); err != nil {
		return "", err
	}
	defer f.leave()
	// Shared bucket lock: DeleteBucket (exclusive) must not race creation.
	unlock, err := f.locker.RLock(ctx, bucket, "")
	if err != nil {
		return "", err
	}
	defer unlock()
	if err := f.requireBucket(bucket); err != nil {
		return "", err
	}
	id, err := meta.NewVersionID()
	if err != nil {
		return "", err
	}
	ct := opts.ContentType
	if ct == "" {
		ct = defaultContentType
	}
	lockCfg, err := f.objectLockOf(bucket)
	if err != nil {
		return "", err
	}
	req, err := objlock.Request(lockCfg.cfg, opts, time.Now())
	if err != nil {
		return "", storage.Wrap(err, bucket, object)
	}
	doc, err := json.Marshal(uploadDoc{Bucket: bucket, Object: object, Initiated: time.Now().UTC(),
		ContentType: ct, UserDefined: copyMap(opts.UserDefined), Lock: req})
	if err != nil {
		return "", err
	}
	stage := filepath.Join(f.tmp, "mpu-"+id)
	if err := os.Mkdir(stage, dirPerm); err != nil {
		return "", mapErr(err, bucket, object)
	}
	defer f.holdStage(stage)()
	defer os.RemoveAll(stage)
	if err := fsutil.WriteFileSync(filepath.Join(stage, uploadMetaFile), doc, filePerm); err != nil {
		return "", mapErr(err, bucket, object)
	}
	if err := fsutil.SyncDir(stage); err != nil {
		return "", mapErr(err, bucket, object)
	}
	dest, err := f.uploadDir(bucket, id)
	if err != nil {
		return "", err
	}
	// The collector removes empty per-bucket upload directories, which can
	// vanish between creating the directory and renaming the upload into
	// it; retry, exactly as an object commit does.
	parent := filepath.Dir(dest)
	for attempt := 0; ; attempt++ {
		err = fsutil.MkdirAllSync(f.root, parent, dirPerm)
		if err == nil {
			err = os.Rename(stage, dest)
		}
		if err == nil {
			break
		}
		if fsutil.IsPruneRace(err) && attempt < 20 {
			continue
		}
		return "", mapErr(err, bucket, object)
	}
	return id, mapErr(fsutil.SyncDir(parent), bucket, object)
}

// PutObjectPart stores one part. Uploading a part number again replaces
// the earlier bytes atomically.
func (f *FS) PutObjectPart(ctx context.Context, bucket, object, uploadID string, partNumber int,
	r io.Reader, size int64, opts storage.PartOptions) (storage.PartInfo, error) {
	var zero storage.PartInfo
	if err := validate(bucket, object); err != nil {
		return zero, err
	}
	if err := checkUploadID(bucket, object, uploadID); err != nil {
		return zero, err
	}
	if partNumber < 1 || partNumber > MaxParts {
		return zero, storage.Wrap(fmt.Errorf("%w: part number %d is outside 1..%d", storage.ErrInvalidPart, partNumber, MaxParts), bucket, object)
	}
	if size > MaxPartSize {
		return zero, storage.Wrap(storage.ErrEntityTooLarge, bucket, object)
	}
	if err := f.enter(); err != nil {
		return zero, err
	}
	defer f.leave()
	// Fail before streaming gigabytes into an upload that does not exist.
	if _, _, err := f.readUpload(bucket, object, uploadID); err != nil {
		return zero, err
	}

	fs := &faultState{f: f}
	id, err := newToken()
	if err != nil {
		return zero, err
	}
	stage := filepath.Join(f.tmp, "part-"+id)
	if err := os.Mkdir(stage, dirPerm); err != nil {
		return zero, mapErr(err, bucket, object)
	}
	defer f.holdStage(stage)()
	defer func() {
		if !fs.crashed {
			os.RemoveAll(stage)
		}
	}()
	dataName := fmt.Sprintf("%d.%s.data", partNumber, id)
	stagedData := filepath.Join(stage, dataName)
	n, etag, err := f.stageBody(ctx, bucket, object, r, size, opts.ContentMD5, opts.ContentSHA256, stagedData)
	if err != nil {
		return zero, err
	}
	if err := fs.hit(FaultPartStaged); err != nil {
		return zero, err
	}

	unlockBucket, err := f.locker.RLock(ctx, bucket, "")
	if err != nil {
		return zero, err
	}
	defer unlockBucket()
	unlockUpload, err := f.locker.Lock(ctx, bucket, uploadLockKey(uploadID))
	if err != nil {
		return zero, err
	}
	defer unlockUpload()
	if _, _, err := f.readUpload(bucket, object, uploadID); err != nil { // aborted or completed meanwhile
		return zero, err
	}
	dir, err := f.uploadDir(bucket, uploadID)
	if err != nil {
		return zero, err
	}

	var oldFile string
	if data, err := os.ReadFile(filepath.Join(dir, fmt.Sprintf("%d.json", partNumber))); err == nil {
		var old partDoc
		if json.Unmarshal(data, &old) == nil {
			oldFile = old.File
		}
	}
	if err := os.Rename(stagedData, filepath.Join(dir, dataName)); err != nil {
		return zero, mapErr(err, bucket, object)
	}
	if err := fsutil.SyncDir(dir); err != nil {
		return zero, mapErr(err, bucket, object)
	}
	if err := fs.hit(FaultPartData); err != nil {
		return zero, err
	}

	now := time.Now().UTC()
	doc, err := json.Marshal(partDoc{Number: partNumber, File: dataName, Size: n, ETag: etag, ModTime: now})
	if err != nil {
		return zero, err
	}
	stagedMeta := filepath.Join(stage, fmt.Sprintf("%d.json", partNumber))
	if err := fsutil.WriteFileSync(stagedMeta, doc, filePerm); err != nil {
		return zero, mapErr(err, bucket, object)
	}
	if err := os.Rename(stagedMeta, filepath.Join(dir, fmt.Sprintf("%d.json", partNumber))); err != nil {
		return zero, mapErr(err, bucket, object)
	}
	if err := fsutil.SyncDir(dir); err != nil {
		return zero, mapErr(err, bucket, object)
	}
	if err := fs.hit(FaultPartMeta); err != nil {
		return zero, err
	}
	if oldFile != "" && oldFile != dataName {
		os.Remove(filepath.Join(dir, oldFile))
	}
	return storage.PartInfo{Number: partNumber, ETag: etag, Size: n, ModTime: now}, nil
}

// ListObjectParts lists the parts uploaded so far, ascending by number.
func (f *FS) ListObjectParts(ctx context.Context, bucket, object, uploadID string, opts storage.ListPartsOptions) (storage.ListPartsResult, error) {
	var zero storage.ListPartsResult
	if err := validate(bucket, object); err != nil {
		return zero, err
	}
	if err := checkUploadID(bucket, object, uploadID); err != nil {
		return zero, err
	}
	if err := f.enter(); err != nil {
		return zero, err
	}
	defer f.leave()
	unlock, err := f.locker.RLock(ctx, bucket, uploadLockKey(uploadID))
	if err != nil {
		return zero, err
	}
	defer unlock()
	udoc, dir, err := f.readUpload(bucket, object, uploadID)
	if err != nil {
		return zero, err
	}
	parts, err := f.readParts(dir)
	if err != nil {
		return zero, mapErr(err, bucket, object)
	}
	numbers := make([]int, 0, len(parts))
	for n := range parts {
		if n > opts.PartNumberMarker {
			numbers = append(numbers, n)
		}
	}
	sort.Ints(numbers)
	limit := opts.MaxParts
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	res := storage.ListPartsResult{UserDefined: copyMap(udoc.UserDefined)}
	for i, n := range numbers {
		if i == limit {
			res.IsTruncated = true
			break
		}
		p := parts[n]
		res.Parts = append(res.Parts, storage.PartInfo{Number: n, ETag: p.ETag, Size: p.Size, ModTime: p.ModTime})
		res.NextPartNumberMarker = n
	}
	if !res.IsTruncated {
		res.NextPartNumberMarker = 0
	}
	return res, nil
}

// ListMultipartUploads lists in-progress uploads of a bucket ordered by key,
// then initiation time.
func (f *FS) ListMultipartUploads(ctx context.Context, bucket string, opts storage.ListUploadsOptions) (storage.ListUploadsResult, error) {
	var zero storage.ListUploadsResult
	if err := storage.ValidateBucketName(bucket); err != nil {
		return zero, err
	}
	if err := f.enter(); err != nil {
		return zero, err
	}
	defer f.leave()
	if err := f.requireBucket(bucket); err != nil {
		return zero, err
	}
	root, err := f.uploadsRoot(bucket)
	if err != nil {
		return zero, err
	}
	entries, err := os.ReadDir(root)
	if err != nil && !errors.Is(err, iofs.ErrNotExist) {
		return zero, mapErr(err, bucket, "")
	}
	var all []storage.UploadInfo
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return zero, err
		}
		if !e.IsDir() || !uploadIDRE.MatchString(e.Name()) {
			continue
		}
		doc, _, err := f.readUpload(bucket, "", e.Name())
		if err != nil {
			continue // completed or aborted while listing, or unreadable
		}
		all = append(all, storage.UploadInfo{Object: doc.Object, UploadID: e.Name(), Initiated: doc.Initiated})
	}
	return listing.PageUploads(all, opts), nil
}

// AbortMultipartUpload discards an upload and its parts.
func (f *FS) AbortMultipartUpload(ctx context.Context, bucket, object, uploadID string) error {
	if err := validate(bucket, object); err != nil {
		return err
	}
	if err := checkUploadID(bucket, object, uploadID); err != nil {
		return err
	}
	if err := f.enter(); err != nil {
		return err
	}
	defer f.leave()
	unlockBucket, err := f.locker.RLock(ctx, bucket, "")
	if err != nil {
		return err
	}
	defer unlockBucket()
	unlock, err := f.locker.Lock(ctx, bucket, uploadLockKey(uploadID))
	if err != nil {
		return err
	}
	defer unlock()
	_, dir, err := f.readUpload(bucket, object, uploadID)
	if err != nil {
		return err
	}
	return mapErr(f.discardDir(dir), bucket, object)
}

// discardDir removes dir by first renaming it into staging, so it vanishes
// atomically even if the deletion of its contents is interrupted.
func (f *FS) discardDir(dir string) error {
	token, err := newToken()
	if err != nil {
		return err
	}
	trash := filepath.Join(f.tmp, "trash-"+token)
	if err := os.Rename(dir, trash); err != nil {
		if errors.Is(err, iofs.ErrNotExist) {
			return nil
		}
		return err
	}
	if err := fsutil.SyncDir(filepath.Dir(dir)); err != nil {
		return err
	}
	return os.RemoveAll(trash)
}

// CompleteMultipartUpload assembles the listed parts into the object.
// Parts must be given in ascending order with the ETags returned when they
// were uploaded; every part but the last must be at least the minimum part
// size. The resulting ETag is the MD5 of the concatenated binary part MD5s,
// followed by "-" and the part count.
//
// The part files are hard-linked (copied if linking is impossible) into a
// staged data directory and published through the same atomic commit as a
// plain PutObject; the upload stays intact until that commit succeeds, so
// a crash at any point leaves either the upload or the finished object.
func (f *FS) CompleteMultipartUpload(ctx context.Context, bucket, object, uploadID string,
	parts []storage.CompletePart, opts storage.PutOptions) (storage.ObjectInfo, error) {
	var zero storage.ObjectInfo
	if err := validate(bucket, object); err != nil {
		return zero, err
	}
	if err := checkUploadID(bucket, object, uploadID); err != nil {
		return zero, err
	}
	if len(parts) == 0 || len(parts) > MaxParts {
		return zero, storage.Wrap(fmt.Errorf("%w: %d parts listed", storage.ErrInvalidPart, len(parts)), bucket, object)
	}
	for i, p := range parts {
		if p.Number < 1 || p.Number > MaxParts {
			return zero, storage.Wrap(fmt.Errorf("%w: part number %d is outside 1..%d", storage.ErrInvalidPart, p.Number, MaxParts), bucket, object)
		}
		if i > 0 && p.Number <= parts[i-1].Number {
			return zero, storage.Wrap(storage.ErrInvalidPartOrder, bucket, object)
		}
	}
	if err := f.enter(); err != nil {
		return zero, err
	}
	defer f.leave()

	fs := &faultState{f: f}
	unlockBucket, err := f.locker.RLock(ctx, bucket, "")
	if err != nil {
		return zero, err
	}
	defer unlockBucket()
	unlockUpload, err := f.locker.Lock(ctx, bucket, uploadLockKey(uploadID))
	if err != nil {
		return zero, err
	}
	defer unlockUpload()
	unlockKey, err := f.locker.Lock(ctx, bucket, object)
	if err != nil {
		return zero, err
	}
	defer unlockKey()

	doc, dir, err := f.readUpload(bucket, object, uploadID)
	if err != nil {
		return zero, err
	}
	stored, err := f.readParts(dir)
	if err != nil {
		return zero, mapErr(err, bucket, object)
	}

	// Validate the client's list against what was actually uploaded.
	var total int64
	sum := md5.New()
	versionParts := make([]meta.Part, 0, len(parts))
	for i, want := range parts {
		have, ok := stored[want.Number]
		if !ok || !strings.EqualFold(trimETag(want.ETag), have.ETag) {
			return zero, storage.Wrap(fmt.Errorf("%w: part %d was not uploaded or its ETag differs", storage.ErrInvalidPart, want.Number), bucket, object)
		}
		if i < len(parts)-1 && have.Size < f.minPartSize {
			return zero, storage.Wrap(fmt.Errorf("%w: part %d is %d bytes, the minimum is %d", storage.ErrEntityTooSmall, want.Number, have.Size, f.minPartSize), bucket, object)
		}
		raw, err := hex.DecodeString(have.ETag)
		if err != nil || len(raw) != md5.Size {
			return zero, storage.Wrap(storage.ErrCorrupted, bucket, object)
		}
		sum.Write(raw)
		total += have.Size
		if total > maxObjectSize {
			return zero, storage.Wrap(storage.ErrEntityTooLarge, bucket, object)
		}
		versionParts = append(versionParts, meta.Part{N: want.Number, Size: have.Size, ETag: have.ETag})
	}
	etag := fmt.Sprintf("%s-%d", hex.EncodeToString(sum.Sum(nil)), len(parts))

	// Stage a data directory holding the parts as part.<N>.
	token, err := newToken()
	if err != nil {
		return zero, err
	}
	stage := filepath.Join(f.tmp, "complete-"+token)
	if err := os.Mkdir(stage, dirPerm); err != nil {
		return zero, mapErr(err, bucket, object)
	}
	defer f.holdStage(stage)()
	defer func() {
		if !fs.crashed {
			os.RemoveAll(stage)
		}
	}()
	dataDir := storage.DataDirPrefix + "data-" + token
	stagedData := filepath.Join(stage, dataDir)
	if err := os.Mkdir(stagedData, dirPerm); err != nil {
		return zero, mapErr(err, bucket, object)
	}
	for _, want := range parts {
		if err := ctx.Err(); err != nil {
			return zero, err
		}
		if err := linkOrCopy(filepath.Join(dir, stored[want.Number].File), filepath.Join(stagedData, partFileName(want.Number))); err != nil {
			return zero, mapErr(err, bucket, object)
		}
	}
	if err := fsutil.SyncDir(stagedData); err != nil {
		return zero, mapErr(err, bucket, object)
	}
	if err := fs.hit(FaultStaged); err != nil {
		return zero, err
	}

	info, err := f.commit(bucket, object, stage, stagedData, meta.Version{
		Type: meta.TypeObject, Size: total, ETag: etag, DataDir: dataDir,
		ContentType: doc.ContentType, UserMeta: copyMap(doc.UserDefined), Parts: versionParts,
	}, objlock.Carry(opts, doc.Lock, time.Now()), fs.hit)
	if err != nil {
		return zero, err
	}
	// Published. The upload directory is now garbage; failing to remove it
	// is harmless because the collector will.
	if err := f.discardDir(dir); err != nil {
		f.log.Warn("fs: could not remove completed upload", "bucket", bucket, "upload", uploadID, "err", err)
	}
	return info, nil
}

// linkOrCopy hard-links src to dst, falling back to a durable copy when the
// filesystem cannot link.
func linkOrCopy(src, dst string) error {
	if err := os.Link(src, dst); err == nil {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	_, err = fsutil.CopySync(dst, in, filePerm)
	return err
}

// hasUploads reports whether bucket has any in-progress upload.
func (f *FS) hasUploads(bucket string) bool {
	root, err := f.uploadsRoot(bucket)
	if err != nil {
		return false
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.IsDir() && uploadIDRE.MatchString(e.Name()) {
			return true
		}
	}
	return false
}

// removeUploads discards every upload of bucket (forced bucket delete).
func (f *FS) removeUploads(bucket string) error {
	root, err := f.uploadsRoot(bucket)
	if err != nil {
		return err
	}
	if _, err := os.Stat(root); err != nil {
		if errors.Is(err, iofs.ErrNotExist) {
			return nil
		}
		return err
	}
	return f.discardDir(root)
}
