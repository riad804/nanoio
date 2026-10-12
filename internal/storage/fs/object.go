package fs

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	iofs "io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"nanoio/internal/meta"
	"nanoio/internal/storage"
	"nanoio/internal/storage/internal/fsutil"
	"nanoio/internal/storage/internal/objlock"
)

// ctxReader fails reads once ctx is done so a cancelled upload stops
// promptly even if the client keeps the connection open.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

func validate(bucket, object string) error {
	if err := storage.ValidateBucketName(bucket); err != nil {
		return err
	}
	return storage.ValidateObjectName(object)
}

func copyMap(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func trimETag(s string) string { return strings.Trim(s, `"`) }

func toInfo(bucket, object string, v *meta.Version, latest bool, state storage.VersioningState) storage.ObjectInfo {
	info := storage.ObjectInfo{
		Bucket: bucket, Name: object, VersionID: storage.ReportedVersionID(state, v.VersionID), IsLatest: latest,
		DeleteMarker: v.Type == meta.TypeDeleteMarker,
		Size:         v.Size, ModTime: v.ModTime, ETag: v.ETag,
		ContentType: v.ContentType, UserDefined: copyMap(v.UserMeta),
	}
	for _, p := range v.Parts {
		info.Parts = append(info.Parts, storage.PartInfo{Number: p.N, ETag: p.ETag, Size: p.Size})
	}
	info.Retention, info.LegalHold = objlock.Info(v.Lock)
	return info
}

// PutObject stores r as bucket/object, replacing any existing object.
// size < 0 means unknown. ContentMD5 and ContentSHA256 are hex digests,
// verified while streaming; on mismatch nothing is committed.
func (f *FS) PutObject(ctx context.Context, bucket, object string, r io.Reader, size int64, opts storage.PutOptions) (storage.ObjectInfo, error) {
	var zero storage.ObjectInfo
	if err := validate(bucket, object); err != nil {
		return zero, err
	}
	if size > maxObjectSize {
		return zero, storage.Wrap(storage.ErrEntityTooLarge, bucket, object)
	}
	if err := f.enter(); err != nil {
		return zero, err
	}
	defer f.leave()
	if err := f.requireBucket(bucket); err != nil {
		return zero, err
	}

	fs := &faultState{f: f}
	hit := fs.hit

	id, err := meta.NewVersionID()
	if err != nil {
		return zero, err
	}
	stage := filepath.Join(f.tmp, id)
	if err := os.Mkdir(stage, dirPerm); err != nil {
		return zero, mapErr(err, bucket, object)
	}
	defer f.holdStage(stage)()
	defer func() {
		if !fs.crashed {
			os.RemoveAll(stage)
		}
	}()

	// 1. Stream the body into staging, hashing as it passes.
	dataDir := storage.DataDirPrefix + "data-" + id
	stagedData := filepath.Join(stage, dataDir)
	if err := os.Mkdir(stagedData, dirPerm); err != nil {
		return zero, mapErr(err, bucket, object)
	}
	n, etag, err := f.stageBody(ctx, bucket, object, r, size, opts.ContentMD5, opts.ContentSHA256,
		filepath.Join(stagedData, partFileName(1)))
	if err != nil {
		return zero, err
	}
	if err := hit(FaultStaged); err != nil {
		return zero, err
	}

	// 2. Lock for the commit only: bucket (shared), then key (exclusive).
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

	// 3. Publish.
	ct := opts.ContentType
	if ct == "" {
		ct = defaultContentType
	}
	return f.commit(bucket, object, stage, stagedData, meta.Version{
		Type: meta.TypeObject, Size: n, ETag: etag,
		DataDir: dataDir, ContentType: ct, UserMeta: opts.FinalUserDefined(),
		Parts: []meta.Part{{N: 1, Size: n, ETag: etag}},
	}, opts, hit)
}

// stageBody streams r into a new file at dest, fsyncs it, and verifies the
// declared size and digests (hex MD5 and SHA-256, either may be empty). It
// returns the byte count and the hex MD5, which is the part or object ETag.
// On any failure dest is removed and the error is a storage sentinel,
// the caller's context error, or an I/O error.
func (f *FS) stageBody(ctx context.Context, bucket, object string, r io.Reader, size int64,
	wantMD5, wantSHA256, dest string) (n int64, etag string, err error) {
	md5h := md5.New()
	var shah hash.Hash
	sinks := []io.Writer{md5h}
	if wantSHA256 != "" {
		shah = sha256.New()
		sinks = append(sinks, shah)
	}
	src := io.Reader(ctxReader{ctx, r})
	if size >= 0 {
		src = io.LimitReader(src, size)
	}
	pf, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, filePerm)
	if err != nil {
		return 0, "", mapErr(err, bucket, object)
	}
	defer func() {
		if err != nil {
			os.Remove(dest)
		}
	}()
	n, err = io.Copy(io.MultiWriter(append(sinks, pf)...), src)
	if err == nil {
		err = pf.Sync()
	}
	if cerr := pf.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return 0, "", mapErr(err, bucket, object)
	}
	if size >= 0 && n != size {
		err = storage.Wrap(storage.ErrIncompleteBody, bucket, object)
		return 0, "", err
	}
	etag = hex.EncodeToString(md5h.Sum(nil))
	if wantMD5 != "" && !strings.EqualFold(wantMD5, etag) {
		err = storage.Wrap(storage.ErrBadDigest, bucket, object)
		return 0, "", err
	}
	if shah != nil && !strings.EqualFold(wantSHA256, hex.EncodeToString(shah.Sum(nil))) {
		err = storage.Wrap(storage.ErrSHA256Mismatch, bucket, object)
		return 0, "", err
	}
	return n, etag, nil
}

// faultState implements the Options.Fault crash simulation: when the hook
// fires, the operation stops at once and its caller must skip cleanup so
// the staging debris of a real crash is left behind.
type faultState struct {
	f       *FS
	crashed bool
}

func (s *faultState) hit(point string) error {
	if s.f.fault == nil {
		return nil
	}
	if err := s.f.fault(point); err != nil {
		s.crashed = true
		return err
	}
	return nil
}

// commit publishes a staged data directory as a new version of
// bucket/object. The caller holds the bucket's shared lock and the key's
// exclusive lock, has fully written and fsynced stagedData (a directory
// inside stageDir whose name is ver.DataDir), and has filled in every field
// of ver except VersionID, Seq and ModTime.
//
// Because the bucket's shared lock is held, the versioning state read here
// cannot change before the commit is done: the write is entirely before or
// entirely after any change of state.
func (f *FS) commit(bucket, object, stageDir, stagedData string, ver meta.Version, opts storage.PutOptions, hit func(string) error) (storage.ObjectInfo, error) {
	var zero storage.ObjectInfo
	if err := f.requireBucket(bucket); err != nil {
		return zero, err
	}
	cfg, err := f.versioningOf(bucket)
	if err != nil {
		return zero, err
	}
	bucketDir, _ := f.path(bucket)
	keyDir, err := f.keyDir(bucket, object)
	if err != nil {
		return zero, err
	}

	// Read, check preconditions, and build the new xl.meta.
	file, err := f.readMeta(keyDir)
	if err != nil {
		return zero, storage.Wrap(err, bucket, object)
	}
	var cur *meta.Version
	if file != nil {
		if v := file.Latest(); v != nil && v.Type == meta.TypeObject {
			cur = v // a latest delete marker counts as "does not exist"
		}
	}
	if opts.IfNoneMatch == "*" && cur != nil {
		return zero, storage.Wrap(storage.ErrPreconditionFailed, bucket, object)
	}
	if opts.IfMatch != "" && (cur == nil || trimETag(opts.IfMatch) != "*" && trimETag(opts.IfMatch) != cur.ETag) {
		return zero, storage.Wrap(storage.ErrPreconditionFailed, bucket, object)
	}
	if file == nil {
		file = &meta.File{Format: meta.FormatVersion}
	}
	id, err := meta.VersionIDFor(metaVersioning(cfg.State))
	if err != nil {
		return zero, err
	}
	// The bucket's lock configuration cannot change while the shared bucket
	// lock is held, so what is applied here is what the bucket says now.
	lockCfg, err := f.objectLockOf(bucket)
	if err != nil {
		return zero, err
	}
	now := time.Now().UTC()
	ver.Lock, err = objlock.Resolve(lockCfg.cfg, opts, now)
	if err != nil {
		return zero, storage.Wrap(err, bucket, object)
	}
	ver.VersionID = id
	ver.Seq = file.Generation() + 1
	ver.ModTime = now
	dataDir := ver.DataDir
	superseded, err := file.ApplyPut(ver, objlock.Guard(now, false))
	if err != nil {
		return zero, objlock.Err(err, bucket, object)
	}
	enc, err := meta.Encode(file)
	if err != nil {
		return zero, err
	}
	stagedMeta := filepath.Join(stageDir, storage.MetaFileName)
	if err := fsutil.WriteFileSync(stagedMeta, enc, filePerm); err != nil {
		return zero, mapErr(err, bucket, object)
	}
	if err := hit(FaultMetaStaged); err != nil {
		return zero, err
	}

	// Move the data dir into place. A concurrent delete of a sibling key
	// can prune a just-created parent, so retry (ENOENT on Linux, EINVAL on
	// macOS when the parent is being unlinked).
	for attempt := 0; ; attempt++ {
		err = fsutil.MkdirAllSync(bucketDir, keyDir, dirPerm)
		if err == nil {
			err = os.Rename(stagedData, filepath.Join(keyDir, dataDir))
		}
		if err == nil {
			break
		}
		if fsutil.IsPruneRace(err) && attempt < 20 {
			continue
		}
		return zero, mapErr(err, bucket, object)
	}
	if err := fsutil.SyncDir(keyDir); err != nil {
		return zero, mapErr(err, bucket, object)
	}
	if err := hit(FaultDataRenamed); err != nil {
		return zero, err
	}

	// Commit point: rename xl.meta into place.
	if err := os.Rename(stagedMeta, filepath.Join(keyDir, storage.MetaFileName)); err != nil {
		return zero, mapErr(err, bucket, object)
	}
	if err := fsutil.SyncDir(keyDir); err != nil {
		return zero, mapErr(err, bucket, object)
	}
	if err := hit(FaultMetaRenamed); err != nil {
		return zero, err
	}

	// Committed. Drop the replaced null version's data; a failure here only
	// leaves garbage for the collector. Other versions are untouched.
	for _, old := range superseded {
		if old == dataDir {
			continue
		}
		if err := f.pins.Remove(filepath.Join(keyDir, old)); err != nil {
			f.log.Warn("fs: could not remove replaced data dir", "bucket", bucket, "object", object, "err", err)
		}
	}
	return toInfo(bucket, object, file.Find(id), true, cfg.State), nil
}

// lookup resolves bucket/object[/versionID] to a version and its directory.
// The caller holds the key lock. A delete marker is reported as a
// *storage.DeleteMarkerError: "not found" when the latest version was
// asked for, "method not allowed" when the marker was named.
func (f *FS) lookup(bucket, object, versionID string) (*meta.Version, bool, string, storage.VersioningState, error) {
	keyDir, err := f.keyDir(bucket, object)
	if err != nil {
		return nil, false, "", "", err
	}
	stored, err := storage.StoredVersionID(versionID)
	if err != nil {
		return nil, false, "", "", storage.Wrap(err, bucket, object)
	}
	file, err := f.readMeta(keyDir)
	if err != nil {
		return nil, false, "", "", storage.Wrap(err, bucket, object)
	}
	if file == nil || len(file.Versions) == 0 {
		if err := f.requireBucket(bucket); err != nil {
			return nil, false, "", "", err
		}
		if versionID != "" {
			return nil, false, "", "", storage.Wrap(storage.ErrVersionNotFound, bucket, object)
		}
		return nil, false, "", "", storage.Wrap(storage.ErrObjectNotFound, bucket, object)
	}
	cfg, err := f.versioningOf(bucket)
	if err != nil {
		return nil, false, "", "", err
	}
	explicit := versionID != ""
	v, rerr := file.Resolve(stored, !explicit)
	if rerr != nil {
		return nil, false, "", "", storage.Wrap(storage.ErrVersionNotFound, bucket, object)
	}
	if v.Type == meta.TypeDeleteMarker {
		return nil, false, "", "", &storage.DeleteMarkerError{
			Bucket: bucket, Object: object, ModTime: v.ModTime, Explicit: explicit,
			VersionID: storage.ReportedVersionID(cfg.State, v.VersionID),
		}
	}
	return v, v == file.Latest(), keyDir, cfg.State, nil
}

// StatObject returns object metadata without opening its data.
func (f *FS) StatObject(ctx context.Context, bucket, object string, opts storage.GetOptions) (storage.ObjectInfo, error) {
	if err := validate(bucket, object); err != nil {
		return storage.ObjectInfo{}, err
	}
	if err := f.enter(); err != nil {
		return storage.ObjectInfo{}, err
	}
	defer f.leave()
	unlock, err := f.locker.RLock(ctx, bucket, object)
	if err != nil {
		return storage.ObjectInfo{}, err
	}
	defer unlock()
	v, latest, _, state, err := f.lookup(bucket, object, opts.VersionID)
	if err != nil {
		return storage.ObjectInfo{}, err
	}
	return toInfo(bucket, object, v, latest, state), nil
}

// readCloser pairs a section reader with the file it reads.
type readCloser struct {
	io.Reader
	io.Closer
}

// GetObject opens an object. The shared lock is released before this
// returns: data dirs are immutable and the open handle survives a later
// overwrite or delete, so the reader is a stable snapshot. info.Size is the
// full object size even for a ranged read.
func (f *FS) GetObject(ctx context.Context, bucket, object string, opts storage.GetOptions) (io.ReadCloser, storage.ObjectInfo, error) {
	var zero storage.ObjectInfo
	if err := validate(bucket, object); err != nil {
		return nil, zero, err
	}
	if err := f.enter(); err != nil {
		return nil, zero, err
	}
	defer f.leave()
	unlock, err := f.locker.RLock(ctx, bucket, object)
	if err != nil {
		return nil, zero, err
	}
	defer unlock()
	v, latest, keyDir, state, err := f.lookup(bucket, object, opts.VersionID)
	if err != nil {
		return nil, zero, err
	}
	info := toInfo(bucket, object, v, latest, state)
	if rg := opts.Range; rg != nil {
		if rg.Start < 0 || rg.Length <= 0 || rg.Start+rg.Length > v.Size {
			return nil, zero, storage.Wrap(storage.ErrInvalidRange, bucket, object)
		}
	}
	// Pin the data directory before the lock is released: a concurrent
	// overwrite or delete defers its removal until this reader closes, so a
	// lazily opened multipart read still sees the snapshot it started on.
	release := f.pins.Pin(filepath.Join(keyDir, v.DataDir))
	fh, err := openObjectData(keyDir, v)
	if err != nil {
		release()
		if errors.Is(err, errDataCorrupt) {
			f.corrupted.Add(1)
			f.log.Error("fs: object data does not match its metadata", "bucket", bucket, "object", object, "err", err)
			return nil, zero, storage.Wrap(storage.ErrCorrupted, bucket, object)
		}
		return nil, zero, mapErr(err, bucket, object)
	}
	pf := &pinnedFile{readSeekReadAtCloser: fh, release: release}
	if rg := opts.Range; rg != nil {
		return readCloser{io.NewSectionReader(pf, rg.Start, rg.Length), pf}, info, nil
	}
	return pf, info, nil
}

// pinnedFile releases its data directory pin when closed. It embeds the
// reader interface so it stays seekable, which the API relies on for
// ranges.
type pinnedFile struct {
	readSeekReadAtCloser
	release func()
}

func (p *pinnedFile) Close() error {
	err := p.readSeekReadAtCloser.Close()
	p.release()
	return err
}

var errDataCorrupt = errors.New("object data is missing or the wrong size")

// openObjectData opens a version's data for reading and verifies every part
// file against the metadata first, so a truncated or missing part is
// reported as corruption before any byte is served. A single-part object
// opens its file directly; a multipart object is presented as one seekable
// stream across its part files.
func openObjectData(keyDir string, v *meta.Version) (readSeekReadAtCloser, error) {
	parts := v.Parts
	if len(parts) == 0 {
		parts = []meta.Part{{N: 1, Size: v.Size}}
	}
	paths := make([]string, len(parts))
	sizes := make([]int64, len(parts))
	var total int64
	for i, p := range parts {
		paths[i] = filepath.Join(keyDir, v.DataDir, partFileName(p.N))
		st, err := os.Stat(paths[i])
		if err != nil {
			if errors.Is(err, iofs.ErrNotExist) {
				return nil, fmt.Errorf("%w: part %d is missing", errDataCorrupt, p.N)
			}
			return nil, err
		}
		if st.Size() != p.Size {
			return nil, fmt.Errorf("%w: part %d is %d bytes, metadata says %d", errDataCorrupt, p.N, st.Size(), p.Size)
		}
		sizes[i] = st.Size()
		total += st.Size()
	}
	if total != v.Size {
		return nil, fmt.Errorf("%w: parts total %d bytes, metadata says %d", errDataCorrupt, total, v.Size)
	}
	if len(paths) == 1 {
		return os.Open(paths[0])
	}
	return newMultiFile(paths, sizes), nil
}

// partFileName is the data file name of part n inside a version's data dir.
func partFileName(n int) string { return fmt.Sprintf("part.%d", n) }

type readSeekReadAtCloser interface {
	io.Reader
	io.Seeker
	io.ReaderAt
	io.Closer
}

// multiFile presents several files as one read-only, seekable stream.
// Only one underlying file is held open at a time, so an object of 10,000
// parts does not exhaust file descriptors.
type multiFile struct {
	mu      sync.Mutex
	paths   []string
	offsets []int64 // start offset of each part
	size    int64
	pos     int64
	cur     int // index of the open file, or -1
	f       *os.File
}

func newMultiFile(paths []string, sizes []int64) *multiFile {
	m := &multiFile{paths: paths, offsets: make([]int64, len(paths)), cur: -1}
	for i, s := range sizes {
		m.offsets[i] = m.size
		m.size += s
	}
	return m
}

// partAt returns the index of the part containing off.
func (m *multiFile) partAt(off int64) int {
	lo, hi := 0, len(m.offsets)-1
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if m.offsets[mid] <= off {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return lo
}

func (m *multiFile) ReadAt(p []byte, off int64) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.readAt(p, off)
}

func (m *multiFile) readAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("multifile: negative offset")
	}
	n := 0
	for n < len(p) {
		if off >= m.size {
			return n, io.EOF
		}
		i := m.partAt(off)
		if m.cur != i {
			if m.f != nil {
				m.f.Close()
				m.f, m.cur = nil, -1
			}
			f, err := os.Open(m.paths[i])
			if err != nil {
				return n, err
			}
			m.f, m.cur = f, i
		}
		k, err := m.f.ReadAt(p[n:], off-m.offsets[i])
		n += k
		off += int64(k)
		if err != nil && err != io.EOF {
			return n, err
		}
		if err == io.EOF && k == 0 {
			return n, io.ErrUnexpectedEOF // file shorter than verified
		}
	}
	return n, nil
}

func (m *multiFile) Read(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pos >= m.size {
		return 0, io.EOF
	}
	n, err := m.readAt(p, m.pos)
	m.pos += int64(n)
	if err == io.EOF && n > 0 {
		err = nil
	}
	return n, err
}

func (m *multiFile) Seek(offset int64, whence int) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var abs int64
	switch whence {
	case io.SeekStart:
		abs = offset
	case io.SeekCurrent:
		abs = m.pos + offset
	case io.SeekEnd:
		abs = m.size + offset
	default:
		return 0, errors.New("multifile: invalid whence")
	}
	if abs < 0 {
		return 0, errors.New("multifile: negative position")
	}
	m.pos = abs
	return abs, nil
}

func (m *multiFile) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.f != nil {
		err := m.f.Close()
		m.f, m.cur = nil, -1
		return err
	}
	return nil
}

// DeleteObject implements storage.StorageAPI.
//
//   - With opts.VersionID the one version, object or delete marker, is
//     removed permanently; naming a version that is not there succeeds.
//   - Without it, an Unversioned bucket loses the object; an Enabled bucket
//     gets a delete marker with a new version ID (even for a key that has no
//     versions, as S3 does); a Suspended bucket gets a null delete marker
//     that replaces the null version.
//
// Deleting a missing object succeeds, as in S3.
func (f *FS) DeleteObject(ctx context.Context, bucket, object string, opts storage.DeleteOptions) (storage.DeleteResult, error) {
	if err := validate(bucket, object); err != nil {
		return storage.DeleteResult{}, err
	}
	stored, err := storage.StoredVersionID(opts.VersionID)
	if err != nil {
		return storage.DeleteResult{}, storage.Wrap(err, bucket, object)
	}
	if err := f.enter(); err != nil {
		return storage.DeleteResult{}, err
	}
	defer f.leave()
	unlockBucket, err := f.locker.RLock(ctx, bucket, "")
	if err != nil {
		return storage.DeleteResult{}, err
	}
	defer unlockBucket()
	unlockKey, err := f.locker.Lock(ctx, bucket, object)
	if err != nil {
		return storage.DeleteResult{}, err
	}
	defer unlockKey()
	if err := f.requireBucket(bucket); err != nil {
		return storage.DeleteResult{}, err
	}
	cfg, err := f.versioningOf(bucket)
	if err != nil {
		return storage.DeleteResult{}, err
	}
	keyDir, err := f.keyDir(bucket, object)
	if err != nil {
		return storage.DeleteResult{}, err
	}
	file, err := f.readMeta(keyDir)
	if err != nil {
		return storage.DeleteResult{}, storage.Wrap(err, bucket, object)
	}
	st := metaVersioning(cfg.State)
	guard := objlock.Guard(time.Now(), opts.BypassGovernance)
	switch {
	case opts.VersionID != "":
		res := storage.DeleteResult{VersionID: storage.ReportedVersionID(cfg.State, stored)}
		if file == nil {
			return res, nil
		}
		v := file.Find(stored)
		if v == nil {
			return res, nil
		}
		res.DeleteMarker = v.Type == meta.TypeDeleteMarker
		dirs, err := file.ApplyRemove(stored, file.Generation()+1, guard)
		if err != nil {
			return storage.DeleteResult{}, objlock.Err(err, bucket, object)
		}
		return res, f.persist(bucket, object, keyDir, file, dirs)
	case st == meta.Unversioned:
		if file == nil {
			return storage.DeleteResult{}, nil
		}
		// Only the null version can exist here.
		if err := file.Protected(guard); err != nil {
			return storage.DeleteResult{}, objlock.Err(err, bucket, object)
		}
		var dirs []string
		for _, v := range file.Versions {
			if v.DataDir != "" {
				dirs = append(dirs, v.DataDir)
			}
		}
		file.Versions = nil
		return storage.DeleteResult{}, f.persist(bucket, object, keyDir, file, dirs)
	default:
		if file == nil {
			file = &meta.File{Format: meta.FormatVersion}
		}
		id, err := meta.VersionIDFor(st)
		if err != nil {
			return storage.DeleteResult{}, err
		}
		dirs, err := file.ApplyMarker(id, file.Generation()+1, time.Now().UTC(), guard)
		if err != nil {
			return storage.DeleteResult{}, objlock.Err(err, bucket, object)
		}
		res := storage.DeleteResult{VersionID: storage.ReportedVersionID(cfg.State, id), DeleteMarker: true}
		return res, f.persist(bucket, object, keyDir, file, dirs)
	}
}

// persist makes file the key's xl.meta (or removes the key when no version
// is left) and then deletes the data directories dirs, which the new state
// no longer references. Writing or removing xl.meta is the commit point.
// The caller holds the key lock.
func (f *FS) persist(bucket, object, keyDir string, file *meta.File, dirs []string) error {
	bucketDir, _ := f.path(bucket)
	metaPath := filepath.Join(keyDir, storage.MetaFileName)
	if len(file.Versions) == 0 {
		if err := os.Remove(metaPath); err != nil && !errors.Is(err, iofs.ErrNotExist) {
			return mapErr(err, bucket, object)
		}
	} else {
		enc, err := meta.Encode(file)
		if err != nil {
			return err
		}
		id, err := meta.NewVersionID()
		if err != nil {
			return err
		}
		staged := filepath.Join(f.tmp, "meta-"+id)
		defer f.holdStage(staged)()
		if err := fsutil.WriteFileSync(staged, enc, filePerm); err != nil {
			os.Remove(staged)
			return mapErr(err, bucket, object)
		}
		for attempt := 0; ; attempt++ {
			err = fsutil.MkdirAllSync(bucketDir, keyDir, dirPerm)
			if err == nil {
				err = os.Rename(staged, metaPath)
			}
			if err == nil {
				break
			}
			if fsutil.IsPruneRace(err) && attempt < 20 {
				continue
			}
			os.Remove(staged)
			return mapErr(err, bucket, object)
		}
		if err := fsutil.SyncDir(keyDir); err != nil {
			return mapErr(err, bucket, object)
		}
	}
	for _, d := range dirs {
		if err := f.pins.Remove(filepath.Join(keyDir, d)); err != nil {
			f.log.Warn("fs: could not remove data dir", "bucket", bucket, "object", object, "err", err)
		}
	}
	if len(file.Versions) == 0 {
		// Prune now-empty key dirs up to (not including) the bucket.
		for d := keyDir; d != bucketDir; d = filepath.Dir(d) {
			if os.Remove(d) != nil {
				break
			}
		}
		if err := fsutil.SyncDir(filepath.Dir(keyDir)); err != nil && !errors.Is(err, iofs.ErrNotExist) {
			return mapErr(err, bucket, object)
		}
	}
	return nil
}
