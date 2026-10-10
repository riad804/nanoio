package disk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	iofs "io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"nanoio/internal/meta"
	"nanoio/internal/storage"
	"nanoio/internal/storage/internal/fsutil"
	"nanoio/internal/storage/internal/listing"
	"nanoio/internal/storage/internal/pins"
)

const (
	sysDirName       = ".nanoio.sys"
	tmpDirName       = "tmp"
	multipartDirName = "multipart"
	lockFileName     = ".lock"
	formatFileName   = "format.json"
	bucketMarker     = storage.DataDirPrefix + "bucket"
	uploadMetaFile   = "upload.json"

	dirPerm  = 0o755
	filePerm = 0o644
)

// LocalOptions configures a Local drive.
type LocalOptions struct {
	// Fault, when non-nil, is called at the Fault* points of CommitObject;
	// an error fails that commit. For tests.
	Fault func(point string) error
}

// Local is a Disk backed by one directory of the local filesystem. It owns
// the directory exclusively for as long as it is open: an advisory lock
// keeps other processes out, and an in-process registry keeps data
// directories alive while readers stream from them.
type Local struct {
	root  string
	fault func(string) error

	mu       sync.Mutex
	lock     *os.File // held flock; nil while the drive is not usable
	awaiting bool     // locked but blank: not usable until formatted

	pins pins.Registry

	stagesMu sync.Mutex
	stages   map[string]bool

	// keyMu serialises commits and rollbacks per object, so a conditional
	// commit's check and its rename are one step.
	keyMu [64]sync.Mutex

	fmtMu  sync.Mutex // serialises WriteFormat
	openMu sync.Mutex // serialises Open: concurrent callers must not race for the flock
}

func (d *Local) keyLock(bucket, object string) *sync.Mutex {
	h := uint32(2166136261)
	for _, c := range []byte(bucket + "\x00" + object) {
		h = (h ^ uint32(c)) * 16777619
	}
	return &d.keyMu[h%uint32(len(d.keyMu))]
}

var _ Disk = (*Local)(nil)

// NewLocal returns a Disk over root. It does not touch the filesystem until
// Open.
func NewLocal(root string, opts LocalOptions) (*Local, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	return &Local{root: abs, fault: opts.Fault, stages: map[string]bool{}}, nil
}

// Root is the drive's directory.
func (d *Local) Root() string { return d.root }

func (d *Local) String() string { return d.root }

func (d *Local) sys() string        { return filepath.Join(d.root, sysDirName) }
func (d *Local) tmp() string        { return filepath.Join(d.sys(), tmpDirName) }
func (d *Local) formatPath() string { return filepath.Join(d.sys(), formatFileName) }

func (d *Local) path(elems ...string) (string, error) { return fsutil.SafeJoin(d.root, elems...) }

func (d *Local) objDir(bucket, object string) (string, error) {
	return d.path(append([]string{bucket}, storage.KeySegments(object)...)...)
}

func (d *Local) faultAt(point string) error {
	if d.fault == nil {
		return nil
	}
	return d.fault(point)
}

// open implements Disk.Open. It is idempotent: a drive this Local already holds
// is not locked a second time, which lets a node's RPC server and its own
// erasure set share one Local.
func (d *Local) open(create bool) (*Format, error) {
	d.openMu.Lock()
	defer d.openMu.Unlock()
	d.mu.Lock()
	lf := d.lock
	d.mu.Unlock()
	owned := lf == nil
	if owned {
		if !create {
			if st, err := os.Stat(d.root); err != nil || !st.IsDir() {
				return nil, fmt.Errorf("%w: %s does not exist", ErrOffline, d.root)
			}
		}
		if err := os.MkdirAll(d.tmp(), dirPerm); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrOffline, err)
		}
		var err error
		lf, err = os.OpenFile(filepath.Join(d.sys(), lockFileName), os.O_CREATE|os.O_RDWR, filePerm)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrOffline, err)
		}
		if err := fsutil.LockFile(lf); err != nil {
			lf.Close()
			return nil, fmt.Errorf("%w: %s: %v", ErrInUse, d.root, err)
		}
	}
	release := func() {
		if owned {
			lf.Close()
		}
	}
	data, err := os.ReadFile(d.formatPath())
	switch {
	case err == nil:
		var f Format
		if err := json.Unmarshal(data, &f); err != nil {
			release()
			return nil, fmt.Errorf("%w: format.json of %s: %v", storage.ErrCorrupted, d.root, err)
		}
		if f.Format != FormatVersion {
			release()
			return nil, fmt.Errorf("%w: %s has unsupported format version %d", storage.ErrCorrupted, d.root, f.Format)
		}
		d.mu.Lock()
		d.lock, d.awaiting = lf, false
		d.mu.Unlock()
		return &f, nil
	case errors.Is(err, iofs.ErrNotExist):
		// Blank only if nothing but our own directory exists, so a
		// populated, unformatted directory is never adopted.
		entries, rerr := os.ReadDir(d.root)
		if rerr != nil {
			release()
			return nil, rerr
		}
		for _, e := range entries {
			if e.Name() != sysDirName {
				release()
				return nil, fmt.Errorf("%w: %s", ErrForeign, d.root)
			}
		}
		d.mu.Lock()
		d.lock, d.awaiting = lf, true
		d.mu.Unlock()
		return nil, ErrUnformatted
	}
	release()
	return nil, err
}

// WriteFormat implements Disk. It is idempotent and safe to call from
// several nodes at once: when the drive already carries the same identity
// the call succeeds without rewriting it.
func (d *Local) writeFormat(f *Format) error {
	d.fmtMu.Lock()
	defer d.fmtMu.Unlock()
	if cur, err := os.ReadFile(d.formatPath()); err == nil {
		var have Format
		if json.Unmarshal(cur, &have) == nil && have.Format == f.Format &&
			have.DeploymentID == f.DeploymentID && have.Index == f.Index &&
			have.DataBlocks == f.DataBlocks && have.ParityBlocks == f.ParityBlocks {
			d.mu.Lock()
			d.awaiting = false
			d.mu.Unlock()
			return nil
		}
	}
	doc, err := json.Marshal(f)
	if err != nil {
		return err
	}
	tok, err := newToken()
	if err != nil {
		return err
	}
	stage := filepath.Join(d.tmp(), "format-"+tok)
	if err := fsutil.WriteFileSync(stage, doc, filePerm); err != nil {
		return err
	}
	if err := os.Rename(stage, d.formatPath()); err != nil {
		os.Remove(stage)
		return err
	}
	if err := fsutil.SyncDir(d.sys()); err != nil {
		return err
	}
	d.mu.Lock()
	d.awaiting = false
	d.mu.Unlock()
	return nil
}

// Ready implements Disk.
func (d *Local) ready() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.lock == nil || d.awaiting {
		return false
	}
	if _, err := os.Stat(d.formatPath()); err != nil {
		d.lock.Close()
		d.lock = nil
		return false
	}
	return true
}

// Info implements Disk.
func (d *Local) info() (Info, error) {
	t, f, err := fsutil.DiskUsage(d.root)
	return Info{Total: t, Free: f}, err
}

// Close implements Disk.
func (d *Local) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.lock != nil {
		d.lock.Close()
		d.lock = nil
	}
	d.awaiting = false
	return nil
}

func (d *Local) check() error {
	if !d.ready() {
		return ErrOffline
	}
	return nil
}

func newToken() (string, error) {
	id, err := meta.NewVersionID()
	if err != nil {
		return "", err
	}
	return strings.ReplaceAll(id, "-", ""), nil
}

type bucketDoc struct {
	Created time.Time `json:"created"`
}

// MakeBucket implements Disk.
func (d *Local) makeBucket(bucket string, created time.Time) (bool, error) {
	if err := d.check(); err != nil {
		return false, err
	}
	dir, err := d.path(bucket)
	if err != nil {
		return false, err
	}
	if st, err := os.Lstat(dir); err == nil && st.IsDir() {
		return false, nil
	}
	doc, err := json.Marshal(bucketDoc{Created: created.UTC()})
	if err != nil {
		return false, err
	}
	token, err := newToken()
	if err != nil {
		return false, err
	}
	stage := filepath.Join(d.tmp(), "mkb-"+token)
	if err := os.Mkdir(stage, dirPerm); err != nil {
		return false, err
	}
	defer os.RemoveAll(stage)
	if err := fsutil.WriteFileSync(filepath.Join(stage, bucketMarker), doc, filePerm); err != nil {
		return false, err
	}
	if err := os.Rename(stage, dir); err != nil {
		return false, err
	}
	return true, fsutil.SyncDir(d.root)
}

// StatBucket implements Disk.
func (d *Local) statBucket(bucket string) (bool, time.Time, error) {
	if err := d.check(); err != nil {
		return false, time.Time{}, err
	}
	dir, err := d.path(bucket)
	if err != nil {
		return false, time.Time{}, err
	}
	st, err := os.Lstat(dir)
	switch {
	case err == nil && st.IsDir():
	case err == nil || errors.Is(err, iofs.ErrNotExist):
		return false, time.Time{}, nil
	default:
		return false, time.Time{}, err
	}
	created := st.ModTime().UTC()
	if data, err := os.ReadFile(filepath.Join(dir, bucketMarker)); err == nil {
		var doc bucketDoc
		if json.Unmarshal(data, &doc) == nil && !doc.Created.IsZero() {
			created = doc.Created.UTC()
		}
	}
	return true, created, nil
}

// ListBuckets implements Disk.
func (d *Local) listBuckets() ([]string, error) {
	if err := d.check(); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(d.root)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() && storage.ValidateBucketName(e.Name()) == nil {
			out = append(out, e.Name())
		}
	}
	return out, nil
}

// DeleteBucket implements Disk.
func (d *Local) deleteBucket(bucket string) error {
	if err := d.check(); err != nil {
		return err
	}
	dir, err := d.path(bucket)
	if err != nil {
		return err
	}
	token, err := newToken()
	if err != nil {
		return err
	}
	trash := filepath.Join(d.tmp(), "trash-"+token)
	if err := os.Rename(dir, trash); err != nil && !errors.Is(err, iofs.ErrNotExist) {
		return err
	}
	if uploads, err := d.path(sysDirName, multipartDirName, bucket); err == nil {
		os.RemoveAll(uploads)
	}
	fsutil.SyncDir(d.root)
	return os.RemoveAll(trash)
}

// ListKeys implements Disk.
func (d *Local) listKeys(ctx context.Context, bucket, prefix string) ([]string, error) {
	if err := d.check(); err != nil {
		return nil, err
	}
	dir, err := d.path(bucket)
	if err != nil {
		return nil, err
	}
	return listing.CollectKeys(ctx, dir, prefix)
}

// ReadMeta implements Disk.
func (d *Local) readMeta(bucket, object string) ([]byte, error) {
	if err := d.check(); err != nil {
		return nil, err
	}
	dir, err := d.objDir(bucket, object)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(dir, storage.MetaFileName))
	if err != nil {
		if errors.Is(err, iofs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return data, nil
}

func (d *Local) shardPath(bucket, object, dataDir string, part int) (string, error) {
	dir, err := d.objDir(bucket, object)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, dataDir, fmt.Sprintf("part.%d", part)), nil
}

type localShard struct {
	*os.File
	size int64
}

func (s localShard) Size() int64 { return s.size }

// OpenShard implements Disk.
func (d *Local) openShard(bucket, object, dataDir string, part int) (Shard, error) {
	if err := d.check(); err != nil {
		return nil, err
	}
	p, err := d.shardPath(bucket, object, dataDir, part)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(p)
	if err != nil {
		if errors.Is(err, iofs.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	return localShard{f, st.Size()}, nil
}

// StatShard implements Disk.
func (d *Local) statShard(bucket, object, dataDir string, part int) (int64, error) {
	if err := d.check(); err != nil {
		return 0, err
	}
	p, err := d.shardPath(bucket, object, dataDir, part)
	if err != nil {
		return 0, err
	}
	st, err := os.Stat(p)
	if err != nil {
		if errors.Is(err, iofs.ErrNotExist) {
			return 0, ErrNotFound
		}
		return 0, err
	}
	return st.Size(), nil
}

// VerifyShard implements Disk.
func (d *Local) verifyShard(ctx context.Context, bucket, object, dataDir string, part int, partSize, blockSize int64, dataBlocks int) (string, error) {
	sh, err := d.openShard(bucket, object, dataDir, part)
	if err != nil {
		return "", err
	}
	defer sh.Close()
	return VerifyStream(ctxReaderAt{ctx, sh}, partSize, blockSize, dataBlocks)
}

// ctxReaderAt fails reads once its context is done, so verifying a large
// shard stops promptly.
type ctxReaderAt struct {
	ctx context.Context
	r   io.ReaderAt
}

func (c ctxReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.ReadAt(p, off)
}

// PinData implements Disk.
func (d *Local) pinData(bucket, object, dataDir string) (func(), error) {
	dir, err := d.objDir(bucket, object)
	if err != nil {
		return nil, err
	}
	return d.pins.Pin(filepath.Join(dir, dataDir)), nil
}

// DeleteObject implements Disk. xl.meta is removed first: that is the
// drive's commit point for the deletion.
func (d *Local) deleteObject(bucket, object string) error {
	if err := d.check(); err != nil {
		return err
	}
	dir, err := d.objDir(bucket, object)
	if err != nil {
		return err
	}
	bucketDir, _ := d.path(bucket)
	var dataDirs []string
	if data, err := os.ReadFile(filepath.Join(dir, storage.MetaFileName)); err == nil {
		if f, derr := meta.Decode(data); derr == nil {
			for _, v := range f.Versions {
				if v.DataDir != "" {
					dataDirs = append(dataDirs, filepath.Join(dir, v.DataDir))
				}
			}
		}
	}
	if err := os.Remove(filepath.Join(dir, storage.MetaFileName)); err != nil && !errors.Is(err, iofs.ErrNotExist) {
		return err
	}
	for _, p := range dataDirs {
		d.pins.Remove(p)
	}
	for p := dir; p != bucketDir && strings.HasPrefix(p, bucketDir); p = filepath.Dir(p) {
		if os.Remove(p) != nil {
			break
		}
	}
	return nil
}

// localWriter is a staged file.
type localWriter struct {
	f    *os.File
	path string
	done bool
}

func (w *localWriter) Write(p []byte) (int, error) { return w.f.Write(p) }

func (w *localWriter) Close() error {
	if w.done {
		return nil
	}
	w.done = true
	err := w.f.Sync()
	if cerr := w.f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(w.path)
	}
	return err
}

func (w *localWriter) Abort() {
	if w.done {
		return
	}
	w.done = true
	w.f.Close()
	os.Remove(w.path)
}

func (d *Local) stagePath(stageID string, rel ...string) (string, error) {
	return fsutil.SafeJoin(d.tmp(), append([]string{stageID}, rel...)...)
}

func (d *Local) hold(stageID string) {
	d.stagesMu.Lock()
	d.stages[stageID] = true
	d.stagesMu.Unlock()
}

func (d *Local) held(stageID string) bool {
	d.stagesMu.Lock()
	defer d.stagesMu.Unlock()
	return d.stages[stageID]
}

// CreateStageFile implements Disk.
func (d *Local) createStageFile(stageID, rel string) (FileWriter, error) {
	if err := d.check(); err != nil {
		return nil, err
	}
	p, err := d.stagePath(stageID, rel)
	if err != nil {
		return nil, err
	}
	d.hold(stageID)
	if err := os.MkdirAll(filepath.Dir(p), dirPerm); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, filePerm)
	if err != nil {
		return nil, err
	}
	return &localWriter{f: f, path: p}, nil
}

// RemoveStage implements Disk.
func (d *Local) removeStage(stageID string) {
	if p, err := d.stagePath(stageID); err == nil {
		os.RemoveAll(p)
	}
	d.stagesMu.Lock()
	delete(d.stages, stageID)
	d.stagesMu.Unlock()
}

// localCommit is a published change awaiting its verdict.
type localCommit struct {
	undo   func()
	finish func()
}

func (c *localCommit) Rollback(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return Wrap("Rollback", "", err)
	}
	if c.undo != nil {
		c.undo()
	}
	return nil
}

func (c *localCommit) Finish(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return Wrap("Finish", "", err)
	}
	if c.finish != nil {
		c.finish()
	}
	return nil
}

// CommitObject implements Disk. Its steps are: place the data dir (setting
// aside any same-named one inside the stage, restored if publishing
// fails), keep a backup of the previous xl.meta, and rename the new xl.meta
// into place, which is this drive's commit point.
func (d *Local) commitObject(req CommitRequest) (Commit, error) {
	if err := d.check(); err != nil {
		return nil, err
	}
	if err := d.faultAt(FaultPreCommit); err != nil {
		return nil, err
	}
	objDir, err := d.objDir(req.Bucket, req.Object)
	if err != nil {
		return nil, err
	}
	bucketDir, _ := d.path(req.Bucket)
	stageDir, err := d.stagePath(req.StageID)
	if err != nil {
		return nil, err
	}
	stagedData := filepath.Join(stageDir, req.DataDir)
	metaPath := filepath.Join(objDir, storage.MetaFileName)

	km := d.keyLock(req.Bucket, req.Object)
	km.Lock()
	defer km.Unlock()

	// What is there now: its bytes (for rollback) and its data dir (to
	// remove once the commit is final).
	oldBytes, rerr := os.ReadFile(metaPath)
	if rerr != nil && !errors.Is(rerr, iofs.ErrNotExist) {
		return nil, rerr
	}
	oldDataDir := ""
	if rerr == nil {
		if old, derr := meta.Decode(oldBytes); derr == nil {
			if ov := old.Find(""); ov != nil {
				if req.CheckGen && ov.Generation > req.PrevGen {
					return nil, fmt.Errorf("%w: drive holds generation %d, write was based on %d",
						ErrConflict, ov.Generation, req.PrevGen)
				}
				if ov.DataDir != "" && ov.DataDir != req.DataDir {
					oldDataDir = filepath.Join(objDir, ov.DataDir)
				}
			}
		}
	}
	file := &meta.File{Format: meta.FormatVersion}
	file.Add(req.Version)
	enc, err := meta.Encode(file)
	if err != nil {
		return nil, err
	}
	stagedMeta := filepath.Join(stageDir, storage.MetaFileName)
	os.Remove(stagedMeta)
	if err := fsutil.WriteFileSync(stagedMeta, enc, filePerm); err != nil {
		return nil, err
	}

	newData := filepath.Join(objDir, req.DataDir)
	aside := ""
	for attempt := 0; ; attempt++ {
		err = fsutil.MkdirAllSync(bucketDir, objDir, dirPerm)
		if err == nil {
			if _, serr := os.Stat(newData); serr == nil && aside == "" {
				aside = filepath.Join(stageDir, "replaced-"+req.DataDir)
				if err = os.Rename(newData, aside); err != nil {
					aside = ""
				}
			}
		}
		if err == nil {
			err = os.Rename(stagedData, newData)
		}
		if err == nil {
			break
		}
		if fsutil.IsPruneRace(err) && attempt < 20 {
			continue
		}
		if aside != "" {
			os.Rename(aside, newData)
		}
		return nil, err
	}
	undoData := func() {
		os.RemoveAll(newData)
		if aside != "" {
			os.Rename(aside, newData)
		}
	}
	if err := fsutil.SyncDir(objDir); err != nil {
		undoData()
		return nil, err
	}
	if err := d.faultAt(FaultDataRenamed); err != nil {
		undoData()
		return nil, err
	}

	backup := filepath.Join(stageDir, "xl.meta.bak")
	hadOld := rerr == nil
	if hadOld {
		os.Remove(backup)
		if err := fsutil.WriteFileSync(backup, oldBytes, filePerm); err != nil {
			undoData()
			return nil, err
		}
	}
	if err := os.Rename(stagedMeta, metaPath); err != nil {
		undoData()
		return nil, err
	}
	fsutil.SyncDir(objDir) // published; a failed sync is left for the quorum to judge
	revert := func() {
		if hadOld {
			os.Rename(backup, metaPath)
		} else {
			os.Remove(metaPath)
		}
		undoData()
	}
	if err := d.faultAt(FaultMetaRenamed); err != nil {
		// The drive did commit; report failure so quorum accounting is
		// conservative, and revert it (the key lock is still held).
		revert()
		return nil, err
	}
	// A rollback arrives later, possibly after another writer committed
	// over this version; it must then leave that writer's state alone.
	undo := func() {
		km.Lock()
		defer km.Unlock()
		if cur, err := os.ReadFile(metaPath); err != nil || !bytes.Equal(cur, enc) {
			return
		}
		revert()
	}
	return &localCommit{
		undo: undo,
		finish: func() {
			if oldDataDir != "" {
				d.pins.Remove(oldDataDir)
			}
		},
	}, nil
}

// LinkPartIntoStage implements Disk.
func (d *Local) linkPartIntoStage(bucket, uploadID, partFile, stageID, rel string) error {
	if err := d.check(); err != nil {
		return err
	}
	src, err := d.uploadDirPath(bucket, uploadID)
	if err != nil {
		return err
	}
	if partFile != filepath.Base(partFile) {
		return fmt.Errorf("disk: invalid part file name %q", partFile)
	}
	dst, err := d.stagePath(stageID, rel)
	if err != nil {
		return err
	}
	d.hold(stageID)
	if err := os.MkdirAll(filepath.Dir(dst), dirPerm); err != nil {
		return err
	}
	return linkOrCopy(filepath.Join(src, partFile), dst)
}

// linkOrCopy hard-links src to dst, falling back to a durable copy.
func linkOrCopy(src, dst string) error {
	if err := os.Link(src, dst); err == nil {
		return nil
	} else if errors.Is(err, iofs.ErrNotExist) {
		return ErrNotFound
	}
	in, err := os.Open(src)
	if err != nil {
		if errors.Is(err, iofs.ErrNotExist) {
			return ErrNotFound
		}
		return err
	}
	defer in.Close()
	_, err = fsutil.CopySync(dst, in, filePerm)
	return err
}

var _ = io.EOF
