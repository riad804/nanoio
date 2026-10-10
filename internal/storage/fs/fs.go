// Package fs implements storage.StorageAPI on a single directory.
//
// On-disk layout (shared with the future xl backend):
//
//	<root>/.nanoio.sys/format.json   disk identity and format version
//	<root>/.nanoio.sys/.lock         flock: one process per root
//	<root>/.nanoio.sys/tmp/<uuid>/   staging for atomic commits
//	<root>/<bucket>/.nanoio-bucket   bucket creation marker
//	<root>/<bucket>/<key>/xl.meta    envelope + JSON, see package meta
//	<root>/<bucket>/<key>/.nanoio-data-<uuid>/part.1
//
// Object data is staged and fsynced before any lock is taken; the lock
// covers only the commit, whose single visible event is the rename of
// xl.meta. Only the null version exists in Phase 1: versioning, multipart,
// copy and metadata update return storage.ErrNotImplemented (see TODO.md).
package fs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	iofs "io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"nanoio/internal/meta"
	"nanoio/internal/storage"
	"nanoio/internal/storage/internal/fsutil"
	"nanoio/internal/storage/internal/pins"
)

const (
	sysDirName          = ".nanoio.sys"
	tmpDirName          = "tmp"
	lockFileName        = ".lock"
	formatFileName      = "format.json"
	bucketMarker        = storage.DataDirPrefix + "bucket"
	formatVersion       = 1
	maxObjectSize       = 5 << 40 // S3's 5 TiB
	defaultContentType  = "binary/octet-stream"
	defaultTmpMaxAge    = 24 * time.Hour
	defaultUploadExpiry = 7 * 24 * time.Hour
	defaultGCInterval   = time.Hour
	dirPerm             = 0o755
	filePerm            = 0o644
)

var _ storage.StorageAPI = (*FS)(nil)

// Options configures New.
type Options struct {
	// Locker is the namespace lock manager. Required.
	Locker storage.Locker
	// Logger defaults to slog.Default().
	Logger *slog.Logger
	// TmpMaxAge is the age past which the startup sweep removes staging
	// directories left by a crash. 0 means 24h; negative removes them all.
	TmpMaxAge time.Duration
	// MinPartSize is the smallest size of any multipart part but the last.
	// 0 means 5 MiB, S3's limit; only tests lower it.
	MinPartSize int64
	// UploadExpiry is how long an upload may sit without activity before
	// the collector aborts it. 0 means 7 days.
	UploadExpiry time.Duration
	// GCInterval is the period of the background collector. 0 means one
	// hour; a negative value disables it (GC can still be called).
	GCInterval time.Duration
	// Fault, when non-nil, is called at named commit points. If it returns
	// an error the operation stops there and skips cleanup, simulating a
	// crash. For tests only.
	Fault func(point string) error
}

// Fault points, in commit order.
const (
	FaultStaged      = "staged"       // body staged, no lock taken
	FaultMetaStaged  = "meta-staged"  // new xl.meta written to staging
	FaultDataRenamed = "data-renamed" // data dir moved into place
	FaultMetaRenamed = "meta-renamed" // xl.meta renamed: committed

	FaultPartStaged = "part-staged"       // part body staged, no lock taken
	FaultPartData   = "part-data-renamed" // part data in the upload dir, not yet referenced
	FaultPartMeta   = "part-meta-renamed" // part metadata switched: part committed
)

// FS is a single-directory storage backend.
type FS struct {
	root   string
	tmp    string
	locker storage.Locker
	log    *slog.Logger
	fault  func(string) error

	lock *os.File

	// pins keeps a data directory alive while a reader streams from it.
	pins pins.Registry

	minPartSize  int64
	uploadExpiry time.Duration
	tmpMaxAge    time.Duration

	gcCancel context.CancelFunc
	gcDone   chan struct{}

	// stages holds the staging directories of operations in flight, which
	// the collector must not remove however old they look: a multi-hour
	// upload's staging directory is as old as its first byte.
	stagesMu sync.Mutex
	stages   map[string]int

	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup

	corrupted atomic.Int64
}

type formatDoc struct {
	Format  int       `json:"format"`
	ID      string    `json:"id"`
	Created time.Time `json:"created"`
}

// New opens (creating if needed) the store rooted at root. It takes an
// exclusive lock on the root so two processes cannot share it.
func New(root string, opts Options) (*FS, error) {
	if opts.Locker == nil {
		return nil, errors.New("fs: Options.Locker is required")
	}
	if root == "" {
		return nil, errors.New("fs: empty root")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("fs: %w", err)
	}
	tmp := filepath.Join(abs, sysDirName, tmpDirName)
	if err := os.MkdirAll(tmp, dirPerm); err != nil {
		return nil, fmt.Errorf("fs: %w", err)
	}
	lf, err := os.OpenFile(filepath.Join(abs, sysDirName, lockFileName), os.O_CREATE|os.O_RDWR, filePerm)
	if err != nil {
		return nil, fmt.Errorf("fs: %w", err)
	}
	if err := fsutil.LockFile(lf); err != nil {
		lf.Close()
		return nil, fmt.Errorf("fs: root %s is in use by another process: %w", abs, err)
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	f := &FS{root: abs, tmp: tmp, locker: opts.Locker, log: logger, fault: opts.Fault, lock: lf,
		minPartSize: opts.MinPartSize, uploadExpiry: opts.UploadExpiry, tmpMaxAge: opts.TmpMaxAge}
	if f.minPartSize <= 0 {
		f.minPartSize = DefaultMinPartSize
	}
	if f.uploadExpiry <= 0 {
		f.uploadExpiry = defaultUploadExpiry
	}
	if err := os.MkdirAll(filepath.Join(abs, sysDirName, multipartDirName), dirPerm); err != nil {
		lf.Close()
		return nil, fmt.Errorf("fs: %w", err)
	}
	if err := f.loadFormat(); err != nil {
		lf.Close()
		return nil, err
	}
	f.sweepTmp(opts.TmpMaxAge)
	f.gcDone = make(chan struct{})
	interval := opts.GCInterval
	if interval == 0 {
		interval = defaultGCInterval
	}
	ctx, cancel := context.WithCancel(context.Background())
	f.gcCancel = cancel
	if interval > 0 {
		go f.gcLoop(ctx, interval)
	} else {
		close(f.gcDone)
	}
	return f, nil
}

func (f *FS) loadFormat() error {
	path := filepath.Join(f.root, sysDirName, formatFileName)
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		var doc formatDoc
		if err := json.Unmarshal(data, &doc); err != nil {
			return fmt.Errorf("%w: %s: %v", storage.ErrCorrupted, path, err)
		}
		if doc.Format != formatVersion {
			return fmt.Errorf("%w: %s: unsupported format version %d (this build understands %d)",
				storage.ErrCorrupted, path, doc.Format, formatVersion)
		}
		return nil
	case !errors.Is(err, iofs.ErrNotExist):
		return fmt.Errorf("fs: %w", err)
	}
	id, err := meta.NewVersionID()
	if err != nil {
		return err
	}
	data, err = json.Marshal(formatDoc{Format: formatVersion, ID: id, Created: time.Now().UTC()})
	if err != nil {
		return err
	}
	staged := filepath.Join(f.tmp, formatFileName+"."+id)
	if err := fsutil.WriteFileSync(staged, data, filePerm); err != nil {
		return fmt.Errorf("fs: %w", err)
	}
	if err := os.Rename(staged, path); err != nil {
		os.Remove(staged)
		return fmt.Errorf("fs: %w", err)
	}
	return fsutil.SyncDir(filepath.Dir(path))
}

// sweepTmp removes staging leftovers from a previous crash. Nothing in tmp
// is referenced by committed state, so age is the only safety condition.
func (f *FS) sweepTmp(maxAge time.Duration) (removed int) {
	if maxAge == 0 {
		maxAge = defaultTmpMaxAge
	}
	entries, err := os.ReadDir(f.tmp)
	if err != nil {
		f.log.Warn("fs: cannot read staging dir", "err", err)
		return 0
	}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		full := filepath.Join(f.tmp, e.Name())
		if f.stageHeld(full) {
			continue
		}
		if maxAge < 0 || time.Since(info.ModTime()) > maxAge {
			if err := os.RemoveAll(full); err != nil {
				f.log.Warn("fs: sweep failed", "entry", e.Name(), "err", err)
				continue
			}
			removed++
		}
	}
	return removed
}

// holdStage marks a staging directory as in use until the returned func is
// called.
func (f *FS) holdStage(path string) func() {
	f.stagesMu.Lock()
	if f.stages == nil {
		f.stages = map[string]int{}
	}
	f.stages[path]++
	f.stagesMu.Unlock()
	return func() {
		f.stagesMu.Lock()
		if f.stages[path]--; f.stages[path] <= 0 {
			delete(f.stages, path)
		}
		f.stagesMu.Unlock()
	}
}

func (f *FS) stageHeld(path string) bool {
	f.stagesMu.Lock()
	defer f.stagesMu.Unlock()
	return f.stages[path] > 0
}

// Close waits for in-flight calls, then releases the root. Further calls
// return ErrBackendUnavailable. It is idempotent. Readers already returned
// by GetObject stay valid: they hold their own file handles.
func (f *FS) Close() error {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return nil
	}
	f.closed = true
	f.mu.Unlock()
	f.gcCancel() // stop the collector before waiting for in-flight calls
	f.wg.Wait()
	<-f.gcDone
	return f.lock.Close() // releases the flock
}

// enter registers an in-flight call.
func (f *FS) enter() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return storage.ErrBackendUnavailable
	}
	f.wg.Add(1)
	return nil
}

func (f *FS) leave() { f.wg.Done() }

// Info reports backend identity and health.
func (f *FS) Info(ctx context.Context) (storage.BackendInfo, error) {
	if err := f.enter(); err != nil {
		return storage.BackendInfo{}, err
	}
	defer f.leave()
	total, free, err := fsutil.DiskUsage(f.root)
	return storage.BackendInfo{
		Kind: "fs", Disks: 1, TotalBytes: total, FreeBytes: free,
		Healthy: err == nil, Corrupted: int(f.corrupted.Load()),
	}, nil
}

// path joins elems under the root, confined by fsutil.SafeJoin.
func (f *FS) path(elems ...string) (string, error) {
	return fsutil.SafeJoin(f.root, elems...)
}

// keyDir returns the directory holding a validated key's xl.meta. A key
// ending in "/" maps to a directory carrying DirObjectSuffix so it cannot
// collide with the key without the slash.
func (f *FS) keyDir(bucket, object string) (string, error) {
	segs := strings.Split(object, "/")
	if last := len(segs) - 1; segs[last] == "" {
		segs = segs[:last]
		segs[len(segs)-1] += storage.DirObjectSuffix
	}
	return f.path(append([]string{bucket}, segs...)...)
}

// requireBucket returns ErrBucketNotFound unless bucket's directory exists.
func (f *FS) requireBucket(bucket string) error {
	dir, err := f.path(bucket)
	if err != nil {
		return storage.Wrap(storage.ErrInvalidBucketName, bucket, "")
	}
	st, err := os.Lstat(dir)
	if err != nil {
		if errors.Is(err, iofs.ErrNotExist) {
			return storage.Wrap(storage.ErrBucketNotFound, bucket, "")
		}
		return err
	}
	if !st.IsDir() {
		return storage.Wrap(storage.ErrBucketNotFound, bucket, "")
	}
	return nil
}

// readMeta loads and verifies keyDir/xl.meta. A missing file returns
// (nil, nil); any verification failure wraps storage.ErrCorrupted.
func (f *FS) readMeta(keyDir string) (*meta.File, error) {
	data, err := os.ReadFile(filepath.Join(keyDir, storage.MetaFileName))
	if err != nil {
		if errors.Is(err, iofs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
			return nil, nil
		}
		return nil, err
	}
	file, err := meta.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", storage.ErrCorrupted, keyDir, err)
	}
	return file, nil
}

// mapErr translates OS-level errors into storage sentinels. Context errors
// pass through unchanged so callers can tell cancellation from failure.
func mapErr(err error, bucket, object string) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case fsutil.IsNoSpace(err):
		return storage.Wrap(storage.ErrDiskFull, bucket, object)
	case errors.Is(err, io.ErrUnexpectedEOF):
		return storage.Wrap(storage.ErrIncompleteBody, bucket, object)
	}
	return err
}

func notImpl(op string) error {
	return fmt.Errorf("fs: %s: %w", op, storage.ErrNotImplemented)
}
