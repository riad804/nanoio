// Package xl implements storage.StorageAPI over a set of drives with
// Reed-Solomon erasure coding and per-block bitrot protection.
//
// An object is cut into blocks (1 MiB by default); each block is encoded
// into K data shards plus M parity shards, and shard i of every block is
// appended to a shard file on drive d where the object's rotation puts
// shard i. Any K of the K+M drives suffice to read the object, so up to M
// drives may be missing, offline or corrupt at once.
//
// On-disk layout, per drive (every drive has the same tree):
//
//	<drive>/.nanoio.sys/format.json   drive identity, set layout
//	<drive>/.nanoio.sys/.lock         flock: one process per drive
//	<drive>/.nanoio.sys/tmp/<id>/     staging for atomic commits
//	<drive>/<bucket>/<key>/xl.meta    this drive's metadata (see package meta)
//	<drive>/<bucket>/<key>/.nanoio-data-<id>/part.N   shard stream of part N
//
// A shard file is a sequence of [32-byte SHA-256][shard bytes] records, one
// per erasure block, so a read verifies exactly the blocks it needs and a
// ranged read touches only the blocks it spans.
//
// Metadata is the same JSON-in-CRC-envelope as the fs backend, written to
// every drive; only Erasure.Index and the per-part checksums differ between
// drives. A read takes the latest version that at least K drives agree on.
// Writes commit on all drives and succeed when a write quorum (K, or K+1
// when K == M) has committed; a failed commit is rolled back.
//
// Beyond the StorageAPI, an XL exposes Heal, HealObject and Scan, and runs
// a background scanner that reconstructs missing or corrupt shards, formats
// replacement drives, and collects abandoned uploads and orphaned data.
package xl

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klauspost/reedsolomon"

	"nanoio/internal/meta"
	"nanoio/internal/storage"
	"nanoio/internal/storage/internal/fsutil"
	"nanoio/internal/storage/xl/disk"
)

const (
	// DefaultBlockSize is the erasure block size: the unit that is encoded,
	// hashed and, on a ranged read, fetched.
	DefaultBlockSize = 1 << 20
	// MaxDrives bounds a set: Reed-Solomon over GF(2^8) allows 256 shards,
	// and fan-out beyond a few dozen drives is not what this backend is for.
	MaxDrives = 32

	maxObjectSize = 5 << 40
	algorithm     = "reedsolomon"
	hashAlgorithm = "sha256"
	defaultCT     = "binary/octet-stream"
)

// errDriveOffline marks a drive that is missing, unformatted or failed.
var errDriveOffline = disk.ErrOffline

// Options configures New.
type Options struct {
	// Locker is the namespace lock manager. Required.
	Locker storage.Locker
	// Logger defaults to slog.Default().
	Logger *slog.Logger
	// ParityBlocks is M, the number of drives that may be lost. Data blocks
	// K = len(drives) - M. 0 means half the drives. M must be 1..K.
	ParityBlocks int
	// BlockSize is the erasure block size for new objects; existing
	// objects keep the size they were written with. 0 means 1 MiB.
	BlockSize int64
	// MinPartSize is the smallest multipart part but the last. 0 means 5 MiB.
	MinPartSize int64
	// UploadExpiry is how long an upload may idle before the scanner
	// aborts it. 0 means 7 days.
	UploadExpiry time.Duration
	// TmpMaxAge is the age past which staging debris is swept. 0 means
	// 24h; negative removes all debris (for tests, at startup).
	TmpMaxAge time.Duration
	// ScanInterval is the period of the background scanner. 0 means one
	// hour; negative disables it (Scan can still be called). Reads that
	// find damage queue a heal regardless.
	ScanInterval time.Duration
	// StorageClasses maps a storage class name to the parity count its
	// objects are written with (data = drives - parity). STANDARD is the
	// set's own ParityBlocks and may not be redefined; REDUCED_REDUNDANCY
	// defaults to parity 1. A class's parity must be between 1 and
	// ParityBlocks: a class can be less redundant than STANDARD, never more.
	// Objects keep the layout they were written with.
	StorageClasses map[string]int
	// DeploymentID, when set, identifies a deployment whose drives are not
	// yet formatted. Nodes that format the same set concurrently must agree
	// on it; if any drive already carries an ID, that one wins.
	DeploymentID string
	// StragglerGrace is how long a write waits for the drives that have not
	// finished once the write quorum has: they are then dropped from the
	// write and repaired by heal. 0 means 500ms; negative means do not wait.
	StragglerGrace time.Duration
	// OnTransitionFreed is called (after the change is committed, from the
	// writer's goroutine) when a version whose data lives in a tier is
	// removed or overwritten, so the remote copy can be deleted. It must
	// not block; a copy missed here (a crash between commit and callback)
	// is an orphan in the tier, not a correctness problem.
	OnTransitionFreed func(bucket, object string, tr storage.TransitionInfo)
	// WriteQueue is how many erasure blocks may be queued for one drive. A
	// full queue holds the write back, since every drive is slower than
	// memory; 0 means 8.
	WriteQueue int
	// WriteStallTimeout is how long a write waits for room in one drive's
	// full queue before dropping that drive from the write (when the
	// quorum can spare it). 0 means 2s.
	WriteStallTimeout time.Duration
	// Fault, when non-nil, is called at named commit points with the drive
	// index; an error is treated as that drive's failure. For tests only.
	// It applies to the local drives New creates; drives handed to
	// NewWithDisks carry their own hooks.
	Fault func(point string, drive int) error
}

// Fault points.
const (
	FaultPreCommit   = disk.FaultPreCommit   // before a drive publishes its data
	FaultDataRenamed = disk.FaultDataRenamed // data dir in place, xl.meta not yet
	FaultMetaRenamed = disk.FaultMetaRenamed // drive committed
)

// drive is one member of the set: a Disk and its position.
type drive struct {
	idx int
	disk.Disk
}

// XL is an erasure-coded storage.StorageAPI.
type XL struct {
	drives    []*drive
	k, m      int
	blockSize int64
	enc       reedsolomon.Encoder
	// classes maps a storage class to its parity; encMu guards encs, the
	// encoders of the layouts classes (and existing objects) use.
	classes map[string]int
	encMu   sync.Mutex
	encs    map[[2]int]reedsolomon.Encoder

	locker storage.Locker
	log    *slog.Logger

	deploymentID   string
	wantDeployment string

	stragglerGrace time.Duration
	onFreed        func(bucket, object string, tr storage.TransitionInfo)
	writeQueue     int
	stallTimeout   time.Duration

	minPartSize  int64
	uploadExpiry time.Duration
	tmpMaxAge    time.Duration

	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup

	healQ      chan healReq
	scanCancel context.CancelFunc
	scanDone   chan struct{}

	corrupted atomic.Int64

	verMu    sync.Mutex
	verCache map[string]cachedVersioning
}

// cachedVersioning is a bucket's versioning state as last seen, used only
// to decide how version IDs are reported on reads. Writes always read the
// state under the bucket lock.
type cachedVersioning struct {
	cfg storage.VersioningConfig
	at  time.Time
}

const versioningCacheTTL = 2 * time.Second

// reportState returns the bucket's versioning state for reporting version
// IDs. It may be a couple of seconds old; if it cannot be read the bucket
// reports as unversioned (the version ID header is merely omitted).
func (x *XL) reportState(ctx context.Context, bucket string) storage.VersioningState {
	x.verMu.Lock()
	c, ok := x.verCache[bucket]
	x.verMu.Unlock()
	if ok && time.Since(c.at) < versioningCacheTTL {
		return c.cfg.State
	}
	v, err := x.versioning(ctx, bucket)
	if err != nil {
		return c.cfg.State
	}
	x.noteVersioning(bucket, v.cfg)
	return v.cfg.State
}

// noteVersioning records a freshly read or written state.
func (x *XL) noteVersioning(bucket string, cfg storage.VersioningConfig) {
	x.verMu.Lock()
	if x.verCache == nil {
		x.verCache = map[string]cachedVersioning{}
	}
	x.verCache[bucket] = cachedVersioning{cfg, time.Now()}
	x.verMu.Unlock()
}

var _ storage.StorageAPI = (*XL)(nil)

// New opens (formatting if needed) an erasure set over the given drive
// directories, in order: the position of a directory in the list is its
// identity, recorded on the drive, so reordering is detected.
func New(drives []string, opts Options) (*XL, error) {
	if n := len(drives); n < 2 || n > MaxDrives {
		return nil, fmt.Errorf("xl: %d drives given; need 2 to %d", n, MaxDrives)
	}
	seen := map[string]bool{}
	disks := make([]disk.Disk, 0, len(drives))
	for i, p := range drives {
		abs, err := filepath.Abs(p)
		if err != nil {
			return nil, fmt.Errorf("xl: drive %d: %w", i, err)
		}
		if seen[abs] {
			return nil, fmt.Errorf("xl: drive %q listed twice", abs)
		}
		seen[abs] = true
		lo := disk.LocalOptions{}
		if opts.Fault != nil {
			lo.Fault = func(point string) error { return opts.Fault(point, i) }
		}
		l, err := disk.NewLocal(abs, lo)
		if err != nil {
			return nil, fmt.Errorf("xl: drive %d: %w", i, err)
		}
		disks = append(disks, l)
	}
	return NewWithDisks(context.Background(), disks, opts)
}

// NewWithDisks opens (formatting if needed) an erasure set over the given
// disks, in order. ctx bounds the startup calls only. The position of a disk in the list is its identity,
// recorded on it, so reordering is detected. The set takes ownership of the
// disks and closes them on Close.
func NewWithDisks(ctx context.Context, disks []disk.Disk, opts Options) (*XL, error) {
	if opts.Locker == nil {
		return nil, errors.New("xl: Options.Locker is required")
	}
	n := len(disks)
	if n < 2 || n > MaxDrives {
		return nil, fmt.Errorf("xl: %d drives given; need 2 to %d", n, MaxDrives)
	}
	m := opts.ParityBlocks
	if m == 0 {
		m = n / 2
	}
	k := n - m
	if m < 1 || m > k {
		return nil, fmt.Errorf("xl: %d drives with %d parity gives %d+%d; need 1 <= parity <= data", n, m, k, m)
	}
	enc, err := reedsolomon.New(k, m)
	if err != nil {
		return nil, fmt.Errorf("xl: %w", err)
	}
	classes, err := resolveClasses(opts.StorageClasses, n, m)
	if err != nil {
		return nil, err
	}
	x := &XL{k: k, m: m, enc: enc, classes: classes, locker: opts.Locker, log: opts.Logger,
		blockSize: opts.BlockSize, minPartSize: opts.MinPartSize, uploadExpiry: opts.UploadExpiry,
		tmpMaxAge: opts.TmpMaxAge, healQ: make(chan healReq, 1024), wantDeployment: opts.DeploymentID}
	if x.log == nil {
		x.log = slog.Default()
	}
	if x.blockSize <= 0 {
		x.blockSize = DefaultBlockSize
	}
	x.onFreed = opts.OnTransitionFreed
	x.stragglerGrace, x.writeQueue = opts.StragglerGrace, opts.WriteQueue
	if x.stragglerGrace == 0 {
		x.stragglerGrace = 500 * time.Millisecond
	} else if x.stragglerGrace < 0 {
		x.stragglerGrace = 0
	}
	if x.writeQueue <= 0 {
		x.writeQueue = 8
	}
	x.stallTimeout = opts.WriteStallTimeout
	if x.stallTimeout <= 0 {
		x.stallTimeout = 2 * time.Second
	}
	if x.minPartSize <= 0 {
		x.minPartSize = 5 << 20
	}
	if x.uploadExpiry <= 0 {
		x.uploadExpiry = 7 * 24 * time.Hour
	}
	names := map[string]bool{}
	for i, dk := range disks {
		if names[dk.String()] {
			return nil, fmt.Errorf("xl: drive %q listed twice", dk.String())
		}
		names[dk.String()] = true
		x.drives = append(x.drives, &drive{idx: i, Disk: dk})
	}

	// Open every drive, then agree on one deployment identity.
	var errs []error
	formats := make([]*disk.Format, n)
	blank := make([]bool, n)
	for i, d := range x.drives {
		f, err := d.Open(ctx, true)
		switch {
		case errors.Is(err, disk.ErrUnformatted):
			blank[i] = true
		case err != nil:
			errs = append(errs, fmt.Errorf("drive %d (%s): %w", i, d, err))
			x.log.Warn("xl: drive unavailable at startup", "drive", i, "err", err)
		default:
			formats[i] = f
		}
	}
	if err := x.reconcileFormats(ctx, formats, blank); err != nil {
		x.closeDrives()
		return nil, err
	}
	if ready := x.readyCount(ctx); ready < k {
		x.closeDrives()
		return nil, fmt.Errorf("xl: only %d of %d drives are usable; need at least %d: %w", ready, n, k, errors.Join(errs...))
	}
	for _, d := range x.drives {
		if d.Ready(ctx) {
			x.sweepTmp(ctx, d, opts.TmpMaxAge)
		}
	}
	x.startScanner(opts.ScanInterval)
	return x, nil
}

// reconcileFormats validates the formatted drives against each other and
// against the configuration, then formats blank ones (new deployment, or
// replacement drives joining an existing one). An unusable drive is
// tolerated (it counts against quorum); structural problems are fatal.
func (x *XL) reconcileFormats(ctx context.Context, formats []*disk.Format, blank []bool) error {
	id := ""
	for i, f := range formats {
		if f == nil {
			continue
		}
		if f.DataBlocks != x.k || f.ParityBlocks != x.m {
			return fmt.Errorf("xl: drive %d was formatted as %d+%d but %d+%d is configured", i, f.DataBlocks, f.ParityBlocks, x.k, x.m)
		}
		if f.Index != i {
			return fmt.Errorf("xl: drive %q is position %d in the configuration but %d in its format; the drive list was reordered", x.drives[i].String(), i, f.Index)
		}
		if id != "" && f.DeploymentID != id {
			return fmt.Errorf("xl: drive %d belongs to deployment %s, others to %s", i, f.DeploymentID, id)
		}
		id = f.DeploymentID
	}
	if id == "" {
		id = x.wantDeployment
	}
	if id == "" {
		fresh, err := meta.NewVersionID()
		if err != nil {
			return err
		}
		id = fresh
	}
	x.deploymentID = id
	for i, isBlank := range blank {
		if !isBlank {
			continue
		}
		d := x.drives[i]
		if err := x.writeFormat(ctx, d); err != nil {
			x.log.Warn("xl: could not format drive", "drive", i, "err", err)
			d.Close()
		}
	}
	return nil
}

func (x *XL) writeFormat(ctx context.Context, d *drive) error {
	return d.WriteFormat(ctx, &disk.Format{Format: disk.FormatVersion, DeploymentID: x.deploymentID,
		Index: d.idx, DataBlocks: x.k, ParityBlocks: x.m, Created: time.Now().UTC()})
}

func (x *XL) closeDrives() {
	for _, d := range x.drives {
		d.Close()
	}
}

func (x *XL) readyCount(ctx context.Context) int {
	n := 0
	for _, d := range x.drives {
		if d.Ready(ctx) {
			n++
		}
	}
	return n
}

// readQuorum is the number of agreeing drives a read needs.
func (x *XL) readQuorum() int { return x.k }

// writeQuorum is the number of drives a write must reach. With K == M two
// disjoint halves could each hold a "latest" version, so one more is
// required; this guarantees the surviving old version is never a quorum.
func (x *XL) writeQuorum() int { return quorumOf(x.k, x.m) }

// quorumOf is the write quorum of a k+m layout.
func quorumOf(k, m int) int {
	if k == m {
		return k + 1
	}
	return k
}

// DefaultReducedParity is REDUCED_REDUNDANCY's parity when none is set.
const DefaultReducedParity = 1

// resolveClasses validates the configured storage classes for a set of n
// drives whose STANDARD parity is std.
func resolveClasses(in map[string]int, n, std int) (map[string]int, error) {
	out := map[string]int{}
	for name, p := range in {
		switch {
		case name == "" || len(name) > 32 || strings.ToUpper(name) != name || strings.ContainsAny(name, " \t/"):
			return nil, fmt.Errorf("xl: storage class %q: names are 1-32 upper-case characters", name)
		case name == "STANDARD":
			if p != std {
				return nil, fmt.Errorf("xl: STANDARD parity is the set's parity (%d); it cannot be set to %d", std, p)
			}
			continue
		case p < 1 || p > n/2:
			return nil, fmt.Errorf("xl: storage class %s: parity %d with %d drives; need 1 <= parity <= %d", name, p, n, n/2)
		case p > std:
			// An object's metadata is committed to, and read back from, a
			// quorum sized for the set's own layout; an object that
			// tolerated more lost drives than that could not be found once
			// they were gone, so more parity than STANDARD buys nothing.
			return nil, fmt.Errorf("xl: storage class %s: parity %d exceeds STANDARD's %d; classes may only be less redundant", name, p, std)
		}
		out[name] = p
	}
	if _, ok := out["REDUCED_REDUNDANCY"]; !ok {
		out["REDUCED_REDUNDANCY"] = min(DefaultReducedParity, std)
	}
	return out, nil
}

// geomFor resolves a storage class to its erasure layout. class is the
// canonical name to record: empty for STANDARD.
func (x *XL) geomFor(class string) (k, m int, canonical string, err error) {
	if class == "" || class == "STANDARD" {
		return x.k, x.m, "", nil
	}
	p, ok := x.classes[class]
	if !ok {
		return 0, 0, "", fmt.Errorf("%w: %q", storage.ErrInvalidStorageClass, class)
	}
	return len(x.drives) - p, p, class, nil
}

// encoder returns the Reed-Solomon encoder of a k+m layout.
func (x *XL) encoder(k, m int) (reedsolomon.Encoder, error) {
	if k == x.k && m == x.m {
		return x.enc, nil
	}
	x.encMu.Lock()
	defer x.encMu.Unlock()
	key := [2]int{k, m}
	if e, ok := x.encs[key]; ok {
		return e, nil
	}
	e, err := reedsolomon.New(k, m)
	if err != nil {
		return nil, err
	}
	if x.encs == nil {
		x.encs = map[[2]int]reedsolomon.Encoder{}
	}
	x.encs[key] = e
	return e, nil
}

// distribution returns, for a key, the shard index each drive stores:
// dist[d] is the shard on drive d. A per-key rotation spreads parity (and
// therefore the lighter read load) evenly across drives.
func (x *XL) distribution(bucket, object string) []int {
	n := len(x.drives)
	h := uint32(2166136261) // FNV-1a
	for _, c := range []byte(bucket + "/" + object) {
		h = (h ^ uint32(c)) * 16777619
	}
	off := int(h % uint32(n))
	dist := make([]int, n)
	for d := range dist {
		dist[d] = (d + off) % n
	}
	return dist
}

// enter registers an in-flight call; leave must follow.
func (x *XL) enter(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.closed {
		return storage.ErrBackendUnavailable
	}
	x.wg.Add(1)
	return nil
}

func (x *XL) leave() { x.wg.Done() }

// each runs fn on every drive concurrently. Drives that are not ready are
// reported as errDriveOffline without calling fn.
func (x *XL) each(ctx context.Context, fn func(d *drive) error) []error {
	errs := make([]error, len(x.drives))
	var wg sync.WaitGroup
	for i, d := range x.drives {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !d.Ready(ctx) {
				errs[i] = errDriveOffline
				return
			}
			errs[i] = fn(d)
		}()
	}
	wg.Wait()
	return errs
}

// scatter runs fn on every drive concurrently and returns once need of them
// have succeeded and grace has passed for the rest (grace <= 0 returns at
// once), or, with giveUp set, as soon as need can no longer be reached. The
// calls carry on after scatter returns (detached from ctx when detach is set); a success
// that arrives late is handed to late (which may be nil) so it can be
// cleaned up or completed. Drives that had not answered report
// errStraggler. Drives that are not ready report errDriveOffline.
func scatter[T any](ctx context.Context, x *XL, need int, grace time.Duration, giveUp, detach bool,
	fn func(ctx context.Context, d *drive) (T, error), late func(i int, v T)) ([]T, []error) {
	n := len(x.drives)
	// With detach set the calls outlive the request (cleanup-like work whose
	// results are plain values). Without it they run under ctx itself, for
	// calls that return objects bound to their context, such as writers.
	cctx, cancel := ctx, context.CancelFunc(func() {})
	if detach {
		cctx, cancel = detached(ctx)
	}
	type answer struct {
		i   int
		v   T
		err error
	}
	ch := make(chan answer, n)
	for i, d := range x.drives {
		go func() {
			var zero T
			if !d.Ready(cctx) {
				ch <- answer{i, zero, errDriveOffline}
				return
			}
			v, err := fn(cctx, d)
			ch <- answer{i, v, err}
		}()
	}
	vals := make([]T, n)
	errs := make([]error, n)
	seen := make([]bool, n)
	got, ok := 0, 0
	var graceC <-chan time.Time
loop:
	for got < n {
		if ok >= need && graceC == nil {
			if grace <= 0 {
				break
			}
			t := time.NewTimer(grace)
			defer t.Stop()
			graceC = t.C
		}
		if giveUp && ok+(n-got) < need {
			break
		}
		select {
		case a := <-ch:
			got++
			seen[a.i] = true
			vals[a.i], errs[a.i] = a.v, a.err
			if a.err == nil {
				ok++
			}
		case <-graceC:
			break loop
		}
	}
	if got == n {
		cancel()
		return vals, errs
	}
	for i := range errs {
		if !seen[i] {
			errs[i] = errStraggler
		}
	}
	remaining := n - got
	go func() {
		defer cancel()
		for k := 0; k < remaining; k++ {
			if a := <-ch; a.err == nil && late != nil {
				late(a.i, a.v)
			}
		}
	}()
	return vals, errs
}

func countNil(errs []error) int {
	n := 0
	for _, e := range errs {
		if e == nil {
			n++
		}
	}
	return n
}

// Close stops the scanner, waits for in-flight calls and releases every
// drive. It is idempotent.
func (x *XL) Close() error {
	x.mu.Lock()
	if x.closed {
		x.mu.Unlock()
		return nil
	}
	x.closed = true
	x.mu.Unlock()
	x.scanCancel()
	x.wg.Wait()
	<-x.scanDone
	x.closeDrives()
	return nil
}

// Info reports the set's size and health. Healthy means every drive is
// usable; a degraded but readable set reports false with Disks counting
// all members.
func (x *XL) Info(ctx context.Context) (storage.BackendInfo, error) {
	if err := x.enter(ctx); err != nil {
		return storage.BackendInfo{}, err
	}
	defer x.leave()
	var total, free uint64
	ready := 0
	for _, d := range x.drives {
		if !d.Ready(ctx) {
			continue
		}
		ready++
		if info, err := d.Info(ctx); err == nil {
			total += info.Total
			free += info.Free
		}
	}
	return storage.BackendInfo{
		Kind: "xl", Disks: len(x.drives), TotalBytes: total, FreeBytes: free,
		Healthy: ready == len(x.drives), Corrupted: int(x.corrupted.Load()),
	}, nil
}

// Layout reports the erasure configuration.
func (x *XL) Layout() (data, parity int, blockSize int64) { return x.k, x.m, x.blockSize }

// OnlineDrives reports how many drives are currently usable.
func (x *XL) OnlineDrives() int { return x.readyCount(context.Background()) }

// sweepTmp removes staging debris older than maxAge from one drive. Zero
// means the 24h default; negative removes every unheld staging area.
func (x *XL) sweepTmp(ctx context.Context, d *drive, maxAge time.Duration) int {
	if maxAge == 0 {
		maxAge = 24 * time.Hour
	}
	n, err := d.SweepStaging(ctx, maxAge)
	if err != nil {
		x.log.Debug("xl: staging sweep failed", "drive", d.idx, "err", err)
	}
	return n
}

func mapErr(err error, bucket, object string) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case fsutil.IsNoSpace(err), errors.Is(err, storage.ErrDiskFull):
		return storage.Wrap(storage.ErrDiskFull, bucket, object)
	}
	return err
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
