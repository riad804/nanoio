package remote

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"nanoio/internal/cluster/rpc"
	"nanoio/internal/storage/xl/disk"
)

// Options tunes a Remote.
type Options struct {
	// OpTimeout bounds a metadata RPC (in addition to the caller's context).
	// 0 means 30s.
	OpTimeout time.Duration
	// DataTimeout bounds a bulk RPC (shard read, stage append, verify).
	// 0 means 5 minutes.
	DataTimeout time.Duration
	// ProbeTimeout bounds a readiness probe. 0 means 2s.
	ProbeTimeout time.Duration
	// OKFor is how long a successful call vouches for the drive without
	// another probe. 0 means 2s.
	OKFor time.Duration
	// DownFor is the circuit breaker's first open interval: after
	// BreakerThreshold consecutive transport failures the drive fails fast
	// for this long, then one probe call is let through; each failed probe
	// doubles the interval up to BreakerMax. 0 means 1s.
	DownFor time.Duration
	// BreakerThreshold is how many consecutive transport failures open the
	// breaker. 0 means 2.
	BreakerThreshold int
	// BreakerMax caps the open interval. 0 means 30s.
	BreakerMax time.Duration
	// ChunkSize is how many bytes of a staged file are buffered before an
	// append RPC. 0 means 1 MiB.
	ChunkSize int
	// Lease is the server's handle lease, so pins can be kept alive. 0
	// means DefaultLease.
	Lease time.Duration
}

// Remote is a disk.Disk on another node.
type Remote struct {
	c     *rpc.Client
	node  string
	drive string
	opt   Options

	mu      sync.Mutex
	okUntil time.Time // a success this recent vouches for the drive

	// Circuit breaker. openUntil is zero while closed. Once it has passed
	// the breaker is half-open: exactly one call (the probe) is allowed,
	// and its outcome closes or re-opens the breaker.
	fails     int
	openUntil time.Time
	backoff   time.Duration
	probing   bool
}

var _ disk.Disk = (*Remote)(nil)

// New returns the Disk for drive on node. drive is the ID the node serves it
// under.
func New(c *rpc.Client, node, drive string, opt Options) *Remote {
	if opt.OpTimeout <= 0 {
		opt.OpTimeout = 30 * time.Second
	}
	if opt.DataTimeout <= 0 {
		opt.DataTimeout = 5 * time.Minute
	}
	if opt.ProbeTimeout <= 0 {
		opt.ProbeTimeout = 2 * time.Second
	}
	if opt.OKFor <= 0 {
		opt.OKFor = 2 * time.Second
	}
	if opt.DownFor <= 0 {
		opt.DownFor = time.Second
	}
	if opt.BreakerThreshold <= 0 {
		opt.BreakerThreshold = 2
	}
	if opt.BreakerMax <= 0 {
		opt.BreakerMax = 30 * time.Second
	}
	if opt.ChunkSize <= 0 {
		opt.ChunkSize = 1 << 20
	}
	if opt.Lease <= 0 {
		opt.Lease = DefaultLease
	}
	return &Remote{c: c, node: node, drive: drive, opt: opt}
}

func (r *Remote) String() string { return r.node + ":" + r.drive }

// errBreakerOpen is the cause of a call refused without touching the
// network.
var errBreakerOpen = errors.New("circuit breaker open: recent calls to this drive failed")

// allow reports whether a call may go out: always while the breaker is
// closed, never while it is open, and for one probe at a time when it is
// half-open.
func (r *Remote) allow() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.openUntil.IsZero() {
		return true
	}
	if time.Now().Before(r.openUntil) || r.probing {
		return false
	}
	r.probing = true
	return true
}

// succeeded closes the breaker.
func (r *Remote) succeeded() {
	r.mu.Lock()
	r.fails, r.openUntil, r.backoff, r.probing = 0, time.Time{}, 0, false
	r.okUntil = time.Now().Add(r.opt.OKFor)
	r.mu.Unlock()
}

// failed records a transport failure, opening the breaker when the
// threshold is reached or a half-open probe fails.
func (r *Remote) failed() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.okUntil = time.Time{}
	r.fails++
	if !r.probing && r.fails < r.opt.BreakerThreshold {
		return
	}
	if r.backoff == 0 {
		r.backoff = r.opt.DownFor
	} else {
		r.backoff = min(r.backoff*2, r.opt.BreakerMax)
	}
	r.openUntil = time.Now().Add(r.backoff)
	r.probing = false
}

// abandoned releases a half-open probe slot when the caller cancelled
// before the call said anything about the drive.
func (r *Remote) abandoned() {
	r.mu.Lock()
	r.probing = false
	r.mu.Unlock()
}

// translate converts an RPC outcome into a *disk.Error and updates the
// breaker. The caller's own cancellation says nothing about the drive.
func (r *Remote) translate(ctx context.Context, op, path string, err error) error {
	if err == nil {
		r.succeeded()
		return nil
	}
	var re *rpc.Error
	if errors.As(err, &re) {
		r.succeeded() // the node answered: it is up, whatever it said
		e := decodeError(op, re).(*disk.Error)
		e.Path = path
		return e
	}
	if ctx.Err() != nil {
		r.abandoned()
		return &disk.Error{Kind: disk.KindCanceled, Op: op, Path: path, Err: ctx.Err()}
	}
	r.failed()
	return &disk.Error{Kind: disk.KindOffline, Op: op, Path: path, Err: fmt.Errorf("%s: %w", r, err)}
}

func (r *Remote) refused(op, path string) error {
	return &disk.Error{Kind: disk.KindOffline, Op: op, Path: path, Err: fmt.Errorf("%s: %w", r, errBreakerOpen)}
}

// call performs a JSON RPC bounded by both ctx and the metadata timeout.
func (r *Remote) call(ctx context.Context, op, path string, in, out any) error {
	return r.callT(ctx, r.opt.OpTimeout, op, path, in, out)
}

func (r *Remote) callT(ctx context.Context, d time.Duration, op, path string, in, out any) error {
	if !r.allow() {
		return r.refused(op, path)
	}
	cctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	return r.translate(ctx, op, path, r.c.Call(cctx, r.node, "disk."+opWire[op], in, out))
}

// opWire maps Disk method names to wire ops.
var opWire = map[string]string{
	"Open": "open", "WriteFormat": "writeformat", "Ready": "ready", "Info": "info",
	"MakeBucket": "bucket.make", "StatBucket": "bucket.stat", "ListBuckets": "bucket.list",
	"DeleteBucket": "bucket.delete", "ListKeys": "keys", "ReadMeta": "meta.read",
	"StatShard": "shard.stat", "VerifyShard": "shard.verify", "ReadAt": "shard.read",
	"PinData": "pin", "PinTouch": "pin.touch", "Unpin": "unpin", "DeleteObject": "object.delete",
	"CreateStageFile": "stage.create", "StageAppend": "stage.append", "StageClose": "stage.close",
	"StageAbort": "stage.abort", "RemoveStage": "stage.remove", "CommitObject": "commit",
	"CommitFinish": "commit.finish", "CommitRollback": "commit.rollback", "LinkPartIntoStage": "link",
	"CreateUpload": "upload.create", "ReadUpload": "upload.read", "ListUploadIDs": "upload.ids",
	"ListParts": "upload.parts", "CommitPart": "part.commit", "DiscardUpload": "upload.discard",
	"SweepStaging": "sweep", "StaleUploads": "upload.stale", "DiscardUploadIfStale": "upload.discardstale",
	"FindOrphans": "orphans", "RemoveOrphans": "orphans.remove",
}

func (r *Remote) raw(ctx context.Context, op, path string, args any, body []byte) ([]byte, error) {
	a, err := json.Marshal(args)
	if err != nil {
		return nil, err
	}
	if !r.allow() {
		return nil, r.refused(op, path)
	}
	cctx, cancel := context.WithTimeout(ctx, r.opt.DataTimeout)
	defer cancel()
	out, err := r.c.Do(cctx, r.node, "disk."+opWire[op], a, body)
	return out, r.translate(ctx, op, path, err)
}

// detached returns a context that survives the caller's cancellation, for
// cleanup that must still run.
func (r *Remote) detached(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), r.opt.OpTimeout)
}

func (r *Remote) da() DriveArg { return DriveArg{r.drive} }

func (r *Remote) obj(bucket, object, dataDir string, part int) objArgs {
	return objArgs{DriveArg: r.da(), Bucket: bucket, Object: object, DataDir: dataDir, Part: part}
}

func objPath(bucket, object string) string {
	if object == "" {
		return bucket
	}
	return bucket + "/" + object
}

// Open implements disk.Disk.
func (r *Remote) Open(ctx context.Context, create bool) (*disk.Format, error) {
	var res formatRes
	if err := r.call(ctx, "Open", "", openArgs{r.da(), create}, &res); err != nil {
		return nil, err
	}
	return res.Format, nil
}

// WriteFormat implements disk.Disk.
func (r *Remote) WriteFormat(ctx context.Context, f *disk.Format) error {
	return r.call(ctx, "WriteFormat", "", formatArgs{r.da(), *f}, nil)
}

// Ready implements disk.Disk. A recent success answers without a round
// trip, an open circuit breaker answers "no" without one, and otherwise the
// node is probed (which, for a half-open breaker, is the probe call).
func (r *Remote) Ready(ctx context.Context) bool {
	if ctx.Err() != nil {
		return false
	}
	r.mu.Lock()
	vouched := time.Now().Before(r.okUntil)
	r.mu.Unlock()
	if vouched {
		return true
	}
	var res readyRes
	if err := r.callT(ctx, r.opt.ProbeTimeout, "Ready", "", r.da(), &res); err != nil {
		return false
	}
	if !res.Ready { // the node is up but says the drive is not
		r.mu.Lock()
		r.okUntil = time.Time{}
		r.mu.Unlock()
	}
	return res.Ready
}

// Breaker reports the circuit breaker's state for health reporting:
// "closed", "open" or "half-open".
func (r *Remote) Breaker() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case r.openUntil.IsZero():
		return "closed"
	case time.Now().Before(r.openUntil):
		return "open"
	}
	return "half-open"
}

// Info implements disk.Disk.
func (r *Remote) Info(ctx context.Context) (disk.Info, error) {
	var res infoRes
	err := r.call(ctx, "Info", "", r.da(), &res)
	return disk.Info{Total: res.Total, Free: res.Free}, err
}

// Close implements disk.Disk. The drive belongs to its node; a remote
// client never closes it.
func (r *Remote) Close() error { return nil }

// MakeBucket implements disk.Disk.
func (r *Remote) MakeBucket(ctx context.Context, bucket string, created time.Time) (bool, error) {
	var res madeRes
	err := r.call(ctx, "MakeBucket", bucket, bucketArgs{r.da(), bucket, created}, &res)
	return res.Made, err
}

// StatBucket implements disk.Disk.
func (r *Remote) StatBucket(ctx context.Context, bucket string) (bool, time.Time, error) {
	var res statBucketRes
	err := r.call(ctx, "StatBucket", bucket, bucketArgs{DriveArg: r.da(), Bucket: bucket}, &res)
	return res.Exists, res.Created, err
}

// ListBuckets implements disk.Disk.
func (r *Remote) ListBuckets(ctx context.Context) ([]string, error) {
	var res namesRes
	err := r.call(ctx, "ListBuckets", "", r.da(), &res)
	return res.Names, err
}

// DeleteBucket implements disk.Disk.
func (r *Remote) DeleteBucket(ctx context.Context, bucket string) error {
	return r.call(ctx, "DeleteBucket", bucket, bucketArgs{DriveArg: r.da(), Bucket: bucket}, nil)
}

// ListKeys implements disk.Disk.
func (r *Remote) ListKeys(ctx context.Context, bucket, prefix string) ([]string, error) {
	var res namesRes
	err := r.callT(ctx, r.opt.DataTimeout, "ListKeys", bucket, listKeysArgs{r.da(), bucket, prefix}, &res)
	return res.Names, err
}

// ReadMeta implements disk.Disk.
func (r *Remote) ReadMeta(ctx context.Context, bucket, object string) ([]byte, error) {
	var res bytesRes
	err := r.call(ctx, "ReadMeta", objPath(bucket, object), r.obj(bucket, object, "", 0), &res)
	return res.Data, err
}

// remoteShard reads a shard file with one RPC per ReadAt, bound to the
// context its OpenShard was given.
type remoteShard struct {
	r    *Remote
	ctx  context.Context
	args objArgs
	size int64
}

func (s *remoteShard) Size() int64  { return s.size }
func (s *remoteShard) Close() error { return nil }

func (s *remoteShard) ReadAt(p []byte, off int64) (int, error) {
	total := 0
	for total < len(p) {
		n := min(len(p)-total, maxRead)
		data, err := s.r.raw(s.ctx, "ReadAt", objPath(s.args.Bucket, s.args.Object), struct {
			objArgs
			Off int64 `json:"off"`
			Len int   `json:"len"`
		}{s.args, off + int64(total), n}, nil)
		if err != nil {
			return total, err
		}
		copy(p[total:], data)
		total += len(data)
		if len(data) < n {
			return total, io.EOF
		}
	}
	return total, nil
}

// OpenShard implements disk.Disk.
func (r *Remote) OpenShard(ctx context.Context, bucket, object, dataDir string, part int) (disk.Shard, error) {
	size, err := r.StatShard(ctx, bucket, object, dataDir, part)
	if err != nil {
		return nil, err
	}
	return &remoteShard{r: r, ctx: ctx, args: r.obj(bucket, object, dataDir, part), size: size}, nil
}

// StatShard implements disk.Disk.
func (r *Remote) StatShard(ctx context.Context, bucket, object, dataDir string, part int) (int64, error) {
	var res sizeRes
	err := r.call(ctx, "StatShard", objPath(bucket, object), r.obj(bucket, object, dataDir, part), &res)
	return res.Size, err
}

// VerifyShard implements disk.Disk. The drive reads the file itself; only
// the root crosses the network.
func (r *Remote) VerifyShard(ctx context.Context, bucket, object, dataDir string, part int, partSize, blockSize int64, dataBlocks int) (string, error) {
	var res rootRes
	err := r.callT(ctx, r.opt.DataTimeout, "VerifyShard", objPath(bucket, object),
		verifyArgs{r.obj(bucket, object, dataDir, part), partSize, blockSize, dataBlocks}, &res)
	return res.Root, err
}

// PinData implements disk.Disk. A background keepalive holds the server's
// lease open for as long as the pin is wanted.
func (r *Remote) PinData(ctx context.Context, bucket, object, dataDir string) (func(), error) {
	var res handleRes
	if err := r.call(ctx, "PinData", objPath(bucket, object), r.obj(bucket, object, dataDir, 0), &res); err != nil {
		return nil, err
	}
	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(r.opt.Lease / 3)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				r.call(context.Background(), "PinTouch", "", handleArgs{r.da(), res.Handle}, nil)
			}
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			close(stop)
			dctx, cancel := r.detached(context.Background())
			defer cancel()
			r.call(dctx, "Unpin", "", handleArgs{r.da(), res.Handle}, nil)
		})
	}, nil
}

// DeleteObject implements disk.Disk.
func (r *Remote) DeleteObject(ctx context.Context, bucket, object string) error {
	return r.call(ctx, "DeleteObject", objPath(bucket, object), r.obj(bucket, object, "", 0), nil)
}

// remoteWriter buffers a staged file and appends it in chunks; its appends
// are bound to the context CreateStageFile was given.
type remoteWriter struct {
	r      *Remote
	ctx    context.Context
	handle string
	buf    []byte
	sent   int64
	err    error
	done   bool
}

func (w *remoteWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	w.buf = append(w.buf, p...)
	if len(w.buf) >= w.r.opt.ChunkSize {
		if err := w.flush(); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func (w *remoteWriter) flush() error {
	if len(w.buf) == 0 || w.err != nil {
		return w.err
	}
	_, err := w.r.raw(w.ctx, "StageAppend", "", struct {
		Handle string `json:"handle"`
		Offset int64  `json:"offset"`
	}{w.handle, w.sent}, w.buf)
	if err != nil {
		w.err = err
		return err
	}
	w.sent += int64(len(w.buf))
	w.buf = w.buf[:0]
	return nil
}

func (w *remoteWriter) abort() {
	dctx, cancel := w.r.detached(w.ctx)
	defer cancel()
	w.r.call(dctx, "StageAbort", "", handleArgs{w.r.da(), w.handle}, nil)
}

func (w *remoteWriter) Close() error {
	if w.done {
		return nil
	}
	w.done = true
	if err := w.flush(); err != nil {
		w.abort()
		return err
	}
	return w.r.call(w.ctx, "StageClose", "", handleArgs{w.r.da(), w.handle}, nil)
}

func (w *remoteWriter) Abort() {
	if w.done {
		return
	}
	w.done = true
	w.abort()
}

// CreateStageFile implements disk.Disk.
func (r *Remote) CreateStageFile(ctx context.Context, stageID, rel string) (disk.FileWriter, error) {
	var res handleRes
	if err := r.call(ctx, "CreateStageFile", stageID, stageCreateArgs{r.da(), stageID, rel}, &res); err != nil {
		return nil, err
	}
	return &remoteWriter{r: r, ctx: ctx, handle: res.Handle}, nil
}

// RemoveStage implements disk.Disk.
func (r *Remote) RemoveStage(ctx context.Context, stageID string) error {
	return r.call(ctx, "RemoveStage", stageID, stageArgs{r.da(), stageID}, nil)
}

type remoteCommit struct {
	r      *Remote
	handle string
	once   sync.Once
}

func (c *remoteCommit) Rollback(ctx context.Context) error {
	var err error
	c.once.Do(func() { err = c.r.call(ctx, "CommitRollback", "", handleArgs{c.r.da(), c.handle}, nil) })
	return err
}

func (c *remoteCommit) Finish(ctx context.Context) error {
	var err error
	c.once.Do(func() { err = c.r.call(ctx, "CommitFinish", "", handleArgs{c.r.da(), c.handle}, nil) })
	return err
}

// CommitObject implements disk.Disk.
func (r *Remote) CommitObject(ctx context.Context, req disk.CommitRequest) (disk.Commit, error) {
	var res handleRes
	if err := r.call(ctx, "CommitObject", objPath(req.Bucket, req.Object), commitArgs{r.da(), req}, &res); err != nil {
		return nil, err
	}
	return &remoteCommit{r: r, handle: res.Handle}, nil
}

// LinkPartIntoStage implements disk.Disk.
func (r *Remote) LinkPartIntoStage(ctx context.Context, bucket, uploadID, partFile, stageID, rel string) error {
	return r.call(ctx, "LinkPartIntoStage", bucket, linkArgs{r.da(), bucket, uploadID, partFile, stageID, rel}, nil)
}

// CreateUpload implements disk.Disk.
func (r *Remote) CreateUpload(ctx context.Context, bucket, uploadID string, doc []byte) error {
	return r.call(ctx, "CreateUpload", bucket, uploadArgs{DriveArg: r.da(), Bucket: bucket, UploadID: uploadID, Doc: doc}, nil)
}

// ReadUpload implements disk.Disk.
func (r *Remote) ReadUpload(ctx context.Context, bucket, uploadID string) ([]byte, error) {
	var res bytesRes
	err := r.call(ctx, "ReadUpload", bucket, uploadArgs{DriveArg: r.da(), Bucket: bucket, UploadID: uploadID}, &res)
	return res.Data, err
}

// ListUploadIDs implements disk.Disk.
func (r *Remote) ListUploadIDs(ctx context.Context, bucket string) ([]string, error) {
	var res idsRes
	err := r.call(ctx, "ListUploadIDs", bucket, uploadArgs{DriveArg: r.da(), Bucket: bucket}, &res)
	return res.IDs, err
}

// ListParts implements disk.Disk.
func (r *Remote) ListParts(ctx context.Context, bucket, uploadID string) ([]disk.PartRecord, error) {
	var res partsRes
	err := r.call(ctx, "ListParts", bucket, uploadArgs{DriveArg: r.da(), Bucket: bucket, UploadID: uploadID}, &res)
	return res.Parts, err
}

// CommitPart implements disk.Disk.
func (r *Remote) CommitPart(ctx context.Context, pc disk.PartCommit) (disk.Commit, error) {
	var res handleRes
	if err := r.call(ctx, "CommitPart", pc.Bucket, partCommitArgs{r.da(), pc}, &res); err != nil {
		return nil, err
	}
	return &remoteCommit{r: r, handle: res.Handle}, nil
}

// DiscardUpload implements disk.Disk.
func (r *Remote) DiscardUpload(ctx context.Context, bucket, uploadID string) error {
	return r.call(ctx, "DiscardUpload", bucket, uploadArgs{DriveArg: r.da(), Bucket: bucket, UploadID: uploadID}, nil)
}

// SweepStaging implements disk.Disk.
func (r *Remote) SweepStaging(ctx context.Context, maxAge time.Duration) (int, error) {
	var res countRes
	err := r.call(ctx, "SweepStaging", "", sweepArgs{r.da(), int64(maxAge)}, &res)
	return res.N, err
}

// StaleUploads implements disk.Disk.
func (r *Remote) StaleUploads(ctx context.Context, maxAge time.Duration) ([]disk.StaleUpload, error) {
	var res staleRes
	err := r.call(ctx, "StaleUploads", "", sweepArgs{r.da(), int64(maxAge)}, &res)
	return res.Uploads, err
}

// DiscardUploadIfStale implements disk.Disk.
func (r *Remote) DiscardUploadIfStale(ctx context.Context, bucket, uploadID string, maxAge time.Duration) (bool, error) {
	var res okRes
	err := r.call(ctx, "DiscardUploadIfStale", bucket,
		uploadArgs{DriveArg: r.da(), Bucket: bucket, UploadID: uploadID, MaxAgeNs: int64(maxAge)}, &res)
	return res.OK, err
}

// FindOrphans implements disk.Disk.
func (r *Remote) FindOrphans(ctx context.Context, bucket string) ([]disk.Orphan, error) {
	var res orphansRes
	err := r.callT(ctx, r.opt.DataTimeout, "FindOrphans", bucket, bucketArgs{DriveArg: r.da(), Bucket: bucket}, &res)
	return res.Orphans, err
}

// RemoveOrphans implements disk.Disk.
func (r *Remote) RemoveOrphans(ctx context.Context, bucket, object string, dataDirs []string) (int, error) {
	var res countRes
	err := r.call(ctx, "RemoveOrphans", objPath(bucket, object), removeOrphansArgs{r.da(), bucket, object, dataDirs}, &res)
	return res.N, err
}
