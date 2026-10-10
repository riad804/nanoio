// Package remote carries disk.Disk over the inter-node RPC layer.
//
// A Server exposes a node's local disks; Remote is the client-side Disk
// that forwards each operation as one RPC. Stateful objects (open stage
// writers, uncommitted commits, data pins) live in server-side handle
// tables with idle leases, so a client that crashes leaks nothing for long:
// writers are aborted, pins released and staging areas dropped, and a
// commit that was never finished or rolled back is left published, which is
// exactly the indeterminate state quorum logic and the scanner already
// handle.
package remote

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"nanoio/internal/cluster/rpc"
	"nanoio/internal/storage/xl/disk"
)

// DefaultLease is how long an idle server-side handle survives.
const DefaultLease = 15 * time.Minute

// maxRead bounds one shard read RPC.
const maxRead = 8 << 20

// DriveArg names the drive an operation applies to.
type DriveArg struct {
	Drive string `json:"drive"`
}

func (a DriveArg) driveID() string { return a.Drive }

type drived interface{ driveID() string }

// Server serves a node's local disks.
type Server struct {
	disks map[string]disk.Disk
	lease time.Duration
	now   func() time.Time

	mu      sync.Mutex
	commits map[string]*commitEntry
	writers map[string]*writerEntry
	pins    map[string]*pinEntry
	stages  map[string]*stageEntry
	stop    chan struct{}
	done    chan struct{}
}

type commitEntry struct {
	c    disk.Commit
	last time.Time
}

type writerEntry struct {
	w       disk.FileWriter
	written int64
	last    time.Time
	stage   string
}

type pinEntry struct {
	release func()
	last    time.Time
}

type stageEntry struct {
	d    disk.Disk
	last time.Time
}

// NewServer returns a Server over disks, keyed by drive ID (the drive's
// configured path). lease <= 0 means DefaultLease.
func NewServer(disks map[string]disk.Disk, lease time.Duration) *Server {
	if lease <= 0 {
		lease = DefaultLease
	}
	s := &Server{disks: disks, lease: lease, now: time.Now,
		commits: map[string]*commitEntry{}, writers: map[string]*writerEntry{},
		pins: map[string]*pinEntry{}, stages: map[string]*stageEntry{},
		stop: make(chan struct{}), done: make(chan struct{})}
	go s.janitor()
	return s
}

// Close stops the janitor and releases every outstanding handle.
func (s *Server) Close() {
	select {
	case <-s.stop:
		return
	default:
	}
	close(s.stop)
	<-s.done
	s.expire(time.Time{}.Add(1<<62), true)
}

func (s *Server) janitor() {
	defer close(s.done)
	period := s.lease / 4
	if period < 10*time.Millisecond {
		period = 10 * time.Millisecond
	}
	t := time.NewTicker(period)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			s.expire(s.now().Add(-s.lease), false)
		}
	}
}

// expire drops handles idle since before cutoff. With all set it drops
// every handle.
func (s *Server) expire(cutoff time.Time, all bool) {
	var releases []func()
	var removeStage []stageEntry
	var stageIDs []string
	s.mu.Lock()
	for id, c := range s.commits {
		if all || c.last.Before(cutoff) {
			delete(s.commits, id)
		}
	}
	for id, w := range s.writers {
		if all || w.last.Before(cutoff) {
			delete(s.writers, id)
			releases = append(releases, w.w.Abort)
		}
	}
	for id, p := range s.pins {
		if all || p.last.Before(cutoff) {
			delete(s.pins, id)
			releases = append(releases, p.release)
		}
	}
	for id, st := range s.stages {
		if all || st.last.Before(cutoff) {
			delete(s.stages, id)
			removeStage = append(removeStage, *st)
			stageIDs = append(stageIDs, id)
		}
	}
	s.mu.Unlock()
	for _, f := range releases {
		f()
	}
	if len(removeStage) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		for i, st := range removeStage {
			_, id, _ := splitStageKey(stageIDs[i])
			st.d.RemoveStage(ctx, id)
		}
	}
}

func stageKey(drive, stage string) string { return drive + "\x00" + stage }

func splitStageKey(k string) (drive, stage string, ok bool) {
	for i := 0; i < len(k); i++ {
		if k[i] == 0 {
			return k[:i], k[i+1:], true
		}
	}
	return "", k, false
}

func (s *Server) touchStage(drive, stage string, d disk.Disk) {
	s.mu.Lock()
	s.stages[stageKey(drive, stage)] = &stageEntry{d: d, last: s.now()}
	s.mu.Unlock()
}

func (s *Server) dropStage(drive, stage string) {
	s.mu.Lock()
	delete(s.stages, stageKey(drive, stage))
	s.mu.Unlock()
}

func newID() string {
	var b [16]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// EncodeError maps an application error to an HTTP status and a wire code.
// The code is the disk.Kind, which is all that crosses the wire; the
// message travels alongside for diagnostics only.
func EncodeError(err error) (int, string) {
	var de *disk.Error
	if !errors.As(err, &de) {
		de, _ = disk.Wrap("", "", err).(*disk.Error)
	}
	status := http.StatusInternalServerError
	switch de.Kind {
	case disk.KindOffline, disk.KindCanceled:
		status = http.StatusServiceUnavailable
	case disk.KindNotFound:
		status = http.StatusNotFound
	case disk.KindUnformatted, disk.KindForeign, disk.KindInUse, disk.KindConflict:
		status = http.StatusConflict
	case disk.KindDiskFull:
		status = http.StatusInsufficientStorage
	}
	return status, "k" + strconv.Itoa(int(de.Kind))
}

// decodeError rebuilds the typed error on the client: a bare *disk.Error of
// the transmitted Kind (so errors.Is against the sentinels works exactly as
// for a local drive), with the remote message kept as its cause text.
func decodeError(op string, e *rpc.Error) error {
	kind := disk.KindIO
	switch {
	case strings.HasPrefix(e.Code, "k"):
		if n, err := strconv.Atoi(e.Code[1:]); err == nil && n >= 0 && n <= 255 {
			kind = disk.Kind(n)
		}
	case e.Code == "denied":
		kind = disk.KindOffline // an unauthenticated peer is as good as gone
	}
	return &disk.Error{Kind: kind, Op: op, Err: errors.New(e.Msg)}
}

func (s *Server) disk(a drived) (disk.Disk, error) {
	d := s.disks[a.driveID()]
	if d == nil {
		return nil, fmt.Errorf("%w: no drive %q on this node", disk.ErrOffline, a.driveID())
	}
	return d, nil
}

// reg registers a typed JSON operation.
func reg[A drived, R any](s *Server, rs *rpc.Server, op string, f func(ctx context.Context, d disk.Disk, a A) (R, error)) {
	rs.Handle("disk."+op, rpc.JSON(func(ctx context.Context, _ string, a A) (R, error) {
		var zero R
		d, err := s.disk(a)
		if err != nil {
			return zero, err
		}
		return f(ctx, d, a)
	}))
}

type empty struct{}

// Argument and result documents.
type (
	openArgs struct {
		DriveArg
		Create bool `json:"create"`
	}
	formatRes struct {
		Format *disk.Format `json:"format,omitempty"`
	}
	formatArgs struct {
		DriveArg
		Format disk.Format `json:"format"`
	}
	readyRes struct {
		Ready bool `json:"ready"`
	}
	infoRes struct {
		Total uint64 `json:"total"`
		Free  uint64 `json:"free"`
	}
	bucketArgs struct {
		DriveArg
		Bucket  string    `json:"bucket"`
		Created time.Time `json:"created,omitempty"`
	}
	madeRes struct {
		Made bool `json:"made"`
	}
	statBucketRes struct {
		Exists  bool      `json:"exists"`
		Created time.Time `json:"created"`
	}
	namesRes struct {
		Names []string `json:"names"`
	}
	listKeysArgs struct {
		DriveArg
		Bucket string `json:"bucket"`
		Prefix string `json:"prefix"`
	}
	objArgs struct {
		DriveArg
		Bucket  string `json:"bucket"`
		Object  string `json:"object"`
		DataDir string `json:"dataDir,omitempty"`
		Part    int    `json:"part,omitempty"`
	}
	bytesRes struct {
		Data []byte `json:"data"`
	}
	sizeRes struct {
		Size int64 `json:"size"`
	}
	verifyArgs struct {
		objArgs
		PartSize   int64 `json:"partSize"`
		BlockSize  int64 `json:"blockSize"`
		DataBlocks int   `json:"dataBlocks"`
	}
	rootRes struct {
		Root string `json:"root"`
	}
	handleArgs struct {
		DriveArg
		Handle string `json:"handle"`
	}
	handleRes struct {
		Handle string `json:"handle"`
	}
	stageCreateArgs struct {
		DriveArg
		Stage string `json:"stage"`
		Rel   string `json:"rel"`
	}
	stageArgs struct {
		DriveArg
		Stage string `json:"stage"`
	}
	commitArgs struct {
		DriveArg
		Req disk.CommitRequest `json:"req"`
	}
	linkArgs struct {
		DriveArg
		Bucket   string `json:"bucket"`
		UploadID string `json:"uploadId"`
		PartFile string `json:"partFile"`
		Stage    string `json:"stage"`
		Rel      string `json:"rel"`
	}
	uploadArgs struct {
		DriveArg
		Bucket   string `json:"bucket"`
		UploadID string `json:"uploadId"`
		Doc      []byte `json:"doc,omitempty"`
		MaxAgeNs int64  `json:"maxAgeNs,omitempty"`
	}
	idsRes struct {
		IDs []string `json:"ids"`
	}
	partsRes struct {
		Parts []disk.PartRecord `json:"parts"`
	}
	partCommitArgs struct {
		DriveArg
		PC disk.PartCommit `json:"pc"`
	}
	sweepArgs struct {
		DriveArg
		MaxAgeNs int64 `json:"maxAgeNs"`
	}
	countRes struct {
		N int `json:"n"`
	}
	staleRes struct {
		Uploads []disk.StaleUpload `json:"uploads"`
	}
	okRes struct {
		OK bool `json:"ok"`
	}
	orphansRes struct {
		Orphans []disk.Orphan `json:"orphans"`
	}
	removeOrphansArgs struct {
		DriveArg
		Bucket  string   `json:"bucket"`
		Object  string   `json:"object"`
		DataDir []string `json:"dataDirs"`
	}
)

// Register installs every disk operation on rs.
func (s *Server) Register(rs *rpc.Server) {
	reg(s, rs, "open", func(ctx context.Context, d disk.Disk, a openArgs) (formatRes, error) {
		f, err := d.Open(ctx, a.Create)
		return formatRes{Format: f}, err
	})
	reg(s, rs, "writeformat", func(ctx context.Context, d disk.Disk, a formatArgs) (empty, error) {
		f := a.Format
		return empty{}, d.WriteFormat(ctx, &f)
	})
	reg(s, rs, "ready", func(ctx context.Context, d disk.Disk, a DriveArg) (readyRes, error) {
		return readyRes{d.Ready(ctx)}, nil
	})
	reg(s, rs, "info", func(ctx context.Context, d disk.Disk, a DriveArg) (infoRes, error) {
		i, err := d.Info(ctx)
		return infoRes{i.Total, i.Free}, err
	})
	reg(s, rs, "bucket.make", func(ctx context.Context, d disk.Disk, a bucketArgs) (madeRes, error) {
		m, err := d.MakeBucket(ctx, a.Bucket, a.Created)
		return madeRes{m}, err
	})
	reg(s, rs, "bucket.stat", func(ctx context.Context, d disk.Disk, a bucketArgs) (statBucketRes, error) {
		e, c, err := d.StatBucket(ctx, a.Bucket)
		return statBucketRes{e, c}, err
	})
	reg(s, rs, "bucket.list", func(ctx context.Context, d disk.Disk, a DriveArg) (namesRes, error) {
		n, err := d.ListBuckets(ctx)
		return namesRes{n}, err
	})
	reg(s, rs, "bucket.delete", func(ctx context.Context, d disk.Disk, a bucketArgs) (empty, error) {
		return empty{}, d.DeleteBucket(ctx, a.Bucket)
	})
	rs.Handle("disk.keys", rpc.JSON(func(ctx context.Context, _ string, a listKeysArgs) (namesRes, error) {
		d, err := s.disk(a)
		if err != nil {
			return namesRes{}, err
		}
		n, err := d.ListKeys(ctx, a.Bucket, a.Prefix)
		return namesRes{n}, err
	}))
	reg(s, rs, "meta.read", func(ctx context.Context, d disk.Disk, a objArgs) (bytesRes, error) {
		b, err := d.ReadMeta(ctx, a.Bucket, a.Object)
		return bytesRes{b}, err
	})
	reg(s, rs, "shard.stat", func(ctx context.Context, d disk.Disk, a objArgs) (sizeRes, error) {
		n, err := d.StatShard(ctx, a.Bucket, a.Object, a.DataDir, a.Part)
		return sizeRes{n}, err
	})
	reg(s, rs, "shard.verify", func(ctx context.Context, d disk.Disk, a verifyArgs) (rootRes, error) {
		r, err := d.VerifyShard(ctx, a.Bucket, a.Object, a.DataDir, a.Part, a.PartSize, a.BlockSize, a.DataBlocks)
		return rootRes{r}, err
	})
	// Raw: args in the header, payload as the response body.
	rs.Handle("disk.shard.read", func(ctx context.Context, _ string, args, _ []byte) ([]byte, error) {
		var a struct {
			objArgs
			Off int64 `json:"off"`
			Len int   `json:"len"`
		}
		if err := json.Unmarshal(args, &a); err != nil {
			return nil, err
		}
		d, err := s.disk(a.objArgs)
		if err != nil {
			return nil, err
		}
		if a.Len < 0 || a.Len > maxRead {
			return nil, fmt.Errorf("read length %d outside 0..%d", a.Len, maxRead)
		}
		sh, err := d.OpenShard(ctx, a.Bucket, a.Object, a.DataDir, a.Part)
		if err != nil {
			return nil, err
		}
		defer sh.Close()
		buf := make([]byte, a.Len)
		n, err := sh.ReadAt(buf, a.Off)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		return buf[:n], nil
	})
	reg(s, rs, "pin", func(ctx context.Context, d disk.Disk, a objArgs) (handleRes, error) {
		id := newID()
		rel, err := d.PinData(ctx, a.Bucket, a.Object, a.DataDir)
		if err != nil {
			return handleRes{}, err
		}
		s.mu.Lock()
		s.pins[id] = &pinEntry{release: rel, last: s.now()}
		s.mu.Unlock()
		return handleRes{id}, nil
	})
	reg(s, rs, "pin.touch", func(ctx context.Context, d disk.Disk, a handleArgs) (okRes, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		p := s.pins[a.Handle]
		if p == nil {
			return okRes{false}, nil
		}
		p.last = s.now()
		return okRes{true}, nil
	})
	reg(s, rs, "unpin", func(ctx context.Context, d disk.Disk, a handleArgs) (empty, error) {
		s.mu.Lock()
		p := s.pins[a.Handle]
		delete(s.pins, a.Handle)
		s.mu.Unlock()
		if p != nil {
			p.release()
		}
		return empty{}, nil
	})
	reg(s, rs, "object.delete", func(ctx context.Context, d disk.Disk, a objArgs) (empty, error) {
		return empty{}, d.DeleteObject(ctx, a.Bucket, a.Object)
	})

	reg(s, rs, "stage.create", func(ctx context.Context, d disk.Disk, a stageCreateArgs) (handleRes, error) {
		w, err := d.CreateStageFile(ctx, a.Stage, a.Rel)
		if err != nil {
			return handleRes{}, err
		}
		id := newID()
		s.mu.Lock()
		s.writers[id] = &writerEntry{w: w, last: s.now(), stage: stageKey(a.Drive, a.Stage)}
		s.mu.Unlock()
		s.touchStage(a.Drive, a.Stage, d)
		return handleRes{id}, nil
	})
	rs.Handle("disk.stage.append", func(_ context.Context, _ string, args, body []byte) ([]byte, error) {
		var a struct {
			Handle string `json:"handle"`
			Offset int64  `json:"offset"`
		}
		if err := json.Unmarshal(args, &a); err != nil {
			return nil, err
		}
		s.mu.Lock()
		w := s.writers[a.Handle]
		if w != nil {
			w.last = s.now()
		}
		s.mu.Unlock()
		if w == nil {
			return nil, fmt.Errorf("%w: unknown or expired write handle", disk.ErrNotFound)
		}
		if a.Offset != w.written {
			return nil, fmt.Errorf("append at %d but %d bytes are written", a.Offset, w.written)
		}
		n, err := w.w.Write(body)
		w.written += int64(n)
		return nil, err
	})
	closeWriter := func(abort bool) func(ctx context.Context, d disk.Disk, a handleArgs) (empty, error) {
		return func(ctx context.Context, d disk.Disk, a handleArgs) (empty, error) {
			s.mu.Lock()
			w := s.writers[a.Handle]
			delete(s.writers, a.Handle)
			s.mu.Unlock()
			if w == nil {
				if abort {
					return empty{}, nil
				}
				return empty{}, fmt.Errorf("%w: unknown or expired write handle", disk.ErrNotFound)
			}
			if abort {
				w.w.Abort()
				return empty{}, nil
			}
			return empty{}, w.w.Close()
		}
	}
	reg(s, rs, "stage.close", closeWriter(false))
	reg(s, rs, "stage.abort", closeWriter(true))
	reg(s, rs, "stage.remove", func(ctx context.Context, d disk.Disk, a stageArgs) (empty, error) {
		d.RemoveStage(ctx, a.Stage)
		s.dropStage(a.Drive, a.Stage)
		return empty{}, nil
	})
	reg(s, rs, "commit", func(ctx context.Context, d disk.Disk, a commitArgs) (handleRes, error) {
		c, err := d.CommitObject(ctx, a.Req)
		if err != nil {
			return handleRes{}, err
		}
		return handleRes{s.addCommit(c)}, nil
	})
	finish := func(roll bool) func(ctx context.Context, d disk.Disk, a handleArgs) (empty, error) {
		return func(ctx context.Context, d disk.Disk, a handleArgs) (empty, error) {
			s.mu.Lock()
			c := s.commits[a.Handle]
			delete(s.commits, a.Handle)
			s.mu.Unlock()
			if c == nil {
				return empty{}, nil // already settled, or the lease expired
			}
			if roll {
				return empty{}, c.c.Rollback(ctx)
			}
			return empty{}, c.c.Finish(ctx)
		}
	}
	reg(s, rs, "commit.finish", finish(false))
	reg(s, rs, "commit.rollback", finish(true))
	reg(s, rs, "link", func(ctx context.Context, d disk.Disk, a linkArgs) (empty, error) {
		err := d.LinkPartIntoStage(ctx, a.Bucket, a.UploadID, a.PartFile, a.Stage, a.Rel)
		if err == nil {
			s.touchStage(a.Drive, a.Stage, d)
		}
		return empty{}, err
	})

	reg(s, rs, "upload.create", func(ctx context.Context, d disk.Disk, a uploadArgs) (empty, error) {
		return empty{}, d.CreateUpload(ctx, a.Bucket, a.UploadID, a.Doc)
	})
	reg(s, rs, "upload.read", func(ctx context.Context, d disk.Disk, a uploadArgs) (bytesRes, error) {
		b, err := d.ReadUpload(ctx, a.Bucket, a.UploadID)
		return bytesRes{b}, err
	})
	reg(s, rs, "upload.ids", func(ctx context.Context, d disk.Disk, a uploadArgs) (idsRes, error) {
		ids, err := d.ListUploadIDs(ctx, a.Bucket)
		return idsRes{ids}, err
	})
	reg(s, rs, "upload.parts", func(ctx context.Context, d disk.Disk, a uploadArgs) (partsRes, error) {
		p, err := d.ListParts(ctx, a.Bucket, a.UploadID)
		return partsRes{p}, err
	})
	reg(s, rs, "upload.discard", func(ctx context.Context, d disk.Disk, a uploadArgs) (empty, error) {
		return empty{}, d.DiscardUpload(ctx, a.Bucket, a.UploadID)
	})
	reg(s, rs, "part.commit", func(ctx context.Context, d disk.Disk, a partCommitArgs) (handleRes, error) {
		c, err := d.CommitPart(ctx, a.PC)
		if err != nil {
			return handleRes{}, err
		}
		return handleRes{s.addCommit(c)}, nil
	})

	reg(s, rs, "sweep", func(ctx context.Context, d disk.Disk, a sweepArgs) (countRes, error) {
		n, err := d.SweepStaging(ctx, time.Duration(a.MaxAgeNs))
		return countRes{n}, err
	})
	reg(s, rs, "upload.stale", func(ctx context.Context, d disk.Disk, a sweepArgs) (staleRes, error) {
		u, err := d.StaleUploads(ctx, time.Duration(a.MaxAgeNs))
		return staleRes{u}, err
	})
	reg(s, rs, "upload.discardstale", func(ctx context.Context, d disk.Disk, a uploadArgs) (okRes, error) {
		ok, err := d.DiscardUploadIfStale(ctx, a.Bucket, a.UploadID, time.Duration(a.MaxAgeNs))
		return okRes{ok}, err
	})
	rs.Handle("disk.orphans", rpc.JSON(func(ctx context.Context, _ string, a bucketArgs) (orphansRes, error) {
		d, err := s.disk(a)
		if err != nil {
			return orphansRes{}, err
		}
		o, err := d.FindOrphans(ctx, a.Bucket)
		return orphansRes{o}, err
	}))
	reg(s, rs, "orphans.remove", func(ctx context.Context, d disk.Disk, a removeOrphansArgs) (countRes, error) {
		n, err := d.RemoveOrphans(ctx, a.Bucket, a.Object, a.DataDir)
		return countRes{n}, err
	})
}

func (s *Server) addCommit(c disk.Commit) string {
	id := newID()
	s.mu.Lock()
	s.commits[id] = &commitEntry{c: c, last: s.now()}
	s.mu.Unlock()
	return id
}
