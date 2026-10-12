package xl

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"nanoio/internal/storage"
	"nanoio/internal/storage/xl/disk"
)

// ctxReader fails reads once ctx is done.
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

// shardWriter appends [hash][shard] records to one staged shard file and
// keeps a running hash over the record hashes, which is stored in xl.meta as
// the file's checksum root.
//
// Writing is asynchronous: blocks are queued to a goroutine that owns the
// file, so one slow drive does not hold up the others block by block. A
// writer that falls too far behind is evicted (while enough others remain),
// and one that is still unfinished after the write quorum has been reached
// is evicted too; its object is then repaired by heal instead of waited for.
// Only the writer's goroutine touches the FileWriter.
type shardWriter struct {
	in      chan []byte
	done    chan struct{}
	evicted atomic.Bool
	closed  bool // main goroutine only: in has been closed

	mu   sync.Mutex
	err  error  // sticky first failure
	root string // valid once done is closed and err is nil
}

// newShardWriter stages the file rel under stageID on d and starts its
// writer goroutine. queue is how many blocks may wait for the drive.
func newShardWriter(ctx context.Context, d disk.Disk, stageID, rel string, queue int) (*shardWriter, error) {
	fw, err := d.CreateStageFile(ctx, stageID, rel)
	if err != nil {
		return nil, err
	}
	if queue < 1 {
		queue = 1
	}
	w := &shardWriter{in: make(chan []byte, queue), done: make(chan struct{})}
	go w.run(fw)
	return w, nil
}

func (w *shardWriter) fail(err error) {
	w.mu.Lock()
	if w.err == nil {
		w.err = err
	}
	w.mu.Unlock()
}

func (w *shardWriter) firstErr() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.err
}

func (w *shardWriter) run(fw disk.FileWriter) {
	defer close(w.done)
	bw := bufio.NewWriterSize(fw, 256<<10)
	root := sha256.New()
	for shard := range w.in {
		if w.evicted.Load() || w.firstErr() != nil {
			continue // drain: the sender must never block on a dead writer
		}
		sum := sha256.Sum256(shard)
		if _, err := bw.Write(sum[:]); err != nil {
			w.fail(err)
			continue
		}
		if _, err := bw.Write(shard); err != nil {
			w.fail(err)
			continue
		}
		root.Write(sum[:])
	}
	if w.evicted.Load() || w.firstErr() != nil {
		fw.Abort()
		w.fail(errEvicted) // no-op if a real error is already recorded
		return
	}
	if err := bw.Flush(); err != nil {
		fw.Abort()
		w.fail(err)
		return
	}
	if err := fw.Close(); err != nil {
		w.fail(err)
		return
	}
	w.mu.Lock()
	w.root = hex.EncodeToString(root.Sum(nil))
	w.mu.Unlock()
}

var errEvicted = errors.New("shard writer evicted")

// failed reports whether the writer can no longer produce a good file.
func (w *shardWriter) failed() bool { return w.evicted.Load() || w.firstErr() != nil }

// enqueue hands a block to the writer. A full queue is waited out: the
// producer is memory-speed and every drive is slower than it, so a full
// queue alone proves nothing. With droppable set the wait is bounded by
// stall; a writer that has made no room by then is evicted (the caller has
// quorum to spare). The block must not be reused by the caller.
func (w *shardWriter) enqueue(ctx context.Context, b []byte, droppable bool, stall time.Duration) {
	select {
	case w.in <- b:
		return
	default:
	}
	var timeout <-chan time.Time
	if droppable {
		t := time.NewTimer(stall)
		defer t.Stop()
		timeout = t.C
	}
	select {
	case w.in <- b:
	case <-timeout:
		w.evict()
	case <-ctx.Done():
		w.evict()
	}
}

func (w *shardWriter) closeInput() {
	if !w.closed {
		w.closed = true
		close(w.in)
	}
}

// evict abandons the writer: its file is aborted once its goroutine is done
// with the call in flight.
func (w *shardWriter) evict() {
	w.evicted.Store(true)
	w.closeInput()
}

// abort is evict, kept for call sites that mean "discard".
func (w *shardWriter) abort() { w.evict() }

// result is valid after done is closed.
func (w *shardWriter) result() (root string, ok bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.root, w.err == nil && !w.evicted.Load()
}

// wait closes the input and blocks until the file is durable or failed.
func (w *shardWriter) wait(ctx context.Context) (string, error) {
	w.closeInput()
	select {
	case <-w.done:
	case <-ctx.Done():
		w.evict()
		return "", ctx.Err()
	}
	root, ok := w.result()
	if !ok {
		if err := w.firstErr(); err != nil {
			return "", err
		}
		return "", errEvicted
	}
	return root, nil
}

// errQuorumLost means too many shard writers failed to reach write quorum.
var errQuorumLost = errors.New("write quorum lost while streaming")

// encodeStream reads r (exactly size bytes, or to EOF if size < 0), erasure
// codes it block by block and appends shard i of every block to ws[i].
// Writers that fail are aborted and set to nil; if fewer than minLive
// remain, encoding stops. md5h and shah (optional) see the plaintext. It
// returns the plaintext byte count.
func (x *XL) encodeStream(ctx context.Context, r io.Reader, size, blockSize int64, ws []*shardWriter,
	minLive int, md5h, shah hash.Hash) (int64, error) {
	src := io.Reader(ctxReader{ctx, r})
	if size >= 0 {
		src = io.LimitReader(src, size)
	}
	buf := make([]byte, blockSize)
	var total int64
	for {
		n, rerr := io.ReadFull(src, buf)
		if n > 0 {
			md5h.Write(buf[:n])
			if shah != nil {
				shah.Write(buf[:n])
			}
			total += int64(n)
			shards, err := x.enc.Split(buf[:n])
			if err != nil {
				return total, err
			}
			if err := x.enc.Encode(shards); err != nil {
				return total, err
			}
			if live := x.queueShards(ctx, ws, shards, minLive); live < minLive {
				return total, errQuorumLost
			}
		}
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			return total, nil
		}
		if rerr != nil {
			return total, rerr
		}
	}
}

// queueShards hands shard i to ws[i] without waiting for the drives, and
// returns how many writers are still healthy. Failed writers are evicted and
// nilled; a writer whose queue is full is evicted too as long as at least
// minLive others remain, otherwise it is waited for.
func (x *XL) queueShards(ctx context.Context, ws []*shardWriter, shards [][]byte, minLive int) int {
	live := 0
	for i, w := range ws {
		if w == nil {
			continue
		}
		if w.failed() {
			w.evict()
			ws[i] = nil
			continue
		}
		live++
	}
	for i, w := range ws {
		if w == nil {
			continue
		}
		cp := make([]byte, len(shards[i]))
		copy(cp, shards[i])
		w.enqueue(ctx, cp, live-1 >= minLive, x.stallTimeout)
		if w.failed() { // evicted for lagging
			ws[i] = nil
			live--
		}
	}
	return live
}

func quorumError(bucket, object string, got, need int, errs []error) error {
	// Enough drives refusing because object lock protects the version to
	// make a quorum impossible is a refusal, not an outage.
	locked := 0
	for _, e := range errs {
		if e != nil && errors.Is(e, storage.ErrObjectLocked) {
			locked++
		}
	}
	if locked > 0 && locked > len(errs)-need {
		return storage.Wrap(fmt.Errorf("%w: refused by %d drives", storage.ErrObjectLocked, locked), bucket, object)
	}
	detail := ""
	shown := 0
	for i, e := range errs {
		if e == nil || shown == 3 {
			continue
		}
		detail += fmt.Sprintf("; drive %d: %v", i, e)
		shown++
	}
	return storage.Wrap(fmt.Errorf("%w: write quorum not met (%d of %d drives)%s",
		storage.ErrBackendUnavailable, got, need, detail), bucket, object)
}
