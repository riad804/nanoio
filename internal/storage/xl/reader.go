package xl

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"

	"github.com/klauspost/reedsolomon"

	"nanoio/internal/meta"
	"nanoio/internal/storage"
	"nanoio/internal/storage/xl/disk"
)

// objectReader streams an object by fetching, verifying and decoding one
// erasure block at a time. It implements io.ReadSeekCloser and io.ReaderAt,
// so a ranged read decodes only the blocks it spans.
//
// For each block it reads the K data shards first; a shard that is missing
// or fails its hash is replaced by reading parity shards, and the data is
// reconstructed. Any damage it meets queues the object for healing.
type objectReader struct {
	x              *XL
	ctx            context.Context
	bucket, object string
	ver            *meta.Version
	byShard        []*drive // shard index -> drive holding it (agreeing drives only)
	dataDir        string
	parts          []meta.Part
	starts         []int64 // part start offsets
	blockSize      int64
	k, m           int
	enc            reedsolomon.Encoder
	size, pos      int64

	files   []disk.Shard // per shard index, for curPart
	curPart int

	blk     []byte
	blkPart int
	blkIdx  int64

	release func()
	damaged atomic.Bool
	closed  bool
}

// newObjectReader builds a reader over version v of the object, using the
// drives of st that agree on the version list. It pins their copies of v's
// data directory so a concurrent overwrite or delete defers their removal
// until the reader is closed.
func (x *XL) newObjectReader(ctx context.Context, bucket, object string, st *objState, v *meta.Version) (*objectReader, error) {
	e := v.Erasure
	if e == nil || e.ParityBlocks < 1 || e.DataBlocks < e.ParityBlocks ||
		e.DataBlocks+e.ParityBlocks != len(x.drives) || e.BlockSize <= 0 {
		return nil, storage.Wrap(fmt.Errorf("%w: object was written with an incompatible erasure layout", storage.ErrCorrupted), bucket, object)
	}
	enc, err := x.encoder(e.DataBlocks, e.ParityBlocks)
	if err != nil {
		return nil, err
	}
	r := &objectReader{
		x: x, ctx: ctx, bucket: bucket, object: object, ver: v, enc: enc,
		byShard: make([]*drive, e.DataBlocks+e.ParityBlocks),
		dataDir: v.DataDir, parts: v.Parts, blockSize: e.BlockSize, k: e.DataBlocks, m: e.ParityBlocks, size: v.Size,
		files: make([]disk.Shard, e.DataBlocks+e.ParityBlocks), curPart: -1, blkPart: -1, blkIdx: -1,
	}
	if len(r.parts) == 0 {
		r.parts = []meta.Part{{N: 1, Size: v.Size}}
	}
	var off int64
	for _, p := range r.parts {
		r.starts = append(r.starts, off)
		off += p.Size
	}
	if off != v.Size {
		return nil, storage.Wrap(fmt.Errorf("%w: parts total %d bytes, metadata says %d", storage.ErrCorrupted, off, v.Size), bucket, object)
	}
	var releases []func()
	for _, i := range st.agree {
		d := x.drives[i]
		// Each drive's own record of this version says which shard it holds.
		mine := st.metas[i].file.Find(v.VersionID)
		if mine == nil || mine.Erasure == nil {
			continue
		}
		idx := mine.Erasure.Index
		if idx < 0 || idx >= len(r.byShard) || r.byShard[idx] != nil {
			continue // inconsistent shard index: do not trust this drive
		}
		rel, err := d.PinData(ctx, bucket, object, v.DataDir)
		if err != nil {
			continue // no stable snapshot on this drive: read around it
		}
		r.byShard[idx] = d
		releases = append(releases, rel)
	}
	r.release = func() {
		for _, f := range releases {
			f()
		}
	}
	return r, nil
}

func (r *objectReader) Read(p []byte) (int, error) {
	if r.closed {
		return 0, os.ErrClosed
	}
	if r.pos >= r.size {
		return 0, io.EOF
	}
	n := 0
	for n < len(p) && r.pos < r.size {
		if err := r.ctx.Err(); err != nil {
			return n, err
		}
		partIdx := r.partOf(r.pos)
		inPart := r.pos - r.starts[partIdx]
		blockIdx := inPart / r.blockSize
		if r.blkPart != partIdx || r.blkIdx != blockIdx {
			if err := r.loadBlock(partIdx, blockIdx); err != nil {
				return n, err
			}
		}
		off := inPart - blockIdx*r.blockSize
		c := copy(p[n:], r.blk[off:])
		n += c
		r.pos += int64(c)
	}
	return n, nil
}

// partOf returns the index of the part containing off.
func (r *objectReader) partOf(off int64) int {
	lo, hi := 0, len(r.starts)-1
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if r.starts[mid] <= off {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return lo
}

func (r *objectReader) Seek(offset int64, whence int) (int64, error) {
	var abs int64
	switch whence {
	case io.SeekStart:
		abs = offset
	case io.SeekCurrent:
		abs = r.pos + offset
	case io.SeekEnd:
		abs = r.size + offset
	default:
		return 0, errors.New("xl: invalid whence")
	}
	if abs < 0 {
		return 0, errors.New("xl: negative position")
	}
	r.pos = abs
	return abs, nil
}

func (r *objectReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("xl: negative offset")
	}
	saved := r.pos
	defer func() { r.pos = saved }()
	r.pos = off
	n, err := io.ReadFull(r, p)
	if err == io.ErrUnexpectedEOF {
		err = io.EOF
	}
	return n, err
}

func (r *objectReader) Close() error {
	if r.closed {
		return nil
	}
	r.closed = true
	r.closeFiles()
	r.release()
	return nil
}

func (r *objectReader) closeFiles() {
	for i, f := range r.files {
		if f != nil {
			f.Close()
			r.files[i] = nil
		}
	}
}

var errShardMissing = errors.New("shard unavailable")

// readVerifiedShard reads shard block blockIdx (blockLen plaintext bytes
// long) from an open shard file and checks it against its stored hash.
func readVerifiedShard(f io.ReaderAt, blockIdx, blockLen, blockSize int64, k int) ([]byte, error) {
	sl := disk.ShardLen(blockLen, k)
	buf := make([]byte, disk.HashSize+sl)
	if _, err := f.ReadAt(buf, blockIdx*(disk.HashSize+disk.ShardLen(blockSize, k))); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(buf[disk.HashSize:])
	if !bytes.Equal(sum[:], buf[:disk.HashSize]) {
		return nil, fmt.Errorf("%w: block %d fails its hash", storage.ErrCorrupted, blockIdx)
	}
	return buf[disk.HashSize:], nil
}

// readShard fetches and verifies shard s of one block.
func (r *objectReader) readShard(s, partIdx int, blockIdx, blockLen int64) ([]byte, error) {
	d := r.byShard[s]
	if d == nil || !d.Ready(r.ctx) {
		return nil, errShardMissing
	}
	if r.files[s] == nil {
		f, err := d.OpenShard(r.ctx, r.bucket, r.object, r.dataDir, r.parts[partIdx].N)
		if err != nil {
			return nil, err
		}
		r.files[s] = f
	}
	return readVerifiedShard(r.files[s], blockIdx, blockLen, r.blockSize, r.k)
}

// loadBlock decodes one block into r.blk.
func (r *objectReader) loadBlock(partIdx int, blockIdx int64) error {
	if r.curPart != partIdx {
		r.closeFiles()
		r.curPart = partIdx
	}
	partSize := r.parts[partIdx].Size
	blockLen := min(r.blockSize, partSize-blockIdx*r.blockSize)
	n := r.k + r.m
	shards := make([][]byte, n)
	var corrupt atomic.Int64

	fetch := func(idxs []int) {
		var wg sync.WaitGroup
		for _, s := range idxs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				b, err := r.readShard(s, partIdx, blockIdx, blockLen)
				if err != nil {
					r.damaged.Store(true)
					if errors.Is(err, storage.ErrCorrupted) {
						corrupt.Add(1)
					}
					return
				}
				shards[s] = b
			}()
		}
		wg.Wait()
	}
	good := func() int {
		c := 0
		for _, s := range shards {
			if s != nil {
				c++
			}
		}
		return c
	}

	data := make([]int, r.k)
	for i := range data {
		data[i] = i
	}
	fetch(data)
	if good() < r.k {
		parity := make([]int, r.m)
		for i := range parity {
			parity[i] = r.k + i
		}
		fetch(parity)
	}
	if r.damaged.Load() {
		r.x.queueHeal(r.bucket, r.object)
	}
	if good() < r.k {
		if corrupt.Load() > 0 {
			r.x.corrupted.Add(1)
			return storage.Wrap(fmt.Errorf("%w: only %d of %d shards of a block are intact",
				storage.ErrCorrupted, good(), r.k), r.bucket, r.object)
		}
		return storage.Wrap(fmt.Errorf("%w: only %d of %d shards of a block are readable",
			storage.ErrBackendUnavailable, good(), r.k), r.bucket, r.object)
	}
	for s := 0; s < r.k; s++ {
		if shards[s] == nil {
			if err := r.enc.ReconstructData(shards); err != nil {
				return storage.Wrap(fmt.Errorf("%w: reconstruct: %v", storage.ErrCorrupted, err), r.bucket, r.object)
			}
			break
		}
	}
	out := r.blk[:0]
	for s := 0; s < r.k; s++ {
		out = append(out, shards[s]...)
	}
	r.blk = out[:blockLen]
	r.blkPart, r.blkIdx = partIdx, blockIdx
	return nil
}
