package xl

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"
	"sync"
	"time"

	"nanoio/internal/meta"
	"nanoio/internal/storage"
	"nanoio/internal/storage/internal/listing"
)

func newToken() (string, error) {
	id, err := meta.NewVersionID()
	if err != nil {
		return "", err
	}
	return strings.ReplaceAll(id, "-", ""), nil
}

// removeStages discards a staging area on every drive; unknown stages and
// offline drives are ignored.
func (x *XL) removeStages(ctx context.Context, stageID string) {
	ctx, cancel := detached(ctx)
	defer cancel()
	for _, d := range x.drives {
		d.RemoveStage(ctx, stageID)
	}
}

// PutObject erasure-codes r across the drives and publishes it atomically.
// The body is encoded and written to staging before any lock is taken; the
// lock covers only the commit.
func (x *XL) PutObject(ctx context.Context, bucket, object string, r io.Reader, size int64, opts storage.PutOptions) (storage.ObjectInfo, error) {
	var zero storage.ObjectInfo
	if err := validate(bucket, object); err != nil {
		return zero, err
	}
	if opts.Versioned {
		return zero, notImpl("versioned PutObject")
	}
	if size > maxObjectSize {
		return zero, storage.Wrap(storage.ErrEntityTooLarge, bucket, object)
	}
	if err := x.enter(ctx); err != nil {
		return zero, err
	}
	defer x.leave()
	if err := x.requireBucket(ctx, bucket); err != nil {
		return zero, err
	}

	stageID, err := newToken()
	if err != nil {
		return zero, err
	}
	dataDir := storage.DataDirPrefix + "data-" + stageID
	defer x.removeStages(ctx, stageID)

	dist := x.distribution(bucket, object)
	ws, participants := x.openWriters(ctx, stageID, dataDir+"/part.1", dist)
	if live := countWriters(ws); live < x.writeQuorum() {
		abortWriters(ws)
		return zero, quorumError(bucket, object, live, x.writeQuorum(), nil)
	}

	md5h := md5.New()
	var shah hash.Hash
	if opts.ContentSHA256 != "" {
		shah = sha256.New()
	}
	n, err := x.encodeStream(ctx, r, size, x.blockSize, ws, x.writeQuorum(), md5h, shah)
	if err != nil {
		abortWriters(ws)
		switch {
		case errors.Is(err, errQuorumLost):
			return zero, quorumError(bucket, object, countWriters(ws), x.writeQuorum(), nil)
		case errors.Is(err, io.ErrUnexpectedEOF):
			return zero, storage.Wrap(storage.ErrIncompleteBody, bucket, object)
		}
		return zero, mapErr(err, bucket, object)
	}
	if size >= 0 && n != size {
		abortWriters(ws)
		return zero, storage.Wrap(storage.ErrIncompleteBody, bucket, object)
	}
	etag := hex.EncodeToString(md5h.Sum(nil))
	if opts.ContentMD5 != "" && !strings.EqualFold(opts.ContentMD5, etag) {
		abortWriters(ws)
		return zero, storage.Wrap(storage.ErrBadDigest, bucket, object)
	}
	if shah != nil && !strings.EqualFold(opts.ContentSHA256, hex.EncodeToString(shah.Sum(nil))) {
		abortWriters(ws)
		return zero, storage.Wrap(storage.ErrSHA256Mismatch, bucket, object)
	}

	roots, parts := x.settleWriters(ctx, ws, dist, participants, x.writeQuorum())
	if live := countTrue(parts); live < x.writeQuorum() {
		return zero, quorumError(bucket, object, live, x.writeQuorum(), nil)
	}

	unlockBucket, err := x.locker.RLock(ctx, bucket, "")
	if err != nil {
		return zero, err
	}
	defer unlockBucket()
	unlockKey, err := x.locker.Lock(ctx, bucket, object)
	if err != nil {
		return zero, err
	}
	defer unlockKey()
	if err := x.requireBucket(ctx, bucket); err != nil {
		return zero, err
	}
	st := x.stateOf(ctx, bucket, object)
	if err := checkPreconditions(st, x.k, opts, bucket, object); err != nil {
		return zero, err
	}

	ct := opts.ContentType
	if ct == "" {
		ct = defaultCT
	}
	gen, prevGen := nextGeneration(st, x.k)
	tmpl := meta.Version{
		Type: meta.TypeObject, Generation: gen, ModTime: time.Now().UTC(), Size: n, ETag: etag, DataDir: dataDir,
		ContentType: ct, UserMeta: copyMap(opts.UserDefined),
		Parts: []meta.Part{{N: 1, Size: n, ETag: etag}},
	}
	sums := make([][]meta.Checksum, len(x.drives))
	for d := range x.drives {
		if parts[d] {
			sums[d] = []meta.Checksum{{Part: 1, Algorithm: hashAlgorithm, Hash: roots[d]}}
		}
	}
	spec := commitSpec{bucket: bucket, object: object, stageID: stageID, dataDir: dataDir,
		tmpl: tmpl, dist: dist, blockSize: x.blockSize, sums: sums, participants: parts,
		checkGen: true, prevGen: prevGen, need: x.writeQuorum()}
	res := x.commit(ctx, spec)
	if err := x.finishCommit(ctx, spec, res); err != nil {
		return zero, mapErr(err, bucket, object)
	}
	return toInfo(bucket, object, &tmpl), nil
}

// openWriters stages the shard file rel under stageID on every ready drive,
// returning writers indexed by shard and which drives participate.
func (x *XL) openWriters(ctx context.Context, stageID, rel string, dist []int) (ws []*shardWriter, participants []bool) {
	ws = make([]*shardWriter, len(x.drives))
	participants = make([]bool, len(x.drives))
	var wg syncWG
	var mu sync.Mutex
	for i, d := range x.drives {
		wg.Go(func() {
			w, err := newShardWriter(ctx, d, stageID, rel, x.writeQueue)
			if err != nil {
				return
			}
			mu.Lock()
			ws[dist[i]] = w
			participants[i] = true
			mu.Unlock()
		})
	}
	wg.Wait()
	return ws, participants
}

func countWriters(ws []*shardWriter) int {
	n := 0
	for _, w := range ws {
		if w != nil && !w.failed() {
			n++
		}
	}
	return n
}

func countTrue(b []bool) int {
	n := 0
	for _, v := range b {
		if v {
			n++
		}
	}
	return n
}

func abortWriters(ws []*shardWriter) {
	for i, w := range ws {
		if w != nil {
			w.evict()
			ws[i] = nil
		}
	}
}

// settleWriters closes every writer's input and waits for the files to be
// durable, but only as long as the write quorum needs: once need writers
// have finished, the rest get StragglerGrace and are then evicted (heal
// repairs the drives they were on). It returns per-drive checksum roots and
// which drives hold a complete shard file.
func (x *XL) settleWriters(ctx context.Context, ws []*shardWriter, dist []int, participants []bool, need int) (roots []string, ok []bool) {
	roots = make([]string, len(dist))
	ok = make([]bool, len(dist))
	type fin struct{ drive int }
	finished := make(chan fin, len(dist))
	pending := 0
	for d := range dist {
		if !participants[d] || ws[dist[d]] == nil {
			continue
		}
		w := ws[dist[d]]
		w.closeInput()
		pending++
		go func() {
			<-w.done
			finished <- fin{d}
		}()
	}
	good := 0
	var grace <-chan time.Time
	for pending > 0 {
		select {
		case f := <-finished:
			pending--
			w := ws[dist[f.drive]]
			if root, fine := w.result(); fine {
				roots[f.drive], ok[f.drive] = root, true
				good++
			}
			if good >= need && grace == nil && pending > 0 {
				t := time.NewTimer(x.stragglerGrace)
				defer t.Stop()
				grace = t.C
			}
			if good+pending < need { // cannot reach quorum: stop waiting
				pending = 0
				evictRest(ws, dist, participants, ok)
			}
		case <-grace:
			evictRest(ws, dist, participants, ok)
			pending = 0
		case <-ctx.Done():
			evictRest(ws, dist, participants, ok)
			pending = 0
		}
	}
	return roots, ok
}

// evictRest abandons every writer that has not produced a good file.
func evictRest(ws []*shardWriter, dist []int, participants []bool, ok []bool) {
	for d := range dist {
		if participants[d] && !ok[d] && ws[dist[d]] != nil {
			ws[dist[d]].evict()
		}
	}
}

// lookup resolves bucket/object to its quorum state, or the error to
// return. The caller holds the key lock.
func (x *XL) lookup(ctx context.Context, bucket, object string) (*objState, error) {
	st := x.stateOf(ctx, bucket, object)
	if st.found(x.k) {
		return st, nil
	}
	if ok, err := x.bucketExists(ctx, bucket); err == nil && !ok {
		return nil, storage.Wrap(storage.ErrBucketNotFound, bucket, "")
	}
	return nil, x.failure(st, bucket, object)
}

// StatObject returns object metadata agreed by a read quorum.
func (x *XL) StatObject(ctx context.Context, bucket, object string, opts storage.GetOptions) (storage.ObjectInfo, error) {
	if err := validate(bucket, object); err != nil {
		return storage.ObjectInfo{}, err
	}
	if opts.VersionID != "" {
		return storage.ObjectInfo{}, storage.Wrap(storage.ErrVersionNotFound, bucket, object)
	}
	if err := x.enter(ctx); err != nil {
		return storage.ObjectInfo{}, err
	}
	defer x.leave()
	unlock, err := x.locker.RLock(ctx, bucket, object)
	if err != nil {
		return storage.ObjectInfo{}, err
	}
	defer unlock()
	st, err := x.lookup(ctx, bucket, object)
	if err != nil {
		return storage.ObjectInfo{}, err
	}
	return toInfo(bucket, object, st.ver), nil
}

// GetObject opens an object. Its data directories are pinned before the
// lock is released, so the returned reader is a stable snapshot that a
// later overwrite or delete cannot disturb.
func (x *XL) GetObject(ctx context.Context, bucket, object string, opts storage.GetOptions) (io.ReadCloser, storage.ObjectInfo, error) {
	var zero storage.ObjectInfo
	if err := validate(bucket, object); err != nil {
		return nil, zero, err
	}
	if opts.VersionID != "" {
		return nil, zero, storage.Wrap(storage.ErrVersionNotFound, bucket, object)
	}
	if err := x.enter(ctx); err != nil {
		return nil, zero, err
	}
	defer x.leave()
	unlock, err := x.locker.RLock(ctx, bucket, object)
	if err != nil {
		return nil, zero, err
	}
	defer unlock()
	st, err := x.lookup(ctx, bucket, object)
	if err != nil {
		return nil, zero, err
	}
	info := toInfo(bucket, object, st.ver)
	if rg := opts.Range; rg != nil {
		if rg.Start < 0 || rg.Length <= 0 || rg.Start+rg.Length > st.ver.Size {
			return nil, zero, storage.Wrap(storage.ErrInvalidRange, bucket, object)
		}
	}
	rd, err := x.newObjectReader(ctx, bucket, object, st)
	if err != nil {
		return nil, zero, err
	}
	if st.stale+st.absent+st.corrupt+st.failed > 0 {
		// Some drive is stale or unreadable: repair it in the background.
		x.queueHeal(bucket, object)
	}
	if rg := opts.Range; rg != nil {
		return struct {
			io.Reader
			io.Closer
		}{io.NewSectionReader(rd, rg.Start, rg.Length), rd}, info, nil
	}
	return rd, info, nil
}

// DeleteObject removes an object from every drive. Deleting a missing
// object succeeds. It succeeds when a write quorum of drives is clean of
// the object afterwards; shards on drives that were offline are removed by
// the scanner (a lone survivor below read quorum is dangling, never
// resurrected).
func (x *XL) DeleteObject(ctx context.Context, bucket, object string, opts storage.DeleteOptions) (storage.DeleteResult, error) {
	if err := validate(bucket, object); err != nil {
		return storage.DeleteResult{}, err
	}
	if opts.Versioned || opts.VersionID != "" {
		return storage.DeleteResult{}, notImpl("versioned DeleteObject")
	}
	if err := x.enter(ctx); err != nil {
		return storage.DeleteResult{}, err
	}
	defer x.leave()
	unlockBucket, err := x.locker.RLock(ctx, bucket, "")
	if err != nil {
		return storage.DeleteResult{}, err
	}
	defer unlockBucket()
	unlockKey, err := x.locker.Lock(ctx, bucket, object)
	if err != nil {
		return storage.DeleteResult{}, err
	}
	defer unlockKey()
	if err := x.requireBucket(ctx, bucket); err != nil {
		return storage.DeleteResult{}, err
	}
	// A delete waits for every drive, unlike a write: a delayed delete
	// that lands after a newer write would remove that write's copy on
	// the drive, and unlike a commit it carries no generation to refuse.
	errs := x.each(ctx, func(d *drive) error { return d.DeleteObject(ctx, bucket, object) })
	if countNil(errs) < x.writeQuorum() {
		return storage.DeleteResult{}, quorumError(bucket, object, countNil(errs), x.writeQuorum(), errs)
	}
	return storage.DeleteResult{}, nil
}

// ListObjects lists keys in UTF-8 byte order. Keys are gathered from enough
// drives to see every committed object, and each is confirmed by a
// metadata read quorum, so a stray shard on one drive never appears.
func (x *XL) ListObjects(ctx context.Context, bucket string, opts storage.ListOptions) (storage.ListResult, error) {
	if err := storage.ValidateBucketName(bucket); err != nil {
		return storage.ListResult{}, err
	}
	if err := x.enter(ctx); err != nil {
		return storage.ListResult{}, err
	}
	defer x.leave()
	if err := x.requireBucket(ctx, bucket); err != nil {
		return storage.ListResult{}, err
	}
	keys, err := x.listKeys(ctx, bucket, opts.Prefix)
	if err != nil {
		return storage.ListResult{}, mapErr(err, bucket, "")
	}
	return listing.Page(keys, opts, func(key string) (storage.ObjectInfo, bool) {
		st := x.stateOf(ctx, bucket, key)
		if !st.found(x.k) {
			return storage.ObjectInfo{}, false
		}
		return toInfo(bucket, key, st.ver), true
	}), nil
}

// ListObjectVersions, CopyObject and UpdateObjectMetadata are outside this
// backend's scope, exactly as in fs, and say so.
func (x *XL) ListObjectVersions(context.Context, string, storage.ListOptions) (storage.ListVersionsResult, error) {
	return storage.ListVersionsResult{}, notImpl("ListObjectVersions")
}

func (x *XL) CopyObject(context.Context, storage.ObjectRef, storage.ObjectRef, storage.CopyOptions) (storage.ObjectInfo, error) {
	return storage.ObjectInfo{}, notImpl("CopyObject")
}

func (x *XL) UpdateObjectMetadata(context.Context, string, string, storage.UpdateMetaOptions) (storage.ObjectInfo, error) {
	return storage.ObjectInfo{}, notImpl("UpdateObjectMetadata")
}

func notImpl(op string) error {
	return fmt.Errorf("xl: %s: %w", op, storage.ErrNotImplemented)
}

// newSHA returns a SHA-256 hasher if a digest was requested, else nil.
func newSHA(want string) hash.Hash {
	if want == "" {
		return nil
	}
	return sha256.New()
}
