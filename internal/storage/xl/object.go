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
	"time"

	"nanoio/internal/meta"
	"nanoio/internal/storage"
	"nanoio/internal/storage/internal/listing"
	"nanoio/internal/storage/internal/objlock"
	"nanoio/internal/storage/xl/disk"
)

func newToken() (string, error) {
	id, err := meta.NewVersionID()
	if err != nil {
		return "", err
	}
	return strings.ReplaceAll(id, "-", ""), nil
}

// removeStages discards a staging area on every drive, in parallel. It
// waits for the drives only as long as StragglerGrace; a slow one finishes
// in the background (an unremoved staging area is swept later anyway).
func (x *XL) removeStages(ctx context.Context, stageID string) {
	dctx, cancel := detached(ctx)
	done := make(chan struct{}, len(x.drives))
	for _, d := range x.drives {
		go func() {
			d.RemoveStage(dctx, stageID)
			done <- struct{}{}
		}()
	}
	timer := time.NewTimer(x.stragglerGrace)
	defer timer.Stop()
	for range x.drives {
		select {
		case <-done:
		case <-timer.C:
			// Let the stragglers finish, then release the context.
			go func(rest int) {
				for ; rest > 0; rest-- {
					<-done
				}
				cancel()
			}(len(x.drives))
			return
		}
	}
	cancel()
}

// PutObject erasure-codes r across the drives and publishes it atomically.
// The body is encoded and written to staging before any lock is taken; the
// lock covers only the commit.
func (x *XL) PutObject(ctx context.Context, bucket, object string, r io.Reader, size int64, opts storage.PutOptions) (storage.ObjectInfo, error) {
	var zero storage.ObjectInfo
	if err := validate(bucket, object); err != nil {
		return zero, err
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

	gk, gm, class, err := x.geomFor(opts.StorageClass)
	if err != nil {
		return zero, storage.Wrap(err, bucket, object)
	}
	enc, err := x.encoder(gk, gm)
	if err != nil {
		return zero, err
	}
	// A write must reach the shards its own layout needs to be readable,
	// and the metadata quorum of the set, whichever is more.
	wq := max(quorumOf(gk, gm), x.writeQuorum())

	stageID, err := newToken()
	if err != nil {
		return zero, err
	}
	dataDir := storage.DataDirPrefix + "data-" + stageID
	defer x.removeStages(ctx, stageID)

	dist := x.distribution(bucket, object)
	ws, participants := x.openWriters(ctx, stageID, dataDir+"/part.1", dist, wq)
	if live := countWriters(ws); live < wq {
		abortWriters(ws)
		return zero, quorumError(bucket, object, live, wq, nil)
	}

	md5h := md5.New()
	var shah hash.Hash
	if opts.ContentSHA256 != "" {
		shah = sha256.New()
	}
	n, err := x.encodeStream(ctx, enc, r, size, x.blockSize, ws, wq, md5h, shah)
	if err != nil {
		abortWriters(ws)
		switch {
		case errors.Is(err, errQuorumLost):
			return zero, quorumError(bucket, object, countWriters(ws), wq, nil)
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

	roots, parts := x.settleWriters(ctx, ws, dist, participants, wq)
	if live := countTrue(parts); live < wq {
		return zero, quorumError(bucket, object, live, wq, nil)
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
	ct := opts.ContentType
	if ct == "" {
		ct = defaultCT
	}
	sums := make([][]meta.Checksum, len(x.drives))
	for d := range x.drives {
		if parts[d] {
			sums[d] = []meta.Checksum{{Part: 1, Algorithm: hashAlgorithm, Hash: roots[d]}}
		}
	}
	return x.publishVersion(ctx, bucket, object, publishSpec{
		stageID: stageID, dataDir: dataDir, dist: dist, blockSize: x.blockSize, sums: sums, participants: parts,
		k: gk, m: gm, quorum: wq,
		tmpl: meta.Version{
			Type: meta.TypeObject, Size: n, ETag: etag, DataDir: dataDir, ContentType: ct,
			UserMeta: opts.FinalUserDefined(), StorageClass: class,
			Parts: []meta.Part{{N: 1, Size: n, ETag: etag}},
		},
	}, opts)
}

// publishSpec is what publishVersion needs besides the staged data's
// location: the version record without its ID, number and time.
type publishSpec struct {
	stageID, dataDir string
	dist             []int
	blockSize        int64
	sums             [][]meta.Checksum
	participants     []bool
	// k and m are the object's erasure layout and quorum the number of
	// drives its commit must reach.
	k, m   int
	quorum int
	tmpl   meta.Version
}

// metaVersioning converts a bucket's state to the form the meta mutation
// functions take.
func metaVersioning(s storage.VersioningState) meta.Versioning {
	switch s {
	case storage.VersioningEnabled:
		return meta.Enabled
	case storage.VersioningSuspended:
		return meta.Suspended
	}
	return meta.Unversioned
}

// publishVersion commits a staged object as a new version of
// bucket/object. The caller holds the bucket's shared lock and the key's
// exclusive lock. The bucket's versioning state is read here, under that
// lock, so it cannot change between the decision and the commit; the
// version's ID (a new UUID when versioning is enabled, the null version
// otherwise) and sequence number are chosen once and sent to every drive.
func (x *XL) publishVersion(ctx context.Context, bucket, object string, ps publishSpec, opts storage.PutOptions) (storage.ObjectInfo, error) {
	var zero storage.ObjectInfo
	if err := x.requireBucket(ctx, bucket); err != nil {
		return zero, err
	}
	cfg, err := x.versioning(ctx, bucket)
	if err != nil {
		return zero, mapErr(err, bucket, object)
	}
	st := x.stateOf(ctx, bucket, object)
	if err := checkPreconditions(st, x.k, opts, bucket, object); err != nil {
		return zero, err
	}
	id, err := meta.VersionIDFor(metaVersioning(cfg.cfg.State))
	if err != nil {
		return zero, err
	}
	prev := uint64(0)
	if st.found(x.k) {
		prev = st.generation()
	}
	// The bucket's lock configuration is part of the settings read under
	// the shared bucket lock, so what is applied is what the bucket says now.
	now := time.Now().UTC()
	modTime := now
	if st.found(x.k) {
		modTime = st.file.MonotonicTime(now)
	}
	if imp := opts.Import; imp != nil {
		sid, ierr := importID(cfg.cfg.State, imp)
		if ierr != nil {
			return zero, storage.Wrap(ierr, bucket, object)
		}
		if st.found(x.k) {
			if old := st.file.Find(sid); old != nil {
				return toInfo(bucket, object, old, st.file.Latest() == old, cfg.cfg.State), nil
			}
		}
		id, modTime = sid, imp.ModTime.UTC()
	}
	lock, err := objlock.Resolve(cfg.lock.cfg, opts, now)
	if err != nil {
		return zero, storage.Wrap(err, bucket, object)
	}
	tmpl := ps.tmpl
	tmpl.VersionID, tmpl.Seq, tmpl.ModTime, tmpl.Lock = id, prev+1, modTime, lock
	spec := commitSpec{bucket: bucket, object: object, op: disk.OpPut, stageID: ps.stageID, dataDir: ps.dataDir,
		tmpl: tmpl, dist: ps.dist, blockSize: ps.blockSize, sums: ps.sums, participants: ps.participants,
		checkGen: true, prevGen: prev, need: max(ps.quorum, x.writeQuorum()), k: ps.k, m: ps.m, guard: objlock.Guard(now, false)}
	res := x.commit(ctx, spec)
	if err := x.finishCommit(ctx, spec, res); err != nil {
		return zero, mapErr(err, bucket, object)
	}
	x.noteVersioning(bucket, cfg.cfg)
	if st.found(x.k) && id == meta.NullVersion {
		x.noteFreed(bucket, object, st.file.Find(meta.NullVersion)) // overwrote the null version
	}
	latest := !st.found(x.k) || !st.file.Latest().ModTime.After(modTime)
	return toInfo(bucket, object, &tmpl, latest, cfg.cfg.State), nil
}

// openWriters stages the shard file rel under stageID on the drives,
// returning writers indexed by shard and which drives participate. It
// returns once a write quorum of drives has a staged file (plus the
// straggler grace); a drive that answers later has its file discarded.
func (x *XL) openWriters(ctx context.Context, stageID, rel string, dist []int, quorum int) (ws []*shardWriter, participants []bool) {
	ws = make([]*shardWriter, len(x.drives))
	participants = make([]bool, len(x.drives))
	got, errs := scatter(ctx, x, quorum, x.stragglerGrace, true, false,
		func(ctx context.Context, d *drive) (*shardWriter, error) {
			return newShardWriter(ctx, d, stageID, rel, x.writeQueue)
		},
		func(_ int, w *shardWriter) { w.evict() })
	for i, w := range got {
		if errs[i] == nil && w != nil {
			ws[dist[i]] = w
			participants[i] = true
		}
	}
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

// resolve picks the version a read addresses out of the agreed list. A
// delete marker is a *storage.DeleteMarkerError (see its documentation).
func (x *XL) resolve(ctx context.Context, bucket, object, versionID string, st *objState) (*meta.Version, bool, storage.VersioningState, error) {
	stored, err := storage.StoredVersionID(versionID)
	if err != nil {
		return nil, false, "", storage.Wrap(err, bucket, object)
	}
	explicit := versionID != ""
	v, rerr := st.file.Resolve(stored, !explicit)
	if rerr != nil {
		return nil, false, "", storage.Wrap(storage.ErrVersionNotFound, bucket, object)
	}
	state := x.reportState(ctx, bucket)
	if v.Type == meta.TypeDeleteMarker {
		return nil, false, state, &storage.DeleteMarkerError{
			Bucket: bucket, Object: object, ModTime: v.ModTime, Explicit: explicit,
			VersionID: storage.ReportedVersionID(state, v.VersionID),
		}
	}
	return v, v == st.file.Latest(), state, nil
}

// StatObject returns object metadata agreed by a read quorum.
func (x *XL) StatObject(ctx context.Context, bucket, object string, opts storage.GetOptions) (storage.ObjectInfo, error) {
	if err := validate(bucket, object); err != nil {
		return storage.ObjectInfo{}, err
	}
	if _, err := storage.StoredVersionID(opts.VersionID); err != nil {
		return storage.ObjectInfo{}, storage.Wrap(err, bucket, object)
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
	v, latest, state, err := x.resolve(ctx, bucket, object, opts.VersionID, st)
	if err != nil {
		return storage.ObjectInfo{}, err
	}
	return toInfo(bucket, object, v, latest, state), nil
}

// GetObject opens an object version. Its data directories are pinned before
// the lock is released, so the returned reader is a stable snapshot that a
// later overwrite or delete cannot disturb.
func (x *XL) GetObject(ctx context.Context, bucket, object string, opts storage.GetOptions) (io.ReadCloser, storage.ObjectInfo, error) {
	var zero storage.ObjectInfo
	if err := validate(bucket, object); err != nil {
		return nil, zero, err
	}
	if _, err := storage.StoredVersionID(opts.VersionID); err != nil {
		return nil, zero, storage.Wrap(err, bucket, object)
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
	v, latest, state, err := x.resolve(ctx, bucket, object, opts.VersionID, st)
	if err != nil {
		return nil, zero, err
	}
	info := toInfo(bucket, object, v, latest, state)
	if v.Transition != nil {
		// The data is in a tier; the caller streams it from there.
		return nil, zero, &storage.TransitionedError{Info: info}
	}
	if rg := opts.Range; rg != nil {
		if rg.Start < 0 || rg.Length <= 0 || rg.Start+rg.Length > v.Size {
			return nil, zero, storage.Wrap(storage.ErrInvalidRange, bucket, object)
		}
	}
	rd, err := x.newObjectReader(ctx, bucket, object, st, v)
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

// DeleteObject implements storage.StorageAPI.
//
//   - With opts.VersionID that one version (object or delete marker) is
//     removed permanently; naming a version that is not there succeeds.
//   - Without it an Unversioned bucket loses the object (from every drive,
//     as before versioning), an Enabled bucket gets a delete marker with a
//     new version ID (also for a key that has no versions, as in S3), and a
//     Suspended bucket gets a null delete marker replacing the null version.
//
// The lock protects the key's whole version list: bucket shared, key
// exclusive, as for a write. Version changes are conditional on the
// generation the lock holder read.
func (x *XL) DeleteObject(ctx context.Context, bucket, object string, opts storage.DeleteOptions) (storage.DeleteResult, error) {
	if err := validate(bucket, object); err != nil {
		return storage.DeleteResult{}, err
	}
	stored, err := storage.StoredVersionID(opts.VersionID)
	if err != nil {
		return storage.DeleteResult{}, storage.Wrap(err, bucket, object)
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
	cfg, err := x.versioning(ctx, bucket)
	if err != nil {
		return storage.DeleteResult{}, mapErr(err, bucket, object)
	}
	state := cfg.cfg.State
	st := meta.Versioning(metaVersioning(state))
	if opts.VersionID == "" && st == meta.Unversioned {
		// A write quorum of drives must be clean of the object afterwards;
		// shards on drives that were offline are removed by the scanner (a
		// lone survivor below read quorum is dangling, never resurrected).
		// A delete waits for every drive: it carries no generation, so one
		// that arrived late could remove a newer write's copy.
		//
		// A key that holds a protected version is never removed whole. (A
		// bucket with object lock is always versioned, so this is only
		// reachable by something that bypassed the bucket's settings; each
		// drive refuses as well.)
		if obj := x.stateOf(ctx, bucket, object); obj.found(x.k) {
			if err := obj.file.Protected(objlock.Guard(time.Now(), opts.BypassGovernance)); err != nil {
				return storage.DeleteResult{}, objlock.Err(err, bucket, object)
			}
		}
		var gone *meta.File
		if obj := x.stateOf(ctx, bucket, object); obj.found(x.k) {
			gone = obj.file
		}
		errs := x.each(ctx, func(d *drive) error { return d.DeleteObject(ctx, bucket, object) })
		if countNil(errs) < x.writeQuorum() {
			return storage.DeleteResult{}, quorumError(bucket, object, countNil(errs), x.writeQuorum(), errs)
		}
		if gone != nil {
			for i := range gone.Versions {
				x.noteFreed(bucket, object, &gone.Versions[i])
			}
		}
		return storage.DeleteResult{}, nil
	}

	obj := x.stateOf(ctx, bucket, object)
	if !obj.found(x.k) && !obj.missing(len(x.drives), x.k) {
		return storage.DeleteResult{}, x.failure(obj, bucket, object)
	}
	known := obj.found(x.k)
	prev := uint64(0)
	if known {
		prev = obj.generation()
	}
	spec := commitSpec{bucket: bucket, object: object, checkGen: true, prevGen: prev, need: x.writeQuorum(),
		participants: make([]bool, len(x.drives))}
	for i, d := range x.drives {
		spec.participants[i] = d.Ready(ctx)
	}
	now := time.Now().UTC()
	spec.guard = objlock.Guard(now, opts.BypassGovernance)
	var res storage.DeleteResult
	switch {
	case opts.VersionID != "":
		res.VersionID = storage.ReportedVersionID(state, stored)
		var v *meta.Version
		if known {
			v = obj.file.Find(stored)
		}
		if v == nil {
			return res, nil // not there: nothing to remove
		}
		// Object lock is judged here, under the key lock, on the version
		// list a read quorum agrees on, and again by every drive.
		if err := meta.CheckRemove(v, spec.guard); err != nil {
			return storage.DeleteResult{}, objlock.Err(err, bucket, object)
		}
		res.DeleteMarker = v.Type == meta.TypeDeleteMarker
		spec.op, spec.removeID = disk.OpRemove, stored
		spec.tmpl.Seq = prev + 1
	default:
		id, err := meta.VersionIDFor(st)
		if err != nil {
			return storage.DeleteResult{}, err
		}
		markerTime := now
		if known {
			markerTime = obj.file.MonotonicTime(now)
		}
		if imp := opts.ImportMarker; imp != nil {
			sid, ierr := importID(state, imp)
			if ierr != nil {
				return storage.DeleteResult{}, storage.Wrap(ierr, bucket, object)
			}
			if known && obj.file.Find(sid) != nil {
				return storage.DeleteResult{VersionID: storage.ReportedVersionID(state, sid), DeleteMarker: true}, nil
			}
			id, markerTime = sid, imp.ModTime.UTC()
		}
		if known {
			// Replacing the null version (suspended buckets) removes it.
			if old := obj.file.Find(id); old != nil {
				if err := meta.CheckRemove(old, spec.guard); err != nil {
					return storage.DeleteResult{}, objlock.Err(err, bucket, object)
				}
			}
		}
		spec.op = disk.OpMarker
		spec.tmpl = meta.Version{Type: meta.TypeDeleteMarker, VersionID: id, Seq: prev + 1, ModTime: markerTime}
		res.VersionID, res.DeleteMarker = storage.ReportedVersionID(state, id), true
	}
	cres := x.commit(ctx, spec)
	if err := x.finishCommit(ctx, spec, cres); err != nil {
		return storage.DeleteResult{}, mapErr(err, bucket, object)
	}
	if known {
		switch spec.op {
		case disk.OpRemove:
			x.noteFreed(bucket, object, obj.file.Find(spec.removeID))
		case disk.OpMarker:
			x.noteFreed(bucket, object, obj.file.Find(spec.tmpl.VersionID))
		}
	}
	return res, nil
}

// ListObjects lists keys in UTF-8 byte order. Keys are gathered from enough
// drives to see every committed object, and each is confirmed by a
// metadata read quorum, so a stray shard on one drive never appears. A key
// whose latest version is a delete marker is not listed.
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
	state := x.reportState(ctx, bucket)
	return listing.Page(keys, opts, func(key string) (storage.ObjectInfo, bool) {
		st := x.stateOf(ctx, bucket, key)
		if !st.found(x.k) {
			return storage.ObjectInfo{}, false
		}
		l := st.latest()
		if l == nil || l.Type != meta.TypeObject {
			return storage.ObjectInfo{}, false
		}
		return toInfo(bucket, key, l, true, state), true
	}), nil
}

// ListObjectVersions lists every version and delete marker (see the fs
// backend for the ordering and markers). Each key's list is confirmed by a
// metadata read quorum.
func (x *XL) ListObjectVersions(ctx context.Context, bucket string, opts storage.ListOptions) (storage.ListVersionsResult, error) {
	if err := storage.ValidateBucketName(bucket); err != nil {
		return storage.ListVersionsResult{}, err
	}
	if err := x.enter(ctx); err != nil {
		return storage.ListVersionsResult{}, err
	}
	defer x.leave()
	if err := x.requireBucket(ctx, bucket); err != nil {
		return storage.ListVersionsResult{}, err
	}
	keys, err := x.listKeys(ctx, bucket, opts.Prefix)
	if err != nil {
		return storage.ListVersionsResult{}, mapErr(err, bucket, "")
	}
	state := x.reportState(ctx, bucket)
	return listing.PageVersions(keys, opts, func(key string) ([]storage.ObjectInfo, bool) {
		st := x.stateOf(ctx, bucket, key)
		if !st.found(x.k) {
			return nil, false
		}
		out := make([]storage.ObjectInfo, 0, len(st.file.Versions))
		for i := range st.file.Versions {
			out = append(out, toInfo(bucket, key, &st.file.Versions[i], i == 0, state))
		}
		return out, true
	}), nil
}

// CopyObject is outside this backend's scope (the API layer composes it),
// exactly as in fs, and say so.
func (x *XL) CopyObject(context.Context, storage.ObjectRef, storage.ObjectRef, storage.CopyOptions) (storage.ObjectInfo, error) {
	return storage.ObjectInfo{}, notImpl("CopyObject")
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
