package xl

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"nanoio/internal/meta"
	"nanoio/internal/storage"
	"nanoio/internal/storage/internal/objlock"
	"nanoio/internal/storage/xl/disk"
)

// driveMeta is what one drive says about an object.
type driveMeta struct {
	file   *meta.File // decoded xl.meta; nil unless the drive answered with one
	fp     string     // fingerprint of the whole file (see fileFingerprint)
	absent bool       // definitively not present (ENOENT)
	err    error      // unreadable: offline, corrupt, I/O error
	// pending means the drive had not answered when a quorum read returned;
	// it says nothing about the drive.
	pending bool
}

// readMeta loads and verifies one drive's xl.meta for an object.
func (x *XL) readMeta(ctx context.Context, d *drive, bucket, object string) driveMeta {
	data, err := d.ReadMeta(ctx, bucket, object)
	if err != nil {
		if errors.Is(err, disk.ErrNotFound) {
			return driveMeta{absent: true}
		}
		return driveMeta{err: err}
	}
	f, err := meta.Decode(data)
	if err != nil {
		x.corrupted.Add(1)
		return driveMeta{err: fmt.Errorf("%w: drive %d: %s/%s: %v", storage.ErrCorrupted, d.idx, bucket, object, err)}
	}
	if len(f.Versions) == 0 {
		return driveMeta{absent: true, file: f}
	}
	return driveMeta{file: f, fp: fileFingerprint(f)}
}

// objState is the quorum view of one object: the version list a read
// quorum of drives agrees on.
type objState struct {
	metas   []driveMeta
	file    *meta.File // the winning group's version list (one drive's copy)
	agree   []int      // drives whose xl.meta matches it
	absent  int
	corrupt int
	failed  int // offline or unreadable for another reason
	stale   int // answered with a different version list than the winning one
}

// latest is the newest version, object or delete marker; nil when the
// object is not (yet) known.
func (st *objState) latest() *meta.Version {
	if st.file == nil {
		return nil
	}
	return st.file.Latest()
}

// generation is the key's compare-and-set generation, 0 when unknown.
func (st *objState) generation() uint64 {
	if st.file == nil {
		return 0
	}
	return st.file.Generation()
}

// fileFingerprint identifies a version list for agreement: everything that
// must be identical on every drive after one change. Per-drive fields
// (shard index, checksums) are excluded.
func fileFingerprint(f *meta.File) string {
	var b strings.Builder
	fmt.Fprintf(&b, "g%d", f.Generation())
	for i := range f.Versions {
		v := &f.Versions[i]
		fmt.Fprintf(&b, "|%s,%d,%s,%d,%s,%d,%s,%s", v.VersionID, v.Seq, v.Type, v.ModTime.UnixNano(), v.ETag, v.Size,
			v.DataDir, v.ContentType)
		if e := v.Erasure; e != nil {
			fmt.Fprintf(&b, ",%d+%d/%d", e.DataBlocks, e.ParityBlocks, e.BlockSize)
		}
		if t := v.Transition; t != nil {
			fmt.Fprintf(&b, ",T:%s/%s/%s", t.Tier, t.Object, t.VersionID)
		}
	}
	return b.String()
}

// versionFingerprint identifies one version, for deciding whether a drive's
// copy of it is the agreed one.
func versionFingerprint(v *meta.Version) string {
	e := ""
	if v.Erasure != nil {
		e = fmt.Sprintf("%d+%d/%d", v.Erasure.DataBlocks, v.Erasure.ParityBlocks, v.Erasure.BlockSize)
	}
	if t := v.Transition; t != nil {
		e += fmt.Sprintf(",T:%s/%s/%s", t.Tier, t.Object, t.VersionID)
	}
	return fmt.Sprintf("%s,%d,%s,%d,%s,%d,%s,%s,%s", v.VersionID, v.Seq, v.Type, v.ModTime.UnixNano(), v.ETag, v.Size,
		v.DataDir, v.ContentType, e)
}

// stateOf returns the quorum view of bucket/object. When K > M a version
// held by K drives is the only one that can be, so it returns as soon as K
// drives agree (or enough say "absent"), without waiting for slow ones; the
// drives that had not answered are marked pending. With K == M two disjoint
// groups of K are possible, so every drive is asked.
func (x *XL) stateOf(ctx context.Context, bucket, object string) *objState {
	if x.k <= x.m {
		return x.stateOfAll(ctx, bucket, object)
	}
	n := len(x.drives)
	type answer struct {
		i int
		m driveMeta
	}
	ch := make(chan answer, n)
	for i, d := range x.drives {
		go func() { ch <- answer{i, x.readMeta(ctx, d, bucket, object)} }()
	}
	st := &objState{metas: make([]driveMeta, n)}
	for i := range st.metas {
		st.metas[i].pending = true
	}
	counts := map[string]int{}
	absent := 0
	var graceC <-chan time.Time
loop:
	for got := 0; got < n; got++ {
		select {
		case a := <-ch:
			st.metas[a.i] = a.m
			switch {
			case a.m.file != nil && !a.m.absent:
				fp := a.m.fp
				counts[fp]++
				if counts[fp] >= x.k && graceC == nil {
					// Quorum agrees. The drives that have not answered
					// get StragglerGrace: normally they answer within it,
					// and every agreeing drive is spare redundancy for
					// the read (a damaged shard among the first K must
					// have parity to fall back on). A hung drive costs
					// the grace, not its timeout.
					if x.stragglerGrace <= 0 {
						break loop
					}
					t := time.NewTimer(x.stragglerGrace)
					defer t.Stop()
					graceC = t.C
				}
			case a.m.absent:
				absent++
				if absent > n-x.k {
					break loop // definitively not there
				}
			}
		case <-graceC:
			break loop
		}
	}
	st.group()
	return st
}

// stateOfAll reads every drive's metadata and groups the agreeing ones. Heal
// and other maintenance need the whole picture.
func (x *XL) stateOfAll(ctx context.Context, bucket, object string) *objState {
	st := &objState{metas: make([]driveMeta, len(x.drives))}
	var wg syncWG
	for i, d := range x.drives {
		wg.Go(func() { st.metas[i] = x.readMeta(ctx, d, bucket, object) })
	}
	wg.Wait()
	st.group()
	return st
}

func (st *objState) group() {
	groups := map[string][]int{}
	for i, m := range st.metas {
		switch {
		case m.pending:
		case m.file != nil && !m.absent:
			groups[m.fp] = append(groups[m.fp], i)
		case m.absent:
			st.absent++
		case errors.Is(m.err, storage.ErrCorrupted):
			st.corrupt++
		default:
			st.failed++
		}
	}
	bestFP := ""
	for fp, idxs := range groups {
		better := bestFP == "" || len(idxs) > len(groups[bestFP])
		if !better && len(idxs) == len(groups[bestFP]) {
			// Tie: prefer the newer generation, then the newer write.
			a, b := st.metas[idxs[0]].file, st.metas[groups[bestFP][0]].file
			better = a.Generation() > b.Generation() ||
				a.Generation() == b.Generation() && a.Latest().ModTime.After(b.Latest().ModTime)
		}
		if better {
			bestFP = fp
		}
	}
	for fp, idxs := range groups {
		if fp != bestFP {
			st.stale += len(idxs)
		}
	}
	if bestFP != "" {
		st.agree = groups[bestFP]
		sort.Ints(st.agree)
		st.file = st.metas[st.agree[0]].file
	}
}

// found reports whether enough drives agree to serve the object.
func (st *objState) found(readQuorum int) bool { return len(st.agree) >= readQuorum }

// missing reports whether the object is definitively not there: too many
// drives say so for it ever to have reached a write quorum.
func (st *objState) missing(n, readQuorum int) bool { return st.absent > n-readQuorum }

// failure is the sentinel to return when the object cannot be served.
func (x *XL) failure(st *objState, bucket, object string) error {
	switch {
	case st.missing(len(x.drives), x.k):
		return storage.Wrap(storage.ErrObjectNotFound, bucket, object)
	case st.corrupt > 0:
		return storage.Wrap(fmt.Errorf("%w: %d drives hold unreadable metadata and only %d agree",
			storage.ErrCorrupted, st.corrupt, len(st.agree)), bucket, object)
	}
	return storage.Wrap(fmt.Errorf("%w: read quorum not met (%d of %d drives agree)",
		storage.ErrBackendUnavailable, len(st.agree), x.k), bucket, object)
}

// versionFor builds the per-drive version from a template: the erasure
// block records this drive's shard index and part checksums.
func (x *XL) versionFor(tmpl meta.Version, dist []int, drive int, sums []meta.Checksum, blockSize int64, k, m int) meta.Version {
	if k == 0 {
		k, m = x.k, x.m
	}
	v := tmpl
	v.Erasure = &meta.Erasure{
		Algorithm: algorithm, DataBlocks: k, ParityBlocks: m, BlockSize: blockSize,
		Index: dist[drive], Distribution: dist, Checksums: sums,
	}
	return v
}

// commitSpec describes one change to a key's version list on every drive:
// publishing a staged object (op OpPut), adding a delete marker (OpMarker)
// or removing a version (OpRemove).
type commitSpec struct {
	bucket, object string
	op             disk.CommitOp
	stageID        string
	dataDir        string
	// k and m are the erasure layout of an OpPut; zero means the set's.
	k, m int
	// tmpl is the version without Erasure: VersionID, Seq, ModTime set.
	// For OpMarker it is the whole delete marker.
	tmpl meta.Version
	// removeID is the stored version ID OpRemove removes and OpSetLock
	// changes.
	removeID string
	// lock is the new lock state of OpSetLock.
	lock *meta.Lock
	// metaUpd is the change of OpSetMeta.
	metaUpd *meta.MetaUpdate
	// transition is the stub OpTransition installs.
	transition *meta.Transition
	// guard is how object lock is judged on every drive; guard.Now is set
	// once by the coordinator so all drives decide alike.
	guard     meta.Guard
	dist      []int
	blockSize int64
	// sums[d] are drive d's part checksums. participants[d] says whether a
	// staged data dir exists on drive d.
	sums         [][]meta.Checksum
	participants []bool
	// checkGen makes every drive's commit conditional on not already holding
	// a generation greater than prevGen (see disk.CommitRequest).
	checkGen bool
	prevGen  uint64
	// need is how many committed drives commit waits for before returning
	// (0 means every participating drive).
	need int
	// files and dataDirs are, per drive, the whole xl.meta and the staged
	// data directories of an OpReplace (repair), which is built per drive.
	files    []*meta.File
	dataDirs [][]string
}

// commitResult is the outcome on the drives that took part.
type commitResult struct {
	committed []int
	errs      []error
	commits   []disk.Commit
}

// errStraggler marks a drive that had not answered when its caller had
// what it needed.
var errStraggler = errors.New("still in flight when the quorum was reached")

// commit publishes the staged object on the participating drives; each
// drive's CommitObject is atomic on that drive. It returns when spec.need
// drives have committed and StragglerGrace has passed for the rest (all
// drives when need is 0, as for repairs). Commits still in flight then are
// finished in the background if they succeed, and a delayed commit that
// lands after a newer write is refused by that drive's generation check.
// On failure it waits for every commit, since each one that landed must be
// rolled back. The caller decides, by quorum, whether to Finish or Rollback.
func (x *XL) commit(ctx context.Context, spec commitSpec) commitResult {
	n := len(x.drives)
	need := spec.need
	if need <= 0 {
		need = countTrue(spec.participants)
	}
	grace := x.stragglerGrace
	late := func(i int, c disk.Commit) {
		fctx, cancel := detached(ctx)
		defer cancel()
		if err := c.Finish(fctx); err != nil {
			x.log.Warn("xl: could not finish a late commit", "bucket", spec.bucket, "object", spec.object, "drive", i, "err", err)
		}
	}
	// Non-participants are not asked; scatter would otherwise try them.
	commits, errs := scatterSubset(ctx, x, spec.participants, need, grace,
		func(ctx context.Context, d *drive) (disk.Commit, error) {
			req := disk.CommitRequest{
				Bucket: spec.bucket, Object: spec.object, Op: spec.op, StageID: spec.stageID, DataDir: spec.dataDir,
				VersionID: spec.removeID, Seq: spec.tmpl.Seq, CheckGen: spec.checkGen, PrevGen: spec.prevGen,
				Lock: spec.lock, Meta: spec.metaUpd, Transition: spec.transition, Guard: spec.guard,
			}
			switch spec.op {
			case disk.OpPut:
				req.Version = x.versionFor(spec.tmpl, spec.dist, d.idx, spec.sums[d.idx], spec.blockSize, spec.k, spec.m)
			case disk.OpMarker:
				req.Version = spec.tmpl
			case disk.OpReplace:
				req.File, req.DataDirs = spec.files[d.idx], spec.dataDirs[d.idx]
			}
			return d.CommitObject(ctx, req)
		}, late)
	res := commitResult{errs: errs, commits: commits}
	for i := 0; i < n; i++ {
		if errs[i] == nil {
			res.committed = append(res.committed, i)
		}
	}
	return res
}

// scatterSubset is scatter over the drives with include set. Drives left
// out report errDriveOffline. When the quorum fails it waits for every
// answer (giveUp is off) because the caller must undo the ones that landed.
func scatterSubset[T any](ctx context.Context, x *XL, include []bool, need int, grace time.Duration,
	fn func(ctx context.Context, d *drive) (T, error), late func(i int, v T)) ([]T, []error) {
	return scatter(ctx, x, need, grace, false, true, func(ctx context.Context, d *drive) (T, error) {
		var zero T
		if !include[d.idx] {
			return zero, errDriveOffline
		}
		return fn(ctx, d)
	}, late)
}

// detached returns a context that outlives ctx's cancellation but not a
// bounded time: cleanup (finish, rollback, discard) must still run when the
// request that needed it has been cancelled.
func detached(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
}

// finish makes every committed drive's commit final, dropping the data it
// superseded.
func (x *XL) finish(ctx context.Context, spec commitSpec, res commitResult) {
	ctx, cancel := detached(ctx)
	defer cancel()
	for _, i := range res.committed {
		if err := res.commits[i].Finish(ctx); err != nil {
			x.log.Warn("xl: could not finish commit", "bucket", spec.bucket, "object", spec.object, "drive", i, "err", err)
		}
	}
}

// finishCommit applies quorum to a commit: on success it makes the commits
// final; on failure it rolls every drive back. The staging areas are the
// caller's to remove (each caller defers removeStages). The
// follow-up runs detached from ctx: a client that gave up must not leave a
// half-committed object behind.
func (x *XL) finishCommit(ctx context.Context, spec commitSpec, res commitResult) error {
	need := max(x.writeQuorum(), spec.need)
	if len(res.committed) < need {
		dctx, cancel := detached(ctx)
		defer cancel()
		for _, i := range res.committed {
			if err := res.commits[i].Rollback(dctx); err != nil {
				x.log.Warn("xl: could not roll back commit", "bucket", spec.bucket, "object", spec.object, "drive", i, "err", err)
			}
		}
		return quorumError(spec.bucket, spec.object, len(res.committed), need, res.errs)
	}
	x.finish(ctx, spec, res)
	// Drives that missed the commit are stale; have the scanner repair them.
	if len(res.committed) < len(x.drives) {
		x.queueHeal(spec.bucket, spec.object)
	}
	return nil
}

// toInfo converts a version to the API-facing description. state is the
// bucket's versioning state, which decides how the version ID is reported.
func toInfo(bucket, object string, v *meta.Version, latest bool, state storage.VersioningState) storage.ObjectInfo {
	info := storage.ObjectInfo{
		Bucket: bucket, Name: object, VersionID: storage.ReportedVersionID(state, v.VersionID), IsLatest: latest,
		DeleteMarker: v.Type == meta.TypeDeleteMarker,
		Size:         v.Size, ModTime: v.ModTime, ETag: v.ETag, ContentType: v.ContentType,
		UserDefined: copyMap(v.UserMeta), StorageClass: v.StorageClass,
	}
	for _, p := range v.Parts {
		info.Parts = append(info.Parts, storage.PartInfo{Number: p.N, ETag: p.ETag, Size: p.Size})
	}
	info.Retention, info.LegalHold = objlock.Info(v.Lock)
	if t := v.Transition; t != nil {
		info.Transition = &storage.TransitionInfo{Tier: t.Tier, Object: t.Object, VersionID: t.VersionID, Time: t.Time}
	}
	return info
}

func trimETag(s string) string { return strings.Trim(s, `"`) }

// checkPreconditions evaluates If-Match / If-None-Match for a write
// against the current state. A latest delete marker counts as "the object
// does not exist".
func checkPreconditions(st *objState, readQuorum int, opts storage.PutOptions, bucket, object string) error {
	var cur *meta.Version
	if st.found(readQuorum) {
		if l := st.latest(); l != nil && l.Type == meta.TypeObject {
			cur = l
		}
	}
	if opts.IfNoneMatch == "*" && cur != nil {
		return storage.Wrap(storage.ErrPreconditionFailed, bucket, object)
	}
	if opts.IfMatch != "" && (cur == nil || trimETag(opts.IfMatch) != "*" && trimETag(opts.IfMatch) != cur.ETag) {
		return storage.Wrap(storage.ErrPreconditionFailed, bucket, object)
	}
	return nil
}
