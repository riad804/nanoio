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
	"nanoio/internal/storage/xl/disk"
)

// driveMeta is what one drive says about an object.
type driveMeta struct {
	file   *meta.File
	ver    *meta.Version // latest version, nil when none
	absent bool          // definitively not present (ENOENT)
	err    error         // unreadable: offline, corrupt, I/O error
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
	v := f.Latest()
	if v == nil || v.Type != meta.TypeObject {
		return driveMeta{absent: true, file: f}
	}
	return driveMeta{file: f, ver: v}
}

// objState is the quorum view of one object.
type objState struct {
	metas   []driveMeta
	ver     *meta.Version // a version from the winning group
	agree   []int         // drives whose metadata matches ver
	absent  int
	corrupt int
	failed  int // offline or unreadable for another reason
	stale   int // answered with a different version than the winning one
}

// fingerprint identifies a version for agreement: everything that must be
// identical on every drive of one write. Per-drive fields (shard index,
// checksums) are excluded.
func fingerprint(v *meta.Version) string {
	e := v.Erasure
	if e == nil {
		return "no-erasure"
	}
	return fmt.Sprintf("%d|%d|%s|%d|%s|%d|%d|%d|%s", v.Generation, v.ModTime.UnixNano(), v.ETag, v.Size, v.DataDir,
		e.DataBlocks, e.ParityBlocks, e.BlockSize, v.ContentType)
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
	for got := 0; got < n; got++ {
		a := <-ch
		st.metas[a.i] = a.m
		done := false
		switch {
		case a.m.ver != nil:
			fp := fingerprint(a.m.ver)
			counts[fp]++
			done = counts[fp] >= x.k
		case a.m.absent:
			absent++
			done = absent > n-x.k
		}
		if done {
			break
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
		case m.ver != nil:
			fp := fingerprint(m.ver)
			groups[fp] = append(groups[fp], i)
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
			// Tie: prefer the newer write.
			better = st.metas[idxs[0]].ver.ModTime.After(st.metas[groups[bestFP][0]].ver.ModTime)
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
		st.ver = st.metas[st.agree[0]].ver
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
func (x *XL) versionFor(tmpl meta.Version, dist []int, drive int, sums []meta.Checksum, blockSize int64) meta.Version {
	v := tmpl
	v.Erasure = &meta.Erasure{
		Algorithm: algorithm, DataBlocks: x.k, ParityBlocks: x.m, BlockSize: blockSize,
		Index: dist[drive], Distribution: dist, Checksums: sums,
	}
	return v
}

// commitSpec describes publishing one staged object on every drive.
type commitSpec struct {
	bucket, object string
	stageID        string
	dataDir        string
	tmpl           meta.Version // version without Erasure; ModTime set
	dist           []int
	blockSize      int64
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
}

// nextGeneration is the generation a write based on st should carry, and
// the generation the drives must not exceed for it to commit. An object
// that is not (yet) present at quorum starts at 1.
func nextGeneration(st *objState, readQuorum int) (next, prev uint64) {
	if st.found(readQuorum) {
		prev = st.ver.Generation
	}
	return prev + 1, prev
}

// commitResult is the outcome on the drives that took part.
type commitResult struct {
	committed []int
	errs      []error
	commits   []disk.Commit
}

// errStraggler marks a drive whose commit had not answered when the write
// quorum was reached.
var errStraggler = errors.New("commit still in flight when the write quorum was reached")

// commit publishes the staged object on the participating drives; each
// drive's CommitObject is atomic on that drive. It returns when spec.need
// drives have committed and StragglerGrace has passed for the rest (all
// drives when need is 0, as for repairs). Commits still in flight then are
// finished in the background if they succeed, and a delayed commit that
// lands after a newer write is refused by that drive's generation check.
// The caller decides, by quorum, whether to Finish or Rollback.
func (x *XL) commit(ctx context.Context, spec commitSpec) commitResult {
	n := len(x.drives)
	res := commitResult{errs: make([]error, n), commits: make([]disk.Commit, n)}
	// The calls run detached from the request: a drive that has begun a
	// commit finishes it, and the bookkeeping below settles it either way.
	cctx, cancel := detached(ctx)
	type outcome struct {
		i   int
		c   disk.Commit
		err error
	}
	ch := make(chan outcome, n)
	launched := 0
	for i, d := range x.drives {
		if !spec.participants[i] {
			res.errs[i] = errDriveOffline
			continue
		}
		launched++
		go func() {
			c, err := d.CommitObject(cctx, disk.CommitRequest{
				Bucket: spec.bucket, Object: spec.object, StageID: spec.stageID, DataDir: spec.dataDir,
				Version:  x.versionFor(spec.tmpl, spec.dist, i, spec.sums[i], spec.blockSize),
				CheckGen: spec.checkGen, PrevGen: spec.prevGen,
			})
			ch <- outcome{i, c, err}
		}()
	}
	need := spec.need
	if need <= 0 || need > launched {
		need = launched
	}
	seen := make([]bool, n)
	got, ok := 0, 0
	var grace <-chan time.Time
	for got < launched {
		select {
		case o := <-ch:
			got++
			seen[o.i] = true
			res.commits[o.i], res.errs[o.i] = o.c, o.err
			if o.err == nil {
				ok++
				res.committed = append(res.committed, o.i)
			}
			if ok >= need && grace == nil && got < launched {
				t := time.NewTimer(x.stragglerGrace)
				defer t.Stop()
				grace = t.C
			}
			continue
		case <-grace:
		}
		break
	}
	sort.Ints(res.committed)
	if got == launched {
		cancel()
		return res
	}
	for i := range res.errs {
		if spec.participants[i] && !seen[i] {
			res.errs[i] = errStraggler
		}
	}
	remaining := launched - got
	go func() {
		defer cancel()
		fctx, fcancel := detached(ctx)
		defer fcancel()
		for k := 0; k < remaining; k++ {
			if o := <-ch; o.err == nil {
				if err := o.c.Finish(fctx); err != nil {
					x.log.Warn("xl: could not finish a late commit", "bucket", spec.bucket, "object", spec.object, "drive", o.i, "err", err)
				}
			}
		}
	}()
	return res
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
// final and removes staging; on failure it rolls every drive back. The
// follow-up runs detached from ctx: a client that gave up must not leave a
// half-committed object behind.
func (x *XL) finishCommit(ctx context.Context, spec commitSpec, res commitResult) error {
	need := x.writeQuorum()
	if len(res.committed) < need {
		dctx, cancel := detached(ctx)
		defer cancel()
		for _, i := range res.committed {
			if err := res.commits[i].Rollback(dctx); err != nil {
				x.log.Warn("xl: could not roll back commit", "bucket", spec.bucket, "object", spec.object, "drive", i, "err", err)
			}
		}
		x.removeStages(ctx, spec.stageID)
		return quorumError(spec.bucket, spec.object, len(res.committed), need, res.errs)
	}
	x.finish(ctx, spec, res)
	x.removeStages(ctx, spec.stageID)
	// Drives that missed the commit are stale; have the scanner repair them.
	if len(res.committed) < len(x.drives) {
		x.queueHeal(spec.bucket, spec.object)
	}
	return nil
}

// objectInfo converts a version to the API-facing description.
func toInfo(bucket, object string, v *meta.Version) storage.ObjectInfo {
	info := storage.ObjectInfo{
		Bucket: bucket, Name: object, VersionID: v.VersionID, IsLatest: true,
		Size: v.Size, ModTime: v.ModTime, ETag: v.ETag, ContentType: v.ContentType,
		UserDefined: copyMap(v.UserMeta),
	}
	for _, p := range v.Parts {
		info.Parts = append(info.Parts, storage.PartInfo{Number: p.N, ETag: p.ETag, Size: p.Size})
	}
	return info
}

func trimETag(s string) string { return strings.Trim(s, `"`) }

// checkPreconditions evaluates If-Match / If-None-Match for a write
// against the current state.
func checkPreconditions(st *objState, readQuorum int, opts storage.PutOptions, bucket, object string) error {
	var cur *meta.Version
	if st.found(readQuorum) {
		cur = st.ver
	}
	if opts.IfNoneMatch == "*" && cur != nil {
		return storage.Wrap(storage.ErrPreconditionFailed, bucket, object)
	}
	if opts.IfMatch != "" && (cur == nil || trimETag(opts.IfMatch) != "*" && trimETag(opts.IfMatch) != cur.ETag) {
		return storage.Wrap(storage.ErrPreconditionFailed, bucket, object)
	}
	return nil
}
