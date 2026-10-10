package xl

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"nanoio/internal/meta"
	"nanoio/internal/storage"
	"nanoio/internal/storage/xl/disk"
)

type healReq struct{ bucket, object string }

// queueHeal asks the scanner to repair an object soon. It never blocks and
// coalesces duplicates; a full queue drops the request, which the periodic
// scan will rediscover.
func (x *XL) queueHeal(bucket, object string) {
	select {
	case x.healQ <- healReq{bucket, object}:
	default:
	}
}

// startScanner launches the background goroutine that repairs queued
// objects immediately and runs a full Scan every interval.
func (x *XL) startScanner(interval time.Duration) {
	x.scanDone = make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	x.scanCancel = cancel
	if interval == 0 {
		interval = time.Hour
	}
	go func() {
		defer close(x.scanDone)
		var tick <-chan time.Time
		if interval > 0 {
			t := time.NewTicker(interval)
			defer t.Stop()
			tick = t.C
		}
		pending := map[healReq]bool{}
		for {
			select {
			case <-ctx.Done():
				return
			case req := <-x.healQ:
				if pending[req] {
					continue
				}
				pending[req] = true
				if len(pending) > 4096 {
					pending = map[healReq]bool{}
				}
				res, err := x.HealObject(ctx, req.bucket, req.object, false)
				delete(pending, req)
				switch {
				case errors.Is(err, context.Canceled), errors.Is(err, storage.ErrBackendUnavailable) && x.isClosed():
					return
				case err != nil:
					x.log.Warn("xl: heal failed", "bucket", req.bucket, "object", req.object, "err", err)
				case len(res.Healed) > 0 || res.Dangling:
					x.log.Info("xl: healed", "bucket", req.bucket, "object", req.object, "drives", res.Healed, "dangling", res.Dangling)
				}
			case <-tick:
				stats, err := x.scan(ctx, false)
				switch {
				case errors.Is(err, context.Canceled):
					return
				case err != nil:
					x.log.Warn("xl: scan failed", "err", err)
				case stats.changed() > 0:
					x.log.Info("xl: scan", "objects", stats.Objects, "shardsHealed", stats.ShardsHealed,
						"dangling", stats.Dangling, "expiredUploads", stats.ExpiredUploads,
						"orphans", stats.OrphanDirs, "staging", stats.Staging, "drivesFormatted", stats.DrivesFormatted)
				}
			}
		}
	}()
}

func (x *XL) isClosed() bool {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.closed
}

// HealResult reports what HealObject did.
type HealResult struct {
	Bucket, Object string
	// Healed lists the drives whose copy was rebuilt.
	Healed []int
	// Dangling is true when shards that could never be read (below read
	// quorum on a fully responsive set) were removed.
	Dangling bool
	// Skipped explains why nothing was done: "healthy", "absent",
	// "changed" (the object was rewritten while healing) or
	// "indeterminate" (too many drives unavailable to decide).
	Skipped string
}

// shardsHealthy checks one drive's copy of an object against the agreed
// version: its metadata matches and every part's shard file exists with the
// right size. With deep it also re-reads every block and verifies its hash
// and the checksum root recorded in xl.meta.
func (x *XL) shardsHealthy(ctx context.Context, d *drive, st *objState, bucket, object string, deep bool) bool {
	i := d.idx
	m := st.metas[i]
	if m.ver == nil || fingerprint(m.ver) != fingerprint(st.ver) {
		return false
	}
	e := st.ver.Erasure
	parts := st.ver.Parts
	if len(parts) == 0 {
		parts = []meta.Part{{N: 1, Size: st.ver.Size}}
	}
	for _, p := range parts {
		size, err := d.StatShard(ctx, bucket, object, st.ver.DataDir, p.N)
		if err != nil || size != disk.ShardFileSize(p.Size, e.BlockSize, x.k) {
			return false
		}
		if !deep {
			continue
		}
		root, err := d.VerifyShard(ctx, bucket, object, st.ver.DataDir, p.N, p.Size, e.BlockSize, x.k)
		if err != nil {
			return false
		}
		for _, c := range m.ver.Erasure.Checksums {
			if c.Part == p.N && c.Hash != "" && c.Hash != root {
				return false
			}
		}
	}
	return true
}

// HealObject repairs one object: shards that are missing, outdated or
// corrupt on any usable drive are reconstructed from the intact ones and
// published, and shards that can never be read are removed. deep also
// verifies every block's hash on every drive (bitrot scrub).
//
// Reconstruction runs under the shared lock, so readers are not blocked;
// the exclusive lock is taken only for the commit, after re-checking that
// the object has not been rewritten in the meantime.
func (x *XL) HealObject(ctx context.Context, bucket, object string, deep bool) (HealResult, error) {
	res := HealResult{Bucket: bucket, Object: object}
	if err := validate(bucket, object); err != nil {
		return res, err
	}
	if err := x.enter(ctx); err != nil {
		return res, err
	}
	defer x.leave()

	// Phase 1: diagnose and reconstruct under the shared lock.
	unlockR, err := x.locker.RLock(ctx, bucket, object)
	if err != nil {
		return res, err
	}
	st := x.stateOfAll(ctx, bucket, object)
	if !st.found(x.k) {
		unlockR()
		return x.healDangling(ctx, bucket, object, st)
	}
	var need, good []int
	for i, d := range x.drives {
		if !d.Ready(ctx) {
			continue
		}
		if x.shardsHealthy(ctx, d, st, bucket, object, deep) {
			good = append(good, i)
		} else {
			need = append(need, i)
		}
	}
	x.log.Debug("xl: heal diagnosis", "bucket", bucket, "object", object, "need", need, "good", good, "deep", deep)
	if len(need) == 0 {
		unlockR()
		res.Skipped = "healthy"
		return res, nil
	}
	if len(good) < x.k {
		unlockR()
		return res, storage.Wrap(fmt.Errorf("%w: %d intact copies, %d needed to rebuild",
			storage.ErrCorrupted, len(good), x.k), bucket, object)
	}
	ver := *st.ver
	e := ver.Erasure
	dist := e.Distribution
	if len(dist) != len(x.drives) {
		unlockR()
		return res, storage.Wrap(fmt.Errorf("%w: object has no valid distribution", storage.ErrCorrupted), bucket, object)
	}
	token, err := newToken()
	if err != nil {
		unlockR()
		return res, err
	}
	stageID := "heal-" + token
	defer x.removeStages(ctx, stageID)
	participants := make([]bool, len(x.drives))
	for _, i := range need {
		participants[i] = true // cleared by rebuildPart if the drive cannot take its shard
	}
	parts := ver.Parts
	if len(parts) == 0 {
		parts = []meta.Part{{N: 1, Size: ver.Size}}
	}
	roots := make([]map[int]string, len(x.drives)) // drive -> part -> root
	for _, i := range need {
		roots[i] = map[int]string{}
	}
	for _, p := range parts {
		if err := ctx.Err(); err != nil {
			unlockR()
			return res, err
		}
		got, err := x.rebuildPart(ctx, bucket, object, st, good, need, participants, stageID, p, e.BlockSize)
		if err != nil {
			unlockR()
			return res, err
		}
		for i, root := range got {
			roots[i][p.N] = root
		}
	}
	unlockR()

	// Phase 2: publish under the exclusive lock, if nothing changed.
	unlockBucket, err := x.locker.RLock(ctx, bucket, "")
	if err != nil {
		return res, err
	}
	defer unlockBucket()
	unlockKey, err := x.locker.Lock(ctx, bucket, object)
	if err != nil {
		return res, err
	}
	defer unlockKey()
	st2 := x.stateOfAll(ctx, bucket, object)
	if !st2.found(x.k) || fingerprint(st2.ver) != fingerprint(st.ver) {
		res.Skipped = "changed"
		return res, nil
	}
	x.log.Debug("xl: heal publishing", "bucket", bucket, "object", object, "need", need, "participants", participants)
	sums := make([][]meta.Checksum, len(x.drives))
	for _, i := range need {
		if !participants[i] {
			continue
		}
		for _, p := range parts {
			sums[i] = append(sums[i], meta.Checksum{Part: p.N, Algorithm: hashAlgorithm, Hash: roots[i][p.N]})
		}
	}
	tmpl := ver
	tmpl.Erasure = nil
	spec := commitSpec{bucket: bucket, object: object, stageID: stageID, dataDir: ver.DataDir, tmpl: tmpl,
		dist: dist, blockSize: e.BlockSize, sums: sums, participants: participants}
	cres := x.commit(ctx, spec)
	x.log.Debug("xl: heal committed", "bucket", bucket, "object", object, "committed", cres.committed, "errs", fmt.Sprint(cres.errs))
	res.Healed = cres.committed
	// A drive that held an older version keeps its superseded data
	// directory until now; Finish drops it, as an ordinary overwrite would.
	x.finish(ctx, spec, cres)
	for i, err := range cres.errs {
		if err != nil && participants[i] && !errors.Is(err, errDriveOffline) {
			x.log.Warn("xl: heal commit failed", "bucket", bucket, "object", object, "drive", i, "err", err)
		}
	}
	return res, nil
}

// rebuildPart reconstructs part p onto the need drives' staging files and
// returns each drive's checksum root.
func (x *XL) rebuildPart(ctx context.Context, bucket, object string, st *objState, good, need []int,
	participants []bool, stageID string, p meta.Part, blockSize int64) (map[int]string, error) {
	e := st.ver.Erasure
	n := x.k + x.m
	// Open one source per good drive, keyed by the shard it holds.
	type src struct {
		f     disk.Shard
		shard int
	}
	var srcs []src
	defer func() {
		for _, s := range srcs {
			s.f.Close()
		}
	}()
	for _, i := range good {
		f, err := x.drives[i].OpenShard(ctx, bucket, object, st.ver.DataDir, p.N)
		if err != nil {
			continue
		}
		srcs = append(srcs, src{f: f, shard: st.metas[i].ver.Erasure.Index})
	}
	if len(srcs) < x.k {
		return nil, storage.Wrap(fmt.Errorf("%w: cannot open enough shards of part %d", storage.ErrCorrupted, p.N), bucket, object)
	}
	// Writers indexed by drive; the shard each takes is dist[drive].
	writers := make(map[int]*shardWriter)
	for _, i := range need {
		if !participants[i] {
			continue
		}
		w, err := newShardWriter(ctx, x.drives[i], stageID, fmt.Sprintf("%s/part.%d", st.ver.DataDir, p.N), x.writeQueue)
		if err != nil {
			participants[i] = false
			continue
		}
		writers[i] = w
	}
	abort := func() {
		for i, w := range writers {
			w.abort()
			participants[i] = false
		}
	}
	for b := int64(0); b < disk.BlockCount(p.Size, blockSize); b++ {
		if err := ctx.Err(); err != nil {
			abort()
			return nil, err
		}
		blockLen := min(blockSize, p.Size-b*blockSize)
		shards := make([][]byte, n)
		have := 0
		for _, s := range srcs {
			if have >= x.k {
				break
			}
			buf, err := readVerifiedShard(s.f, b, blockLen, blockSize, x.k)
			if err != nil {
				continue // a shard that failed verification mid-heal is skipped
			}
			shards[s.shard] = buf
			have++
		}
		if have < x.k {
			abort()
			return nil, storage.Wrap(fmt.Errorf("%w: block %d of part %d has only %d intact shards",
				storage.ErrCorrupted, b, p.N, have), bucket, object)
		}
		if err := x.enc.Reconstruct(shards); err != nil {
			abort()
			return nil, storage.Wrap(fmt.Errorf("%w: reconstruct: %v", storage.ErrCorrupted, err), bucket, object)
		}
		for i, w := range writers {
			if !w.failed() {
				w.enqueue(ctx, shards[e.Distribution[i]], false)
			}
		}
	}
	roots := map[int]string{}
	for i, w := range writers {
		root, err := w.wait(ctx)
		if err != nil {
			participants[i] = false
			continue
		}
		roots[i] = root
	}
	return roots, nil
}

// healDangling removes shards of an object that exists on fewer than K
// drives while every drive answered: it can never have reached a write
// quorum (a failed write's remnant) or has lost too many shards to ever be
// read. With any drive unavailable it does nothing, since the missing
// drives might hold the rest.
func (x *XL) healDangling(ctx context.Context, bucket, object string, st *objState) (HealResult, error) {
	res := HealResult{Bucket: bucket, Object: object}
	if st.ver == nil && st.corrupt == 0 {
		res.Skipped = "absent"
		return res, nil
	}
	if st.failed > 0 {
		res.Skipped = "indeterminate"
		return res, nil
	}
	unlockBucket, err := x.locker.RLock(ctx, bucket, "")
	if err != nil {
		return res, err
	}
	defer unlockBucket()
	unlockKey, err := x.locker.Lock(ctx, bucket, object)
	if err != nil {
		return res, err
	}
	defer unlockKey()
	st = x.stateOfAll(ctx, bucket, object) // re-read under the exclusive lock
	if st.found(x.k) || st.failed > 0 {
		res.Skipped = "changed"
		return res, nil
	}
	errs := x.each(ctx, func(d *drive) error { return d.DeleteObject(ctx, bucket, object) })
	if countNil(errs) == 0 {
		return res, quorumError(bucket, object, 0, 1, errs)
	}
	res.Dangling = true
	return res, nil
}

// HealBucket recreates a bucket directory (with its marker) on every ready
// drive that lacks it, provided a read quorum has it.
func (x *XL) HealBucket(ctx context.Context, bucket string) ([]int, error) {
	if err := storage.ValidateBucketName(bucket); err != nil {
		return nil, err
	}
	if err := x.enter(ctx); err != nil {
		return nil, err
	}
	defer x.leave()
	unlock, err := x.locker.Lock(ctx, bucket, "")
	if err != nil {
		return nil, err
	}
	defer unlock()
	return x.healBucket(ctx, bucket)
}

func (x *XL) healBucket(ctx context.Context, bucket string) ([]int, error) {
	if ok, err := x.bucketExists(ctx, bucket); err != nil || !ok {
		return nil, err
	}
	created := x.bucketCreated(ctx, bucket)
	var healed []int
	for _, d := range x.drives {
		if !d.Ready(ctx) {
			continue
		}
		if exists, _, err := d.StatBucket(ctx, bucket); err != nil || exists {
			continue
		}
		if made, err := d.MakeBucket(ctx, bucket, created); err == nil && made {
			healed = append(healed, d.idx)
		}
	}
	return healed, nil
}

// reviveDrive re-opens a drive that went away. A blank, existing directory
// is formatted and joins the set (the scanner then repopulates it); a
// directory that no longer exists, or a drive that belongs to a different
// deployment or position, is left alone.
func (x *XL) reviveDrive(ctx context.Context, d *drive) bool {
	if d.Ready(ctx) {
		return false
	}
	// Only adopt a directory somebody put there: Open(false) refuses a
	// drive whose directory has vanished (a disk that was unmounted or
	// removed), since recreating the path would quietly fill whatever now
	// sits underneath it, typically the root filesystem, with shards.
	d.Close()
	f, err := d.Open(ctx, false)
	switch {
	case errors.Is(err, disk.ErrUnformatted):
		if err := x.writeFormat(ctx, d); err != nil {
			d.Close()
			return false
		}
		return true
	case err != nil:
		return false
	}
	if f.DeploymentID != x.deploymentID || f.Index != d.idx || f.DataBlocks != x.k || f.ParityBlocks != x.m {
		x.log.Warn("xl: drive belongs to a different set; leaving it offline", "drive", d.idx, "disk", d.String())
		d.Close()
		return false
	}
	return true
}

// ScanStats counts what a scan did.
type ScanStats struct {
	DrivesFormatted int
	Buckets         int
	BucketsHealed   int
	Objects         int
	ShardsHealed    int // object copies rebuilt, summed over drives
	Dangling        int
	Unrecoverable   int
	ExpiredUploads  int // per-drive upload directories removed
	OrphanDirs      int
	Staging         int
}

func (s ScanStats) changed() int {
	return s.DrivesFormatted + s.BucketsHealed + s.ShardsHealed + s.Dangling + s.ExpiredUploads + s.OrphanDirs + s.Staging
}

// Scan runs one full maintenance pass: revive and format replacement
// drives, recreate missing bucket directories, heal every object, expire
// abandoned uploads, remove orphaned data directories and sweep staging.
// deep additionally verifies every block's hash on every drive.
func (x *XL) Scan(ctx context.Context, deep bool) (ScanStats, error) {
	if err := x.enter(ctx); err != nil {
		return ScanStats{}, err
	}
	defer x.leave()
	return x.scan(ctx, deep)
}

func (x *XL) scan(ctx context.Context, deep bool) (ScanStats, error) {
	var st ScanStats
	for _, d := range x.drives {
		if x.reviveDrive(ctx, d) {
			st.DrivesFormatted++
		}
	}
	for _, d := range x.drives {
		if d.Ready(ctx) {
			st.Staging += x.sweepTmp(ctx, d, x.tmpMaxAge)
		}
	}
	buckets := x.bucketNames(ctx)
	for _, bucket := range buckets {
		if err := ctx.Err(); err != nil {
			return st, err
		}
		ok, err := x.bucketExists(ctx, bucket)
		if err != nil || !ok {
			continue
		}
		st.Buckets++
		if healed, _ := x.healBucket(ctx, bucket); len(healed) > 0 {
			st.BucketsHealed += len(healed)
		}
		for _, key := range x.allKeys(ctx, bucket) {
			if err := ctx.Err(); err != nil {
				return st, err
			}
			res, err := x.HealObject(ctx, bucket, key, deep)
			switch {
			case errors.Is(err, context.Canceled):
				return st, err
			case err != nil:
				st.Unrecoverable++
				x.log.Warn("xl: object could not be healed", "bucket", bucket, "object", key, "err", err)
				continue
			}
			st.Objects++
			st.ShardsHealed += len(res.Healed)
			if res.Dangling {
				st.Dangling++
			}
		}
		st.OrphanDirs += x.collectOrphans(ctx, bucket)
	}
	st.ExpiredUploads += x.expireUploads(ctx)
	return st, nil
}

// bucketNames is the union of bucket directories on all ready drives.
func (x *XL) bucketNames(ctx context.Context) []string {
	seen := map[string]bool{}
	var names []string
	for _, d := range x.drives {
		list, err := d.ListBuckets(ctx)
		if err != nil {
			continue
		}
		for _, name := range list {
			if !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
	}
	return names
}

// allKeys is the union of keys across every ready drive, so stray shards
// on a single drive are found too.
func (x *XL) allKeys(ctx context.Context, bucket string) []string {
	seen := map[string]bool{}
	var keys []string
	var mu sync.Mutex
	var wg syncWG
	for _, d := range x.drives {
		if !d.Ready(ctx) {
			continue
		}
		wg.Go(func() {
			ks, err := d.ListKeys(ctx, bucket, "")
			if err != nil {
				return
			}
			mu.Lock()
			for _, k := range ks {
				if !seen[k] {
					seen[k] = true
					keys = append(keys, k)
				}
			}
			mu.Unlock()
		})
	}
	wg.Wait()
	return keys
}

// collectOrphans removes data directories that no xl.meta on their drive
// references, under the key's exclusive lock so a commit in flight is never
// mistaken for garbage. The drive re-checks references and pins when it
// removes; directories next to unreadable metadata are never reported.
func (x *XL) collectOrphans(ctx context.Context, bucket string) int {
	removed := 0
	for _, d := range x.drives {
		if !d.Ready(ctx) {
			continue
		}
		orphans, err := d.FindOrphans(ctx, bucket)
		if err != nil {
			continue
		}
		for _, o := range orphans {
			if ctx.Err() != nil {
				return removed
			}
			removed += x.removeOrphans(ctx, d, bucket, o)
		}
	}
	return removed
}

func (x *XL) removeOrphans(ctx context.Context, d *drive, bucket string, o disk.Orphan) int {
	ub, err := x.locker.RLock(ctx, bucket, "")
	if err != nil {
		return 0
	}
	defer ub()
	uk, err := x.locker.Lock(ctx, bucket, o.Object)
	if err != nil {
		return 0
	}
	defer uk()
	n, _ := d.RemoveOrphans(ctx, bucket, o.Object, o.DataDirs)
	return n
}

// expireUploads removes, per drive, uploads with no activity within the
// expiry window (or whose bucket is gone). Staleness is judged per drive,
// first to pick candidates and again under the upload's lock.
func (x *XL) expireUploads(ctx context.Context) int {
	removed := 0
	for _, d := range x.drives {
		if !d.Ready(ctx) {
			continue
		}
		stale, err := d.StaleUploads(ctx, x.uploadExpiry)
		if err != nil {
			continue
		}
		for _, u := range stale {
			if ctx.Err() != nil {
				return removed
			}
			ub, err := x.locker.RLock(ctx, u.Bucket, "")
			if err != nil {
				continue
			}
			ul, err := x.locker.Lock(ctx, u.Bucket, uploadLockKey(u.ID))
			if err != nil {
				ub()
				continue
			}
			if ok, _ := d.DiscardUploadIfStale(ctx, u.Bucket, u.ID, x.uploadExpiry); ok {
				removed++
			}
			ul()
			ub()
		}
	}
	return removed
}
