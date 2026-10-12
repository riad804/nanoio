package xl

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	"nanoio/internal/meta"
	"nanoio/internal/storage"
	"nanoio/internal/storage/internal/listing"
	"nanoio/internal/storage/internal/objlock"
	"nanoio/internal/storage/xl/disk"
)

// Multipart state lives on every drive, behind disk.Disk's upload methods:
// an upload descriptor, and per part this drive's record and shard stream.
// Each part is erasure coded exactly like an object part, with the layout
// fixed when the upload was created. Completion hard-links the shard files
// into a staged data directory on every drive and publishes with the normal
// commit, so the finished object needs no data copy.
const (
	maxParts    = 10000
	maxPartSize = 5 << 30
)

var (
	uploadIDRE  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	errNoUpload = errors.New("upload not found on drive")
)

type uploadDoc struct {
	Bucket       string            `json:"bucket"`
	Object       string            `json:"object"`
	Initiated    time.Time         `json:"initiated"`
	ContentType  string            `json:"contentType,omitempty"`
	UserDefined  map[string]string `json:"userDefined,omitempty"`
	DataBlocks   int               `json:"dataBlocks"`
	ParityBlocks int               `json:"parityBlocks"`
	BlockSize    int64             `json:"blockSize"`
	Distribution []int             `json:"distribution"`
	// Lock is the object lock requested when the upload was started.
	Lock objlock.Requested `json:"lock,omitzero"`
}

func uploadLockKey(id string) string { return storage.DataDirPrefix + "upload-" + id }

func checkUploadID(bucket, object, id string) error {
	if !uploadIDRE.MatchString(id) {
		return storage.Wrap(storage.ErrNoSuchUpload, bucket, object)
	}
	return nil
}

// readUploadDoc loads one drive's upload descriptor.
func readUploadDoc(ctx context.Context, d *drive, bucket, id string) (*uploadDoc, error) {
	data, err := d.ReadUpload(ctx, bucket, id)
	if err != nil {
		if errors.Is(err, disk.ErrNotFound) {
			return nil, errNoUpload
		}
		return nil, err
	}
	var doc uploadDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%w: %v", storage.ErrCorrupted, err)
	}
	return &doc, nil
}

// readUpload returns the upload descriptor agreed by a read quorum.
func (x *XL) readUpload(ctx context.Context, bucket, object, id string) (*uploadDoc, error) {
	docs := make([]*uploadDoc, len(x.drives))
	errs := x.each(ctx, func(d *drive) error {
		doc, err := readUploadDoc(ctx, d, bucket, id)
		docs[d.idx] = doc
		return err
	})
	groups := map[string][]int{}
	absent := 0
	for i, err := range errs {
		switch {
		case err == nil:
			key := fmt.Sprintf("%s|%d", docs[i].Object, docs[i].Initiated.UnixNano())
			groups[key] = append(groups[key], i)
		case errors.Is(err, errNoUpload):
			absent++
		}
	}
	for _, idxs := range groups {
		if len(idxs) >= x.k {
			doc := docs[idxs[0]]
			if doc.Bucket != bucket || (object != "" && doc.Object != object) {
				return nil, storage.Wrap(storage.ErrNoSuchUpload, bucket, object)
			}
			if doc.DataBlocks != x.k || doc.ParityBlocks != x.m || len(doc.Distribution) != len(x.drives) {
				return nil, storage.Wrap(fmt.Errorf("%w: upload was created with a different erasure layout", storage.ErrCorrupted), bucket, object)
			}
			return doc, nil
		}
	}
	if absent > len(x.drives)-x.k || len(groups) == 0 && absent > 0 && countNil(errs)+absent >= x.k {
		return nil, storage.Wrap(storage.ErrNoSuchUpload, bucket, object)
	}
	return nil, storage.Wrap(fmt.Errorf("%w: upload metadata quorum not met", storage.ErrBackendUnavailable), bucket, object)
}

// NewMultipartUpload starts an upload and returns its ID.
func (x *XL) NewMultipartUpload(ctx context.Context, bucket, object string, opts storage.PutOptions) (string, error) {
	if err := validate(bucket, object); err != nil {
		return "", err
	}
	if err := x.enter(ctx); err != nil {
		return "", err
	}
	defer x.leave()
	unlock, err := x.locker.RLock(ctx, bucket, "")
	if err != nil {
		return "", err
	}
	defer unlock()
	if err := x.requireBucket(ctx, bucket); err != nil {
		return "", err
	}
	id, err := meta.NewVersionID()
	if err != nil {
		return "", err
	}
	ct := opts.ContentType
	if ct == "" {
		ct = defaultCT
	}
	settings, err := x.versioning(ctx, bucket)
	if err != nil {
		return "", mapErr(err, bucket, object)
	}
	req, err := objlock.Request(settings.lock.cfg, opts, time.Now())
	if err != nil {
		return "", storage.Wrap(err, bucket, object)
	}
	docBytes, err := json.Marshal(uploadDoc{
		Bucket: bucket, Object: object, Initiated: time.Now().UTC(), ContentType: ct,
		UserDefined: copyMap(opts.UserDefined), DataBlocks: x.k, ParityBlocks: x.m,
		BlockSize: x.blockSize, Distribution: x.distribution(bucket, object), Lock: req,
	})
	if err != nil {
		return "", err
	}
	errs := x.each(ctx, func(d *drive) error { return d.CreateUpload(ctx, bucket, id, docBytes) })
	if countNil(errs) < x.writeQuorum() {
		dctx, cancel := detached(ctx)
		defer cancel()
		x.each(dctx, func(d *drive) error { return d.DiscardUpload(dctx, bucket, id) })
		return "", quorumError(bucket, object, countNil(errs), x.writeQuorum(), errs)
	}
	return id, nil
}

// drivePartDocs loads the committed parts of an upload on one drive. A part
// whose record or shard file is missing or the wrong size is not listed.
func (x *XL) drivePartDocs(ctx context.Context, d *drive, bucket, id string) map[int]disk.PartRecord {
	out := map[int]disk.PartRecord{}
	recs, err := d.ListParts(ctx, bucket, id)
	if err != nil {
		return out
	}
	for _, r := range recs {
		out[r.Number] = r
	}
	return out
}

// partsQuorum returns, per part number, the record agreed by a read
// quorum of drives and the drives holding it.
func (x *XL) partsQuorum(ctx context.Context, bucket, id string) (map[int]disk.PartRecord, map[int][]int) {
	perDrive := make([]map[int]disk.PartRecord, len(x.drives))
	x.each(ctx, func(d *drive) error {
		perDrive[d.idx] = x.drivePartDocs(ctx, d, bucket, id)
		return nil
	})
	type vote struct {
		doc    disk.PartRecord
		drives []int
	}
	byNum := map[int]map[string]*vote{}
	for i, docs := range perDrive {
		for n, pd := range docs {
			key := fmt.Sprintf("%s|%s|%d", pd.File, pd.ETag, pd.Size)
			if byNum[n] == nil {
				byNum[n] = map[string]*vote{}
			}
			v := byNum[n][key]
			if v == nil {
				v = &vote{doc: pd}
				byNum[n][key] = v
			}
			v.drives = append(v.drives, i)
		}
	}
	docs := map[int]disk.PartRecord{}
	holders := map[int][]int{}
	for n, votes := range byNum {
		for _, v := range votes {
			if len(v.drives) >= x.k {
				docs[n] = v.doc
				holders[n] = v.drives
			}
		}
	}
	return docs, holders
}

// PutObjectPart stores one part, erasure coded like an object.
func (x *XL) PutObjectPart(ctx context.Context, bucket, object, uploadID string, partNumber int,
	r io.Reader, size int64, opts storage.PartOptions) (storage.PartInfo, error) {
	var zero storage.PartInfo
	if err := validate(bucket, object); err != nil {
		return zero, err
	}
	if err := checkUploadID(bucket, object, uploadID); err != nil {
		return zero, err
	}
	if partNumber < 1 || partNumber > maxParts {
		return zero, storage.Wrap(fmt.Errorf("%w: part number %d is outside 1..%d", storage.ErrInvalidPart, partNumber, maxParts), bucket, object)
	}
	if size > maxPartSize {
		return zero, storage.Wrap(storage.ErrEntityTooLarge, bucket, object)
	}
	if err := x.enter(ctx); err != nil {
		return zero, err
	}
	defer x.leave()
	doc, err := x.readUpload(ctx, bucket, object, uploadID)
	if err != nil {
		return zero, err
	}

	token, err := newToken()
	if err != nil {
		return zero, err
	}
	stageID := "part-" + token
	defer x.removeStages(ctx, stageID)
	dataName := fmt.Sprintf("%d.%s.data", partNumber, token)
	ws, participants := x.openWriters(ctx, stageID, dataName, doc.Distribution)
	if live := countWriters(ws); live < x.writeQuorum() {
		abortWriters(ws)
		return zero, quorumError(bucket, object, live, x.writeQuorum(), nil)
	}
	md5h := md5.New()
	var shah = newSHA(opts.ContentSHA256)
	n, err := x.encodeStream(ctx, r, size, doc.BlockSize, ws, x.writeQuorum(), md5h, shah)
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
	roots, okDrives := x.settleWriters(ctx, ws, doc.Distribution, participants, x.writeQuorum())
	if live := countTrue(okDrives); live < x.writeQuorum() {
		return zero, quorumError(bucket, object, live, x.writeQuorum(), nil)
	}

	unlockBucket, err := x.locker.RLock(ctx, bucket, "")
	if err != nil {
		return zero, err
	}
	defer unlockBucket()
	unlockUpload, err := x.locker.Lock(ctx, bucket, uploadLockKey(uploadID))
	if err != nil {
		return zero, err
	}
	defer unlockUpload()
	if _, err := x.readUpload(ctx, bucket, object, uploadID); err != nil { // aborted or completed meanwhile
		return zero, err
	}

	now := time.Now().UTC()
	commits := make([]disk.Commit, len(x.drives))
	errs := x.each(ctx, func(d *drive) error {
		if !okDrives[d.idx] {
			return errDriveOffline
		}
		rec, err := json.Marshal(disk.PartRecord{Number: partNumber, File: dataName, Size: n, ETag: etag, ModTime: now,
			Root: roots[d.idx], ShardSize: disk.ShardFileSize(n, doc.BlockSize, x.k)})
		if err != nil {
			return err
		}
		c, err := d.CommitPart(ctx, disk.PartCommit{Bucket: bucket, UploadID: uploadID, StageID: stageID,
			DataFile: dataName, Number: partNumber, Record: rec})
		commits[d.idx] = c
		return err
	})
	dctx, dcancel := detached(ctx)
	defer dcancel()
	if countNil(errs) < x.writeQuorum() {
		for i, c := range commits {
			if c != nil && errs[i] == nil {
				c.Rollback(dctx)
			}
		}
		return zero, quorumError(bucket, object, countNil(errs), x.writeQuorum(), errs)
	}
	// Quorum reached: the replaced part's data is dropped only now.
	for i, c := range commits {
		if c != nil && errs[i] == nil {
			c.Finish(dctx)
		}
	}
	return storage.PartInfo{Number: partNumber, ETag: etag, Size: n, ModTime: now}, nil
}

// ListObjectParts lists the parts a read quorum of drives agrees on.
func (x *XL) ListObjectParts(ctx context.Context, bucket, object, uploadID string, opts storage.ListPartsOptions) (storage.ListPartsResult, error) {
	var zero storage.ListPartsResult
	if err := validate(bucket, object); err != nil {
		return zero, err
	}
	if err := checkUploadID(bucket, object, uploadID); err != nil {
		return zero, err
	}
	if err := x.enter(ctx); err != nil {
		return zero, err
	}
	defer x.leave()
	unlock, err := x.locker.RLock(ctx, bucket, uploadLockKey(uploadID))
	if err != nil {
		return zero, err
	}
	defer unlock()
	udoc, err := x.readUpload(ctx, bucket, object, uploadID)
	if err != nil {
		return zero, err
	}
	docs, _ := x.partsQuorum(ctx, bucket, uploadID)
	numbers := make([]int, 0, len(docs))
	for n := range docs {
		if n > opts.PartNumberMarker {
			numbers = append(numbers, n)
		}
	}
	sort.Ints(numbers)
	limit := opts.MaxParts
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	res := storage.ListPartsResult{UserDefined: copyMap(udoc.UserDefined)}
	for i, n := range numbers {
		if i == limit {
			res.IsTruncated = true
			break
		}
		p := docs[n]
		res.Parts = append(res.Parts, storage.PartInfo{Number: n, ETag: p.ETag, Size: p.Size, ModTime: p.ModTime})
		res.NextPartNumberMarker = n
	}
	if !res.IsTruncated {
		res.NextPartNumberMarker = 0
	}
	return res, nil
}

// uploadIDs gathers upload IDs of a bucket from enough drives to see every
// upload that reached quorum.
func (x *XL) uploadIDs(ctx context.Context, bucket string) map[string]bool {
	need := x.m + 1
	ids := map[string]bool{}
	seen := 0
	for _, d := range x.drives {
		if !d.Ready(ctx) {
			continue
		}
		list, err := d.ListUploadIDs(ctx, bucket)
		if err != nil {
			continue
		}
		for _, id := range list {
			ids[id] = true
		}
		if seen++; seen == need {
			break
		}
	}
	return ids
}

func (x *XL) hasUploads(ctx context.Context, bucket string) bool {
	for id := range x.uploadIDs(ctx, bucket) {
		if _, err := x.readUpload(ctx, bucket, "", id); err == nil {
			return true
		}
	}
	return false
}

// ListMultipartUploads lists in-progress uploads of a bucket.
func (x *XL) ListMultipartUploads(ctx context.Context, bucket string, opts storage.ListUploadsOptions) (storage.ListUploadsResult, error) {
	var zero storage.ListUploadsResult
	if err := storage.ValidateBucketName(bucket); err != nil {
		return zero, err
	}
	if err := x.enter(ctx); err != nil {
		return zero, err
	}
	defer x.leave()
	if err := x.requireBucket(ctx, bucket); err != nil {
		return zero, err
	}
	var all []storage.UploadInfo
	for id := range x.uploadIDs(ctx, bucket) {
		if err := ctx.Err(); err != nil {
			return zero, err
		}
		doc, err := x.readUpload(ctx, bucket, "", id)
		if err != nil {
			continue
		}
		all = append(all, storage.UploadInfo{Object: doc.Object, UploadID: id, Initiated: doc.Initiated})
	}
	return listing.PageUploads(all, opts), nil
}

// discardUpload removes an upload's directory from every drive.
func (x *XL) discardUpload(ctx context.Context, bucket, id string) int {
	ctx, cancel := detached(ctx) // a finished or failed upload must be cleaned up even if the client left
	defer cancel()
	errs := x.each(ctx, func(d *drive) error { return d.DiscardUpload(ctx, bucket, id) })
	return countNil(errs)
}

// AbortMultipartUpload discards an upload and its parts.
func (x *XL) AbortMultipartUpload(ctx context.Context, bucket, object, uploadID string) error {
	if err := validate(bucket, object); err != nil {
		return err
	}
	if err := checkUploadID(bucket, object, uploadID); err != nil {
		return err
	}
	if err := x.enter(ctx); err != nil {
		return err
	}
	defer x.leave()
	unlockBucket, err := x.locker.RLock(ctx, bucket, "")
	if err != nil {
		return err
	}
	defer unlockBucket()
	unlock, err := x.locker.Lock(ctx, bucket, uploadLockKey(uploadID))
	if err != nil {
		return err
	}
	defer unlock()
	if _, err := x.readUpload(ctx, bucket, object, uploadID); err != nil {
		return err
	}
	if n := x.discardUpload(ctx, bucket, uploadID); n < x.writeQuorum() {
		return quorumError(bucket, object, n, x.writeQuorum(), nil)
	}
	return nil
}

// CompleteMultipartUpload assembles the listed parts into the object. The
// ETag is the MD5 of the concatenated binary part MD5s plus "-<count>".
func (x *XL) CompleteMultipartUpload(ctx context.Context, bucket, object, uploadID string,
	parts []storage.CompletePart, opts storage.PutOptions) (storage.ObjectInfo, error) {
	var zero storage.ObjectInfo
	if err := validate(bucket, object); err != nil {
		return zero, err
	}
	if err := checkUploadID(bucket, object, uploadID); err != nil {
		return zero, err
	}
	if len(parts) == 0 || len(parts) > maxParts {
		return zero, storage.Wrap(fmt.Errorf("%w: %d parts listed", storage.ErrInvalidPart, len(parts)), bucket, object)
	}
	for i, p := range parts {
		if p.Number < 1 || p.Number > maxParts {
			return zero, storage.Wrap(fmt.Errorf("%w: part number %d is outside 1..%d", storage.ErrInvalidPart, p.Number, maxParts), bucket, object)
		}
		if i > 0 && p.Number <= parts[i-1].Number {
			return zero, storage.Wrap(storage.ErrInvalidPartOrder, bucket, object)
		}
	}
	if err := x.enter(ctx); err != nil {
		return zero, err
	}
	defer x.leave()
	unlockBucket, err := x.locker.RLock(ctx, bucket, "")
	if err != nil {
		return zero, err
	}
	defer unlockBucket()
	unlockUpload, err := x.locker.Lock(ctx, bucket, uploadLockKey(uploadID))
	if err != nil {
		return zero, err
	}
	defer unlockUpload()
	unlockKey, err := x.locker.Lock(ctx, bucket, object)
	if err != nil {
		return zero, err
	}
	defer unlockKey()

	doc, err := x.readUpload(ctx, bucket, object, uploadID)
	if err != nil {
		return zero, err
	}
	stored, holders := x.partsQuorum(ctx, bucket, uploadID)

	var total int64
	sum := md5.New()
	versionParts := make([]meta.Part, 0, len(parts))
	for i, want := range parts {
		have, ok := stored[want.Number]
		if !ok || !strings.EqualFold(trimETag(want.ETag), have.ETag) {
			return zero, storage.Wrap(fmt.Errorf("%w: part %d was not uploaded or its ETag differs", storage.ErrInvalidPart, want.Number), bucket, object)
		}
		if i < len(parts)-1 && have.Size < x.minPartSize {
			return zero, storage.Wrap(fmt.Errorf("%w: part %d is %d bytes, the minimum is %d", storage.ErrEntityTooSmall, want.Number, have.Size, x.minPartSize), bucket, object)
		}
		raw, err := hex.DecodeString(have.ETag)
		if err != nil || len(raw) != md5.Size {
			return zero, storage.Wrap(storage.ErrCorrupted, bucket, object)
		}
		sum.Write(raw)
		total += have.Size
		if total > maxObjectSize {
			return zero, storage.Wrap(storage.ErrEntityTooLarge, bucket, object)
		}
		versionParts = append(versionParts, meta.Part{N: want.Number, Size: have.Size, ETag: have.ETag})
	}
	etag := fmt.Sprintf("%s-%d", hex.EncodeToString(sum.Sum(nil)), len(parts))

	// Stage a data dir on each drive that holds every listed part.
	token, err := newToken()
	if err != nil {
		return zero, err
	}
	stageID := "complete-" + token
	dataDir := storage.DataDirPrefix + "data-" + token
	defer x.removeStages(ctx, stageID)
	participants := make([]bool, len(x.drives))
	sums := make([][]meta.Checksum, len(x.drives))
	for i, d := range x.drives {
		if !d.Ready(ctx) {
			continue
		}
		ok := true
		perDrive := x.drivePartDocs(ctx, d, bucket, uploadID)
		for _, want := range parts {
			pd, have := perDrive[want.Number]
			if !have || pd.File != stored[want.Number].File || pd.ETag != stored[want.Number].ETag || !contains(holders[want.Number], i) {
				ok = false
				break
			}
			if err := d.LinkPartIntoStage(ctx, bucket, uploadID, pd.File, stageID, fmt.Sprintf("%s/part.%d", dataDir, want.Number)); err != nil {
				ok = false
				break
			}
			sums[i] = append(sums[i], meta.Checksum{Part: want.Number, Algorithm: hashAlgorithm, Hash: pd.Root})
		}
		participants[i] = ok
	}
	if live := countTrue(participants); live < x.writeQuorum() {
		return zero, quorumError(bucket, object, live, x.writeQuorum(), nil)
	}
	ct := doc.ContentType
	if ct == "" {
		ct = defaultCT
	}
	info, err := x.publishVersion(ctx, bucket, object, publishSpec{
		stageID: stageID, dataDir: dataDir, dist: doc.Distribution, blockSize: doc.BlockSize,
		sums: sums, participants: participants,
		tmpl: meta.Version{
			Type: meta.TypeObject, Size: total, ETag: etag, DataDir: dataDir,
			ContentType: ct, UserMeta: copyMap(doc.UserDefined), Parts: versionParts,
		},
	}, objlock.Carry(opts, doc.Lock, time.Now()))
	if err != nil {
		return zero, err
	}
	x.discardUpload(ctx, bucket, uploadID)
	return info, nil
}

func contains(s []int, v int) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
