package disk

import (
	"context"
	"time"
)

// This file is the Disk face of Local. Each method checks the context, runs
// the implementation (the unexported method of the same name) and returns
// its error as an *Error, outermost.

func (d *Local) Open(ctx context.Context, create bool) (*Format, error) {
	if err := ctx.Err(); err != nil {
		return nil, Wrap("Open", "", err)
	}
	r0, err := d.open(create)
	return r0, Wrap("Open", "", err)
}

func (d *Local) WriteFormat(ctx context.Context, f *Format) error {
	if err := ctx.Err(); err != nil {
		return Wrap("WriteFormat", "", err)
	}
	return Wrap("WriteFormat", "", d.writeFormat(f))
}

func (d *Local) Info(ctx context.Context) (Info, error) {
	if err := ctx.Err(); err != nil {
		return Info{}, Wrap("Info", "", err)
	}
	r0, err := d.info()
	return r0, Wrap("Info", "", err)
}

func (d *Local) MakeBucket(ctx context.Context, bucket string, created time.Time) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, Wrap("MakeBucket", bucket, err)
	}
	r0, err := d.makeBucket(bucket, created)
	return r0, Wrap("MakeBucket", bucket, err)
}

func (d *Local) StatBucket(ctx context.Context, bucket string) (bool, time.Time, error) {
	if err := ctx.Err(); err != nil {
		return false, time.Time{}, Wrap("StatBucket", bucket, err)
	}
	r0, r1, err := d.statBucket(bucket)
	return r0, r1, Wrap("StatBucket", bucket, err)
}

func (d *Local) ListBuckets(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, Wrap("ListBuckets", "", err)
	}
	r0, err := d.listBuckets()
	return r0, Wrap("ListBuckets", "", err)
}

func (d *Local) DeleteBucket(ctx context.Context, bucket string) error {
	if err := ctx.Err(); err != nil {
		return Wrap("DeleteBucket", bucket, err)
	}
	return Wrap("DeleteBucket", bucket, d.deleteBucket(bucket))
}

func (d *Local) ListKeys(ctx context.Context, bucket, prefix string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, Wrap("ListKeys", bucket, err)
	}
	r0, err := d.listKeys(ctx, bucket, prefix)
	return r0, Wrap("ListKeys", bucket, err)
}

func (d *Local) ReadMeta(ctx context.Context, bucket, object string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, Wrap("ReadMeta", bucket+"/"+object, err)
	}
	r0, err := d.readMeta(bucket, object)
	return r0, Wrap("ReadMeta", bucket+"/"+object, err)
}

func (d *Local) OpenShard(ctx context.Context, bucket, object, dataDir string, part int) (Shard, error) {
	if err := ctx.Err(); err != nil {
		return nil, Wrap("OpenShard", bucket+"/"+object, err)
	}
	r0, err := d.openShard(bucket, object, dataDir, part)
	return r0, Wrap("OpenShard", bucket+"/"+object, err)
}

func (d *Local) StatShard(ctx context.Context, bucket, object, dataDir string, part int) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, Wrap("StatShard", bucket+"/"+object, err)
	}
	r0, err := d.statShard(bucket, object, dataDir, part)
	return r0, Wrap("StatShard", bucket+"/"+object, err)
}

func (d *Local) VerifyShard(ctx context.Context, bucket, object, dataDir string, part int, partSize, blockSize int64, dataBlocks int) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", Wrap("VerifyShard", bucket+"/"+object, err)
	}
	r0, err := d.verifyShard(ctx, bucket, object, dataDir, part, partSize, blockSize, dataBlocks)
	return r0, Wrap("VerifyShard", bucket+"/"+object, err)
}

func (d *Local) DeleteObject(ctx context.Context, bucket, object string) error {
	if err := ctx.Err(); err != nil {
		return Wrap("DeleteObject", bucket+"/"+object, err)
	}
	return Wrap("DeleteObject", bucket+"/"+object, d.deleteObject(bucket, object))
}

func (d *Local) CreateStageFile(ctx context.Context, stageID, rel string) (FileWriter, error) {
	if err := ctx.Err(); err != nil {
		return nil, Wrap("CreateStageFile", "", err)
	}
	r0, err := d.createStageFile(stageID, rel)
	return r0, Wrap("CreateStageFile", "", err)
}

func (d *Local) CommitObject(ctx context.Context, req CommitRequest) (Commit, error) {
	if err := ctx.Err(); err != nil {
		return nil, Wrap("CommitObject", "", err)
	}
	r0, err := d.commitObject(req)
	return r0, Wrap("CommitObject", "", err)
}

func (d *Local) LinkPartIntoStage(ctx context.Context, bucket, uploadID, partFile, stageID, rel string) error {
	if err := ctx.Err(); err != nil {
		return Wrap("LinkPartIntoStage", bucket, err)
	}
	return Wrap("LinkPartIntoStage", bucket, d.linkPartIntoStage(bucket, uploadID, partFile, stageID, rel))
}

func (d *Local) CreateUpload(ctx context.Context, bucket, uploadID string, doc []byte) error {
	if err := ctx.Err(); err != nil {
		return Wrap("CreateUpload", bucket, err)
	}
	return Wrap("CreateUpload", bucket, d.createUpload(bucket, uploadID, doc))
}

func (d *Local) ReadUpload(ctx context.Context, bucket, uploadID string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, Wrap("ReadUpload", bucket, err)
	}
	r0, err := d.readUpload(bucket, uploadID)
	return r0, Wrap("ReadUpload", bucket, err)
}

func (d *Local) ListUploadIDs(ctx context.Context, bucket string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, Wrap("ListUploadIDs", bucket, err)
	}
	r0, err := d.listUploadIDs(bucket)
	return r0, Wrap("ListUploadIDs", bucket, err)
}

func (d *Local) ListParts(ctx context.Context, bucket, uploadID string) ([]PartRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, Wrap("ListParts", bucket, err)
	}
	r0, err := d.listParts(bucket, uploadID)
	return r0, Wrap("ListParts", bucket, err)
}

func (d *Local) CommitPart(ctx context.Context, pc PartCommit) (Commit, error) {
	if err := ctx.Err(); err != nil {
		return nil, Wrap("CommitPart", "", err)
	}
	r0, err := d.commitPart(pc)
	return r0, Wrap("CommitPart", "", err)
}

func (d *Local) DiscardUpload(ctx context.Context, bucket, uploadID string) error {
	if err := ctx.Err(); err != nil {
		return Wrap("DiscardUpload", bucket, err)
	}
	return Wrap("DiscardUpload", bucket, d.discardUpload(bucket, uploadID))
}

func (d *Local) StaleUploads(ctx context.Context, maxAge time.Duration) ([]StaleUpload, error) {
	if err := ctx.Err(); err != nil {
		return nil, Wrap("StaleUploads", "", err)
	}
	r0, err := d.staleUploads(maxAge)
	return r0, Wrap("StaleUploads", "", err)
}

func (d *Local) DiscardUploadIfStale(ctx context.Context, bucket, uploadID string, maxAge time.Duration) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, Wrap("DiscardUploadIfStale", bucket, err)
	}
	r0, err := d.discardUploadIfStale(bucket, uploadID, maxAge)
	return r0, Wrap("DiscardUploadIfStale", bucket, err)
}

func (d *Local) FindOrphans(ctx context.Context, bucket string) ([]Orphan, error) {
	if err := ctx.Err(); err != nil {
		return nil, Wrap("FindOrphans", bucket, err)
	}
	r0, err := d.findOrphans(ctx, bucket)
	return r0, Wrap("FindOrphans", bucket, err)
}

func (d *Local) RemoveOrphans(ctx context.Context, bucket, object string, dataDirs []string) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, Wrap("RemoveOrphans", bucket+"/"+object, err)
	}
	r0, err := d.removeOrphans(bucket, object, dataDirs)
	return r0, Wrap("RemoveOrphans", bucket+"/"+object, err)
}

// Ready implements Disk.
func (d *Local) Ready(ctx context.Context) bool { return ctx.Err() == nil && d.ready() }

// PinData implements Disk.
func (d *Local) PinData(ctx context.Context, bucket, object, dataDir string) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, Wrap("PinData", bucket+"/"+object, err)
	}
	if !d.ready() {
		return nil, Wrap("PinData", bucket+"/"+object, ErrOffline)
	}
	rel, err := d.pinData(bucket, object, dataDir)
	return rel, Wrap("PinData", bucket+"/"+object, err)
}

// RemoveStage implements Disk.
func (d *Local) RemoveStage(ctx context.Context, stageID string) error {
	if err := ctx.Err(); err != nil {
		return Wrap("RemoveStage", stageID, err)
	}
	d.removeStage(stageID)
	return nil
}

// SweepStaging implements Disk.
func (d *Local) SweepStaging(ctx context.Context, maxAge time.Duration) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, Wrap("SweepStaging", "", err)
	}
	return d.sweepStaging(maxAge), nil
}

// ReadBucketVersioning implements Disk.
func (d *Local) ReadBucketVersioning(ctx context.Context, bucket string) (string, uint64, error) {
	if err := ctx.Err(); err != nil {
		return "", 0, Wrap("ReadBucketVersioning", bucket, err)
	}
	st, seq, err := d.readBucketVersioning(bucket)
	return st, seq, Wrap("ReadBucketVersioning", bucket, err)
}

// WriteBucketVersioning implements Disk.
func (d *Local) WriteBucketVersioning(ctx context.Context, bucket, state string, seq uint64) error {
	if err := ctx.Err(); err != nil {
		return Wrap("WriteBucketVersioning", bucket, err)
	}
	return Wrap("WriteBucketVersioning", bucket, d.writeBucketVersioning(bucket, state, seq))
}

// ReadBucketSettings implements Disk.
func (d *Local) ReadBucketSettings(ctx context.Context, bucket string) (BucketSettings, error) {
	if err := ctx.Err(); err != nil {
		return BucketSettings{}, Wrap("ReadBucketSettings", bucket, err)
	}
	r0, err := d.readBucketSettings(bucket)
	return r0, Wrap("ReadBucketSettings", bucket, err)
}

// WriteBucketObjectLock implements Disk.
func (d *Local) WriteBucketObjectLock(ctx context.Context, bucket, doc string, seq uint64) error {
	if err := ctx.Err(); err != nil {
		return Wrap("WriteBucketObjectLock", bucket, err)
	}
	return Wrap("WriteBucketObjectLock", bucket, d.writeBucketObjectLock(bucket, doc, seq))
}
