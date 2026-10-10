// Package disk defines Disk, the unit of storage the erasure-coded backend
// is built from, and Local, its filesystem implementation.
//
// A Disk is one drive of an erasure set. The xl backend composes many of
// them with quorum logic; a Disk itself only ever acts on its own drive.
// Because a drive may live on another node, the interface is deliberately
// operation-level: one method per thing xl does to a drive (commit an
// object, list the parts of an upload, verify a shard), so that a remote
// implementation costs one round trip per operation rather than one per
// filesystem call. Paths never cross the interface; callers name buckets,
// objects and staging IDs and the implementation owns its layout.
//
// Every method takes a context. A cancelled or expired context aborts the
// call; Local checks it on entry and between blocks of long reads, a remote
// drive turns it into the RPC deadline. Cleanup that must outlive a
// cancelled request (Rollback, RemoveStage, aborting a writer) is the
// caller's to run on a detached context. Objects a call returns (Shard,
// FileWriter) stay bound to the context they were created with.
//
// Every error returned by a method is an *Error, outermost, so errors.Is
// against the Err* sentinels behaves identically for local and remote
// drives.
//
// Every implementation must pass the contract suite in package disktest.
package disk

import (
	"context"
	"io"
	"time"

	"nanoio/internal/meta"
)

// Fault points a Local drive exposes to tests, in commit order.
const (
	FaultPreCommit   = "pre-commit"   // before the drive publishes anything
	FaultDataRenamed = "data-renamed" // data dir in place, xl.meta not yet
	FaultMetaRenamed = "meta-renamed" // drive committed
)

// FormatVersion is the version of the drive format document.
const FormatVersion = 1

// Format is a drive's identity within a deployment.
type Format struct {
	Format       int       `json:"format"`
	DeploymentID string    `json:"deploymentId"`
	Index        int       `json:"index"`
	DataBlocks   int       `json:"dataBlocks"`
	ParityBlocks int       `json:"parityBlocks"`
	Created      time.Time `json:"created"`
}

// Info is a drive's capacity.
type Info struct {
	Total, Free uint64
}

// Shard is an open shard file of one part of one object version.
type Shard interface {
	io.ReaderAt
	io.Closer
	// Size is the file length in bytes.
	Size() int64
}

// FileWriter writes one staged file. Close makes it durable and final;
// Abort discards it. Exactly one of them must be called.
type FileWriter interface {
	io.Writer
	Close() error
	Abort()
}

// CommitRequest publishes a staged object on one drive.
type CommitRequest struct {
	Bucket, Object string
	// StageID names the staging area holding DataDir.
	StageID string
	// DataDir is the staged data directory's name; it becomes the version's
	// data directory.
	DataDir string
	// Version is this drive's version record, erasure info included.
	Version meta.Version
	// CheckGen makes the commit conditional: it fails with ErrConflict if
	// the drive already holds a generation of the object greater than
	// PrevGen. A drive that is merely behind (older generation, or none)
	// accepts, which is how a stale drive catches up. Repairs, which
	// rewrite an existing generation, leave CheckGen unset.
	CheckGen bool
	PrevGen  uint64
}

// Commit is a published change that is not yet final. Exactly one of
// Rollback and Finish must be called.
type Commit interface {
	// Rollback restores the drive to what it held before the commit.
	Rollback(ctx context.Context) error
	// Finish makes the commit final, discarding what it superseded.
	Finish(ctx context.Context) error
}

// PartRecord is one drive's record of an uploaded part.
type PartRecord struct {
	Number    int       `json:"number"`
	File      string    `json:"file"`
	Size      int64     `json:"size"`
	ETag      string    `json:"etag"`
	ModTime   time.Time `json:"modTime"`
	Root      string    `json:"root"`
	ShardSize int64     `json:"shardSize"`
}

// PartCommit publishes one staged part of an upload on one drive.
type PartCommit struct {
	Bucket, UploadID string
	StageID          string
	// DataFile is the staged shard file's name inside the stage.
	DataFile string
	Number   int
	// Record is the JSON encoding of the PartRecord to store.
	Record []byte
}

// StaleUpload names an upload that has seen no activity within an expiry
// window, or whose bucket no longer exists.
type StaleUpload struct {
	Bucket, ID string
	BucketGone bool
}

// Orphan is an object directory holding data directories its xl.meta does
// not reference.
type Orphan struct {
	Object   string
	DataDirs []string
}

// Disk is one drive of an erasure set.
type Disk interface {
	// String identifies the drive in logs and errors.
	String() string

	// Open prepares the drive for use: it creates the drive's working
	// directories (only if create is set; a drive that has vanished must
	// not be silently re-created), takes exclusive ownership of it, and
	// returns its format. A blank drive returns ErrUnformatted and is held
	// but not usable until WriteFormat; a populated unformatted directory
	// returns ErrForeign. Open is idempotent for a drive already held.
	Open(ctx context.Context, create bool) (*Format, error)
	// WriteFormat formats a blank, opened drive and makes it usable. It is
	// idempotent when the drive already carries the same identity.
	WriteFormat(ctx context.Context, f *Format) error
	// Ready reports whether the drive is usable now. It notices a drive
	// that vanished or was replaced under it.
	Ready(ctx context.Context) bool
	// Info reports capacity.
	Info(ctx context.Context) (Info, error)
	// Close releases the drive. A remote drive's Close releases nothing:
	// the drive belongs to its node.
	Close() error

	// MakeBucket creates the bucket directory with a creation marker. It is
	// idempotent and reports whether it created anything.
	MakeBucket(ctx context.Context, bucket string, created time.Time) (made bool, err error)
	// StatBucket reports whether the bucket exists and when it was created.
	StatBucket(ctx context.Context, bucket string) (exists bool, created time.Time, err error)
	// ListBuckets lists bucket names.
	ListBuckets(ctx context.Context) ([]string, error)
	// DeleteBucket removes the bucket and its in-progress uploads. A
	// missing bucket is not an error.
	DeleteBucket(ctx context.Context, bucket string) error
	// ListKeys lists the keys under a bucket that have an xl.meta here.
	ListKeys(ctx context.Context, bucket, prefix string) ([]string, error)

	// ReadMeta returns the raw xl.meta of an object, or ErrNotFound.
	ReadMeta(ctx context.Context, bucket, object string) ([]byte, error)
	// OpenShard opens the shard file of one part of a data directory.
	OpenShard(ctx context.Context, bucket, object, dataDir string, part int) (Shard, error)
	// StatShard returns the size of a shard file.
	StatShard(ctx context.Context, bucket, object, dataDir string, part int) (int64, error)
	// VerifyShard reads a whole shard file on the drive, checks every
	// block's hash and returns the checksum root.
	VerifyShard(ctx context.Context, bucket, object, dataDir string, part int, partSize, blockSize int64, dataBlocks int) (root string, err error)
	// PinData keeps a data directory alive until release is called, even if
	// the version is overwritten or deleted meanwhile, so a reader that has
	// begun streaming sees a stable snapshot. If the pin cannot be taken
	// the caller must not rely on the snapshot and gets an error.
	PinData(ctx context.Context, bucket, object, dataDir string) (release func(), err error)
	// DeleteObject removes an object's xl.meta and data directories and
	// prunes empty parents. A missing object is not an error.
	DeleteObject(ctx context.Context, bucket, object string) error

	// CreateStageFile creates a new file under a staging area. The staging
	// area is protected from SweepStaging until RemoveStage.
	CreateStageFile(ctx context.Context, stageID, rel string) (FileWriter, error)
	// RemoveStage discards a staging area and releases its protection.
	RemoveStage(ctx context.Context, stageID string) error
	// CommitObject publishes a staged data directory and xl.meta.
	CommitObject(ctx context.Context, req CommitRequest) (Commit, error)
	// LinkPartIntoStage places a part's shard file of an upload into a
	// staging area, hard-linking where possible.
	LinkPartIntoStage(ctx context.Context, bucket, uploadID, partFile, stageID, rel string) error

	// CreateUpload records a new upload with its descriptor document.
	CreateUpload(ctx context.Context, bucket, uploadID string, doc []byte) error
	// ReadUpload returns an upload's descriptor, or ErrNotFound.
	ReadUpload(ctx context.Context, bucket, uploadID string) ([]byte, error)
	// ListUploadIDs lists the uploads of a bucket.
	ListUploadIDs(ctx context.Context, bucket string) ([]string, error)
	// ListParts returns the committed parts of an upload whose record and
	// shard file are intact.
	ListParts(ctx context.Context, bucket, uploadID string) ([]PartRecord, error)
	// CommitPart publishes a staged part, replacing any earlier one.
	CommitPart(ctx context.Context, pc PartCommit) (Commit, error)
	// DiscardUpload removes an upload. A missing upload is not an error.
	DiscardUpload(ctx context.Context, bucket, uploadID string) error

	// SweepStaging removes staging areas older than maxAge that no
	// operation holds; negative maxAge removes every unheld one. It returns
	// how many it removed.
	SweepStaging(ctx context.Context, maxAge time.Duration) (int, error)
	// StaleUploads lists uploads idle longer than maxAge or whose bucket is
	// gone.
	StaleUploads(ctx context.Context, maxAge time.Duration) ([]StaleUpload, error)
	// DiscardUploadIfStale re-checks staleness and removes the upload if it
	// still is, reporting whether it did. It is the second half of a
	// check-then-act the caller performs under a lock.
	DiscardUploadIfStale(ctx context.Context, bucket, uploadID string, maxAge time.Duration) (bool, error)
	// FindOrphans lists object directories of a bucket that hold data
	// directories their xl.meta does not reference. Directories next to
	// unreadable metadata are never reported.
	FindOrphans(ctx context.Context, bucket string) ([]Orphan, error)
	// RemoveOrphans removes the named data directories of an object if they
	// are still unreferenced and unpinned, returning how many it removed.
	RemoveOrphans(ctx context.Context, bucket, object string, dataDirs []string) (int, error)
}
