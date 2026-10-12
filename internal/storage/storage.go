// Package storage defines StorageAPI, the object-level abstraction every
// NanoIO backend (fs, xl) implements. It is policy-free and HTTP-free: it
// stores and returns bytes and metadata and knows nothing about users,
// signatures or S3 wire formats.
package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"
)

// StorageAPI is the only thing api/ knows about storage.
//
// Contract every backend must meet (enforced by storagetest):
//   - PutObject is atomically visible: a reader sees all of it or none of it.
//   - The reader from GetObject keeps serving the version it opened.
//   - Names are re-validated by the backend; ErrInvalidBucketName,
//     ErrInvalidObjectName and ErrKeyTooLong are returned for bad names.
//   - A cancelled ctx aborts the call and removes its temp files.
//   - The backend takes namespace locks itself; callers never lock.
//   - Errors match with errors.Is against the sentinels in errors.go.
//   - Out-of-scope behaviour returns ErrNotImplemented.
type StorageAPI interface {
	// Buckets.
	MakeBucket(ctx context.Context, bucket string, opts MakeBucketOptions) error
	GetBucketInfo(ctx context.Context, bucket string) (BucketInfo, error)
	// BucketExists reports whether bucket exists. A malformed name returns
	// ErrInvalidBucketName rather than false.
	BucketExists(ctx context.Context, bucket string) (bool, error)
	ListBuckets(ctx context.Context) ([]BucketInfo, error)
	DeleteBucket(ctx context.Context, bucket string, opts DeleteBucketOptions) error
	// GetBucketVersioning reports the bucket's versioning state.
	GetBucketVersioning(ctx context.Context, bucket string) (VersioningConfig, error)
	// SetBucketVersioning moves the bucket to state. The state machine is
	// Unversioned -> Enabled <-> Suspended; Enabled and Suspended never go
	// back to Unversioned, and a transition not in it returns
	// ErrIllegalVersioning. Setting the current state is a no-op.
	SetBucketVersioning(ctx context.Context, bucket string, state VersioningState) error
	// GetBucketObjectLock reports the bucket's object lock configuration.
	// A bucket created without object lock returns Enabled == false.
	GetBucketObjectLock(ctx context.Context, bucket string) (ObjectLockConfig, error)
	// SetBucketObjectLock replaces the default retention of a bucket that
	// was created with object lock. A bucket without it, or a configuration
	// that would turn it off, returns ErrInvalidBucketState.
	SetBucketObjectLock(ctx context.Context, bucket string, cfg ObjectLockConfig) error

	// Objects.
	PutObject(ctx context.Context, bucket, object string, r io.Reader, size int64, opts PutOptions) (ObjectInfo, error)
	GetObject(ctx context.Context, bucket, object string, opts GetOptions) (io.ReadCloser, ObjectInfo, error)
	StatObject(ctx context.Context, bucket, object string, opts GetOptions) (ObjectInfo, error)
	DeleteObject(ctx context.Context, bucket, object string, opts DeleteOptions) (DeleteResult, error)
	CopyObject(ctx context.Context, src, dst ObjectRef, opts CopyOptions) (ObjectInfo, error)
	UpdateObjectMetadata(ctx context.Context, bucket, object string, opts UpdateMetaOptions) (ObjectInfo, error)
	ListObjects(ctx context.Context, bucket string, opts ListOptions) (ListResult, error)
	ListObjectVersions(ctx context.Context, bucket string, opts ListOptions) (ListVersionsResult, error)
	// SetObjectRetention sets, extends, shortens or removes (zero r) the
	// retention of one object version, subject to the rules on Retention.
	// A refusal is ErrObjectLocked and changes nothing.
	SetObjectRetention(ctx context.Context, ref ObjectRef, r Retention, opts RetentionOptions) (ObjectInfo, error)
	// SetObjectLegalHold turns the legal hold of one object version on or
	// off.
	SetObjectLegalHold(ctx context.Context, ref ObjectRef, on bool) (ObjectInfo, error)

	// Multipart.
	NewMultipartUpload(ctx context.Context, bucket, object string, opts PutOptions) (uploadID string, err error)
	PutObjectPart(ctx context.Context, bucket, object, uploadID string, partNumber int, r io.Reader, size int64, opts PartOptions) (PartInfo, error)
	ListObjectParts(ctx context.Context, bucket, object, uploadID string, opts ListPartsOptions) (ListPartsResult, error)
	CompleteMultipartUpload(ctx context.Context, bucket, object, uploadID string, parts []CompletePart, opts PutOptions) (ObjectInfo, error)
	AbortMultipartUpload(ctx context.Context, bucket, object, uploadID string) error
	ListMultipartUploads(ctx context.Context, bucket string, opts ListUploadsOptions) (ListUploadsResult, error)

	// Lifecycle.
	Info(ctx context.Context) (BackendInfo, error)
	Close() error
}

// Locker is the namespace lock manager injected into every backend
// constructor. It is declared here, not in bucket/, so backends can depend on
// it without an import cycle; bucket/nslock implements it.
//
// Lock order is fixed: bucket, then upload, then key.
type Locker interface {
	// Lock takes an exclusive lock on bucket/object. An empty object locks
	// the bucket itself. The returned unlock func is idempotent.
	Lock(ctx context.Context, bucket, object string) (unlock func(), err error)
	// RLock takes a shared lock with the same naming rules as Lock.
	RLock(ctx context.Context, bucket, object string) (unlock func(), err error)
}

// ObjectRef names one object, optionally one specific version.
type ObjectRef struct {
	Bucket    string
	Object    string
	VersionID string
}

// MakeBucketOptions holds per-bucket creation settings.
type MakeBucketOptions struct {
	// ObjectLock creates the bucket with S3 Object Lock, which also
	// enables versioning and can never be turned off.
	ObjectLock bool
}

// DeleteBucketOptions controls DeleteBucket.
type DeleteBucketOptions struct {
	// Force removes the bucket even if it contains objects.
	Force bool
}

// VersioningState is a bucket's versioning state.
type VersioningState string

const (
	// VersioningUnversioned is the state of a bucket that has never had
	// versioning enabled. S3 reports it as an empty configuration.
	VersioningUnversioned VersioningState = ""
	VersioningEnabled     VersioningState = "Enabled"
	VersioningSuspended   VersioningState = "Suspended"
)

// Valid reports whether s is one of the three states.
func (s VersioningState) Valid() bool {
	return s == VersioningUnversioned || s == VersioningEnabled || s == VersioningSuspended
}

// VersioningConfig is the state plus the sequence number of the change that
// produced it (0 for a bucket that never had one). The sequence orders
// changes across drives and sets.
type VersioningConfig struct {
	State VersioningState
	Seq   uint64
}

// RetentionMode is an S3 Object Lock retention mode.
type RetentionMode string

const (
	// RetentionGovernance retention can be shortened or removed only by a
	// caller who asked to bypass it (DeleteOptions.BypassGovernance,
	// RetentionOptions.BypassGovernance) and was authorised to.
	RetentionGovernance RetentionMode = "GOVERNANCE"
	// RetentionCompliance retention can be extended and nothing else, by
	// anyone, until it expires.
	RetentionCompliance RetentionMode = "COMPLIANCE"
)

// Valid reports whether m is a retention mode.
func (m RetentionMode) Valid() bool {
	return m == RetentionGovernance || m == RetentionCompliance
}

// Retention is a retention mode and the instant it ends. The zero value
// means no retention. Retention that has ended protects nothing.
type Retention struct {
	Mode  RetentionMode
	Until time.Time
}

// IsZero reports whether r is no retention.
func (r Retention) IsZero() bool { return r.Mode == "" && r.Until.IsZero() }

// Validate checks r against now: a mode and a date together, the mode known,
// and the date strictly in the future. It is deliberately strict about the
// future for both modes, so a clock-skewed client cannot create retention
// that is already over.
func (r Retention) Validate(now time.Time) error {
	switch {
	case r.IsZero():
		return nil
	case !r.Mode.Valid():
		return fmt.Errorf("%w: unknown retention mode %q", ErrInvalidRetention, r.Mode)
	case r.Until.IsZero():
		return fmt.Errorf("%w: retention mode without a retain-until date", ErrInvalidRetention)
	case !r.Until.After(now):
		return fmt.Errorf("%w: the retain-until date must be in the future", ErrInvalidRetention)
	}
	return nil
}

// RetentionOptions controls SetObjectRetention.
type RetentionOptions struct {
	// BypassGovernance lets the change shorten or remove GOVERNANCE
	// retention. The API layer sets it only for a principal holding
	// s3:BypassGovernanceRetention that sent
	// x-amz-bypass-governance-retention: true. It never affects COMPLIANCE
	// retention or a legal hold.
	BypassGovernance bool
}

// DefaultRetention is the retention a bucket applies to new versions that
// bring none of their own. Exactly one of Days and Years is positive.
type DefaultRetention struct {
	Mode  RetentionMode
	Days  int
	Years int
}

// Validate checks the shape S3 allows.
func (d DefaultRetention) Validate() error {
	switch {
	case !d.Mode.Valid():
		return fmt.Errorf("%w: unknown retention mode %q", ErrInvalidRetention, d.Mode)
	case d.Days < 0 || d.Years < 0 || (d.Days > 0) == (d.Years > 0):
		return fmt.Errorf("%w: a default retention needs exactly one of Days and Years, positive", ErrInvalidRetention)
	}
	return nil
}

// Until returns the end date of a retention that starts at t.
func (d DefaultRetention) Until(t time.Time) time.Time {
	if d.Years > 0 {
		return t.AddDate(d.Years, 0, 0)
	}
	return t.AddDate(0, 0, d.Days)
}

// ObjectLockConfig is a bucket's object lock configuration.
type ObjectLockConfig struct {
	// Enabled is true for a bucket created with object lock. It is
	// irreversible.
	Enabled bool
	// Default applies to new versions that carry no retention; nil for none.
	Default *DefaultRetention
	// Seq counts changes to the configuration. It is reported by
	// GetBucketObjectLock, which lets a cluster tell which of two diverged
	// copies is newer, and ignored by SetBucketObjectLock.
	Seq uint64
}

// CheckVersioningTransition validates a move between states. A bucket that
// has ever been versioned can never return to Unversioned.
func CheckVersioningTransition(from, to VersioningState) error {
	switch {
	case !to.Valid() || !from.Valid():
		return fmt.Errorf("%w: unknown state %q", ErrIllegalVersioning, to)
	case to == VersioningUnversioned && from != VersioningUnversioned:
		return fmt.Errorf("%w: a versioned bucket cannot become unversioned", ErrIllegalVersioning)
	}
	return nil
}

// BucketInfo describes a bucket.
type BucketInfo struct {
	Name    string
	Created time.Time
}

// ByteRange is a range already resolved against the object size by the
// caller. Backends return ErrInvalidRange if it falls outside the object.
type ByteRange struct {
	Start  int64
	Length int64
}

// PutOptions controls PutObject, NewMultipartUpload and
// CompleteMultipartUpload.
type PutOptions struct {
	ContentType   string
	UserDefined   map[string]string
	ContentMD5    string // hex or empty; verified while streaming
	ContentSHA256 string // hex or empty; verified while streaming
	// Whether the write creates a new version or replaces the null version
	// is decided by the backend from the bucket's versioning state, under
	// the bucket lock.
	IfMatch     string // commit only if the current ETag matches
	IfNoneMatch string // "*" commits only if the key does not exist
	// Retention and LegalHold lock the new version. Either on a bucket
	// without object lock is ErrObjectLockNotEnabled. A zero Retention gets
	// the bucket's default retention, if it has one; an explicit one
	// replaces it.
	Retention Retention
	LegalHold bool
	// StorageClass selects the redundancy of the new object: "" and
	// "STANDARD" are the backend's default; others are backend-specific
	// (xl maps each class to a parity count). An unknown class is
	// ErrInvalidStorageClass, and a backend with no redundancy options
	// accepts only STANDARD.
	StorageClass string
	// Import, if set, stores the object as the version Import.VersionID
	// with Import.ModTime instead of minting an ID and a time. It is how
	// replication writes a replica: the bucket must be versioned, and
	// importing a version that already exists changes nothing and returns
	// it (so a retried replication is harmless). Not for multipart uploads.
	Import *VersionImport
	// Finalize, if set, is called by PutObject once the whole body has been
	// read and verified and before the version is committed. The keys it
	// returns are added to UserDefined. It is how a caller records a digest
	// of data the backend never sees (the plaintext MD5 of an encrypted
	// body). It is not used by multipart uploads.
	Finalize func() map[string]string
}

// VersionImport names the identity of a replicated version.
type VersionImport struct {
	// VersionID is the source's version ID, in the API form: a UUID or
	// NullVersionID.
	VersionID string
	ModTime   time.Time
}

// FinalUserDefined returns a copy of o.UserDefined with the keys of
// o.Finalize (if set) added. A backend calls it once, after the body has been
// read and verified.
func (o PutOptions) FinalUserDefined() map[string]string {
	var extra map[string]string
	if o.Finalize != nil {
		extra = o.Finalize()
	}
	if len(o.UserDefined) == 0 && len(extra) == 0 {
		return nil
	}
	out := make(map[string]string, len(o.UserDefined)+len(extra))
	for k, v := range o.UserDefined {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

// NullVersionID is how the null version appears at the StorageAPI boundary
// and on the wire. Backends store it as the empty version ID, and report it
// only for buckets that are (or have been) versioned: a bucket that never
// had versioning reports no version ID at all.
const NullVersionID = "null"

// GetOptions controls GetObject and StatObject.
type GetOptions struct {
	// VersionID selects a version: "" the latest, NullVersionID the null
	// version, otherwise a version UUID.
	VersionID string
	Range     *ByteRange
}

// DeleteOptions controls DeleteObject.
//
// Without VersionID the backend decides from the bucket's versioning state:
// Enabled adds a delete marker with a new version ID, Suspended replaces
// the null version with a null delete marker, Unversioned removes the
// object. With VersionID that one version (object or delete marker) is
// removed permanently.
//
// Removing a version that object lock protects (a legal hold, or retention
// that has not ended and that the caller may not bypass) fails with
// ErrObjectLocked. Adding a delete marker is never refused: it removes
// nothing.
type DeleteOptions struct {
	VersionID string
	// ImportMarker, if set (and VersionID empty), adds a delete marker with
	// that ID and time instead of minting them: replication of a delete.
	// The bucket must be versioned; a marker that already exists is left
	// alone.
	ImportMarker *VersionImport
	// BypassGovernance allows removing a version under GOVERNANCE retention.
	// See RetentionOptions.BypassGovernance.
	BypassGovernance bool
}

// DeleteResult reports what DeleteObject did.
type DeleteResult struct {
	VersionID    string
	DeleteMarker bool
}

// CopyOptions controls CopyObject.
type CopyOptions struct {
	// ReplaceMetadata uses Put's metadata instead of the source's.
	ReplaceMetadata bool
	Put             PutOptions
}

// UpdateMetaOptions changes the metadata of one version in place. Its data,
// ETag, size and parts are never touched, and no data is read or written.
type UpdateMetaOptions struct {
	// VersionID selects the version: "" the latest, NullVersionID the
	// null version.
	VersionID string
	// UserDefined, when non-nil, replaces the version's whole user-defined
	// map (an empty non-nil map clears it). Nil leaves it unchanged.
	UserDefined map[string]string
	// ContentType, when non-empty, replaces the content type.
	ContentType string
	// Touch sets the modification time to now (S3 does this on a copy);
	// otherwise it is left alone (an internal re-wrap).
	Touch bool
	// IfETag, when non-empty, makes the update conditional on the version's
	// current ETag: a version rewritten meanwhile is ErrPreconditionFailed
	// rather than being overwritten with metadata computed for its
	// predecessor.
	IfETag string
}

// ObjectInfo is the API-facing view of one object version. It is built from
// meta.Version; no on-disk detail leaks through it.
type ObjectInfo struct {
	Bucket       string
	Name         string
	VersionID    string
	IsLatest     bool
	DeleteMarker bool
	Size         int64
	ModTime      time.Time
	ETag         string
	ContentType  string
	UserDefined  map[string]string
	Parts        []PartInfo
	// Retention and LegalHold are the version's object lock state.
	Retention Retention
	LegalHold bool
	// StorageClass is "" for STANDARD, otherwise the class the object was
	// written with.
	StorageClass string
	// Transition is non-nil for a version whose data has moved to a tier:
	// the backend holds only a stub, and reading the data is the caller's
	// job (GetObject returns a *TransitionedError).
	Transition *TransitionInfo
}

// TransitionInfo says where a transitioned version's data lives.
type TransitionInfo struct {
	// Tier names the configured tier; Object and VersionID locate the data
	// in it.
	Tier      string
	Object    string
	VersionID string
	Time      time.Time
}

// Transitioner is implemented by backends that can hold transitioned-object
// stubs (xl and the cluster store; fs cannot).
type Transitioner interface {
	// TransitionObject records that the data of one version now lives at
	// tr and releases the local data. It succeeds only if the version still
	// has ETag ifETag (so a version rewritten since the data was uploaded is
	// not turned into a stub of the wrong bytes) and is not already a stub.
	TransitionObject(ctx context.Context, ref ObjectRef, tr TransitionInfo, ifETag string) (ObjectInfo, error)
}

// ErrTransitioned is the sentinel inside a *TransitionedError.
var ErrTransitioned = errors.New("object data is in a remote tier")

// TransitionedError is returned by GetObject for a stub: the caller reads
// the data from Info.Transition.
type TransitionedError struct {
	Info ObjectInfo
}

func (e *TransitionedError) Error() string { return ErrTransitioned.Error() }
func (e *TransitionedError) Unwrap() error { return ErrTransitioned }

// ListOptions controls ListObjects and ListObjectVersions. Results are in
// UTF-8 byte order, as S3 requires.
//
// Marker and StartAfter are both exclusive lower bounds; when both are set
// the greater applies. The API layer maps ListObjectsV2 continuation tokens
// onto Marker and start-after onto StartAfter. MaxKeys <= 0 or > 1000 means
// 1000.
type ListOptions struct {
	Prefix          string
	Delimiter       string
	Marker          string
	StartAfter      string
	VersionIDMarker string
	MaxKeys         int
}

// ListResult is the result of ListObjects.
type ListResult struct {
	Objects     []ObjectInfo
	Prefixes    []string
	IsTruncated bool
	NextMarker  string
	// Incomplete is set by distributed backends configured to allow it when
	// some part of the namespace could not be listed. The result is then a
	// subset of the truth.
	Incomplete bool
}

// ListVersionsResult is the result of ListObjectVersions.
type ListVersionsResult struct {
	Versions            []ObjectInfo
	Prefixes            []string
	IsTruncated         bool
	NextMarker          string
	NextVersionIDMarker string
}

// PartOptions controls PutObjectPart.
type PartOptions struct {
	ContentMD5    string
	ContentSHA256 string
}

// PartInfo describes one uploaded part.
type PartInfo struct {
	Number  int
	ETag    string
	Size    int64
	ModTime time.Time
}

// CompletePart is one entry of a CompleteMultipartUpload request.
type CompletePart struct {
	Number int
	ETag   string
}

// ListPartsOptions controls ListObjectParts.
type ListPartsOptions struct {
	PartNumberMarker int
	MaxParts         int
}

// ListPartsResult is the result of ListObjectParts.
type ListPartsResult struct {
	// UserDefined is the metadata the upload was created with; the API
	// layer reads the encryption description of an upload from it.
	UserDefined          map[string]string
	Parts                []PartInfo
	IsTruncated          bool
	NextPartNumberMarker int
}

// ListUploadsOptions controls ListMultipartUploads.
type ListUploadsOptions struct {
	Prefix         string
	Delimiter      string
	KeyMarker      string
	UploadIDMarker string
	MaxUploads     int
}

// UploadInfo describes one in-progress multipart upload.
type UploadInfo struct {
	Object    string
	UploadID  string
	Initiated time.Time
}

// ListUploadsResult is the result of ListMultipartUploads.
type ListUploadsResult struct {
	Uploads            []UploadInfo
	Prefixes           []string
	IsTruncated        bool
	NextKeyMarker      string
	NextUploadIDMarker string
}

// BackendInfo reports backend identity and health.
type BackendInfo struct {
	Kind       string // "fs" or "xl"
	Disks      int
	TotalBytes uint64
	FreeBytes  uint64
	Healthy    bool
	// Corrupted counts metadata files skipped because they failed
	// verification.
	Corrupted int
}
