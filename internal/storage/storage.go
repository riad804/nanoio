// Package storage defines StorageAPI, the object-level abstraction every
// NanoIO backend (fs, xl) implements. It is policy-free and HTTP-free: it
// stores and returns bytes and metadata and knows nothing about users,
// signatures or S3 wire formats.
package storage

import (
	"context"
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

	// Objects.
	PutObject(ctx context.Context, bucket, object string, r io.Reader, size int64, opts PutOptions) (ObjectInfo, error)
	GetObject(ctx context.Context, bucket, object string, opts GetOptions) (io.ReadCloser, ObjectInfo, error)
	StatObject(ctx context.Context, bucket, object string, opts GetOptions) (ObjectInfo, error)
	DeleteObject(ctx context.Context, bucket, object string, opts DeleteOptions) (DeleteResult, error)
	CopyObject(ctx context.Context, src, dst ObjectRef, opts CopyOptions) (ObjectInfo, error)
	UpdateObjectMetadata(ctx context.Context, bucket, object string, opts UpdateMetaOptions) (ObjectInfo, error)
	ListObjects(ctx context.Context, bucket string, opts ListOptions) (ListResult, error)
	ListObjectVersions(ctx context.Context, bucket string, opts ListOptions) (ListVersionsResult, error)

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

// MakeBucketOptions is reserved for future per-bucket creation settings.
type MakeBucketOptions struct{}

// DeleteBucketOptions controls DeleteBucket.
type DeleteBucketOptions struct {
	// Force removes the bucket even if it contains objects.
	Force bool
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
	// Versioned is decided by the caller from bucket config.
	Versioned   bool
	IfMatch     string // commit only if the current ETag matches
	IfNoneMatch string // "*" commits only if the key does not exist
}

// GetOptions controls GetObject and StatObject.
type GetOptions struct {
	VersionID string
	Range     *ByteRange
}

// DeleteOptions controls DeleteObject.
type DeleteOptions struct {
	VersionID string
	// Versioned without VersionID writes a delete marker.
	Versioned bool
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

// UpdateMetaOptions replaces the user metadata of one version.
type UpdateMetaOptions struct {
	VersionID   string
	UserDefined map[string]string
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
}

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
