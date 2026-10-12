package storage

import (
	"errors"
	"time"
)

// Sentinel errors. The mapping to S3 codes and HTTP statuses lives in api/ so
// this package stays HTTP-free; api/ has a test that fails if any sentinel
// returned by AllErrors has no mapping.
var (
	ErrBucketNotFound     = errors.New("bucket not found")
	ErrBucketExists       = errors.New("bucket already exists")
	ErrBucketNotEmpty     = errors.New("bucket not empty")
	ErrInvalidBucketName  = errors.New("invalid bucket name")
	ErrObjectNotFound     = errors.New("object not found")
	ErrVersionNotFound    = errors.New("version not found")
	ErrIsDeleteMarker     = errors.New("object is a delete marker")
	ErrKeyTooLong         = errors.New("object key too long")
	ErrInvalidObjectName  = errors.New("invalid object name")
	ErrBadDigest          = errors.New("content-md5 does not match body")
	ErrSHA256Mismatch     = errors.New("content-sha256 does not match body")
	ErrIncompleteBody     = errors.New("body shorter than declared size")
	ErrEntityTooLarge     = errors.New("object too large")
	ErrInvalidRange       = errors.New("invalid byte range")
	ErrPreconditionFailed = errors.New("precondition failed")
	ErrNoSuchUpload       = errors.New("no such multipart upload")
	ErrInvalidPart        = errors.New("invalid part")
	ErrInvalidPartOrder   = errors.New("parts not in ascending order")
	ErrEntityTooSmall     = errors.New("part too small")
	ErrLockTimeout        = errors.New("timed out waiting for namespace lock")
	ErrBackendUnavailable = errors.New("storage backend unavailable")
	ErrDiskFull           = errors.New("disk full")
	ErrCorrupted          = errors.New("stored data failed verification")
	ErrNotImplemented     = errors.New("not implemented")
	// ErrIllegalVersioning is a versioning configuration the state machine
	// does not allow.
	ErrIllegalVersioning = errors.New("illegal versioning configuration")
	// ErrObjectLocked means object lock refuses the change: a legal hold,
	// or retention that has not ended and that the caller may not bypass.
	ErrObjectLocked = errors.New("object is protected by object lock")
	// ErrObjectLockNotEnabled means the bucket was not created with object
	// lock, so there is nothing to configure or apply.
	ErrObjectLockNotEnabled = errors.New("bucket does not have object lock enabled")
	// ErrInvalidRetention is a retention that is malformed or already over.
	ErrInvalidRetention = errors.New("invalid retention")
	// ErrInvalidBucketState means the bucket's state does not allow the
	// request, such as suspending versioning on a bucket with object lock.
	ErrInvalidBucketState = errors.New("invalid bucket state")
	// ErrInvalidVersionID is a version ID that is neither "null" nor a UUID.
	ErrInvalidVersionID = errors.New("invalid version id")
)

// DeleteMarkerError reports that the version a read resolved to is a delete
// marker. Without an explicit version ID the object is "not found" (and
// matches ErrObjectNotFound, as in S3, which answers 404); asking for the
// marker's own version ID is "method not allowed" (ErrIsDeleteMarker, 405).
// Either way the marker's identity travels with it for the response headers.
type DeleteMarkerError struct {
	Bucket, Object string
	VersionID      string // as reported: "null" or a UUID
	ModTime        time.Time
	// Explicit is true when the caller named the marker's version ID.
	Explicit bool
}

func (e *DeleteMarkerError) Error() string {
	if e.Explicit {
		return ErrIsDeleteMarker.Error() + ": " + e.Bucket + "/" + e.Object
	}
	return ErrObjectNotFound.Error() + " (latest version is a delete marker): " + e.Bucket + "/" + e.Object
}

// Is makes the error match the sentinel that fits the request.
func (e *DeleteMarkerError) Is(target error) bool {
	if e.Explicit {
		return target == ErrIsDeleteMarker
	}
	return target == ErrObjectNotFound
}

// AllErrors returns every sentinel, for exhaustiveness checks.
func AllErrors() []error {
	return []error{
		ErrBucketNotFound, ErrBucketExists, ErrBucketNotEmpty,
		ErrInvalidBucketName, ErrObjectNotFound, ErrVersionNotFound,
		ErrIsDeleteMarker, ErrKeyTooLong, ErrInvalidObjectName,
		ErrBadDigest, ErrSHA256Mismatch, ErrIncompleteBody,
		ErrEntityTooLarge, ErrInvalidRange, ErrPreconditionFailed,
		ErrNoSuchUpload, ErrInvalidPart, ErrInvalidPartOrder,
		ErrEntityTooSmall, ErrLockTimeout, ErrBackendUnavailable,
		ErrDiskFull, ErrCorrupted, ErrNotImplemented, ErrIllegalVersioning, ErrInvalidVersionID,
		ErrObjectLocked, ErrObjectLockNotEnabled, ErrInvalidRetention, ErrInvalidBucketState,
	}
}

// ObjectError attaches the bucket and object a sentinel refers to. It matches
// its sentinel with errors.Is.
type ObjectError struct {
	Bucket string
	Object string
	Err    error
}

func (e *ObjectError) Error() string {
	switch {
	case e.Bucket == "":
		return e.Err.Error()
	case e.Object == "":
		return e.Err.Error() + ": " + e.Bucket
	default:
		return e.Err.Error() + ": " + e.Bucket + "/" + e.Object
	}
}

func (e *ObjectError) Unwrap() error { return e.Err }

// Wrap returns err annotated with bucket and object.
func Wrap(err error, bucket, object string) error {
	if err == nil {
		return nil
	}
	return &ObjectError{Bucket: bucket, Object: object, Err: err}
}
