package storage

import "errors"

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
)

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
		ErrDiskFull, ErrCorrupted, ErrNotImplemented,
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
