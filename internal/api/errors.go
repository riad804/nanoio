package api

import (
	"context"
	"encoding/xml"
	"errors"
	"net/http"
	"strings"

	"nanoio/internal/auth"
	"nanoio/internal/storage"
)

// APIError is an S3 error: a code clients switch on, a human message and an
// HTTP status. It implements error so handlers can return it uniformly.
type APIError struct {
	Code    string
	Message string
	Status  int
}

func (e *APIError) Error() string { return e.Code + ": " + e.Message }

// API-level errors that do not originate in storage.
var (
	errMalformedXML = &APIError{"MalformedXML", "The XML you provided was not well-formed or did not validate against our published schema.", http.StatusBadRequest}
	errMissingLen   = &APIError{"MissingContentLength", "You must provide the Content-Length HTTP header.", http.StatusLengthRequired}
	errBadMethod    = &APIError{"MethodNotAllowed", "The specified method is not allowed against this resource.", http.StatusMethodNotAllowed}
	errInvalidMD5   = &APIError{"InvalidDigest", "The Content-MD5 you specified is not valid.", http.StatusBadRequest}
	errMetaTooLarge = &APIError{"MetadataTooLarge", "Your metadata headers exceed the maximum allowed metadata size.", http.StatusBadRequest}
	errTooManyKeys  = &APIError{"MalformedXML", "The request must not contain more than 1000 keys.", http.StatusBadRequest}
	errBadChunk     = &APIError{"InvalidRequest", "The aws-chunked request body is malformed.", http.StatusBadRequest}
	errEntityLarge  = &APIError{"EntityTooLarge", "Your proposed upload exceeds the maximum allowed size.", http.StatusBadRequest}
	errInternal     = &APIError{"InternalError", "We encountered an internal error. Please try again.", http.StatusInternalServerError}
	errNotModified  = &APIError{"NotModified", "Not Modified", http.StatusNotModified}
	errPrecondition = &APIError{"PreconditionFailed", "At least one of the pre-conditions you specified did not hold.", http.StatusPreconditionFailed}
	errInvalidRange = &APIError{"InvalidRange", "The requested range is not satisfiable.", http.StatusRequestedRangeNotSatisfiable}
	errAccessDenied = &APIError{"AccessDenied", "Access Denied.", http.StatusForbidden}
	errSHA256Wrong  = &APIError{"XAmzContentSHA256Mismatch", "The provided 'x-amz-content-sha256' header does not match what was computed.", http.StatusBadRequest}
)

// authErrors maps every auth sentinel to its S3 representation. A test
// fails if auth.AllErrors() contains an error missing from here.
var authErrors = []struct {
	err error
	api APIError
}{
	{auth.ErrAnonymous, APIError{"AccessDenied", "Access Denied.", 403}},
	{auth.ErrInvalidAccessKeyID, APIError{"InvalidAccessKeyId", "The Access Key Id you provided does not exist in our records.", 403}},
	{auth.ErrSignatureDoesNotMatch, APIError{"SignatureDoesNotMatch", "The request signature we calculated does not match the signature you provided. Check your key and signing method.", 403}},
	{auth.ErrAuthHeaderMalformed, APIError{"AuthorizationHeaderMalformed", "The authorization header is malformed.", 400}},
	{auth.ErrQueryParamsMalformed, APIError{"AuthorizationQueryParametersError", "The authorization query parameters are malformed.", 400}},
	{auth.ErrMissingSecurityHeader, APIError{"MissingSecurityHeader", "Your request was missing a required header.", 400}},
	{auth.ErrRequestTimeTooSkewed, APIError{"RequestTimeTooSkewed", "The difference between the request time and the current time is too large.", 403}},
	{auth.ErrRequestExpired, APIError{"AccessDenied", "Request has expired.", 403}},
	{auth.ErrUnsupportedAlgorithm, APIError{"InvalidRequest", "The authorization mechanism you have provided is not supported. Please use AWS4-HMAC-SHA256.", 400}},
	{auth.ErrInvalidToken, APIError{"InvalidToken", "The provided token is malformed or otherwise invalid.", 400}},
	{auth.ErrInvalidPayloadHash, APIError{"InvalidArgument", "x-amz-content-sha256 must be UNSIGNED-PAYLOAD, STREAMING-UNSIGNED-PAYLOAD-TRAILER, STREAMING-AWS4-HMAC-SHA256-PAYLOAD, STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER or a valid sha256 value.", 400}},
	{auth.ErrUnsignedHeaders, APIError{"AccessDenied", "There were headers present in the request which were not signed.", 403}},
	{auth.ErrAmbiguousAuth, APIError{"InvalidArgument", "Only one auth mechanism allowed; only the X-Amz-Algorithm query parameter, Signature query string parameter or the Authorization header should be specified.", 400}},
}

func invalidArgument(msg string) *APIError {
	return &APIError{"InvalidArgument", msg, http.StatusBadRequest}
}

func invalidRequest(msg string) *APIError {
	return &APIError{"InvalidRequest", msg, http.StatusBadRequest}
}

func notImplemented(what string) *APIError {
	return &APIError{"NotImplemented", "A header you provided implies functionality that is not implemented: " + what, http.StatusNotImplemented}
}

// storageErrors maps every storage sentinel to its S3 representation. A
// test fails if storage.AllErrors() contains an error missing from here.
var storageErrors = []struct {
	err error
	api APIError
}{
	{storage.ErrBucketNotFound, APIError{"NoSuchBucket", "The specified bucket does not exist.", 404}},
	{storage.ErrBucketExists, APIError{"BucketAlreadyOwnedByYou", "Your previous request to create the named bucket succeeded and you already own it.", 409}},
	{storage.ErrBucketNotEmpty, APIError{"BucketNotEmpty", "The bucket you tried to delete is not empty.", 409}},
	{storage.ErrInvalidBucketName, APIError{"InvalidBucketName", "The specified bucket is not valid.", 400}},
	{storage.ErrObjectNotFound, APIError{"NoSuchKey", "The specified key does not exist.", 404}},
	{storage.ErrVersionNotFound, APIError{"NoSuchVersion", "The specified version does not exist.", 404}},
	{storage.ErrIsDeleteMarker, APIError{"MethodNotAllowed", "The specified method is not allowed against this resource.", 405}},
	{storage.ErrKeyTooLong, APIError{"KeyTooLongError", "Your key is too long.", 400}},
	{storage.ErrInvalidObjectName, APIError{"XNanoIOInvalidObjectName", "The object name is not supported by this server.", 400}},
	{storage.ErrBadDigest, APIError{"BadDigest", "The Content-MD5 you specified did not match what we received.", 400}},
	{storage.ErrSHA256Mismatch, APIError{"XAmzContentSHA256Mismatch", "The provided 'x-amz-content-sha256' header does not match what was computed.", 400}},
	{storage.ErrIncompleteBody, APIError{"IncompleteBody", "You did not provide the number of bytes specified by the Content-Length HTTP header.", 400}},
	{storage.ErrEntityTooLarge, APIError{"EntityTooLarge", "Your proposed upload exceeds the maximum allowed object size.", 400}},
	{storage.ErrInvalidRange, APIError{"InvalidRange", "The requested range is not satisfiable.", 416}},
	{storage.ErrPreconditionFailed, APIError{"PreconditionFailed", "At least one of the pre-conditions you specified did not hold.", 412}},
	{storage.ErrNoSuchUpload, APIError{"NoSuchUpload", "The specified multipart upload does not exist.", 404}},
	{storage.ErrInvalidPart, APIError{"InvalidPart", "One or more of the specified parts could not be found.", 400}},
	{storage.ErrInvalidPartOrder, APIError{"InvalidPartOrder", "The list of parts was not in ascending order.", 400}},
	{storage.ErrEntityTooSmall, APIError{"EntityTooSmall", "Your proposed upload is smaller than the minimum allowed object size.", 400}},
	{storage.ErrLockTimeout, APIError{"SlowDown", "Resource requested is busy. Please reduce your request rate.", 503}},
	{storage.ErrBackendUnavailable, APIError{"ServiceUnavailable", "The service is unavailable. Please retry.", 503}},
	{storage.ErrDiskFull, APIError{"XNanoIOStorageFull", "Storage backend has reached its minimum free drive threshold.", 507}},
	{storage.ErrCorrupted, APIError{"InternalError", "We encountered an internal error. Please try again.", 500}},
	{storage.ErrInvalidVersionID, APIError{"InvalidArgument", "Invalid version id specified", 400}},
	{storage.ErrIllegalVersioning, APIError{"IllegalVersioningConfigurationException", "The versioning configuration specified in the request is invalid.", 400}},
	{storage.ErrObjectLocked, APIError{"AccessDenied", "Access Denied because object protected by object lock.", 403}},
	{storage.ErrObjectLockNotEnabled, APIError{"InvalidRequest", "Bucket is missing Object Lock Configuration", 400}},
	{storage.ErrInvalidRetention, APIError{"InvalidArgument", "The retention is not valid.", 400}},
	{storage.ErrInvalidBucketState, APIError{"InvalidBucketState", "The request is not valid with the current state of the bucket.", 409}},
	{storage.ErrInvalidStorageClass, APIError{"InvalidStorageClass", "The storage class you specified is not valid.", 400}},
	{storage.ErrNotImplemented, APIError{"NotImplemented", "A header you provided implies functionality that is not implemented.", 501}},
}

// detailSafe lists the storage errors whose wrapped explanation is meant
// for the client (which part, how small). Others, such as corruption, wrap
// internal paths and keep their stock message.
var detailSafe = map[error]bool{
	storage.ErrInvalidBucketName: true, storage.ErrInvalidObjectName: true, storage.ErrKeyTooLong: true,
	storage.ErrInvalidPart: true, storage.ErrInvalidPartOrder: true, storage.ErrEntityTooSmall: true,
	storage.ErrInvalidRetention: true, storage.ErrInvalidBucketState: true,
}

// classify turns any error into the APIError to send. The second result is
// false when the client is gone and nothing should be written. Unknown
// errors become InternalError; the caller logs them with the cause.
func classify(err error) (apiErr *APIError, respond bool, known bool) {
	var ae *APIError
	switch {
	case errors.As(err, &ae):
		return ae, true, true
	case errors.Is(err, context.Canceled):
		return nil, false, true
	case errors.Is(err, context.DeadlineExceeded):
		return &APIError{"RequestTimeout", "Your socket connection to the server was not read from or written to within the timeout period.", http.StatusBadRequest}, true, true
	case errors.Is(err, errChunkFormat):
		return errBadChunk, true, true
	}
	var mbe *http.MaxBytesError
	if errors.As(err, &mbe) {
		return errEntityLarge, true, true
	}
	for _, m := range authErrors {
		if errors.Is(err, m.err) {
			e := m.api
			// The detail wrapped around a sentinel (expected region, skew,
			// which headers were unsigned) is safe and useful to the client.
			if d := detail(err, m.err); d != "" {
				e.Message = d
			}
			return &e, true, true
		}
	}
	for _, m := range storageErrors {
		if errors.Is(err, m.err) {
			e := m.api
			if detailSafe[m.err] {
				inner := err
				var oe *storage.ObjectError
				if errors.As(err, &oe) {
					inner = oe.Err
				}
				if d := detail(inner, m.err); d != "" {
					e.Message = d
				}
			}
			return &e, true, true
		}
	}
	return errInternal, true, false
}

// errorResponse is the S3 error XML body.
type errorResponse struct {
	XMLName    xml.Name `xml:"Error"`
	Code       string   `xml:"Code"`
	Message    string   `xml:"Message"`
	BucketName string   `xml:"BucketName,omitempty"`
	Key        string   `xml:"Key,omitempty"`
	Resource   string   `xml:"Resource"`
	RequestID  string   `xml:"RequestId"`
	HostID     string   `xml:"HostId"`
}

// detail returns the human text a wrapping error adds around sentinel, e.g.
// "the region \"x\" is wrong; expecting \"us-east-1\"" for
// "auth: ...: the region ...". It returns "" when nothing was added.
func detail(err, sentinel error) string {
	full, base := err.Error(), sentinel.Error()
	if full == base {
		return ""
	}
	if rest, ok := strings.CutPrefix(full, base+": "); ok {
		return upperFirst(rest) + "."
	}
	return ""
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
