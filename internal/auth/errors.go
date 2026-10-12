package auth

import "errors"

// Sentinel errors returned by Authenticate and the chunk signer. They carry
// no HTTP detail: api/ maps each to an S3 code and status, and a test fails
// if one is missing from that table (see AllErrors).
var (
	// ErrAnonymous means the request carried no credentials at all.
	ErrAnonymous = errors.New("auth: request is not signed")
	// ErrInvalidAccessKeyID means the access key is unknown or disabled.
	ErrInvalidAccessKeyID = errors.New("auth: access key id does not exist")
	// ErrSignatureDoesNotMatch means the computed signature differs.
	ErrSignatureDoesNotMatch = errors.New("auth: signature does not match")
	// ErrAuthHeaderMalformed means the Authorization header is unparseable
	// or its credential scope is wrong.
	ErrAuthHeaderMalformed = errors.New("auth: authorization header is malformed")
	// ErrQueryParamsMalformed is ErrAuthHeaderMalformed for presigned URLs.
	ErrQueryParamsMalformed = errors.New("auth: authorization query parameters are malformed")
	// ErrMissingSecurityHeader means a header required for signing is
	// absent (x-amz-date, x-amz-content-sha256).
	ErrMissingSecurityHeader = errors.New("auth: missing required header")
	// ErrRequestTimeTooSkewed means the request time is too far from now.
	ErrRequestTimeTooSkewed = errors.New("auth: request time is too skewed")
	// ErrRequestExpired means a presigned URL is past its X-Amz-Expires.
	ErrRequestExpired = errors.New("auth: request has expired")
	// ErrUnsupportedAlgorithm means a signing scheme other than
	// AWS4-HMAC-SHA256 (SigV2, ECDSA) was used.
	ErrUnsupportedAlgorithm = errors.New("auth: unsupported authorization mechanism")
	// ErrInvalidToken means a temporary credential was used without its
	// session token, or with a wrong one.
	ErrInvalidToken = errors.New("auth: the session token is missing or does not match")
	// ErrInvalidPayloadHash means x-amz-content-sha256 is not a known value.
	ErrInvalidPayloadHash = errors.New("auth: invalid x-amz-content-sha256")
	// ErrUnsignedHeaders means x-amz-* headers were sent but not signed.
	ErrUnsignedHeaders = errors.New("auth: headers present in the request were not signed")
	// ErrAmbiguousAuth means header and query authentication were mixed.
	ErrAmbiguousAuth = errors.New("auth: more than one authentication mechanism")
)

// AllErrors returns every sentinel, for the exhaustiveness test in api/.
func AllErrors() []error {
	return []error{
		ErrAnonymous, ErrInvalidAccessKeyID, ErrSignatureDoesNotMatch,
		ErrAuthHeaderMalformed, ErrQueryParamsMalformed, ErrMissingSecurityHeader,
		ErrRequestTimeTooSkewed, ErrRequestExpired, ErrUnsupportedAlgorithm,
		ErrInvalidToken, ErrInvalidPayloadHash, ErrUnsignedHeaders, ErrAmbiguousAuth,
	}
}
