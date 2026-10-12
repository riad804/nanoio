package auth

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// CredentialProvider looks up secrets. Implementations must return ok=false
// for unknown and for disabled keys alike.
type CredentialProvider interface {
	SecretKey(accessKey string) (secret string, ok bool)
}

// Verifier authenticates S3 requests signed with SigV4, either through the
// Authorization header or as a presigned URL.
type Verifier struct {
	Provider CredentialProvider
	// Region the credential scope must name. Empty accepts any region.
	Region string
	// AllowSessionToken accepts X-Amz-Security-Token; the caller must then
	// check that it matches the credential (temporary credentials).
	AllowSessionToken bool
	// Service is the credential-scope service name the verifier requires;
	// empty means "s3". (The STS endpoint is signed for "sts".)
	Service string
	// RegionlessPrefixes lists request path prefixes whose clients sign
	// with an empty credential-scope region (the MinIO admin SDK does).
	// Only an empty region is added to what is accepted there.
	RegionlessPrefixes []string
	// MaxSkew bounds |now - request time|; zero means 15 minutes.
	MaxSkew time.Duration
	// Now is the clock; nil means time.Now.
	Now func() time.Time

	// Test hooks. The official AWS test suite targets a generic service
	// ("service"), normalises paths, and computes the payload hash from the
	// body rather than reading x-amz-content-sha256.
	service     string
	generic     bool
	payloadHash func(r *http.Request) string
}

// Result describes an authenticated request.
type Result struct {
	AccessKey string
	// Presigned is true for query-string authentication.
	Presigned bool
	// PayloadHash is the value that was signed: a hex SHA-256, or one of
	// the Payload* sentinels.
	PayloadHash string
	// Chunk is non-nil for STREAMING-AWS4-HMAC-SHA256-PAYLOAD[-TRAILER]
	// bodies and must be used to verify every chunk before it is trusted.
	Chunk *ChunkSigner
	// SignedAt is the signing time.
	SignedAt time.Time
}

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

func (v *Verifier) skew() time.Duration {
	if v.MaxSkew > 0 {
		return v.MaxSkew
	}
	return 15 * time.Minute
}

func (v *Verifier) svc() string {
	if v.Service != "" {
		return v.Service
	}
	if v.service != "" {
		return v.service
	}
	return "s3"
}

// Authenticate verifies the request's signature. It returns ErrAnonymous
// when the request carries no credentials; every other failure is one of
// the package's sentinels, possibly wrapped with detail for the message.
func (v *Verifier) Authenticate(r *http.Request) (*Result, error) {
	authz := r.Header.Get("Authorization")
	rawQuery := rawQueryOf(r)
	q, _ := url.ParseQuery(rawQuery)
	presigned := q.Has("X-Amz-Algorithm") || q.Has("X-Amz-Signature") || q.Has("X-Amz-Credential")
	switch {
	case authz != "" && presigned:
		return nil, ErrAmbiguousAuth
	case authz != "":
		return v.authenticateHeader(r, authz, rawQuery)
	case presigned:
		return v.authenticatePresigned(r, q, rawQuery)
	case q.Has("AWSAccessKeyId") && q.Has("Signature"):
		return nil, fmt.Errorf("%w: SigV2 presigned URLs; use AWS4-HMAC-SHA256", ErrUnsupportedAlgorithm)
	}
	return nil, ErrAnonymous
}

// rawQueryOf returns the query string exactly as sent.
func rawQueryOf(r *http.Request) string {
	if r.RequestURI != "" {
		if _, q, ok := strings.Cut(r.RequestURI, "?"); ok {
			return q
		}
		return ""
	}
	if r.URL != nil {
		return r.URL.RawQuery
	}
	return ""
}

func rawPathOf(r *http.Request) string {
	if r.RequestURI != "" {
		p, _, _ := strings.Cut(r.RequestURI, "?")
		return p
	}
	return r.URL.EscapedPath()
}

// requestHeaders gathers the request's headers by lowercase name, adding
// the pseudo-headers Go's server strips (Host, Transfer-Encoding).
func requestHeaders(r *http.Request) headerSet {
	h := make(headerSet, len(r.Header)+2)
	for k, vs := range r.Header {
		h[strings.ToLower(k)] = vs
	}
	if _, ok := h["host"]; !ok {
		host := r.Host
		if host == "" && r.URL != nil {
			host = r.URL.Host
		}
		h["host"] = []string{host}
	}
	if _, ok := h["transfer-encoding"]; !ok && len(r.TransferEncoding) > 0 {
		h["transfer-encoding"] = []string{strings.Join(r.TransferEncoding, ",")}
	}
	return h
}

// canonicalURIFor picks the S3 or generic path canonicalisation.
func (v *Verifier) canonicalURIFor(r *http.Request) string {
	if v.generic {
		return canonicalURIGeneric(rawPathOf(r))
	}
	return canonicalURIS3(r.URL.Path)
}

type credentialScope struct {
	accessKey, date, region, service string
}

// parseCredential splits "AKID/20150830/us-east-1/s3/aws4_request".
func parseCredential(s string) (credentialScope, bool) {
	parts := strings.Split(s, "/")
	if len(parts) != 5 || parts[4] != Terminator || parts[0] == "" {
		return credentialScope{}, false
	}
	return credentialScope{parts[0], parts[1], parts[2], parts[3]}, true
}

// checkScope validates the date, region and service of a credential scope
// against the request time and the server's configuration.
func (v *Verifier) checkScope(r *http.Request, sc credentialScope, t time.Time, malformed error) error {
	if sc.date != t.UTC().Format(scopeDateLayout) {
		return fmt.Errorf("%w: the date in the credential scope %q does not match the request date %q",
			malformed, sc.date, t.UTC().Format(scopeDateLayout))
	}
	if sc.service != v.svc() {
		return fmt.Errorf("%w: the credential scope service is %q, expecting %q",
			malformed, sc.service, v.svc())
	}
	if sc.region == "" && v.regionless(r) {
		return nil
	}
	if v.Region != "" && sc.region != v.Region {
		return fmt.Errorf("%w: the region %q is wrong; expecting %q", malformed, sc.region, v.Region)
	}
	return nil
}

func (v *Verifier) regionless(r *http.Request) bool {
	for _, p := range v.RegionlessPrefixes {
		if r.URL != nil && strings.HasPrefix(r.URL.Path, p) {
			return true
		}
	}
	return false
}

// unsignedAmzHeaders returns the x-amz-* headers present in the request
// that SignedHeaders does not cover. Leaving them unsigned would let an
// intermediary rewrite metadata, copy sources or ACLs.
func unsignedAmzHeaders(r *http.Request, signed []string) []string {
	set := make(map[string]bool, len(signed))
	for _, s := range signed {
		set[s] = true
	}
	var bad []string
	for k := range r.Header {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-amz-") && !set[lk] {
			bad = append(bad, lk)
		}
	}
	sort.Strings(bad)
	return bad
}

func hasHost(signed []string) bool {
	for _, s := range signed {
		if s == "host" {
			return true
		}
	}
	return false
}

func validPayloadHash(p string) bool {
	switch p {
	case PayloadUnsigned, PayloadStreamingSigned, PayloadStreamingTrailer, PayloadStreamingUnsigned:
		return true
	}
	if len(p) != 64 {
		return false
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func (v *Verifier) authenticateHeader(r *http.Request, authz, rawQuery string) (*Result, error) {
	algo, rest, _ := strings.Cut(authz, " ")
	if algo != Algorithm {
		return nil, fmt.Errorf("%w: use %s", ErrUnsupportedAlgorithm, Algorithm)
	}
	fields := map[string]string{}
	for _, part := range strings.Split(rest, ",") {
		k, val, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			return nil, fmt.Errorf("%w: expected Credential, SignedHeaders and Signature fields", ErrAuthHeaderMalformed)
		}
		fields[k] = val
	}
	sc, ok := parseCredential(fields["Credential"])
	if !ok {
		return nil, fmt.Errorf("%w: the Credential must be <access key>/<date>/<region>/<service>/%s", ErrAuthHeaderMalformed, Terminator)
	}
	signed := sortedLower(strings.Split(fields["SignedHeaders"], ";"))
	if len(signed) == 0 || fields["Signature"] == "" {
		return nil, fmt.Errorf("%w: SignedHeaders and Signature are required", ErrAuthHeaderMalformed)
	}

	amzDate := r.Header.Get("X-Amz-Date")
	var t time.Time
	var err error
	switch {
	case amzDate != "":
		if t, err = parseAmzDate(amzDate); err != nil {
			return nil, fmt.Errorf("%w: X-Amz-Date must be in the ISO 8601 basic format", ErrAuthHeaderMalformed)
		}
	case r.Header.Get("Date") != "":
		if t, err = http.ParseTime(r.Header.Get("Date")); err != nil {
			return nil, fmt.Errorf("%w: Date is not a valid HTTP date", ErrAuthHeaderMalformed)
		}
		amzDate = t.UTC().Format(amzDateLayout)
	default:
		return nil, fmt.Errorf("%w: Authorization header requires an X-Amz-Date or Date header", ErrMissingSecurityHeader)
	}
	if d := v.now().Sub(t); d > v.skew() || d < -v.skew() {
		return nil, fmt.Errorf("%w: request time %s, server time %s",
			ErrRequestTimeTooSkewed, t.UTC().Format(time.RFC3339), v.now().UTC().Format(time.RFC3339))
	}
	if err := v.checkScope(r, sc, t, ErrAuthHeaderMalformed); err != nil {
		return nil, err
	}
	if !hasHost(signed) {
		return nil, fmt.Errorf("%w: host must be a signed header", ErrAuthHeaderMalformed)
	}

	var payload string
	switch {
	case v.payloadHash != nil:
		payload = v.payloadHash(r)
	default:
		payload = r.Header.Get("X-Amz-Content-Sha256")
		if payload == "" {
			return nil, fmt.Errorf("%w: the x-amz-content-sha256 header is required", ErrMissingSecurityHeader)
		}
		if !validPayloadHash(payload) {
			return nil, ErrInvalidPayloadHash
		}
	}
	if !v.generic {
		if !v.AllowSessionToken && r.Header.Get("X-Amz-Security-Token") != "" {
			return nil, ErrInvalidToken
		}
	}

	secret, found := v.Provider.SecretKey(sc.accessKey)
	if !found {
		return nil, ErrInvalidAccessKeyID
	}
	if !v.generic {
		if bad := unsignedAmzHeaders(r, signed); len(bad) > 0 {
			return nil, fmt.Errorf("%w: these headers were sent but are not listed in SignedHeaders: %s", ErrUnsignedHeaders, strings.Join(bad, ", "))
		}
	}

	hdrs, ok := canonicalHeaders(requestHeaders(r), signed)
	if !ok {
		return nil, ErrSignatureDoesNotMatch
	}
	creq := canonicalRequest(r.Method, v.canonicalURIFor(r), canonicalQuery(rawQuery, nil), hdrs, signed, payload)
	scope := scopeString(sc.date, sc.region, sc.service)
	key := signingKey(secret, sc.date, sc.region, sc.service)
	want := hexMAC(key, stringToSign(amzDate, scope, creq))
	if !equalHex(want, strings.ToLower(fields["Signature"])) {
		return nil, ErrSignatureDoesNotMatch
	}

	res := &Result{AccessKey: sc.accessKey, PayloadHash: payload, SignedAt: t}
	switch payload {
	case PayloadStreamingSigned, PayloadStreamingTrailer:
		res.Chunk = newChunkSigner(key, amzDate, scope, want, payload == PayloadStreamingTrailer)
	}
	return res, nil
}

func (v *Verifier) authenticatePresigned(r *http.Request, q url.Values, rawQuery string) (*Result, error) {
	get := func(name string) string { return q.Get(name) }
	if get("X-Amz-Algorithm") != Algorithm {
		return nil, fmt.Errorf("%w: X-Amz-Algorithm must be %s", ErrUnsupportedAlgorithm, Algorithm)
	}
	for _, p := range []string{"X-Amz-Credential", "X-Amz-Date", "X-Amz-Expires", "X-Amz-SignedHeaders", "X-Amz-Signature"} {
		if get(p) == "" {
			return nil, fmt.Errorf("%w: %s is required", ErrQueryParamsMalformed, p)
		}
	}
	if !v.AllowSessionToken && q.Has("X-Amz-Security-Token") {
		return nil, ErrInvalidToken
	}
	sc, ok := parseCredential(get("X-Amz-Credential"))
	if !ok {
		return nil, fmt.Errorf("%w: X-Amz-Credential must be <access key>/<date>/<region>/<service>/%s", ErrQueryParamsMalformed, Terminator)
	}
	t, err := parseAmzDate(get("X-Amz-Date"))
	if err != nil {
		return nil, fmt.Errorf("%w: X-Amz-Date must be in the ISO 8601 basic format", ErrQueryParamsMalformed)
	}
	secs, err := strconv.Atoi(get("X-Amz-Expires"))
	if err != nil || secs < 1 {
		return nil, fmt.Errorf("%w: X-Amz-Expires must be a positive integer", ErrQueryParamsMalformed)
	}
	if secs > 604800 {
		return nil, fmt.Errorf("%w: X-Amz-Expires must be less than 604800 seconds", ErrQueryParamsMalformed)
	}
	now := v.now()
	if t.Sub(now) > v.skew() {
		return nil, fmt.Errorf("%w: the request is not valid yet", ErrRequestTimeTooSkewed)
	}
	if now.After(t.Add(time.Duration(secs) * time.Second)) {
		return nil, ErrRequestExpired
	}
	if err := v.checkScope(r, sc, t, ErrQueryParamsMalformed); err != nil {
		return nil, err
	}
	signed := sortedLower(strings.Split(get("X-Amz-SignedHeaders"), ";"))
	if !hasHost(signed) {
		return nil, fmt.Errorf("%w: host must be a signed header", ErrQueryParamsMalformed)
	}

	payload := PayloadUnsigned
	if h := r.Header.Get("X-Amz-Content-Sha256"); h != "" {
		if !validPayloadHash(h) || strings.HasPrefix(h, "STREAMING-") {
			return nil, ErrInvalidPayloadHash
		}
		payload = h
	}

	secret, found := v.Provider.SecretKey(sc.accessKey)
	if !found {
		return nil, ErrInvalidAccessKeyID
	}
	if !v.generic {
		if bad := unsignedAmzHeaders(r, signed); len(bad) > 0 {
			return nil, fmt.Errorf("%w: these headers were sent but are not listed in SignedHeaders: %s", ErrUnsignedHeaders, strings.Join(bad, ", "))
		}
	}
	hdrs, ok := canonicalHeaders(requestHeaders(r), signed)
	if !ok {
		return nil, ErrSignatureDoesNotMatch
	}
	query := canonicalQuery(rawQuery, func(n string) bool { return n == "X-Amz-Signature" })
	creq := canonicalRequest(r.Method, v.canonicalURIFor(r), query, hdrs, signed, payload)
	scope := scopeString(sc.date, sc.region, sc.service)
	key := signingKey(secret, sc.date, sc.region, sc.service)
	want := hexMAC(key, stringToSign(get("X-Amz-Date"), scope, creq))
	if !equalHex(want, strings.ToLower(get("X-Amz-Signature"))) {
		return nil, ErrSignatureDoesNotMatch
	}
	return &Result{AccessKey: sc.accessKey, Presigned: true, PayloadHash: payload, SignedAt: t}, nil
}
