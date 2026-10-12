package api

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"nanoio/internal/auth"
	"nanoio/internal/kms"
	"nanoio/internal/sse"
	"nanoio/internal/storage"
)

const (
	userMetaPrefix = "x-amz-meta-"
	maxUserMeta    = 2048 // S3 limit: total bytes of user-defined metadata
)

// System headers stored with an object and returned on GET and HEAD. They
// are kept in ObjectInfo.UserDefined under their lowercase names, which
// cannot collide with user metadata (always prefixed x-amz-meta-).
var systemHeaders = []string{"Cache-Control", "Content-Disposition", "Content-Encoding", "Content-Language", "Expires"}

const (
	shaUnsigned = "UNSIGNED-PAYLOAD"
	shaStream   = "STREAMING-"
)

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// putRequest is a parsed PutObject request.
type putRequest struct {
	body io.Reader
	size int64
	opts storage.PutOptions
}

// parseObjectMeta extracts what an object is stored with: its content type,
// user metadata and the system headers returned on GET. It is shared by
// PutObject and CreateMultipartUpload.
func parseObjectMeta(h http.Header) (storage.PutOptions, error) {
	var opts storage.PutOptions
	if h.Get("x-amz-tagging") != "" {
		return opts, notImplemented("object tagging (x-amz-tagging)")
	}
	opts.ContentType = h.Get("Content-Type")

	var encodings []string
	for _, e := range strings.Split(h.Get("Content-Encoding"), ",") {
		if e = strings.TrimSpace(e); e != "" && !strings.EqualFold(e, "aws-chunked") {
			encodings = append(encodings, e)
		}
	}
	meta := map[string]string{}
	total := 0
	for k, vs := range h {
		lk := strings.ToLower(k)
		if !strings.HasPrefix(lk, userMetaPrefix) {
			continue
		}
		v := strings.Join(vs, ",")
		total += len(lk) - len(userMetaPrefix) + len(v)
		meta[lk] = v
	}
	if total > maxUserMeta {
		return opts, errMetaTooLarge
	}
	for _, name := range systemHeaders {
		v := h.Get(name)
		if name == "Content-Encoding" {
			v = strings.Join(encodings, ", ")
		}
		if v != "" {
			meta[strings.ToLower(name)] = v
		}
	}
	if len(meta) > 0 {
		opts.UserDefined = meta
	}
	return opts, nil
}

// bodyInfo describes how a request body is framed and what it must hash to.
type bodyInfo struct {
	body   io.Reader
	size   int64
	md5    string // hex, from Content-MD5
	sha256 string // hex, from x-amz-content-sha256
}

// parseBody resolves the body of an upload: its length (declared, or the
// decoded length of an aws-chunked stream), the chunk decoder and signature
// verifier for streaming uploads, and the digests to verify while streaming.
func parseBody(r *http.Request, res *auth.Result) (*bodyInfo, error) {
	h := r.Header
	b := &bodyInfo{body: r.Body, size: r.ContentLength}

	chunked := false
	streamingHeader := false
	switch sha := h.Get("x-amz-content-sha256"); {
	case sha == "" || sha == shaUnsigned:
	case strings.HasPrefix(sha, shaStream):
		chunked = true
		streamingHeader = true
	case isHex64(sha):
		b.sha256 = strings.ToLower(sha)
	default:
		return nil, invalidArgument("x-amz-content-sha256 must be UNSIGNED-PAYLOAD, STREAMING-UNSIGNED-PAYLOAD-TRAILER, STREAMING-AWS4-HMAC-SHA256-PAYLOAD or a valid sha256 value.")
	}
	for _, e := range strings.Split(h.Get("Content-Encoding"), ",") {
		if strings.EqualFold(strings.TrimSpace(e), "aws-chunked") {
			chunked = true
		}
	}

	if chunked {
		if !streamingHeader && h.Get("x-amz-content-sha256") != "" {
			return nil, invalidRequest("aws-chunked content encoding requires a STREAMING-* x-amz-content-sha256 value")
		}
		n, err := strconv.ParseInt(h.Get("x-amz-decoded-content-length"), 10, 64)
		if err != nil || n < 0 {
			return nil, errMissingLen
		}
		b.size = n
		var signer *auth.ChunkSigner
		if res != nil {
			signer = res.Chunk
		}
		if streamingHeader && res != nil && res.Chunk == nil &&
			strings.HasPrefix(h.Get("x-amz-content-sha256"), "STREAMING-AWS4-") {
			return nil, errBadChunk // signed streaming declared but not authenticated as such
		}
		cr := newChunkedReader(r.Body, n, signer)
		b.body = cr
		if n == 0 {
			// Storage never reads a zero-length body, so verify the framing
			// of the empty payload here.
			if extra, err := io.Copy(io.Discard, cr); err != nil {
				return nil, err
			} else if extra != 0 {
				return nil, errBadChunk
			}
		}
	} else if b.size < 0 {
		return nil, errMissingLen
	}

	if md5b64 := h.Get("Content-MD5"); md5b64 != "" {
		raw, err := base64.StdEncoding.DecodeString(md5b64)
		if err != nil || len(raw) != 16 {
			return nil, errInvalidMD5
		}
		b.md5 = hex.EncodeToString(raw)
	}
	return b, nil
}

func parsePut(r *http.Request, res *auth.Result) (*putRequest, error) {
	opts, err := parseObjectMeta(r.Header)
	if err != nil {
		return nil, err
	}
	b, err := parseBody(r, res)
	if err != nil {
		return nil, err
	}
	opts.ContentMD5, opts.ContentSHA256 = b.md5, b.sha256
	opts.IfMatch = r.Header.Get("If-Match")
	opts.IfNoneMatch = r.Header.Get("If-None-Match")
	return &putRequest{body: b.body, size: b.size, opts: opts}, nil
}

func (s *Server) putObject(q *request) {
	if !s.authorize(q, "s3:PutObject", q.bucket, q.key, nil) {
		return
	}
	if q.r.Header.Get("x-amz-copy-source") != "" {
		s.copyObject(q)
		return
	}
	p, err := parsePut(q.r, q.res)
	if err != nil {
		s.fail(q, err)
		return
	}
	lock, aerr := parseLockHeaders(q.r.Header)
	if aerr != nil {
		s.fail(q, aerr)
		return
	}
	if !s.authorizeLockHeaders(q, lock) {
		return
	}
	p.opts.Retention, p.opts.LegalHold = lock.retention, lock.hold
	spec, err := s.writeSpec(q, q.bucket)
	if err != nil {
		s.fail(q, err)
		return
	}
	body, size := p.body, p.size
	var (
		finish func() string
		meta   *sse.Meta
	)
	if spec != nil {
		defer kms.Zero(spec.clientKey)
		body, size, finish, meta, err = s.encryptedBody(q, spec, q.bucket+"/"+q.key, p.body, p.size, &p.opts)
		if err != nil {
			s.fail(q, err)
			return
		}
	}
	info, err := s.st.PutObject(q.r.Context(), q.bucket, q.key, body, size, p.opts)
	if err != nil {
		s.fail(q, err)
		return
	}
	etag := info.ETag
	if finish != nil {
		etag = finish()
	}
	h := q.w.Header()
	h["ETag"] = []string{`"` + etag + `"`}
	if info.VersionID != "" {
		h.Set("x-amz-version-id", info.VersionID)
	}
	if meta != nil {
		setSSEHeaders(h, meta, ssecKeyMD5(spec))
	}
	q.w.WriteHeader(http.StatusOK)
}

// ssecKeyMD5 is the base64 MD5 of an SSE-C spec's key, for response headers.
func ssecKeyMD5(spec *sseSpec) string {
	if spec == nil || spec.mode != sse.ModeC {
		return ""
	}
	sum := md5.Sum(spec.clientKey)
	return base64.StdEncoding.EncodeToString(sum[:])
}

func (s *Server) deleteObject(q *request) {
	action := "s3:DeleteObject"
	if q.query.Get("versionId") != "" {
		action = "s3:DeleteObjectVersion"
	}
	if !s.authorize(q, action, q.bucket, q.key, nil) {
		return
	}
	bypass, ok := s.bypassGovernance(q, q.key)
	if !ok {
		return
	}
	res, err := s.st.DeleteObject(q.r.Context(), q.bucket, q.key, storage.DeleteOptions{
		VersionID:        q.query.Get("versionId"),
		BypassGovernance: bypass,
	})
	if err != nil {
		s.logLockRefusal(q, "delete", err)
		s.fail(q, err)
		return
	}
	h := q.w.Header()
	if res.VersionID != "" {
		h.Set("x-amz-version-id", res.VersionID)
	}
	if res.DeleteMarker {
		h.Set("x-amz-delete-marker", "true")
	}
	q.w.WriteHeader(http.StatusNoContent)
}

// objectHeaders sets the representation headers shared by GET, HEAD and
// 304 responses.
func objectHeaders(h http.Header, info storage.ObjectInfo) {
	h["ETag"] = []string{`"` + info.ETag + `"`} // exact case; Set would emit "Etag"
	h.Set("Last-Modified", info.ModTime.UTC().Format(http.TimeFormat))
	h.Set("Content-Type", info.ContentType)
	h.Set("Accept-Ranges", "bytes")
	for k, v := range info.UserDefined {
		if strings.HasPrefix(k, userMetaPrefix) {
			h.Set(k, v)
			continue
		}
		for _, sys := range systemHeaders {
			if k == strings.ToLower(sys) {
				h.Set(sys, v)
			}
		}
	}
	if info.VersionID != "" {
		h.Set("x-amz-version-id", info.VersionID)
	}
	lockResponseHeaders(h, info)
}

// etagMatches implements the entity-tag list comparison of If-Match and
// If-None-Match: "*" matches anything, weak validators compare equal.
func etagMatches(header, etag string) bool {
	for _, c := range strings.Split(header, ",") {
		c = strings.TrimSpace(c)
		if c == "*" {
			return true
		}
		c = strings.Trim(strings.TrimPrefix(c, "W/"), `"`)
		if c == etag {
			return true
		}
	}
	return false
}

// checkConditions applies RFC 7232 precedence for GET and HEAD.
func checkConditions(h http.Header, info storage.ObjectInfo, alt string) *APIError {
	mod := info.ModTime.UTC().Truncate(time.Second)
	// matches also accepts alt: for an encrypted object, the stored ETag
	// that listings show next to the plaintext one GET reports.
	matches := func(v string) bool { return etagMatches(v, info.ETag) || (alt != "" && etagMatches(v, alt)) }
	if v := h.Get("If-Match"); v != "" {
		if !matches(v) {
			return errPrecondition
		}
	} else if v := h.Get("If-Unmodified-Since"); v != "" {
		if t, err := http.ParseTime(v); err == nil && mod.After(t) {
			return errPrecondition
		}
	}
	if v := h.Get("If-None-Match"); v != "" {
		if matches(v) {
			return errNotModified
		}
	} else if v := h.Get("If-Modified-Since"); v != "" {
		if t, err := http.ParseTime(v); err == nil && !mod.After(t) {
			return errNotModified
		}
	}
	return nil
}

// parseRange resolves a single-range Range header against size. Headers
// S3 ignores (wrong unit, several ranges, bad syntax) return partial=false
// and the whole object is served; an unsatisfiable range is an error.
func parseRange(header string, size int64) (start, length int64, partial bool, err *APIError) {
	spec, ok := strings.CutPrefix(header, "bytes=")
	if !ok || strings.Contains(spec, ",") {
		return 0, 0, false, nil
	}
	lo, hi, ok := strings.Cut(spec, "-")
	if !ok {
		return 0, 0, false, nil
	}
	lo, hi = strings.TrimSpace(lo), strings.TrimSpace(hi)
	switch {
	case lo == "" && hi != "": // suffix: last N bytes
		n, perr := strconv.ParseInt(hi, 10, 64)
		if perr != nil || n < 0 {
			return 0, 0, false, nil
		}
		if n == 0 || size == 0 {
			return 0, 0, false, errInvalidRange
		}
		n = min(n, size)
		return size - n, n, true, nil
	case lo != "":
		a, perr := strconv.ParseInt(lo, 10, 64)
		if perr != nil || a < 0 {
			return 0, 0, false, nil
		}
		b := size - 1
		if hi != "" {
			e, perr := strconv.ParseInt(hi, 10, 64)
			if perr != nil || e < a {
				return 0, 0, false, nil
			}
			b = min(e, size-1)
		}
		if a >= size {
			return 0, 0, false, errInvalidRange
		}
		return a, b - a + 1, true, nil
	}
	return 0, 0, false, nil
}

// getObject serves GET and HEAD. It opens the object once and applies the
// range to that open snapshot, so the range always refers to the bytes and
// size the response describes even if the key is overwritten meanwhile.
//
// An encrypted object is unsealed before any header is written (so a wrong
// key or an unavailable KMS is a proper error response), reported with its
// plaintext size and ETag, and read through a decrypter that seeks to just
// the chunks the range covers.
func (s *Server) getObject(q *request, head bool) {
	action := "s3:GetObject"
	if q.query.Get("versionId") != "" {
		action = "s3:GetObjectVersion"
	}
	if !s.authorize(q, action, q.bucket, q.key, nil) {
		return
	}
	if aerr := rejectSSEOnRead(q.r.Header); aerr != nil {
		s.fail(q, aerr)
		return
	}
	ctx := q.r.Context()
	opts := storage.GetOptions{VersionID: q.query.Get("versionId")}

	var (
		rc   io.ReadCloser
		info storage.ObjectInfo
		err  error
	)
	if head {
		info, err = s.st.StatObject(ctx, q.bucket, q.key, opts)
	} else {
		rc, info, err = s.st.GetObject(ctx, q.bucket, q.key, opts)
	}
	if err != nil {
		s.fail(q, err)
		return
	}
	if rc != nil {
		defer rc.Close()
	}

	enc, err := s.openEncrypted(q, info, ssecPrefix)
	if err != nil {
		s.fail(q, err)
		return
	}
	defer enc.close()
	size, alt := info.Size, ""
	if enc != nil {
		size, alt = enc.size, enc.storedTag
		info.Size, info.ETag = enc.size, enc.etag
	}

	h := q.w.Header()
	objectHeaders(h, info)
	if enc != nil {
		setSSEHeaders(h, enc.meta, enc.clientMD5)
	}
	if cerr := checkConditions(q.r.Header, info, alt); cerr != nil {
		s.writeAPIError(q, cerr)
		return
	}
	start, length, partial, rerr := parseRange(q.r.Header.Get("Range"), size)
	if rerr != nil {
		s.writeAPIError(q, rerr)
		return
	}
	status := http.StatusOK
	if partial {
		status = http.StatusPartialContent
		h.Set("Content-Range", "bytes "+strconv.FormatInt(start, 10)+"-"+
			strconv.FormatInt(start+length-1, 10)+"/"+strconv.FormatInt(size, 10))
	} else {
		length = size
	}
	h.Set("Content-Length", strconv.FormatInt(length, 10))
	q.w.WriteHeader(status)
	if head || length == 0 {
		return
	}
	var body io.Reader = rc
	if enc != nil {
		body, err = sse.NewDecrypter(rc, enc.layout, enc.key, start, length)
		if err != nil {
			s.log.Error("cannot open decrypter", "id", q.id, "bucket", q.bucket, "key", q.key, "err", err)
			panic(http.ErrAbortHandler)
		}
	} else if start > 0 {
		if sk, ok := rc.(io.Seeker); ok {
			_, err = sk.Seek(start, io.SeekStart)
		} else {
			_, err = io.CopyN(io.Discard, rc, start)
		}
		if err != nil {
			s.log.Error("seek failed", "id", q.id, "err", err)
			panic(http.ErrAbortHandler)
		}
	}
	if _, err := io.CopyN(q.w, body, length); err != nil {
		// Headers are out; the only honest signal left is to cut the
		// connection so the client sees a short body.
		s.log.Warn("response body truncated", "id", q.id, "bucket", q.bucket, "key", q.key, "err", err)
		panic(http.ErrAbortHandler)
	}
}
