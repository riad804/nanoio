package api

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"nanoio/internal/event"
	"nanoio/internal/kms"
	"nanoio/internal/sse"
	"nanoio/internal/storage"
)

const (
	maxPartNumber = 10000
	// maxCompleteBody bounds the CompleteMultipartUpload XML: 10,000 parts
	// at well under 200 bytes each.
	maxCompleteBody = 4 << 20
)

// multipartOp routes the object-level multipart operations, all of which
// carry ?uploads or ?uploadId.
func (s *Server) multipartOp(q *request) {
	switch q.r.Method {
	case http.MethodPost:
		if q.has("uploadId") {
			s.completeMultipartUpload(q)
		} else {
			s.createMultipartUpload(q)
		}
	case http.MethodPut:
		if q.has("uploadId") {
			s.uploadPart(q)
			return
		}
		s.fail(q, errBadMethod)
	case http.MethodGet:
		if q.has("uploadId") {
			s.listParts(q)
			return
		}
		s.fail(q, errBadMethod)
	case http.MethodDelete:
		if q.has("uploadId") {
			s.abortMultipartUpload(q)
			return
		}
		s.fail(q, errBadMethod)
	default:
		s.fail(q, errBadMethod)
	}
}

func (s *Server) createMultipartUpload(q *request) {
	if !s.authorize(q, "s3:PutObject", q.bucket, q.key, writeContext(q.r.Header)) {
		return
	}
	if q.r.Header.Get("x-amz-copy-source") != "" {
		s.fail(q, invalidRequest("x-amz-copy-source is not valid when creating a multipart upload"))
		return
	}
	opts, err := parseObjectMeta(q.r.Header)
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
	opts.Retention, opts.LegalHold = lock.retention, lock.hold
	opts.StorageClass = strings.TrimSpace(q.r.Header.Get("x-amz-storage-class"))
	if !s.applyACLHeaders(q, &opts) || !s.applyTagHeader(q, &opts) {
		return
	}
	spec, err := s.writeSpec(q, q.bucket)
	if err != nil {
		s.fail(q, err)
		return
	}
	var meta *sse.Meta
	if spec != nil {
		defer kms.Zero(spec.clientKey)
		// One object key per upload; each part derives its own key from it.
		ok, m, err := sse.NewObjectKey(q.r.Context(), s.kms, spec.params(q.bucket+"/"+q.key))
		if err != nil {
			s.fail(q, s.sseError(q, spec.mode, err))
			return
		}
		kms.Zero(ok)
		ud := make(map[string]string, len(opts.UserDefined)+8)
		for k, v := range opts.UserDefined {
			ud[k] = v
		}
		m.Put(ud)
		opts.UserDefined, meta = ud, m
	}
	opts.UserDefined = s.replPrepare(q.ctx(), q.bucket, q.key, opts.UserDefined)
	id, err := s.st.NewMultipartUpload(q.r.Context(), q.bucket, q.key, opts)
	if err != nil {
		s.fail(q, err)
		return
	}
	if meta != nil {
		setSSEHeaders(q.w.Header(), meta, ssecKeyMD5(spec))
	}
	s.writeXML(q, http.StatusOK, &initiateMultipartUploadResult{Bucket: q.bucket, Key: q.key, UploadID: id})
}

// partNumberParam parses ?partNumber=, which must be an integer in 1..10000.
func partNumberParam(q *request) (int, *APIError) {
	n, err := strconv.Atoi(q.query.Get("partNumber"))
	if err != nil || n < 1 || n > maxPartNumber {
		return 0, invalidArgument("Part number must be an integer between 1 and 10000, inclusive")
	}
	return n, nil
}

func (s *Server) uploadPart(q *request) {
	if !s.authorize(q, "s3:PutObject", q.bucket, q.key, nil) {
		return
	}
	n, aerr := partNumberParam(q)
	if aerr != nil {
		s.fail(q, aerr)
		return
	}
	id := q.query.Get("uploadId")
	if q.r.Header.Get("x-amz-copy-source") != "" {
		s.uploadPartCopy(q, id, n)
		return
	}
	if aerr := rejectSSEOnRead(q.r.Header); aerr != nil {
		s.fail(q, aerr)
		return
	}
	enc, _, err := s.uploadEncryption(q, id, ssecPrefix)
	if err != nil {
		s.fail(q, err)
		return
	}
	defer enc.close()
	b, err := parseBody(q.r, q.res)
	if err != nil {
		s.fail(q, err)
		return
	}
	body, size, popts := b.body, b.size, storage.PartOptions{ContentMD5: b.md5, ContentSHA256: b.sha256}
	if enc != nil {
		// Digests are over the plaintext the client sent; storage sees
		// ciphertext, so verify here.
		vr := newVerifyReader(b.body, b.md5, b.sha256)
		body, size, popts = sse.NewEncrypter(vr, sse.PartKey(enc.key, n)), sse.CipherSize(b.size), storage.PartOptions{}
	}
	part, err := s.st.PutObjectPart(q.r.Context(), q.bucket, q.key, id, n, body, size, popts)
	if err != nil {
		s.fail(q, err)
		return
	}
	h := q.w.Header()
	h["ETag"] = []string{`"` + part.ETag + `"`}
	if enc != nil {
		setSSEHeaders(h, enc.meta, enc.clientMD5)
	}
	q.w.WriteHeader(http.StatusOK)
}

// copySource is a parsed x-amz-copy-source.
type copySource struct {
	bucket, key, versionID string
}

// parseCopySource accepts "bucket/key", "/bucket/key" and an optional
// "?versionId=..." suffix; the path part is percent-encoded by clients.
func parseCopySource(v string) (copySource, *APIError) {
	bad := invalidArgument("Copy Source must mention the source bucket and key: sourcebucket/sourcekey")
	rawPath, rawQuery, _ := strings.Cut(v, "?")
	p, err := url.PathUnescape(rawPath)
	if err != nil {
		return copySource{}, bad
	}
	p = strings.TrimPrefix(p, "/")
	bucket, key, ok := strings.Cut(p, "/")
	if !ok || bucket == "" || key == "" {
		return copySource{}, bad
	}
	cs := copySource{bucket: bucket, key: key}
	if rawQuery != "" {
		qv, err := url.ParseQuery(rawQuery)
		if err != nil {
			return copySource{}, bad
		}
		cs.versionID = qv.Get("versionId")
	}
	return cs, nil
}

// parseCopyRange parses x-amz-copy-source-range, which S3 requires in the
// explicit form bytes=first-last.
func parseCopyRange(v string, size int64) (start, length int64, err *APIError) {
	bad := invalidArgument("The x-amz-copy-source-range value must be of the form bytes=first-last where first and last are the zero-based offsets of the first and last bytes to copy")
	spec, ok := strings.CutPrefix(v, "bytes=")
	if !ok {
		return 0, 0, bad
	}
	lo, hi, ok := strings.Cut(spec, "-")
	if !ok || lo == "" || hi == "" {
		return 0, 0, bad
	}
	a, e1 := strconv.ParseInt(lo, 10, 64)
	b, e2 := strconv.ParseInt(hi, 10, 64)
	if e1 != nil || e2 != nil || a < 0 || b < a {
		return 0, 0, bad
	}
	if b >= size {
		return 0, 0, &APIError{"InvalidRange", "The x-amz-copy-source-range value must be less than or equal to the size of the source object.", http.StatusRequestedRangeNotSatisfiable}
	}
	return a, b - a + 1, nil
}

// copyConditionsFail reports whether the x-amz-copy-source-if-* headers
// reject the source.
//
// etag is the ETag the client knows the source by; for an encrypted object
// that is the plaintext one, and the stored ETag (info.ETag) matches too.
func copyConditionsFail(h http.Header, info storage.ObjectInfo, etag string) bool {
	mod := info.ModTime.UTC().Truncate(time.Second)
	matches := func(v string) bool { return etagMatches(v, etag) || etagMatches(v, info.ETag) }
	if v := h.Get("x-amz-copy-source-if-match"); v != "" && !matches(v) {
		return true
	}
	if v := h.Get("x-amz-copy-source-if-none-match"); v != "" && matches(v) {
		return true
	}
	if v := h.Get("x-amz-copy-source-if-unmodified-since"); v != "" {
		if t, err := http.ParseTime(v); err == nil && mod.After(t) {
			return true
		}
	}
	if v := h.Get("x-amz-copy-source-if-modified-since"); v != "" {
		if t, err := http.ParseTime(v); err == nil && !mod.After(t) {
			return true
		}
	}
	return false
}

// uploadPartCopy implements UploadPart with x-amz-copy-source: the part's
// bytes come from an existing object (optionally a byte range of it)
// instead of the request body.
func (s *Server) uploadPartCopy(q *request, id string, n int) {
	src, aerr := parseCopySource(q.r.Header.Get("x-amz-copy-source"))
	if aerr != nil {
		s.fail(q, aerr)
		return
	}
	action := "s3:GetObject"
	if src.versionID != "" {
		action = "s3:GetObjectVersion"
	}
	// The caller needs read access to the source as well as write access to
	// the destination upload (checked by the caller).
	if !s.authorize(q, action, src.bucket, src.key, nil) {
		return
	}
	ctx := q.r.Context()
	if src.bucket == sysBucket {
		s.fail(q, storage.ErrBucketNotFound)
		return
	}
	dst, _, err := s.uploadEncryption(q, id, ssecPrefix)
	if err != nil {
		s.fail(q, err)
		return
	}
	defer dst.close()
	rc, info, err := s.openObject(ctx, src.bucket, src.key, storage.GetOptions{VersionID: src.versionID})
	if err != nil {
		s.fail(q, err)
		return
	}
	defer rc.Close()
	srcEnc, err := s.openEncrypted(q, info, ssecCopyPrefix)
	if err != nil {
		s.fail(q, err)
		return
	}
	defer srcEnc.close()
	size, etag := info.Size, info.ETag
	if srcEnc != nil {
		size, etag = srcEnc.size, srcEnc.etag
	}
	if copyConditionsFail(q.r.Header, info, etag) {
		s.fail(q, errPrecondition)
		return
	}
	start, length := int64(0), size
	if v := q.r.Header.Get("x-amz-copy-source-range"); v != "" {
		if start, length, aerr = parseCopyRange(v, size); aerr != nil {
			s.fail(q, aerr)
			return
		}
	}
	var body io.Reader
	if srcEnc != nil {
		body, err = sse.NewDecrypter(rc, srcEnc.layout, srcEnc.key, start, length)
		if err != nil {
			s.fail(q, err)
			return
		}
	} else {
		if start > 0 {
			var err error
			if sk, ok := rc.(io.Seeker); ok {
				_, err = sk.Seek(start, io.SeekStart)
			} else {
				_, err = io.CopyN(io.Discard, rc, start)
			}
			if err != nil {
				s.fail(q, err)
				return
			}
		}
		body = io.LimitReader(rc, length)
	}
	storedLen := length
	if dst != nil {
		body, storedLen = sse.NewEncrypter(body, sse.PartKey(dst.key, n)), sse.CipherSize(length)
	}
	part, err := s.st.PutObjectPart(ctx, q.bucket, q.key, id, n, body, storedLen, storage.PartOptions{})
	if err != nil {
		s.fail(q, err)
		return
	}
	if dst != nil {
		setSSEHeaders(q.w.Header(), dst.meta, dst.clientMD5)
	}
	s.writeXML(q, http.StatusOK, &copyPartResult{LastModified: isoTime(part.ModTime), ETag: `"` + part.ETag + `"`})
}

func (s *Server) completeMultipartUpload(q *request) {
	if !s.authorize(q, "s3:PutObject", q.bucket, q.key, nil) {
		return
	}
	body, err := s.readBody(q, maxCompleteBody)
	if err != nil {
		s.fail(q, err)
		return
	}
	var req completeMultipartUploadRequest
	if err := xml.Unmarshal(body, &req); err != nil || len(req.Parts) == 0 {
		s.fail(q, errMalformedXML)
		return
	}
	if len(req.Parts) > maxPartNumber {
		s.fail(q, errMalformedXML)
		return
	}
	parts := make([]storage.CompletePart, len(req.Parts))
	for i, p := range req.Parts {
		if p.PartNumber < 1 || p.PartNumber > maxPartNumber || strings.TrimSpace(p.ETag) == "" {
			s.fail(q, errMalformedXML)
			return
		}
		parts[i] = storage.CompletePart{Number: p.PartNumber, ETag: strings.TrimSpace(p.ETag)}
	}
	opts := storage.PutOptions{
		IfMatch:     q.r.Header.Get("If-Match"),
		IfNoneMatch: q.r.Header.Get("If-None-Match"),
	}
	if err := s.checkEncryptedPartSizes(q, q.query.Get("uploadId"), parts); err != nil {
		s.fail(q, err)
		return
	}
	info, err := s.st.CompleteMultipartUpload(q.r.Context(), q.bucket, q.key, q.query.Get("uploadId"), parts, opts)
	if err != nil {
		s.fail(q, err)
		return
	}
	scheme := "http"
	if q.r.TLS != nil {
		scheme = "https"
	}
	if info.VersionID != "" {
		q.w.Header().Set("x-amz-version-id", info.VersionID)
	}
	setSSEHeadersFromInfo(q.w.Header(), info.UserDefined)
	s.writeXML(q, http.StatusOK, &completeMultipartUploadResult{
		Location: scheme + "://" + q.r.Host + "/" + q.bucket + "/" + q.key,
		Bucket:   q.bucket, Key: q.key, ETag: `"` + info.ETag + `"`,
	})
	s.notify(q, event.ObjectCreatedCompleteMultipartUpload, objectFromInfo(info, q.key, ""))
	s.replAfterPut(q.ctx(), q.bucket, q.key, info.VersionID, info.UserDefined)
}

func (s *Server) abortMultipartUpload(q *request) {
	if !s.authorize(q, "s3:AbortMultipartUpload", q.bucket, q.key, nil) {
		return
	}
	if err := s.st.AbortMultipartUpload(q.r.Context(), q.bucket, q.key, q.query.Get("uploadId")); err != nil {
		s.fail(q, err)
		return
	}
	q.w.WriteHeader(http.StatusNoContent)
}

// intParam parses an optional non-negative integer query parameter.
func intParam(q *request, name string, def, max int) (int, *APIError) {
	if !q.has(name) {
		return def, nil
	}
	n, err := strconv.Atoi(q.query.Get(name))
	if err != nil || n < 0 {
		return 0, invalidArgument(fmt.Sprintf("Provided %s not an integer or within integer range", name))
	}
	if n > max {
		n = max
	}
	return n, nil
}

func (s *Server) listParts(q *request) {
	if !s.authorize(q, "s3:ListMultipartUploadParts", q.bucket, q.key, nil) {
		return
	}
	maxParts, aerr := intParam(q, "max-parts", 1000, 1000)
	if aerr != nil {
		s.fail(q, aerr)
		return
	}
	marker, aerr := intParam(q, "part-number-marker", 0, 1<<31-1)
	if aerr != nil {
		s.fail(q, aerr)
		return
	}
	id := q.query.Get("uploadId")
	res := listPartsResult{
		Bucket: q.bucket, Key: q.key, UploadID: id, PartNumberMarker: marker, MaxParts: maxParts,
		Parts: []partEntry{}, Initiator: placeholderOwner, Owner: placeholderOwner, StorageClass: "STANDARD",
	}
	if maxParts == 0 {
		// Nothing to return, but the upload must exist.
		if _, err := s.st.ListObjectParts(q.r.Context(), q.bucket, q.key, id, storage.ListPartsOptions{MaxParts: 1}); err != nil {
			s.fail(q, err)
			return
		}
		s.writeXML(q, http.StatusOK, &res)
		return
	}
	out, err := s.st.ListObjectParts(q.r.Context(), q.bucket, q.key, id,
		storage.ListPartsOptions{PartNumberMarker: marker, MaxParts: maxParts})
	if err != nil {
		s.fail(q, err)
		return
	}
	encrypted := sse.Encrypted(out.UserDefined)
	for _, p := range out.Parts {
		size := p.Size
		if encrypted {
			if n, err := sse.PlainSize(p.Size); err == nil {
				size = n
			}
		}
		res.Parts = append(res.Parts, partEntry{PartNumber: p.Number, LastModified: isoTime(p.ModTime),
			ETag: `"` + p.ETag + `"`, Size: size})
	}
	res.IsTruncated = out.IsTruncated
	res.NextPartNumberMarker = out.NextPartNumberMarker
	s.writeXML(q, http.StatusOK, &res)
}

func (s *Server) listMultipartUploads(q *request) {
	ctx := map[string]string{}
	for qp, key := range map[string]string{"prefix": "s3:prefix", "delimiter": "s3:delimiter"} {
		if q.has(qp) {
			ctx[key] = q.query.Get(qp)
		}
	}
	if !s.authorize(q, "s3:ListBucketMultipartUploads", q.bucket, "", ctx) {
		return
	}
	p, aerr := parseListParams(q)
	if aerr != nil {
		s.fail(q, aerr)
		return
	}
	maxUploads, aerr := intParam(q, "max-uploads", 1000, 1000)
	if aerr != nil {
		s.fail(q, aerr)
		return
	}
	keyMarker, idMarker := q.query.Get("key-marker"), q.query.Get("upload-id-marker")
	if idMarker != "" && keyMarker == "" {
		s.fail(q, invalidArgument("Invalid upload-id-marker: key-marker must be specified"))
		return
	}
	res := listMultipartUploadsResult{
		Bucket: q.bucket, KeyMarker: p.enc(keyMarker), UploadIDMarker: idMarker,
		Prefix: p.enc(p.prefix), Delimiter: p.enc(p.delimiter), MaxUploads: maxUploads,
		Uploads: []uploadEntry{}, CommonPrefixes: []commonPrefix{},
	}
	if p.urlEncode {
		res.EncodingType = "url"
	}
	if maxUploads == 0 {
		if s.requireBucket(q) {
			s.writeXML(q, http.StatusOK, &res)
		}
		return
	}
	out, err := s.st.ListMultipartUploads(q.r.Context(), q.bucket, storage.ListUploadsOptions{
		Prefix: p.prefix, Delimiter: p.delimiter, KeyMarker: keyMarker,
		UploadIDMarker: idMarker, MaxUploads: maxUploads,
	})
	if err != nil {
		s.fail(q, err)
		return
	}
	for _, u := range out.Uploads {
		res.Uploads = append(res.Uploads, uploadEntry{
			Key: p.enc(u.Object), UploadID: u.UploadID, Initiator: placeholderOwner, Owner: placeholderOwner,
			StorageClass: "STANDARD", Initiated: isoTime(u.Initiated),
		})
	}
	res.CommonPrefixes = p.prefixes(out.Prefixes)
	res.IsTruncated = out.IsTruncated
	res.NextKeyMarker = p.enc(out.NextKeyMarker)
	res.NextUploadIDMarker = out.NextUploadIDMarker
	s.writeXML(q, http.StatusOK, &res)
}

// minPartSize is S3's minimum size of every part but the last.
const minPartSize = 5 << 20

// checkEncryptedPartSizes enforces S3's 5 MiB part minimum on the plaintext
// size of an encrypted upload's parts. Storage only sees ciphertext, which
// is slightly larger, so it can be more lenient than S3 but never stricter.
func (s *Server) checkEncryptedPartSizes(q *request, id string, parts []storage.CompletePart) error {
	ctx := q.r.Context()
	first, err := s.st.ListObjectParts(ctx, q.bucket, q.key, id, storage.ListPartsOptions{PartNumberMarker: 1 << 30, MaxParts: 1})
	if err != nil {
		return err
	}
	if !sse.Encrypted(first.UserDefined) {
		return nil
	}
	sizes := map[int]int64{}
	marker := 0
	for {
		page, err := s.st.ListObjectParts(ctx, q.bucket, q.key, id, storage.ListPartsOptions{PartNumberMarker: marker, MaxParts: 1000})
		if err != nil {
			return err
		}
		for _, p := range page.Parts {
			n, perr := sse.PlainSize(p.Size)
			if perr != nil {
				return errInternal
			}
			sizes[p.Number] = n
		}
		if !page.IsTruncated {
			break
		}
		marker = page.NextPartNumberMarker
	}
	for i, p := range parts {
		if i == len(parts)-1 {
			break
		}
		if n, ok := sizes[p.Number]; ok && n < minPartSize {
			return storage.Wrap(fmt.Errorf("%w: part %d is %d bytes; every part but the last must be at least %d", storage.ErrEntityTooSmall, p.Number, n, minPartSize), q.bucket, q.key)
		}
	}
	return nil
}
