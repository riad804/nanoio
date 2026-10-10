package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"io"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"nanoio/internal/iam"
	"nanoio/internal/storage"
)

const maxListKeys = 1000

func (s *Server) listBuckets(q *request) {
	if !s.authorize(q, "s3:ListAllMyBuckets", "", "", nil) {
		return
	}
	list, err := s.st.ListBuckets(q.r.Context())
	if err != nil {
		s.fail(q, err)
		return
	}
	res := listAllMyBucketsResult{Owner: placeholderOwner}
	res.Buckets.Bucket = make([]bucketEntry, 0, len(list))
	for _, b := range list {
		res.Buckets.Bucket = append(res.Buckets.Bucket, bucketEntry{Name: b.Name, CreationDate: isoTime(b.Created)})
	}
	s.writeXML(q, http.StatusOK, &res)
}

func (s *Server) createBucket(q *request) {
	if !s.authorize(q, "s3:CreateBucket", q.bucket, "", nil) {
		return
	}
	body, err := s.readBody(q, 64<<10)
	if err != nil {
		s.fail(q, err)
		return
	}
	if len(strings.TrimSpace(string(body))) > 0 {
		var cfg createBucketConfiguration
		if err := xml.Unmarshal(body, &cfg); err != nil {
			s.fail(q, errMalformedXML)
			return
		}
		// The location constraint is accepted and ignored: this server has
		// a single region and clients routinely send their own.
	}
	if err := s.st.MakeBucket(q.r.Context(), q.bucket, storage.MakeBucketOptions{}); err != nil {
		s.fail(q, err)
		return
	}
	q.w.Header().Set("Location", "/"+q.bucket)
	q.w.WriteHeader(http.StatusOK)
}

func (s *Server) headBucket(q *request) {
	if !s.authorize(q, "s3:ListBucket", q.bucket, "", nil) {
		return
	}
	ok, err := s.st.BucketExists(q.r.Context(), q.bucket)
	if err == nil && !ok {
		err = storage.ErrBucketNotFound
	}
	if err != nil {
		s.fail(q, err)
		return
	}
	q.w.Header().Set("x-amz-bucket-region", s.region)
	q.w.WriteHeader(http.StatusOK)
}

func (s *Server) deleteBucket(q *request) {
	if !s.authorize(q, "s3:DeleteBucket", q.bucket, "", nil) {
		return
	}
	if err := s.st.DeleteBucket(q.r.Context(), q.bucket, storage.DeleteBucketOptions{}); err != nil {
		s.fail(q, err)
		return
	}
	q.w.WriteHeader(http.StatusNoContent)
}

func (s *Server) getBucketLocation(q *request) {
	if !s.authorize(q, "s3:GetBucketLocation", q.bucket, "", nil) {
		return
	}
	ok, err := s.st.BucketExists(q.r.Context(), q.bucket)
	if err == nil && !ok {
		err = storage.ErrBucketNotFound
	}
	if err != nil {
		s.fail(q, err)
		return
	}
	res := locationConstraint{}
	if s.region != "us-east-1" { // S3 reports us-east-1 as an empty element
		res.Region = s.region
	}
	s.writeXML(q, http.StatusOK, &res)
}

// listParams holds the query parameters shared by ListObjects v1 and v2.
type listParams struct {
	prefix, delimiter string
	maxKeys           int
	urlEncode         bool
}

func parseListParams(q *request) (listParams, *APIError) {
	p := listParams{
		prefix:    q.query.Get("prefix"),
		delimiter: q.query.Get("delimiter"),
		maxKeys:   maxListKeys,
	}
	switch enc := q.query.Get("encoding-type"); enc {
	case "":
	case "url":
		p.urlEncode = true
	default:
		return p, invalidArgument("Invalid Encoding Method specified in Request")
	}
	if v := q.query.Get("max-keys"); v != "" || q.has("max-keys") {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return p, invalidArgument("Argument maxKeys must be an integer between 0 and 2147483647")
		}
		p.maxKeys = min(n, maxListKeys)
	}
	return p, nil
}

func (p listParams) enc(s string) string {
	if p.urlEncode {
		return s3Encode(s)
	}
	return s
}

// contents converts storage objects to XML entries.
func (p listParams) contents(objs []storage.ObjectInfo, owner bool) []contentsEntry {
	out := make([]contentsEntry, 0, len(objs))
	for _, o := range objs {
		e := contentsEntry{
			Key: p.enc(o.Name), LastModified: isoTime(o.ModTime),
			ETag: `"` + o.ETag + `"`, Size: o.Size, StorageClass: "STANDARD",
		}
		if owner {
			ow := placeholderOwner
			e.Owner = &ow
		}
		out = append(out, e)
	}
	return out
}

func (p listParams) prefixes(ps []string) []commonPrefix {
	out := make([]commonPrefix, 0, len(ps))
	for _, x := range ps {
		out = append(out, commonPrefix{Prefix: p.enc(x)})
	}
	return out
}

func (s *Server) requireBucket(q *request) bool {
	ok, err := s.st.BucketExists(q.r.Context(), q.bucket)
	if err == nil && !ok {
		err = storage.ErrBucketNotFound
	}
	if err != nil {
		s.fail(q, err)
		return false
	}
	return true
}

// authorizeList checks s3:ListBucket with the condition keys S3 defines for
// listings, taken from the raw query so denial precedes validation.
func (s *Server) authorizeList(q *request) bool {
	ctx := map[string]string{}
	for qp, key := range map[string]string{"prefix": "s3:prefix", "delimiter": "s3:delimiter", "max-keys": "s3:max-keys"} {
		if q.has(qp) {
			ctx[key] = q.query.Get(qp)
		}
	}
	return s.authorize(q, "s3:ListBucket", q.bucket, "", ctx)
}

func (s *Server) listObjectsV1(q *request) {
	if !s.authorizeList(q) {
		return
	}
	p, aerr := parseListParams(q)
	if aerr != nil {
		s.fail(q, aerr)
		return
	}
	marker := q.query.Get("marker")
	res := listBucketResultV1{
		Name: q.bucket, Prefix: p.enc(p.prefix), Marker: p.enc(marker),
		MaxKeys: p.maxKeys, Delimiter: p.enc(p.delimiter),
		Contents: []contentsEntry{}, CommonPrefixes: []commonPrefix{},
	}
	if p.urlEncode {
		res.EncodingType = "url"
	}
	if p.maxKeys == 0 {
		if s.requireBucket(q) {
			s.writeXML(q, http.StatusOK, &res)
		}
		return
	}
	out, err := s.st.ListObjects(q.r.Context(), q.bucket, storage.ListOptions{
		Prefix: p.prefix, Delimiter: p.delimiter, Marker: marker, MaxKeys: p.maxKeys,
	})
	if err != nil {
		s.fail(q, err)
		return
	}
	res.Contents = p.contents(out.Objects, true)
	res.CommonPrefixes = p.prefixes(out.Prefixes)
	res.IsTruncated = out.IsTruncated
	markIncomplete(q, out)
	if out.IsTruncated && p.delimiter != "" {
		res.NextMarker = p.enc(out.NextMarker) // S3 returns it only with a delimiter
	}
	s.writeXML(q, http.StatusOK, &res)
}

// A continuation token is the opaque, URL-safe base64 of the last key (or
// common prefix) returned on the previous page.
func encodeToken(marker string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(marker))
}

func decodeToken(tok string) (string, bool) {
	b, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil || len(b) == 0 || !utf8.Valid(b) {
		return "", false
	}
	return string(b), true
}

func (s *Server) listObjectsV2(q *request) {
	if !s.authorizeList(q) {
		return
	}
	if q.query.Get("list-type") != "2" {
		s.fail(q, invalidArgument("Invalid list-type: only list-type=2 is supported"))
		return
	}
	p, aerr := parseListParams(q)
	if aerr != nil {
		s.fail(q, aerr)
		return
	}
	startAfter := q.query.Get("start-after")
	token := q.query.Get("continuation-token")
	marker := ""
	if q.has("continuation-token") {
		m, ok := decodeToken(token)
		if !ok {
			s.fail(q, invalidArgument("The continuation token provided is incorrect"))
			return
		}
		marker = m
	}
	res := listBucketResultV2{
		Name: q.bucket, Prefix: p.enc(p.prefix), Delimiter: p.enc(p.delimiter),
		MaxKeys: p.maxKeys, ContinuationToken: token, StartAfter: p.enc(startAfter),
		Contents: []contentsEntry{}, CommonPrefixes: []commonPrefix{},
	}
	if p.urlEncode {
		res.EncodingType = "url"
	}
	if p.maxKeys == 0 {
		if s.requireBucket(q) {
			s.writeXML(q, http.StatusOK, &res)
		}
		return
	}
	out, err := s.st.ListObjects(q.r.Context(), q.bucket, storage.ListOptions{
		Prefix: p.prefix, Delimiter: p.delimiter, Marker: marker,
		StartAfter: startAfter, MaxKeys: p.maxKeys,
	})
	if err != nil {
		s.fail(q, err)
		return
	}
	res.Contents = p.contents(out.Objects, q.query.Get("fetch-owner") == "true")
	res.CommonPrefixes = p.prefixes(out.Prefixes)
	res.KeyCount = len(out.Objects) + len(out.Prefixes)
	res.IsTruncated = out.IsTruncated
	markIncomplete(q, out)
	if out.IsTruncated {
		res.NextContinuationToken = encodeToken(out.NextMarker)
	}
	s.writeXML(q, http.StatusOK, &res)
}

// deleteObjects implements POST /bucket?delete (multi-object delete, used
// by `aws s3 rm --recursive`).
func (s *Server) deleteObjects(q *request) {
	body, err := s.readBody(q, 4<<20)
	if err != nil {
		s.fail(q, err)
		return
	}
	var req deleteRequest
	if err := xml.Unmarshal(body, &req); err != nil || len(req.Objects) == 0 {
		s.fail(q, errMalformedXML)
		return
	}
	if len(req.Objects) > maxListKeys {
		s.fail(q, errTooManyKeys)
		return
	}
	// Authorise every key before touching storage. Keys the caller may not
	// delete are reported per key, as S3 does; the bucket's existence is
	// only revealed to a caller allowed to delete at least one key.
	allowed := make([]bool, len(req.Objects))
	anyAllowed := false
	for i, o := range req.Objects {
		allowed[i] = s.mayDelete(q, o)
		anyAllowed = anyAllowed || allowed[i]
	}
	if anyAllowed && !s.requireBucket(q) {
		return
	}
	res := deleteResult{Deleted: []deletedEntry{}, Errors: []deleteError{}}
	for i, o := range req.Objects {
		if err := q.r.Context().Err(); err != nil {
			return
		}
		if !allowed[i] {
			res.Errors = append(res.Errors, deleteError{Key: o.Key, Code: "AccessDenied", Message: "Access Denied."})
			continue
		}
		if o.VersionID != "" {
			res.Errors = append(res.Errors, deleteError{Key: o.Key, Code: "NotImplemented",
				Message: "Deleting a specific version is not implemented."})
			continue
		}
		if _, err := s.st.DeleteObject(q.r.Context(), q.bucket, o.Key, storage.DeleteOptions{}); err != nil {
			ae, _, known := classify(err)
			if !known {
				s.log.Error("multi-delete failed", "id", q.id, "bucket", q.bucket, "key", o.Key, "err", err)
			}
			res.Errors = append(res.Errors, deleteError{Key: o.Key, Code: ae.Code, Message: ae.Message})
			continue
		}
		if !req.Quiet {
			res.Deleted = append(res.Deleted, deletedEntry{Key: o.Key})
		}
	}
	s.writeXML(q, http.StatusOK, &res)
}

// mayDelete authorises one key of a multi-object delete without writing a
// response.
func (s *Server) mayDelete(q *request, o deleteObject) bool {
	if s.noAuth {
		return true
	}
	action := "s3:DeleteObject"
	if o.VersionID != "" {
		action = "s3:DeleteObjectVersion"
	}
	return s.authz.Allowed(q.who, iam.Request{
		Action: action, Bucket: q.bucket, Key: o.Key,
		Context: map[string]string{"aws:sourceip": remoteIP(q.r), "aws:securetransport": strconv.FormatBool(q.r.TLS != nil)},
	})
}

// readBody reads at most limit bytes of a small request body (XML) and, if
// the request declared a body hash, verifies it. The hash is part of the
// signature, so a verified hash makes the body authentic too.
func (s *Server) readBody(q *request, limit int64) ([]byte, error) {
	body, err := io.ReadAll(http.MaxBytesReader(q.w, q.r.Body, limit))
	if err != nil {
		return nil, err
	}
	declared := ""
	if q.res != nil {
		declared = q.res.PayloadHash
	} else {
		declared = q.r.Header.Get("x-amz-content-sha256")
	}
	if isHex64(declared) {
		sum := sha256.Sum256(body)
		if !strings.EqualFold(declared, hex.EncodeToString(sum[:])) {
			return nil, errSHA256Wrong
		}
	}
	return body, nil
}

// markIncomplete flags a listing that a distributed backend, configured to
// allow it, assembled from only some of its sets.
func markIncomplete(q *request, out storage.ListResult) {
	if out.Incomplete {
		q.w.Header().Set("x-nanoio-list-incomplete", "true")
	}
}
