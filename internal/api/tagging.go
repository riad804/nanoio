package api

import (
	"encoding/json"
	"encoding/xml"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"nanoio/internal/storage"
)

// tagsKey is the reserved user-defined key holding an object's tag set (a
// JSON object of key to value).
const tagsKey = "x-nanoio-internal-tags"

const (
	maxObjectTags = 10
	maxBucketTags = 50
	maxTagKey     = 128
	maxTagValue   = 256
)

var (
	errNoSuchTagSet = &APIError{"NoSuchTagSet", "The TagSet does not exist", http.StatusNotFound}
)

func invalidTag(msg string) *APIError {
	return &APIError{"InvalidTag", msg, http.StatusBadRequest}
}

func validTagChars(s string) bool {
	for _, r := range s {
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r), unicode.IsSpace(r):
		case strings.ContainsRune("+-=._:/@", r):
		default:
			return false
		}
	}
	return true
}

// validateTags applies S3's tag rules.
func validateTags(tags map[string]string, max int) *APIError {
	if len(tags) > max {
		return invalidTag("Object tags cannot be greater than " + strconv.Itoa(max))
	}
	for k, v := range tags {
		switch {
		case k == "" || len([]rune(k)) > maxTagKey:
			return invalidTag("The TagKey you have provided is invalid")
		case len([]rune(v)) > maxTagValue:
			return invalidTag("The TagValue you have provided is invalid")
		case !validTagChars(k):
			return invalidTag("The TagKey you have provided is invalid")
		case !validTagChars(v):
			return invalidTag("The TagValue you have provided is invalid")
		case strings.HasPrefix(strings.ToLower(k), "aws:"):
			return invalidTag("Your TagKey cannot be prefixed with aws:")
		}
	}
	return nil
}

// tagsFromHeader parses an x-amz-tagging value (URL query encoding).
func tagsFromHeader(v string) (map[string]string, *APIError) {
	if strings.Contains(v, ";") {
		return nil, invalidTag("The header 'x-amz-tagging' shall be encoded as UTF-8 then URLEncoded URL query parameters without tag name duplicates.")
	}
	q, err := url.ParseQuery(v)
	if err != nil {
		return nil, invalidTag("The header 'x-amz-tagging' shall be encoded as UTF-8 then URLEncoded URL query parameters without tag name duplicates.")
	}
	tags := make(map[string]string, len(q))
	for k, vs := range q {
		if len(vs) > 1 {
			return nil, invalidTag("Cannot provide multiple Tags with the same key")
		}
		tags[k] = vs[0]
	}
	if aerr := validateTags(tags, maxObjectTags); aerr != nil {
		return nil, aerr
	}
	return tags, nil
}

func encodeTags(tags map[string]string) string {
	if len(tags) == 0 {
		return ""
	}
	b, _ := json.Marshal(tags)
	return string(b)
}

func decodeTags(ud map[string]string) map[string]string {
	raw, ok := ud[tagsKey]
	if !ok {
		return nil
	}
	var m map[string]string
	if json.Unmarshal([]byte(raw), &m) != nil {
		return nil
	}
	return m
}

// ----- XML ------------------------------------------------------------

type tagXML struct {
	Key   string `xml:"Key"`
	Value string `xml:"Value"`
}

type taggingRequest struct {
	XMLName xml.Name `xml:"Tagging"`
	Tags    []tagXML `xml:"TagSet>Tag"`
}

type taggingResponse struct {
	XMLName xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ Tagging"`
	Tags    []tagXML `xml:"TagSet>Tag"`
}

func tagsFromXML(body []byte, max int) (map[string]string, *APIError) {
	var req taggingRequest
	if err := xml.Unmarshal(body, &req); err != nil {
		return nil, errMalformedXML
	}
	tags := make(map[string]string, len(req.Tags))
	for _, t := range req.Tags {
		if _, dup := tags[t.Key]; dup {
			return nil, invalidTag("Cannot provide multiple Tags with the same key")
		}
		tags[t.Key] = t.Value
	}
	if len(req.Tags) > max {
		return nil, invalidTag("Object tags cannot be greater than " + strconv.Itoa(max))
	}
	if aerr := validateTags(tags, max); aerr != nil {
		return nil, aerr
	}
	return tags, nil
}

func renderTags(tags map[string]string) *taggingResponse {
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := &taggingResponse{Tags: []tagXML{}}
	for _, k := range keys {
		out.Tags = append(out.Tags, tagXML{Key: k, Value: tags[k]})
	}
	return out
}

// ----- policy condition keys ------------------------------------------

const (
	existingTagPrefix = "s3:existingobjecttag/"
	requestTagPrefix  = "s3:requestobjecttag/"
)

// requestTagContext exposes the tags a write carries as
// s3:RequestObjectTag/<key> condition keys (lower-cased, as the engine
// compares keys).
func requestTagContext(tags map[string]string) map[string]string {
	ctx := map[string]string{}
	for k, v := range tags {
		ctx[requestTagPrefix+strings.ToLower(k)] = v
	}
	return ctx
}

// existingTagLookup resolves s3:ExistingObjectTag/<key> on demand: the
// object is read once per request, and only if a statement asks.
func (s *Server) existingTagLookup(q *request, bucket, key string) func(string) (string, bool) {
	var (
		loaded bool
		tags   map[string]string
	)
	return func(k string) (string, bool) {
		if !strings.HasPrefix(k, existingTagPrefix) || key == "" {
			return "", false
		}
		if !loaded {
			loaded = true
			info, err := s.st.StatObject(q.r.Context(), bucket, key, storage.GetOptions{VersionID: q.query.Get("versionId")})
			if err == nil {
				tags = decodeTags(info.UserDefined)
			}
		}
		name := strings.TrimPrefix(k, existingTagPrefix)
		for tk, tv := range tags {
			if strings.EqualFold(tk, name) {
				return tv, true
			}
		}
		return "", false
	}
}

// ----- handlers -------------------------------------------------------

func (s *Server) objectTaggingOp(q *request) {
	vid := q.query.Get("versionId")
	verAction := func(base string) string {
		if vid != "" {
			return strings.Replace(base, "Object", "ObjectVersion", 1)
		}
		return base
	}
	switch q.r.Method {
	case http.MethodGet:
		if !s.authorize(q, verAction("s3:GetObjectTagging"), q.bucket, q.key, nil) {
			return
		}
		info, err := s.st.StatObject(q.ctx(), q.bucket, q.key, storage.GetOptions{VersionID: vid})
		if err != nil {
			s.fail(q, err)
			return
		}
		if info.VersionID != "" {
			q.w.Header().Set("x-amz-version-id", info.VersionID)
		}
		s.writeXML(q, http.StatusOK, renderTags(decodeTags(info.UserDefined)))
	case http.MethodPut:
		body, err := s.readBody(q, 64<<10)
		if err != nil {
			s.fail(q, err)
			return
		}
		tags, aerr := tagsFromXML(body, maxObjectTags)
		// Authorise first with the tags the request carries, so a policy can
		// condition on s3:RequestObjectTag/<key>; then report bad input.
		if !s.authorize(q, verAction("s3:PutObjectTagging"), q.bucket, q.key, requestTagContext(tags)) {
			return
		}
		if aerr != nil {
			s.fail(q, aerr)
			return
		}
		s.setObjectTags(q, vid, tags)
	case http.MethodDelete:
		if !s.authorize(q, verAction("s3:DeleteObjectTagging"), q.bucket, q.key, nil) {
			return
		}
		s.setObjectTags(q, vid, nil)
	default:
		s.fail(q, errBadMethod)
	}
}

func (s *Server) setObjectTags(q *request, vid string, tags map[string]string) {
	ri, rbad := s.replicaRequest(q)
	if rbad {
		return
	}
	info, err := s.st.StatObject(q.ctx(), q.bucket, q.key, storage.GetOptions{VersionID: vid})
	if err != nil {
		s.fail(q, err)
		return
	}
	ud := make(map[string]string, len(info.UserDefined)+1)
	for k, v := range info.UserDefined {
		ud[k] = v
	}
	delete(ud, tagsKey)
	if len(tags) > 0 {
		ud[tagsKey] = encodeTags(tags)
	}
	upd, err := s.st.UpdateObjectMetadata(q.ctx(), q.bucket, q.key, storage.UpdateMetaOptions{
		VersionID: info.VersionID, UserDefined: ud, IfETag: info.ETag,
	})
	if err != nil {
		s.fail(q, err)
		return
	}
	if upd.VersionID != "" {
		q.w.Header().Set("x-amz-version-id", upd.VersionID)
	}
	if ri == nil {
		s.replAfterMeta(q.ctx(), q.bucket, q.key, upd.VersionID)
	}
	if q.r.Method == http.MethodDelete {
		q.w.WriteHeader(http.StatusNoContent)
		return
	}
	q.w.WriteHeader(http.StatusOK)
}

func (s *Server) bucketTaggingOp(q *request) {
	switch q.r.Method {
	case http.MethodGet:
		if !s.authorize(q, "s3:GetBucketTagging", q.bucket, "", nil) || !s.requireBucket(q) {
			return
		}
		raw, err := s.confRaw(q.ctx(), q.bucket, confTagging)
		if err != nil {
			s.fail(q, err)
			return
		}
		if raw == nil {
			s.fail(q, errNoSuchTagSet)
			return
		}
		var tags map[string]string
		json.Unmarshal(raw, &tags)
		s.writeXML(q, http.StatusOK, renderTags(tags))
	case http.MethodPut:
		if !s.authorize(q, "s3:PutBucketTagging", q.bucket, "", nil) {
			return
		}
		body, err := s.readBody(q, 64<<10)
		if err != nil {
			s.fail(q, err)
			return
		}
		tags, aerr := tagsFromXML(body, maxBucketTags)
		if aerr != nil {
			s.fail(q, aerr)
			return
		}
		if len(tags) == 0 {
			s.fail(q, errMalformedXML)
			return
		}
		if !s.requireBucket(q) {
			return
		}
		data, _ := json.Marshal(tags)
		if err := s.confPut(q.ctx(), q.bucket, confTagging, data); err != nil {
			s.fail(q, err)
			return
		}
		q.w.WriteHeader(http.StatusNoContent)
	case http.MethodDelete:
		if !s.authorize(q, "s3:PutBucketTagging", q.bucket, "", nil) || !s.requireBucket(q) {
			return
		}
		s.confDrop(q.ctx(), q.bucket, confTagging)
		q.w.WriteHeader(http.StatusNoContent)
	default:
		s.fail(q, errBadMethod)
	}
}

// applyTagHeader records the tags of an x-amz-tagging header in opts,
// authorising s3:PutObjectTagging (with the tags as request-tag condition
// keys) as S3 does. It reports false after writing a response.
func (s *Server) applyTagHeader(q *request, opts *storage.PutOptions) bool {
	v := q.r.Header.Get("x-amz-tagging")
	if v == "" {
		return true
	}
	tags, aerr := tagsFromHeader(v)
	if !s.authorize(q, "s3:PutObjectTagging", q.bucket, q.key, requestTagContext(tags)) {
		return false
	}
	if aerr != nil {
		s.fail(q, aerr)
		return false
	}
	if len(tags) > 0 {
		ud := make(map[string]string, len(opts.UserDefined)+1)
		for k, val := range opts.UserDefined {
			ud[k] = val
		}
		ud[tagsKey] = encodeTags(tags)
		opts.UserDefined = ud
	}
	return true
}

// tagCountHeader sets x-amz-tagging-count when the caller may read tags.
func (s *Server) tagCountHeader(q *request, h http.Header, ud map[string]string, versionID string) {
	tags := decodeTags(ud)
	if len(tags) == 0 {
		return
	}
	action := "s3:GetObjectTagging"
	if q.query.Get("versionId") != "" {
		action = "s3:GetObjectVersionTagging"
	}
	if s.allowed(q, action, q.bucket, q.key) {
		h.Set("x-amz-tagging-count", strconv.Itoa(len(tags)))
	}
}

// headerTagContext is the s3:RequestObjectTag/<key> context of a write that
// carries an x-amz-tagging header (empty if it carries none or an invalid
// one, which applyTagHeader reports).
func headerTagContext(h http.Header) map[string]string {
	v := h.Get("x-amz-tagging")
	if v == "" {
		return nil
	}
	tags, aerr := tagsFromHeader(v)
	if aerr != nil {
		return nil
	}
	return requestTagContext(tags)
}

// writeContext is the request-derived condition context of a write: the
// tags it carries and the storage class it asks for.
func writeContext(h http.Header) map[string]string {
	ctx := headerTagContext(h)
	if c := strings.TrimSpace(h.Get("x-amz-storage-class")); c != "" {
		if ctx == nil {
			ctx = map[string]string{}
		}
		ctx["s3:x-amz-storage-class"] = c
	}
	return ctx
}

func classOrStandard(c string) string {
	if c == "" {
		return "STANDARD"
	}
	return c
}
