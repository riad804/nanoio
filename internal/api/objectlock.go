package api

import (
	"encoding/xml"
	"errors"
	"net/http"
	"strings"
	"time"

	"nanoio/internal/iam"
	"nanoio/internal/storage"
)

// Object lock request and response headers.
const (
	hdrLockEnabled = "x-amz-bucket-object-lock-enabled"
	hdrLockMode    = "x-amz-object-lock-mode"
	hdrLockUntil   = "x-amz-object-lock-retain-until-date"
	hdrLockHold    = "x-amz-object-lock-legal-hold"
	hdrBypass      = "x-amz-bypass-governance-retention"
)

var (
	errNoLockConfig = &APIError{"ObjectLockConfigurationNotFoundError", "Object Lock configuration does not exist for this bucket", http.StatusNotFound}
	errNoObjectLock = &APIError{"NoSuchObjectLockConfiguration", "The specified object does not have a ObjectLock configuration", http.StatusNotFound}
	errNoBucketLock = &APIError{"InvalidRequest", "Bucket is missing Object Lock Configuration", http.StatusBadRequest}
)

// lockRequest is the object lock a PUT or an upload initiation asks for.
type lockRequest struct {
	retention storage.Retention
	hold      bool
	// holdGiven is whether x-amz-object-lock-legal-hold was present, which
	// needs s3:PutObjectLegalHold even when it says OFF.
	holdGiven bool
}

func (l lockRequest) any() bool { return !l.retention.IsZero() || l.holdGiven }

// parseLockHeaders reads the per-object lock headers. Mode and date must
// come together; a date that is not in the future is rejected by storage
// (ErrInvalidRetention, 400), under the same clock that judges expiry.
func parseLockHeaders(h http.Header) (lockRequest, *APIError) {
	var l lockRequest
	mode, until := h.Get(hdrLockMode), h.Get(hdrLockUntil)
	if (mode == "") != (until == "") {
		return l, invalidArgument("x-amz-object-lock-retain-until-date and x-amz-object-lock-mode must both be supplied")
	}
	if mode != "" {
		m := storage.RetentionMode(mode)
		if !m.Valid() {
			return l, invalidArgument("Unknown wormMode directive.")
		}
		t, err := time.Parse(time.RFC3339Nano, until)
		if err != nil {
			return l, invalidArgument("The retain until date must be provided in ISO 8601 format")
		}
		l.retention = storage.Retention{Mode: m, Until: t.UTC()}
	}
	switch v := h.Get(hdrLockHold); v {
	case "":
	case "ON":
		l.hold, l.holdGiven = true, true
	case "OFF":
		l.holdGiven = true
	default:
		return l, invalidArgument("Legal hold status must be ON or OFF")
	}
	return l, nil
}

// authorizeLockHeaders checks the permissions the lock headers of a write
// need, in addition to s3:PutObject. It writes the response on failure.
func (s *Server) authorizeLockHeaders(q *request, l lockRequest) bool {
	if !l.retention.IsZero() && !s.authorize(q, "s3:PutObjectRetention", q.bucket, q.key, nil) {
		return false
	}
	if l.holdGiven && !s.authorize(q, "s3:PutObjectLegalHold", q.bucket, q.key, nil) {
		return false
	}
	return true
}

// allowed asks the policy engine without writing a response.
func (s *Server) allowed(q *request, action, bucket, key string) bool {
	if s.noAuth {
		return true
	}
	return s.authz.Allowed(q.who, iam.Request{
		Action: action, Bucket: bucket, Key: key,
		Context: map[string]string{"aws:sourceip": remoteIP(q.r), "aws:securetransport": boolStr(q.r.TLS != nil)},
	})
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// wantsBypass reports whether the request asked to bypass governance
// retention. Anything but "true" is no.
func wantsBypass(h http.Header) bool {
	return strings.EqualFold(strings.TrimSpace(h.Get(hdrBypass)), "true")
}

// bypassGovernance decides the bypass flag for one key. Bypass is granted
// only when the request asked for it AND the principal holds
// s3:BypassGovernanceRetention on the key; asking without the permission is
// AccessDenied, never a silent downgrade to "no bypass". It writes the
// response and returns ok=false in that case.
func (s *Server) bypassGovernance(q *request, key string) (bypass, ok bool) {
	if !wantsBypass(q.r.Header) {
		return false, true
	}
	if !s.allowed(q, "s3:BypassGovernanceRetention", q.bucket, key) {
		s.log.Info("access denied", "id", q.id, "user", q.who, "action", "s3:BypassGovernanceRetention", "resource", q.bucket+"/"+key)
		s.fail(q, errAccessDenied)
		return false, false
	}
	return true, true
}

// lockResponseHeaders adds the object lock headers GET and HEAD return.
func lockResponseHeaders(h http.Header, info storage.ObjectInfo) {
	if !info.Retention.IsZero() {
		h.Set(hdrLockMode, string(info.Retention.Mode))
		h.Set(hdrLockUntil, isoTime(info.Retention.Until))
	}
	if info.LegalHold {
		h.Set(hdrLockHold, "ON")
	}
}

// --- bucket configuration ---

type objectLockConfiguration struct {
	XMLName           xml.Name  `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ObjectLockConfiguration"`
	ObjectLockEnabled string    `xml:"ObjectLockEnabled"`
	Rule              *lockRule `xml:"Rule,omitempty"`
}

type lockRule struct {
	DefaultRetention *defaultRetention `xml:"DefaultRetention"`
}

type defaultRetention struct {
	Mode  string `xml:"Mode"`
	Days  int    `xml:"Days,omitempty"`
	Years int    `xml:"Years,omitempty"`
}

// putObjectLockConfigurationRequest is the PUT ?object-lock body; the
// namespace is optional, as clients differ.
type putObjectLockConfigurationRequest struct {
	XMLName           xml.Name  `xml:"ObjectLockConfiguration"`
	ObjectLockEnabled string    `xml:"ObjectLockEnabled"`
	Rule              *lockRule `xml:"Rule"`
}

// createBucketLockRequested reads x-amz-bucket-object-lock-enabled.
func createBucketLockRequested(h http.Header) (bool, *APIError) {
	switch v := strings.TrimSpace(h.Get(hdrLockEnabled)); {
	case v == "":
		return false, nil
	case strings.EqualFold(v, "true"):
		return true, nil
	case strings.EqualFold(v, "false"):
		return false, nil
	}
	return false, invalidArgument("x-amz-bucket-object-lock-enabled must be true or false")
}

// putObjectLockConfiguration implements PUT /bucket?object-lock.
func (s *Server) putObjectLockConfiguration(q *request) {
	if !s.authorize(q, "s3:PutBucketObjectLockConfiguration", q.bucket, "", nil) {
		return
	}
	body, err := s.readBody(q, 1<<20)
	if err != nil {
		s.fail(q, err)
		return
	}
	var req putObjectLockConfigurationRequest
	if err := xml.Unmarshal(body, &req); err != nil || req.ObjectLockEnabled != "Enabled" {
		s.fail(q, errMalformedXML)
		return
	}
	cfg := storage.ObjectLockConfig{Enabled: true}
	if req.Rule != nil {
		d := req.Rule.DefaultRetention
		if d == nil {
			s.fail(q, errMalformedXML)
			return
		}
		dr := storage.DefaultRetention{Mode: storage.RetentionMode(d.Mode), Days: d.Days, Years: d.Years}
		if dr.Validate() != nil {
			s.fail(q, errMalformedXML)
			return
		}
		cfg.Default = &dr
	}
	if err := s.st.SetBucketObjectLock(q.r.Context(), q.bucket, cfg); err != nil {
		s.fail(q, err)
		return
	}
	q.w.WriteHeader(http.StatusOK)
}

// getObjectLockConfiguration implements GET /bucket?object-lock.
func (s *Server) getObjectLockConfiguration(q *request) {
	if !s.authorize(q, "s3:GetBucketObjectLockConfiguration", q.bucket, "", nil) {
		return
	}
	cfg, err := s.st.GetBucketObjectLock(q.r.Context(), q.bucket)
	if err != nil {
		s.fail(q, err)
		return
	}
	if !cfg.Enabled {
		s.writeAPIError(q, errNoLockConfig)
		return
	}
	out := objectLockConfiguration{ObjectLockEnabled: "Enabled"}
	if d := cfg.Default; d != nil {
		out.Rule = &lockRule{DefaultRetention: &defaultRetention{Mode: string(d.Mode), Days: d.Days, Years: d.Years}}
	}
	s.writeXML(q, http.StatusOK, &out)
}

// --- per-object retention and legal hold ---

type retentionDoc struct {
	XMLName         xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ Retention"`
	Mode            string   `xml:"Mode,omitempty"`
	RetainUntilDate string   `xml:"RetainUntilDate,omitempty"`
}

type putRetentionRequest struct {
	XMLName         xml.Name `xml:"Retention"`
	Mode            string   `xml:"Mode"`
	RetainUntilDate string   `xml:"RetainUntilDate"`
}

type legalHoldDoc struct {
	XMLName xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ LegalHold"`
	Status  string   `xml:"Status"`
}

type putLegalHoldRequest struct {
	XMLName xml.Name `xml:"LegalHold"`
	Status  string   `xml:"Status"`
}

// objectLockOp routes ?retention and ?legal-hold on an object.
func (s *Server) objectLockOp(q *request, sub string) {
	m := q.r.Method
	switch {
	case sub == "retention" && m == http.MethodPut:
		s.putObjectRetention(q)
	case sub == "retention" && m == http.MethodGet:
		s.getObjectRetention(q)
	case sub == "legal-hold" && m == http.MethodPut:
		s.putObjectLegalHold(q)
	case sub == "legal-hold" && m == http.MethodGet:
		s.getObjectLegalHold(q)
	default:
		s.fail(q, errBadMethod)
	}
}

func (q *request) ref() storage.ObjectRef {
	return storage.ObjectRef{Bucket: q.bucket, Object: q.key, VersionID: q.query.Get("versionId")}
}

// putObjectRetention implements PUT /bucket/key?retention. An empty
// <Retention/> removes the retention, which the storage layer allows only for
// governance retention and only with bypass.
func (s *Server) putObjectRetention(q *request) {
	if !s.authorize(q, "s3:PutObjectRetention", q.bucket, q.key, nil) {
		return
	}
	body, err := s.readBody(q, 64<<10)
	if err != nil {
		s.fail(q, err)
		return
	}
	var req putRetentionRequest
	if err := xml.Unmarshal(body, &req); err != nil {
		s.fail(q, errMalformedXML)
		return
	}
	var r storage.Retention
	if req.Mode != "" || req.RetainUntilDate != "" {
		t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(req.RetainUntilDate))
		if req.Mode == "" || req.RetainUntilDate == "" || err != nil {
			s.fail(q, errMalformedXML)
			return
		}
		r = storage.Retention{Mode: storage.RetentionMode(req.Mode), Until: t.UTC()}
		if !r.Mode.Valid() {
			s.fail(q, errMalformedXML)
			return
		}
	}
	bypass, ok := s.bypassGovernance(q, q.key)
	if !ok {
		return
	}
	info, err := s.st.SetObjectRetention(q.r.Context(), q.ref(), r, storage.RetentionOptions{BypassGovernance: bypass})
	if err != nil {
		s.logLockRefusal(q, "retention", err)
		s.fail(q, err)
		return
	}
	if info.VersionID != "" {
		q.w.Header().Set("x-amz-version-id", info.VersionID)
	}
	q.w.WriteHeader(http.StatusOK)
}

// getObjectRetention implements GET /bucket/key?retention.
func (s *Server) getObjectRetention(q *request) {
	if !s.authorize(q, "s3:GetObjectRetention", q.bucket, q.key, nil) {
		return
	}
	info, ok := s.statForLock(q)
	if !ok {
		return
	}
	if info.Retention.IsZero() {
		s.writeAPIError(q, errNoObjectLock)
		return
	}
	if info.VersionID != "" {
		q.w.Header().Set("x-amz-version-id", info.VersionID)
	}
	s.writeXML(q, http.StatusOK, &retentionDoc{Mode: string(info.Retention.Mode), RetainUntilDate: isoTime(info.Retention.Until)})
}

// putObjectLegalHold implements PUT /bucket/key?legal-hold.
func (s *Server) putObjectLegalHold(q *request) {
	if !s.authorize(q, "s3:PutObjectLegalHold", q.bucket, q.key, nil) {
		return
	}
	body, err := s.readBody(q, 64<<10)
	if err != nil {
		s.fail(q, err)
		return
	}
	var req putLegalHoldRequest
	if err := xml.Unmarshal(body, &req); err != nil || (req.Status != "ON" && req.Status != "OFF") {
		s.fail(q, errMalformedXML)
		return
	}
	info, err := s.st.SetObjectLegalHold(q.r.Context(), q.ref(), req.Status == "ON")
	if err != nil {
		s.fail(q, err)
		return
	}
	if info.VersionID != "" {
		q.w.Header().Set("x-amz-version-id", info.VersionID)
	}
	q.w.WriteHeader(http.StatusOK)
}

// getObjectLegalHold implements GET /bucket/key?legal-hold.
func (s *Server) getObjectLegalHold(q *request) {
	if !s.authorize(q, "s3:GetObjectLegalHold", q.bucket, q.key, nil) {
		return
	}
	info, ok := s.statForLock(q)
	if !ok {
		return
	}
	status := "OFF"
	if info.LegalHold {
		status = "ON"
	}
	if info.VersionID != "" {
		q.w.Header().Set("x-amz-version-id", info.VersionID)
	}
	s.writeXML(q, http.StatusOK, &legalHoldDoc{Status: status})
}

// statForLock resolves the version a lock read addresses. A bucket without
// object lock has nothing to read: InvalidRequest, as S3 answers.
func (s *Server) statForLock(q *request) (storage.ObjectInfo, bool) {
	cfg, err := s.st.GetBucketObjectLock(q.r.Context(), q.bucket)
	if err != nil {
		s.fail(q, err)
		return storage.ObjectInfo{}, false
	}
	if !cfg.Enabled {
		s.writeAPIError(q, errNoBucketLock)
		return storage.ObjectInfo{}, false
	}
	info, err := s.st.StatObject(q.r.Context(), q.bucket, q.key, storage.GetOptions{VersionID: q.query.Get("versionId")})
	if err != nil {
		s.fail(q, err)
		return storage.ObjectInfo{}, false
	}
	return info, true
}

// logLockRefusal records, for the operator, a change that object lock
// refused; the client is told only AccessDenied.
func (s *Server) logLockRefusal(q *request, what string, err error) {
	if errors.Is(err, storage.ErrObjectLocked) {
		s.log.Info("object lock refused a change", "id", q.id, "user", q.who, "op", what,
			"bucket", q.bucket, "key", q.key, "version", q.query.Get("versionId"), "why", err.Error())
	}
}
