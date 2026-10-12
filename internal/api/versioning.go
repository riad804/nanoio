package api

import (
	"encoding/xml"
	"net/http"

	"nanoio/internal/storage"
)

// versioningConfiguration is the response of GetBucketVersioning.
type versioningConfiguration struct {
	XMLName xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ VersioningConfiguration"`
	Status  string   `xml:"Status,omitempty"`
}

// putVersioningRequest is the PutBucketVersioning body. The namespace is
// not required: clients differ.
type putVersioningRequest struct {
	XMLName   xml.Name `xml:"VersioningConfiguration"`
	Status    string   `xml:"Status"`
	MFADelete string   `xml:"MfaDelete"`
}

// putBucketVersioning implements PUT /bucket?versioning.
func (s *Server) putBucketVersioning(q *request) {
	if !s.authorize(q, "s3:PutBucketVersioning", q.bucket, "", nil) {
		return
	}
	body, err := s.readBody(q, 1<<20)
	if err != nil {
		s.fail(q, err)
		return
	}
	var req putVersioningRequest
	if err := xml.Unmarshal(body, &req); err != nil {
		s.fail(q, errMalformedXML)
		return
	}
	if req.MFADelete != "" {
		s.fail(q, notImplemented("MFA delete"))
		return
	}
	var state storage.VersioningState
	switch req.Status {
	case "Enabled":
		state = storage.VersioningEnabled
	case "Suspended":
		state = storage.VersioningSuspended
	default:
		// A missing or unknown Status is a schema violation, not an
		// attempt to go back to unversioned.
		s.fail(q, errMalformedXML)
		return
	}
	if err := s.st.SetBucketVersioning(q.r.Context(), q.bucket, state); err != nil {
		s.fail(q, err)
		return
	}
	q.w.WriteHeader(http.StatusOK)
}

// getBucketVersioning implements GET /bucket?versioning. A bucket that
// never had versioning returns an empty configuration, as S3 does.
func (s *Server) getBucketVersioning(q *request) {
	if !s.authorize(q, "s3:GetBucketVersioning", q.bucket, "", nil) {
		return
	}
	cfg, err := s.st.GetBucketVersioning(q.r.Context(), q.bucket)
	if err != nil {
		s.fail(q, err)
		return
	}
	s.writeXML(q, http.StatusOK, &versioningConfiguration{Status: string(cfg.State)})
}
