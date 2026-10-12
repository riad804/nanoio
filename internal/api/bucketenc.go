package api

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"net/http"
	"strings"

	"nanoio/internal/kms"
	"nanoio/internal/sse"
	"nanoio/internal/storage"
)

// A bucket's default encryption is a small JSON document of kind
// confEncryption (see bucketconf.go).
type bucketEncConfig struct {
	Algorithm string `json:"algorithm"` // "AES256" or "aws:kms"
	KeyID     string `json:"keyId,omitempty"`
}

// loadEncConfig reads the bucket's default encryption, or nil.
func (s *Server) loadEncConfig(ctx context.Context, bucket string) (*bucketEncConfig, error) {
	v, err := s.confParsed(ctx, bucket, confEncryption, func(b []byte) (any, error) {
		var cfg bucketEncConfig
		if err := json.Unmarshal(b, &cfg); err != nil {
			return nil, err
		}
		return &cfg, nil
	})
	if err != nil || v == nil {
		return nil, err
	}
	return v.(*bucketEncConfig), nil
}

// bucketDefaultSpec is the encryption a write with no SSE headers gets.
func (s *Server) bucketDefaultSpec(ctx context.Context, bucket string) (*sseSpec, error) {
	cfg, err := s.loadEncConfig(ctx, bucket)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}
	if s.kms == nil {
		return nil, errKMSNotConfigured
	}
	switch cfg.Algorithm {
	case "AES256":
		return &sseSpec{mode: sse.ModeS3, keyID: s.defaultKey}, nil
	case "aws:kms":
		id := cfg.KeyID
		if id == "" {
			id = s.defaultKey
		}
		return &sseSpec{mode: sse.ModeKMS, keyID: id}, nil
	}
	return nil, errInternal
}

// serverSideEncryptionConfiguration is the S3 document (the response form,
// with the namespace).
type serverSideEncryptionConfiguration struct {
	XMLName xml.Name  `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ServerSideEncryptionConfiguration"`
	Rules   []sseRule `xml:"Rule"`
}

// putEncryptionRequest is the request form: the namespace is not required,
// as clients differ.
type putEncryptionRequest struct {
	XMLName xml.Name  `xml:"ServerSideEncryptionConfiguration"`
	Rules   []sseRule `xml:"Rule"`
}

type sseRule struct {
	Default          sseDefault `xml:"ApplyServerSideEncryptionByDefault"`
	BucketKeyEnabled *bool      `xml:"BucketKeyEnabled,omitempty"`
}

type sseDefault struct {
	SSEAlgorithm   string `xml:"SSEAlgorithm"`
	KMSMasterKeyID string `xml:"KMSMasterKeyID,omitempty"`
}

var errNoEncConfig = &APIError{"ServerSideEncryptionConfigurationNotFoundError",
	"The server side encryption configuration was not found.", http.StatusNotFound}

func (s *Server) bucketEncryptionOp(q *request) {
	switch q.r.Method {
	case http.MethodPut:
		s.putBucketEncryption(q)
	case http.MethodGet:
		s.getBucketEncryption(q)
	case http.MethodDelete:
		s.deleteBucketEncryption(q)
	default:
		s.fail(q, errBadMethod)
	}
}

func (s *Server) putBucketEncryption(q *request) {
	if !s.authorize(q, "s3:PutEncryptionConfiguration", q.bucket, "", nil) {
		return
	}
	body, err := s.readBody(q, 64<<10)
	if err != nil {
		s.fail(q, err)
		return
	}
	var doc putEncryptionRequest
	if err := xml.Unmarshal(body, &doc); err != nil || len(doc.Rules) != 1 {
		s.fail(q, errMalformedXML)
		return
	}
	d := doc.Rules[0].Default
	cfg := bucketEncConfig{Algorithm: d.SSEAlgorithm}
	switch d.SSEAlgorithm {
	case "AES256":
		if d.KMSMasterKeyID != "" {
			s.fail(q, invalidArgument("KMSMasterKeyID is only valid with aws:kms."))
			return
		}
	case "aws:kms":
		cfg.KeyID = strings.TrimPrefix(d.KMSMasterKeyID, "arn:aws:kms:")
	default:
		s.fail(q, errMalformedXML)
		return
	}
	if s.kms == nil {
		s.fail(q, errKMSNotConfigured)
		return
	}
	if ok, err := s.st.BucketExists(q.ctx(), q.bucket); err != nil || !ok {
		if err == nil {
			err = storage.ErrBucketNotFound
		}
		s.fail(q, err)
		return
	}
	id := cfg.KeyID
	if id == "" {
		id = s.defaultKey
	}
	if _, err := s.kms.DescribeKey(q.ctx(), id); err != nil {
		s.fail(q, s.sseError(q, sse.ModeKMS, err))
		return
	}
	data, _ := json.Marshal(cfg)
	if err := s.confPut(q.ctx(), q.bucket, confEncryption, data); err != nil {
		s.fail(q, err)
		return
	}
	q.w.WriteHeader(http.StatusOK)
}

func (s *Server) getBucketEncryption(q *request) {
	if !s.authorize(q, "s3:GetEncryptionConfiguration", q.bucket, "", nil) {
		return
	}
	if ok, err := s.st.BucketExists(q.ctx(), q.bucket); err != nil || !ok {
		if err == nil {
			err = storage.ErrBucketNotFound
		}
		s.fail(q, err)
		return
	}
	cfg, err := s.loadEncConfig(q.ctx(), q.bucket)
	if err != nil {
		s.fail(q, err)
		return
	}
	if cfg == nil {
		s.fail(q, errNoEncConfig)
		return
	}
	out := serverSideEncryptionConfiguration{Rules: []sseRule{{Default: sseDefault{SSEAlgorithm: cfg.Algorithm}}}}
	if cfg.KeyID != "" {
		out.Rules[0].Default.KMSMasterKeyID = "arn:aws:kms:" + cfg.KeyID
	}
	s.writeXML(q, http.StatusOK, &out)
}

func (s *Server) deleteBucketEncryption(q *request) {
	if !s.authorize(q, "s3:PutEncryptionConfiguration", q.bucket, "", nil) {
		return
	}
	if ok, err := s.st.BucketExists(q.ctx(), q.bucket); err != nil || !ok {
		if err == nil {
			err = storage.ErrBucketNotFound
		}
		s.fail(q, err)
		return
	}
	s.confDrop(q.ctx(), q.bucket, confEncryption)
	q.w.WriteHeader(http.StatusNoContent)
}

var _ = kms.Zero
