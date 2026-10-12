package api

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"nanoio/internal/kms"
	"nanoio/internal/sse"
	"nanoio/internal/storage"
)

// A bucket's default encryption is a small JSON document stored as an
// ordinary object, "<bucket>/encryption", in the reserved bucket sysBucket.
// It therefore gets the backend's quorum, healing and cluster placement
// for free. The API never serves sysBucket to clients.
const encConfigName = "/encryption"

// encConfigTTL bounds how stale another node's change can be; a change made
// through this node is visible at once.
const encConfigTTL = 5 * time.Second

type bucketEncConfig struct {
	Algorithm string `json:"algorithm"` // "AES256" or "aws:kms"
	KeyID     string `json:"keyId,omitempty"`
}

type encConfigEntry struct {
	cfg     *bucketEncConfig
	expires time.Time
}

type encConfigCache struct {
	mu sync.Mutex
	m  map[string]encConfigEntry
}

func (c *encConfigCache) get(b string) (*bucketEncConfig, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[b]
	if !ok || time.Now().After(e.expires) {
		return nil, false
	}
	return e.cfg, true
}

func (c *encConfigCache) put(b string, cfg *bucketEncConfig) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]encConfigEntry{}
	}
	c.m[b] = encConfigEntry{cfg, time.Now().Add(encConfigTTL)}
}

func (c *encConfigCache) drop(b string) {
	c.mu.Lock()
	delete(c.m, b)
	c.mu.Unlock()
}

// loadEncConfig reads the bucket's default encryption, or nil.
func (s *Server) loadEncConfig(ctx context.Context, bucket string) (*bucketEncConfig, error) {
	if cfg, ok := s.encCache.get(bucket); ok {
		return cfg, nil
	}
	rc, _, err := s.st.GetObject(ctx, sysBucket, bucket+encConfigName, storage.GetOptions{})
	switch {
	case errors.Is(err, storage.ErrObjectNotFound), errors.Is(err, storage.ErrBucketNotFound):
		s.encCache.put(bucket, nil)
		return nil, nil
	case err != nil:
		return nil, err
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, 64<<10))
	if err != nil {
		return nil, err
	}
	var cfg bucketEncConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	s.encCache.put(bucket, &cfg)
	return &cfg, nil
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
	if err := s.ensureSysBucket(q.ctx()); err != nil {
		s.fail(q, err)
		return
	}
	if _, err := s.st.PutObject(q.ctx(), sysBucket, q.bucket+encConfigName, bytes.NewReader(data), int64(len(data)), storage.PutOptions{}); err != nil {
		s.fail(q, err)
		return
	}
	s.encCache.drop(q.bucket)
	q.w.WriteHeader(http.StatusOK)
}

func (s *Server) ensureSysBucket(ctx context.Context) error {
	err := s.st.MakeBucket(ctx, sysBucket, storage.MakeBucketOptions{})
	if err != nil && !errors.Is(err, storage.ErrBucketExists) {
		return err
	}
	return nil
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
	s.dropEncConfig(q.ctx(), q.bucket)
	q.w.WriteHeader(http.StatusNoContent)
}

// dropEncConfig removes a bucket's default encryption document, if any.
func (s *Server) dropEncConfig(ctx context.Context, bucket string) {
	_, err := s.st.DeleteObject(ctx, sysBucket, bucket+encConfigName, storage.DeleteOptions{})
	if err != nil && !errors.Is(err, storage.ErrObjectNotFound) && !errors.Is(err, storage.ErrBucketNotFound) {
		s.log.Warn("could not remove bucket encryption config", "bucket", bucket, "err", err)
	}
	s.encCache.drop(bucket)
}

var _ = kms.Zero
