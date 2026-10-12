package api

import (
	"net/http"
	"strconv"

	"nanoio/internal/iam"
)

var (
	errNoSuchBucketPolicy = &APIError{"NoSuchBucketPolicy", "The bucket policy does not exist.", http.StatusNotFound}
)

func malformedPolicy(msg string) *APIError {
	return &APIError{"MalformedPolicy", msg, http.StatusBadRequest}
}

// bucketPolicyOp serves PUT, GET and DELETE of /bucket?policy.
func (s *Server) bucketPolicyOp(q *request) {
	switch q.r.Method {
	case http.MethodPut:
		s.putBucketPolicy(q)
	case http.MethodGet:
		s.getBucketPolicy(q)
	case http.MethodDelete:
		s.deleteBucketPolicy(q)
	default:
		s.fail(q, errBadMethod)
	}
}

func (s *Server) putBucketPolicy(q *request) {
	if !s.authorize(q, "s3:PutBucketPolicy", q.bucket, "", nil) {
		return
	}
	body, err := s.readBody(q, iam.MaxBucketPolicySize+1)
	if err != nil {
		s.fail(q, err)
		return
	}
	if _, err := iam.ParseBucketPolicy(body, q.bucket); err != nil {
		s.fail(q, malformedPolicy(upperFirst(err.Error())+"."))
		return
	}
	if !s.requireBucket(q) {
		return
	}
	if err := s.confPut(q.ctx(), q.bucket, confPolicy, body); err != nil {
		s.fail(q, err)
		return
	}
	q.w.WriteHeader(http.StatusNoContent)
}

func (s *Server) getBucketPolicy(q *request) {
	if !s.authorize(q, "s3:GetBucketPolicy", q.bucket, "", nil) {
		return
	}
	if !s.requireBucket(q) {
		return
	}
	raw, err := s.confRaw(q.ctx(), q.bucket, confPolicy)
	if err != nil {
		s.fail(q, err)
		return
	}
	if raw == nil {
		s.fail(q, errNoSuchBucketPolicy)
		return
	}
	h := q.w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Content-Length", strconv.Itoa(len(raw)))
	q.w.WriteHeader(http.StatusOK)
	q.w.Write(raw)
}

func (s *Server) deleteBucketPolicy(q *request) {
	if !s.authorize(q, "s3:DeleteBucketPolicy", q.bucket, "", nil) {
		return
	}
	if !s.requireBucket(q) {
		return
	}
	s.confDrop(q.ctx(), q.bucket, confPolicy)
	q.w.WriteHeader(http.StatusNoContent)
}
