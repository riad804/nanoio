package api

import (
	"strconv"

	"nanoio/internal/iam"
	"nanoio/internal/storage"
)

// requestContext builds the condition-key context of a request. extra holds
// keys the handler knows (s3:prefix, s3:delimiter, s3:max-keys, tag keys).
func (s *Server) requestContext(q *request, extra map[string]string) map[string]string {
	ctx := make(map[string]string, len(extra)+4)
	for k, v := range extra {
		ctx[k] = v
	}
	ctx["aws:sourceip"] = remoteIP(q.r)
	ctx["aws:securetransport"] = strconv.FormatBool(q.r.TLS != nil)
	if v := q.r.Header.Get("Referer"); v != "" {
		ctx["aws:referer"] = v
	}
	if v := q.r.Header.Get("User-Agent"); v != "" {
		ctx["aws:useragent"] = v
	}
	return ctx
}

// bucketPolicy returns the bucket's parsed policy, or nil.
func (s *Server) bucketPolicy(q *request, bucket string) (*iam.BucketPolicy, error) {
	v, err := s.confParsed(q.r.Context(), bucket, confPolicy, func(b []byte) (any, error) {
		return iam.ParseBucketPolicy(b, bucket)
	})
	if err != nil || v == nil {
		return nil, err
	}
	return v.(*iam.BucketPolicy), nil
}

// decide is the single authorisation decision: the caller's identity
// policies and the bucket's resource policy, combined as AWS does. An
// explicit Deny in either wins; otherwise an Allow in either grants;
// otherwise the request is denied. The root credential is not subject to
// either kind of policy. An anonymous request is judged by the bucket policy
// alone. The error is a failure to read the bucket's configuration, in which
// case the request must be refused (never served on a guess).
func (s *Server) decide(q *request, req iam.Request) (bool, error) {
	var allow, deny bool
	if !q.anon && q.who != "" {
		if d, ok := s.authz.(Decider); ok {
			var root bool
			allow, deny, root = d.Decide(q.who, req)
			if root {
				return true, nil
			}
		} else if s.authz.Allowed(q.who, req) {
			allow = true
		}
	}
	if req.Bucket != "" {
		pol, err := s.bucketPolicy(q, req.Bucket)
		if err != nil {
			return false, err
		}
		if pol != nil {
			a, d := pol.Evaluate(req, iam.Principal{AccessKey: q.who, Anonymous: q.anon || q.who == ""})
			allow, deny = allow || a, deny || d
		}
	}
	if !allow && !deny && req.Bucket != "" {
		// ACLs only add Allows, so they are consulted last and only when
		// nothing else has decided.
		who := iam.Principal{AccessKey: q.who, Anonymous: q.anon || q.who == ""}
		a, err := s.aclDecision(q, req, who)
		if err != nil {
			return false, err
		}
		allow = a
	}
	return allow && !deny, nil
}

// allowed asks the policy engine without writing a response.
func (s *Server) allowed(q *request, action, bucket, key string) bool {
	return s.allowedCtx(q, action, bucket, key, nil)
}

func (s *Server) allowedCtx(q *request, action, bucket, key string, extra map[string]string) bool {
	if s.noAuth {
		return true
	}
	ok, err := s.decide(q, iam.Request{Action: action, Bucket: bucket, Key: key, Context: s.requestContext(q, extra),
		Lookup: s.existingTagLookup(q, bucket, key)})
	if err != nil {
		s.log.Error("cannot read bucket configuration for authorisation", "id", q.id, "bucket", bucket, "err", err)
		return false
	}
	return ok
}

// authorize checks that the caller may perform action on bucket/key before
// the handler does any work. ctx carries condition keys such as s3:prefix.
// It returns false after writing the response: AccessDenied, or 503 when
// the bucket's configuration cannot be read.
func (s *Server) authorize(q *request, action, bucket, key string, ctx map[string]string) bool {
	if s.noAuth {
		return true
	}
	req := iam.Request{Action: action, Bucket: bucket, Key: key, Context: s.requestContext(q, ctx),
		Lookup: s.existingTagLookup(q, bucket, key)}
	ok, err := s.decide(q, req)
	if err != nil {
		s.log.Error("cannot read bucket configuration for authorisation", "id", q.id, "bucket", bucket, "err", err)
		s.fail(q, storage.ErrBackendUnavailable)
		return false
	}
	if ok {
		return true
	}
	who := q.who
	if q.anon {
		who = "(anonymous)"
	}
	s.log.Info("access denied", "id", q.id, "user", who, "action", action, "resource", req.ARN())
	s.fail(q, errAccessDenied)
	return false
}
