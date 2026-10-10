// Package api is NanoIO's S3 HTTP layer: it parses path-style and
// virtual-host-style requests, authenticates and authorises them, calls
// storage.StorageAPI, and renders S3 XML and errors. It depends on the
// storage interface only, never on a backend.
//
// Every request is authenticated (SigV4 header or presigned URL) before any
// handler runs, and each handler authorises its specific action before it
// touches storage, so an unauthorised caller learns nothing about what
// exists. Authentication can be disabled only explicitly, with
// Options.InsecureNoAuth.
package api

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"nanoio/internal/auth"
	"nanoio/internal/iam"
	"nanoio/internal/storage"
)

// Authenticator verifies who sent a request. *auth.Verifier implements it.
type Authenticator interface {
	Authenticate(r *http.Request) (*auth.Result, error)
}

// Authorizer decides whether an authenticated identity may perform an
// action. *iam.Store implements it.
type Authorizer interface {
	Allowed(accessKey string, req iam.Request) bool
}

// Options configures New.
type Options struct {
	// Storage is the backend. Required.
	Storage storage.StorageAPI
	// Auth and Authz are required unless InsecureNoAuth is set.
	Auth  Authenticator
	Authz Authorizer
	// InsecureNoAuth serves every request as an all-powerful anonymous
	// caller. For local development only; New refuses to start without Auth
	// and Authz otherwise, so authentication cannot be skipped by accident.
	InsecureNoAuth bool
	// Domains are the base domains for virtual-host-style requests: a Host
	// of "photos.<domain>" addresses bucket "photos". Hosts that are not a
	// subdomain of any entry are treated as path-style.
	Domains []string
	// Region is reported by HeadBucket and GetBucketLocation. Defaults to
	// "us-east-1".
	Region string
	// Logger defaults to slog.Default().
	Logger *slog.Logger
	// Internal, when set, serves every path-style request under
	// /_nanoio/ (health, node-to-node RPC, admin) before S3 routing and
	// authentication, which it does for itself. No bucket name can start
	// with an underscore, so the prefix never collides with a bucket; a
	// virtual-host request whose key happens to start with "_nanoio/" is
	// still an object request.
	Internal http.Handler
}

// InternalPrefix is the reserved internal namespace.
const InternalPrefix = "/_nanoio/"

// Server is the S3 http.Handler.
type Server struct {
	st       storage.StorageAPI
	authn    Authenticator
	authz    Authorizer
	noAuth   bool
	domains  []string
	region   string
	log      *slog.Logger
	internal http.Handler
}

// New validates opts and returns the handler.
func New(opts Options) (*Server, error) {
	if opts.Storage == nil {
		return nil, errors.New("api: Options.Storage is required")
	}
	s := &Server{st: opts.Storage, region: opts.Region, log: opts.Logger,
		authn: opts.Auth, authz: opts.Authz, noAuth: opts.InsecureNoAuth, internal: opts.Internal}
	if !s.noAuth && (s.authn == nil || s.authz == nil) {
		return nil, errors.New("api: Options.Auth and Options.Authz are required (set InsecureNoAuth to disable authentication explicitly)")
	}
	if s.region == "" {
		s.region = "us-east-1"
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	for _, d := range opts.Domains {
		d = strings.ToLower(strings.Trim(strings.TrimSpace(d), "."))
		if d == "" || strings.ContainsAny(d, "/: ") {
			return nil, errors.New("api: invalid domain " + strconv.Quote(d))
		}
		s.domains = append(s.domains, d)
	}
	return s, nil
}

// request carries one parsed S3 request through the handlers.
type request struct {
	w      http.ResponseWriter
	r      *http.Request
	bucket string
	key    string
	query  url.Values
	id     string
	// who is the authenticated access key ("" when authentication is off).
	who string
	// res is the authentication result: payload hash and chunk signer.
	res *auth.Result
}

// statusWriter records the status and body size for access logging and
// lets the panic handler know whether a response was started.
type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytes += int64(n)
	return n, err
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func newRequestID() string {
	var b [8]byte
	rand.Read(b[:])
	return strings.ToUpper(hex.EncodeToString(b[:]))
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.internal != nil && strings.HasPrefix(r.URL.Path, InternalPrefix) {
		if _, vhost := s.hostBucket(r.Host); !vhost {
			s.internal.ServeHTTP(w, r)
			return
		}
	}
	start := time.Now()
	sw := &statusWriter{ResponseWriter: w}
	q := &request{w: sw, r: r, id: newRequestID(), query: r.URL.Query()}
	var hostID [24]byte
	rand.Read(hostID[:])
	h := sw.Header()
	h.Set("Server", "NanoIO")
	h.Set("x-amz-request-id", q.id)
	h.Set("x-amz-id-2", base64.StdEncoding.EncodeToString(hostID[:]))

	defer func() {
		if rec := recover(); rec != nil {
			if rec == http.ErrAbortHandler {
				panic(rec)
			}
			s.log.Error("panic serving request", "method", r.Method, "path", r.URL.Path,
				"panic", rec, "stack", string(debug.Stack()))
			if sw.status == 0 {
				s.fail(q, errInternal)
			}
		}
		s.log.Debug("request", "id", q.id, "method", r.Method, "path", r.URL.Path,
			"status", sw.status, "bytes", sw.bytes, "dur", time.Since(start))
	}()

	q.bucket, q.key = s.target(r.Host, r.URL.Path)
	if !s.noAuth {
		res, err := s.authn.Authenticate(r)
		if err != nil {
			s.fail(q, err)
			return
		}
		q.who, q.res = res.AccessKey, res
	}
	switch {
	case q.bucket == "":
		s.serviceOp(q)
	case q.key == "":
		s.bucketOp(q)
	default:
		s.objectOp(q)
	}
}

// target resolves the bucket and key of a request. A Host that is a
// subdomain of a configured domain selects virtual-host style; anything
// else is path style. A path of "/" with no virtual host is the service.
func (s *Server) target(host, path string) (bucket, key string) {
	if b, ok := s.hostBucket(host); ok {
		return b, strings.TrimPrefix(path, "/")
	}
	rest := strings.TrimPrefix(path, "/")
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		return rest[:i], rest[i+1:]
	}
	return rest, ""
}

func (s *Server) hostBucket(host string) (string, bool) {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(strings.Trim(host, "[]"))
	for _, d := range s.domains {
		if len(host) > len(d)+1 && strings.HasSuffix(host, "."+d) {
			return host[:len(host)-len(d)-1], true
		}
	}
	return "", false
}

// fail writes err as an S3 error response.
func (s *Server) fail(q *request, err error) {
	ae, respond, known := classify(err)
	if !known {
		s.log.Error("request failed", "id", q.id, "method", q.r.Method,
			"path", q.r.URL.Path, "err", err)
	}
	if !respond {
		return
	}
	if ae.Code == "NotImplemented" && errors.Is(err, storage.ErrNotImplemented) {
		e := *ae
		e.Message = err.Error()
		ae = &e
	}
	s.writeAPIError(q, ae)
}

func (s *Server) writeAPIError(q *request, ae *APIError) {
	if ae.Status == http.StatusNotModified {
		q.w.WriteHeader(ae.Status)
		return
	}
	s.writeXML(q, ae.Status, &errorResponse{
		Code: ae.Code, Message: ae.Message,
		BucketName: q.bucket, Key: q.key,
		Resource: q.r.URL.Path, RequestID: q.id,
		HostID: q.w.Header().Get("x-amz-id-2"),
	})
}

// writeXML renders v with the XML declaration and the given status.
func (s *Server) writeXML(q *request, status int, v any) {
	var buf bytes.Buffer
	buf.WriteString(xml.Header)
	if err := xml.NewEncoder(&buf).Encode(v); err != nil {
		s.log.Error("xml encode", "id", q.id, "err", err)
		q.w.WriteHeader(http.StatusInternalServerError)
		return
	}
	h := q.w.Header()
	h.Set("Content-Type", "application/xml")
	h.Set("Content-Length", strconv.Itoa(buf.Len()))
	q.w.WriteHeader(status)
	q.w.Write(buf.Bytes())
}

// authorize checks that the caller may perform action on bucket/key before
// the handler does any work. ctx carries condition keys such as s3:prefix.
// It returns false after writing AccessDenied.
func (s *Server) authorize(q *request, action, bucket, key string, ctx map[string]string) bool {
	if s.noAuth {
		return true
	}
	if ctx == nil {
		ctx = map[string]string{}
	}
	ctx["aws:sourceip"] = remoteIP(q.r)
	ctx["aws:securetransport"] = strconv.FormatBool(q.r.TLS != nil)
	req := iam.Request{Action: action, Bucket: bucket, Key: key, Context: ctx}
	if s.authz.Allowed(q.who, req) {
		return true
	}
	s.log.Info("access denied", "id", q.id, "user", q.who, "action", action, "resource", req.ARN())
	s.fail(q, errAccessDenied)
	return false
}

// remoteIP is the TCP peer address. X-Forwarded-For is deliberately not
// trusted: any client can set it.
func remoteIP(r *http.Request) string {
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}

// has reports whether the query string carries a (possibly valueless)
// parameter, as S3 subresources like ?acl and ?delete do.
func (q *request) has(name string) bool {
	_, ok := q.query[name]
	return ok
}

// firstOf returns the first of names present in the query, or "".
func (q *request) firstOf(names []string) string {
	for _, n := range names {
		if q.has(n) {
			return n
		}
	}
	return ""
}

// Subresources this server does not implement. A request carrying one is
// refused with NotImplemented rather than being served as a plain bucket or
// object operation, which would silently do the wrong thing (a PUT ?acl
// must not create a bucket).
var (
	bucketSubresources = []string{
		"accelerate", "acl", "analytics", "cors", "encryption", "intelligent-tiering",
		"inventory", "lifecycle", "logging", "metrics", "notification", "object-lock",
		"policy", "policyStatus", "publicAccessBlock", "replication", "requestPayment",
		"tagging", "versioning", "versions", "website", "ownershipControls",
	}
	// partNumber is listed because GET ?partNumber=N (read one part of a
	// finished object) is not implemented; PUT ?partNumber&uploadId is
	// routed to UploadPart before this check.
	objectSubresources = []string{
		"acl", "attributes", "legal-hold", "partNumber", "restore", "retention",
		"select", "tagging", "torrent",
	}
)

func (s *Server) serviceOp(q *request) {
	if q.r.Method != http.MethodGet {
		s.fail(q, errBadMethod)
		return
	}
	s.listBuckets(q)
}

func (s *Server) bucketOp(q *request) {
	m := q.r.Method
	switch {
	case m == http.MethodGet && q.has("location"):
		s.getBucketLocation(q)
		return
	case m == http.MethodPost && q.has("delete"):
		s.deleteObjects(q)
		return
	case m == http.MethodGet && q.has("uploads"):
		s.listMultipartUploads(q)
		return
	}
	if sub := q.firstOf(bucketSubresources); sub != "" {
		s.fail(q, notImplemented("bucket subresource ?"+sub))
		return
	}
	switch m {
	case http.MethodPut:
		s.createBucket(q)
	case http.MethodHead:
		s.headBucket(q)
	case http.MethodDelete:
		s.deleteBucket(q)
	case http.MethodGet:
		if q.has("list-type") {
			s.listObjectsV2(q)
		} else {
			s.listObjectsV1(q)
		}
	default:
		s.fail(q, errBadMethod)
	}
}

func (s *Server) objectOp(q *request) {
	if q.has("uploads") || q.has("uploadId") {
		s.multipartOp(q)
		return
	}
	if sub := q.firstOf(objectSubresources); sub != "" {
		s.fail(q, notImplemented("object subresource ?"+sub))
		return
	}
	switch q.r.Method {
	case http.MethodPut:
		s.putObject(q)
	case http.MethodGet:
		s.getObject(q, false)
	case http.MethodHead:
		s.getObject(q, true)
	case http.MethodDelete:
		s.deleteObject(q)
	default:
		s.fail(q, errBadMethod)
	}
}
