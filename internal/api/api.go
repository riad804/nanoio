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
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"nanoio/internal/auth"
	"nanoio/internal/batch"
	"nanoio/internal/event"
	"nanoio/internal/iam"
	"nanoio/internal/kms"
	"nanoio/internal/lifecycle"
	"nanoio/internal/storage"
	"nanoio/internal/tier"
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

// Decider is an Authorizer that reports its decision in parts, so the API
// can combine it with a bucket's resource policy: explicit Deny anywhere
// wins, then an Allow from either, otherwise deny. root marks the
// credential no policy can restrict. *iam.Store implements it; an
// Authorizer that does not is treated as having no explicit Deny.
type Decider interface {
	Decide(accessKey string, req iam.Request) (allow, deny, root bool)
}

// Options configures New.
type Options struct {
	// STSAuth verifies signed STS requests (signed for service "sts"). Nil
	// means Auth is used.
	STSAuth Authenticator
	// Maintenance backs heal, scan and pool administration (optional; the
	// operations report themselves unavailable without it).
	Maintenance Maintainer
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

	// KMS enables SSE-S3 and SSE-KMS (and bucket default encryption). Nil
	// means those modes answer 501; SSE-C needs no KMS.
	KMS kms.KMS
	// DefaultKMSKey is the key SSE-S3 uses and SSE-KMS defaults to. Required
	// when KMS is set.
	DefaultKMSKey string
	// AllowInsecureSSEC accepts SSE-C keys over a connection that is not
	// TLS. Off by default; for development and for deployments where a
	// trusted proxy terminates TLS.
	AllowInsecureSSEC bool

	// Events receives bucket events and delivers them to notification
	// targets. New starts it (it must not be started already) and the
	// caller closes it after the server has stopped. Nil disables
	// notifications: no events are produced and only an empty notification
	// configuration is accepted.
	Events *event.Manager
	// EventLocker, with Events, replicates the notification queues in the
	// backend: queued events are written to the system bucket (quorum,
	// erasure-coded) and delivered by whichever node holds the cluster
	// lock for the target. Set it in cluster mode only. EventNodeID names
	// this node in the stored objects and must be unique in the cluster.
	EventLocker storage.Locker
	EventNodeID string

	// Lifecycle, when set, runs the lifecycle scanner in the background.
	Lifecycle *LifecycleOptions
	// Tier configures transitions to remote tiers (all optional).
	Tier *TierOptions
	// Batch, when set, runs the batch-job runner on this node.
	Batch *BatchOptions
	// Replication, when set, runs bucket replication on this node.
	Replication *ReplicationOptions
	// IAM, when set (it must be the store Authz uses), enables runtime
	// users, groups and policies through the admin API, kept in the system
	// bucket on top of the store's static file.
	IAM *iam.Store
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

	kms               kms.KMS
	defaultKey        string
	allowInsecureSSEC bool
	conf              confCache
	events            *event.Manager
	lc                *lifecycle.Scanner
	stop              []context.CancelFunc
	bg                sync.WaitGroup
	tiers             *tier.Manager
	tcache            *tier.Cache
	tierTTL           time.Duration
	janitor           *tier.Janitor
	batch             *batch.Manager
	nodeID            string
	iam               *iam.Store
	iamrt             *iamRuntime
	repl              *replEngine
	site              *siteRuntime
	siteLocker        storage.Locker
	clusterIDv        atomic.Pointer[string]
	maint             Maintainer
	stsAuth           Authenticator
	idp               idpState
	idpMu             sync.Mutex
	logins            loginLimiter
	traces            traceBus
	logs              logRing
	healJobs          healJobs
	decom             decomState
	cfgOnce           sync.Once
	cfgrt             *configRuntime
}

// New validates opts and returns the handler.
func New(opts Options) (*Server, error) {
	if opts.Storage == nil {
		return nil, errors.New("api: Options.Storage is required")
	}
	s := &Server{st: opts.Storage, region: opts.Region, log: opts.Logger,
		authn: opts.Auth, authz: opts.Authz, noAuth: opts.InsecureNoAuth, internal: opts.Internal,
		kms: opts.KMS, defaultKey: opts.DefaultKMSKey, allowInsecureSSEC: opts.AllowInsecureSSEC,
		events: opts.Events, maint: opts.Maintenance, stsAuth: opts.STSAuth}
	if s.kms != nil && s.defaultKey == "" {
		return nil, errors.New("api: Options.DefaultKMSKey is required with Options.KMS")
	}
	if !s.noAuth && (s.authn == nil || s.authz == nil) {
		return nil, errors.New("api: Options.Auth and Options.Authz are required (set InsecureNoAuth to disable authentication explicitly)")
	}
	if s.region == "" {
		s.region = "us-east-1"
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	host, _ := os.Hostname()
	s.log = slog.New(&ringHandler{inner: s.log.Handler(), ring: &s.logs, node: host})
	for _, d := range opts.Domains {
		d = strings.ToLower(strings.Trim(strings.TrimSpace(d), "."))
		if d == "" || strings.ContainsAny(d, "/: ") {
			return nil, errors.New("api: invalid domain " + strconv.Quote(d))
		}
		s.domains = append(s.domains, d)
	}
	if err := s.initTiers(opts.Tier); err != nil {
		return nil, err
	}
	if s.events != nil {
		if opts.EventLocker != nil {
			if opts.EventNodeID == "" {
				return nil, errors.New("api: Options.EventNodeID is required with Options.EventLocker")
			}
			s.events.SetShared(&eventStore{st: s.st, locker: opts.EventLocker}, opts.EventNodeID)
		}
		s.events.Start(s.notifyConfig)
	}
	s.nodeID = opts.EventNodeID
	s.initIAM(opts.IAM)
	if opts.Lifecycle != nil {
		if err := s.startLifecycle(opts.Lifecycle); err != nil {
			return nil, err
		}
	}
	if opts.Replication != nil {
		if err := s.startReplication(opts.Replication); err != nil {
			return nil, err
		}
		s.siteLocker = opts.Replication.Locker
		s.initSite(opts.Replication)
	}
	if opts.Batch != nil {
		if err := s.startBatch(opts.Batch); err != nil {
			return nil, err
		}
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
	// anon is set for a request that carried no credentials.
	anon bool
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
	if adminRoutes[strings.TrimPrefix(r.URL.Path, InternalPrefix)] {
		s.serveAdmin(w, r)
		return
	}
	if isMadmin(r.URL.Path) {
		if _, vhost := s.hostBucket(r.Host); !vhost {
			s.serveMadmin(w, r)
			return
		}
	}
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
		if s.traces.active() {
			s.publishTrace(traceS3, "s3."+r.Method, r, sw.status, r.ContentLength, sw.bytes, start, sw.Header())
		}
	}()

	if isSTSRequest(r) {
		if _, vhost := s.hostBucket(r.Host); !vhost {
			s.serveSTS(sw, r)
			return
		}
	}
	q.bucket, q.key = s.target(r.Host, r.URL.Path)
	if q.bucket != sysBucket {
		if isPreflight(r) {
			s.preflight(q)
			return
		}
		s.applyCORS(q)
	}
	if !s.noAuth {
		res, err := s.authn.Authenticate(r)
		switch {
		case errors.Is(err, auth.ErrAnonymous):
			// No credentials at all: the request is anonymous and may be
			// served only if the bucket's policy allows it. A request that
			// carries credentials which fail is never downgraded to this.
			q.anon = true
		case err != nil:
			s.fail(q, err)
			return
		default:
			if err := s.sessionOK(r, res.AccessKey); err != nil {
				s.fail(q, err)
				return
			}
			q.who, q.res = res.AccessKey, res
		}
	}
	if q.bucket == sysBucket {
		// NanoIO's own configuration bucket is not part of the S3 namespace.
		if q.key == "" && r.Method == http.MethodPut {
			s.fail(q, storage.ErrInvalidBucketName)
		} else {
			s.fail(q, storage.ErrBucketNotFound)
		}
		return
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

// adminRoutes are the paths (under InternalPrefix) this server answers
// itself; any other path in the namespace belongs to the internal handler.
var adminRoutes = map[string]bool{
	"admin/rewrap": true, "admin/events": true,
	"admin/notify/targets": true, "admin/notify/dead": true, "admin/notify/requeue": true,
	"admin/tier": true, "admin/tier/check": true,
	"admin/batch/start": true, "admin/batch/list": true, "admin/batch/describe": true,
	"admin/batch/cancel": true, "admin/batch/template": true,
	"admin/iam/user": true, "admin/iam/group": true, "admin/iam/policy": true,
	"admin/replication/target": true, "admin/replication/metrics": true, "admin/replication/resync": true,
	"admin/site/info": true, "admin/site/add": true, "admin/site/issue": true, "admin/site/peer": true,
	"admin/site/remove": true, "admin/site/status": true, "admin/site/apply": true, "admin/site/state": true,
	"admin/site/resync": true,
}

// serveAdmin authenticates an admin request with the ordinary S3
// credentials, then dispatches it.
func (s *Server) serveAdmin(w http.ResponseWriter, r *http.Request) {
	sw := &statusWriter{ResponseWriter: w}
	q := &request{w: sw, r: r, id: newRequestID(), query: r.URL.Query()}
	sw.Header().Set("Server", "NanoIO")
	sw.Header().Set("x-amz-request-id", q.id)
	if !s.noAuth {
		res, err := s.authn.Authenticate(r)
		if err == nil {
			err = s.sessionOK(r, res.AccessKey)
		}
		if err != nil {
			s.fail(q, err)
			return
		}
		q.who, q.res = res.AccessKey, res
	}
	switch strings.TrimPrefix(r.URL.Path, InternalPrefix+"admin/") {
	case "rewrap":
		s.adminRewrap(sw, r, q)
	case "events":
		s.adminEvents(q)
	case "notify/targets":
		s.adminNotifyTargets(q)
	case "notify/dead":
		s.adminNotifyDead(q)
	case "notify/requeue":
		s.adminNotifyRequeue(q)
	case "tier":
		s.adminTier(q)
	case "tier/check":
		s.adminTierCheck(q)
	case "site/info", "site/add", "site/issue", "site/peer", "site/remove", "site/status", "site/apply", "site/state", "site/resync":
		s.adminSite(q, strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, InternalPrefix), "admin/site/"))
	case "replication/target":
		s.adminReplTarget(q)
	case "replication/metrics":
		s.adminReplMetrics(q)
	case "replication/resync":
		s.adminReplResync(q)
	case "iam/user":
		s.adminIAM(q, "user")
	case "iam/group":
		s.adminIAM(q, "group")
	case "iam/policy":
		s.adminIAM(q, "policy")
	case "batch/start", "batch/list", "batch/describe", "batch/cancel", "batch/template":
		s.adminBatch(q, strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, InternalPrefix), "admin/batch/"))
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
	var dm *storage.DeleteMarkerError
	if errors.As(err, &dm) {
		// S3 identifies the marker that answered the request.
		h := q.w.Header()
		h.Set("x-amz-delete-marker", "true")
		if dm.VersionID != "" {
			h.Set("x-amz-version-id", dm.VersionID)
		}
		if dm.Explicit {
			h.Set("Last-Modified", dm.ModTime.UTC().Format(http.TimeFormat))
		}
	}
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
		"accelerate", "analytics", "intelligent-tiering",
		"inventory", "logging", "metrics",
		"policyStatus", "publicAccessBlock", "requestPayment",
		"website", "ownershipControls",
	}
	// partNumber is listed because GET ?partNumber=N (read one part of a
	// finished object) is not implemented; PUT ?partNumber&uploadId is
	// routed to UploadPart before this check.
	objectSubresources = []string{
		"attributes", "partNumber",
		"select", "torrent",
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
	case m == http.MethodGet && q.has("versions"):
		s.listObjectVersions(q)
		return
	case q.has("object-lock"):
		switch m {
		case http.MethodPut:
			s.putObjectLockConfiguration(q)
		case http.MethodGet:
			s.getObjectLockConfiguration(q)
		default:
			s.fail(q, errBadMethod)
		}
		return
	case q.has("encryption"):
		s.bucketEncryptionOp(q)
		return
	case q.has("policy"):
		s.bucketPolicyOp(q)
		return
	case q.has("acl"):
		s.bucketACLOp(q)
		return
	case q.has("cors"):
		s.bucketCORSOp(q)
		return
	case q.has("tagging"):
		s.bucketTaggingOp(q)
		return
	case q.has("notification"):
		s.bucketNotificationOp(q)
		return
	case q.has("lifecycle"):
		s.bucketLifecycleOp(q)
		return
	case q.has("replication"):
		s.bucketReplicationOp(q)
		return
	case q.has("versioning"):
		switch m {
		case http.MethodPut:
			s.putBucketVersioning(q)
		case http.MethodGet:
			s.getBucketVersioning(q)
		default:
			s.fail(q, errBadMethod)
		}
		return
	}
	if sub := q.firstOf(bucketSubresources); sub != "" {
		if q.anon {
			s.fail(q, errAccessDenied) // nothing anonymous reaches a feature that has no policy action
			return
		}
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
	if q.has("acl") {
		s.objectACLOp(q)
		return
	}
	if q.has("tagging") {
		s.objectTaggingOp(q)
		return
	}
	if sub := q.firstOf([]string{"retention", "legal-hold"}); sub != "" {
		s.objectLockOp(q, sub)
		return
	}
	if q.has("restore") {
		s.restoreObject(q)
		return
	}
	if sub := q.firstOf(objectSubresources); sub != "" {
		if q.anon {
			s.fail(q, errAccessDenied)
			return
		}
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
