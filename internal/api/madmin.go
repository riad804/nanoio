package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"runtime"
	"strings"
	"time"

	"nanoio/internal/auth"
	"nanoio/internal/madmincrypt"
	"nanoio/internal/storage"
)

// The MinIO-compatible admin API: /minio/admin/v3/<operation>, the
// /minio/health/* probes and /minio/kms/v1/*. It is a second front for the
// same functionality as /_nanoio/admin, shaped so that MinIO's own clients
// (`mc admin ...`, madmin-go) work against NanoIO unchanged.
//
// Every admin request must be SigV4-signed; the authenticated identity then
// needs the admin:<Action> policy permission (the root credential has them
// all). Request and response bodies that carry secrets are encrypted with a
// key derived from the caller's own secret key (internal/madmincrypt).
// Nothing under /minio/admin or /minio/kms is reachable anonymously; only
// the health probes are, as in MinIO, and they reveal nothing but liveness.

const (
	madminPrefix  = "/minio/admin/v3/"
	madminHealth  = "/minio/health/"
	madminKMS     = "/minio/kms/v1/"
	madminMaxBody = 8 << 20
)

// madminHandler serves one operation. The request is authenticated and
// authorised against the route's action before it runs.
type madminHandler func(s *Server, q *request)

type madminRoute struct {
	methods string // allowed methods, space separated
	action  string // admin:<Action>
	h       madminHandler
}

var madminRoutes = map[string]madminRoute{}

func madminRegister(path, methods, action string, h madminHandler) {
	madminRoutes[path] = madminRoute{methods: methods, action: action, h: h}
}

// isMadmin reports whether a request path belongs to the MinIO-compatible
// admin namespaces.
func isMadmin(p string) bool {
	return strings.HasPrefix(p, madminPrefix) || strings.HasPrefix(p, madminHealth) || strings.HasPrefix(p, madminKMS)
}

// madminError is the JSON error body MinIO's admin API returns (and its
// clients decode).
type madminErrorBody struct {
	Code       string `json:"Code"`
	Message    string `json:"Message"`
	Resource   string `json:"Resource,omitempty"`
	RequestID  string `json:"RequestID,omitempty"`
	HostID     string `json:"HostID,omitempty"`
	Region     string `json:"Region,omitempty"`
	BucketName string `json:"BucketName,omitempty"`
}

func (s *Server) madminFail(q *request, status int, code, msg string) {
	h := q.w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Content-Security-Policy", "block-all-mixed-content")
	q.w.WriteHeader(status)
	json.NewEncoder(q.w).Encode(madminErrorBody{Code: code, Message: msg, Resource: q.r.URL.Path, RequestID: q.id})
}

// madminErr converts an internal error to an admin error response.
func (s *Server) madminErr(q *request, err error) {
	switch {
	case errors.Is(err, errMadminBadRequest):
		s.madminFail(q, http.StatusBadRequest, "XMinioAdminInvalidRequest", err.Error())
	case errors.Is(err, storage.ErrBucketNotFound):
		s.madminFail(q, http.StatusNotFound, "NoSuchBucket", "The specified bucket does not exist")
	case errors.Is(err, storage.ErrBackendUnavailable), errors.Is(err, storage.ErrLockTimeout):
		s.madminFail(q, http.StatusServiceUnavailable, "XMinioServerNotInitialized", "The server is not ready")
	default:
		s.log.Error("admin request failed", "id", q.id, "path", q.r.URL.Path, "err", err)
		s.madminFail(q, http.StatusInternalServerError, "XMinioAdminInternalError", "internal error")
	}
}

var errMadminBadRequest = errors.New("bad request")

func madminBad(msg string) error { return errors.Join(errMadminBadRequest, errors.New(msg)) }

// serveMadmin routes and authenticates an admin-namespace request.
func (s *Server) serveMadmin(w http.ResponseWriter, r *http.Request) {
	sw := &statusWriter{ResponseWriter: w}
	q := &request{w: sw, r: r, id: newRequestID(), query: r.URL.Query()}
	h := sw.Header()
	h.Set("Server", "NanoIO")
	h.Set("x-amz-request-id", q.id)
	h.Set("Vary", "Origin")
	defer func() {
		if rec := recover(); rec != nil {
			if rec == http.ErrAbortHandler {
				panic(rec)
			}
			s.log.Error("panic serving admin request", "path", r.URL.Path, "panic", rec)
			if sw.status == 0 {
				s.madminFail(q, http.StatusInternalServerError, "XMinioAdminInternalError", "internal error")
			}
		}
	}()
	start := time.Now()
	defer func() {
		if s.traces.active() && !strings.HasPrefix(r.URL.Path, madminHealth) {
			s.publishTrace(traceInternal, "admin."+r.Method, r, sw.status, r.ContentLength, sw.bytes, start, sw.Header())
		}
	}()
	p := r.URL.Path
	switch {
	case strings.HasPrefix(p, madminHealth):
		s.serveHealth(q, strings.TrimPrefix(p, madminHealth))
		return
	case s.noAuth:
		s.madminFail(q, http.StatusForbidden, "XMinioAdminAccessDenied",
			"The admin API requires authentication; this server runs with authentication disabled")
		return
	}
	res, err := s.authn.Authenticate(r)
	switch {
	case errors.Is(err, auth.ErrAnonymous):
		s.madminFail(q, http.StatusForbidden, "XMinioAdminAccessDenied", "Access Denied.")
		return
	case err != nil:
		ae, _, _ := classify(err)
		s.madminFail(q, ae.Status, ae.Code, ae.Message)
		return
	}
	if err := s.sessionOK(r, res.AccessKey); err != nil {
		ae, _, _ := classify(err)
		s.madminFail(q, ae.Status, ae.Code, ae.Message)
		return
	}
	q.who, q.res = res.AccessKey, res
	if strings.HasPrefix(p, madminKMS) {
		s.serveKMS(q, strings.TrimPrefix(p, madminKMS))
		return
	}
	op := strings.TrimPrefix(p, madminPrefix)
	rt, ok := madminRoutes[op]
	if !ok {
		// Operations with a variable tail (heal/<bucket>/<prefix>, ...).
		for prefix, route := range madminRoutes {
			if strings.HasSuffix(prefix, "/") && strings.HasPrefix(op, prefix) {
				rt, ok = route, true
				break
			}
		}
	}
	if !ok {
		s.madminFail(q, http.StatusNotFound, "XMinioAdminNotImplemented", "This admin operation is not implemented by NanoIO: "+op)
		return
	}
	if !strings.Contains(" "+rt.methods+" ", " "+r.Method+" ") {
		s.madminFail(q, http.StatusMethodNotAllowed, "XMinioAdminMethodNotAllowed", "method not allowed")
		return
	}
	if !s.madminAllowed(q, rt.action) {
		s.log.Info("admin access denied", "id", q.id, "user", q.who, "action", rt.action)
		s.madminFail(q, http.StatusForbidden, "XMinioAdminAccessDenied", "Access Denied.")
		return
	}
	rt.h(s, q)
}

// madminAllowed checks an admin:<Action> permission.
func (s *Server) madminAllowed(q *request, action string) bool {
	if s.iam != nil && s.iam.IsRoot(q.who) {
		return true
	}
	if q.who == "" {
		return false
	}
	return s.authz.Allowed(q.who, iamRequest(action))
}

// callerSecret is the authenticated caller's secret key, the password of
// the envelope its sensitive bodies are in.
func (s *Server) callerSecret(q *request) (string, bool) {
	if s.iam == nil {
		return "", false
	}
	return s.iam.SecretKey(q.who)
}

// readEncrypted reads and decrypts a request body.
func (s *Server) readEncrypted(q *request) ([]byte, error) {
	sk, ok := s.callerSecret(q)
	if !ok {
		return nil, madminBad("cannot determine the caller's secret key")
	}
	body, err := io.ReadAll(io.LimitReader(q.r.Body, madminMaxBody+1))
	if err != nil {
		return nil, err
	}
	if len(body) > madminMaxBody {
		return nil, madminBad("request body too large")
	}
	pt, err := madmincrypt.Decrypt(sk, bytes.NewReader(body))
	if err != nil {
		return nil, madminBad("the request body could not be decrypted with the caller's secret key")
	}
	return pt, nil
}

// readJSONBody reads a plain JSON request body.
func (s *Server) readJSONBody(q *request, v any) error {
	body, err := io.ReadAll(io.LimitReader(q.r.Body, madminMaxBody+1))
	if err != nil {
		return err
	}
	if len(body) > madminMaxBody {
		return madminBad("request body too large")
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	if err := json.Unmarshal(body, v); err != nil {
		return madminBad("invalid JSON body: " + err.Error())
	}
	return nil
}

// writeEncrypted marshals v and sends it in the caller's envelope.
func (s *Server) writeEncrypted(q *request, v any) {
	sk, ok := s.callerSecret(q)
	if !ok {
		s.madminFail(q, http.StatusInternalServerError, "XMinioAdminInternalError", "cannot determine the caller's secret key")
		return
	}
	data, err := json.Marshal(v)
	if err != nil {
		s.madminErr(q, err)
		return
	}
	s.writeEncryptedRaw(q, sk, data)
}

// writeEncryptedRaw sends data in the caller's envelope.
func (s *Server) writeEncryptedRaw(q *request, sk string, data []byte) {
	enc, err := madmincrypt.Encrypt(sk, data)
	if err != nil {
		s.madminErr(q, err)
		return
	}
	h := q.w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Length", itoa(len(enc)))
	q.w.WriteHeader(http.StatusOK)
	q.w.Write(enc)
}

func (s *Server) writeJSONOK(q *request, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		s.madminErr(q, err)
		return
	}
	h := q.w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Content-Length", itoa(len(data)))
	q.w.WriteHeader(http.StatusOK)
	q.w.Write(data)
}

func (s *Server) madminOK(q *request) { q.w.WriteHeader(http.StatusOK) }

func itoa(n int) string {
	var b [20]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
		if n == 0 {
			break
		}
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// ----- health ----------------------------------------------------------------------------------

// serveHealth answers the unauthenticated probes. They disclose liveness
// and quorum health only.
func (s *Server) serveHealth(q *request, which string) {
	w := q.w
	set := func(k, v string) { w.Header().Set(k, v) }
	set("Server", "NanoIO")
	set("Cache-Control", "no-store")
	switch which {
	case "live", "liveness":
		w.WriteHeader(http.StatusOK)
	case "ready", "readiness":
		ctx, cancel := context.WithTimeout(q.r.Context(), 5*time.Second)
		defer cancel()
		if _, err := s.st.Info(ctx); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	case "cluster", "cluster/read":
		ctx, cancel := context.WithTimeout(q.r.Context(), 5*time.Second)
		defer cancel()
		info, err := s.st.Info(ctx)
		set("X-Minio-Write-Quorum", "1")
		set("X-Minio-Healing", "false")
		if err != nil || !info.Healthy {
			set("X-Minio-Server-Status", "offline")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func goVersion() string { return runtime.Version() }

func readAllLimited(q *request, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(q.r.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, madminBad("request body too large")
	}
	return b, nil
}
