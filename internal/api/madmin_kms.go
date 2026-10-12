package api

import (
	"bytes"
	"net/http"
	"runtime"
	"time"

	"nanoio/internal/kms"
)

// serveKMS handles /minio/kms/v1/<op>. NanoIO's KMS abstraction can wrap
// and unwrap keys and describe one; it cannot enumerate, create or delete
// keys or manage KES-style policies, so those operations say so.
func (s *Server) serveKMS(q *request, op string) {
	var action, method string
	switch op {
	case "status":
		action, method = "kms:Status", http.MethodGet
	case "version":
		action, method = "kms:Version", http.MethodGet
	case "apis":
		action, method = "kms:API", http.MethodGet
	case "metrics":
		action, method = "kms:Metrics", http.MethodGet
	case "key/status":
		action, method = "kms:KeyStatus", http.MethodGet
	case "key/list":
		action, method = "kms:ListKeys", http.MethodGet
	default:
		s.madminFail(q, http.StatusNotImplemented, "XMinioAdminNotImplemented",
			"the KMS operation "+op+" is not supported: NanoIO's KMS interface cannot create, delete, import or manage keys and policies")
		return
	}
	if q.r.Method != method {
		s.madminFail(q, http.StatusMethodNotAllowed, "XMinioAdminMethodNotAllowed", "method not allowed")
		return
	}
	if !s.madminAllowed(q, action) {
		s.madminFail(q, http.StatusForbidden, "XMinioAdminAccessDenied", "Access Denied.")
		return
	}
	if s.kms == nil {
		s.madminFail(q, http.StatusNotImplemented, "XMinioKMSNotConfigured", "no KMS is configured on this server")
		return
	}
	switch op {
	case "version":
		s.writeJSONOK(q, map[string]string{"version": "nanoio"})
	case "apis":
		s.writeJSONOK(q, []map[string]any{
			{"Method": "GET", "Path": "/v1/status", "MaxBody": 0, "Timeout": 15},
			{"Method": "GET", "Path": "/v1/key/status", "MaxBody": 0, "Timeout": 15},
			{"Method": "GET", "Path": "/v1/key/list", "MaxBody": 0, "Timeout": 15}})
	case "metrics":
		s.writeJSONOK(q, map[string]any{})
	case "status":
		start := time.Now()
		_, err := s.kms.DescribeKey(q.ctx(), s.defaultKey)
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		state := "online"
		if err != nil {
			state = "offline"
		}
		s.writeJSONOK(q, map[string]any{
			"name": "NanoIO KMS", "default-key-id": s.defaultKey,
			"endpoints": map[string]string{"local": state},
			"state": map[string]any{"Version": "nanoio", "KeyStoreLatency": time.Since(start).Nanoseconds(),
				"KeyStoreReachable": err == nil, "KeystoreAvailable": err == nil, "OS": runtime.GOOS, "Arch": runtime.GOARCH,
				"UpTime": time.Since(processStart).Nanoseconds(), "CPUs": runtime.NumCPU(), "UsableCPUs": runtime.GOMAXPROCS(0),
				"HeapAlloc": ms.HeapAlloc, "StackAlloc": ms.StackInuse},
		})
	case "key/list":
		info, err := s.kms.DescribeKey(q.ctx(), s.defaultKey)
		out := []map[string]any{}
		if err == nil {
			out = append(out, map[string]any{"name": info.ID, "createdAt": info.Created, "createdBy": "nanoio"})
		}
		s.writeJSONOK(q, out)
	case "key/status":
		id := q.query.Get("key-id")
		if id == "" {
			id = s.defaultKey
		}
		st := map[string]string{"key-id": id}
		kctx := kms.Context{"purpose": "admin-key-status"}
		dk, err := s.kms.GenerateKey(q.ctx(), id, kctx)
		if err != nil {
			st["encryption-error"] = err.Error()
		} else {
			pt, err := s.kms.Decrypt(q.ctx(), id, dk.Ciphertext, kctx)
			if err != nil {
				st["decryption-error"] = err.Error()
			} else if !bytes.Equal(pt, dk.Plaintext) {
				st["decryption-error"] = "decrypted key differs from the generated key"
			}
			kms.Zero(pt)
			kms.Zero(dk.Plaintext)
		}
		s.writeJSONOK(q, st)
	}
}
