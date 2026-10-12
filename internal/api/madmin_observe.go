package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Trace bit values (madmin.TraceType).
const (
	traceS3       uint64 = 1 << 2
	traceInternal uint64 = 1 << 3
)

type traceBus struct {
	mu   sync.Mutex
	subs map[chan []byte]traceSub
}

type traceSub struct {
	mask      uint64
	onlyErr   bool
	threshold time.Duration
}

func (b *traceBus) subscribe(sub traceSub) (chan []byte, func()) {
	ch := make(chan []byte, 256)
	b.mu.Lock()
	if b.subs == nil {
		b.subs = map[chan []byte]traceSub{}
	}
	b.subs[ch] = sub
	b.mu.Unlock()
	return ch, func() {
		b.mu.Lock()
		delete(b.subs, ch)
		b.mu.Unlock()
	}
}

func (b *traceBus) active() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.subs) > 0
}

// publish never blocks the request path: a slow listener loses entries.
func (b *traceBus) publish(typ uint64, status int, dur time.Duration, body func() []byte) {
	b.mu.Lock()
	var targets []chan []byte
	for ch, sub := range b.subs {
		if sub.mask&typ == 0 || (sub.onlyErr && status < 400) || dur < sub.threshold {
			continue
		}
		targets = append(targets, ch)
	}
	b.mu.Unlock()
	if len(targets) == 0 {
		return
	}
	data := body()
	for _, ch := range targets {
		select {
		case ch <- data:
		default:
		}
	}
}

// redactHeaders drops what must never leave through a trace: signatures,
// session tokens and anything that carries a secret.
func redactHeaders(h http.Header) http.Header {
	out := http.Header{}
	for k, v := range h {
		switch strings.ToLower(k) {
		case "authorization", "x-amz-security-token", "cookie", "x-amz-server-side-encryption-customer-key",
			"x-amz-copy-source-server-side-encryption-customer-key", "x-minio-internal-server-side-encryption-sealed-key":
			out[k] = []string{"*REDACTED*"}
		default:
			out[k] = v
		}
	}
	return out
}

func redactQuery(raw string) string {
	if raw == "" {
		return raw
	}
	parts := strings.Split(raw, "&")
	for i, p := range parts {
		k, _, _ := strings.Cut(p, "=")
		switch k {
		case "X-Amz-Signature", "X-Amz-Credential", "X-Amz-Security-Token", "Signature", "AWSAccessKeyId":
			parts[i] = k + "=*REDACTED*"
		}
	}
	return strings.Join(parts, "&")
}

func (s *Server) publishTrace(typ uint64, fn string, r *http.Request, status int, in, out int64, start time.Time, respHdr http.Header) {
	end := time.Now()
	s.traces.publish(typ, status, end.Sub(start), func() []byte {
		host, _ := os.Hostname()
		path := r.URL.Path
		b, _ := json.Marshal(map[string]any{
			"type": typ, "nodename": host, "funcname": fn, "time": start.UTC(), "path": path,
			"dur": end.Sub(start).Nanoseconds(), "bytes": out,
			"http": map[string]any{
				"request": map[string]any{"time": start.UTC(), "proto": r.Proto, "method": r.Method, "path": path,
					"rawquery": redactQuery(r.URL.RawQuery), "headers": redactHeaders(r.Header), "client": r.RemoteAddr},
				"response": map[string]any{"time": end.UTC(), "headers": redactHeaders(respHdr), "statuscode": status},
				"stats":    map[string]any{"inputbytes": in, "outputbytes": out, "latency": end.Sub(start).Nanoseconds()},
			},
		})
		return append(b, '\n')
	})
}

// ----- console log ring ---------------------------------------------------------------------------

const logRingSize = 512

type logRing struct {
	mu   sync.Mutex
	buf  [][]byte
	next int
	full bool
	subs map[chan []byte]struct{}
}

func (l *logRing) add(entry []byte) {
	l.mu.Lock()
	if l.buf == nil {
		l.buf = make([][]byte, logRingSize)
	}
	l.buf[l.next] = entry
	l.next = (l.next + 1) % logRingSize
	if l.next == 0 {
		l.full = true
	}
	for ch := range l.subs {
		select {
		case ch <- entry:
		default:
		}
	}
	l.mu.Unlock()
}

// last returns up to n recent entries, oldest first.
func (l *logRing) last(n int) [][]byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	var all [][]byte
	if l.full {
		all = append(all, l.buf[l.next:]...)
	}
	all = append(all, l.buf[:l.next]...)
	if n > 0 && len(all) > n {
		all = all[len(all)-n:]
	}
	return all
}

func (l *logRing) subscribe() (chan []byte, func()) {
	ch := make(chan []byte, 128)
	l.mu.Lock()
	if l.subs == nil {
		l.subs = map[chan []byte]struct{}{}
	}
	l.subs[ch] = struct{}{}
	l.mu.Unlock()
	return ch, func() {
		l.mu.Lock()
		delete(l.subs, ch)
		l.mu.Unlock()
	}
}

// ringHandler feeds records of level Info and above (the console log)
// into the ring and passes everything on to the real handler.
type ringHandler struct {
	inner slog.Handler
	ring  *logRing
	node  string
	attrs []slog.Attr
}

func (h *ringHandler) Enabled(ctx context.Context, l slog.Level) bool { return h.inner.Enabled(ctx, l) }

func (h *ringHandler) Handle(ctx context.Context, r slog.Record) error {
	if r.Level >= slog.LevelInfo {
		kind := "INFO"
		switch {
		case r.Level >= slog.LevelError:
			kind = "ERROR"
		case r.Level >= slog.LevelWarn:
			kind = "WARNING"
		}
		fields := map[string]any{}
		for _, a := range h.attrs {
			fields[a.Key] = a.Value.String()
		}
		r.Attrs(func(a slog.Attr) bool {
			fields[a.Key] = a.Value.String()
			return true
		})
		e := map[string]any{"level": kind, "errKind": kind, "time": r.Time.UTC(), "message": r.Message, "node": h.node,
			"ConsoleMsg": r.Message, "trace": map[string]any{"message": r.Message, "variables": fields}}
		if b, err := json.Marshal(e); err == nil {
			h.ring.add(append(b, '\n'))
		}
	}
	return h.inner.Handle(ctx, r)
}

func (h *ringHandler) WithAttrs(a []slog.Attr) slog.Handler {
	return &ringHandler{inner: h.inner.WithAttrs(a), ring: h.ring, node: h.node, attrs: append(append([]slog.Attr(nil), h.attrs...), a...)}
}

func (h *ringHandler) WithGroup(n string) slog.Handler {
	return &ringHandler{inner: h.inner.WithGroup(n), ring: h.ring, node: h.node, attrs: h.attrs}
}

func init() {
	r := madminRegister
	r("trace", "GET", "admin:ServerTrace", (*Server).madminTrace)
	r("log", "GET", "admin:ConsoleLog", (*Server).madminLog)
	r("top/locks", "GET", "admin:TopLocksInfo", (*Server).madminTopLocks)
	r("service", "POST", "admin:ServiceRestart", (*Server).madminService)
	r("speedtest", "POST", "admin:BandwidthMonitor", (*Server).madminNotSupported)
}

func (s *Server) madminNotSupported(q *request) {
	s.madminFail(q, http.StatusNotImplemented, "XMinioAdminNotImplemented", "this admin operation is not supported by NanoIO")
}

func (s *Server) streamLines(q *request, ch chan []byte, first [][]byte) {
	fl, _ := q.w.(http.Flusher)
	h := q.w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("X-Accel-Buffering", "no")
	q.w.WriteHeader(http.StatusOK)
	for _, e := range first {
		q.w.Write(e)
	}
	if fl != nil {
		fl.Flush()
	}
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-q.r.Context().Done():
			return
		case e := <-ch:
			if _, err := q.w.Write(e); err != nil {
				return
			}
		case <-tick.C:
			// A blank line keeps idle connections open; JSON decoders skip it.
			if _, err := q.w.Write([]byte("\n")); err != nil {
				return
			}
		}
		if fl != nil {
			fl.Flush()
		}
	}
}

func (s *Server) madminTrace(q *request) {
	sub := traceSub{onlyErr: q.query.Get("err") == "true"}
	if q.query.Get("s3") == "true" {
		sub.mask |= traceS3
	}
	if q.query.Get("internal") == "true" {
		sub.mask |= traceInternal
	}
	if th := q.query.Get("threshold"); th != "" {
		d, err := time.ParseDuration(th)
		if err != nil {
			s.madminErr(q, madminBad("invalid threshold"))
			return
		}
		sub.threshold = d
	}
	ch, cancel := s.traces.subscribe(sub)
	defer cancel()
	s.streamLines(q, ch, nil)
}

func (s *Server) madminLog(q *request) {
	limit := 10
	if v := q.query.Get("limit"); v != "" {
		var n int
		if _, err := fmt.Sscan(v, &n); err == nil && n > 0 {
			limit = n
		}
	}
	ch, cancel := s.logs.subscribe()
	defer cancel()
	s.streamLines(q, ch, s.logs.last(limit))
}

func (s *Server) madminTopLocks(q *request) {
	// Lock state lives in the distributed lock manager and is not exposed.
	s.writeJSONOK(q, []any{})
}

func (s *Server) madminService(q *request) {
	switch q.query.Get("action") {
	case "restart", "stop", "freeze", "unfreeze", "cancel-restart":
		s.madminFail(q, http.StatusNotImplemented, "XMinioAdminNotImplemented",
			"NanoIO does not restart or stop itself through the API; use the process manager that runs it")
	default:
		s.madminFail(q, http.StatusBadRequest, "XMinioAdminInvalidArgument", "unknown service action")
	}
}
