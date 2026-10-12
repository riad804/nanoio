package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"nanoio/internal/event"
)

// streamFrame is one event on the admin stream: the S3 notification payload
// plus the node's sequence number, which a consumer passes back as ?since=
// to resume.
type streamFrame struct {
	Seq uint64 `json:"seq"`
	event.Payload
}

type droppedFrame struct {
	Type  string `json:"type"`
	Count uint64 `json:"count"`
}

// eventFilter builds the stream filter from the query: bucket, prefix,
// suffix and events (repeatable, comma separated; wildcards such as
// s3:ObjectCreated:* allowed).
func eventFilter(q *request) (func(*event.Event) bool, *APIError) {
	bucket, prefix, suffix := q.query.Get("bucket"), q.query.Get("prefix"), q.query.Get("suffix")
	var names []string
	for _, v := range q.query["events"] {
		for _, n := range strings.Split(v, ",") {
			if n = strings.TrimSpace(n); n != "" {
				if !event.ValidName(n) {
					return nil, invalidArgument("Unknown event name " + strconv.Quote(n))
				}
				names = append(names, n)
			}
		}
	}
	return func(e *event.Event) bool {
		if bucket != "" && e.Bucket != bucket {
			return false
		}
		if !strings.HasPrefix(e.Key, prefix) || !strings.HasSuffix(e.Key, suffix) {
			return false
		}
		if len(names) == 0 {
			return true
		}
		for _, n := range names {
			if event.NameMatches(n, e.Name) {
				return true
			}
		}
		return false
	}, nil
}

// adminEvents serves GET /_nanoio/admin/events: a live stream of bucket
// events, the equivalent of `mc admin trace` for object activity. It is a
// WebSocket when the client asks for an upgrade, otherwise newline-delimited
// JSON over a chunked response. With ?since=N the retained history after
// sequence N is sent first (since=0 for all of it).
func (s *Server) adminEvents(q *request) {
	if q.r.Method != http.MethodGet {
		s.fail(q, errBadMethod)
		return
	}
	if !s.authorize(q, "nanoio:ListenEvents", "", "", nil) {
		return
	}
	if s.events == nil {
		s.fail(q, notImplemented("event notifications are not enabled"))
		return
	}
	filter, aerr := eventFilter(q)
	if aerr != nil {
		s.fail(q, aerr)
		return
	}
	opts := event.StreamOptions{Filter: filter}
	if q.has("since") {
		n, err := strconv.ParseUint(q.query.Get("since"), 10, 64)
		if err != nil {
			s.fail(q, invalidArgument("since must be a sequence number"))
			return
		}
		if !s.events.ReplayEnabled() {
			s.fail(q, invalidRequest("The replay log is disabled on this server; remove the since parameter."))
			return
		}
		opts.Since, opts.Replay = n, true
	}

	ctx, cancel := context.WithCancel(q.r.Context())
	defer cancel()
	var write func([]byte) error
	if isWebSocket(q.r) {
		ws, err := wsAccept(q.w, q.r)
		if err != nil {
			s.fail(q, invalidRequest("Malformed WebSocket handshake."))
			return
		}
		defer ws.Close()
		go func() {
			ws.readLoop()
			cancel()
		}()
		go func() { // keep idle streams alive through proxies, detect dead peers
			t := time.NewTicker(30 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					if ws.writeFrame(wsPing, nil) != nil {
						cancel()
						return
					}
				}
			}
		}()
		write = ws.WriteText
	} else {
		rc := http.NewResponseController(q.w)
		h := q.w.Header()
		h.Set("Content-Type", "application/x-ndjson")
		h.Set("Cache-Control", "no-store")
		q.w.WriteHeader(http.StatusOK)
		rc.Flush()
		write = func(p []byte) error {
			if _, err := q.w.Write(append(p, '\n')); err != nil {
				return err
			}
			return rc.Flush()
		}
	}
	err := s.events.Stream(ctx, opts, func(it event.StreamItem) error {
		var b []byte
		if it.Event != nil {
			b, _ = json.Marshal(streamFrame{Seq: it.Event.Seq, Payload: event.NewPayload([]*event.Event{it.Event})})
		} else {
			b, _ = json.Marshal(droppedFrame{Type: "dropped", Count: it.Dropped})
		}
		return write(b)
	})
	if err != nil && ctx.Err() == nil {
		s.log.Warn("event stream ended", "id", q.id, "err", err)
	}
}

func (s *Server) adminNotifyAuthorized(q *request, action string, method string) bool {
	if q.r.Method != method {
		s.fail(q, errBadMethod)
		return false
	}
	if !s.authorize(q, action, "", "", nil) {
		return false
	}
	if s.events == nil {
		s.fail(q, notImplemented("event notifications are not enabled"))
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

// adminNotifyTargets serves GET /_nanoio/admin/notify/targets: every
// target's health (probed live unless ?probe=false), queue depth and
// delivery counters, and pipeline-wide counters.
func (s *Server) adminNotifyTargets(q *request) {
	if !s.adminNotifyAuthorized(q, "nanoio:NotificationStatus", http.MethodGet) {
		return
	}
	probe := q.query.Get("probe") != "false"
	ctx, cancel := context.WithTimeout(q.ctx(), 10*time.Second)
	defer cancel()
	writeJSON(q.w, struct {
		Targets  []event.TargetStatus `json:"targets"`
		Pipeline event.ManagerStats   `json:"pipeline"`
	}{s.events.Status(ctx, probe), s.events.Stats()})
}

// adminNotifyDead serves GET /_nanoio/admin/notify/dead?arn=: the events a
// target gave up on, with the reason.
func (s *Server) adminNotifyDead(q *request) {
	if !s.adminNotifyAuthorized(q, "nanoio:NotificationStatus", http.MethodGet) {
		return
	}
	max := 100
	if v := q.query.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 1000 {
			max = n
		}
	}
	dl, err := s.events.DeadLetters(q.query.Get("arn"), max)
	switch err {
	case nil:
		writeJSON(q.w, dl)
	case event.ErrNoSuchTarget:
		s.fail(q, invalidArgument("Unknown notification target ARN."))
	default:
		s.fail(q, err)
	}
}

// adminNotifyRequeue serves POST /_nanoio/admin/notify/requeue?arn=: moves
// the target's dead-lettered events back onto its queue.
func (s *Server) adminNotifyRequeue(q *request) {
	if !s.adminNotifyAuthorized(q, "nanoio:RequeueNotifications", http.MethodPost) {
		return
	}
	n, err := s.events.Requeue(q.query.Get("arn"))
	switch err {
	case nil, event.ErrQueueFull:
		writeJSON(q.w, struct {
			Requeued int  `json:"requeued"`
			Complete bool `json:"complete"`
		}{n, err == nil})
	case event.ErrNoSuchTarget:
		s.fail(q, invalidArgument("Unknown notification target ARN."))
	default:
		s.fail(q, err)
	}
}
