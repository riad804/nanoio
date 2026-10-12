package api

import (
	"context"
	"net/http"
	"time"

	"nanoio/internal/event"
	"nanoio/internal/lifecycle"
	"nanoio/internal/storage"
)

var errNoSuchLifecycle = &APIError{"NoSuchLifecycleConfiguration", "The lifecycle configuration does not exist", http.StatusNotFound}

// LifecycleOptions turns on the background lifecycle scanner.
type LifecycleOptions struct {
	// Locker elects the node that scans a bucket (the cluster lock in
	// cluster mode). Required.
	Locker storage.Locker
	// Interval is the minimum time between scans of one bucket
	// (default 1h); Tick is how often a node looks for work (default 1m).
	Interval, Tick time.Duration
	// OpsPerSecond rate-limits the scan (0 unlimited).
	OpsPerSecond float64
	// Clock overrides the wall clock (tests).
	Clock lifecycle.Clock
}

// lifecycleConfig returns the bucket's parsed lifecycle configuration, or
// nil. Stored documents are parsed leniently about tiers: a tier removed
// since the rule was written must not make the document unreadable.
func (s *Server) lifecycleConfig(ctx context.Context, bucket string) (*lifecycle.Config, error) {
	v, err := s.confParsed(ctx, bucket, confLifecycle, func(b []byte) (any, error) {
		return lifecycle.Parse(b, lifecycle.ParseOptions{TierExists: func(string) bool { return true }})
	})
	if err != nil || v == nil {
		return nil, err
	}
	return v.(*lifecycle.Config), nil
}

func (s *Server) bucketLifecycleOp(q *request) {
	switch q.r.Method {
	case http.MethodPut:
		s.putBucketLifecycle(q)
	case http.MethodGet:
		s.getBucketLifecycle(q)
	case http.MethodDelete:
		s.deleteBucketLifecycle(q)
	default:
		s.fail(q, errBadMethod)
	}
}

func (s *Server) putBucketLifecycle(q *request) {
	if !s.authorize(q, "s3:PutLifecycleConfiguration", q.bucket, "", nil) {
		return
	}
	body, err := s.readBody(q, lifecycle.MaxXMLSize+1)
	if err != nil {
		s.fail(q, err)
		return
	}
	cfg, perr := lifecycle.Parse(body, lifecycle.ParseOptions{TierExists: s.tierExists})
	if perr != nil {
		le, _ := perr.(*lifecycle.Error)
		switch {
		case le == nil || le.Code == "MalformedXML":
			s.fail(q, &APIError{"MalformedXML", errMsg(le), http.StatusBadRequest})
		case le.Code == "EntityTooLarge":
			s.fail(q, errEntityLarge)
		default:
			s.fail(q, invalidArgument(le.Message))
		}
		return
	}
	if cfg.UsesTransitions() && !s.supportsTransition() {
		s.fail(q, invalidRequest("Transition rules need the erasure-coded or cluster backend; this server's backend cannot hold transitioned objects."))
		return
	}
	if !s.requireBucket(q) {
		return
	}
	doc, merr := cfg.Marshal()
	if merr != nil {
		s.fail(q, merr)
		return
	}
	if err := s.confPut(q.ctx(), q.bucket, confLifecycle, doc); err != nil {
		s.fail(q, err)
		return
	}
	q.w.WriteHeader(http.StatusOK)
}

func errMsg(le *lifecycle.Error) string {
	if le == nil {
		return errMalformedXML.Message
	}
	return le.Message
}

func (s *Server) getBucketLifecycle(q *request) {
	if !s.authorize(q, "s3:GetLifecycleConfiguration", q.bucket, "", nil) {
		return
	}
	if !s.requireBucket(q) {
		return
	}
	cfg, err := s.lifecycleConfig(q.ctx(), q.bucket)
	if err != nil {
		s.fail(q, err)
		return
	}
	if cfg == nil {
		s.fail(q, errNoSuchLifecycle)
		return
	}
	s.writeXML(q, http.StatusOK, cfg.Render())
}

func (s *Server) deleteBucketLifecycle(q *request) {
	if !s.authorize(q, "s3:PutLifecycleConfiguration", q.bucket, "", nil) {
		return
	}
	if !s.requireBucket(q) {
		return
	}
	s.confDrop(q.ctx(), q.bucket, confLifecycle)
	q.w.WriteHeader(http.StatusNoContent)
}

// ----- scanner wiring ---------------------------------------------------

// lcState keeps scanner state in the system bucket.
type lcState struct{ es *eventStore }

func (l lcState) GetState(ctx context.Context, name string) ([]byte, error) {
	b, err := l.es.Get(ctx, name)
	if err == event.ErrSharedNotFound {
		return nil, nil
	}
	return b, err
}

func (l lcState) PutState(ctx context.Context, name string, data []byte) error {
	return l.es.Put(ctx, name, data)
}

// startLifecycle launches the scanner; it stops with Close.
func (s *Server) startLifecycle(o *LifecycleOptions) error {
	sc, err := lifecycle.NewScanner(lifecycle.Options{
		Store: s.st, Configs: s.lifecycleConfig, Locker: o.Locker, LockBucket: sysBucket,
		State: lcState{&eventStore{st: s.st, locker: o.Locker}}, Clock: o.Clock,
		Interval: o.Interval, OpsPerSecond: o.OpsPerSecond,
		Transitioner: s.transitioner(),
		TagsOf:       decodeTags,
		TierOf:       tierOf,
		Skip:         func(b string) bool { return b == sysBucket },
		Result:       s.lifecycleResult,
		Log:          s.log,
	})
	if err != nil {
		return err
	}
	s.lc = sc
	ctx, cancel := context.WithCancel(context.Background())
	s.stop = append(s.stop, cancel)
	s.bg.Add(1)
	go func() {
		defer s.bg.Done()
		sc.Run(ctx, o.Tick)
	}()
	return nil
}

// Close stops the server's background work (the lifecycle scanner). It does
// not close the storage or the event manager.
func (s *Server) Close() {
	for _, c := range s.stop {
		c()
	}
	s.bg.Wait()
}

// lifecycleResult is the audit trail: every lifecycle action is logged and,
// when notifications are enabled, published as an event.
func (s *Server) lifecycleResult(r lifecycle.Result) {
	if r.Err != nil {
		return
	}
	var name string
	switch {
	case r.Aborted:
		s.log.Info("lifecycle: aborted incomplete multipart upload", "bucket", r.Bucket, "key", r.Key, "uploadId", r.UploadID, "rule", r.RuleID)
		return
	case r.Action == lifecycle.ActionDelete:
		name = event.LifecycleExpirationDelete
	case r.Action == lifecycle.ActionDeleteMarker:
		name = event.LifecycleExpirationDeleteMarkerCreated
	case r.Action == lifecycle.ActionTransition:
		name = event.LifecycleTransition
	default:
		return
	}
	s.log.Info("lifecycle: "+r.Action.String(), "bucket", r.Bucket, "key", r.Key, "version", r.VersionID, "rule", r.RuleID, "tier", r.Tier)
	if s.events == nil {
		return
	}
	e := &event.Event{
		Name: name, Bucket: r.Bucket, Key: r.Key, VersionID: r.VersionID, ETag: r.Info.ETag, Size: r.Info.Size,
		ContentType: r.Info.ContentType, Principal: "nanoio:lifecycle", Region: s.region, RequestID: r.RuleID,
		Time: r.Time.UTC(), Tags: decodeTags(r.Info.UserDefined),
	}
	s.events.Publish(e)
}
