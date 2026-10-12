package api

import (
	"context"
	"net/http"
	"net/textproto"
	"strings"
	"time"

	"nanoio/internal/event"
	"nanoio/internal/storage"
)

// confNotification is the stored bucket notification configuration: the
// canonical XML of event.Config.
const confNotification = "notification"

// lenientARNs accepts every ARN. Stored configurations are parsed with it:
// a target that was valid when the configuration was written but has since
// been removed from the server's configuration must not make the whole
// bucket configuration unreadable. Matching a removed target is counted by
// the manager and the event is dropped.
func lenientARNs(arn string) (string, bool) { return arn, true }

// notifyConfig returns the bucket's parsed notification configuration, or
// nil when it has none.
func (s *Server) notifyConfig(ctx context.Context, bucket string) (*event.Config, error) {
	v, err := s.confParsed(ctx, bucket, confNotification, func(b []byte) (any, error) {
		return event.ParseConfig(b, lenientARNs)
	})
	if err != nil || v == nil {
		return nil, err
	}
	return v.(*event.Config), nil
}

func (s *Server) bucketNotificationOp(q *request) {
	switch q.r.Method {
	case http.MethodPut:
		s.putBucketNotification(q)
	case http.MethodGet:
		s.getBucketNotification(q)
	default:
		s.fail(q, errBadMethod)
	}
}

func (s *Server) putBucketNotification(q *request) {
	if !s.authorize(q, "s3:PutBucketNotification", q.bucket, "", nil) {
		return
	}
	body, err := s.readBody(q, event.MaxConfigSize+1)
	if err != nil {
		s.fail(q, err)
		return
	}
	// With no event manager no target exists, so only an empty
	// configuration (which removes it) can be accepted.
	resolve := func(string) (string, bool) { return "", false }
	if s.events != nil {
		resolve = s.events.Resolve
	}
	cfg, perr := event.ParseConfig(body, resolve)
	if perr != nil {
		ce, _ := perr.(*event.ConfigError)
		switch {
		case ce == nil || ce.Code == "MalformedXML":
			s.fail(q, errMalformedXML)
		case ce.Code == "EntityTooLarge":
			s.fail(q, errEntityLarge)
		default:
			s.fail(q, invalidArgument(ce.Message))
		}
		return
	}
	if !s.requireBucket(q) {
		return
	}
	if len(cfg.Rules) == 0 {
		// An empty document removes the configuration, as in S3.
		s.confDrop(q.ctx(), q.bucket, confNotification)
		q.w.WriteHeader(http.StatusOK)
		return
	}
	doc, merr := cfg.Marshal()
	if merr != nil {
		s.fail(q, merr)
		return
	}
	if err := s.confPut(q.ctx(), q.bucket, confNotification, doc); err != nil {
		s.fail(q, err)
		return
	}
	q.w.WriteHeader(http.StatusOK)
}

func (s *Server) getBucketNotification(q *request) {
	if !s.authorize(q, "s3:GetBucketNotification", q.bucket, "", nil) {
		return
	}
	if !s.requireBucket(q) {
		return
	}
	cfg, err := s.notifyConfig(q.ctx(), q.bucket)
	if err != nil {
		s.fail(q, err)
		return
	}
	s.writeXML(q, http.StatusOK, cfg.Render())
}

// ----- emission ---------------------------------------------------------

// notifyObj describes the object an event is about.
type notifyObj struct {
	key, versionID, etag, contentType string
	size                              int64
	modTime                           time.Time
	// ud is the object's stored user-defined map: the source of its user
	// metadata and tags.
	ud map[string]string
	// tags overrides the tags found in ud (a removal event, whose object
	// is gone, carries the tags read just before the delete).
	tags map[string]string
}

func objectFromInfo(info storage.ObjectInfo, key, etag string) notifyObj {
	if etag == "" {
		etag = info.ETag
	}
	return notifyObj{key: key, versionID: info.VersionID, etag: etag, contentType: info.ContentType,
		size: plainSize(info), modTime: info.ModTime, ud: info.UserDefined}
}

// notify publishes an event for the request. It never blocks, never fails
// and never panics into the caller: notifications are a side effect that
// must not be able to break the S3 operation that produced them.
func (s *Server) notify(q *request, name string, o notifyObj) {
	if s.events == nil || q.bucket == sysBucket {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("notification: panic while building an event", "event", name, "panic", r)
		}
	}()
	e := &event.Event{
		Name: name, Bucket: q.bucket, Key: o.key, VersionID: o.versionID, ETag: o.etag,
		Size: o.size, ContentType: o.contentType,
		Principal: q.who, SourceIP: remoteIP(q.r), UserAgent: q.r.UserAgent(),
		RequestID: q.id, HostID: q.w.Header().Get("x-amz-id-2"), Region: s.region,
		Tags: o.tags,
	}
	if !o.modTime.IsZero() && !strings.HasPrefix(name, "s3:ObjectAccessed:") {
		e.Time = o.modTime.UTC()
	}
	if e.Tags == nil {
		e.Tags = decodeTags(o.ud)
	}
	for k, v := range o.ud {
		if strings.HasPrefix(k, userMetaPrefix) {
			if e.UserMetadata == nil {
				e.UserMetadata = map[string]string{}
			}
			e.UserMetadata[textproto.CanonicalMIMEHeaderKey(k)] = v
		}
	}
	s.events.Publish(e)
}

// notifyAccess publishes an ObjectAccessed event if anyone could want it:
// the bucket's configuration selects it, or a live stream is attached. Reads
// are the bulk of traffic; without this gate every GET would be journaled.
func (s *Server) notifyAccess(q *request, name string, o notifyObj) {
	if s.events == nil || q.bucket == sysBucket {
		return
	}
	if s.events.Listeners() == 0 {
		// The response is already out and a client that read it in full may
		// have closed the connection: do not let that cancel the lookup.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(q.ctx()), 2*time.Second)
		defer cancel()
		cfg, err := s.notifyConfig(ctx, q.bucket)
		if err != nil || !cfg.Wants(name) {
			return
		}
	}
	s.notify(q, name, o)
}

// removalTags reads the tags of an object about to be removed, but only
// when a configured tag filter could need them, so deletes stay one
// storage call otherwise.
func (s *Server) removalTags(q *request, key, versionID string) map[string]string {
	if s.events == nil {
		return nil
	}
	cfg, err := s.notifyConfig(q.ctx(), q.bucket)
	if err != nil || cfg == nil || !(cfg.NeedsTags(event.ObjectRemovedDelete) || cfg.NeedsTags(event.ObjectRemovedDeleteMarkerCreated)) {
		return nil
	}
	info, err := s.st.StatObject(q.ctx(), q.bucket, key, storage.GetOptions{VersionID: versionID})
	if err != nil {
		return nil
	}
	return decodeTags(info.UserDefined)
}

// notifyRemoval publishes the event for a DeleteObject result: a delete
// marker when none was named and one was created, otherwise a delete.
func (s *Server) notifyRemoval(q *request, key, requestedVersion string, res storage.DeleteResult, tags map[string]string) {
	name, version := event.ObjectRemovedDelete, requestedVersion
	if requestedVersion == "" && res.DeleteMarker {
		name, version = event.ObjectRemovedDeleteMarkerCreated, res.VersionID
	}
	s.notify(q, name, notifyObj{key: key, versionID: version, tags: tags})
}
