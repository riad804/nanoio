package event

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Event is one thing that happened to an object. It is immutable once
// published: the bus hands the same *Event to every subscriber.
type Event struct {
	// Seq orders events published by one node; it is assigned by the Bus
	// and increases across restarts.
	Seq  uint64    `json:"seq"`
	Name string    `json:"name"`
	Time time.Time `json:"time"`

	Bucket      string `json:"bucket"`
	Key         string `json:"key"`
	VersionID   string `json:"versionId,omitempty"`
	ETag        string `json:"etag,omitempty"`
	Size        int64  `json:"size,omitempty"`
	ContentType string `json:"contentType,omitempty"`
	// Sequencer orders events for the same key: a hex string that compares
	// greater for a later change to the object.
	Sequencer    string            `json:"sequencer,omitempty"`
	UserMetadata map[string]string `json:"userMetadata,omitempty"`
	// Tags are the object's tags when the event was produced, used by tag
	// filters. They are not part of the delivered record.
	Tags map[string]string `json:"tags,omitempty"`

	Principal string `json:"principal,omitempty"`
	SourceIP  string `json:"sourceIP,omitempty"`
	UserAgent string `json:"userAgent,omitempty"`
	RequestID string `json:"requestId,omitempty"`
	HostID    string `json:"hostId,omitempty"`
	Region    string `json:"region,omitempty"`
}

// ObjectPath is "bucket/key", the identity MinIO uses for the top-level Key
// of a notification.
func (e *Event) ObjectPath() string { return e.Bucket + "/" + e.Key }

// Record is the S3 notification record format, as MinIO emits it (the
// event name keeps its "s3:" prefix).
type Record struct {
	EventVersion      string            `json:"eventVersion"`
	EventSource       string            `json:"eventSource"`
	AWSRegion         string            `json:"awsRegion"`
	EventTime         string            `json:"eventTime"`
	EventName         string            `json:"eventName"`
	UserIdentity      identity          `json:"userIdentity"`
	RequestParameters map[string]string `json:"requestParameters"`
	ResponseElements  map[string]string `json:"responseElements"`
	S3                s3Entity          `json:"s3"`
	Source            source            `json:"source"`
}

type identity struct {
	PrincipalID string `json:"principalId"`
}

type s3Entity struct {
	SchemaVersion   string   `json:"s3SchemaVersion"`
	ConfigurationID string   `json:"configurationId"`
	Bucket          s3Bucket `json:"bucket"`
	Object          s3Object `json:"object"`
}

type s3Bucket struct {
	Name          string   `json:"name"`
	OwnerIdentity identity `json:"ownerIdentity"`
	ARN           string   `json:"arn"`
}

type s3Object struct {
	Key          string            `json:"key"`
	Size         int64             `json:"size,omitempty"`
	ETag         string            `json:"eTag,omitempty"`
	ContentType  string            `json:"contentType,omitempty"`
	UserMetadata map[string]string `json:"userMetadata,omitempty"`
	VersionID    string            `json:"versionId,omitempty"`
	Sequencer    string            `json:"sequencer"`
}

type source struct {
	Host      string `json:"host"`
	Port      string `json:"port"`
	UserAgent string `json:"userAgent"`
}

// Record renders the event in S3 notification form.
func (e *Event) Record() Record {
	r := Record{
		EventVersion: "2.0",
		EventSource:  "nanoio:s3",
		AWSRegion:    e.Region,
		EventTime:    e.Time.UTC().Format("2006-01-02T15:04:05.000Z"),
		EventName:    e.Name,
		UserIdentity: identity{PrincipalID: e.Principal},
		RequestParameters: map[string]string{
			"principalId":     e.Principal,
			"region":          e.Region,
			"sourceIPAddress": e.SourceIP,
		},
		ResponseElements: map[string]string{
			"x-amz-id-2":       e.HostID,
			"x-amz-request-id": e.RequestID,
		},
		S3: s3Entity{
			SchemaVersion:   "1.0",
			ConfigurationID: "Config",
			Bucket:          s3Bucket{Name: e.Bucket, OwnerIdentity: identity{PrincipalID: e.Principal}, ARN: "arn:aws:s3:::" + e.Bucket},
			Object: s3Object{
				Key: url.QueryEscape(e.Key), Size: e.Size, ETag: e.ETag, ContentType: e.ContentType,
				UserMetadata: e.UserMetadata, VersionID: e.VersionID, Sequencer: e.Sequencer,
			},
		},
		Source: source{Host: e.SourceIP, UserAgent: e.UserAgent},
	}
	return r
}

// Payload is the JSON document targets deliver for one or more events:
// {"EventName": ..., "Key": "bucket/key", "Records": [...]}. EventName and
// Key describe the first event.
type Payload struct {
	EventName string   `json:"EventName"`
	Key       string   `json:"Key"`
	Records   []Record `json:"Records"`
}

// NewPayload builds the payload for a batch; events must not be empty.
func NewPayload(events []*Event) Payload {
	p := Payload{EventName: events[0].Name, Key: events[0].ObjectPath(), Records: make([]Record, len(events))}
	for i, e := range events {
		p.Records[i] = e.Record()
	}
	return p
}

// JSON is the payload of a single event.
func (e *Event) JSON() []byte {
	b, _ := json.Marshal(NewPayload([]*Event{e}))
	return b
}

// Sequencer builds a Sequencer from the object's modification time and the
// event's sequence number: later changes compare greater, and two events in
// the same nanosecond are still ordered.
func Sequencer(mod time.Time, seq uint64) string {
	return fmt.Sprintf("%016X%08X", uint64(mod.UnixNano()), seq&0xffffffff)
}

// ARN is a target's identifier in a notification configuration:
// arn:minio:sqs:<region>:<id>:<type>. The "minio" partition is kept so
// existing clients (mc event add) accept it.
func ARN(region, id, typ string) string {
	return "arn:minio:sqs:" + region + ":" + id + ":" + typ
}

// ParseARN splits an ARN. ok is false unless it has the exact form.
func ParseARN(arn string) (region, id, typ string, ok bool) {
	parts := strings.Split(arn, ":")
	if len(parts) != 6 || parts[0] != "arn" || parts[1] != "minio" || parts[2] != "sqs" || parts[4] == "" || parts[5] == "" {
		return "", "", "", false
	}
	return parts[3], parts[4], parts[5], true
}
