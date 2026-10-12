// Package targetutil holds what several notification targets share: the
// "namespace" and "access" record formats used by the key-value and
// database targets.
package targetutil

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"nanoio/internal/event"
)

// Format is how the key-value and database targets store events.
//
//   - Namespace keeps the current state of the bucket: one entry per object
//     key, written when the object is created and removed when it is
//     deleted. A reader sees "what objects exist" and the last event that
//     touched each.
//   - Access appends every event as a new entry: an event log.
type Format string

const (
	Namespace Format = "namespace"
	Access    Format = "access"
)

// ParseFormat validates a configured format; empty means namespace.
func ParseFormat(s string) (Format, error) {
	switch Format(strings.ToLower(s)) {
	case "", Namespace:
		return Namespace, nil
	case Access:
		return Access, nil
	}
	return "", fmt.Errorf("format %q: must be %q or %q", s, Namespace, Access)
}

// Op is one change to a namespace-format store.
type Op struct {
	// Key is "bucket/key".
	Key    string
	Delete bool
	// Value is the JSON document to store for a put.
	Value []byte
	Time  time.Time
}

// recordsDoc is the stored value of a namespace entry: {"Records":[...]}.
type recordsDoc struct {
	Records []event.Record `json:"Records"`
}

// NamespaceOps turns events into the ordered changes to apply. Removal
// events (including delete markers and lifecycle expiry) delete the key;
// everything else stores the event's record under it. Access events (GET,
// HEAD) do not describe a change to the namespace and are skipped.
func NamespaceOps(events []*event.Event) []Op {
	ops := make([]Op, 0, len(events))
	for _, e := range events {
		switch {
		case event.IsRemoval(e.Name):
			ops = append(ops, Op{Key: e.ObjectPath(), Delete: true, Time: e.Time})
		case strings.HasPrefix(e.Name, "s3:ObjectAccessed:"):
		default:
			v, _ := json.Marshal(recordsDoc{Records: []event.Record{e.Record()}})
			ops = append(ops, Op{Key: e.ObjectPath(), Value: v, Time: e.Time})
		}
	}
	return ops
}

type accessDoc struct {
	Event     []event.Record `json:"Event"`
	EventTime string         `json:"EventTime"`
}

// AccessEntry is the JSON stored for one event in the access format:
// {"Event":[record],"EventTime":"..."}.
func AccessEntry(e *event.Event) []byte {
	b, _ := json.Marshal(accessDoc{Event: []event.Record{e.Record()},
		EventTime: e.Time.UTC().Format("2006-01-02T15:04:05.000Z")})
	return b
}

// KeyOf is the stored key of an event in the namespace format.
func KeyOf(e *event.Event) string { return e.ObjectPath() }
