package targetutil

import (
	"encoding/json"
	"testing"
	"time"

	"nanoio/internal/event"
)

func ev(name, key string) *event.Event {
	return &event.Event{Name: name, Bucket: "b", Key: key, Time: time.Unix(0, 0).UTC(), Size: 3, ETag: "e"}
}

func TestNamespaceOps(t *testing.T) {
	ops := NamespaceOps([]*event.Event{
		ev(event.ObjectCreatedPut, "a"),
		ev(event.ObjectAccessedGet, "a"), // not a change
		ev(event.ObjectCreatedCopy, "a"),
		ev(event.ObjectRemovedDelete, "a"),
		ev(event.ObjectRemovedDeleteMarkerCreated, "c"),
		ev(event.LifecycleExpirationDelete, "d"),
	})
	want := []struct {
		key string
		del bool
	}{{"b/a", false}, {"b/a", false}, {"b/a", true}, {"b/c", true}, {"b/d", true}}
	if len(ops) != len(want) {
		t.Fatalf("ops = %+v", ops)
	}
	for i, w := range want {
		if ops[i].Key != w.key || ops[i].Delete != w.del {
			t.Errorf("op %d = %+v, want %+v", i, ops[i], w)
		}
	}
	var doc struct{ Records []struct{ EventName string } }
	if err := json.Unmarshal(ops[0].Value, &doc); err != nil || len(doc.Records) != 1 || doc.Records[0].EventName != event.ObjectCreatedPut {
		t.Errorf("value = %s (%v)", ops[0].Value, err)
	}
}

func TestAccessEntryAndFormat(t *testing.T) {
	var doc struct {
		Event     []map[string]any
		EventTime string
	}
	if err := json.Unmarshal(AccessEntry(ev(event.ObjectCreatedPut, "k")), &doc); err != nil || len(doc.Event) != 1 || doc.EventTime != "1970-01-01T00:00:00.000Z" {
		t.Errorf("entry = %+v (%v)", doc, err)
	}
	for in, want := range map[string]Format{"": Namespace, "namespace": Namespace, "ACCESS": Access} {
		if got, err := ParseFormat(in); err != nil || got != want {
			t.Errorf("ParseFormat(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := ParseFormat("both"); err == nil {
		t.Error("an unknown format must be refused")
	}
}
