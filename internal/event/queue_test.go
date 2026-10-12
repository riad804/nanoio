package event

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func drain(t *testing.T, q *Queue) []string {
	t.Helper()
	var out []string
	for {
		items, err := q.Peek(7)
		if err != nil {
			t.Fatal(err)
		}
		if len(items) == 0 {
			return out
		}
		for _, it := range items {
			out = append(out, string(it.Data))
		}
		if err := q.Ack(items); err != nil {
			t.Fatal(err)
		}
	}
}

func TestQueueOrderAcrossSegmentsAndRestart(t *testing.T) {
	dir := t.TempDir()
	q, err := OpenQueue(dir, 0, 200) // tiny segments: rotates every few records
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for i := 0; i < 100; i++ {
		s := fmt.Sprintf("event-%03d", i)
		want = append(want, s)
		if err := q.Append([]byte(s)); err != nil {
			t.Fatal(err)
		}
	}
	q.Sync()
	// Acknowledge the first 30, then "crash" (close without anything else).
	items, _ := q.Peek(30)
	if err := q.Ack(items); err != nil {
		t.Fatal(err)
	}
	if q.Len() != 70 {
		t.Fatalf("Len = %d, want 70", q.Len())
	}
	q.Close()

	q, err = OpenQueue(dir, 0, 200)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	if q.Len() != 70 {
		t.Fatalf("after reopen Len = %d, want 70", q.Len())
	}
	got := drain(t, q)
	if fmt.Sprint(got) != fmt.Sprint(want[30:]) {
		t.Fatalf("after reopen got %v\nwant %v", got[:3], want[30:33])
	}
	// Fully acknowledged segments are deleted.
	ents, _ := os.ReadDir(dir)
	segs := 0
	for _, e := range ents {
		if filepath.Ext(e.Name()) == segSuffix {
			segs++
		}
	}
	if segs > 2 {
		t.Errorf("%d segment files remain after the queue drained", segs)
	}
}

func TestQueueLimit(t *testing.T) {
	q, err := OpenQueue(t.TempDir(), 3, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	for i := 0; i < 3; i++ {
		if err := q.Append([]byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if err := q.Append([]byte("y")); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("append past the limit = %v, want ErrQueueFull", err)
	}
	ev, err := q.AppendEvicting([]byte("z"))
	if err != nil || !ev {
		t.Fatalf("AppendEvicting = %v, %v; want eviction", ev, err)
	}
}

func TestQueueSurvivesATornTail(t *testing.T) {
	dir := t.TempDir()
	q, _ := OpenQueue(dir, 0, 0)
	for i := 0; i < 5; i++ {
		q.Append([]byte(fmt.Sprintf("e%d", i)))
	}
	q.Sync()
	q.Close()
	// Simulate a crash in the middle of an append: half a record.
	seg := filepath.Join(dir, segName(1))
	f, err := os.OpenFile(seg, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte{0, 0, 0, 40, 1, 2, 3, 4, 'p', 'a', 'r'})
	f.Close()

	q, err = OpenQueue(dir, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	if err := q.Append([]byte("after")); err != nil {
		t.Fatal(err)
	}
	got := drain(t, q)
	if fmt.Sprint(got) != "[e0 e1 e2 e3 e4 after]" {
		t.Fatalf("got %v", got)
	}
}

func TestQueueDamagedCursorRedeliversNeverLoses(t *testing.T) {
	dir := t.TempDir()
	q, _ := OpenQueue(dir, 0, 0)
	for i := 0; i < 4; i++ {
		q.Append([]byte(fmt.Sprintf("e%d", i)))
	}
	items, _ := q.Peek(2)
	q.Ack(items)
	q.Close()
	os.WriteFile(filepath.Join(dir, cursorFile), bytes.Repeat([]byte{0xff}, 20), 0o600)
	q, _ = OpenQueue(dir, 0, 0)
	defer q.Close()
	if got := drain(t, q); fmt.Sprint(got) != "[e0 e1 e2 e3]" {
		t.Fatalf("got %v, want a full redelivery", got)
	}
}

func TestReplayLogBoundedAndResumes(t *testing.T) {
	dir := t.TempDir()
	r, err := OpenReplayLog(dir, 128<<10) // 16 KiB segments, but min 64 KiB each
	if err != nil {
		t.Fatal(err)
	}
	big := string(bytes.Repeat([]byte("v"), 1000))
	var last uint64
	for i := 1; i <= 2000; i++ {
		e := &Event{Seq: uint64(i), Name: ObjectCreatedPut, Bucket: "b", Key: fmt.Sprintf("k%d", i), ETag: big}
		if err := r.Append(e); err != nil {
			t.Fatal(err)
		}
		last = e.Seq
	}
	r.Sync()
	if sz := r.Size(); sz > 128<<10+64<<10 {
		t.Errorf("replay log holds %d bytes, budget is %d", sz, 128<<10)
	}
	if r.OldestSeq() <= 1 {
		t.Error("rotation never dropped the oldest events")
	}
	r.Close()

	r, err = OpenReplayLog(dir, 128<<10)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if r.LastSeq() != last {
		t.Fatalf("LastSeq after reopen = %d, want %d", r.LastSeq(), last)
	}
	n := 0
	var prev uint64
	r.Read(last-10, func(e *Event) bool {
		if e.Seq <= prev || e.Seq <= last-10 {
			t.Fatalf("out of order or too old: %d", e.Seq)
		}
		prev = e.Seq
		n++
		return true
	})
	if n != 10 {
		t.Fatalf("read %d events after seq %d, want 10", n, last-10)
	}
}
