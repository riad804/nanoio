package disk

import (
	"context"
	"errors"
	"fmt"
	"syscall"
	"testing"

	"nanoio/internal/storage"
)

// The numeric values cross the wire; this test is the tripwire for anyone
// tempted to renumber or reuse one.
func TestKindValuesAreStable(t *testing.T) {
	want := map[Kind]uint8{
		KindIO: 0, KindOffline: 1, KindNotFound: 2, KindUnformatted: 3, KindForeign: 4,
		KindInUse: 5, KindConflict: 6, KindCorrupted: 7, KindDiskFull: 8, KindCanceled: 9,
	}
	for k, v := range want {
		if uint8(k) != v {
			t.Errorf("%v = %d, want %d: Kind values are append-only", k, uint8(k), v)
		}
	}
}

func TestErrorIsAndWrap(t *testing.T) {
	tests := []struct {
		name string
		err  error
		kind Kind
		is   []error
	}{
		{"sentinel", ErrNotFound, KindNotFound, []error{ErrNotFound}},
		{"wrapped sentinel", fmt.Errorf("ctx: %w", ErrOffline), KindOffline, []error{ErrOffline}},
		{"cancel", context.Canceled, KindCanceled, []error{context.Canceled, ErrCanceled}},
		{"deadline", context.DeadlineExceeded, KindCanceled, []error{context.DeadlineExceeded, ErrCanceled}},
		{"enospc", syscall.ENOSPC, KindDiskFull, []error{ErrDiskFull, storage.ErrDiskFull}},
		{"corrupt", fmt.Errorf("%w: bad", storage.ErrCorrupted), KindCorrupted, []error{ErrCorrupted, storage.ErrCorrupted}},
		{"unclassified", errors.New("boom"), KindIO, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Wrap("Op", "b/o", tt.err)
			e, ok := got.(*Error)
			if !ok {
				t.Fatalf("Wrap returned %T, want *Error outermost", got)
			}
			if e.Kind != tt.kind || e.Op != "Op" {
				t.Errorf("Kind=%v Op=%q", e.Kind, e.Op)
			}
			for _, target := range tt.is {
				if !errors.Is(got, target) {
					t.Errorf("errors.Is(%v, %v) = false", got, target)
				}
			}
			if tt.kind != KindOffline && errors.Is(got, ErrOffline) {
				t.Error("matches an unrelated sentinel")
			}
		})
	}
	if Wrap("Op", "", nil) != nil {
		t.Error("Wrap(nil) is not nil")
	}
	// An existing *Error is not re-wrapped, only completed.
	orig := &Error{Kind: KindConflict}
	if got := Wrap("CommitObject", "b/o", orig).(*Error); got.Kind != KindConflict || got.Op != "CommitObject" || got.Path != "b/o" {
		t.Errorf("completed error = %+v", got)
	}
	// A bare reconstructed error (as on the wire) matches the sentinel.
	if !errors.Is(&Error{Kind: KindNotFound}, ErrNotFound) {
		t.Error("bare wire error does not match its sentinel")
	}
}
