package storage

import (
	"errors"
	"fmt"
	"testing"
)

func TestAllErrorsUniqueAndNonNil(t *testing.T) {
	seen := map[error]bool{}
	seenMsg := map[string]bool{}
	for _, err := range AllErrors() {
		if err == nil {
			t.Fatal("AllErrors contains nil")
		}
		if seen[err] {
			t.Errorf("duplicate sentinel %v", err)
		}
		if seenMsg[err.Error()] {
			t.Errorf("duplicate message %q", err.Error())
		}
		seen[err] = true
		seenMsg[err.Error()] = true
	}
	if got := len(AllErrors()); got != 31 {
		t.Errorf("AllErrors has %d entries, want 31 (update the table in api/ too)", got)
	}
}

func TestWrap(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		bucket  string
		object  string
		is      error
		wantMsg string
		wantNil bool
	}{
		{"nil stays nil", nil, "b", "o", nil, "", true},
		{"object", ErrObjectNotFound, "b", "k", ErrObjectNotFound, "object not found: b/k", false},
		{"bucket only", ErrBucketNotFound, "b", "", ErrBucketNotFound, "bucket not found: b", false},
		{"no names", ErrNotImplemented, "", "", ErrNotImplemented, "not implemented", false},
		{"wrapped twice", fmt.Errorf("ctx: %w", ErrCorrupted), "b", "k", ErrCorrupted, "ctx: stored data failed verification: b/k", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Wrap(tt.err, tt.bucket, tt.object)
			if tt.wantNil {
				if got != nil {
					t.Fatalf("Wrap = %v, want nil", got)
				}
				return
			}
			if !errors.Is(got, tt.is) {
				t.Errorf("errors.Is(%v, %v) = false", got, tt.is)
			}
			if got.Error() != tt.wantMsg {
				t.Errorf("Error() = %q, want %q", got.Error(), tt.wantMsg)
			}
			var oe *ObjectError
			if !errors.As(got, &oe) || oe.Bucket != tt.bucket || oe.Object != tt.object {
				t.Errorf("errors.As did not recover bucket/object: %+v", oe)
			}
		})
	}
}

func TestWrapDoesNotMatchOtherSentinels(t *testing.T) {
	err := Wrap(ErrObjectNotFound, "b", "k")
	for _, other := range AllErrors() {
		if other == ErrObjectNotFound {
			continue
		}
		if errors.Is(err, other) {
			t.Errorf("Wrap(ErrObjectNotFound) wrongly matches %v", other)
		}
	}
}
