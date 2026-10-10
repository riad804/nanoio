package api

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"nanoio/internal/auth"
	"nanoio/internal/storage"
)

func TestEveryStorageErrorIsMapped(t *testing.T) {
	if got, want := len(storageErrors), len(storage.AllErrors()); got != want {
		t.Errorf("storageErrors has %d entries, storage.AllErrors() has %d", got, want)
	}
	for _, sentinel := range storage.AllErrors() {
		t.Run(sentinel.Error(), func(t *testing.T) {
			ae, respond, known := classify(fmt.Errorf("outer: %w", storage.Wrap(sentinel, "b", "k")))
			if !known || !respond {
				t.Fatalf("not mapped (known=%v respond=%v)", known, respond)
			}
			if ae.Code == "" || ae.Message == "" {
				t.Errorf("empty code or message: %+v", ae)
			}
			if ae.Status < 400 || ae.Status > 599 {
				t.Errorf("status %d is not an error status", ae.Status)
			}
		})
	}
	seen := map[error]bool{}
	for _, m := range storageErrors {
		if seen[m.err] {
			t.Errorf("%v appears twice in storageErrors", m.err)
		}
		seen[m.err] = true
	}
}

func TestEveryAuthErrorIsMapped(t *testing.T) {
	if got, want := len(authErrors), len(auth.AllErrors()); got != want {
		t.Errorf("authErrors has %d entries, auth.AllErrors() has %d", got, want)
	}
	for _, sentinel := range auth.AllErrors() {
		t.Run(sentinel.Error(), func(t *testing.T) {
			ae, respond, known := classify(fmt.Errorf("wrap: %w", sentinel))
			if !known || !respond {
				t.Fatalf("not mapped (known=%v respond=%v)", known, respond)
			}
			if ae.Code == "" || ae.Message == "" || ae.Status < 400 || ae.Status > 499 {
				t.Errorf("bad mapping: %+v", ae)
			}
		})
	}
	t.Run("wrapped detail reaches the client message", func(t *testing.T) {
		err := fmt.Errorf("%w: the region %q is wrong; expecting %q", auth.ErrAuthHeaderMalformed, "eu-west-1", "us-east-1")
		ae, _, _ := classify(err)
		if ae.Code != "AuthorizationHeaderMalformed" || !strings.Contains(ae.Message, `expecting "us-east-1"`) {
			t.Errorf("%+v", ae)
		}
	})
	t.Run("bare sentinel keeps the stock message", func(t *testing.T) {
		ae, _, _ := classify(auth.ErrSignatureDoesNotMatch)
		if !strings.Contains(ae.Message, "does not match") {
			t.Errorf("%+v", ae)
		}
	})
}

func TestClassify(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		code      string
		status    int
		respond   bool
		wantKnown bool
	}{
		{"no such bucket", storage.Wrap(storage.ErrBucketNotFound, "b", ""), "NoSuchBucket", 404, true, true},
		{"no such key", storage.Wrap(storage.ErrObjectNotFound, "b", "k"), "NoSuchKey", 404, true, true},
		{"bucket exists", storage.ErrBucketExists, "BucketAlreadyOwnedByYou", 409, true, true},
		{"not empty", storage.ErrBucketNotEmpty, "BucketNotEmpty", 409, true, true},
		{"invalid bucket", fmt.Errorf("%w: %q", storage.ErrInvalidBucketName, "x"), "InvalidBucketName", 400, true, true},
		{"key too long", storage.ErrKeyTooLong, "KeyTooLongError", 400, true, true},
		{"bad digest", storage.ErrBadDigest, "BadDigest", 400, true, true},
		{"sha mismatch", storage.ErrSHA256Mismatch, "XAmzContentSHA256Mismatch", 400, true, true},
		{"incomplete body", storage.ErrIncompleteBody, "IncompleteBody", 400, true, true},
		{"precondition", storage.ErrPreconditionFailed, "PreconditionFailed", 412, true, true},
		{"invalid range", storage.ErrInvalidRange, "InvalidRange", 416, true, true},
		{"lock timeout", storage.ErrLockTimeout, "SlowDown", 503, true, true},
		{"unavailable", storage.ErrBackendUnavailable, "ServiceUnavailable", 503, true, true},
		{"disk full", storage.ErrDiskFull, "XNanoIOStorageFull", 507, true, true},
		{"corrupted hides detail", fmt.Errorf("%w: /secret/path", storage.ErrCorrupted), "InternalError", 500, true, true},
		{"not implemented", storage.ErrNotImplemented, "NotImplemented", 501, true, true},
		{"api error passes through", invalidArgument("nope"), "InvalidArgument", 400, true, true},
		{"api error wrapped", fmt.Errorf("ctx: %w", errMalformedXML), "MalformedXML", 400, true, true},
		{"chunk format", fmt.Errorf("%w: bad", errChunkFormat), "InvalidRequest", 400, true, true},
		{"client went away", context.Canceled, "", 0, false, true},
		{"deadline", context.DeadlineExceeded, "RequestTimeout", 400, true, true},
		{"unknown error", errors.New("disk exploded at /var/secret"), "InternalError", 500, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ae, respond, known := classify(tt.err)
			if respond != tt.respond || known != tt.wantKnown {
				t.Fatalf("respond=%v known=%v, want %v %v", respond, known, tt.respond, tt.wantKnown)
			}
			if !respond {
				return
			}
			if ae.Code != tt.code || ae.Status != tt.status {
				t.Errorf("got %s/%d, want %s/%d", ae.Code, ae.Status, tt.code, tt.status)
			}
			if tt.err != nil && ae.Code == "InternalError" && containsAny(ae.Message, "secret", "/var") {
				t.Errorf("internal detail leaked into message %q", ae.Message)
			}
		})
	}
}

func containsAny(s string, subs ...string) bool {
	for _, x := range subs {
		for i := 0; i+len(x) <= len(s); i++ {
			if s[i:i+len(x)] == x {
				return true
			}
		}
	}
	return false
}
