package storage

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateBucketName(t *testing.T) {
	tests := []struct {
		name string
		ok   bool
	}{
		{"abc", true},
		{"my-bucket.v2", true},
		{"a1b", true},
		{strings.Repeat("a", 63), true},
		{"ab", false},
		{strings.Repeat("a", 64), false},
		{"", false},
		{"Upper", false},
		{"under_score", false},
		{"-abc", false},
		{"abc-", false},
		{".abc", false},
		{"abc.", false},
		{"a..b", false},
		{"a.-b", false},
		{"a-.b", false},
		{"192.168.1.1", false},
		{".nanoio.sys", false},
		{"has space", false},
		{"slash/es", false},
		{"ünï", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateBucketName(tt.name)
			if tt.ok && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !tt.ok && !errors.Is(err, ErrInvalidBucketName) {
				t.Errorf("error = %v, want ErrInvalidBucketName", err)
			}
		})
	}
}

func TestValidateObjectName(t *testing.T) {
	tests := []struct {
		name string
		want error // nil = valid
	}{
		{"a", nil},
		{"a/b/c.txt", nil},
		{"folder/", nil},
		{"a b/ü/日本語", nil},
		{"a//b", ErrInvalidObjectName},
		{"/a", ErrInvalidObjectName},
		{"/", ErrInvalidObjectName},
		{"a//", ErrInvalidObjectName},
		{"", ErrInvalidObjectName},
		{"a/../b", ErrInvalidObjectName},
		{"..", ErrInvalidObjectName},
		{"a/./b", ErrInvalidObjectName},
		{"a\x00b", ErrInvalidObjectName},
		{"a\xffb", ErrInvalidObjectName},
		{"xl.meta", ErrInvalidObjectName},
		{"dir/xl.meta", ErrInvalidObjectName},
		{"dir/.nanoio-data-1", ErrInvalidObjectName},
		{".nanoio-bucket", ErrInvalidObjectName},
		{"x__NANOIO_DIR__", ErrInvalidObjectName},
		{"xl.meta.bak", nil},
		{strings.Repeat("a", 255), nil},
		{strings.Repeat("a", 256), ErrKeyTooLong},
		{strings.Repeat("a", 250) + "/", ErrKeyTooLong}, // + suffix exceeds 255
		{strings.Repeat("a/", 513), ErrKeyTooLong},
		{strings.Repeat("a", MaxObjectNameLen), ErrKeyTooLong}, // one segment too long
	}
	for _, tt := range tests {
		name := tt.name
		if len(name) > 20 {
			name = name[:20] + "..."
		}
		t.Run(name, func(t *testing.T) {
			err := ValidateObjectName(tt.name)
			if tt.want == nil {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				return
			}
			if !errors.Is(err, tt.want) {
				t.Errorf("error = %v, want %v", err, tt.want)
			}
		})
	}
}

// TestReservedInternalNamespace: every internal endpoint lives under
// /_nanoio/, so no bucket name may begin with an underscore, and "cluster"
// (the name of a health endpoint) is deliberately an ordinary bucket name.
func TestReservedInternalNamespace(t *testing.T) {
	for _, name := range []string{"_nanoio", "_internal", "_abc", "_cluster", "_a_b", "__x"} {
		if err := ValidateBucketName(name); err == nil {
			t.Errorf("%q was accepted; a leading underscore must be rejected", name)
		}
	}
	for _, name := range []string{"cluster", "health", "live", "ready", "admin", "rpc", "nanoio"} {
		if err := ValidateBucketName(name); err != nil {
			t.Errorf("%q rejected (%v); only the /_nanoio/ path prefix is reserved, not these words", name, err)
		}
	}
}
