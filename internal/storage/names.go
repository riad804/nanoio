package storage

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Names reserved by the shared on-disk layout. Object key path segments may
// not use them, so a key can never collide with backend-private files.
const (
	// DataDirPrefix starts every per-version data directory and every
	// backend-private file inside a bucket.
	DataDirPrefix = ".nanoio-"
	// MetaFileName is the per-key metadata file.
	MetaFileName = "xl.meta"
	// DirObjectSuffix is appended to the directory of a key ending in "/".
	DirObjectSuffix = "__NANOIO_DIR__"

	// MaxObjectNameLen is the S3 key length limit in bytes.
	MaxObjectNameLen = 1024
	// MaxSegmentLen is the longest path segment most filesystems accept.
	MaxSegmentLen = 255
)

var ipLike = regexp.MustCompile(`^\d{1,3}(\.\d{1,3}){3}$`)

// ValidateBucketName applies the S3 bucket naming rules. Errors match
// ErrInvalidBucketName.
func ValidateBucketName(name string) error {
	bad := func(why string) error {
		return fmt.Errorf("%w: %q: %s", ErrInvalidBucketName, name, why)
	}
	if len(name) < 3 || len(name) > 63 {
		return bad("length must be 3 to 63")
	}
	alnum := func(c byte) bool { return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' }
	for i := 0; i < len(name); i++ {
		if c := name[i]; !alnum(c) && c != '-' && c != '.' {
			return bad("only lowercase letters, digits, '-' and '.' allowed")
		}
	}
	if !alnum(name[0]) || !alnum(name[len(name)-1]) {
		return bad("must start and end with a letter or digit")
	}
	for _, bad2 := range []string{"..", ".-", "-."} {
		if strings.Contains(name, bad2) {
			return bad("contains " + bad2)
		}
	}
	if ipLike.MatchString(name) {
		return bad("must not look like an IP address")
	}
	return nil
}

// ValidateObjectName checks a key against S3 limits and the layout's
// reserved names. Errors match ErrKeyTooLong or ErrInvalidObjectName.
//
// Deliberate deviations from S3 (see the design doc): empty path segments,
// "." and ".." segments, segments named xl.meta or starting ".nanoio-" or
// ending "__NANOIO_DIR__", and segments over 255 bytes are rejected.
func ValidateObjectName(name string) error {
	bad := func(why string) error {
		return fmt.Errorf("%w: %q: %s", ErrInvalidObjectName, name, why)
	}
	if name == "" {
		return bad("empty")
	}
	if len(name) > MaxObjectNameLen {
		return fmt.Errorf("%w: %d bytes, limit %d", ErrKeyTooLong, len(name), MaxObjectNameLen)
	}
	if !utf8.ValidString(name) {
		return bad("not valid UTF-8")
	}
	if strings.IndexByte(name, 0) >= 0 {
		return bad("contains NUL")
	}
	trailing := strings.HasSuffix(name, "/")
	segs := strings.Split(strings.TrimSuffix(name, "/"), "/")
	for i, seg := range segs {
		switch {
		case seg == "":
			return bad("empty path segment")
		case seg == "." || seg == "..":
			return bad("'.' and '..' segments not allowed")
		case seg == MetaFileName:
			return bad("segment named " + MetaFileName + " is reserved")
		case strings.HasPrefix(seg, DataDirPrefix):
			return bad("segment starting " + DataDirPrefix + " is reserved")
		case strings.HasSuffix(seg, DirObjectSuffix):
			return bad("segment ending " + DirObjectSuffix + " is reserved")
		}
		n := len(seg)
		if trailing && i == len(segs)-1 {
			n += len(DirObjectSuffix)
		}
		if n > MaxSegmentLen {
			return fmt.Errorf("%w: path segment over %d bytes", ErrKeyTooLong, MaxSegmentLen)
		}
	}
	return nil
}

// KeySegments returns the directory names that hold a validated object key
// under a bucket: its path segments, with the last one carrying
// DirObjectSuffix when the key ends in "/" so that "dir/" cannot collide
// with "dir". Both backends use it, so they share one on-disk layout.
func KeySegments(object string) []string {
	segs := strings.Split(object, "/")
	if last := len(segs) - 1; segs[last] == "" {
		segs = segs[:last]
		segs[len(segs)-1] += DirObjectSuffix
	}
	return segs
}
