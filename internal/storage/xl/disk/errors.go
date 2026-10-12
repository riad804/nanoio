package disk

import (
	"context"
	"errors"
	"fmt"
	iofs "io/fs"

	"nanoio/internal/meta"
	"nanoio/internal/storage"
	"nanoio/internal/storage/internal/fsutil"
)

// Kind classifies a Disk failure. Values cross the wire, so they are
// append-only: never renumber or reuse one.
type Kind uint8

const (
	KindIO          Kind = 0  // anything unclassified
	KindOffline     Kind = 1  // drive missing, unformatted, unreachable or failed
	KindNotFound    Kind = 2  // bucket, object, upload, part or file absent
	KindUnformatted Kind = 3  // blank drive, usable once formatted
	KindForeign     Kind = 4  // populated directory without a format: never adopted
	KindInUse       Kind = 5  // another process holds the drive
	KindConflict    Kind = 6  // conditional commit lost to a newer generation
	KindCorrupted   Kind = 7  // stored data failed verification
	KindDiskFull    Kind = 8  // no space left
	KindCanceled    Kind = 9  // context cancelled or deadline exceeded
	KindLocked      Kind = 10 // object lock refuses the change
)

var kindNames = map[Kind]string{
	KindIO: "i/o error", KindOffline: "offline", KindNotFound: "not found",
	KindUnformatted: "not formatted", KindForeign: "directory is not empty and has no format",
	KindInUse: "in use by another process", KindConflict: "conflicting newer generation",
	KindCorrupted: "corrupted", KindDiskFull: "disk full", KindCanceled: "canceled",
	KindLocked: "protected by object lock",
}

func (k Kind) String() string {
	if s, ok := kindNames[k]; ok {
		return s
	}
	return fmt.Sprintf("kind(%d)", uint8(k))
}

// Error is the error type of every Disk method: it is always the outermost
// error returned, so a caller (local or across the network) can classify a
// failure with errors.Is(err, disk.ErrNotFound) without unwrapping
// transport detail. Only Kind crosses the wire; Op, Path and Err describe
// the failure on the side that produced or received it.
type Error struct {
	Kind Kind
	Op   string // Disk method, e.g. "CommitObject"
	Path string // bucket/object or drive, when known
	Err  error  // underlying cause; not serialized
}

func (e *Error) Error() string {
	s := "disk"
	if e.Op != "" {
		s += " " + e.Op
	}
	if e.Path != "" {
		s += " " + e.Path
	}
	s += ": " + e.Kind.String()
	if e.Err != nil {
		s += ": " + e.Err.Error()
	}
	return s
}

func (e *Error) Unwrap() error { return e.Err }

// Is matches the sentinels below by Kind, and the storage package's
// sentinels where a Kind has an equivalent there.
func (e *Error) Is(target error) bool {
	if t, ok := target.(*Error); ok {
		return t != nil && t.Kind == e.Kind
	}
	switch e.Kind {
	case KindCorrupted:
		return target == storage.ErrCorrupted
	case KindDiskFull:
		return target == storage.ErrDiskFull
	case KindLocked:
		return target == storage.ErrObjectLocked
	}
	return false
}

// Sentinels for errors.Is. Do not modify them.
var (
	ErrOffline     = &Error{Kind: KindOffline}
	ErrNotFound    = &Error{Kind: KindNotFound}
	ErrUnformatted = &Error{Kind: KindUnformatted}
	ErrForeign     = &Error{Kind: KindForeign}
	ErrInUse       = &Error{Kind: KindInUse}
	ErrConflict    = &Error{Kind: KindConflict}
	ErrCorrupted   = &Error{Kind: KindCorrupted}
	ErrDiskFull    = &Error{Kind: KindDiskFull}
	ErrCanceled    = &Error{Kind: KindCanceled}
	ErrLocked      = &Error{Kind: KindLocked}
)

// Wrap returns err as an *Error with op and path filled in, classifying it
// if it is not already one. A nil err stays nil; an *Error that is already
// outermost is returned (completed with op/path) rather than re-wrapped.
func Wrap(op, path string, err error) error {
	if err == nil {
		return nil
	}
	if e, ok := err.(*Error); ok {
		if e.Op == "" && op != "" || e.Path == "" && path != "" {
			c := *e
			if c.Op == "" {
				c.Op = op
			}
			if c.Path == "" {
				c.Path = path
			}
			return &c
		}
		return e
	}
	return &Error{Kind: classify(err), Op: op, Path: path, Err: err}
}

func classify(err error) Kind {
	var e *Error
	switch {
	case errors.As(err, &e):
		return e.Kind
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return KindCanceled
	case fsutil.IsNoSpace(err):
		return KindDiskFull
	case errors.Is(err, meta.ErrLocked), errors.Is(err, storage.ErrObjectLocked):
		return KindLocked
	case errors.Is(err, storage.ErrCorrupted):
		return KindCorrupted
	case errors.Is(err, iofs.ErrNotExist):
		return KindNotFound
	}
	return KindIO
}
