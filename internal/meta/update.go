package meta

import (
	"errors"
	"fmt"
	"time"
)

// ErrNotObject means the version is a delete marker, which has no metadata
// to update.
var ErrNotObject = errors.New("meta: version is a delete marker")

// MetaUpdate is an in-place change of one object version's metadata.
type MetaUpdate struct {
	// UserMeta replaces the version's user metadata when non-nil.
	UserMeta map[string]string `json:"userMeta,omitempty"`
	// ClearUserMeta distinguishes "replace with empty" from "leave alone"
	// across JSON, where an empty map is omitted.
	ClearUserMeta bool `json:"clearUserMeta,omitempty"`
	// ContentType replaces the content type when non-nil.
	ContentType *string `json:"contentType,omitempty"`
	// ModTime replaces the modification time when non-nil.
	ModTime *time.Time `json:"modTime,omitempty"`
}

// ApplySetMeta updates one version's metadata and makes seq the file's
// generation.
func (f *File) ApplySetMeta(id string, seq uint64, u MetaUpdate) error {
	if seq == 0 || seq <= f.Generation() {
		return fmt.Errorf("%w: seq %d, generation %d", ErrStale, seq, f.Generation())
	}
	v := f.Find(id)
	if v == nil {
		return fmt.Errorf("%w: %q", ErrNoSuchVersion, id)
	}
	if v.Type != TypeObject {
		return fmt.Errorf("%w: %q", ErrNotObject, id)
	}
	switch {
	case u.UserMeta != nil:
		v.UserMeta = make(map[string]string, len(u.UserMeta))
		for k, val := range u.UserMeta {
			v.UserMeta[k] = val
		}
	case u.ClearUserMeta:
		v.UserMeta = nil
	}
	if u.ContentType != nil {
		v.ContentType = *u.ContentType
	}
	if u.ModTime != nil {
		v.ModTime = *u.ModTime
	}
	f.Gen = seq
	return nil
}
