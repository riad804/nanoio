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

// ErrAlreadyTransitioned means the version is already a stub.
var ErrAlreadyTransitioned = errors.New("meta: version is already transitioned")

// ApplyTransition turns an object version into a stub pointing at tr and
// returns the data directory it no longer references, for the caller to
// remove once the change is final. seq becomes the file's generation.
func (f *File) ApplyTransition(id string, seq uint64, tr Transition) (superseded []string, err error) {
	if seq == 0 || seq <= f.Generation() {
		return nil, fmt.Errorf("%w: seq %d, generation %d", ErrStale, seq, f.Generation())
	}
	v := f.Find(id)
	if v == nil {
		return nil, fmt.Errorf("%w: %q", ErrNoSuchVersion, id)
	}
	if v.Type != TypeObject {
		return nil, fmt.Errorf("%w: %q", ErrNotObject, id)
	}
	if v.Transition != nil && v.Transition.Tier == tr.Tier && v.Transition.Object == tr.Object {
		return nil, fmt.Errorf("%w: %q", ErrAlreadyTransitioned, id)
	}
	// A stub may be moved to another tier: it is replaced, with no data
	// directory to release.
	if v.DataDir != "" {
		superseded = []string{v.DataDir}
	}
	t := tr
	v.Transition = &t
	v.DataDir = ""
	v.Erasure = nil
	f.Gen = seq
	return superseded, nil
}
