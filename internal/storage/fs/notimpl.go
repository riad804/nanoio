package fs

import (
	"context"

	"nanoio/internal/storage"
)

// The methods below are outside Phase 1. Each returns ErrNotImplemented
// explicitly and is listed in TODO.md.

func (f *FS) CopyObject(context.Context, storage.ObjectRef, storage.ObjectRef, storage.CopyOptions) (storage.ObjectInfo, error) {
	return storage.ObjectInfo{}, notImpl("CopyObject")
}
