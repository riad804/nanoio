package api

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"

	"nanoio/internal/event"
	"nanoio/internal/storage"
)

// maxSharedObject bounds one replicated queue object (a batch of events).
const maxSharedObject = 16 << 20

// eventStore implements event.SharedStore over the backend: queue objects
// live in the reserved system bucket under "_events/" (no bucket name can
// start with an underscore), so they get the cluster's quorum writes,
// erasure coding and healing. The lease is the cluster namespace lock.
type eventStore struct {
	st     storage.StorageAPI
	locker storage.Locker

	mu    sync.Mutex
	ready bool
}

func (e *eventStore) ensureBucket(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.ready {
		return nil
	}
	err := e.st.MakeBucket(ctx, sysBucket, storage.MakeBucketOptions{})
	if err != nil && !errors.Is(err, storage.ErrBucketExists) {
		return err // not cached: the cluster may only be below quorum
	}
	e.ready = true
	return nil
}

func (e *eventStore) Put(ctx context.Context, name string, data []byte) error {
	if err := e.ensureBucket(ctx); err != nil {
		return err
	}
	_, err := e.st.PutObject(ctx, sysBucket, name, bytes.NewReader(data), int64(len(data)), storage.PutOptions{})
	return err
}

func (e *eventStore) Get(ctx context.Context, name string) ([]byte, error) {
	rc, _, err := e.st.GetObject(ctx, sysBucket, name, storage.GetOptions{})
	switch {
	case errors.Is(err, storage.ErrObjectNotFound), errors.Is(err, storage.ErrBucketNotFound):
		return nil, event.ErrSharedNotFound
	case err != nil:
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(io.LimitReader(rc, maxSharedObject))
}

func (e *eventStore) Delete(ctx context.Context, name string) error {
	_, err := e.st.DeleteObject(ctx, sysBucket, name, storage.DeleteOptions{})
	if errors.Is(err, storage.ErrObjectNotFound) || errors.Is(err, storage.ErrBucketNotFound) {
		return nil
	}
	return err
}

func (e *eventStore) List(ctx context.Context, prefix string, max int) ([]string, error) {
	var out []string
	marker := ""
	for len(out) < max {
		page, err := e.st.ListObjects(ctx, sysBucket, storage.ListOptions{Prefix: prefix, Marker: marker, MaxKeys: min(max-len(out), 1000)})
		if errors.Is(err, storage.ErrBucketNotFound) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		for _, o := range page.Objects {
			out = append(out, o.Name)
		}
		if !page.IsTruncated || len(page.Objects) == 0 {
			break
		}
		marker = page.NextMarker
	}
	return out, nil
}

func (e *eventStore) Lead(ctx context.Context, key string) (func(), error) {
	if err := e.ensureBucket(ctx); err != nil {
		return nil, err
	}
	// Lock takes the bucket's own namespace lock only for the named
	// object, so this does not block bucket operations.
	return e.locker.Lock(ctx, sysBucket, "_events-lease/"+key)
}
