package cluster

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"nanoio/internal/storage"
)

// DrainStats reports a drain.
type DrainStats struct {
	Objects int // copied and removed from the draining pool
	Skipped int // already present on the destination (newer or moved before)
	Failed  int // left in place; see the log
	Bytes   int64
}

// Drain moves every object out of pool onto the ring's sets and removes the
// source copy. The pool must be configured draining (so no new object is
// placed in it); Drain can be run repeatedly and resumes where an earlier
// run stopped. Objects that cannot be moved stay where they are and are
// counted in Failed. In-progress multipart uploads in the pool block the
// drain: they must complete or be aborted first.
func (s *Store) Drain(ctx context.Context, pool int) (DrainStats, error) {
	var st DrainStats
	if pool < 0 || pool >= len(s.pools) {
		return st, fmt.Errorf("cluster: no pool %d", pool)
	}
	if !s.pools[pool].Draining {
		return st, fmt.Errorf("cluster: pool %d is not marked draining; set draining on every node and restart before draining", pool)
	}
	if len(s.ringSets) == 0 {
		return st, ErrNoPlacement
	}
	for g := range s.sets {
		if s.setPool[g] != pool {
			continue
		}
		if err := s.drainSet(ctx, g, &st); err != nil {
			return st, err
		}
	}
	return st, nil
}

func (s *Store) drainSet(ctx context.Context, g int, st *DrainStats) error {
	src := s.sets[g]
	buckets, err := src.ListBuckets(ctx)
	if err != nil {
		return err
	}
	for _, b := range buckets {
		ups, err := src.ListMultipartUploads(ctx, b.Name, storage.ListUploadsOptions{MaxUploads: 1})
		if err != nil {
			return err
		}
		if len(ups.Uploads) > 0 {
			return fmt.Errorf("cluster: bucket %s has in-progress multipart uploads in set %s; complete or abort them first", b.Name, s.setID[g])
		}
		marker := ""
		for {
			page, err := src.ListObjects(ctx, b.Name, storage.ListOptions{Marker: marker, MaxKeys: 500})
			if err != nil {
				return err
			}
			for _, o := range page.Objects {
				if err := ctx.Err(); err != nil {
					return err
				}
				moved, n, err := s.moveObject(ctx, g, b.Name, o)
				switch {
				case err != nil:
					st.Failed++
					s.log.Warn("cluster: drain could not move an object", "bucket", b.Name, "object", o.Name, "set", s.setID[g], "err", err)
				case moved:
					st.Objects++
					st.Bytes += n
				default:
					st.Skipped++
				}
			}
			if !page.IsTruncated {
				break
			}
			marker = page.NextMarker
		}
	}
	return nil
}

// moveObject copies one object to its ring set unless the destination
// already has it, then removes the source. It reports whether it copied.
func (s *Store) moveObject(ctx context.Context, from int, bucket string, o storage.ObjectInfo) (copied bool, n int64, err error) {
	dst := s.ringSet(bucket, o.Name)
	if dst < 0 || dst == from {
		return false, 0, ErrNoPlacement
	}
	rc, info, err := s.sets[from].GetObject(ctx, bucket, o.Name, storage.GetOptions{})
	if err != nil {
		if errors.Is(err, storage.ErrObjectNotFound) {
			return false, 0, nil // deleted meanwhile
		}
		return false, 0, err
	}
	defer rc.Close()
	put, err := s.sets[dst].PutObject(ctx, bucket, o.Name, rc, info.Size, storage.PutOptions{
		ContentType: info.ContentType, UserDefined: info.UserDefined, IfNoneMatch: "*",
	})
	switch {
	case errors.Is(err, storage.ErrPreconditionFailed):
		// The destination already has a version: a client wrote it after
		// the drain began, or an earlier run copied it. Either way it is
		// at least as new as this copy.
	case err != nil:
		return false, 0, err
	default:
		copied, n = true, put.Size
		// Single-part objects keep their ETag; a multipart ETag is
		// necessarily replaced by the content MD5.
		if !strings.Contains(info.ETag, "-") && put.ETag != info.ETag {
			s.sets[dst].DeleteObject(ctx, bucket, o.Name, storage.DeleteOptions{})
			return false, 0, fmt.Errorf("destination ETag %s differs from source %s", put.ETag, info.ETag)
		}
	}
	io.Copy(io.Discard, rc)
	if _, err := s.sets[from].DeleteObject(ctx, bucket, o.Name, storage.DeleteOptions{}); err != nil {
		return copied, n, fmt.Errorf("copied but could not remove the source: %w", err)
	}
	return copied, n, nil
}
