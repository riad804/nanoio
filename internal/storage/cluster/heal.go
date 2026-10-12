package cluster

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"nanoio/internal/storage"
	"nanoio/internal/storage/xl"
)

// healer is what an erasure-coded set offers beyond storage.StorageAPI.
type healer interface {
	HealObject(ctx context.Context, bucket, object string, deep bool) (xl.HealResult, error)
	HealBucket(ctx context.Context, bucket string) ([]int, error)
}

// HealObject heals an object on whichever set holds it. The set is not
// looked up by reading the object (a damaged object may not read), so each
// set is asked; the first that knows the object answers.
func (s *Store) HealObject(ctx context.Context, bucket, object string, deep bool) (xl.HealResult, error) {
	if err := validate(bucket, object); err != nil {
		return xl.HealResult{}, err
	}
	res := xl.HealResult{Bucket: bucket, Object: object, Skipped: "absent"}
	var firstErr error
	for i, set := range s.sets {
		h, ok := set.(healer)
		if !ok {
			continue
		}
		r, err := h.HealObject(ctx, bucket, object, deep)
		if err != nil {
			if firstErr == nil && !errors.Is(err, storage.ErrObjectNotFound) {
				firstErr = fmt.Errorf("%s: %w", s.setID[i], err)
			}
			continue
		}
		if r.Skipped != "absent" {
			return r, nil
		}
	}
	return res, firstErr
}

// HealBucket recreates a bucket's directory on the drives of every set that
// lacks it and returns the number of the drives changed (summed).
func (s *Store) HealBucket(ctx context.Context, bucket string) ([]int, error) {
	var out []int
	for i, set := range s.sets {
		hl, ok := set.(healer)
		if !ok {
			continue
		}
		h, err := hl.HealBucket(ctx, bucket)
		if err != nil {
			return out, fmt.Errorf("%s: %w", s.setID[i], err)
		}
		out = append(out, h...)
	}
	return out, nil
}

// PoolInfo summarises one pool's sets for status reporting.
type PoolInfo struct {
	Index    int
	Sets     int
	Drives   int
	Online   int
	Draining bool
}

// Pools reports every pool from the sets' point of view.
func (s *Store) Pools() []PoolInfo {
	byPool := map[int]*PoolInfo{}
	for _, st := range s.Status() {
		p := byPool[st.Pool]
		if p == nil {
			p = &PoolInfo{Index: st.Pool, Draining: st.Draining}
			byPool[st.Pool] = p
		}
		p.Sets++
		p.Drives += st.Drives
		p.Online += st.Online
	}
	out := make([]PoolInfo, 0, len(byPool))
	for _, p := range byPool {
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return out
}
