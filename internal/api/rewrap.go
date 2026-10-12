package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"nanoio/internal/kms"
	"nanoio/internal/sse"
	"nanoio/internal/storage"
)

// RewrapStats reports a rewrap sweep.
type RewrapStats struct {
	// Versions is the number of object versions looked at.
	Versions int `json:"versions"`
	// Encrypted of them carry a KMS-wrapped key (SSE-S3 or SSE-KMS).
	Encrypted int `json:"encrypted"`
	// Rewrapped were moved to the newest KEK version, metadata only.
	Rewrapped int `json:"rewrapped"`
	// Current were already on the newest KEK version.
	Current int `json:"current"`
	// Failed could not be rewrapped and keep their old (still valid) wrap.
	Failed int `json:"failed"`
	// ByVersion counts KMS-encrypted versions by "key@version" after the
	// sweep, so an operator can tell when an old KEK version is no longer
	// referenced and may be retired.
	ByVersion map[string]int `json:"byVersion"`
}

// Rewrap moves every KMS-wrapped data key in the store to the newest
// version of its KEK (SSE-S3 objects to the configured default key). Only
// object metadata is rewritten: no object data is read, decrypted or
// written. It is idempotent and safe to run beside live traffic; each update
// is conditional on the version it examined.
func (s *Server) Rewrap(ctx context.Context) (RewrapStats, error) {
	st := RewrapStats{ByVersion: map[string]int{}}
	if s.kms == nil {
		return st, sse.ErrNoKMS
	}
	buckets, err := s.st.ListBuckets(ctx)
	if err != nil {
		return st, err
	}
	for _, b := range buckets {
		if b.Name == sysBucket {
			continue
		}
		if err := s.rewrapBucket(ctx, b.Name, &st); err != nil {
			return st, err
		}
	}
	return st, nil
}

func (s *Server) rewrapBucket(ctx context.Context, bucket string, st *RewrapStats) error {
	opts := storage.ListOptions{MaxKeys: 1000}
	for {
		page, err := s.st.ListObjectVersions(ctx, bucket, opts)
		if err != nil {
			return err
		}
		for _, v := range page.Versions {
			if err := ctx.Err(); err != nil {
				return err
			}
			st.Versions++
			if v.DeleteMarker {
				continue
			}
			s.rewrapVersion(ctx, bucket, v, st)
		}
		if !page.IsTruncated {
			return nil
		}
		opts.Marker, opts.VersionIDMarker = page.NextMarker, page.NextVersionIDMarker
	}
}

func (s *Server) rewrapVersion(ctx context.Context, bucket string, v storage.ObjectInfo, st *RewrapStats) {
	m, enc, err := sse.ParseMeta(v.UserDefined)
	if !enc || (err == nil && m.Mode == sse.ModeC) {
		return
	}
	st.Encrypted++
	fail := func(err error) {
		st.Failed++
		s.log.Warn("rewrap: could not rewrap a version", "bucket", bucket, "key", v.Name, "version", v.VersionID, "err", err)
	}
	if err != nil {
		fail(err)
		return
	}
	target := m.KeyID
	if m.Mode == sse.ModeS3 {
		target = s.defaultKey
	}
	info, err := s.kms.DescribeKey(ctx, target)
	if err != nil {
		fail(err)
		return
	}
	if m.KeyID == target && (info.LatestVersion == 0 || m.KeyVersion == info.LatestVersion) {
		st.Current++
		st.ByVersion[bucketKeyVersion(m.KeyID, m.KeyVersion)]++
		return
	}
	path := bucket + "/" + v.Name
	nm, err := sse.RewrapKMS(ctx, s.kms, m, path, target)
	if err != nil {
		fail(err)
		return
	}
	ud := make(map[string]string, len(v.UserDefined))
	for k, val := range v.UserDefined {
		ud[k] = val
	}
	nm.Put(ud)
	vid := v.VersionID
	_, err = s.st.UpdateObjectMetadata(ctx, bucket, v.Name, storage.UpdateMetaOptions{
		VersionID: vid, UserDefined: ud, IfETag: v.ETag,
	})
	switch {
	case errors.Is(err, storage.ErrPreconditionFailed), errors.Is(err, storage.ErrObjectNotFound), errors.Is(err, storage.ErrVersionNotFound):
		// Rewritten or removed since it was listed; whatever replaced it
		// was written with the current key.
		return
	case err != nil:
		fail(err)
		return
	}
	st.Rewrapped++
	st.ByVersion[bucketKeyVersion(nm.KeyID, nm.KeyVersion)]++
}

func bucketKeyVersion(id string, ver uint32) string {
	b, _ := json.Marshal(ver)
	return id + "@" + string(b)
}

// adminRewrap serves POST /_nanoio/admin/rewrap: authenticated like any
// request, and authorised as the action "nanoio:RewrapKeys", which only the
// root credential holds.
func (s *Server) adminRewrap(w http.ResponseWriter, r *http.Request, q *request) {
	if r.Method != http.MethodPost {
		s.fail(q, errBadMethod)
		return
	}
	if !s.authorize(q, "nanoio:RewrapKeys", "", "", nil) {
		return
	}
	stats, err := s.Rewrap(r.Context())
	if err != nil {
		s.fail(q, s.sseError(q, sse.ModeKMS, err))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

var _ = kms.Zero
