package api

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"nanoio/internal/storage"
)

// Per-bucket configuration documents (default encryption, policy, ACL, CORS,
// tags) are stored as ordinary objects, "<bucket>/<kind>", in the reserved
// bucket sysBucket. They therefore get the backend's quorum, healing and
// cluster placement for free. The API never serves sysBucket to clients.
const (
	confEncryption = "encryption"
	confPolicy     = "policy"
	confACL        = "acl"
	confCORS       = "cors"
	confTagging    = "tagging"
	confLifecycle  = "lifecycle"
)

var confKinds = []string{confEncryption, confPolicy, confACL, confCORS, confTagging, confNotification, confLifecycle, confReplication, confReplTargets}

// confTTL bounds how stale another node's change can be; a change made
// through this node is visible at once.
const confTTL = 5 * time.Second

// maxConfCacheEntries bounds the document cache.
const maxConfCacheEntries = 10000

// maxConfSize bounds a stored document.
const maxConfSize = 256 << 10

type confEntry struct {
	raw     []byte
	parsed  any
	expires time.Time
}

type confCache struct {
	mu sync.Mutex
	m  map[string]confEntry
}

func confKey(bucket, kind string) string { return bucket + "\x00" + kind }

func (c *confCache) get(bucket, kind string) (confEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[confKey(bucket, kind)]
	if !ok || time.Now().After(e.expires) {
		return confEntry{}, false
	}
	return e, true
}

func (c *confCache) put(bucket, kind string, e confEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]confEntry{}
	}
	e.expires = time.Now().Add(confTTL)
	if len(c.m) >= maxConfCacheEntries {
		// Bound memory against requests naming arbitrary buckets.
		c.m = map[string]confEntry{}
	}
	c.m[confKey(bucket, kind)] = e
}

func (c *confCache) drop(bucket, kind string) {
	c.mu.Lock()
	delete(c.m, confKey(bucket, kind))
	c.mu.Unlock()
}

// confRaw returns a bucket's document of the given kind, or nil if it has
// none. Absence is cached too.
func (s *Server) confRaw(ctx context.Context, bucket, kind string) ([]byte, error) {
	e, err := s.confLoad(ctx, bucket, kind, nil)
	return e.raw, err
}

// confParsed returns the parsed form of a bucket's document, parsing once
// per cache fill. It returns nil, nil when there is no document.
func (s *Server) confParsed(ctx context.Context, bucket, kind string, parse func([]byte) (any, error)) (any, error) {
	e, err := s.confLoad(ctx, bucket, kind, parse)
	return e.parsed, err
}

func (s *Server) confLoad(ctx context.Context, bucket, kind string, parse func([]byte) (any, error)) (confEntry, error) {
	if e, ok := s.conf.get(bucket, kind); ok && (parse == nil || e.raw == nil || e.parsed != nil) {
		return e, nil
	}
	rc, _, err := s.st.GetObject(ctx, sysBucket, bucket+"/"+kind, storage.GetOptions{})
	switch {
	case errors.Is(err, storage.ErrObjectNotFound), errors.Is(err, storage.ErrBucketNotFound):
		e := confEntry{}
		s.conf.put(bucket, kind, e)
		return e, nil
	case err != nil:
		return confEntry{}, err
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, maxConfSize))
	if err != nil {
		return confEntry{}, err
	}
	e := confEntry{raw: data}
	if parse != nil {
		if e.parsed, err = parse(data); err != nil {
			return confEntry{}, err
		}
	}
	s.conf.put(bucket, kind, e)
	return e, nil
}

// confPut stores a document, creating the system bucket on first use.
func (s *Server) confPut(ctx context.Context, bucket, kind string, data []byte) error {
	err := s.st.MakeBucket(ctx, sysBucket, storage.MakeBucketOptions{})
	if err != nil && !errors.Is(err, storage.ErrBucketExists) {
		return err
	}
	_, err = s.st.PutObject(ctx, sysBucket, bucket+"/"+kind, bytes.NewReader(data), int64(len(data)), storage.PutOptions{})
	s.conf.drop(bucket, kind)
	if err == nil {
		s.siteConfChanged(ctx, bucket, kind, data, false)
	}
	return err
}

// confDrop removes one document, if present.
func (s *Server) confDrop(ctx context.Context, bucket, kind string) {
	_, err := s.st.DeleteObject(ctx, sysBucket, bucket+"/"+kind, storage.DeleteOptions{})
	if err != nil && !errors.Is(err, storage.ErrObjectNotFound) && !errors.Is(err, storage.ErrBucketNotFound) {
		s.log.Warn("could not remove bucket configuration", "bucket", bucket, "kind", kind, "err", err)
	}
	s.conf.drop(bucket, kind)
	s.siteConfChanged(ctx, bucket, kind, nil, true)
}

// confDropAll removes every document of a bucket.
func (s *Server) confDropAll(ctx context.Context, bucket string) {
	for _, k := range confKinds {
		s.confDrop(ctx, bucket, k)
	}
}
