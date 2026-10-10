package cluster

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"nanoio/internal/bucket/nslock"
	"nanoio/internal/storage"
	"nanoio/internal/storage/storagetest"
	"nanoio/internal/storage/xl"
)

var (
	bg      = context.Background()
	discard = slog.New(slog.NewTextHandler(io.Discard, nil))
)

// newSet opens an xl set of 3 drives (2+1) under root/name.
func newSet(t *testing.T, root, name string, locker storage.Locker) *xl.XL {
	t.Helper()
	dirs := make([]string, 3)
	for i := range dirs {
		dirs[i] = filepath.Join(root, name, fmt.Sprintf("d%d", i))
	}
	x, err := xl.New(dirs, xl.Options{Locker: locker, Logger: discard, ParityBlocks: 1,
		BlockSize: 16 << 10, ScanInterval: -1, DeploymentID: "cl-" + name, StragglerGrace: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	return x
}

type topo struct {
	root   string
	locker storage.Locker
}

func (tp topo) pools(t *testing.T, spec ...[]string) []Pool {
	var out []Pool
	for pi, names := range spec {
		p := Pool{Name: fmt.Sprintf("pool%d", pi)}
		for _, n := range names {
			p.Sets = append(p.Sets, newSet(t, tp.root, n, tp.locker))
		}
		out = append(out, p)
	}
	return out
}

func open(t *testing.T, tp topo, opts Options, pools []Pool) *Store {
	t.Helper()
	opts.Logger = discard
	if opts.BucketSync == 0 {
		opts.BucketSync = -1
	}
	s, err := New(pools, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func newTopo(t *testing.T) topo {
	return topo{root: t.TempDir(), locker: nslock.New(10 * time.Second)}
}

func put(t *testing.T, s storage.StorageAPI, b, k, body string) {
	t.Helper()
	if _, err := s.PutObject(bg, b, k, strings.NewReader(body), int64(len(body)), storage.PutOptions{}); err != nil {
		t.Fatalf("put %s/%s: %v", b, k, err)
	}
}

func get(t *testing.T, s storage.StorageAPI, b, k string) (string, error) {
	t.Helper()
	rc, _, err := s.GetObject(bg, b, k, storage.GetOptions{})
	if err != nil {
		return "", err
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	return string(data), err
}

// setHolding returns which sets (by index) hold the object.
func setHolding(s *Store, b, k string) []int {
	var out []int
	for i, set := range s.sets {
		if _, err := set.StatObject(bg, b, k, storage.GetOptions{}); err == nil {
			out = append(out, i)
		}
	}
	return out
}

func TestConformance(t *testing.T) {
	storagetest.Run(t, func(t *testing.T, locker storage.Locker) storage.StorageAPI {
		tp := topo{root: t.TempDir(), locker: locker}
		return open(t, tp, Options{}, tp.pools(t, []string{"a", "b"}, []string{"c"}))
	})
}

func TestPlacementSpreadsAndRoutes(t *testing.T) {
	tp := newTopo(t)
	s := open(t, tp, Options{}, tp.pools(t, []string{"a", "b", "c"}))
	if err := s.MakeBucket(bg, "spread", storage.MakeBucketOptions{}); err != nil {
		t.Fatal(err)
	}
	counts := map[int]int{}
	for i := 0; i < 60; i++ {
		k := fmt.Sprintf("obj-%03d", i)
		put(t, s, "spread", k, k)
		h := setHolding(s, "spread", k)
		if len(h) != 1 {
			t.Fatalf("%s is on sets %v, want exactly one", k, h)
		}
		counts[h[0]]++
	}
	for i := 0; i < 3; i++ {
		if counts[i] < 8 {
			t.Errorf("set %d holds only %d of 60 objects: %v", i, counts[i], counts)
		}
	}
	for i := 0; i < 60; i++ {
		k := fmt.Sprintf("obj-%03d", i)
		if got, err := get(t, s, "spread", k); err != nil || got != k {
			t.Fatalf("get %s = %q, %v", k, got, err)
		}
	}
}

func TestListMergesAcrossSets(t *testing.T) {
	tp := newTopo(t)
	s := open(t, tp, Options{}, tp.pools(t, []string{"a", "b", "c"}))
	s.MakeBucket(bg, "listing", storage.MakeBucketOptions{})
	var want []string
	for i := 0; i < 45; i++ {
		k := fmt.Sprintf("dir%d/file-%02d", i%4, i)
		put(t, s, "listing", k, "x")
		want = append(want, k)
	}
	put(t, s, "listing", "top-level", "x")
	want = append(want, "top-level")
	sort.Strings(want)

	t.Run("flat, paged", func(t *testing.T) {
		var got []string
		marker := ""
		for pages := 0; ; pages++ {
			if pages > 20 {
				t.Fatal("too many pages")
			}
			res, err := s.ListObjects(bg, "listing", storage.ListOptions{Marker: marker, MaxKeys: 7})
			if err != nil {
				t.Fatal(err)
			}
			for _, o := range res.Objects {
				got = append(got, o.Name)
			}
			if !res.IsTruncated {
				break
			}
			if res.NextMarker == "" || len(res.Objects)+len(res.Prefixes) != 7 {
				t.Fatalf("truncated page of %d entries with marker %q", len(res.Objects), res.NextMarker)
			}
			marker = res.NextMarker
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("paged listing differs:\n got %v\nwant %v", got, want)
		}
	})
	t.Run("delimiter merges prefixes from every set", func(t *testing.T) {
		res, err := s.ListObjects(bg, "listing", storage.ListOptions{Delimiter: "/"})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(res.Prefixes, ",") != "dir0/,dir1/,dir2/,dir3/" || len(res.Objects) != 1 || res.Objects[0].Name != "top-level" {
			t.Errorf("prefixes %v objects %v", res.Prefixes, res.Objects)
		}
	})
	t.Run("prefix and start-after", func(t *testing.T) {
		res, err := s.ListObjects(bg, "listing", storage.ListOptions{Prefix: "dir2/", StartAfter: "dir2/file-20"})
		if err != nil {
			t.Fatal(err)
		}
		for _, o := range res.Objects {
			if !strings.HasPrefix(o.Name, "dir2/") || o.Name <= "dir2/file-20" {
				t.Errorf("unexpected %s", o.Name)
			}
		}
		if len(res.Objects) == 0 {
			t.Error("nothing listed")
		}
	})
}

// slowSet makes ListObjects misbehave.
type slowSet struct {
	Set
	delay time.Duration
	err   error
}

func (s slowSet) ListObjects(ctx context.Context, b string, o storage.ListOptions) (storage.ListResult, error) {
	if s.err != nil {
		return storage.ListResult{}, s.err
	}
	select {
	case <-time.After(s.delay):
	case <-ctx.Done():
		return storage.ListResult{}, ctx.Err()
	}
	return s.Set.ListObjects(ctx, b, o)
}

func TestListFailureAndTimeoutPolicy(t *testing.T) {
	setup := func(t *testing.T, bad func(Set) Set, opts Options) (*Store, int) {
		tp := newTopo(t)
		pools := tp.pools(t, []string{"a", "b", "c"})
		plain := open(t, tp, Options{}, append([]Pool(nil), pools...))
		plain.MakeBucket(bg, "pol", storage.MakeBucketOptions{})
		perSet := map[int]int{}
		for i := 0; i < 30; i++ {
			k := fmt.Sprintf("k%02d", i)
			put(t, plain, "pol", k, k)
			perSet[setHolding(plain, "pol", k)[0]]++
		}
		pools[0].Sets[1] = bad(pools[0].Sets[1])
		s, err := New(pools, withDefaults(opts))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		return s, 30 - perSet[1]
	}

	t.Run("a failing set fails the listing", func(t *testing.T) {
		s, _ := setup(t, func(x Set) Set { return slowSet{Set: x, err: errors.New("disk on fire")} }, Options{})
		_, err := s.ListObjects(bg, "pol", storage.ListOptions{})
		if !errors.Is(err, storage.ErrBackendUnavailable) {
			t.Errorf("err = %v, want ErrBackendUnavailable", err)
		}
	})
	t.Run("a slow set times out and fails the listing", func(t *testing.T) {
		s, _ := setup(t, func(x Set) Set { return slowSet{Set: x, delay: 5 * time.Second} },
			Options{ListTimeout: 150 * time.Millisecond})
		start := time.Now()
		_, err := s.ListObjects(bg, "pol", storage.ListOptions{})
		if !errors.Is(err, storage.ErrBackendUnavailable) {
			t.Errorf("err = %v, want ErrBackendUnavailable", err)
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Errorf("took %v; the per-set deadline was not applied", d)
		}
	})
	t.Run("partial listing is opt-in and marked", func(t *testing.T) {
		s, others := setup(t, func(x Set) Set { return slowSet{Set: x, err: errors.New("down")} },
			Options{AllowPartialList: true})
		res, err := s.ListObjects(bg, "pol", storage.ListOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if !res.Incomplete {
			t.Error("a partial result is not marked Incomplete")
		}
		if len(res.Objects) != others {
			t.Errorf("listed %d objects, the surviving sets hold %d", len(res.Objects), others)
		}
	})
	t.Run("a healthy listing is not marked incomplete", func(t *testing.T) {
		tp := newTopo(t)
		s := open(t, tp, Options{AllowPartialList: true}, tp.pools(t, []string{"a", "b"}))
		s.MakeBucket(bg, "okb", storage.MakeBucketOptions{})
		put(t, s, "okb", "k", "v")
		res, err := s.ListObjects(bg, "okb", storage.ListOptions{})
		if err != nil || res.Incomplete || len(res.Objects) != 1 {
			t.Errorf("res=%+v err=%v", res, err)
		}
	})
}

func withDefaults(o Options) Options {
	o.Logger = discard
	if o.BucketSync == 0 {
		o.BucketSync = -1
	}
	return o
}

func TestAddingAPool(t *testing.T) {
	tp := newTopo(t)
	one := open(t, tp, Options{}, tp.pools(t, []string{"a", "b"}))
	one.MakeBucket(bg, "grow", storage.MakeBucketOptions{})
	old := map[string]string{}
	for i := 0; i < 40; i++ {
		k := fmt.Sprintf("old-%02d", i)
		put(t, one, "grow", k, "v1-"+k)
		old[k] = "v1-" + k
	}
	one.Close()

	// The same sets plus a new pool, in the same order.
	two := open(t, tp, Options{}, tp.pools(t, []string{"a", "b"}, []string{"c", "d"}))
	if err := two.EnsureBuckets(bg); err != nil {
		t.Fatal(err)
	}
	for _, i := range []int{2, 3} {
		if ok, _ := two.sets[i].BucketExists(bg, "grow"); !ok {
			t.Errorf("bucket missing on new set %d", i)
		}
	}
	moved := 0
	for k, v := range old {
		if got, err := get(t, two, "grow", k); err != nil || got != v {
			t.Fatalf("existing object %s after the pool add: %q, %v", k, got, err)
		}
		if h := setHolding(two, "grow", k); len(h) != 1 || h[0] > 1 {
			t.Fatalf("existing object %s moved to sets %v; a pool add must not rebalance", k, h)
		}
		if two.ringSet("grow", k) > 1 {
			moved++
		}
	}
	if moved == 0 {
		t.Fatal("the new ring maps no old key to the new pool; the test would prove nothing")
	}
	// Overwriting an old object that the ring now maps elsewhere updates it
	// where it is, leaving no second copy.
	for k := range old {
		if two.ringSet("grow", k) > 1 {
			put(t, two, "grow", k, "v2-"+k)
			if h := setHolding(two, "grow", k); len(h) != 1 || h[0] > 1 {
				t.Fatalf("%s now on %v after an overwrite", k, h)
			}
			if got, _ := get(t, two, "grow", k); got != "v2-"+k {
				t.Fatalf("overwrite not visible: %q", got)
			}
			break
		}
	}
	// New keys are spread over all four sets.
	seen := map[int]bool{}
	for i := 0; i < 80; i++ {
		k := fmt.Sprintf("new-%02d", i)
		put(t, two, "grow", k, k)
		seen[setHolding(two, "grow", k)[0]] = true
	}
	if !seen[2] && !seen[3] {
		t.Error("no new object landed on the new pool")
	}
	// One listing covers everything, once.
	res, err := two.ListObjects(bg, "grow", storage.ListOptions{MaxKeys: 1000})
	if err != nil || len(res.Objects) != 120 {
		t.Fatalf("listed %d objects, %v; want 120", len(res.Objects), err)
	}
	// Deletes reach wherever the object is.
	for k := range old {
		if _, err := two.DeleteObject(bg, "grow", k, storage.DeleteOptions{}); err != nil {
			t.Fatal(err)
		}
		if _, err := get(t, two, "grow", k); !errors.Is(err, storage.ErrObjectNotFound) {
			t.Fatalf("%s after delete: %v", k, err)
		}
	}
}

func TestDrainPool(t *testing.T) {
	tp := newTopo(t)
	pools := tp.pools(t, []string{"a"}, []string{"b"})
	s := open(t, tp, Options{}, pools)
	s.MakeBucket(bg, "drn", storage.MakeBucketOptions{})
	ct := map[string]string{}
	for i := 0; i < 50; i++ {
		k := fmt.Sprintf("o-%02d", i)
		_, err := s.PutObject(bg, "drn", k, strings.NewReader("data-"+k), int64(len("data-"+k)),
			storage.PutOptions{ContentType: "text/x-" + k, UserDefined: map[string]string{"x-amz-meta-n": k}})
		if err != nil {
			t.Fatal(err)
		}
		ct[k] = "text/x-" + k
	}
	if h := countIn(s, "drn", 0); h == 0 {
		t.Fatal("nothing landed in pool 0")
	}
	s.Close()

	// Reopen with pool 0 draining.
	pools2 := tp.pools(t, []string{"a"}, []string{"b"})
	pools2[0].Draining = true
	d := open(t, tp, Options{}, pools2)

	if _, err := d.Drain(bg, 1); err == nil {
		t.Error("draining a pool that is not marked draining was allowed")
	}
	// A client overwrite of an object that lives in the draining pool
	// lands in the other pool and removes the old copy.
	var victim string
	for k := range ct {
		if h := setHolding(d, "drn", k); len(h) == 1 && h[0] == 0 {
			victim = k
			break
		}
	}
	if victim == "" {
		t.Fatal("no object in the draining pool")
	}
	put(t, d, "drn", victim, "fresh")
	if h := setHolding(d, "drn", victim); len(h) != 1 || h[0] != 1 {
		t.Errorf("overwritten object is on %v, want only the live pool", h)
	}
	delete(ct, victim)
	// If-None-Match must still see the object that is in the draining pool.
	var other string
	for k := range ct {
		if h := setHolding(d, "drn", k); len(h) == 1 && h[0] == 0 {
			other = k
			break
		}
	}
	_, err := d.PutObject(bg, "drn", other, strings.NewReader("x"), 1, storage.PutOptions{IfNoneMatch: "*"})
	if !errors.Is(err, storage.ErrPreconditionFailed) {
		t.Errorf("If-None-Match over an object in a draining pool = %v", err)
	}

	st, err := d.Drain(bg, 0)
	if err != nil {
		t.Fatal(err)
	}
	if st.Failed != 0 || st.Objects == 0 {
		t.Errorf("drain stats %+v", st)
	}
	if n := countIn(d, "drn", 0); n != 0 {
		t.Errorf("%d objects remain in the drained pool", n)
	}
	for k, want := range ct {
		got, err := get(t, d, "drn", k)
		if err != nil || got != "data-"+k {
			t.Fatalf("%s after drain: %q, %v", k, got, err)
		}
		info, _ := d.StatObject(bg, "drn", k, storage.GetOptions{})
		if info.ContentType != want || info.UserDefined["x-amz-meta-n"] != k {
			t.Errorf("%s lost its metadata: %+v", k, info)
		}
	}
	if got, _ := get(t, d, "drn", victim); got != "fresh" {
		t.Errorf("client write was overwritten by the drain: %q", got)
	}
	// A second run is a no-op.
	if st2, err := d.Drain(bg, 0); err != nil || st2.Objects != 0 {
		t.Errorf("second drain: %+v, %v", st2, err)
	}
}

func countIn(s *Store, bucket string, set int) int {
	res, err := s.sets[set].ListObjects(bg, bucket, storage.ListOptions{MaxKeys: 1000})
	if err != nil {
		return -1
	}
	return len(res.Objects)
}

func TestMultipartRoutesToTheOwningSet(t *testing.T) {
	tp := newTopo(t)
	s := open(t, tp, Options{}, tp.pools(t, []string{"a", "b", "c"}))
	s.MakeBucket(bg, "mpu", storage.MakeBucketOptions{})
	big := strings.Repeat("p", 6<<20)
	for i := 0; i < 6; i++ {
		key := fmt.Sprintf("big-%d", i)
		id, err := s.NewMultipartUpload(bg, "mpu", key, storage.PutOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(id, ".") {
			t.Fatalf("upload ID %q does not carry its set", id)
		}
		p1, err := s.PutObjectPart(bg, "mpu", key, id, 1, strings.NewReader(big), int64(len(big)), storage.PartOptions{})
		if err != nil {
			t.Fatal(err)
		}
		p2, err := s.PutObjectPart(bg, "mpu", key, id, 2, strings.NewReader("tail"), 4, storage.PartOptions{})
		if err != nil {
			t.Fatal(err)
		}
		ups, err := s.ListMultipartUploads(bg, "mpu", storage.ListUploadsOptions{})
		if err != nil || len(ups.Uploads) != 1 || ups.Uploads[0].UploadID != id {
			t.Fatalf("uploads = %+v, %v", ups.Uploads, err)
		}
		if _, err := s.CompleteMultipartUpload(bg, "mpu", key, id,
			[]storage.CompletePart{{Number: 1, ETag: p1.ETag}, {Number: 2, ETag: p2.ETag}}, storage.PutOptions{}); err != nil {
			t.Fatal(err)
		}
		if h := setHolding(s, "mpu", key); len(h) != 1 {
			t.Fatalf("%s on %v", key, h)
		}
		info, err := s.StatObject(bg, "mpu", key, storage.GetOptions{})
		if err != nil || info.Size != int64(len(big)+4) {
			t.Fatalf("stat %+v, %v", info, err)
		}
	}
	for _, bad := range []string{"", "nodot", "99.deadbeef", "x.y"} {
		_, err := s.PutObjectPart(bg, "mpu", "k", bad, 1, strings.NewReader("a"), 1, storage.PartOptions{})
		if !errors.Is(err, storage.ErrNoSuchUpload) {
			t.Errorf("upload ID %q = %v, want ErrNoSuchUpload", bad, err)
		}
	}
	id, _ := s.NewMultipartUpload(bg, "mpu", "gone", storage.PutOptions{})
	if err := s.AbortMultipartUpload(bg, "mpu", "gone", id); err != nil {
		t.Fatal(err)
	}
	if err := s.AbortMultipartUpload(bg, "mpu", "gone", id); !errors.Is(err, storage.ErrNoSuchUpload) {
		t.Errorf("second abort = %v", err)
	}
}

func TestBucketOpsAcrossSets(t *testing.T) {
	tp := newTopo(t)
	s := open(t, tp, Options{}, tp.pools(t, []string{"a", "b", "c"}))
	if err := s.MakeBucket(bg, "everywhere", storage.MakeBucketOptions{}); err != nil {
		t.Fatal(err)
	}
	for i := range s.sets {
		if ok, _ := s.sets[i].BucketExists(bg, "everywhere"); !ok {
			t.Errorf("set %d lacks the bucket", i)
		}
	}
	if err := s.MakeBucket(bg, "everywhere", storage.MakeBucketOptions{}); !errors.Is(err, storage.ErrBucketExists) {
		t.Errorf("second create = %v", err)
	}
	// A partial create (one set already has it) is completed.
	s.sets[1].DeleteBucket(bg, "everywhere", storage.DeleteBucketOptions{})
	if err := s.MakeBucket(bg, "everywhere", storage.MakeBucketOptions{}); err != nil {
		t.Errorf("completing a partial create: %v", err)
	}
	if ok, _ := s.sets[1].BucketExists(bg, "everywhere"); !ok {
		t.Error("the partial create was not completed")
	}
	// A bucket with an object in any set cannot be deleted, and the sets
	// that were already emptied get it back.
	put(t, s, "everywhere", "k", "v")
	if err := s.DeleteBucket(bg, "everywhere", storage.DeleteBucketOptions{}); !errors.Is(err, storage.ErrBucketNotEmpty) {
		t.Fatalf("delete of a non-empty bucket = %v", err)
	}
	for i := range s.sets {
		if ok, _ := s.sets[i].BucketExists(bg, "everywhere"); !ok {
			t.Errorf("set %d lost the bucket after a refused delete", i)
		}
	}
	s.DeleteObject(bg, "everywhere", "k", storage.DeleteOptions{})
	if err := s.DeleteBucket(bg, "everywhere", storage.DeleteBucketOptions{}); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.BucketExists(bg, "everywhere"); ok {
		t.Error("bucket survived")
	}
	bs, _ := s.ListBuckets(bg)
	if len(bs) != 0 {
		t.Errorf("buckets = %v", bs)
	}
}

func TestEveryPoolDrainingRefusesWrites(t *testing.T) {
	tp := newTopo(t)
	pools := tp.pools(t, []string{"a"})
	pools[0].Draining = true
	s := open(t, tp, Options{}, pools)
	s.MakeBucket(bg, "none", storage.MakeBucketOptions{})
	_, err := s.PutObject(bg, "none", "k", strings.NewReader("v"), 1, storage.PutOptions{})
	if !errors.Is(err, ErrNoPlacement) {
		t.Errorf("err = %v, want ErrNoPlacement", err)
	}
}
