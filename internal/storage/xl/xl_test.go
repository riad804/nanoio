package xl

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nanoio/internal/bucket/nslock"
	"nanoio/internal/storage"
	"nanoio/internal/storage/storagetest"
)

var (
	bg      = context.Background()
	discard = slog.New(slog.NewTextHandler(io.Discard, nil))
)

// layout names an erasure configuration under test.
type layout struct {
	name      string
	drives    int
	parity    int
	blockSize int64
}

var layouts = []layout{
	{"4+4", 8, 4, 0},
	{"2+1", 3, 1, 64 << 10},
	{"6+2", 8, 2, 128 << 10},
	{"1+1", 2, 1, 4 << 10},
}

func driveDirs(t *testing.T, n int) []string {
	t.Helper()
	root := t.TempDir()
	dirs := make([]string, n)
	for i := range dirs {
		dirs[i] = filepath.Join(root, fmt.Sprintf("drive%02d", i))
	}
	return dirs
}

// newXL builds a set of n drives with the given parity.
func newXL(t *testing.T, l layout, mut ...func(*Options)) (*XL, []string) {
	t.Helper()
	dirs := driveDirs(t, l.drives)
	return openXL(t, dirs, l, mut...), dirs
}

func openXL(t *testing.T, dirs []string, l layout, mut ...func(*Options)) *XL {
	t.Helper()
	opts := Options{
		Locker: nslock.New(10 * time.Second), Logger: discard,
		ParityBlocks: l.parity, BlockSize: l.blockSize,
		ScanInterval: -1, // maintenance only when a test asks
		// Tests assert on every drive right after a write; only the
		// resilience tests turn the straggler policy on.
		StragglerGrace: time.Minute,
	}
	for _, m := range mut {
		m(&opts)
	}
	x, err := New(dirs, opts)
	if err != nil {
		t.Fatalf("New(%s): %v", l.name, err)
	}
	t.Cleanup(func() { x.Close() })
	return x
}

func TestConformance(t *testing.T) {
	for _, l := range layouts {
		t.Run(l.name, func(t *testing.T) {
			storagetest.Run(t, func(t *testing.T, locker storage.Locker) storage.StorageAPI {
				dirs := driveDirs(t, l.drives)
				x, err := New(dirs, Options{Locker: locker, Logger: discard, ParityBlocks: l.parity,
					BlockSize: l.blockSize, ScanInterval: -1, StragglerGrace: time.Minute})
				if err != nil {
					t.Fatal(err)
				}
				return x
			})
		})
	}
}

func TestVersionedConformance(t *testing.T) {
	for _, l := range layouts {
		t.Run(l.name, func(t *testing.T) {
			storagetest.RunVersioned(t, func(t *testing.T, locker storage.Locker) storage.StorageAPI {
				dirs := driveDirs(t, l.drives)
				x, err := New(dirs, Options{Locker: locker, Logger: discard, ParityBlocks: l.parity,
					BlockSize: l.blockSize, ScanInterval: -1, StragglerGrace: time.Minute})
				if err != nil {
					t.Fatal(err)
				}
				return x
			})
		})
	}
}

func TestObjectLockConformance(t *testing.T) {
	for _, l := range layouts {
		t.Run(l.name, func(t *testing.T) {
			storagetest.RunObjectLock(t, func(t *testing.T, locker storage.Locker) storage.StorageAPI {
				dirs := driveDirs(t, l.drives)
				x, err := New(dirs, Options{Locker: locker, Logger: discard, ParityBlocks: l.parity,
					BlockSize: l.blockSize, ScanInterval: -1, StragglerGrace: time.Minute})
				if err != nil {
					t.Fatal(err)
				}
				return x
			})
		})
	}
}

func put(t *testing.T, x *XL, bucket, key, body string) storage.ObjectInfo {
	t.Helper()
	info, err := x.PutObject(bg, bucket, key, strings.NewReader(body), int64(len(body)), storage.PutOptions{})
	if err != nil {
		t.Fatalf("PutObject(%s/%s): %v", bucket, key, err)
	}
	return info
}

func read(t *testing.T, x *XL, bucket, key string) (string, error) {
	t.Helper()
	rc, _, err := x.GetObject(bg, bucket, key, storage.GetOptions{})
	if err != nil {
		return "", err
	}
	defer rc.Close()
	b, err := io.ReadAll(rc)
	return string(b), err
}

func mustRead(t *testing.T, x *XL, bucket, key string) string {
	t.Helper()
	got, err := read(t, x, bucket, key)
	if err != nil {
		t.Fatalf("read %s/%s: %v", bucket, key, err)
	}
	return got
}

func mkbucket(t *testing.T, x *XL, name string) {
	t.Helper()
	if err := x.MakeBucket(bg, name, storage.MakeBucketOptions{}); err != nil {
		t.Fatal(err)
	}
}

func md5hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func contextWithCancel() (context.Context, context.CancelFunc) { return context.WithCancel(bg) }
