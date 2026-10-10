//go:build unix

package fsutil

import (
	"errors"
	"os"
	"syscall"
)

// LockFile takes a non-blocking exclusive advisory lock on f, held until f
// is closed. It is how a backend keeps two processes off one directory.
func LockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}

// DiskUsage reports total and available bytes of the filesystem at path.
func DiskUsage(path string) (total, free uint64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, err
	}
	bs := uint64(st.Bsize)
	return uint64(st.Blocks) * bs, uint64(st.Bavail) * bs, nil
}

// IsNoSpace reports whether err means the filesystem is full.
func IsNoSpace(err error) bool { return errors.Is(err, syscall.ENOSPC) }

// IsPruneRace reports whether err is what creating a path inside a
// directory that a concurrent cleanup is removing looks like: ENOENT on
// Linux, and EINVAL on macOS when the parent is being unlinked.
func IsPruneRace(err error) bool {
	return errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.EINVAL)
}
