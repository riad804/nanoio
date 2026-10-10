// Package fsutil holds the filesystem primitives shared by the fs and xl
// backends: durable file writes, directory fsync, and root-confined path
// joining.
package fsutil

import (
	"errors"
	"fmt"
	"io"
	iofs "io/fs"
	"os"
	"path/filepath"
	"strings"
)

// ErrEscapesRoot means a joined path resolved outside its root.
var ErrEscapesRoot = errors.New("fsutil: path escapes root")

// SafeJoin joins elems under root and fails if the cleaned result is not
// root or inside it, or if any element contains NUL. It is a lexical check:
// it does not resolve symlinks.
func SafeJoin(root string, elems ...string) (string, error) {
	for _, e := range elems {
		if strings.IndexByte(e, 0) >= 0 {
			return "", fmt.Errorf("%w: NUL in path element", ErrEscapesRoot)
		}
	}
	p := filepath.Join(append([]string{root}, elems...)...)
	rel, err := filepath.Rel(root, p)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: %q", ErrEscapesRoot, filepath.Join(elems...))
	}
	return p, nil
}

// SyncDir fsyncs a directory so that renames and creates inside it are
// durable.
func SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	if err := d.Sync(); err != nil {
		d.Close()
		return err
	}
	return d.Close()
}

// WriteFileSync creates path exclusively, writes data, fsyncs and closes it.
// On failure the partial file is removed.
func WriteFileSync(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(path)
		return err
	}
	return nil
}

// MkdirAllSync is os.MkdirAll that also fsyncs the parent of every
// directory it created, so the new entries survive a crash. dir must be
// root or inside it; root is assumed to exist.
func MkdirAllSync(root, dir string, perm os.FileMode) error {
	var created []string
	for p := dir; p != root && p != filepath.Dir(p); p = filepath.Dir(p) {
		_, err := os.Stat(p)
		if err == nil {
			break
		}
		if !errors.Is(err, iofs.ErrNotExist) {
			return err
		}
		created = append(created, p)
	}
	if err := os.MkdirAll(dir, perm); err != nil {
		return err
	}
	for _, p := range created {
		if err := SyncDir(filepath.Dir(p)); err != nil {
			return err
		}
	}
	return nil
}

// CopySync copies r to a new file at path with fsync, returning bytes
// written. The file is removed on failure.
func CopySync(path string, r io.Reader, perm os.FileMode) (int64, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(f, r)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(path)
	}
	return n, err
}
