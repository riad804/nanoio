package fsutil

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSafeJoin(t *testing.T) {
	root := filepath.Join(string(filepath.Separator), "data")
	tests := []struct {
		name  string
		elems []string
		want  string // "" = must fail
	}{
		{"simple", []string{"b", "k"}, "/data/b/k"},
		{"no elems", nil, "/data"},
		{"inner dots cleaned", []string{"b", "a/../k"}, "/data/b/k"},
		{"parent escape", []string{".."}, ""},
		{"deep escape", []string{"b", "../../etc"}, ""},
		{"sibling prefix", []string{"../data2"}, ""},
		{"NUL", []string{"b\x00"}, ""},
		{"absolute elem stays inside", []string{"/etc/passwd"}, "/data/etc/passwd"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SafeJoin(root, tt.elems...)
			if tt.want == "" {
				if !errors.Is(err, ErrEscapesRoot) {
					t.Errorf("SafeJoin = %q, %v; want ErrEscapesRoot", got, err)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Errorf("SafeJoin = %q, %v; want %q", got, err, tt.want)
			}
		})
	}
}

func TestWriteFileSync(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"small", []byte("hello")},
		{"large", bytes.Repeat([]byte("x"), 1<<20)},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := filepath.Join(dir, strings.Repeat("f", i+1))
			if err := WriteFileSync(p, tt.data, 0o644); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(p)
			if err != nil || !bytes.Equal(got, tt.data) {
				t.Errorf("read back mismatch: err=%v len=%d", err, len(got))
			}
			if err := WriteFileSync(p, []byte("again"), 0o644); !errors.Is(err, fs.ErrExist) {
				t.Errorf("second write error = %v, want ErrExist (O_EXCL)", err)
			}
			if again, _ := os.ReadFile(p); !bytes.Equal(again, tt.data) {
				t.Error("failed second write damaged the existing file")
			}
		})
	}
	t.Run("missing parent", func(t *testing.T) {
		if err := WriteFileSync(filepath.Join(dir, "no", "such", "f"), nil, 0o644); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("error = %v, want ErrNotExist", err)
		}
	})
}

func TestMkdirAllSync(t *testing.T) {
	root := t.TempDir()
	tests := []struct {
		name string
		dir  string
	}{
		{"one level", "a"},
		{"deep", "a/b/c/d"},
		{"already exists", "a/b"},
		{"sibling of existing", "a/x"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := filepath.Join(root, filepath.FromSlash(tt.dir))
			if err := MkdirAllSync(root, p, 0o755); err != nil {
				t.Fatal(err)
			}
			if st, err := os.Stat(p); err != nil || !st.IsDir() {
				t.Errorf("dir not created: %v", err)
			}
		})
	}
	if err := SyncDir(filepath.Join(root, "missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("SyncDir(missing) = %v, want ErrNotExist", err)
	}
}

func TestCopySync(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	n, err := CopySync(p, strings.NewReader("abcdef"), 0o644)
	if err != nil || n != 6 {
		t.Fatalf("CopySync = %d, %v", n, err)
	}
	if got, _ := os.ReadFile(p); string(got) != "abcdef" {
		t.Errorf("content = %q", got)
	}
	failing := &errReader{}
	p2 := filepath.Join(dir, "g")
	if _, err := CopySync(p2, failing, 0o644); err == nil {
		t.Fatal("expected read error")
	}
	if _, err := os.Stat(p2); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("partial file left behind: %v", err)
	}
}

type errReader struct{}

func (*errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }
