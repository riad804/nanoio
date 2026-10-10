package disk_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"nanoio/internal/storage/xl/disk"
	"nanoio/internal/storage/xl/disk/disktest"
)

var bg = context.Background()

func formatted(t *testing.T, root string, opts disk.LocalOptions) *disk.Local {
	t.Helper()
	d, err := disk.NewLocal(root, opts)
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.Open(bg, true)
	if !errors.Is(err, disk.ErrUnformatted) {
		t.Fatalf("Open of a fresh directory = %v, want ErrUnformatted", err)
	}
	if err := d.WriteFormat(bg, &disk.Format{Format: disk.FormatVersion, DeploymentID: "dep", Index: 0,
		DataBlocks: 2, ParityBlocks: 1, Created: time.Now()}); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestLocalContract(t *testing.T) {
	disktest.Run(t, func(t *testing.T) (disk.Disk, func()) {
		d := formatted(t, filepath.Join(t.TempDir(), "drive"), disk.LocalOptions{})
		return d, func() { d.Close() }
	})
}

func TestLocalLifecycle(t *testing.T) {
	t.Run("blank, then formatted, then reopened", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "d")
		d := formatted(t, root, disk.LocalOptions{})
		if !d.Ready(bg) {
			t.Fatal("not ready after WriteFormat")
		}
		d.Close()
		d2, _ := disk.NewLocal(root, disk.LocalOptions{})
		f, err := d2.Open(bg, true)
		if err != nil || f.DeploymentID != "dep" || f.DataBlocks != 2 || f.ParityBlocks != 1 {
			t.Fatalf("reopen = %+v, %v", f, err)
		}
		if !d2.Ready(bg) {
			t.Error("a formatted drive is not ready after Open")
		}
		d2.Close()
	})
	t.Run("a blank drive is held but not ready until formatted", func(t *testing.T) {
		d, _ := disk.NewLocal(filepath.Join(t.TempDir(), "d"), disk.LocalOptions{})
		if _, err := d.Open(bg, true); !errors.Is(err, disk.ErrUnformatted) {
			t.Fatal(err)
		}
		defer d.Close()
		// Concurrent readiness probes (the background repair goroutine
		// does exactly this) must not tear down the pending drive.
		for i := 0; i < 50; i++ {
			if d.Ready(bg) {
				t.Fatal("blank drive reported ready")
			}
		}
		if err := d.WriteFormat(bg, &disk.Format{Format: disk.FormatVersion, DeploymentID: "x"}); err != nil {
			t.Fatal(err)
		}
		if !d.Ready(bg) {
			t.Error("probing a blank drive broke its formatting")
		}
	})
	t.Run("a populated unformatted directory is never adopted", func(t *testing.T) {
		root := t.TempDir()
		os.WriteFile(filepath.Join(root, "precious.txt"), []byte("mine"), 0o644)
		d, _ := disk.NewLocal(root, disk.LocalOptions{})
		if _, err := d.Open(bg, true); !errors.Is(err, disk.ErrForeign) {
			t.Errorf("Open = %v, want ErrForeign", err)
		}
		if _, err := os.Stat(filepath.Join(root, ".nanoio.sys", "format.json")); err == nil {
			t.Error("a foreign directory was formatted")
		}
		if b, _ := os.ReadFile(filepath.Join(root, "precious.txt")); string(b) != "mine" {
			t.Error("foreign data touched")
		}
	})
	t.Run("a vanished directory is not recreated unless asked", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "gone")
		d, _ := disk.NewLocal(root, disk.LocalOptions{})
		if _, err := d.Open(bg, false); !errors.Is(err, disk.ErrOffline) {
			t.Errorf("Open(create=false) = %v, want ErrOffline", err)
		}
		if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("Open(create=false) created %s", root)
		}
	})
	t.Run("a second owner is refused", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "d")
		d := formatted(t, root, disk.LocalOptions{})
		defer d.Close()
		d2, _ := disk.NewLocal(root, disk.LocalOptions{})
		if _, err := d2.Open(bg, true); !errors.Is(err, disk.ErrInUse) {
			t.Errorf("Open = %v, want ErrInUse", err)
		}
	})
	t.Run("a drive that disappears stops being ready", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "d")
		d := formatted(t, root, disk.LocalOptions{})
		defer d.Close()
		os.RemoveAll(root)
		if d.Ready(bg) {
			t.Error("a removed drive still reports ready")
		}
		if _, err := d.ReadMeta(bg, "b", "k"); !errors.Is(err, disk.ErrOffline) {
			t.Errorf("ReadMeta = %v, want ErrOffline", err)
		}
	})
	t.Run("capacity", func(t *testing.T) {
		d := formatted(t, filepath.Join(t.TempDir(), "d"), disk.LocalOptions{})
		defer d.Close()
		if info, err := d.Info(bg); err != nil || info.Total == 0 || info.Free > info.Total {
			t.Errorf("Info = %+v, %v", info, err)
		}
	})
}

func TestShardFormatMath(t *testing.T) {
	tests := []struct {
		part, block int64
		k           int
		want        int64
	}{
		{0, 64, 2, 0},
		{1, 64, 2, 32 + 1},
		{64, 64, 2, 32 + 32},
		{65, 64, 2, 32 + 32 + 32 + 1},
		{128, 64, 4, 2 * (32 + 16)},
		{100, 64, 3, (32 + 22) + (32 + 12)},
	}
	for _, tt := range tests {
		if got := disk.ShardFileSize(tt.part, tt.block, tt.k); got != tt.want {
			t.Errorf("ShardFileSize(%d,%d,%d) = %d, want %d", tt.part, tt.block, tt.k, got, tt.want)
		}
	}
}
