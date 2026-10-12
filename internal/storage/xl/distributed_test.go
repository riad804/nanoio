package xl

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nanoio/internal/bucket/nslock"
	"nanoio/internal/cluster/faultnet"
	"nanoio/internal/cluster/rpc"
	"nanoio/internal/cluster/rpcauth"
	"nanoio/internal/storage"
	"nanoio/internal/storage/storagetest"
	"nanoio/internal/storage/xl/disk"
	"nanoio/internal/storage/xl/disk/remote"
)

// threeNodes builds three nodes with two drives each. The XL under test
// runs on n1: its own drives are local, n2's and n3's are remote.
type threeNodes struct {
	net  *faultnet.Network
	x    *XL
	dirs map[string][]string // node -> drive dirs
}

func newThreeNodes(t *testing.T, lockers ...storage.Locker) *threeNodes {
	return newThreeNodesWith(t, nil, lockers...)
}

// newThreeNodesWith lets a test adjust the set's options and the remote
// drives' behaviour.
func newThreeNodesWith(t *testing.T, mut func(*Options), lockers ...storage.Locker) *threeNodes {
	t.Helper()
	keys, err := rpcauth.NewKeyring("distributed-test-secret-0123456")
	if err != nil {
		t.Fatal(err)
	}
	tn := &threeNodes{net: faultnet.New(), dirs: map[string][]string{}}
	peers := map[string]string{"n1": "n1:9000", "n2": "n2:9000", "n3": "n3:9000"}
	root := t.TempDir()
	locals := map[string]map[string]disk.Disk{}
	for _, id := range []string{"n1", "n2", "n3"} {
		locals[id] = map[string]disk.Disk{}
		for j := 0; j < 2; j++ {
			dir := filepath.Join(root, id, fmt.Sprintf("d%d", j))
			l, err := disk.NewLocal(dir, disk.LocalOptions{})
			if err != nil {
				t.Fatal(err)
			}
			locals[id][dir] = l
			t.Cleanup(func() { l.Close() })
			tn.dirs[id] = append(tn.dirs[id], dir)
		}
		srv := remote.NewServer(locals[id], 0)
		rs := rpc.NewServer(rpc.ServerConfig{Self: id, Keys: keys, Encode: remote.EncodeError,
			Known: func(string) bool { return true }})
		srv.Register(rs)
		tn.net.Register(peers[id], rs)
		t.Cleanup(srv.Close)
	}
	client, err := rpc.NewClient(rpc.Config{Self: "n1", Keys: keys, Peers: peers, HTTP: tn.net.Client("n1:9000")})
	if err != nil {
		t.Fatal(err)
	}
	var disks []disk.Disk
	for _, id := range []string{"n1", "n2", "n3"} {
		for _, dir := range tn.dirs[id] {
			if id == "n1" {
				disks = append(disks, locals[id][dir])
			} else {
				disks = append(disks, remote.New(client, id, dir, remote.Options{
					OKFor: 5 * time.Millisecond, DownFor: 5 * time.Millisecond, OpTimeout: 2 * time.Second}))
			}
		}
	}
	var locker storage.Locker = nslock.New(5 * time.Second)
	if len(lockers) > 0 {
		locker = lockers[0]
	}
	opts := Options{Locker: locker, Logger: discard,
		ParityBlocks: 2, BlockSize: 4 << 10, ScanInterval: -1, DeploymentID: "dist-test", StragglerGrace: time.Minute}
	if mut != nil {
		mut(&opts)
	}
	x, err := NewWithDisks(bg, disks, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { x.Close() })
	tn.x = x
	return tn
}

func settle() { time.Sleep(15 * time.Millisecond) } // outlast the remote health window

func TestDistributedSet(t *testing.T) {
	t.Run("conformance over mixed local and remote drives", func(t *testing.T) {
		storagetest.Run(t, func(t *testing.T, locker storage.Locker) storage.StorageAPI {
			return newThreeNodes(t, locker).x
		})
	})

	t.Run("versioned objects over mixed local and remote drives", func(t *testing.T) {
		storagetest.RunVersioned(t, func(t *testing.T, locker storage.Locker) storage.StorageAPI {
			return newThreeNodes(t, locker).x
		})
	})

	t.Run("object lock over mixed local and remote drives", func(t *testing.T) {
		storagetest.RunObjectLock(t, func(t *testing.T, locker storage.Locker) storage.StorageAPI {
			return newThreeNodes(t, locker).x
		})
	})

	t.Run("a lost node costs neither reads nor writes; heal brings it back", func(t *testing.T) {
		tn := newThreeNodes(t)
		x := tn.x
		mkbucket(t, x, "dist")
		body := strings.Repeat("distributed-object-", 2000)
		put(t, x, "dist", "before", body)

		tn.net.Crash("n3:9000")
		settle()
		if got := mustRead(t, x, "dist", "before"); got != body {
			t.Fatal("read during node loss differs")
		}
		put(t, x, "dist", "during", body+"!") // 4 of 6 drives: write quorum K=4

		tn.net.Restart("n3:9000")
		waitOnline(t, x, 6)
		stats, err := x.Scan(bg, true)
		if err != nil {
			t.Fatal(err)
		}
		if stats.ShardsHealed == 0 {
			t.Error("the scan found nothing to repair on the returned node")
		}
		// Every object is whole on every drive again.
		for _, key := range []string{"before", "during"} {
			eventuallyHealthy(t, x, "dist", key)
		}
	})

	t.Run("losing two nodes loses availability, not data", func(t *testing.T) {
		tn := newThreeNodes(t)
		x := tn.x
		mkbucket(t, x, "dist")
		put(t, x, "dist", "k", "v")
		tn.net.Partition([]string{"n1:9000"}, []string{"n2:9000"}, []string{"n3:9000"})
		settle()
		_, err := x.PutObject(bg, "dist", "k2", strings.NewReader("v2"), 2, storage.PutOptions{})
		if !errors.Is(err, storage.ErrBackendUnavailable) {
			t.Errorf("write with 2 of 6 drives = %v, want ErrBackendUnavailable", err)
		}
		if _, err := read(t, x, "dist", "k"); err == nil {
			t.Error("a read succeeded with fewer than K drives")
		}
		tn.net.Heal()
		waitOnline(t, x, 6)
		if got := mustRead(t, x, "dist", "k"); got != "v" {
			t.Errorf("data after the partition healed = %q", got)
		}
		if _, err := x.StatObject(bg, "dist", "k2", storage.GetOptions{}); !errors.Is(err, storage.ErrObjectNotFound) {
			t.Errorf("a refused write left an object behind: %v", err)
		}
	})

	t.Run("a reply lost mid-commit leaves no divergent object", func(t *testing.T) {
		tn := newThreeNodes(t)
		x := tn.x
		mkbucket(t, x, "dist")
		tn.net.LoseReplies("n1:9000", "n2:9000", true) // n2 commits, n1 never hears
		settle()
		put(t, x, "dist", "ind", "indeterminate") // 4 other drives still reach quorum
		tn.net.LoseReplies("n1:9000", "n2:9000", false)
		settle()
		if got := mustRead(t, x, "dist", "ind"); got != "indeterminate" {
			t.Errorf("read = %q", got)
		}
		if _, err := x.Scan(bg, true); err != nil {
			t.Fatal(err)
		}
		res, err := x.HealObject(bg, "dist", "ind", true)
		if err != nil || res.Skipped != "healthy" {
			t.Errorf("after scan: %+v, %v", res, err)
		}
	})
}

// waitOnline waits for the circuit breakers of returned remote drives to
// let probes through again.
func waitOnline(t *testing.T, x *XL, want int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for x.OnlineDrives() < want {
		if time.Now().After(deadline) {
			t.Fatalf("only %d of %d drives came back", x.OnlineDrives(), want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
