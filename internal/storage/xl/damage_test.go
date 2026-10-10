package xl

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"nanoio/internal/meta"
	"nanoio/internal/storage"
	"nanoio/internal/storage/xl/disk"
)

// objDirOn is the object directory of bucket/key on drive i.
func objDirOn(dirs []string, i int, bucket, key string) string {
	return filepath.Join(append([]string{dirs[i], bucket}, storage.KeySegments(key)...)...)
}

// shardPathsOn lists drive i's shard files of an object.
func shardPathsOn(t *testing.T, dirs []string, i int, bucket, key string) []string {
	t.Helper()
	dir := objDirOn(dirs, i, bucket, key)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), storage.DataDirPrefix+"data-") {
			files, _ := os.ReadDir(filepath.Join(dir, e.Name()))
			for _, f := range files {
				out = append(out, filepath.Join(dir, e.Name(), f.Name()))
			}
		}
	}
	sort.Strings(out)
	return out
}

func metaOn(t *testing.T, dirs []string, i int, bucket, key string) *meta.File {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(objDirOn(dirs, i, bucket, key), "xl.meta"))
	if err != nil {
		t.Fatalf("drive %d: %v", i, err)
	}
	f, err := meta.Decode(b)
	if err != nil {
		t.Fatalf("drive %d xl.meta: %v", i, err)
	}
	return f
}

// A damage mutates one drive's copy of one object.
type damage struct {
	name string
	// hitsData is true when the damage can make shard bytes unreadable
	// (as opposed to metadata only).
	apply func(t *testing.T, rng *rand.Rand, dirs []string, i int, bucket, key string)
}

func flipByteIn(t *testing.T, rng *rand.Rand, path string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil || len(b) == 0 {
		return
	}
	b[rng.Intn(len(b))] ^= 1 << uint(rng.Intn(8))
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

var damages = []damage{
	{"delete shard files", func(t *testing.T, _ *rand.Rand, dirs []string, i int, b, k string) {
		for _, p := range shardPathsOn(t, dirs, i, b, k) {
			os.Remove(p)
		}
	}},
	{"delete the object directory", func(t *testing.T, _ *rand.Rand, dirs []string, i int, b, k string) {
		os.RemoveAll(objDirOn(dirs, i, b, k))
	}},
	{"truncate a shard to half", func(t *testing.T, rng *rand.Rand, dirs []string, i int, b, k string) {
		ps := shardPathsOn(t, dirs, i, b, k)
		if len(ps) > 0 {
			p := ps[rng.Intn(len(ps))]
			if st, err := os.Stat(p); err == nil {
				os.Truncate(p, st.Size()/2)
			}
		}
	}},
	{"truncate a shard to empty", func(t *testing.T, rng *rand.Rand, dirs []string, i int, b, k string) {
		ps := shardPathsOn(t, dirs, i, b, k)
		if len(ps) > 0 {
			os.Truncate(ps[rng.Intn(len(ps))], 0)
		}
	}},
	{"flip a bit in a shard (bitrot)", func(t *testing.T, rng *rand.Rand, dirs []string, i int, b, k string) {
		ps := shardPathsOn(t, dirs, i, b, k)
		if len(ps) > 0 {
			flipByteIn(t, rng, ps[rng.Intn(len(ps))])
		}
	}},
	{"overwrite a shard with zeros", func(t *testing.T, rng *rand.Rand, dirs []string, i int, b, k string) {
		for _, p := range shardPathsOn(t, dirs, i, b, k) {
			if st, err := os.Stat(p); err == nil {
				os.WriteFile(p, make([]byte, st.Size()), 0o644)
			}
		}
	}},
	{"corrupt xl.meta", func(t *testing.T, rng *rand.Rand, dirs []string, i int, b, k string) {
		flipByteIn(t, rng, filepath.Join(objDirOn(dirs, i, b, k), "xl.meta"))
	}},
	{"replace xl.meta with garbage", func(t *testing.T, _ *rand.Rand, dirs []string, i int, b, k string) {
		os.WriteFile(filepath.Join(objDirOn(dirs, i, b, k), "xl.meta"), []byte("this is not metadata"), 0o644)
	}},
	{"delete xl.meta", func(t *testing.T, _ *rand.Rand, dirs []string, i int, b, k string) {
		os.Remove(filepath.Join(objDirOn(dirs, i, b, k), "xl.meta"))
	}},
}

// testObject is something a trial stores and later expects back whole.
type testObject struct {
	key  string
	body []byte
}

func randBytes(rng *rand.Rand, n int) []byte {
	b := make([]byte, n)
	rng.Read(b)
	return b
}

// sizesFor returns object sizes that exercise empty, tiny, sub-block,
// exact-block and multi-block-with-tail objects.
func sizesFor(blockSize int64, k int) []int {
	bs := int(blockSize)
	return []int{0, 1, k - 1, k, k + 1, bs - 1, bs, bs + 1, 2*bs + 7, 3 * bs}
}

// verifyWhole checks a full read and several ranged reads against want.
func verifyWhole(t *testing.T, x *XL, rng *rand.Rand, bucket string, o testObject) error {
	t.Helper()
	got, err := read(t, x, bucket, o.key)
	if err != nil {
		return err
	}
	if !bytes.Equal([]byte(got), o.body) {
		t.Fatalf("SILENT CORRUPTION: %s returned %d bytes that differ from the %d stored", o.key, len(got), len(o.body))
	}
	size := int64(len(o.body))
	for i := 0; i < 6 && size > 0; i++ {
		start := rng.Int63n(size)
		length := 1 + rng.Int63n(size-start)
		rc, _, err := x.GetObject(bg, bucket, o.key, storage.GetOptions{Range: &storage.ByteRange{Start: start, Length: length}})
		if err != nil {
			return err
		}
		part := make([]byte, length)
		_, rerr := readFull(rc, part)
		rc.Close()
		if rerr != nil {
			return rerr
		}
		if !bytes.Equal(part, o.body[start:start+length]) {
			t.Fatalf("SILENT CORRUPTION in range [%d,%d) of %s", start, start+length, o.key)
		}
	}
	return nil
}

func readFull(r interface{ Read([]byte) (int, error) }, p []byte) (int, error) {
	n := 0
	for n < len(p) {
		c, err := r.Read(p[n:])
		n += c
		if err != nil {
			if n == len(p) {
				return n, nil
			}
			return n, err
		}
	}
	return n, nil
}

// pickDrives returns count distinct drive indexes.
func pickDrives(rng *rand.Rand, n, count int) []int {
	return rng.Perm(n)[:count]
}

// TestKillRandomShards is the headline requirement: for every erasure
// layout, repeatedly destroy a random selection of up to M drives' copies of
// an object in a random way and verify that every read, whole and ranged,
// still returns exactly the stored bytes, and that healing restores full
// redundancy.
func TestKillRandomShards(t *testing.T) {
	for _, l := range layouts {
		t.Run(l.name, func(t *testing.T) {
			rng := rand.New(rand.NewSource(20260101 + int64(l.drives)*31 + int64(l.parity)))
			x, dirs := newXL(t, l, func(o *Options) { o.MinPartSize = 16 })
			mkbucket(t, x, "kill")
			m := l.parity
			bs := x.blockSize
			trials := 0
			for _, size := range sizesFor(bs, l.drives-m) {
				if size < 0 {
					continue
				}
				for rep := 0; rep < 3; rep++ {
					trials++
					key := fmt.Sprintf("t%03d/obj-%d", trials, size)
					o := testObject{key: key, body: randBytes(rng, size)}
					if _, err := x.PutObject(bg, "kill", key, bytes.NewReader(o.body), int64(len(o.body)), storage.PutOptions{}); err != nil {
						t.Fatalf("put: %v", err)
					}
					// Kill up to M drives' copies, each a different way.
					count := 1 + rng.Intn(m)
					victims := pickDrives(rng, l.drives, count)
					var applied []string
					for _, d := range victims {
						dm := damages[rng.Intn(len(damages))]
						dm.apply(t, rng, dirs, d, "kill", key)
						applied = append(applied, fmt.Sprintf("drive %d: %s", d, dm.name))
					}
					if err := verifyWhole(t, x, rng, "kill", o); err != nil {
						t.Fatalf("read failed with only %d of %d drives damaged (%v): %v", count, l.drives, applied, err)
					}
					st, err := x.StatObject(bg, "kill", key, storage.GetOptions{})
					if err != nil || st.Size != int64(len(o.body)) {
						t.Fatalf("stat after damage: %+v %v (%v)", st, err, applied)
					}

					// Heal, then prove redundancy is back: damage M other
					// drives and read again.
					res, err := x.HealObject(bg, "kill", key, true)
					if err != nil {
						t.Fatalf("heal: %v (%v)", err, applied)
					}
					if res.Skipped == "" && len(res.Healed) == 0 {
						t.Fatalf("heal did nothing (%v)", applied)
					}
					if again, err := x.HealObject(bg, "kill", key, true); err != nil || again.Skipped != "healthy" {
						t.Fatalf("object not fully healthy after heal: %+v %v (%v)", again, err, applied)
					}
					second := pickDrives(rng, l.drives, m)
					for _, d := range second {
						damages[rng.Intn(len(damages))].apply(t, rng, dirs, d, "kill", key)
					}
					if err := verifyWhole(t, x, rng, "kill", o); err != nil {
						t.Fatalf("read failed after healing and re-damaging %v: %v", second, err)
					}
				}
			}
			t.Logf("%s: %d objects x (damage up to %d drives, read, heal, damage %d more, read)", l.name, trials, m, m)
		})
	}
}

// Kill the same random damage on a multipart object, whose parts are
// separate shard streams.
func TestKillRandomShardsMultipart(t *testing.T) {
	l := layout{"4+4", 8, 4, 32 << 10}
	rng := rand.New(rand.NewSource(77))
	x, dirs := newXL(t, l, func(o *Options) { o.MinPartSize = 16 })
	mkbucket(t, x, "mpkill")
	for trial := 0; trial < 12; trial++ {
		key := fmt.Sprintf("mp%02d", trial)
		var body []byte
		id, err := x.NewMultipartUpload(bg, "mpkill", key, storage.PutOptions{})
		if err != nil {
			t.Fatal(err)
		}
		var cp []storage.CompletePart
		for p := 1; p <= 3+trial%3; p++ {
			part := randBytes(rng, 20000+rng.Intn(90000))
			info, err := x.PutObjectPart(bg, "mpkill", key, id, p*2, bytes.NewReader(part), int64(len(part)), storage.PartOptions{})
			if err != nil {
				t.Fatal(err)
			}
			cp = append(cp, storage.CompletePart{Number: p * 2, ETag: info.ETag})
			body = append(body, part...)
		}
		if _, err := x.CompleteMultipartUpload(bg, "mpkill", key, id, cp, storage.PutOptions{}); err != nil {
			t.Fatal(err)
		}
		for _, d := range pickDrives(rng, 8, 1+rng.Intn(4)) {
			damages[rng.Intn(len(damages))].apply(t, rng, dirs, d, "mpkill", key)
		}
		if err := verifyWhole(t, x, rng, "mpkill", testObject{key, body}); err != nil {
			t.Fatalf("trial %d: %v", trial, err)
		}
		if _, err := x.HealObject(bg, "mpkill", key, true); err != nil {
			t.Fatalf("trial %d heal: %v", trial, err)
		}
		if again, _ := x.HealObject(bg, "mpkill", key, true); again.Skipped != "healthy" {
			t.Fatalf("trial %d: not healthy after heal: %+v", trial, again)
		}
	}
}

// Beyond M damaged drives the data is gone, and the one thing that must
// never happen is a read that returns different bytes without an error.
func TestBeyondParityFailsLoudly(t *testing.T) {
	for _, l := range layouts {
		t.Run(l.name, func(t *testing.T) {
			rng := rand.New(rand.NewSource(99 + int64(l.drives)))
			x, dirs := newXL(t, l)
			mkbucket(t, x, "gone")
			errored := 0
			for trial := 0; trial < 15; trial++ {
				key := fmt.Sprintf("o%02d", trial)
				body := randBytes(rng, 3*int(x.blockSize)+rng.Intn(1000)+1)
				put(t, x, "gone", key, string(body))
				victims := pickDrives(rng, l.drives, l.parity+1+rng.Intn(l.drives-l.parity)) // M+1 .. N
				for _, d := range victims {
					damages[rng.Intn(5)].apply(t, rng, dirs, d, "gone", key) // data-destroying kinds
				}
				got, err := read(t, x, "gone", key)
				switch {
				case err == nil:
					if !bytes.Equal([]byte(got), body) {
						t.Fatalf("SILENT CORRUPTION: %d of %d drives damaged yet a read returned wrong bytes", len(victims), l.drives)
					}
					// A damage kind can be a no-op (e.g. flipping a bit in
					// parity that is never needed); success is legitimate.
				default:
					errored++
					if !errors.Is(err, storage.ErrCorrupted) && !errors.Is(err, storage.ErrBackendUnavailable) &&
						!errors.Is(err, storage.ErrObjectNotFound) {
						t.Errorf("unexpected error class: %v", err)
					}
				}
			}
			if errored == 0 {
				t.Error("no read failed although more drives than parity were destroyed; the test is not exercising the limit")
			}
		})
	}
}

func TestBitrotInUnreadParityIsFoundByDeepScan(t *testing.T) {
	l := layout{"4+4", 8, 4, 64 << 10}
	x, dirs := newXL(t, l)
	mkbucket(t, x, "rot")
	body := bytes.Repeat([]byte("0123456789abcdef"), 40000) // 640 KiB
	put(t, x, "rot", "o", string(body))

	// Corrupt a parity shard: a normal read uses only data shards, so it
	// cannot notice. Find a drive holding a parity shard (index >= K).
	var victim int = -1
	for i := range dirs {
		if metaOn(t, dirs, i, "rot", "o").Latest().Erasure.Index >= 4 {
			victim = i
			break
		}
	}
	paths := shardPathsOn(t, dirs, victim, "rot", "o")
	rng := rand.New(rand.NewSource(1))
	flipByteIn(t, rng, paths[0])

	if got := mustRead(t, x, "rot", "o"); got != string(body) {
		t.Fatal("read differs")
	}
	// Shallow healing looks at presence and size only: it cannot see it.
	if res, _ := x.HealObject(bg, "rot", "o", false); res.Skipped != "healthy" {
		t.Errorf("shallow heal = %+v, want healthy (the damage is invisible without hashing)", res)
	}
	// A deep scan reads every block and finds it.
	res, err := x.HealObject(bg, "rot", "o", true)
	if err != nil || len(res.Healed) != 1 || res.Healed[0] != victim {
		t.Fatalf("deep heal = %+v, %v; want drive %d repaired", res, err, victim)
	}
	if again, _ := x.HealObject(bg, "rot", "o", true); again.Skipped != "healthy" {
		t.Errorf("still unhealthy after repair: %+v", again)
	}
}

func TestShardDistributionAndFormat(t *testing.T) {
	l := layout{"4+4", 8, 4, 16 << 10}
	x, dirs := newXL(t, l)
	mkbucket(t, x, "lay")
	rng := rand.New(rand.NewSource(5))
	firstShardDrive := map[int]bool{}
	for i := 0; i < 24; i++ {
		key := fmt.Sprintf("dir/key-%d", i)
		size := []int{0, 1, 100, 16 << 10, 50000, 100000}[i%6]
		body := randBytes(rng, size)
		put(t, x, "lay", key, string(body))

		seen := map[int]bool{}
		var dist []int
		for d := range dirs {
			f := metaOn(t, dirs, d, "lay", key)
			v := f.Latest()
			e := v.Erasure
			if e == nil || e.Algorithm != "reedsolomon" || e.DataBlocks != 4 || e.ParityBlocks != 4 || e.BlockSize != 16<<10 {
				t.Fatalf("drive %d erasure info: %+v", d, e)
			}
			if len(e.Distribution) != 8 || e.Distribution[d] != e.Index {
				t.Fatalf("drive %d: index %d disagrees with distribution %v", d, e.Index, e.Distribution)
			}
			if seen[e.Index] {
				t.Fatalf("shard index %d on two drives", e.Index)
			}
			seen[e.Index] = true
			dist = e.Distribution
			if v.Size != int64(size) || len(v.Parts) != 1 || v.Parts[0].Size != int64(size) {
				t.Fatalf("drive %d: size/parts %+v", d, v)
			}
			// Every shard file is exactly the size the layout predicts and
			// its blocks verify.
			ps := shardPathsOn(t, dirs, d, "lay", key)
			if len(ps) != 1 {
				t.Fatalf("drive %d has %d shard files", d, len(ps))
			}
			st, _ := os.Stat(ps[0])
			if st.Size() != disk.ShardFileSize(int64(size), 16<<10, 4) {
				t.Fatalf("drive %d shard file is %d bytes, want %d", d, st.Size(), disk.ShardFileSize(int64(size), 16<<10, 4))
			}
			sf, err := os.Open(ps[0])
			if err != nil {
				t.Fatal(err)
			}
			root, err := disk.VerifyStream(sf, int64(size), 16<<10, 4)
			sf.Close()
			if err != nil {
				t.Fatalf("drive %d shard fails verification: %v", d, err)
			}
			if len(e.Checksums) != 1 || e.Checksums[0].Hash != root || e.Checksums[0].Algorithm != "sha256" {
				t.Fatalf("drive %d checksum record %+v, computed root %s", d, e.Checksums, root)
			}
		}
		for d, s := range dist {
			if s == 0 {
				firstShardDrive[d] = true
			}
		}
	}
	if len(firstShardDrive) < 4 {
		t.Errorf("the first data shard landed on only %d distinct drives over 24 keys; distribution is not spreading load", len(firstShardDrive))
	}
}

func TestBlockBoundaries(t *testing.T) {
	for _, l := range []layout{{"3+2 odd", 5, 2, 1000}, {"4+4", 8, 4, 4096}, {"5+3", 8, 3, 1 << 12}} {
		t.Run(l.name, func(t *testing.T) {
			x, _ := newXL(t, l)
			mkbucket(t, x, "bnd")
			rng := rand.New(rand.NewSource(8))
			k := l.drives - l.parity
			bs := int(l.blockSize)
			for _, size := range []int{0, 1, k - 1, k, k + 1, bs - 1, bs, bs + 1, bs*2 - 1, bs * 2, bs*2 + 1, bs*5 + k - 1} {
				body := randBytes(rng, size)
				key := fmt.Sprintf("s%d", size)
				put(t, x, "bnd", key, string(body))
				if got := mustRead(t, x, "bnd", key); got != string(body) {
					t.Fatalf("size %d round trip differs", size)
				}
				// Ranges that start/end exactly on and around boundaries.
				for _, start := range []int{0, 1, bs - 1, bs, bs + 1, size - 1} {
					for _, ln := range []int{1, 2, bs - 1, bs, bs + 1} {
						if start < 0 || start >= size || start+ln > size {
							continue
						}
						rc, _, err := x.GetObject(bg, "bnd", key, storage.GetOptions{Range: &storage.ByteRange{Start: int64(start), Length: int64(ln)}})
						if err != nil {
							t.Fatal(err)
						}
						buf := make([]byte, ln)
						readFull(rc, buf)
						rc.Close()
						if !bytes.Equal(buf, body[start:start+ln]) {
							t.Fatalf("size %d range [%d,+%d) differs", size, start, ln)
						}
					}
				}
			}
		})
	}
}
