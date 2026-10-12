package meta

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"hash/crc32"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite golden files")

var t0 = time.Date(2026, 10, 10, 10, 28, 0, 123456789, time.UTC)

func obj(id string, mod time.Time) Version {
	return Version{
		Type: TypeObject, VersionID: id, ModTime: mod, Size: 5,
		ETag: "9e107d9d372bb6826bd81d3542a419d6", DataDir: ".nanoio-data-" + id,
		ContentType: "text/plain",
		UserMeta:    map[string]string{"x-amz-meta-owner": "alice"},
		Parts:       []Part{{N: 1, Size: 5, ETag: "9e107d9d372bb6826bd81d3542a419d6"}},
	}
}

func sampleFile() *File {
	return &File{Format: FormatVersion, Versions: []Version{
		{Type: TypeDeleteMarker, VersionID: "dm-1", ModTime: t0.Add(2 * time.Hour)},
		obj("v-2", t0.Add(time.Hour)),
		{
			Type: TypeObject, VersionID: "", ModTime: t0, Size: 1 << 20, DataDir: ".nanoio-data-null",
			Erasure: &Erasure{
				Algorithm: "rs-vandermonde", DataBlocks: 8, ParityBlocks: 4, BlockSize: 1 << 20,
				Index: 3, Distribution: []int{1, 2, 3},
				Checksums: []Checksum{{Part: 1, Algorithm: "crc32c", Hash: "deadbeef"}},
			},
		},
	}}
}

func TestRoundTrip(t *testing.T) {
	empty := &File{Format: FormatVersion}
	tests := []struct {
		name string
		in   *File
	}{
		{"empty file", empty},
		{"object only", &File{Format: FormatVersion, Versions: []Version{obj("a", t0)}}},
		{"mixed versions with erasure", sampleFile()},
		{"zero byte object", &File{Format: FormatVersion, Versions: []Version{
			{Type: TypeObject, VersionID: "z", ModTime: t0, DataDir: ".nanoio-data-z"},
		}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := Encode(tt.in)
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			got, err := Decode(b)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if len(got.Versions) != len(tt.in.Versions) {
				t.Fatalf("versions = %d, want %d", len(got.Versions), len(tt.in.Versions))
			}
			for i := range got.Versions {
				want := tt.in.Versions[i]
				want.ModTime = want.ModTime.UTC()
				g := got.Versions[i]
				if !g.ModTime.Equal(want.ModTime) {
					t.Errorf("v%d modTime = %v, want %v", i, g.ModTime, want.ModTime)
				}
				g.ModTime, want.ModTime = time.Time{}, time.Time{}
				if !reflect.DeepEqual(g, want) {
					t.Errorf("v%d = %+v, want %+v", i, g, want)
				}
			}
			b2, err := Encode(got)
			if err != nil || !bytes.Equal(b, b2) {
				t.Errorf("re-encode differs or failed: %v", err)
			}
		})
	}
}

func TestEncodeSortsNewestFirst(t *testing.T) {
	f := &File{Versions: []Version{
		obj("old", t0), obj("new", t0.Add(time.Hour)), obj("tie-a", t0.Add(30*time.Minute)), obj("tie-b", t0.Add(30*time.Minute)),
	}}
	b, err := Encode(f)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, v := range got.Versions {
		ids = append(ids, v.VersionID)
	}
	want := []string{"new", "tie-b", "tie-a", "old"}
	if !reflect.DeepEqual(ids, want) {
		t.Errorf("order = %v, want %v", ids, want)
	}
}

func TestEncodeRejectsInvalid(t *testing.T) {
	tests := []struct {
		name string
		v    []Version
	}{
		{"object without dataDir", []Version{{Type: TypeObject, VersionID: "a", ModTime: t0}}},
		{"negative size", []Version{{Type: TypeObject, VersionID: "a", ModTime: t0, DataDir: "d", Size: -1}}},
		{"marker with dataDir", []Version{{Type: TypeDeleteMarker, VersionID: "a", ModTime: t0, DataDir: "d"}}},
		{"unknown type", []Version{{Type: "weird", VersionID: "a", ModTime: t0}}},
		{"zero modTime", []Version{{Type: TypeDeleteMarker, VersionID: "a"}}},
		{"duplicate version id", []Version{obj("a", t0), obj("a", t0.Add(time.Hour))}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Encode(&File{Versions: tt.v}); !errors.Is(err, ErrCorrupt) {
				t.Errorf("Encode error = %v, want ErrCorrupt", err)
			}
		})
	}
	if _, err := Encode(nil); err == nil {
		t.Error("Encode(nil) succeeded")
	}
}

func TestDecodeRejectsDamage(t *testing.T) {
	good, err := Encode(sampleFile())
	if err != nil {
		t.Fatal(err)
	}
	mutate := func(f func(b []byte) []byte) []byte { return f(append([]byte(nil), good...)) }
	resum := func(b []byte) {
		binary.LittleEndian.PutUint32(b[12:], crc32.Checksum(b[headerSize:], castagnoli))
	}
	tests := []struct {
		name string
		data []byte
		want error
	}{
		{"nil", nil, ErrCorrupt},
		{"short header", good[:headerSize-1], ErrCorrupt},
		{"header only", good[:headerSize], ErrCorrupt},
		{"bad magic", mutate(func(b []byte) []byte { b[0] = 'X'; return b }), ErrCorrupt},
		{"future envelope", mutate(func(b []byte) []byte { b[4] = 2; return b }), ErrUnsupported},
		{"unknown codec", mutate(func(b []byte) []byte { b[5] = 9; return b }), ErrUnsupported},
		{"reserved set", mutate(func(b []byte) []byte { b[6] = 1; return b }), ErrCorrupt},
		{"truncated payload", good[:len(good)-1], ErrCorrupt},
		{"trailing garbage", append(append([]byte(nil), good...), 0), ErrCorrupt},
		{"flipped payload bit", mutate(func(b []byte) []byte { b[len(b)-3] ^= 0x01; return b }), ErrCorrupt},
		{"flipped crc", mutate(func(b []byte) []byte { b[12] ^= 0xff; return b }), ErrCorrupt},
		{"not json, valid crc", mutate(func(b []byte) []byte {
			b = append(b[:headerSize], []byte("not json")...)
			binary.LittleEndian.PutUint32(b[8:], 8)
			resum(b)
			return b
		}), ErrCorrupt},
		{"future format, valid crc", mutate(func(b []byte) []byte {
			p := bytes.Replace(b[headerSize:], []byte(`"format":2`), []byte(`"format":6`), 1)
			b = append(b[:headerSize], p...)
			resum(b)
			return b
		}), ErrUnsupported},
		{"unordered versions, valid crc", mutate(func(b []byte) []byte {
			p := []byte(`{"format":1,"versions":[` +
				`{"type":"deleteMarker","versionId":"old","modTime":"2026-10-10T10:00:00Z"},` +
				`{"type":"deleteMarker","versionId":"new","modTime":"2026-10-10T11:00:00Z"}]}`)
			b = append(b[:headerSize], p...)
			binary.LittleEndian.PutUint32(b[8:], uint32(len(p)))
			resum(b)
			return b
		}), ErrCorrupt},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := Decode(tt.data)
			if f != nil {
				t.Errorf("Decode returned partial metadata: %+v", f)
			}
			if !errors.Is(err, tt.want) {
				t.Errorf("Decode error = %v, want %v", err, tt.want)
			}
		})
	}
}

// Every single-byte flip and every truncation of a valid file must fail
// cleanly. CRC32C detects all single-byte errors, so none may decode.
func TestDecodeEveryByteFlipAndTruncation(t *testing.T) {
	good, err := Encode(sampleFile())
	if err != nil {
		t.Fatal(err)
	}
	for i := range good {
		b := append([]byte(nil), good...)
		b[i] ^= 0xff
		if _, err := Decode(b); err == nil {
			t.Fatalf("flip at byte %d decoded successfully", i)
		}
	}
	for n := 0; n < len(good); n++ {
		if _, err := Decode(good[:n]); err == nil {
			t.Fatalf("truncation to %d bytes decoded successfully", n)
		}
	}
}

func TestDecodeIgnoresUnknownFields(t *testing.T) {
	payload := []byte(`{"format":1,"future":{"x":1},"versions":[` +
		`{"type":"deleteMarker","versionId":"m","modTime":"2026-10-10T10:28:00Z","newField":true}]}`)
	b := append([]byte(Magic), EnvelopeVersion, CodecJSON, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(b[8:], uint32(len(payload)))
	binary.LittleEndian.PutUint32(b[12:], crc32.Checksum(payload, castagnoli))
	b = append(b, payload...)
	f, err := Decode(b)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if f.Latest() == nil || f.Latest().VersionID != "m" {
		t.Errorf("unexpected content: %+v", f)
	}
}

func TestFileOps(t *testing.T) {
	f := &File{Format: FormatVersion}
	if f.Latest() != nil {
		t.Error("Latest on empty file is non-nil")
	}
	f.Add(obj("a", t0))
	f.Add(obj("b", t0.Add(time.Hour)))
	f.Add(obj("a", t0.Add(2*time.Hour))) // replaces "a"
	tests := []struct {
		name string
		got  func() any
		want any
	}{
		{"count after replace", func() any { return len(f.Versions) }, 2},
		{"latest is replaced a", func() any { return f.Latest().VersionID }, "a"},
		{"find b", func() any { return f.Find("b") != nil }, true},
		{"find missing", func() any { return f.Find("zz") != nil }, false},
		{"remove b", func() any { return f.Remove("b") }, true},
		{"remove b again", func() any { return f.Remove("b") }, false},
		{"count after remove", func() any { return len(f.Versions) }, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.got(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestNewVersionID(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		id, err := NewVersionID()
		if err != nil {
			t.Fatal(err)
		}
		if !uuidRE.MatchString(id) {
			t.Fatalf("%q is not a v4 UUID", id)
		}
		if seen[id] {
			t.Fatalf("duplicate id %q", id)
		}
		seen[id] = true
	}
}

// TestGolden pins the byte-exact encoding. Run with -update to regenerate,
// and only when the format version is deliberately changed.
func TestGolden(t *testing.T) {
	path := filepath.Join("testdata", "v2.meta")
	got, err := Encode(sampleFile())
	if err != nil {
		t.Fatal(err)
	}
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run with -update to create): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("encoding changed:\n got %s\nwant %s", got, want)
	}
	if _, err := Decode(want); err != nil {
		t.Errorf("golden file no longer decodes: %v", err)
	}
}

// TestLegacyGoldenDecodes: files written before versioning (format 1, here
// even with several versions and a marker) must keep decoding, and must
// re-encode as the format they are (1 if they use no versioning feature).
func TestLegacyGoldenDecodes(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "v1.meta"))
	if err != nil {
		t.Fatal(err)
	}
	f, err := Decode(data)
	if err != nil {
		t.Fatalf("a format-1 file no longer decodes: %v", err)
	}
	if f.Format != FormatVersion || len(f.Versions) != 3 || f.Gen != 0 {
		t.Errorf("decoded = format %d, %d versions, gen %d", f.Format, len(f.Versions), f.Gen)
	}
	if f.Generation() != 0 {
		t.Errorf("Generation = %d", f.Generation())
	}
}

func FuzzDecode(f *testing.F) {
	good, _ := Encode(sampleFile())
	f.Add(good)
	f.Add([]byte{})
	f.Add([]byte(Magic))
	f.Fuzz(func(t *testing.T, data []byte) {
		file, err := Decode(data)
		if err != nil {
			if file != nil {
				t.Fatal("non-nil file with error")
			}
			return
		}
		// Anything that decodes must re-encode and decode again.
		b, err := Encode(file)
		if err != nil {
			t.Fatalf("decoded file does not re-encode: %v", err)
		}
		if _, err := Decode(b); err != nil {
			t.Fatalf("re-encoded file does not decode: %v", err)
		}
	})
}
