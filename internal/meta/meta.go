// Package meta defines NanoIO's on-disk object metadata: one xl.meta file per
// key holding every version of that key, as a 16-byte binary envelope around
// a JSON payload. fs and xl write the same format; fs leaves Erasure nil.
//
// The package depends on the standard library only.
package meta

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"sort"
	"time"
)

const (
	// Magic opens every xl.meta file.
	Magic = "NIOM"
	// EnvelopeVersion is the binary envelope layout version.
	EnvelopeVersion = 1
	// CodecJSON identifies the JSON payload codec.
	CodecJSON = 1
	// FormatVersion is the payload schema version written by this build.
	FormatVersion = 1

	headerSize = 16
	// maxPayload bounds decode allocations on hostile input.
	maxPayload = 64 << 20
)

var (
	// ErrCorrupt means the file failed structural or checksum verification.
	// Backends translate it to storage.ErrCorrupted.
	ErrCorrupt = errors.New("meta: corrupt metadata")
	// ErrUnsupported means the file is well-formed but written by a newer
	// format than this build understands. Never rewrite such a file.
	ErrUnsupported = errors.New("meta: unsupported metadata version")
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// Type distinguishes real object versions from delete markers.
type Type string

const (
	TypeObject       Type = "object"
	TypeDeleteMarker Type = "deleteMarker"
)

// File is the decoded content of one xl.meta.
type File struct {
	Format   int       `json:"format"`
	Versions []Version `json:"versions"`
}

// Version is one version of an object, or a delete marker.
type Version struct {
	Type Type `json:"type"`
	// VersionID is empty for the null version of an unversioned or
	// suspended bucket.
	VersionID string `json:"versionId"`
	// Generation counts the committed writes of this object since it was
	// created (1 for the first). A drive refuses a conditional commit based
	// on an older generation than it already holds, which is what keeps two
	// writers that both believe they hold the lock from both succeeding.
	Generation  uint64            `json:"gen,omitempty"`
	ModTime     time.Time         `json:"modTime"`
	Size        int64             `json:"size,omitempty"`
	ETag        string            `json:"etag,omitempty"`
	DataDir     string            `json:"dataDir,omitempty"`
	ContentType string            `json:"contentType,omitempty"`
	UserMeta    map[string]string `json:"userMeta,omitempty"`
	Parts       []Part            `json:"parts,omitempty"`
	Erasure     *Erasure          `json:"erasure,omitempty"`
}

// Part describes one stored part of an object.
type Part struct {
	N    int    `json:"n"`
	Size int64  `json:"size"`
	ETag string `json:"etag,omitempty"`
}

// Erasure is filled in by the xl backend only.
type Erasure struct {
	Algorithm    string     `json:"algorithm"`
	DataBlocks   int        `json:"dataBlocks"`
	ParityBlocks int        `json:"parityBlocks"`
	BlockSize    int64      `json:"blockSize"`
	Index        int        `json:"index"`
	Distribution []int      `json:"distribution"`
	Checksums    []Checksum `json:"checksums,omitempty"`
}

// Checksum is a per-part bitrot hash.
type Checksum struct {
	Part      int    `json:"part"`
	Algorithm string `json:"algorithm"`
	Hash      string `json:"hash"` // hex
}

// Encode validates f and returns the envelope-wrapped bytes. Versions are
// sorted newest first and times are normalised to UTC; f itself is not
// modified. Output is deterministic.
func Encode(f *File) ([]byte, error) {
	if f == nil {
		return nil, errors.New("meta: nil file")
	}
	c := File{Format: FormatVersion, Versions: append([]Version(nil), f.Versions...)}
	for i := range c.Versions {
		c.Versions[i].ModTime = c.Versions[i].ModTime.UTC()
	}
	sortVersions(c.Versions)
	if err := c.validate(); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(&c)
	if err != nil {
		return nil, fmt.Errorf("meta: encode payload: %w", err)
	}
	if len(payload) > maxPayload {
		return nil, fmt.Errorf("meta: payload %d bytes exceeds limit %d", len(payload), maxPayload)
	}
	out := make([]byte, headerSize+len(payload))
	copy(out, Magic)
	out[4] = EnvelopeVersion
	out[5] = CodecJSON
	// out[6:8] reserved, zero.
	binary.LittleEndian.PutUint32(out[8:], uint32(len(payload)))
	binary.LittleEndian.PutUint32(out[12:], crc32.Checksum(payload, castagnoli))
	copy(out[headerSize:], payload)
	return out, nil
}

// Decode verifies and decodes an xl.meta file. It never returns partial
// metadata: any failure yields an error wrapping ErrCorrupt or ErrUnsupported.
func Decode(data []byte) (*File, error) {
	if len(data) < headerSize {
		return nil, fmt.Errorf("%w: %d bytes, need at least %d", ErrCorrupt, len(data), headerSize)
	}
	if string(data[:4]) != Magic {
		return nil, fmt.Errorf("%w: bad magic", ErrCorrupt)
	}
	if v := data[4]; v != EnvelopeVersion {
		return nil, fmt.Errorf("%w: envelope version %d", ErrUnsupported, v)
	}
	if c := data[5]; c != CodecJSON {
		return nil, fmt.Errorf("%w: codec %d", ErrUnsupported, c)
	}
	if data[6] != 0 || data[7] != 0 {
		return nil, fmt.Errorf("%w: reserved bytes set", ErrCorrupt)
	}
	n := binary.LittleEndian.Uint32(data[8:])
	if n > maxPayload || int(n) != len(data)-headerSize {
		return nil, fmt.Errorf("%w: payload length %d does not match file size", ErrCorrupt, n)
	}
	payload := data[headerSize:]
	if got, want := crc32.Checksum(payload, castagnoli), binary.LittleEndian.Uint32(data[12:]); got != want {
		return nil, fmt.Errorf("%w: crc32c mismatch", ErrCorrupt)
	}
	var f File
	if err := json.Unmarshal(payload, &f); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	if f.Format > FormatVersion {
		return nil, fmt.Errorf("%w: format %d", ErrUnsupported, f.Format)
	}
	if err := f.validate(); err != nil {
		return nil, err
	}
	return &f, nil
}

// validate checks structural invariants. Errors wrap ErrCorrupt.
func (f *File) validate() error {
	if f.Format != FormatVersion {
		return fmt.Errorf("%w: format %d", ErrCorrupt, f.Format)
	}
	seen := make(map[string]bool, len(f.Versions))
	for i := range f.Versions {
		v := &f.Versions[i]
		switch v.Type {
		case TypeObject:
			if v.DataDir == "" {
				return fmt.Errorf("%w: version %q: object without dataDir", ErrCorrupt, v.VersionID)
			}
			if v.Size < 0 {
				return fmt.Errorf("%w: version %q: negative size", ErrCorrupt, v.VersionID)
			}
		case TypeDeleteMarker:
			if v.DataDir != "" || v.Size != 0 || len(v.Parts) != 0 {
				return fmt.Errorf("%w: version %q: delete marker carries data", ErrCorrupt, v.VersionID)
			}
		default:
			return fmt.Errorf("%w: version %q: unknown type %q", ErrCorrupt, v.VersionID, v.Type)
		}
		if v.ModTime.IsZero() {
			return fmt.Errorf("%w: version %q: zero modTime", ErrCorrupt, v.VersionID)
		}
		if seen[v.VersionID] {
			return fmt.Errorf("%w: duplicate version %q", ErrCorrupt, v.VersionID)
		}
		seen[v.VersionID] = true
		if i > 0 && newer(v, &f.Versions[i-1]) {
			return fmt.Errorf("%w: versions not ordered newest first", ErrCorrupt)
		}
	}
	return nil
}

// newer reports whether a sorts before b in newest-first order.
func newer(a, b *Version) bool {
	if !a.ModTime.Equal(b.ModTime) {
		return a.ModTime.After(b.ModTime)
	}
	return a.VersionID > b.VersionID
}

func sortVersions(vs []Version) {
	sort.SliceStable(vs, func(i, j int) bool { return newer(&vs[i], &vs[j]) })
}

// Latest returns the newest version, or nil if there are none.
func (f *File) Latest() *Version {
	if len(f.Versions) == 0 {
		return nil
	}
	return &f.Versions[0]
}

// Find returns the version with the given ID (empty = null version).
func (f *File) Find(versionID string) *Version {
	for i := range f.Versions {
		if f.Versions[i].VersionID == versionID {
			return &f.Versions[i]
		}
	}
	return nil
}

// Add inserts v, replacing any existing version with the same ID (the null
// version is replaced on overwrite in unversioned buckets), and keeps the
// list sorted newest first.
func (f *File) Add(v Version) {
	for i := range f.Versions {
		if f.Versions[i].VersionID == v.VersionID {
			f.Versions = append(f.Versions[:i], f.Versions[i+1:]...)
			break
		}
	}
	f.Versions = append(f.Versions, v)
	sortVersions(f.Versions)
}

// Remove deletes the version with the given ID and reports whether it
// existed.
func (f *File) Remove(versionID string) bool {
	for i := range f.Versions {
		if f.Versions[i].VersionID == versionID {
			f.Versions = append(f.Versions[:i], f.Versions[i+1:]...)
			return true
		}
	}
	return false
}

// NewVersionID returns a random RFC 4122 version 4 UUID string. It is
// written here to avoid a third-party dependency.
func NewVersionID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("meta: version id: %w", err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}
