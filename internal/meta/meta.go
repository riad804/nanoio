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
	// FormatVersion is the base payload schema: one object, no versioning
	// features. Files that use any (several versions, a delete marker, a
	// file generation or version sequence numbers) are written as
	// FormatVersioned, which a build that predates versioning refuses
	// rather than silently dropping versions.
	FormatVersion = 1
	// FormatVersioned is the payload schema of versioned files.
	FormatVersioned = 2
	// FormatLocked is the schema of files in which some version carries an
	// object lock. A build that predates object lock would decode such a
	// file, ignore the lock and drop it on its next rewrite, which would
	// quietly void a retention; it refuses the file instead.
	FormatLocked = 3
	// MaxFormat is the newest schema this build understands.
	MaxFormat = FormatLocked

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
	Format int `json:"format"`
	// Gen counts committed mutations of this key's version list: every
	// version added, delete marker added and version removed bumps it. It is
	// the compare-and-set counter drives check, and it numbers versions
	// (Version.Seq). Absent (0) in files written before versioning; see
	// Generation.
	Gen      uint64    `json:"gen,omitempty"`
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
	//
	// Deprecated: File.Gen replaced it when versioning was added; it is
	// still read from older files (see File.Generation) and not written.
	Generation uint64 `json:"gen,omitempty"`
	// Seq orders the versions of one key: it is File.Gen as of the commit
	// that created this version, so it is total, stable, and independent of
	// any node's clock. Zero in files written before versioning, which sort
	// below every sequenced version.
	Seq         uint64            `json:"seq,omitempty"`
	ModTime     time.Time         `json:"modTime"`
	Size        int64             `json:"size,omitempty"`
	ETag        string            `json:"etag,omitempty"`
	DataDir     string            `json:"dataDir,omitempty"`
	ContentType string            `json:"contentType,omitempty"`
	UserMeta    map[string]string `json:"userMeta,omitempty"`
	Parts       []Part            `json:"parts,omitempty"`
	Erasure     *Erasure          `json:"erasure,omitempty"`
	// Lock is the version's object lock state; nil when it has none. Only
	// object versions carry one.
	Lock *Lock `json:"lock,omitempty"`
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
	c := File{Format: FormatVersion, Gen: f.Gen, Versions: append([]Version(nil), f.Versions...)}
	for i := range c.Versions {
		c.Versions[i].ModTime = c.Versions[i].ModTime.UTC()
		c.Versions[i].Lock = c.Versions[i].Lock.Normalized()
	}
	sortVersions(c.Versions)
	if c.usesVersioning() {
		c.Format = FormatVersioned
	}
	if c.usesLock() {
		c.Format = FormatLocked
	}
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
	if f.Format > MaxFormat {
		return nil, fmt.Errorf("%w: format %d", ErrUnsupported, f.Format)
	}
	if err := f.validate(); err != nil {
		return nil, err
	}
	return &f, nil
}

// validate checks structural invariants. Errors wrap ErrCorrupt.
func (f *File) validate() error {
	if f.Format < FormatVersion || f.Format > MaxFormat {
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
			if v.Lock != nil {
				if err := v.Lock.validate(); err != nil {
					return fmt.Errorf("%w: version %q: %v", ErrCorrupt, v.VersionID, err)
				}
			}
		case TypeDeleteMarker:
			if v.DataDir != "" || v.Size != 0 || len(v.Parts) != 0 {
				return fmt.Errorf("%w: version %q: delete marker carries data", ErrCorrupt, v.VersionID)
			}
			if !v.Lock.Empty() {
				return fmt.Errorf("%w: version %q: delete marker carries a lock", ErrCorrupt, v.VersionID)
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

// usesVersioning reports whether f needs the versioned schema.
func (f *File) usesVersioning() bool {
	if f.Gen > 0 || len(f.Versions) > 1 {
		return true
	}
	for i := range f.Versions {
		if f.Versions[i].Seq > 0 || f.Versions[i].Type == TypeDeleteMarker {
			return true
		}
	}
	return false
}

// usesLock reports whether any version carries an object lock.
func (f *File) usesLock() bool {
	for i := range f.Versions {
		if !f.Versions[i].Lock.Empty() {
			return true
		}
	}
	return false
}

// newer reports whether a sorts before b in newest-first order: by sequence
// (zero, from before versioning, sorts last), then by modification time,
// then by version ID so the order is total.
func newer(a, b *Version) bool {
	if a.Seq != b.Seq {
		return a.Seq > b.Seq
	}
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

// Generation is the compare-and-set generation of the key: Gen, or for a
// file written before versioning the generation recorded on its only version.
func (f *File) Generation() uint64 {
	if f.Gen > 0 {
		return f.Gen
	}
	if l := f.Latest(); l != nil {
		return l.Generation
	}
	return 0
}

// Versioning is a bucket's versioning state, as the mutation functions need
// it. Backends map their own representation onto it.
type Versioning uint8

const (
	// Unversioned: writes replace the null version, deletes remove it.
	Unversioned Versioning = iota
	// Enabled: writes create a new version, deletes add a delete marker.
	Enabled
	// Suspended: writes replace the null version (other versions stay),
	// deletes replace it with a null delete marker.
	Suspended
)

func (v Versioning) String() string {
	switch v {
	case Enabled:
		return "Enabled"
	case Suspended:
		return "Suspended"
	}
	return "Unversioned"
}

// NullVersion is the version ID of the null version in storage.
const NullVersion = ""

// Mutation errors.
var (
	// ErrStale means a mutation was numbered at or below the file's
	// generation: someone committed first.
	ErrStale = errors.New("meta: mutation is not newer than the file's generation")
	// ErrNoSuchVersion means the version to remove or resolve is not there.
	ErrNoSuchVersion = errors.New("meta: no such version")
)

// VersionIDFor returns the ID a new object version or delete marker gets
// under st: a fresh UUID when versioning is enabled, the null version
// otherwise.
func VersionIDFor(st Versioning) (string, error) {
	if st == Enabled {
		return NewVersionID()
	}
	return NullVersion, nil
}

// ApplyPut adds the object version v and returns the data directories it
// superseded (the null version's, when v replaces it) for the caller to
// remove once the change is final. v.VersionID must be the ID chosen by
// VersionIDFor and v.Seq the sequence number (the committed generation plus
// one); several drives applying the same mutation must be given the same
// values. The file's generation becomes v.Seq.
//
// Replacing a version (the null version) is a removal and is judged by
// CheckRemove under g: a locked null version is never overwritten.
func (f *File) ApplyPut(v Version, g Guard) (superseded []string, err error) {
	if v.Type != TypeObject {
		return nil, fmt.Errorf("meta: ApplyPut of a %q", v.Type)
	}
	if v.Seq == 0 || v.Seq <= f.Generation() {
		return nil, fmt.Errorf("%w: seq %d, generation %d", ErrStale, v.Seq, f.Generation())
	}
	v.Lock = v.Lock.Normalized()
	old := f.Find(v.VersionID)
	if old != nil {
		if err := CheckRemove(old, g); err != nil {
			return nil, err
		}
		if old.DataDir != "" {
			superseded = append(superseded, old.DataDir)
		}
	}
	f.Add(v)
	f.Gen = v.Seq
	return superseded, nil
}

// ApplyMarker adds a delete marker with the given ID and sequence number.
// Under Suspended the marker is the null version (id == NullVersion) and
// replaces any null object, whose data directory is returned.
//
// Replacing the null version is a removal judged by CheckRemove under g.
func (f *File) ApplyMarker(id string, seq uint64, modTime time.Time, g Guard) (superseded []string, err error) {
	if seq == 0 || seq <= f.Generation() {
		return nil, fmt.Errorf("%w: seq %d, generation %d", ErrStale, seq, f.Generation())
	}
	if old := f.Find(id); old != nil {
		if err := CheckRemove(old, g); err != nil {
			return nil, err
		}
		if old.DataDir != "" {
			superseded = append(superseded, old.DataDir)
		}
	}
	f.Add(Version{Type: TypeDeleteMarker, VersionID: id, Seq: seq, ModTime: modTime})
	f.Gen = seq
	return superseded, nil
}

// ApplyRemove permanently removes one version (object or delete marker) and
// returns its data directory, if it had one. seq is the new generation.
//
// A version that object lock protects at g is refused with a *LockedError
// (errors.Is ErrLocked) and the file is left unchanged.
func (f *File) ApplyRemove(id string, seq uint64, g Guard) (removed []string, err error) {
	if seq == 0 || seq <= f.Generation() {
		return nil, fmt.Errorf("%w: seq %d, generation %d", ErrStale, seq, f.Generation())
	}
	v := f.Find(id)
	if v == nil {
		return nil, fmt.Errorf("%w: %q", ErrNoSuchVersion, id)
	}
	if err := CheckRemove(v, g); err != nil {
		return nil, err
	}
	if v.DataDir != "" {
		removed = append(removed, v.DataDir)
	}
	f.Remove(id)
	f.Gen = seq
	return removed, nil
}

// Resolve picks the version a read addresses: the newest when versionID is
// empty and latest is set, otherwise the one with that ID (NullVersion for
// the null version). A missing version yields ErrNoSuchVersion.
func (f *File) Resolve(versionID string, latest bool) (*Version, error) {
	if latest {
		if v := f.Latest(); v != nil {
			return v, nil
		}
		return nil, ErrNoSuchVersion
	}
	if v := f.Find(versionID); v != nil {
		return v, nil
	}
	return nil, fmt.Errorf("%w: %q", ErrNoSuchVersion, versionID)
}

// After returns the versions that come strictly after the one with the given
// ID in newest-first order, for resuming a listing. If that version is no
// longer there the listing resumes at the next key, so nothing is returned.
func (f *File) After(versionID string) []Version {
	for i := range f.Versions {
		if f.Versions[i].VersionID == versionID {
			return f.Versions[i+1:]
		}
	}
	return nil
}
