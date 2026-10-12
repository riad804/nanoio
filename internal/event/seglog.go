package event

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// seglog is an append-only record log split into segment files. Records are
// framed as
//
//	uint32 length | uint32 crc32c(payload) | payload
//
// A torn final record (a crash during append) is detected by its length or
// checksum and truncated when the log is opened. A record that fails its
// checksum elsewhere ends the readable part of that segment; the reader
// continues at the next segment and reports the damage via the Corrupt
// counter, so one bad sector costs a segment, not the queue.
//
// It is the storage under both the durable target queues (queue.go) and the
// replay log (replay.go).

const (
	recHeader     = 8
	maxRecordSize = 8 << 20
	segSuffix     = ".seg"
)

var crcTable = crc32.MakeTable(crc32.Castagnoli)

// pos addresses a byte offset inside a segment.
type pos struct {
	Seg uint64
	Off int64
}

func (p pos) less(q pos) bool { return p.Seg < q.Seg || (p.Seg == q.Seg && p.Off < q.Off) }

type segInfo struct {
	id   uint64
	size int64 // committed bytes
}

type seglog struct {
	dir    string
	segMax int64

	mu      sync.Mutex
	segs    []segInfo // ascending by id; last is the append target
	cur     *os.File
	total   int64
	corrupt uint64
	closed  bool
}

var errLogClosed = errors.New("event: log is closed")

func segName(id uint64) string { return fmt.Sprintf("%020d%s", id, segSuffix) }

func openSeglog(dir string, segMax int64) (*seglog, error) {
	if segMax <= 0 {
		segMax = 4 << 20
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	l := &seglog{dir: dir, segMax: segMax}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range ents {
		name := e.Name()
		if !strings.HasSuffix(name, segSuffix) {
			continue
		}
		id, err := strconv.ParseUint(strings.TrimSuffix(name, segSuffix), 10, 64)
		if err != nil {
			continue
		}
		st, err := e.Info()
		if err != nil {
			return nil, err
		}
		l.segs = append(l.segs, segInfo{id: id, size: st.Size()})
	}
	sort.Slice(l.segs, func(i, j int) bool { return l.segs[i].id < l.segs[j].id })
	if n := len(l.segs); n > 0 {
		// Only the newest segment can have a torn tail.
		good, err := validPrefix(filepath.Join(dir, segName(l.segs[n-1].id)))
		if err != nil {
			return nil, err
		}
		if good != l.segs[n-1].size {
			if err := os.Truncate(filepath.Join(dir, segName(l.segs[n-1].id)), good); err != nil {
				return nil, err
			}
			l.segs[n-1].size = good
		}
	}
	for _, s := range l.segs {
		l.total += s.size
	}
	if len(l.segs) == 0 {
		l.segs = []segInfo{{id: 1}}
	}
	if err := l.openCur(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *seglog) openCur() error {
	last := l.segs[len(l.segs)-1]
	f, err := os.OpenFile(filepath.Join(l.dir, segName(last.id)), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	l.cur = f
	return nil
}

// validPrefix returns the length of the leading run of intact records.
func validPrefix(path string) (int64, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer f.Close()
	var off int64
	hdr := make([]byte, recHeader)
	buf := make([]byte, 0, 4096)
	for {
		if _, err := io.ReadFull(f, hdr); err != nil {
			return off, nil
		}
		n := int(binary.BigEndian.Uint32(hdr))
		if n > maxRecordSize {
			return off, nil
		}
		if cap(buf) < n {
			buf = make([]byte, n)
		}
		buf = buf[:n]
		if _, err := io.ReadFull(f, buf); err != nil {
			return off, nil
		}
		if crc32.Checksum(buf, crcTable) != binary.BigEndian.Uint32(hdr[4:]) {
			return off, nil
		}
		off += int64(recHeader + n)
	}
}

// Append writes one record. The record is visible to readers when Append
// returns, durable after Sync.
func (l *seglog) Append(payload []byte) error {
	if len(payload) > maxRecordSize {
		return fmt.Errorf("event: record of %d bytes exceeds the %d byte limit", len(payload), maxRecordSize)
	}
	rec := make([]byte, recHeader+len(payload))
	binary.BigEndian.PutUint32(rec, uint32(len(payload)))
	binary.BigEndian.PutUint32(rec[4:], crc32.Checksum(payload, crcTable))
	copy(rec[recHeader:], payload)

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return errLogClosed
	}
	last := &l.segs[len(l.segs)-1]
	if last.size > 0 && last.size+int64(len(rec)) > l.segMax {
		if err := l.cur.Sync(); err != nil {
			return err
		}
		l.cur.Close()
		l.segs = append(l.segs, segInfo{id: last.id + 1})
		if err := l.openCur(); err != nil {
			l.cur = nil
			l.closed = true
			return err
		}
		last = &l.segs[len(l.segs)-1]
	}
	n, err := l.cur.Write(rec)
	if err != nil {
		// A partial record would poison later appends: cut it off.
		if n > 0 {
			l.cur.Truncate(last.size)
		}
		return err
	}
	last.size += int64(n)
	l.total += int64(n)
	return nil
}

// Sync makes appended records durable.
func (l *seglog) Sync() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.cur == nil {
		return nil
	}
	return l.cur.Sync()
}

// Size is the total bytes held.
func (l *seglog) Size() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.total
}

// Corrupt counts records that failed validation while reading.
func (l *seglog) Corrupt() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.corrupt
}

// Start is the position of the oldest byte held.
func (l *seglog) Start() pos {
	l.mu.Lock()
	defer l.mu.Unlock()
	return pos{Seg: l.segs[0].id}
}

// record is one entry read from the log; Next is the position after it.
type record struct {
	Data []byte
	Next pos
}

// ReadFrom returns up to max records at or after p, crossing segments. A
// position in a segment that no longer exists continues at the oldest one.
func (l *seglog) ReadFrom(p pos, max int) ([]record, error) {
	l.mu.Lock()
	segs := make([]segInfo, len(l.segs))
	copy(segs, l.segs)
	l.mu.Unlock()

	var out []record
	for i := 0; i < len(segs) && len(out) < max; i++ {
		s := segs[i]
		if s.id < p.Seg {
			continue
		}
		off := int64(0)
		if s.id == p.Seg {
			off = p.Off
		}
		if off >= s.size {
			continue
		}
		recs, bad, err := l.readSeg(s, off, max-len(out))
		out = append(out, recs...)
		if bad {
			l.mu.Lock()
			l.corrupt++
			l.mu.Unlock()
		}
		if err != nil {
			return out, err
		}
		if len(recs) > 0 && len(out) >= max {
			break
		}
	}
	return out, nil
}

// readSeg reads up to max records of one segment from off, bounded by the
// committed size so a record being appended is never seen half written.
func (l *seglog) readSeg(s segInfo, off int64, max int) (recs []record, corrupt bool, err error) {
	f, err := os.Open(filepath.Join(l.dir, segName(s.id)))
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil // trimmed concurrently
	}
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return nil, false, err
	}
	hdr := make([]byte, recHeader)
	for len(recs) < max && off+recHeader <= s.size {
		if _, err := io.ReadFull(f, hdr); err != nil {
			return recs, false, nil
		}
		n := int64(binary.BigEndian.Uint32(hdr))
		if n > maxRecordSize || off+recHeader+n > s.size {
			return recs, true, nil
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(f, buf); err != nil {
			return recs, true, nil
		}
		if crc32.Checksum(buf, crcTable) != binary.BigEndian.Uint32(hdr[4:]) {
			return recs, true, nil
		}
		off += recHeader + n
		recs = append(recs, record{Data: buf, Next: pos{Seg: s.id, Off: off}})
	}
	return recs, false, nil
}

// DropBefore deletes every segment older than p.Seg. The segment being
// appended to is never deleted.
func (l *seglog) DropBefore(p pos) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	var firstErr error
	for len(l.segs) > 1 && l.segs[0].id < p.Seg {
		s := l.segs[0]
		if err := os.Remove(filepath.Join(l.dir, segName(s.id))); err != nil && !errors.Is(err, os.ErrNotExist) {
			if firstErr == nil {
				firstErr = err
			}
			break
		}
		l.total -= s.size
		l.segs = l.segs[1:]
	}
	return firstErr
}

// TrimTo deletes the oldest segments until at most max bytes remain (the
// newest segment is always kept).
func (l *seglog) TrimTo(max int64) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	for len(l.segs) > 1 && l.total > max {
		s := l.segs[0]
		if err := os.Remove(filepath.Join(l.dir, segName(s.id))); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		l.total -= s.size
		l.segs = l.segs[1:]
	}
	return nil
}

// End is the position after the last committed record.
func (l *seglog) End() pos {
	l.mu.Lock()
	defer l.mu.Unlock()
	last := l.segs[len(l.segs)-1]
	return pos{Seg: last.id, Off: last.size}
}

func (l *seglog) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	if l.cur == nil {
		return nil
	}
	err := l.cur.Sync()
	if cerr := l.cur.Close(); err == nil {
		err = cerr
	}
	return err
}
