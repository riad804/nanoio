package event

import (
	"encoding/binary"
	"encoding/json"
	"errors"
)

// DefaultReplayBytes bounds the replay log when none is configured.
const DefaultReplayBytes = 64 << 20

// replaySegments is how many segments the byte budget is divided into; the
// log drops its oldest segment when the budget is exceeded, so it holds
// between (replaySegments-1)/replaySegments and the full budget.
const replaySegments = 8

// ReplayLog is the node's append-only record of every published event,
// bounded in size and rotated by segment. It exists so a stream consumer
// (the admin event stream, `nanoio admin trace`) can resume after a
// disconnect with "everything after sequence N", and so a restarted node can
// continue its sequence numbers.
//
// It is a best-effort journal, written off the request path by a single
// goroutine fed from a bus subscription; unlike the target queues it is
// allowed to lose its oldest events (rotation) and, under overload, events
// the bus dropped.
type ReplayLog struct {
	log      *seglog
	maxBytes int64
	last     uint64
}

// OpenReplayLog opens the log in dir with a budget of maxBytes
// (<= 0 means DefaultReplayBytes).
func OpenReplayLog(dir string, maxBytes int64) (*ReplayLog, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultReplayBytes
	}
	seg := maxBytes / replaySegments
	if seg < 64<<10 {
		seg = 64 << 10
	}
	l, err := openSeglog(dir, seg)
	if err != nil {
		return nil, err
	}
	r := &ReplayLog{log: l, maxBytes: maxBytes}
	// The newest segment holds the highest sequence number.
	p := l.Start()
	end := l.End()
	for {
		recs, err := l.ReadFrom(p, 1024)
		if err != nil {
			l.Close()
			return nil, err
		}
		if len(recs) == 0 {
			break
		}
		for _, rec := range recs {
			if len(rec.Data) >= 8 {
				if s := binary.BigEndian.Uint64(rec.Data); s > r.last {
					r.last = s
				}
			}
		}
		p = recs[len(recs)-1].Next
		if !p.less(end) {
			break
		}
	}
	return r, nil
}

// LastSeq is the highest sequence number found when the log was opened or
// appended since.
func (r *ReplayLog) LastSeq() uint64 { return r.last }

// Append journals one event (durable after Sync). Not safe for concurrent
// use; the manager's single writer is the only appender.
func (r *ReplayLog) Append(e *Event) error {
	body, err := json.Marshal(e)
	if err != nil {
		return err
	}
	rec := make([]byte, 8+len(body))
	binary.BigEndian.PutUint64(rec, e.Seq)
	copy(rec[8:], body)
	if err := r.log.Append(rec); err != nil {
		return err
	}
	if e.Seq > r.last {
		r.last = e.Seq
	}
	if r.log.Size() > r.maxBytes {
		return r.log.TrimTo(r.maxBytes)
	}
	return nil
}

// Sync flushes the journal.
func (r *ReplayLog) Sync() error { return r.log.Sync() }

// Size is the bytes held on disk.
func (r *ReplayLog) Size() int64 { return r.log.Size() }

// OldestSeq is the sequence number of the oldest retained event, or 0 when
// the log is empty. A consumer asking to resume from before it has missed
// events.
func (r *ReplayLog) OldestSeq() uint64 {
	recs, err := r.log.ReadFrom(r.log.Start(), 1)
	if err != nil || len(recs) == 0 || len(recs[0].Data) < 8 {
		return 0
	}
	return binary.BigEndian.Uint64(recs[0].Data)
}

// Read calls fn, in order, for every retained event with Seq > since, until
// fn returns false.
func (r *ReplayLog) Read(since uint64, fn func(*Event) bool) error {
	p := r.log.Start()
	for {
		recs, err := r.log.ReadFrom(p, 512)
		if err != nil {
			return err
		}
		if len(recs) == 0 {
			return nil
		}
		for _, rec := range recs {
			if len(rec.Data) < 8 || binary.BigEndian.Uint64(rec.Data) <= since {
				continue
			}
			var e Event
			if err := json.Unmarshal(rec.Data[8:], &e); err != nil {
				continue
			}
			if !fn(&e) {
				return nil
			}
		}
		p = recs[len(recs)-1].Next
	}
}

// Close syncs and closes the log.
func (r *ReplayLog) Close() error { return r.log.Close() }

var errReplayDisabled = errors.New("event: the replay log is disabled")
