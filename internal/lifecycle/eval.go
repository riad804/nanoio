package lifecycle

import (
	"strings"
	"time"
)

// Clock supplies "now". The scanner and the evaluator never read the wall
// clock themselves.
type Clock interface{ Now() time.Time }

// RealClock is the wall clock.
type RealClock struct{}

// Now implements Clock.
func (RealClock) Now() time.Time { return time.Now() }

// Action is what the evaluator decided.
type Action int

const (
	// ActionNone: leave the version alone.
	ActionNone Action = iota
	// ActionTransition: move the version's data to Decision.Tier.
	ActionTransition
	// ActionDeleteMarker: add a delete marker (versioned bucket, current
	// version expired).
	ActionDeleteMarker
	// ActionDelete: permanently remove this version (the object itself in
	// an unversioned bucket, a noncurrent version, or a lone delete marker).
	ActionDelete
)

func (a Action) String() string {
	switch a {
	case ActionTransition:
		return "transition"
	case ActionDeleteMarker:
		return "delete-marker"
	case ActionDelete:
		return "delete"
	}
	return "none"
}

// ObjectOpts is everything the evaluator knows about one version.
type ObjectOpts struct {
	Name         string
	VersionID    string
	IsLatest     bool
	DeleteMarker bool
	ModTime      time.Time
	// SuccessorModTime is when the next-newer version was created, i.e.
	// since when this one has been noncurrent. Meaningful if !IsLatest.
	SuccessorModTime time.Time
	Size             int64
	Tags             map[string]string
	// NumVersions is the number of versions (and markers) the key has.
	NumVersions int
	// NoncurrentIndex is the 1-based position of a noncurrent version among
	// the key's noncurrent versions, newest first.
	NoncurrentIndex int
	// Tier is the tier the version's data already lives in, "".
	Tier string
}

// Decision is the evaluator's answer.
type Decision struct {
	Action Action
	RuleID string
	// Tier is the transition target for ActionTransition.
	Tier string
}

// Versioned is whether the bucket keeps versions (Enabled or Suspended):
// expiring a current version then adds a delete marker instead of removing
// data.
type Versioned bool

func (f *Filter) matches(o *ObjectOpts) bool {
	if !strings.HasPrefix(o.Name, f.Prefix) {
		return false
	}
	for k, v := range f.Tags {
		if got, ok := o.Tags[k]; !ok || got != v {
			return false
		}
	}
	if f.SizeGreaterThan >= 0 && !(o.Size > f.SizeGreaterThan) {
		return false
	}
	if f.SizeLessThan >= 0 && !(o.Size < f.SizeLessThan) {
		return false
	}
	return true
}

// dueAfterDays is the instant an action "N days after t" takes effect: S3
// rounds t+N days up to the next midnight UTC, so everything created on one
// UTC day expires together.
func dueAfterDays(t time.Time, days int) time.Time {
	d := t.UTC().Add(time.Duration(days) * 24 * time.Hour)
	mid := time.Date(d.Year(), d.Month(), d.Day(), 0, 0, 0, 0, time.UTC)
	if mid.Equal(d) {
		return mid
	}
	return mid.AddDate(0, 0, 1)
}

// Eval decides what the configuration does to o at instant now.
//
// Overlapping rules: every enabled rule whose filter matches contributes
// candidates and the strongest wins, in this order: permanent deletion of
// the version, then transition, then creation of a delete marker. Among
// several due transitions the one with the largest Days (the coldest) wins.
// A rule's disabled status removes it entirely.
func (c *Config) Eval(o ObjectOpts, versioned Versioned, now time.Time) Decision {
	if c == nil {
		return Decision{}
	}
	var best Decision
	var bestRank int
	var bestDays int
	consider := func(d Decision, rank, days int) {
		if rank > bestRank || (rank == bestRank && d.Action == ActionTransition && days > bestDays) {
			best, bestRank, bestDays = d, rank, days
		}
	}
	const (
		rankMarker = 1
		rankTrans  = 2
		rankDelete = 3
	)
	for i := range c.Rules {
		r := &c.Rules[i]
		if !r.Enabled || !r.Filter.matches(&o) {
			continue
		}
		switch {
		case o.IsLatest && o.DeleteMarker:
			if e := r.Expiration; e != nil && e.ExpiredObjectDeleteMarker && o.NumVersions == 1 {
				consider(Decision{Action: ActionDelete, RuleID: r.ID}, rankDelete, 0)
			}
		case o.IsLatest:
			if e := r.Expiration; e != nil && !e.ExpiredObjectDeleteMarker {
				due := false
				switch {
				case e.Days > 0:
					due = !now.Before(dueAfterDays(o.ModTime, e.Days))
				case !e.Date.IsZero():
					due = !now.Before(e.Date)
				}
				if due {
					if versioned {
						consider(Decision{Action: ActionDeleteMarker, RuleID: r.ID}, rankMarker, 0)
					} else {
						consider(Decision{Action: ActionDelete, RuleID: r.ID}, rankDelete, 0)
					}
				}
			}
			for _, t := range r.Transitions {
				due := false
				if t.Date.IsZero() {
					due = !now.Before(dueAfterDays(o.ModTime, t.Days))
				} else {
					due = !now.Before(t.Date)
				}
				if due && c.mayMove(o.Tier, t.StorageClass, t.rank()) {
					consider(Decision{Action: ActionTransition, RuleID: r.ID, Tier: t.StorageClass}, rankTrans, t.Days)
				}
			}
		default: // noncurrent
			if o.DeleteMarker && r.NoncurrentExpiration == nil {
				continue
			}
			if n := r.NoncurrentExpiration; n != nil {
				due := false
				ageOK := n.NoncurrentDays == 0 || !now.Before(dueAfterDays(o.SuccessorModTime, n.NoncurrentDays))
				switch {
				case n.NewerNoncurrentVersions > 0:
					due = o.NoncurrentIndex > n.NewerNoncurrentVersions && ageOK
				default:
					due = ageOK
				}
				if due {
					consider(Decision{Action: ActionDelete, RuleID: r.ID}, rankDelete, 0)
				}
			}
			if !o.DeleteMarker {
				for _, t := range r.NoncurrentTransition {
					if !now.Before(dueAfterDays(o.SuccessorModTime, t.NoncurrentDays)) && c.mayMove(o.Tier, t.StorageClass, t.NoncurrentDays) {
						consider(Decision{Action: ActionTransition, RuleID: r.ID, Tier: t.StorageClass}, rankTrans, t.NoncurrentDays)
					}
				}
			}
		}
	}
	return best
}

// AbortAfter returns, for an upload on key initiated at t, whether some
// enabled rule aborts it by now.
func (c *Config) AbortAfter(key string, initiated, now time.Time) (RuleID string, abort bool) {
	if c == nil {
		return "", false
	}
	o := ObjectOpts{Name: key}
	for i := range c.Rules {
		r := &c.Rules[i]
		if !r.Enabled || r.AbortIncompleteMultipartDays == 0 {
			continue
		}
		f := r.Filter
		f.Tags = nil
		if !f.matchesName(&o) {
			continue
		}
		if !now.Before(dueAfterDays(initiated, r.AbortIncompleteMultipartDays)) {
			return r.ID, true
		}
	}
	return "", false
}

func (f *Filter) matchesName(o *ObjectOpts) bool {
	return strings.HasPrefix(o.Name, f.Prefix)
}

// HasAbortRules reports whether any enabled rule aborts uploads.
func (c *Config) HasAbortRules() bool {
	for _, r := range c.Rules {
		if r.Enabled && r.AbortIncompleteMultipartDays > 0 {
			return true
		}
	}
	return false
}

// rank orders transitions along time: day-based ones by Days, date-based
// ones after every day-based one, by date.
func (t Transition) rank() int {
	if t.Date.IsZero() {
		return t.Days
	}
	return 100000 + int(t.Date.Unix()/86400)
}

// mayMove reports whether a version currently in tier from (or in no tier)
// may be sent to tier to by a transition of the given rank: only forward
// along the configured chain, never back to a warmer tier and never to the
// tier it is already in. A version in a tier that no rule mentions is left
// alone.
func (c *Config) mayMove(from, to string, rank int) bool {
	if from == to {
		return false
	}
	if from == "" {
		return true
	}
	cur := -1
	for i := range c.Rules {
		r := &c.Rules[i]
		for _, t := range r.Transitions {
			if t.StorageClass == from && t.rank() > cur {
				cur = t.rank()
			}
		}
		for _, t := range r.NoncurrentTransition {
			if t.StorageClass == from && t.NoncurrentDays > cur {
				cur = t.NoncurrentDays
			}
		}
	}
	return cur >= 0 && rank > cur
}
