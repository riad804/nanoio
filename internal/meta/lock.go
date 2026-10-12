package meta

import (
	"errors"
	"fmt"
	"time"
)

// LockMode is an S3 Object Lock retention mode.
type LockMode string

const (
	// ModeGovernance retention can be shortened or removed only by a caller
	// who asked to bypass it and was allowed to.
	ModeGovernance LockMode = "GOVERNANCE"
	// ModeCompliance retention can never be shortened, removed or bypassed
	// by anyone until it expires.
	ModeCompliance LockMode = "COMPLIANCE"
)

// Valid reports whether m is a retention mode.
func (m LockMode) Valid() bool { return m == ModeGovernance || m == ModeCompliance }

// Lock is the object lock state of one object version: an optional
// retention period and an independent legal hold. A nil *Lock and the zero
// Lock both mean "not locked".
type Lock struct {
	// Mode and RetainUntil are set together or not at all.
	Mode        LockMode  `json:"mode,omitempty"`
	RetainUntil time.Time `json:"retainUntil,omitzero"`
	LegalHold   bool      `json:"legalHold,omitempty"`
}

// Empty reports whether l holds nothing.
func (l *Lock) Empty() bool {
	return l == nil || l.Mode == "" && l.RetainUntil.IsZero() && !l.LegalHold
}

// RetentionActive reports whether the retention period is still running at
// now. A retention whose date has passed protects nothing.
func (l *Lock) RetentionActive(now time.Time) bool {
	return l != nil && l.Mode != "" && l.RetainUntil.After(now)
}

// Normalized returns l without empty content (nil when nothing is held) and
// with times in UTC, so equal locks encode identically.
func (l *Lock) Normalized() *Lock {
	if l.Empty() {
		return nil
	}
	c := *l
	c.RetainUntil = c.RetainUntil.UTC()
	return &c
}

func (l *Lock) validate() error {
	switch {
	case l.Mode == "" && !l.RetainUntil.IsZero():
		return errors.New("retain-until date without a mode")
	case l.Mode != "" && !l.Mode.Valid():
		return fmt.Errorf("unknown retention mode %q", l.Mode)
	case l.Mode != "" && l.RetainUntil.IsZero():
		return errors.New("retention mode without a retain-until date")
	}
	return nil
}

// Guard carries what a mutation needs to decide whether a locked version may
// be touched. It is built once by whoever coordinates the change and passed
// to every drive so they all decide the same way.
type Guard struct {
	// Now is the time retention is judged against. Zero means the
	// mutation's own clock (time.Now).
	Now time.Time
	// BypassGovernance is set only after the caller was authorised to
	// bypass governance retention and asked to. It has no effect on
	// COMPLIANCE retention or a legal hold.
	BypassGovernance bool
}

// now returns g.Now, or the wall clock when unset.
func (g Guard) now() time.Time {
	if g.Now.IsZero() {
		return time.Now()
	}
	return g.Now
}

// LockReason says what protects a version.
type LockReason string

const (
	ReasonLegalHold  LockReason = "legal hold"
	ReasonCompliance LockReason = "compliance retention"
	ReasonGovernance LockReason = "governance retention"
)

// ErrLocked is matched (errors.Is) by every refusal made because of object
// lock.
var ErrLocked = errors.New("meta: version is protected by object lock")

// LockedError is a refusal to change or remove a protected version.
type LockedError struct {
	VersionID string
	Reason    LockReason
	Until     time.Time // zero for a legal hold
}

func (e *LockedError) Error() string {
	s := fmt.Sprintf("%v: version %q: %s", ErrLocked, e.VersionID, e.Reason)
	if !e.Until.IsZero() {
		s += " until " + e.Until.UTC().Format(time.RFC3339)
	}
	return s
}

func (e *LockedError) Is(target error) bool { return target == ErrLocked }

// CheckRemove reports whether v may be permanently removed or replaced. It
// is the single rule every deletion goes through:
//
//   - a legal hold blocks it, whatever the retention;
//   - active COMPLIANCE retention blocks it, whoever asks;
//   - active GOVERNANCE retention blocks it unless g.BypassGovernance;
//   - expired retention blocks nothing.
//
// Delete markers carry no lock and are always removable.
func CheckRemove(v *Version, g Guard) error {
	if v == nil || v.Type != TypeObject || v.Lock.Empty() {
		return nil
	}
	if v.Lock.LegalHold {
		return &LockedError{VersionID: v.VersionID, Reason: ReasonLegalHold}
	}
	now := g.now()
	if v.Lock.RetentionActive(now) {
		switch {
		case v.Lock.Mode == ModeCompliance:
			return &LockedError{VersionID: v.VersionID, Reason: ReasonCompliance, Until: v.Lock.RetainUntil}
		case !g.BypassGovernance:
			return &LockedError{VersionID: v.VersionID, Reason: ReasonGovernance, Until: v.Lock.RetainUntil}
		}
	}
	return nil
}

// CheckLockChange validates replacing the lock state old of a version with
// next. The legal hold may be set or cleared freely (its permission is the
// caller's to check); the retention may only be strengthened unless:
//
//   - it has expired, when anything goes;
//   - it is GOVERNANCE and g.BypassGovernance, when it may be shortened,
//     removed, or changed in any way.
//
// COMPLIANCE retention may only be extended, and stays COMPLIANCE.
func CheckLockChange(versionID string, old *Lock, next *Lock, g Guard) error {
	if !old.RetentionActive(g.now()) {
		return nil
	}
	var nextMode LockMode
	var nextUntil time.Time
	if next != nil {
		nextMode, nextUntil = next.Mode, next.RetainUntil
	}
	extends := nextMode != "" && !nextUntil.Before(old.RetainUntil)
	switch old.Mode {
	case ModeCompliance:
		if nextMode == ModeCompliance && extends {
			return nil
		}
		return &LockedError{VersionID: versionID, Reason: ReasonCompliance, Until: old.RetainUntil}
	default: // governance
		if extends || g.BypassGovernance {
			return nil
		}
		return &LockedError{VersionID: versionID, Reason: ReasonGovernance, Until: old.RetainUntil}
	}
}

// ErrNotLockable means the version is a delete marker, which carries no
// lock.
var ErrNotLockable = errors.New("meta: a delete marker cannot be locked")

// ApplySetLock replaces the lock state of one version and makes seq the
// file's generation. The change is judged by CheckLockChange.
func (f *File) ApplySetLock(id string, seq uint64, next *Lock, g Guard) error {
	if seq == 0 || seq <= f.Generation() {
		return fmt.Errorf("%w: seq %d, generation %d", ErrStale, seq, f.Generation())
	}
	v := f.Find(id)
	if v == nil {
		return fmt.Errorf("%w: %q", ErrNoSuchVersion, id)
	}
	if v.Type != TypeObject {
		return fmt.Errorf("%w: %q", ErrNotLockable, id)
	}
	next = next.Normalized()
	if next != nil {
		if err := next.validate(); err != nil {
			return fmt.Errorf("meta: %w", err)
		}
	}
	if err := CheckLockChange(id, v.Lock, next, g); err != nil {
		return err
	}
	v.Lock = next
	f.Gen = seq
	return nil
}

// Protected reports whether any version of f is, at g, immune to removal
// with the guard's privileges. Whole-key and whole-bucket removals use it.
func (f *File) Protected(g Guard) error {
	for i := range f.Versions {
		if err := CheckRemove(&f.Versions[i], g); err != nil {
			return err
		}
	}
	return nil
}
