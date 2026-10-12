package meta

import (
	"errors"
	"testing"
	"time"
)

var lockNow = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

func lockedObj(l *Lock) *Version {
	return &Version{Type: TypeObject, VersionID: "v", DataDir: "d", ModTime: lockNow, Lock: l}
}

// TestCheckRemoveMatrix is the deletion half of the enforcement matrix:
// every combination of retention mode, retention state, legal hold and
// bypass, as a table.
func TestCheckRemoveMatrix(t *testing.T) {
	future, past := lockNow.Add(time.Hour), lockNow.Add(-time.Hour)
	tests := []struct {
		name   string
		lock   *Lock
		bypass bool
		want   LockReason // "" = allowed
	}{
		{"no lock", nil, false, ""},
		{"no lock, bypass", nil, true, ""},
		{"empty lock", &Lock{}, false, ""},

		{"compliance active", &Lock{Mode: ModeCompliance, RetainUntil: future}, false, ReasonCompliance},
		{"compliance active, bypass asked", &Lock{Mode: ModeCompliance, RetainUntil: future}, true, ReasonCompliance},
		{"compliance expired", &Lock{Mode: ModeCompliance, RetainUntil: past}, false, ""},
		{"compliance expiring now", &Lock{Mode: ModeCompliance, RetainUntil: lockNow}, false, ""},

		{"governance active", &Lock{Mode: ModeGovernance, RetainUntil: future}, false, ReasonGovernance},
		{"governance active, bypass", &Lock{Mode: ModeGovernance, RetainUntil: future}, true, ""},
		{"governance expired", &Lock{Mode: ModeGovernance, RetainUntil: past}, false, ""},

		{"legal hold only", &Lock{LegalHold: true}, false, ReasonLegalHold},
		{"legal hold, bypass", &Lock{LegalHold: true}, true, ReasonLegalHold},
		{"legal hold over governance, bypass", &Lock{Mode: ModeGovernance, RetainUntil: future, LegalHold: true}, true, ReasonLegalHold},
		{"legal hold over expired retention", &Lock{Mode: ModeCompliance, RetainUntil: past, LegalHold: true}, false, ReasonLegalHold},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckRemove(lockedObj(tt.lock), Guard{Now: lockNow, BypassGovernance: tt.bypass})
			if tt.want == "" {
				if err != nil {
					t.Fatalf("CheckRemove = %v, want allowed", err)
				}
				return
			}
			var le *LockedError
			if !errors.As(err, &le) || !errors.Is(err, ErrLocked) {
				t.Fatalf("CheckRemove = %v, want a *LockedError", err)
			}
			if le.Reason != tt.want {
				t.Errorf("reason = %q, want %q", le.Reason, tt.want)
			}
		})
	}
}

func TestCheckRemoveMarkerIsAlwaysRemovable(t *testing.T) {
	m := &Version{Type: TypeDeleteMarker, VersionID: "m", ModTime: lockNow}
	if err := CheckRemove(m, Guard{Now: lockNow}); err != nil {
		t.Fatal(err)
	}
}

// TestCheckLockChangeMatrix is the modification half: what may a retention
// become, from each starting point.
func TestCheckLockChangeMatrix(t *testing.T) {
	d := func(h int) time.Time { return lockNow.Add(time.Duration(h) * time.Hour) }
	gov := func(h int) *Lock { return &Lock{Mode: ModeGovernance, RetainUntil: d(h)} }
	comp := func(h int) *Lock { return &Lock{Mode: ModeCompliance, RetainUntil: d(h)} }
	tests := []struct {
		name   string
		old    *Lock
		next   *Lock
		bypass bool
		want   LockReason
	}{
		{"none -> governance", nil, gov(1), false, ""},
		{"none -> compliance", nil, comp(1), false, ""},

		{"compliance extend", comp(2), comp(5), false, ""},
		{"compliance same", comp(2), comp(2), false, ""},
		{"compliance shorten", comp(5), comp(2), false, ReasonCompliance},
		{"compliance shorten, bypass", comp(5), comp(2), true, ReasonCompliance},
		{"compliance remove", comp(5), nil, false, ReasonCompliance},
		{"compliance remove, bypass", comp(5), nil, true, ReasonCompliance},
		{"compliance -> governance later", comp(2), gov(9), true, ReasonCompliance},
		{"compliance expired -> anything", comp(-1), gov(1), false, ""},
		{"compliance expired -> removed", comp(-1), nil, false, ""},

		{"governance extend", gov(2), gov(5), false, ""},
		{"governance -> compliance", gov(2), comp(2), false, ""},
		{"governance shorten", gov(5), gov(2), false, ReasonGovernance},
		{"governance shorten, bypass", gov(5), gov(2), true, ""},
		{"governance remove", gov(5), nil, false, ReasonGovernance},
		{"governance remove, bypass", gov(5), nil, true, ""},
		{"governance -> compliance shorter", gov(5), comp(2), false, ReasonGovernance},
		{"governance expired -> removed", gov(-1), nil, false, ""},

		{"legal hold alone is not retention", &Lock{LegalHold: true}, nil, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckLockChange("v", tt.old, tt.next, Guard{Now: lockNow, BypassGovernance: tt.bypass})
			if tt.want == "" {
				if err != nil {
					t.Fatalf("CheckLockChange = %v, want allowed", err)
				}
				return
			}
			var le *LockedError
			if !errors.As(err, &le) || le.Reason != tt.want {
				t.Fatalf("CheckLockChange = %v, want reason %q", err, tt.want)
			}
		})
	}
}

// TestApplyFunctionsRespectLock pins that the mutation functions themselves
// refuse, so no caller can forget the check.
func TestApplyFunctionsRespectLock(t *testing.T) {
	locked := Version{Type: TypeObject, VersionID: NullVersion, Seq: 1, ModTime: lockNow, DataDir: "d",
		Lock: &Lock{Mode: ModeCompliance, RetainUntil: lockNow.Add(time.Hour)}}
	g := Guard{Now: lockNow, BypassGovernance: true}
	fresh := func() *File {
		f := &File{Format: FormatLocked}
		if _, err := f.ApplyPut(locked, g); err != nil {
			t.Fatal(err)
		}
		return f
	}
	t.Run("remove", func(t *testing.T) {
		f := fresh()
		if _, err := f.ApplyRemove(NullVersion, 2, g); !errors.Is(err, ErrLocked) {
			t.Fatalf("ApplyRemove = %v, want ErrLocked", err)
		}
		if len(f.Versions) != 1 || f.Gen != 1 {
			t.Errorf("a refused removal changed the file: %+v", f)
		}
	})
	t.Run("overwrite the null version", func(t *testing.T) {
		f := fresh()
		next := Version{Type: TypeObject, VersionID: NullVersion, Seq: 2, ModTime: lockNow, DataDir: "e"}
		if _, err := f.ApplyPut(next, g); !errors.Is(err, ErrLocked) {
			t.Fatalf("ApplyPut = %v, want ErrLocked", err)
		}
	})
	t.Run("replace the null version with a marker", func(t *testing.T) {
		f := fresh()
		if _, err := f.ApplyMarker(NullVersion, 2, lockNow, g); !errors.Is(err, ErrLocked) {
			t.Fatalf("ApplyMarker = %v, want ErrLocked", err)
		}
	})
	t.Run("a marker with a new id is fine", func(t *testing.T) {
		f := fresh()
		if _, err := f.ApplyMarker("m1", 2, lockNow, g); err != nil {
			t.Fatal(err)
		}
		if f.Latest().Type != TypeDeleteMarker || f.Find(NullVersion) == nil {
			t.Errorf("marker did not stack on the locked version: %+v", f.Versions)
		}
	})
	t.Run("removal once expired", func(t *testing.T) {
		f := fresh()
		late := Guard{Now: lockNow.Add(2 * time.Hour)}
		if _, err := f.ApplyRemove(NullVersion, 2, late); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("whole key", func(t *testing.T) {
		if err := fresh().Protected(Guard{Now: lockNow, BypassGovernance: true}); !errors.Is(err, ErrLocked) {
			t.Fatalf("Protected = %v, want ErrLocked", err)
		}
	})
}

func TestApplySetLock(t *testing.T) {
	f := &File{Format: FormatVersioned}
	if _, err := f.ApplyPut(Version{Type: TypeObject, VersionID: "a", Seq: 1, ModTime: lockNow, DataDir: "d"}, Guard{}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.ApplyMarker("m", 2, lockNow, Guard{}); err != nil {
		t.Fatal(err)
	}
	g := Guard{Now: lockNow}
	until := lockNow.Add(time.Hour)
	if err := f.ApplySetLock("a", 3, &Lock{Mode: ModeGovernance, RetainUntil: until}, g); err != nil {
		t.Fatal(err)
	}
	if f.Gen != 3 || f.Find("a").Lock == nil {
		t.Fatalf("lock not applied: %+v", f)
	}
	if err := f.ApplySetLock("a", 3, nil, g); !errors.Is(err, ErrStale) {
		t.Errorf("same generation: %v, want ErrStale", err)
	}
	if err := f.ApplySetLock("a", 4, nil, g); !errors.Is(err, ErrLocked) {
		t.Errorf("remove governance: %v, want ErrLocked", err)
	}
	if err := f.ApplySetLock("m", 4, &Lock{LegalHold: true}, g); !errors.Is(err, ErrNotLockable) {
		t.Errorf("lock a marker: %v, want ErrNotLockable", err)
	}
	if err := f.ApplySetLock("zz", 4, &Lock{LegalHold: true}, g); !errors.Is(err, ErrNoSuchVersion) {
		t.Errorf("missing: %v, want ErrNoSuchVersion", err)
	}
	if err := f.ApplySetLock("a", 4, &Lock{Mode: ModeGovernance}, g); err == nil {
		t.Error("a mode without a date was accepted")
	}
	if err := f.ApplySetLock("a", 4, &Lock{Mode: ModeGovernance, RetainUntil: until, LegalHold: true}, g); err != nil {
		t.Errorf("add legal hold: %v", err)
	}
}

func TestLockedFileFormatAndRoundTrip(t *testing.T) {
	f := &File{Gen: 1, Versions: []Version{{Type: TypeObject, VersionID: "a", Seq: 1, ModTime: lockNow, DataDir: "d",
		Lock: &Lock{Mode: ModeCompliance, RetainUntil: lockNow.Add(time.Hour), LegalHold: true}}}}
	b, err := Encode(f)
	if err != nil {
		t.Fatal(err)
	}
	g, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if g.Format != FormatLocked {
		t.Errorf("format = %d, want %d", g.Format, FormatLocked)
	}
	l := g.Versions[0].Lock
	if l == nil || l.Mode != ModeCompliance || !l.LegalHold || !l.RetainUntil.Equal(lockNow.Add(time.Hour)) {
		t.Errorf("lock lost in round trip: %+v", l)
	}
	// A file without any lock stays on the older schema, so builds that
	// predate object lock keep reading it.
	plain := &File{Gen: 1, Versions: []Version{{Type: TypeObject, VersionID: "a", Seq: 1, ModTime: lockNow, DataDir: "d",
		Lock: &Lock{}}}}
	b, _ = Encode(plain)
	if g, _ := Decode(b); g == nil || g.Format != FormatVersioned || g.Versions[0].Lock != nil {
		t.Errorf("empty lock changed the schema: %+v", g)
	}
}
