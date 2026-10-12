package meta

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func putv(t *testing.T, f *File, st Versioning, seq uint64, mod time.Time) (id string, gone []string) {
	t.Helper()
	id, err := VersionIDFor(st)
	if err != nil {
		t.Fatal(err)
	}
	v := Version{Type: TypeObject, VersionID: id, Seq: seq, ModTime: mod, Size: 1,
		DataDir: ".nanoio-data-" + id + "-" + string(rune('a'+seq)), ETag: "e"}
	gone, err = f.ApplyPut(v, Guard{})
	if err != nil {
		t.Fatal(err)
	}
	return id, gone
}

func ids(f *File) []string {
	var out []string
	for _, v := range f.Versions {
		out = append(out, v.VersionID)
	}
	return out
}

func TestVersionIDFor(t *testing.T) {
	if id, err := VersionIDFor(Enabled); err != nil || len(id) != 36 {
		t.Errorf("Enabled = %q, %v; want a UUID", id, err)
	}
	for _, st := range []Versioning{Unversioned, Suspended} {
		if id, err := VersionIDFor(st); err != nil || id != NullVersion {
			t.Errorf("%v = %q, %v; want the null version", st, id, err)
		}
	}
	a, _ := VersionIDFor(Enabled)
	b, _ := VersionIDFor(Enabled)
	if a == b {
		t.Error("two versions got the same ID")
	}
}

func TestApplyPutByState(t *testing.T) {
	t.Run("unversioned: each write replaces the null version", func(t *testing.T) {
		f := &File{Format: FormatVersion}
		_, gone := putv(t, f, Unversioned, 1, t0)
		if len(gone) != 0 {
			t.Errorf("first write superseded %v", gone)
		}
		_, gone = putv(t, f, Unversioned, 2, t0.Add(time.Second))
		if len(f.Versions) != 1 || len(gone) != 1 {
			t.Errorf("%d versions, superseded %v; want 1 and the old data dir", len(f.Versions), gone)
		}
		if f.Gen != 2 || f.Versions[0].Seq != 2 {
			t.Errorf("gen %d seq %d", f.Gen, f.Versions[0].Seq)
		}
	})
	t.Run("enabled: versions accumulate, newest first", func(t *testing.T) {
		f := &File{Format: FormatVersion}
		var made []string
		for i := uint64(1); i <= 4; i++ {
			id, gone := putv(t, f, Enabled, i, t0.Add(time.Duration(i)*time.Second))
			if len(gone) != 0 {
				t.Errorf("a new version superseded %v", gone)
			}
			made = append([]string{id}, made...)
		}
		if got := ids(f); !reflect.DeepEqual(got, made) {
			t.Errorf("order %v, want newest first %v", got, made)
		}
	})
	t.Run("suspended after enabled: null replaces only the null version", func(t *testing.T) {
		f := &File{Format: FormatVersion}
		v1, _ := putv(t, f, Enabled, 1, t0)
		putv(t, f, Suspended, 2, t0.Add(time.Second))
		putv(t, f, Enabled, 3, t0.Add(2*time.Second))
		_, gone := putv(t, f, Suspended, 4, t0.Add(3*time.Second))
		if len(gone) != 1 || len(f.Versions) != 3 {
			t.Fatalf("%d versions, superseded %v; want 3 and one dir", len(f.Versions), gone)
		}
		if f.Find(v1) == nil {
			t.Error("the first versioned object was lost")
		}
		if f.Versions[0].VersionID != NullVersion || f.Versions[0].Seq != 4 {
			t.Errorf("latest = %+v, want the new null version", f.Versions[0])
		}
	})
	t.Run("stale or unsequenced writes are refused", func(t *testing.T) {
		f := &File{Format: FormatVersion}
		putv(t, f, Unversioned, 5, t0)
		for _, seq := range []uint64{0, 4, 5} {
			_, err := f.ApplyPut(Version{Type: TypeObject, Seq: seq, ModTime: t0, DataDir: "d"}, Guard{})
			if !errors.Is(err, ErrStale) {
				t.Errorf("seq %d: err = %v, want ErrStale", seq, err)
			}
		}
		if _, err := f.ApplyPut(Version{Type: TypeDeleteMarker, Seq: 9, ModTime: t0}, Guard{}); err == nil {
			t.Error("ApplyPut accepted a delete marker")
		}
	})
}

func TestApplyMarkerAndRemove(t *testing.T) {
	f := &File{Format: FormatVersion}
	v1, _ := putv(t, f, Enabled, 1, t0)
	id, _ := VersionIDFor(Enabled)
	if _, err := f.ApplyMarker(id, 2, t0.Add(time.Second), Guard{}); err != nil {
		t.Fatal(err)
	}
	if l := f.Latest(); l.Type != TypeDeleteMarker || l.VersionID != id {
		t.Fatalf("latest = %+v", l)
	}
	// Removing the marker undeletes the key.
	if _, err := f.ApplyRemove(id, 3, Guard{}); err != nil {
		t.Fatal(err)
	}
	if l := f.Latest(); l.VersionID != v1 || l.Type != TypeObject {
		t.Errorf("after removing the marker latest = %+v", l)
	}
	if f.Gen != 3 {
		t.Errorf("gen = %d", f.Gen)
	}
	// Removing a version returns its data directory.
	gone, err := f.ApplyRemove(v1, 4, Guard{})
	if err != nil || len(gone) != 1 {
		t.Errorf("remove = %v, %v", gone, err)
	}
	if len(f.Versions) != 0 {
		t.Errorf("%d versions left", len(f.Versions))
	}
	if _, err := f.ApplyRemove(v1, 5, Guard{}); !errors.Is(err, ErrNoSuchVersion) {
		t.Errorf("removing twice = %v", err)
	}
	if _, err := f.ApplyRemove("x", 4, Guard{}); !errors.Is(err, ErrStale) {
		t.Errorf("stale remove = %v", err)
	}

	t.Run("suspended marker replaces the null version", func(t *testing.T) {
		g := &File{Format: FormatVersion}
		putv(t, g, Suspended, 1, t0)
		gone, err := g.ApplyMarker(NullVersion, 2, t0.Add(time.Second), Guard{})
		if err != nil || len(gone) != 1 {
			t.Fatalf("marker = %v, %v", gone, err)
		}
		if len(g.Versions) != 1 || g.Versions[0].Type != TypeDeleteMarker {
			t.Errorf("versions = %+v", g.Versions)
		}
	})
}

func TestOrderingBySeqNotClock(t *testing.T) {
	// Seq 2 carries an EARLIER ModTime (a node with a slow clock wrote it):
	// it is still the newer version.
	f := &File{Format: FormatVersion, Gen: 2, Versions: []Version{
		{Type: TypeObject, VersionID: "a", Seq: 1, ModTime: t0.Add(time.Hour), DataDir: "da"},
		{Type: TypeObject, VersionID: "b", Seq: 2, ModTime: t0, DataDir: "db"},
	}}
	b, err := Encode(f)
	if err != nil {
		t.Fatal(err)
	}
	g, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(g); !reflect.DeepEqual(got, []string{"b", "a"}) {
		t.Errorf("order = %v, want [b a] (by sequence)", got)
	}
	if g.Latest().VersionID != "b" {
		t.Error("latest is chosen by clock")
	}
	// Pre-versioning entries (no Seq) sort below sequenced ones, by time.
	h := &File{Format: FormatVersion, Versions: []Version{
		{Type: TypeObject, VersionID: "old1", ModTime: t0, DataDir: "x"},
		{Type: TypeObject, VersionID: "old2", ModTime: t0.Add(time.Hour), DataDir: "y"},
		{Type: TypeObject, VersionID: "new", Seq: 1, ModTime: t0.Add(-time.Hour), DataDir: "z"},
	}}
	b, _ = Encode(h)
	g, _ = Decode(b)
	if got := ids(g); !reflect.DeepEqual(got, []string{"new", "old2", "old1"}) {
		t.Errorf("mixed order = %v", got)
	}
}

func TestFormatSelection(t *testing.T) {
	one := &File{Format: FormatVersioned /* ignored */, Versions: []Version{obj("", t0)}}
	b, _ := Encode(one)
	if f, _ := Decode(b); f.Format != FormatVersion {
		t.Errorf("a plain single object was written as format %d", f.Format)
	}
	cases := map[string]*File{
		"two versions": {Versions: []Version{obj("a", t0), obj("b", t0.Add(time.Second))}},
		"gen":          {Gen: 1, Versions: []Version{obj("", t0)}},
		"seq":          {Versions: []Version{func() Version { v := obj("", t0); v.Seq = 1; return v }()}},
		"marker":       {Versions: []Version{{Type: TypeDeleteMarker, VersionID: "m", ModTime: t0}}},
	}
	for name, f := range cases {
		f.Format = FormatVersion
		b, err := Encode(f)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		g, err := Decode(b)
		if err != nil || g.Format != FormatVersioned {
			t.Errorf("%s: format %d, %v; want %d", name, g.Format, err, FormatVersioned)
		}
	}
}

func TestGenerationFallbackAndResolve(t *testing.T) {
	legacy := &File{Format: FormatVersion, Versions: []Version{{Type: TypeObject, ModTime: t0, DataDir: "d", Generation: 7}}}
	if g := legacy.Generation(); g != 7 {
		t.Errorf("legacy generation = %d, want the version's 7", g)
	}
	legacy.Gen = 9
	if g := legacy.Generation(); g != 9 {
		t.Errorf("generation = %d, want Gen 9", g)
	}

	f := &File{Format: FormatVersion}
	v1, _ := putv(t, f, Enabled, 1, t0)
	v2, _ := putv(t, f, Enabled, 2, t0.Add(time.Second))
	for _, tt := range []struct {
		id     string
		latest bool
		want   string
		err    error
	}{
		{"", true, v2, nil},
		{v1, false, v1, nil},
		{NullVersion, false, "", ErrNoSuchVersion},
		{"nope", false, "", ErrNoSuchVersion},
	} {
		got, err := f.Resolve(tt.id, tt.latest)
		if !errors.Is(err, tt.err) || (err == nil && got.VersionID != tt.want) {
			t.Errorf("Resolve(%q, %v) = %+v, %v; want %q, %v", tt.id, tt.latest, got, err, tt.want, tt.err)
		}
	}
	if _, err := (&File{}).Resolve("", true); !errors.Is(err, ErrNoSuchVersion) {
		t.Errorf("empty file latest = %v", err)
	}
}

func TestAfter(t *testing.T) {
	f := &File{Format: FormatVersion}
	a, _ := putv(t, f, Enabled, 1, t0)
	b, _ := putv(t, f, Enabled, 2, t0.Add(time.Second))
	c, _ := putv(t, f, Enabled, 3, t0.Add(2*time.Second))
	// Order: c, b, a.
	if got := ids2(f.After(c)); !reflect.DeepEqual(got, []string{b, a}) {
		t.Errorf("after c = %v", got)
	}
	if got := ids2(f.After(a)); len(got) != 0 {
		t.Errorf("after the oldest = %v", got)
	}
	if got := f.After("gone"); got != nil {
		t.Errorf("after a missing version = %v, want nothing (resume at the next key)", got)
	}
}

func ids2(vs []Version) []string {
	var out []string
	for _, v := range vs {
		out = append(out, v.VersionID)
	}
	return out
}
