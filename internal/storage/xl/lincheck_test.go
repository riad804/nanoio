package xl

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"testing"
)

// A tiny linearizability checker for one register (an object key).
//
// States: "" means absent, otherwise the value. Operations:
//
//	put(v)  always succeeds, state becomes v
//	del     always succeeds, state becomes absent
//	get     returns the state (absent is reported as found=false)
//
// A call that failed with an error is indeterminate: it may have taken
// effect at any time after it was invoked, or never. Such calls carry
// ret = +Inf and optional = true. Failed gets carry no information and are
// not recorded.
type linOp struct {
	kind     string // "put", "del", "get"
	val      string // put: value written; get: value observed
	found    bool   // get: whether the object was found
	call     int64
	ret      int64
	optional bool
	label    string
}

func (o linOp) String() string {
	switch o.kind {
	case "put":
		return fmt.Sprintf("put(%s)[%d,%d]%s", o.val, o.call, o.ret, opt(o))
	case "del":
		return fmt.Sprintf("del[%d,%d]%s", o.call, o.ret, opt(o))
	}
	if !o.found {
		return fmt.Sprintf("get=absent[%d,%d]", o.call, o.ret)
	}
	return fmt.Sprintf("get=%s[%d,%d]", o.val, o.call, o.ret)
}

func opt(o linOp) string {
	if o.optional {
		return "?"
	}
	return ""
}

const inf = math.MaxInt64

// linearizable reports whether ops have a legal sequential order that
// respects real time.
func linearizable(ops []linOp) bool {
	if len(ops) > 62 {
		panic("history too long for the bitmask checker")
	}
	sort.SliceStable(ops, func(i, j int) bool { return ops[i].call < ops[j].call })
	n := len(ops)
	var required uint64
	for i, o := range ops {
		if !o.optional {
			required |= 1 << i
		}
	}
	type key struct {
		done  uint64
		state string
	}
	seen := map[key]bool{}
	var search func(done uint64, state string) bool
	search = func(done uint64, state string) bool {
		if done&required == required {
			return true
		}
		k := key{done, state}
		if seen[k] {
			return false
		}
		seen[k] = true
		// An op may go next only if no other pending *required* op
		// returned before it was called.
		minRet := int64(inf)
		for i := 0; i < n; i++ {
			if done&(1<<i) == 0 && !ops[i].optional && ops[i].ret < minRet {
				minRet = ops[i].ret
			}
		}
		for i := 0; i < n; i++ {
			if done&(1<<i) != 0 || ops[i].call > minRet {
				continue
			}
			o := ops[i]
			next := state
			switch o.kind {
			case "put":
				next = o.val
			case "del":
				next = ""
			case "get":
				if (state != "") != o.found || (o.found && state != o.val) {
					continue
				}
			}
			if search(done|1<<i, next) {
				return true
			}
		}
		return false
	}
	return search(0, "")
}

func TestLinearizabilityChecker(t *testing.T) {
	put := func(v string, c, r int64) linOp { return linOp{kind: "put", val: v, call: c, ret: r} }
	get := func(v string, found bool, c, r int64) linOp {
		return linOp{kind: "get", val: v, found: found, call: c, ret: r}
	}
	del := func(c, r int64) linOp { return linOp{kind: "del", call: c, ret: r} }
	maybe := func(o linOp) linOp { o.optional, o.ret = true, inf; return o }

	tests := []struct {
		name string
		ops  []linOp
		want bool
	}{
		{"empty", nil, true},
		{"read your write", []linOp{put("a", 0, 1), get("a", true, 2, 3)}, true},
		{"read before any write", []linOp{get("", false, 0, 1), put("a", 2, 3)}, true},
		{"stale read after write returned", []linOp{put("a", 0, 1), get("", false, 2, 3)}, false},
		{"concurrent put and get may see either", []linOp{put("a", 0, 10), get("", false, 1, 2)}, true},
		{"concurrent put and get may see the put", []linOp{put("a", 0, 10), get("a", true, 1, 2)}, true},
		{"new value then old value", []linOp{put("a", 0, 1), put("b", 2, 10), get("b", true, 3, 4), get("a", true, 5, 6)}, false},
		{"delete then read absent", []linOp{put("a", 0, 1), del(2, 3), get("", false, 4, 5)}, true},
		{"read after delete sees value", []linOp{put("a", 0, 1), del(2, 3), get("a", true, 4, 5)}, false},
		{"value from nowhere", []linOp{get("zzz", true, 0, 1)}, false},
		{"indeterminate put explains a later read", []linOp{maybe(put("a", 0, 0)), get("a", true, 5, 6)}, true},
		{"indeterminate put may never happen", []linOp{maybe(put("a", 0, 0)), get("", false, 5, 6)}, true},
		{"indeterminate put cannot be seen then unseen then seen", []linOp{
			put("z", 0, 1), maybe(put("a", 2, 2)), get("a", true, 5, 6), get("z", true, 7, 8)}, false},
		{"two sequential gets agree", []linOp{put("a", 0, 1), get("a", true, 2, 3), get("a", true, 4, 5)}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := linearizable(append([]linOp(nil), tt.ops...)); got != tt.want {
				t.Errorf("linearizable = %v, want %v", got, tt.want)
			}
		})
	}
}

// A linearizability checker for one key's version list.
//
// State: the versions newest first, as ids, a trailing "!" marking a delete
// marker. Operations:
//
//	put(id)      pushes id
//	marker(id)   pushes id!
//	remove(id)   removes id if present (always succeeds)
//	latest       returns the newest entry: none, an object id or a marker id
//	version(id)  returns found (object), marker, or absent
type verOp struct {
	kind   string // put, marker, remove, latest, version
	id     string // the version created, removed or asked for
	result string // latest: "none", "obj:<id>", "dm:<id>"; version: "found", "marker", "absent"
	call   int64
	ret    int64
}

func (o verOp) String() string {
	return fmt.Sprintf("%s(%s)=%s[%d,%d]", o.kind, o.id, o.result, o.call, o.ret)
}

func versionsLinearizable(ops []verOp) bool {
	if len(ops) > 62 {
		panic("history too long for the bitmask checker")
	}
	sort.SliceStable(ops, func(i, j int) bool { return ops[i].call < ops[j].call })
	n := len(ops)
	all := uint64(1)<<n - 1
	type key struct {
		done  uint64
		state string
	}
	seen := map[key]bool{}
	var search func(done uint64, state []string) bool
	search = func(done uint64, state []string) bool {
		if done == all {
			return true
		}
		k := key{done, strings.Join(state, ",")}
		if seen[k] {
			return false
		}
		seen[k] = true
		minRet := int64(inf)
		for i := 0; i < n; i++ {
			if done&(1<<i) == 0 && ops[i].ret < minRet {
				minRet = ops[i].ret
			}
		}
		for i := 0; i < n; i++ {
			if done&(1<<i) != 0 || ops[i].call > minRet {
				continue
			}
			o := ops[i]
			next := state
			switch o.kind {
			case "put":
				next = append([]string{o.id}, state...)
			case "marker":
				next = append([]string{o.id + "!"}, state...)
			case "remove":
				next = nil
				for _, e := range state {
					if strings.TrimSuffix(e, "!") != o.id {
						next = append(next, e)
					}
				}
			case "latest":
				want := "none"
				if len(state) > 0 {
					if top := state[0]; strings.HasSuffix(top, "!") {
						want = "dm:" + strings.TrimSuffix(top, "!")
					} else {
						want = "obj:" + top
					}
				}
				if o.result != want {
					continue
				}
			case "version":
				want := "absent"
				for _, e := range state {
					if strings.TrimSuffix(e, "!") == o.id {
						want = "found"
						if strings.HasSuffix(e, "!") {
							want = "marker"
						}
					}
				}
				if o.result != want {
					continue
				}
			}
			if search(done|1<<i, next) {
				return true
			}
		}
		return false
	}
	return search(0, nil)
}

func TestVersionListCheckerCatchesViolations(t *testing.T) {
	op := func(kind, id, res string, c, r int64) verOp {
		return verOp{kind: kind, id: id, result: res, call: c, ret: r}
	}
	tests := []struct {
		name string
		ops  []verOp
		want bool
	}{
		{"put then latest", []verOp{op("put", "a", "", 0, 1), op("latest", "", "obj:a", 2, 3)}, true},
		{"newest wins", []verOp{op("put", "a", "", 0, 1), op("put", "b", "", 2, 3), op("latest", "", "obj:b", 4, 5)}, true},
		{"stale latest after a newer put returned", []verOp{op("put", "a", "", 0, 1), op("put", "b", "", 2, 3), op("latest", "", "obj:a", 4, 5)}, false},
		{"marker hides", []verOp{op("put", "a", "", 0, 1), op("marker", "m", "", 2, 3), op("latest", "", "dm:m", 4, 5)}, true},
		{"removing the marker undeletes", []verOp{op("put", "a", "", 0, 1), op("marker", "m", "", 2, 3),
			op("remove", "m", "", 4, 5), op("latest", "", "obj:a", 6, 7)}, true},
		{"object visible through a removed marker's absence", []verOp{op("put", "a", "", 0, 1), op("marker", "m", "", 2, 3),
			op("remove", "m", "", 4, 5), op("latest", "", "dm:m", 6, 7)}, false},
		{"removed version is absent", []verOp{op("put", "a", "", 0, 1), op("remove", "a", "", 2, 3), op("version", "a", "absent", 4, 5)}, true},
		{"removed version still found", []verOp{op("put", "a", "", 0, 1), op("remove", "a", "", 2, 3), op("version", "a", "found", 4, 5)}, false},
		{"concurrent put and latest may miss it", []verOp{op("put", "a", "", 0, 10), op("latest", "", "none", 1, 2)}, true},
		{"version of a marker", []verOp{op("marker", "m", "", 0, 1), op("version", "m", "marker", 2, 3)}, true},
		{"read of a version never written", []verOp{op("latest", "", "obj:ghost", 0, 1)}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := versionsLinearizable(append([]verOp(nil), tt.ops...)); got != tt.want {
				t.Errorf("linearizable = %v, want %v", got, tt.want)
			}
		})
	}
}
