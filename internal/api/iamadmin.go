package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"nanoio/internal/event"
	"nanoio/internal/iam"
)

// Runtime IAM. The IAM file seeds the store and stays authoritative for the
// names it defines; users, groups and policies created through the admin
// API are documents in the system bucket, one per entity:
//
//	_iam/user/<accessKey>.json   _iam/group/<name>.json   _iam/policy/<name>.json
//
// plus _iam/version, a counter that every change replaces. Every node polls
// it and reloads when it moves, so a change made on one node reaches the
// others within the poll interval.
//
// Each document carries the time and origin site of its last change, which
// is what site replication resolves conflicts by (last writer wins,
// ties broken by origin site ID), and a tombstone flag so a deletion
// replicates and cannot be undone by a stale copy.

const (
	iamPrefix       = "_iam/"
	iamVersionKey   = "_iam/version"
	iamPollInterval = 2 * time.Second
)

// iamDoc is one runtime IAM entity.
type iamDoc struct {
	Kind    string `json:"kind"` // user, group, policy
	Name    string `json:"name"`
	Updated int64  `json:"updated"` // unix nanoseconds of the change
	Origin  string `json:"origin,omitempty"`
	Deleted bool   `json:"deleted,omitempty"`

	User   *iam.UserEntry  `json:"user,omitempty"`
	Group  *iam.GroupEntry `json:"group,omitempty"`
	Policy json.RawMessage `json:"policy,omitempty"`
}

func iamDocName(kind, name string) string { return iamPrefix + kind + "/" + name + ".json" }

// newer reports whether d should replace other under last-writer-wins.
func (d *iamDoc) newer(other *iamDoc) bool {
	if other == nil {
		return true
	}
	if d.Updated != other.Updated {
		return d.Updated > other.Updated
	}
	return d.Origin > other.Origin
}

type iamRuntime struct {
	s    *Server
	es   *eventStore
	mu   sync.Mutex // serialises changes made by this process
	seen string
}

func (s *Server) initIAM(store *iam.Store) {
	if store == nil {
		return
	}
	rt := &iamRuntime{s: s, es: &eventStore{st: s.st}}
	s.iamrt = rt
	s.iam = store
	store.SetResolver(s.stsResolve)
	rt.refresh(context.Background(), true)
	ctx, cancel := context.WithCancel(context.Background())
	s.stop = append(s.stop, cancel)
	s.bg.Add(1)
	go s.stsSweepLoop(ctx)
	s.bg.Add(1)
	go func() {
		defer s.bg.Done()
		t := time.NewTicker(iamPollInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				rt.refresh(ctx, false)
			}
		}
	}()
}

func (rt *iamRuntime) readDoc(ctx context.Context, name string) (*iamDoc, error) {
	b, err := rt.es.Get(ctx, name)
	if errors.Is(err, event.ErrSharedNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var d iamDoc
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// refresh reloads the store if the version counter moved (or force).
func (rt *iamRuntime) refresh(ctx context.Context, force bool) {
	defer func() {
		// A backend that panics must not take the server (or its IAM poll
		// loop) down with it; the next poll tries again.
		if r := recover(); r != nil {
			rt.s.log.Error("iam: refresh panicked", "panic", r)
		}
	}()
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	v, err := rt.es.Get(cctx, iamVersionKey)
	cur := ""
	if err == nil {
		cur = string(v)
	}
	rt.mu.Lock()
	changed := cur != rt.seen
	rt.mu.Unlock()
	if !changed && !force {
		return
	}
	if err := rt.reload(cctx); err != nil {
		rt.s.log.Warn("iam: reload failed", "err", err)
		return
	}
	rt.mu.Lock()
	rt.seen = cur
	rt.mu.Unlock()
}

// reload rebuilds the store from every document.
func (rt *iamRuntime) reload(ctx context.Context) error {
	names, err := rt.es.List(ctx, iamPrefix, 100000)
	if err != nil {
		return err
	}
	dyn := &iam.File{Version: 1, Policies: map[string]json.RawMessage{}}
	var users []iam.UserEntry
	var groups []iam.GroupEntry
	for _, n := range names {
		if n == iamVersionKey || !strings.HasSuffix(n, ".json") {
			continue
		}
		d, err := rt.readDoc(ctx, n)
		if err != nil {
			return err
		}
		if d == nil || d.Deleted {
			continue
		}
		switch {
		case d.Kind == "policy" && len(d.Policy) > 0:
			dyn.Policies[d.Name] = d.Policy
		case d.Kind == "user" && d.User != nil:
			users = append(users, *d.User)
		case d.Kind == "group" && d.Group != nil:
			groups = append(groups, *d.Group)
		}
	}
	// Entities replicate independently and may arrive in any order, so a
	// reference to a policy that does not exist (yet) is dropped here, not
	// treated as an error that would stop everyone logging in.
	known := map[string]bool{}
	for _, n := range iam.CannedPolicyNames() {
		known[n] = true
	}
	for n := range dyn.Policies {
		known[n] = true
	}
	for _, p := range rt.s.iam.StaticPolicyNames() {
		known[p] = true
	}
	keep := func(in []string) []string {
		var out []string
		for _, p := range in {
			if known[p] {
				out = append(out, p)
			}
		}
		return out
	}
	for i := range users {
		users[i].Policies = keep(users[i].Policies)
	}
	for i := range groups {
		groups[i].Policies = keep(groups[i].Policies)
	}
	sort.Slice(users, func(i, j int) bool { return users[i].AccessKey < users[j].AccessKey })
	sort.Slice(groups, func(i, j int) bool { return groups[i].Name < groups[j].Name })
	dyn.Users, dyn.Groups = users, groups
	return rt.s.iam.Load(dyn)
}

// apply stores d if it is newer than what is there, reloads, and (for a
// change that did not come from a peer) tells site replication. It reports
// whether the change took effect.
func (rt *iamRuntime) apply(ctx context.Context, d *iamDoc, fromSite bool) (bool, error) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	name := iamDocName(d.Kind, d.Name)
	cur, err := rt.readDoc(ctx, name)
	if err != nil {
		return false, err
	}
	if cur != nil && !d.newer(cur) {
		return false, nil
	}
	b, err := json.Marshal(d)
	if err != nil {
		return false, err
	}
	if err := rt.es.Put(ctx, name, b); err != nil {
		return false, err
	}
	ver := strconv.FormatInt(time.Now().UnixNano(), 10)
	if err := rt.es.Put(ctx, iamVersionKey, []byte(ver)); err != nil {
		return false, err
	}
	if err := rt.reload(ctx); err != nil {
		return true, err
	}
	rt.seen = ver
	if !fromSite {
		rt.s.siteChanged("iam", name, b)
	}
	return true, nil
}

// ----- admin API --------------------------------------------------------------

type userView struct {
	AccessKey string   `json:"accessKey"`
	Status    string   `json:"status"`
	Policies  []string `json:"policies"`
	Groups    []string `json:"groups,omitempty"`
	Static    bool     `json:"static,omitempty"`
}

type groupView struct {
	Name     string   `json:"name"`
	Status   string   `json:"status"`
	Members  []string `json:"members"`
	Policies []string `json:"policies"`
	Static   bool     `json:"static,omitempty"`
}

func (s *Server) adminIAM(q *request, kind string) {
	if s.iamrt == nil {
		s.fail(q, notImplemented("runtime IAM is not enabled"))
		return
	}
	switch q.r.Method {
	case http.MethodGet:
		if !s.authorize(q, "nanoio:ListIAM", "", "", nil) {
			return
		}
		s.iamList(q, kind)
	case http.MethodPut, http.MethodPost:
		if !s.authorize(q, "nanoio:ManageIAM", "", "", nil) {
			return
		}
		s.iamSet(q, kind)
	case http.MethodDelete:
		if !s.authorize(q, "nanoio:ManageIAM", "", "", nil) {
			return
		}
		s.iamDelete(q, kind)
	default:
		s.fail(q, errBadMethod)
	}
}

func (s *Server) iamList(q *request, kind string) {
	ctx := q.ctx()
	names, err := s.iamrt.es.List(ctx, iamPrefix+kind+"/", 100000)
	if err != nil {
		s.fail(q, err)
		return
	}
	out := []any{}
	for _, n := range names {
		d, err := s.iamrt.readDoc(ctx, n)
		if err != nil {
			s.fail(q, err)
			return
		}
		if d == nil || d.Deleted {
			continue
		}
		switch kind {
		case "user":
			if d.User != nil {
				st := d.User.Status
				if st == "" {
					st = "enabled"
				}
				out = append(out, userView{AccessKey: d.User.AccessKey, Status: st, Policies: d.User.Policies, Groups: s.iam.GroupsOf(d.User.AccessKey)})
			}
		case "group":
			if d.Group != nil {
				st := d.Group.Status
				if st == "" {
					st = "enabled"
				}
				out = append(out, groupView{Name: d.Group.Name, Status: st, Members: d.Group.Members, Policies: d.Group.Policies})
			}
		case "policy":
			out = append(out, map[string]any{"name": d.Name, "policy": json.RawMessage(d.Policy)})
		}
	}
	writeJSON(q.w, out)
}

func (s *Server) iamSet(q *request, kind string) {
	body, err := s.readBody(q, 1<<20)
	if err != nil {
		s.fail(q, err)
		return
	}
	d := &iamDoc{Kind: kind, Updated: time.Now().UnixNano(), Origin: s.siteID()}
	switch kind {
	case "user":
		var u iam.UserEntry
		if err := json.Unmarshal(body, &u); err != nil {
			s.fail(q, invalidArgument("invalid user document: "+err.Error()))
			return
		}
		c := iam.Credential{AccessKey: u.AccessKey, SecretKey: u.SecretKey}
		if err := c.Validate(); err != nil {
			s.fail(q, invalidArgument(err.Error()))
			return
		}
		if u.AccessKey == s.iam.Root() {
			s.fail(q, invalidArgument("that is the root access key"))
			return
		}
		if u.Status != "" && u.Status != "enabled" && u.Status != "disabled" {
			s.fail(q, invalidArgument("status must be enabled or disabled"))
			return
		}
		if bad := s.unknownPolicy(u.Policies); bad != "" {
			s.fail(q, invalidArgument("unknown policy "+strconv.Quote(bad)))
			return
		}
		d.Name, d.User = u.AccessKey, &u
	case "group":
		var g iam.GroupEntry
		if err := json.Unmarshal(body, &g); err != nil {
			s.fail(q, invalidArgument("invalid group document: "+err.Error()))
			return
		}
		if g.Name == "" || strings.ContainsAny(g.Name, "/ ") {
			s.fail(q, invalidArgument("a group needs a name without '/' or spaces"))
			return
		}
		if bad := s.unknownPolicy(g.Policies); bad != "" {
			s.fail(q, invalidArgument("unknown policy "+strconv.Quote(bad)))
			return
		}
		d.Name, d.Group = g.Name, &g
	case "policy":
		var in struct {
			Name   string          `json:"name"`
			Policy json.RawMessage `json:"policy"`
		}
		if err := json.Unmarshal(body, &in); err != nil || in.Name == "" || len(in.Policy) == 0 {
			s.fail(q, invalidArgument("a policy document is {\"name\": ..., \"policy\": {...}}"))
			return
		}
		if strings.ContainsAny(in.Name, "/ ") {
			s.fail(q, invalidArgument("a policy name cannot contain '/' or spaces"))
			return
		}
		if _, err := iam.ParsePolicy(in.Policy); err != nil {
			s.fail(q, invalidArgument("invalid policy: "+err.Error()))
			return
		}
		d.Name, d.Policy = in.Name, in.Policy
	}
	if s.iam.IsStatic(kind, d.Name) {
		s.fail(q, &APIError{"AccessDenied", d.Name + " is defined by the IAM file and cannot be changed at run time.", http.StatusForbidden})
		return
	}
	if _, err := s.iamrt.apply(q.ctx(), d, false); err != nil {
		s.fail(q, err)
		return
	}
	q.w.WriteHeader(http.StatusNoContent)
}

func (s *Server) unknownPolicy(names []string) string {
	known := map[string]bool{}
	for _, n := range s.iam.PolicyNames() {
		known[n] = true
	}
	for _, n := range names {
		if !known[n] {
			return n
		}
	}
	return ""
}

func (s *Server) iamDelete(q *request, kind string) {
	name := q.query.Get("name")
	if kind == "user" && name == "" {
		name = q.query.Get("accessKey")
	}
	if name == "" {
		s.fail(q, invalidArgument("name is required"))
		return
	}
	if s.iam.IsStatic(kind, name) {
		s.fail(q, &APIError{"AccessDenied", name + " is defined by the IAM file and cannot be removed at run time.", http.StatusForbidden})
		return
	}
	if kind == "policy" {
		if users := s.iam.PolicyUsers(name); len(users) > 0 {
			s.fail(q, &APIError{"PolicyInUse", "The policy is attached to " + strings.Join(users, ", ") + ".", http.StatusConflict})
			return
		}
	}
	d := &iamDoc{Kind: kind, Name: name, Deleted: true, Updated: time.Now().UnixNano(), Origin: s.siteID()}
	if _, err := s.iamrt.apply(q.ctx(), d, false); err != nil {
		s.fail(q, err)
		return
	}
	q.w.WriteHeader(http.StatusNoContent)
}
