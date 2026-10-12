package iam

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"sync"
	"time"
)

// Credential is an access key and its secret.
type Credential struct {
	AccessKey string
	SecretKey string
}

// String redacts the secret so a credential is safe to log by accident.
func (c Credential) String() string {
	return "Credential{AccessKey:" + c.AccessKey + ", SecretKey:<redacted>}"
}

// GoString redacts for %#v.
func (c Credential) GoString() string { return c.String() }

var accessKeyRE = regexp.MustCompile(`^[A-Za-z0-9._@+=-]{3,128}$`)

// Validate enforces the credential rules: the access key becomes part of
// the signing scope and of policy variables, so its alphabet is
// restricted; secrets need some length.
func (c Credential) Validate() error {
	if !accessKeyRE.MatchString(c.AccessKey) {
		return errors.New("access key must be 3-128 characters from A-Z a-z 0-9 . _ @ + = -")
	}
	if n := len(c.SecretKey); n < 8 || n > 128 {
		return errors.New("secret key must be 8-128 characters")
	}
	for _, r := range c.SecretKey {
		if r < 0x21 || r > 0x7e {
			return errors.New("secret key must be printable ASCII without spaces")
		}
	}
	return nil
}

// File is the on-disk IAM document.
type File struct {
	Version  int                        `json:"version"`
	Users    []UserEntry                `json:"users"`
	Groups   []GroupEntry               `json:"groups,omitempty"`
	Policies map[string]json.RawMessage `json:"policies"`
}

// GroupEntry is a named set of users that share policies. A user's
// effective policies are its own plus those of every enabled group it is a
// member of; as everywhere, an explicit Deny wins.
type GroupEntry struct {
	Name string `json:"name"`
	// Status is "enabled" (default) or "disabled": a disabled group
	// contributes no policies.
	Status   string   `json:"status,omitempty"`
	Members  []string `json:"members"`
	Policies []string `json:"policies"`
}

// UserEntry is one user in the file.
type UserEntry struct {
	AccessKey string `json:"accessKey"`
	SecretKey string `json:"secretKey"`
	// Status is "enabled" (default) or "disabled".
	Status string `json:"status,omitempty"`
	// Policies names canned or file-defined policies attached to the user.
	Policies []string `json:"policies"`

	// The fields below describe derived credentials: a service account
	// (Parent set) acts with the rights of its parent, narrowed by an
	// optional SessionPolicy; a temporary credential (Kind "sts") carries
	// its own Policies and a Token the caller must present.
	Kind          string          `json:"kind,omitempty"`
	Parent        string          `json:"parent,omitempty"`
	SessionPolicy json.RawMessage `json:"sessionPolicy,omitempty"`
	Expiry        time.Time       `json:"expiry,omitempty"`
	Token         string          `json:"token,omitempty"`
	Name          string          `json:"name,omitempty"`
	Description   string          `json:"description,omitempty"`
	// Provider and ProviderUser say who authenticated a federated
	// credential (e.g. "ldap" and the user's DN), for display and
	// revocation.
	Provider     string `json:"provider,omitempty"`
	ProviderUser string `json:"providerUser,omitempty"`
}

type user struct {
	secret   string
	enabled  bool
	policies []*Policy
	// parent, session and expiry make a derived credential.
	parent  string
	session *Policy
	expiry  time.Time
	token   string
}

// Store is the embedded identity and policy store. It is immutable after
// construction and safe for concurrent use.
type Store struct {
	root Credential
	// static is the document the store was built from (the IAM file);
	// runtime-defined entries are layered on top of it by Load.
	static *File

	mu       sync.RWMutex
	users    map[string]*user
	policies map[string]*Policy
	groups   map[string]*GroupEntry
	now      func() time.Time
	// refUsers are the user documents as loaded, for reference queries.
	refUsers []UserEntry
	// loaded is the whole document the maps were built from.
	loaded *File

	// resolver supplies temporary credentials kept outside the store; eph
	// caches its answers (including "no such credential") per access key.
	resolver Resolver
	emu      sync.Mutex
	eph      map[string]ephEntry
}

// Resolver finds a credential the store does not hold. Temporary
// credentials live in shared storage, one document each, so issuing one
// never rebuilds the store. The entry is cached for ttl; a credential
// revoked elsewhere stays usable here for at most that long, which is why
// the caller picks ttl (and why it is a security-relevant setting).
type Resolver func(accessKey string) (e UserEntry, ttl time.Duration, ok bool)

type ephEntry struct {
	u     *user
	until time.Time
}

// maxEphemeral bounds the resolver cache (a flood of unknown access keys
// must not grow it without limit).
const maxEphemeral = 20000

// negativeTTL is how long "no such credential" is remembered.
const negativeTTL = 3 * time.Second

// SetResolver installs the temporary-credential resolver.
func (s *Store) SetResolver(r Resolver) {
	s.mu.Lock()
	s.resolver = r
	s.mu.Unlock()
	s.emu.Lock()
	s.eph = nil
	s.emu.Unlock()
}

// Forget drops a cached temporary credential so the next use re-resolves it.
func (s *Store) Forget(accessKey string) {
	s.emu.Lock()
	delete(s.eph, accessKey)
	s.emu.Unlock()
}

// lookup returns the user for accessKey: a stored one, or a resolved
// temporary credential. It must be called without s.mu held.
func (s *Store) lookup(accessKey string) (*user, bool) {
	s.mu.RLock()
	u, ok := s.users[accessKey]
	r := s.resolver
	now := s.now()
	s.mu.RUnlock()
	if ok {
		return u, true
	}
	if r == nil {
		return nil, false
	}
	s.emu.Lock()
	if e, hit := s.eph[accessKey]; hit && now.Before(e.until) {
		s.emu.Unlock()
		return e.u, e.u != nil
	}
	s.emu.Unlock()
	entry, ttl, found := r(accessKey)
	var nu *user
	if found {
		nu = s.ephemeralUser(entry)
	}
	if nu == nil {
		ttl = negativeTTL
	}
	if ttl <= 0 {
		ttl = negativeTTL
	}
	s.emu.Lock()
	if s.eph == nil || len(s.eph) >= maxEphemeral {
		s.eph = map[string]ephEntry{}
	}
	s.eph[accessKey] = ephEntry{u: nu, until: now.Add(ttl)}
	s.emu.Unlock()
	return nu, nu != nil
}

// ephemeralUser builds the runtime form of a resolved credential; nil when
// it is not valid (unknown policy names are dropped, as at reload).
func (s *Store) ephemeralUser(e UserEntry) *user {
	nu := &user{secret: e.SecretKey, parent: e.Parent, expiry: e.Expiry, token: e.Token, enabled: e.Status == "" || e.Status == "enabled"}
	if len(e.SessionPolicy) > 0 {
		sp, err := ParsePolicy(e.SessionPolicy)
		if err != nil {
			return nil
		}
		nu.session = sp
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, pn := range e.Policies {
		if p, ok := s.policies[pn]; ok {
			nu.policies = append(nu.policies, p)
		}
	}
	return nu
}

// canned policies are always available by name.
var cannedPolicies = map[string]string{
	"readwrite": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:*"],"Resource":["arn:aws:s3:::*"]}]}`,
	"readonly": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":` +
		`["s3:GetObject","s3:ListBucket","s3:GetBucketLocation","s3:ListAllMyBuckets"],"Resource":["arn:aws:s3:::*"]}]}`,
	"writeonly": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:PutObject"],"Resource":["arn:aws:s3:::*"]}]}`,
	// consoleAdmin and diagnostics are MinIO's built-in administrative
	// policies, under the same names so existing tooling finds them.
	"consoleAdmin": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["admin:*"]},` +
		`{"Effect":"Allow","Action":["kms:*"]},{"Effect":"Allow","Action":["s3:*"],"Resource":["arn:aws:s3:::*"]}]}`,
	"diagnostics": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["admin:Prometheus","admin:Profiling",` +
		`"admin:ServerTrace","admin:ConsoleLog","admin:ServerInfo","admin:TopLocksInfo","admin:OBDInfo","admin:BandwidthMonitor"],` +
		`"Resource":["arn:aws:s3:::*"]}]}`,
}

// CannedPolicyNames lists the built-in policy names, sorted.
func CannedPolicyNames() []string {
	names := make([]string, 0, len(cannedPolicies))
	for n := range cannedPolicies {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// New builds a Store from the root credential and an optional document.
func New(root Credential, f *File) (*Store, error) {
	if err := root.Validate(); err != nil {
		return nil, fmt.Errorf("iam: root credential: %w", err)
	}
	s := &Store{root: root, static: f, now: time.Now}
	if err := s.load(f); err != nil {
		return nil, err
	}
	return s, nil
}

// build validates doc and returns the maps a Store serves from.
func build(root Credential, f *File) (map[string]*user, map[string]*Policy, map[string]*GroupEntry, error) {
	users, policies, groups := map[string]*user{}, map[string]*Policy{}, map[string]*GroupEntry{}
	for name, doc := range cannedPolicies {
		p, err := ParsePolicy([]byte(doc))
		if err != nil {
			return nil, nil, nil, fmt.Errorf("iam: canned policy %q: %w", name, err)
		}
		policies[name] = p
	}
	if f == nil {
		return users, policies, groups, nil
	}
	if f.Version != 0 && f.Version != 1 {
		return nil, nil, nil, fmt.Errorf("iam: unsupported file version %d", f.Version)
	}
	for name, doc := range f.Policies {
		if _, canned := cannedPolicies[name]; canned {
			return nil, nil, nil, fmt.Errorf("iam: policy %q redefines a built-in policy", name)
		}
		if name == "" {
			return nil, nil, nil, errors.New("iam: policy with an empty name")
		}
		p, err := ParsePolicy(doc)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("iam: policy %q: %w", name, err)
		}
		policies[name] = p
	}
	for i, u := range f.Users {
		c := Credential{AccessKey: u.AccessKey, SecretKey: u.SecretKey}
		if err := c.Validate(); err != nil {
			return nil, nil, nil, fmt.Errorf("iam: user %d (%q): %w", i, u.AccessKey, err)
		}
		if u.AccessKey == root.AccessKey {
			return nil, nil, nil, fmt.Errorf("iam: user %q collides with the root access key", u.AccessKey)
		}
		if _, dup := users[u.AccessKey]; dup {
			return nil, nil, nil, fmt.Errorf("iam: duplicate user %q", u.AccessKey)
		}
		nu := &user{secret: u.SecretKey, parent: u.Parent, expiry: u.Expiry, token: u.Token}
		if len(u.SessionPolicy) > 0 {
			sp, err := ParsePolicy(u.SessionPolicy)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("iam: user %q: session policy: %w", u.AccessKey, err)
			}
			nu.session = sp
		}
		switch u.Status {
		case "", "enabled":
			nu.enabled = true
		case "disabled":
		default:
			return nil, nil, nil, fmt.Errorf("iam: user %q: status must be enabled or disabled", u.AccessKey)
		}
		for _, pn := range u.Policies {
			p, ok := policies[pn]
			if !ok {
				return nil, nil, nil, fmt.Errorf("iam: user %q references unknown policy %q", u.AccessKey, pn)
			}
			nu.policies = append(nu.policies, p)
		}
		users[u.AccessKey] = nu
	}
	for i := range f.Groups {
		g := f.Groups[i]
		if g.Name == "" {
			return nil, nil, nil, errors.New("iam: group with an empty name")
		}
		if _, dup := groups[g.Name]; dup {
			return nil, nil, nil, fmt.Errorf("iam: duplicate group %q", g.Name)
		}
		switch g.Status {
		case "", "enabled", "disabled":
		default:
			return nil, nil, nil, fmt.Errorf("iam: group %q: status must be enabled or disabled", g.Name)
		}
		var ps []*Policy
		for _, pn := range g.Policies {
			p, ok := policies[pn]
			if !ok {
				return nil, nil, nil, fmt.Errorf("iam: group %q references unknown policy %q", g.Name, pn)
			}
			ps = append(ps, p)
		}
		for _, m := range g.Members {
			u, ok := users[m]
			if !ok {
				// A member that is not (yet) a user is allowed: groups and
				// users replicate independently and may arrive in any order.
				continue
			}
			if g.Status != "disabled" {
				u.policies = append(u.policies, ps...)
			}
		}
		groups[g.Name] = &g
	}
	return users, policies, groups, nil
}

func (s *Store) load(f *File) error {
	users, policies, groups, err := build(s.root, f)
	if err != nil {
		return err
	}
	var refs []UserEntry
	if f != nil {
		refs = append(refs, f.Users...)
	}
	s.mu.Lock()
	s.users, s.policies, s.groups, s.refUsers, s.loaded = users, policies, groups, refs, f
	s.mu.Unlock()
	return nil
}

// Load replaces the store's contents with the static document it was built
// from plus the runtime-defined users, groups and policies in dyn. On error
// the store is unchanged. A runtime entry may not reuse the name of a
// static one.
func (s *Store) Load(dyn *File) error {
	merged := &File{Version: 1, Policies: map[string]json.RawMessage{}}
	taken := map[string]string{}
	if s.static != nil {
		for n, d := range s.static.Policies {
			merged.Policies[n] = d
			taken["policy:"+n] = "the IAM file"
		}
		merged.Users = append(merged.Users, s.static.Users...)
		for _, u := range s.static.Users {
			taken["user:"+u.AccessKey] = "the IAM file"
		}
		merged.Groups = append(merged.Groups, s.static.Groups...)
		for _, g := range s.static.Groups {
			taken["group:"+g.Name] = "the IAM file"
		}
	}
	if dyn != nil {
		for n, d := range dyn.Policies {
			if where, dup := taken["policy:"+n]; dup {
				return fmt.Errorf("iam: policy %q is already defined by %s", n, where)
			}
			merged.Policies[n] = d
		}
		for _, u := range dyn.Users {
			if where, dup := taken["user:"+u.AccessKey]; dup {
				return fmt.Errorf("iam: user %q is already defined by %s", u.AccessKey, where)
			}
			merged.Users = append(merged.Users, u)
		}
		for _, g := range dyn.Groups {
			if where, dup := taken["group:"+g.Name]; dup {
				return fmt.Errorf("iam: group %q is already defined by %s", g.Name, where)
			}
			merged.Groups = append(merged.Groups, g)
		}
	}
	return s.load(merged)
}

// IsStatic reports whether the named entity ("user", "group" or "policy")
// comes from the IAM file and so cannot be changed at run time.
func (s *Store) IsStatic(kind, name string) bool {
	if s.static == nil {
		return false
	}
	switch kind {
	case "policy":
		_, ok := s.static.Policies[name]
		return ok || cannedPolicies[name] != ""
	case "user":
		for _, u := range s.static.Users {
			if u.AccessKey == name {
				return true
			}
		}
	case "group":
		for _, g := range s.static.Groups {
			if g.Name == name {
				return true
			}
		}
	}
	return false
}

// Root is the root access key, which no runtime user may take.
func (s *Store) Root() string { return s.root.AccessKey }

// LoadFile reads an IAM document from path. Warnings (not errors) are
// returned for conditions the operator should fix, such as a secrets file
// that other users can read.
func LoadFile(path string, root Credential) (*Store, []string, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("iam: %w", err)
	}
	defer fh.Close()
	var warnings []string
	if st, err := fh.Stat(); err == nil && st.Mode().Perm()&0o077 != 0 {
		warnings = append(warnings, fmt.Sprintf("%s is accessible to other users (mode %04o); it holds secret keys, chmod 600 it",
			path, st.Mode().Perm()))
	}
	data, err := io.ReadAll(io.LimitReader(fh, 4<<20))
	if err != nil {
		return nil, nil, fmt.Errorf("iam: %w", err)
	}
	var f File
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, nil, fmt.Errorf("iam: %s: %w", path, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, nil, fmt.Errorf("iam: %s: trailing data after JSON document", path)
	}
	s, err := New(root, &f)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	return s, warnings, nil
}

// SecretKey implements auth.CredentialProvider. Unknown and disabled keys
// are indistinguishable to the caller.
func (s *Store) SecretKey(accessKey string) (string, bool) {
	if accessKey == s.root.AccessKey {
		return s.root.SecretKey, true
	}
	u, ok := s.lookup(accessKey)
	s.mu.RLock()
	defer s.mu.RUnlock()
	if ok && u.enabled && (u.expiry.IsZero() || s.now().Before(u.expiry)) {
		return u.secret, true
	}
	return "", false
}

// Allowed reports whether accessKey may perform req. The root credential
// may do anything; other users get the union of their policies' Allows,
// minus any explicit Deny. Unknown, disabled and expired users are denied.
func (s *Store) Allowed(accessKey string, req Request) bool {
	allow, deny, _ := s.Decide(accessKey, req)
	return allow && !deny
}

// SetClock replaces the clock expiries are judged by (tests).
func (s *Store) SetClock(now func() time.Time) {
	s.mu.Lock()
	s.now = now
	s.mu.Unlock()
}

// evalPolicies evaluates a set of policies: union of Allows, any Deny.
func evalPolicies(ps []*Policy, accessKey string, req Request) (allow, deny bool) {
	for _, p := range ps {
		a, d := p.Evaluate(req, accessKey)
		allow = allow || a
		deny = deny || d
	}
	return
}

// Decide evaluates the identity policies of accessKey for req without
// folding in any resource policy: allow is an explicit Allow, deny an
// explicit Deny. root is true for the root credential, which no policy of
// either kind can restrict (so that a bad bucket policy cannot lock the
// operator out). Unknown, disabled and expired users have neither.
//
// A derived credential (service account, temporary credential) is judged as
// its parent and then narrowed: it may only do what its parent may do and
// its session policy, if it has one, allows; a Deny in either wins.
func (s *Store) Decide(accessKey string, req Request) (allow, deny, root bool) {
	if accessKey == s.root.AccessKey {
		return true, false, true
	}
	u, ok := s.lookup(accessKey)
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !ok || !u.enabled || (!u.expiry.IsZero() && !s.now().Before(u.expiry)) {
		return false, false, false
	}
	switch {
	case u.parent == "":
		allow, deny = evalPolicies(u.policies, accessKey, req)
	case u.parent == s.root.AccessKey:
		allow = true
	default:
		pu, ok := s.users[u.parent]
		if !ok || !pu.enabled || (!pu.expiry.IsZero() && !s.now().Before(pu.expiry)) {
			return false, false, false
		}
		allow, deny = evalPolicies(pu.policies, u.parent, req)
	}
	if u.session != nil {
		sa, sd := u.session.Evaluate(req, accessKey)
		allow = allow && sa
		deny = deny || sd
	}
	return allow, deny, false
}

// Token reports the session token a temporary credential must present ("" if
// none is required) and whether the credential exists and is current.
func (s *Store) Token(accessKey string) (token string, ok bool) {
	if accessKey == s.root.AccessKey {
		return "", true
	}
	u, found := s.lookup(accessKey)
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !found || !u.enabled || (!u.expiry.IsZero() && !s.now().Before(u.expiry)) {
		return "", false
	}
	return u.token, true
}

// IsRoot reports whether accessKey is the root credential.
func (s *Store) IsRoot(accessKey string) bool { return accessKey == s.root.AccessKey }

// UserCount returns the number of file-defined users.
func (s *Store) UserCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.users)
}

// PolicyNames lists every policy (canned, file and runtime), sorted.
func (s *Store) PolicyNames() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.policies))
	for n := range s.policies {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// StaticPolicyNames lists the policies the IAM file and the built-ins
// define.
func (s *Store) StaticPolicyNames() []string {
	out := CannedPolicyNames()
	if s.static != nil {
		for n := range s.static.Policies {
			out = append(out, n)
		}
	}
	return out
}

// GroupsOf lists the groups a user is a member of, sorted.
func (s *Store) GroupsOf(accessKey string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []string
	for n, g := range s.groups {
		for _, m := range g.Members {
			if m == accessKey {
				out = append(out, n)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// PolicyUsers lists the users and groups that reference a policy by name.
// It consults the source documents, so it also finds references from
// disabled users and groups.
func (s *Store) PolicyUsers(policy string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []string
	for _, u := range s.refUsers {
		for _, p := range u.Policies {
			if p == policy {
				out = append(out, "user "+u.AccessKey)
				break
			}
		}
	}
	for _, g := range s.groups {
		for _, p := range g.Policies {
			if p == policy {
				out = append(out, "group "+g.Name)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// Snapshot returns a copy of everything the store serves from: the file's
// and the runtime users, groups and policies (built-in policies included,
// under their document text). Secrets are included; callers redact.
func (s *Store) Snapshot() File {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := File{Version: 1, Policies: map[string]json.RawMessage{}}
	for n, d := range cannedPolicies {
		out.Policies[n] = json.RawMessage(d)
	}
	if s.loaded != nil {
		out.Users = append(out.Users, s.loaded.Users...)
		out.Groups = append(out.Groups, s.loaded.Groups...)
		for n, d := range s.loaded.Policies {
			out.Policies[n] = d
		}
	}
	return out
}

// IsCanned reports whether name is a built-in policy.
func IsCanned(name string) bool { _, ok := cannedPolicies[name]; return ok }

// IsDerived reports whether accessKey is a service account or temporary
// credential (it acts through a parent or its own attached policies).
func (s *Store) IsDerived(accessKey string) bool {
	u, ok := s.lookup(accessKey)
	return ok && (u.parent != "" || u.token != "")
}

// ForgetAll drops every cached temporary credential (after a change that
// affects what they may do).
func (s *Store) ForgetAll() {
	s.emu.Lock()
	s.eph = nil
	s.emu.Unlock()
}
