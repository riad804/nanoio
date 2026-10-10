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
	Policies map[string]json.RawMessage `json:"policies"`
}

// UserEntry is one user in the file.
type UserEntry struct {
	AccessKey string `json:"accessKey"`
	SecretKey string `json:"secretKey"`
	// Status is "enabled" (default) or "disabled".
	Status string `json:"status,omitempty"`
	// Policies names canned or file-defined policies attached to the user.
	Policies []string `json:"policies"`
}

type user struct {
	secret   string
	enabled  bool
	policies []*Policy
}

// Store is the embedded identity and policy store. It is immutable after
// construction and safe for concurrent use.
type Store struct {
	root     Credential
	mu       sync.RWMutex
	users    map[string]*user
	policies map[string]*Policy
}

// canned policies are always available by name.
var cannedPolicies = map[string]string{
	"readwrite": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:*"],"Resource":["arn:aws:s3:::*"]}]}`,
	"readonly": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":` +
		`["s3:GetObject","s3:ListBucket","s3:GetBucketLocation","s3:ListAllMyBuckets"],"Resource":["arn:aws:s3:::*"]}]}`,
	"writeonly": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:PutObject"],"Resource":["arn:aws:s3:::*"]}]}`,
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
	s := &Store{root: root, users: map[string]*user{}, policies: map[string]*Policy{}}
	for name, doc := range cannedPolicies {
		p, err := ParsePolicy([]byte(doc))
		if err != nil {
			return nil, fmt.Errorf("iam: canned policy %q: %w", name, err)
		}
		s.policies[name] = p
	}
	if f == nil {
		return s, nil
	}
	if f.Version != 0 && f.Version != 1 {
		return nil, fmt.Errorf("iam: unsupported file version %d", f.Version)
	}
	for name, doc := range f.Policies {
		if _, canned := cannedPolicies[name]; canned {
			return nil, fmt.Errorf("iam: policy %q redefines a built-in policy", name)
		}
		if name == "" {
			return nil, errors.New("iam: policy with an empty name")
		}
		p, err := ParsePolicy(doc)
		if err != nil {
			return nil, fmt.Errorf("iam: policy %q: %w", name, err)
		}
		s.policies[name] = p
	}
	for i, u := range f.Users {
		c := Credential{AccessKey: u.AccessKey, SecretKey: u.SecretKey}
		if err := c.Validate(); err != nil {
			return nil, fmt.Errorf("iam: user %d (%q): %w", i, u.AccessKey, err)
		}
		if u.AccessKey == root.AccessKey {
			return nil, fmt.Errorf("iam: user %q collides with the root access key", u.AccessKey)
		}
		if _, dup := s.users[u.AccessKey]; dup {
			return nil, fmt.Errorf("iam: duplicate user %q", u.AccessKey)
		}
		nu := &user{secret: u.SecretKey}
		switch u.Status {
		case "", "enabled":
			nu.enabled = true
		case "disabled":
		default:
			return nil, fmt.Errorf("iam: user %q: status must be enabled or disabled", u.AccessKey)
		}
		for _, pn := range u.Policies {
			p, ok := s.policies[pn]
			if !ok {
				return nil, fmt.Errorf("iam: user %q references unknown policy %q", u.AccessKey, pn)
			}
			nu.policies = append(nu.policies, p)
		}
		s.users[u.AccessKey] = nu
	}
	return s, nil
}

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
	s.mu.RLock()
	defer s.mu.RUnlock()
	if accessKey == s.root.AccessKey {
		return s.root.SecretKey, true
	}
	if u, ok := s.users[accessKey]; ok && u.enabled {
		return u.secret, true
	}
	return "", false
}

// Allowed reports whether accessKey may perform req. The root credential
// may do anything; other users get the union of their policies' Allows,
// minus any explicit Deny. Unknown or disabled users are denied.
func (s *Store) Allowed(accessKey string, req Request) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if accessKey == s.root.AccessKey {
		return true
	}
	u, ok := s.users[accessKey]
	if !ok || !u.enabled {
		return false
	}
	allowed := false
	for _, p := range u.policies {
		a, d := p.Evaluate(req, accessKey)
		if d {
			return false
		}
		allowed = allowed || a
	}
	return allowed
}

// IsRoot reports whether accessKey is the root credential.
func (s *Store) IsRoot(accessKey string) bool { return accessKey == s.root.AccessKey }

// UserCount returns the number of file-defined users.
func (s *Store) UserCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.users)
}
