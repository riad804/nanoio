package iam

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var root = Credential{AccessKey: "rootadmin", SecretKey: "root-secret-key-1"}

func mustStore(t *testing.T, f *File) *Store {
	t.Helper()
	s, err := New(root, f)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCredentialValidate(t *testing.T) {
	tests := []struct {
		name string
		c    Credential
		ok   bool
	}{
		{"typical", Credential{"alice", "s3cr3t-value"}, true},
		{"aws-looking", Credential{"AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}, true},
		{"min lengths", Credential{"abc", "12345678"}, true},
		{"email-like key", Credential{"a.b+c@d_e-f=", "12345678"}, true},
		{"key too short", Credential{"ab", "12345678"}, false},
		{"key too long", Credential{strings.Repeat("a", 129), "12345678"}, false},
		{"key with slash breaks the scope", Credential{"a/b", "12345678"}, false},
		{"key with space", Credential{"a b", "12345678"}, false},
		{"key with comma", Credential{"a,b", "12345678"}, false},
		{"key with wildcard", Credential{"a*b", "12345678"}, false},
		{"key with policy variable chars", Credential{"a${b}", "12345678"}, false},
		{"unicode key", Credential{"älice", "12345678"}, false},
		{"secret too short", Credential{"alice", "1234567"}, false},
		{"secret too long", Credential{"alice", strings.Repeat("x", 129)}, false},
		{"secret with space", Credential{"alice", "1234 5678"}, false},
		{"secret with newline", Credential{"alice", "12345678\n"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.c.Validate(); (err == nil) != tt.ok {
				t.Errorf("Validate() = %v, want ok=%v", err, tt.ok)
			}
		})
	}
}

func TestCredentialIsRedactedWhenPrinted(t *testing.T) {
	c := Credential{AccessKey: "alice", SecretKey: "super-secret-value"}
	for _, s := range []string{c.String(), fmt.Sprintf("%v", c), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c), fmt.Sprint(&c)} {
		if strings.Contains(s, "super-secret-value") {
			t.Errorf("secret leaked in %q", s)
		}
	}
}

func TestNewValidates(t *testing.T) {
	user := func(ak string, pol ...string) UserEntry {
		return UserEntry{AccessKey: ak, SecretKey: "user-secret-1", Policies: pol}
	}
	good := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`
	tests := []struct {
		name string
		root Credential
		file *File
		want string // "" = ok
	}{
		{"root only", root, nil, ""},
		{"user with canned policy", root, &File{Users: []UserEntry{user("alice", "readonly")}}, ""},
		{"user with file policy", root, &File{Users: []UserEntry{user("alice", "mine")}, Policies: docs(map[string]string{"mine": good})}, ""},
		{"user without policies is allowed", root, &File{Users: []UserEntry{user("alice")}}, ""},
		{"weak root secret", Credential{"rootadmin", "short"}, nil, "root credential"},
		{"bad root key", Credential{"r", "root-secret-key-1"}, nil, "root credential"},
		{"duplicate user", root, &File{Users: []UserEntry{user("alice"), user("alice")}}, "duplicate"},
		{"user collides with root", root, &File{Users: []UserEntry{user("rootadmin")}}, "root"},
		{"unknown policy", root, &File{Users: []UserEntry{user("alice", "nope")}}, "unknown policy"},
		{"bad user key", root, &File{Users: []UserEntry{user("a b")}}, "access key"},
		{"bad user secret", root, &File{Users: []UserEntry{{AccessKey: "alice", SecretKey: "x"}}}, "secret key"},
		{"bad status", root, &File{Users: []UserEntry{{AccessKey: "alice", SecretKey: "user-secret-1", Status: "paused"}}}, "status"},
		{"redefines canned policy", root, &File{Policies: docs(map[string]string{"readonly": good})}, "built-in"},
		{"invalid policy document", root, &File{Policies: docs(map[string]string{"bad": `{"Version":"2012-10-17"}`})}, "bad"},
		{"future file version", root, &File{Version: 2}, "version"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.root, tt.file)
			switch {
			case tt.want == "" && err != nil:
				t.Errorf("unexpected error: %v", err)
			case tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)):
				t.Errorf("error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

// docs converts policy source strings to the raw JSON the file holds.
func docs(m map[string]string) map[string]json.RawMessage {
	out := make(map[string]json.RawMessage, len(m))
	for k, v := range m {
		out[k] = json.RawMessage(v)
	}
	return out
}

func TestAllowedAndSecrets(t *testing.T) {
	f := &File{
		Users: []UserEntry{
			{AccessKey: "reader", SecretKey: "reader-secret-1", Policies: []string{"readonly"}},
			{AccessKey: "writer", SecretKey: "writer-secret-1", Policies: []string{"writeonly"}},
			{AccessKey: "admin2", SecretKey: "admin2-secret-1", Policies: []string{"readwrite"}},
			{AccessKey: "nobody", SecretKey: "nobody-secret-1"},
			{AccessKey: "off", SecretKey: "off-secret-1234", Status: "disabled", Policies: []string{"readwrite"}},
			{AccessKey: "carol", SecretKey: "carol-secret-12", Policies: []string{"home", "ro-secrets-denied"}},
		},
		Policies: docs(map[string]string{
			"home": `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":"s3:*","Resource":["arn:aws:s3:::data","arn:aws:s3:::data/*"]}]}`,
			"ro-secrets-denied": `{"Version":"2012-10-17","Statement":[
				{"Effect":"Deny","Action":"s3:*","Resource":"arn:aws:s3:::data/secret/*"}]}`,
		}),
	}
	s := mustStore(t, f)

	get := Request{Action: "s3:GetObject", Bucket: "b", Key: "k"}
	put := Request{Action: "s3:PutObject", Bucket: "b", Key: "k"}
	del := Request{Action: "s3:DeleteObject", Bucket: "b", Key: "k"}
	mk := Request{Action: "s3:CreateBucket", Bucket: "b"}
	lsb := Request{Action: "s3:ListAllMyBuckets"}
	list := Request{Action: "s3:ListBucket", Bucket: "b"}
	tests := []struct {
		user string
		req  Request
		want bool
	}{
		{"rootadmin", get, true}, {"rootadmin", del, true}, {"rootadmin", mk, true},
		{"rootadmin", Request{Action: "s3:SomethingFuture", Bucket: "x"}, true},
		{"reader", get, true}, {"reader", list, true}, {"reader", lsb, true},
		{"reader", put, false}, {"reader", del, false}, {"reader", mk, false},
		{"writer", put, true}, {"writer", get, false}, {"writer", list, false},
		{"admin2", get, true}, {"admin2", put, true}, {"admin2", del, true}, {"admin2", mk, true},
		{"nobody", get, false}, {"nobody", lsb, false},
		{"off", get, false}, {"off", put, false},
		{"stranger", get, false},
		{"", get, false},
		{"carol", Request{Action: "s3:GetObject", Bucket: "data", Key: "ok"}, true},
		{"carol", Request{Action: "s3:GetObject", Bucket: "data", Key: "secret/x"}, false},
		{"carol", Request{Action: "s3:GetObject", Bucket: "other", Key: "x"}, false},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s %s", tt.user, tt.req.ARN()+" "+tt.req.Action), func(t *testing.T) {
			if got := s.Allowed(tt.user, tt.req); got != tt.want {
				t.Errorf("Allowed = %v, want %v", got, tt.want)
			}
		})
	}

	secrets := []struct {
		key    string
		secret string
		ok     bool
	}{
		{"rootadmin", "root-secret-key-1", true},
		{"reader", "reader-secret-1", true},
		{"off", "", false}, // disabled is indistinguishable from unknown
		{"stranger", "", false},
		{"", "", false},
	}
	for _, tt := range secrets {
		got, ok := s.SecretKey(tt.key)
		if ok != tt.ok || got != tt.secret {
			t.Errorf("SecretKey(%q) = %q, %v; want %q, %v", tt.key, got, ok, tt.secret, tt.ok)
		}
	}
	if !s.IsRoot("rootadmin") || s.IsRoot("reader") {
		t.Error("IsRoot")
	}
	if s.UserCount() != 6 {
		t.Errorf("UserCount = %d", s.UserCount())
	}
}

func TestCannedPoliciesParse(t *testing.T) {
	s := mustStore(t, nil)
	for _, name := range CannedPolicyNames() {
		if s.policies[name] == nil {
			t.Errorf("canned policy %q missing", name)
		}
	}
	if got := strings.Join(CannedPolicyNames(), ","); got != "readonly,readwrite,writeonly" {
		t.Errorf("canned = %s", got)
	}
}

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		os.Chmod(p, mode)
		return p
	}
	valid := `{"version":1,"users":[{"accessKey":"alice","secretKey":"alice-secret-1","policies":["readonly"]}],
		"policies":{"p":{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}}}`

	t.Run("valid, private file", func(t *testing.T) {
		s, warns, err := LoadFile(write("ok.json", valid, 0o600), root)
		if err != nil || len(warns) != 0 {
			t.Fatalf("err=%v warnings=%v", err, warns)
		}
		if !s.Allowed("alice", Request{Action: "s3:GetObject", Bucket: "b", Key: "k"}) {
			t.Error("alice cannot read")
		}
	})
	t.Run("world-readable file warns but loads", func(t *testing.T) {
		_, warns, err := LoadFile(write("open.json", valid, 0o644), root)
		if err != nil {
			t.Fatal(err)
		}
		if len(warns) != 1 || !strings.Contains(warns[0], "chmod 600") {
			t.Errorf("warnings = %v", warns)
		}
	})
	bad := []struct{ name, content, want string }{
		{"not json", `users: []`, "invalid character"},
		{"unknown field", `{"usres":[]}`, "unknown field"},
		{"trailing data", valid + ` {}`, "trailing"},
		{"bad policy inside", `{"policies":{"p":{"Version":"x"}}}`, `policy "p"`},
		{"duplicate users", `{"users":[{"accessKey":"alice","secretKey":"alice-secret-1"},{"accessKey":"alice","secretKey":"alice-secret-2"}]}`, "duplicate"},
	}
	for _, tt := range bad {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := LoadFile(write(tt.name+".json", tt.content, 0o600), root)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want containing %q", err, tt.want)
			}
		})
	}
	t.Run("missing file", func(t *testing.T) {
		if _, _, err := LoadFile(filepath.Join(dir, "none.json"), root); err == nil {
			t.Error("expected an error")
		}
	})
	t.Run("errors never contain secrets", func(t *testing.T) {
		_, _, err := LoadFile(write("leak.json", `{"users":[{"accessKey":"a b","secretKey":"leaky-secret-value"}]}`, 0o600), root)
		if err == nil || strings.Contains(err.Error(), "leaky-secret-value") {
			t.Errorf("error = %v", err)
		}
	})
}
