package api

import (
	"net/http"
	"testing"

	"nanoio/internal/auth"
	"nanoio/internal/iam"
	"nanoio/internal/storage"
)

type nullStorage struct{ storage.StorageAPI }

type fakeAuthn struct{}

func (fakeAuthn) Authenticate(*http.Request) (*auth.Result, error) { return nil, auth.ErrAnonymous }

type fakeAuthz struct{}

func (fakeAuthz) Allowed(string, iam.Request) bool { return false }

func TestTarget(t *testing.T) {
	s, err := New(Options{Storage: nullStorage{}, InsecureNoAuth: true, Domains: []string{"localhost", "S3.Example.com."}})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, host, path string
		bucket, key      string
	}{
		{"service root", "localhost:9000", "/", "", ""},
		{"path-style bucket", "localhost:9000", "/b", "b", ""},
		{"path-style bucket trailing slash", "localhost:9000", "/b/", "b", ""},
		{"path-style key", "localhost:9000", "/b/k", "b", "k"},
		{"path-style nested key", "localhost:9000", "/b/a/b/c.txt", "b", "a/b/c.txt"},
		{"path-style folder placeholder", "localhost:9000", "/b/dir/", "b", "dir/"},
		{"path-style double slash key", "localhost:9000", "/b//x", "b", "/x"},
		{"ip host is path-style", "127.0.0.1:9000", "/b/k", "b", "k"},
		{"ipv6 host is path-style", "[::1]:9000", "/b/k", "b", "k"},
		{"bare domain is path-style", "localhost", "/b/k", "b", "k"},
		{"virtual-host bucket", "b.localhost:9000", "/", "b", ""},
		{"virtual-host key", "b.localhost:9000", "/k/x", "b", "k/x"},
		{"virtual-host folder placeholder", "b.localhost", "/dir/", "b", "dir/"},
		{"virtual-host dotted bucket", "my.dotted.localhost:9000", "/k", "my.dotted", "k"},
		{"virtual-host is case-insensitive", "B.LocalHost:9000", "/k", "b", "k"},
		{"second domain, normalised", "b.s3.example.com", "/k", "b", "k"},
		{"second domain path-style", "s3.example.com", "/b/k", "b", "k"},
		{"unrelated suffix is not virtual-host", "notlocalhost:9000", "/b/k", "b", "k"},
		{"empty label is not virtual-host", ".localhost", "/b/k", "b", "k"},
		{"unknown domain is path-style", "b.other.test", "/b/k", "b", "k"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, k := s.target(tt.host, tt.path)
			if b != tt.bucket || k != tt.key {
				t.Errorf("target(%q, %q) = (%q, %q), want (%q, %q)", tt.host, tt.path, b, k, tt.bucket, tt.key)
			}
		})
	}
}

func TestNewValidatesOptions(t *testing.T) {
	tests := []struct {
		name string
		opts Options
		ok   bool
	}{
		{"valid, auth explicitly off", Options{Storage: nullStorage{}, InsecureNoAuth: true}, true},
		{"no storage", Options{InsecureNoAuth: true}, false},
		{"authentication cannot be forgotten", Options{Storage: nullStorage{}}, false},
		{"authenticator without authorizer", Options{Storage: nullStorage{}, Auth: fakeAuthn{}}, false},
		{"authorizer without authenticator", Options{Storage: nullStorage{}, Authz: fakeAuthz{}}, false},
		{"both supplied", Options{Storage: nullStorage{}, Auth: fakeAuthn{}, Authz: fakeAuthz{}}, true},
		{"domain with port", Options{Storage: nullStorage{}, InsecureNoAuth: true, Domains: []string{"a.com:9000"}}, false},
		{"empty domain", Options{Storage: nullStorage{}, InsecureNoAuth: true, Domains: []string{" "}}, false},
		{"domain with slash", Options{Storage: nullStorage{}, InsecureNoAuth: true, Domains: []string{"a/b"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.opts)
			if (err == nil) != tt.ok {
				t.Errorf("New error = %v, want ok=%v", err, tt.ok)
			}
		})
	}
}
