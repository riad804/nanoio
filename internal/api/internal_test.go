package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"nanoio/internal/bucket/nslock"
	"nanoio/internal/storage"
	"nanoio/internal/storage/fs"
)

// TestInternalNamespaceIsReserved pins the single reserved namespace:
// /_nanoio/ in path-style requests belongs to the node, nothing a bucket
// name can collide with, and "cluster" is just a bucket name.
func TestInternalNamespaceIsReserved(t *testing.T) {
	be, err := fs.New(t.TempDir(), fs.Options{Locker: nslock.New(5 * time.Second), Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	defer be.Close()
	hit := make(chan string, 8)
	internal := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit <- r.URL.Path
		w.WriteHeader(http.StatusTeapot)
	})
	s, err := New(Options{Storage: be, InsecureNoAuth: true, Domains: []string{"localhost"}, Logger: quiet, Internal: internal})
	if err != nil {
		t.Fatal(err)
	}
	do := func(method, host, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "http://"+host+path, strings.NewReader(""))
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		return rec
	}

	t.Run("path-style requests under the prefix go to the internal handler", func(t *testing.T) {
		for _, p := range []string{"/_nanoio/health/live", "/_nanoio/rpc/v1/disk.ready", "/_nanoio/admin/x", "/_nanoio/health/cluster"} {
			if rec := do("GET", "localhost:9000", p); rec.Code != http.StatusTeapot {
				t.Errorf("%s -> %d, want the internal handler", p, rec.Code)
			}
			if got := <-hit; got != p {
				t.Errorf("internal handler saw %q for %q", got, p)
			}
		}
	})
	t.Run("a bucket name cannot start with an underscore", func(t *testing.T) {
		for _, name := range []string{"_nanoio", "_internal", "_x_y"} {
			err := storage.ValidateBucketName(name)
			if err == nil {
				t.Errorf("%q was accepted as a bucket name", name)
			}
		}
		rec := do("PUT", "localhost:9000", "/_nanoio")
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "InvalidBucketName") {
			t.Errorf("PUT /_nanoio = %d %s", rec.Code, rec.Body.String())
		}
		select {
		case p := <-hit:
			t.Errorf("internal handler reached for bucket creation of %q", p)
		default:
		}
	})
	t.Run("cluster is not special", func(t *testing.T) {
		if err := storage.ValidateBucketName("cluster"); err != nil {
			t.Fatalf("%q rejected: %v", "cluster", err)
		}
		if rec := do("PUT", "localhost:9000", "/cluster"); rec.Code != http.StatusOK {
			t.Fatalf("create bucket cluster = %d %s", rec.Code, rec.Body.String())
		}
		if rec := do("PUT", "localhost:9000", "/cluster/health"); rec.Code != http.StatusOK {
			t.Errorf("PUT object cluster/health = %d %s", rec.Code, rec.Body.String())
		}
		rec := do("GET", "localhost:9000", "/cluster/health")
		if rec.Code != http.StatusOK {
			t.Errorf("GET object cluster/health = %d", rec.Code)
		}
		select {
		case p := <-hit:
			t.Errorf("the internal handler saw %q", p)
		default:
		}
	})
	t.Run("virtual-host requests are never internal", func(t *testing.T) {
		do("PUT", "localhost:9000", "/vhost")
		rec := do("GET", "vhost.localhost:9000", "/_nanoio/health/live")
		if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "NoSuchKey") {
			t.Errorf("virtual-host GET of key _nanoio/health/live = %d %s", rec.Code, rec.Body.String())
		}
		select {
		case p := <-hit:
			t.Errorf("internal handler reached through a virtual host: %q", p)
		default:
		}
	})
	t.Run("without an internal handler the prefix is just an invalid bucket", func(t *testing.T) {
		plain, _ := New(Options{Storage: be, InsecureNoAuth: true, Logger: quiet})
		rec := httptest.NewRecorder()
		plain.ServeHTTP(rec, httptest.NewRequest("GET", "http://localhost/_nanoio/health/live", nil))
		if rec.Code == http.StatusTeapot || rec.Code == http.StatusOK {
			t.Errorf("status %d", rec.Code)
		}
		io.Copy(io.Discard, rec.Body)
	})
}
