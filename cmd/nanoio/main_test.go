package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"nanoio/internal/auth"
)

// syncBuf is a goroutine-safe buffer: run logs from its own goroutine.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// env serves m, defaulting the listen address to an ephemeral loopback port
// so tests never collide with a real server or each other.
func env(m map[string]string) func(string) string {
	return func(k string) string {
		if v, ok := m[k]; ok {
			return v
		}
		switch k {
		case "NANOIO_ADDRESS":
			return "127.0.0.1:0"
		case "NANOIO_ROOT_USER":
			return testUser
		case "NANOIO_ROOT_PASSWORD":
			return testSecret
		}
		return ""
	}
}

func TestRunRejectsBadInput(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte(`{"nope":1}`), 0o644)
	tests := []struct {
		name    string
		args    []string
		env     map[string]string
		wantErr string
	}{
		{"no root anywhere", nil, nil, "root, drives or cluster is required"},
		{"unknown flag", []string{"--bogus"}, nil, "bogus"},
		{"positional argument", []string{"--root", dir, "extra"}, nil, "unexpected argument"},
		{"missing config file", []string{"--config", filepath.Join(dir, "none.json"), "--root", dir}, nil, "no such file"},
		{"config with unknown field", []string{"--config", bad}, nil, "unknown field"},
		{"bad env duration", []string{"--root", dir}, map[string]string{"NANOIO_LOCK_TIMEOUT": "soon"}, "NANOIO_LOCK_TIMEOUT"},
		{"bad log level", []string{"--root", dir}, map[string]string{"NANOIO_LOG_LEVEL": "loud"}, "logLevel"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var out syncBuf
			err := run(ctx, tt.args, env(tt.env), &out)
			if err == nil || !strings.Contains(err.Error()+out.String(), tt.wantErr) {
				t.Errorf("error = %v (stderr %q), want containing %q", err, out.String(), tt.wantErr)
			}
		})
	}
}

func TestHelpIsNotAnError(t *testing.T) {
	var out syncBuf
	if err := run(context.Background(), []string{"-h"}, env(nil), &out); err != nil {
		t.Errorf("--help returned %v", err)
	}
	if !strings.Contains(out.String(), "Precedence") {
		t.Errorf("usage text missing: %q", out.String())
	}
}

// runUntilReady starts run in a goroutine, waits for the ready log line,
// and returns a func that cancels it and yields run's result.
func runUntilReady(t *testing.T, args []string, e map[string]string) (out *syncBuf, stop func() error) {
	t.Helper()
	out = &syncBuf{}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- run(ctx, args, env(e), out) }()
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(out.String(), "nanoio ready") {
		select {
		case err := <-result:
			cancel()
			t.Fatalf("run exited before ready: %v\n%s", err, out.String())
		default:
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("never became ready:\n%s", out.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
	return out, func() error {
		cancel()
		select {
		case err := <-result:
			return err
		case <-time.After(5 * time.Second):
			t.Fatal("run did not return after cancellation")
			return nil
		}
	}
}

func TestStartAndGracefulShutdown(t *testing.T) {
	root := filepath.Join(t.TempDir(), "data")
	out, stop := runUntilReady(t, []string{"--root", root}, nil)

	if st, err := os.Stat(filepath.Join(root, ".nanoio.sys", "format.json")); err != nil || st.IsDir() {
		t.Errorf("backend not initialised under --root: %v", err)
	}
	if err := stop(); err != nil {
		t.Fatalf("shutdown error: %v", err)
	}
	for _, want := range []string{"shutting down", "stopped"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("log missing %q:\n%s", want, out.String())
		}
	}
	// The root is released: a second server can take it immediately.
	_, stop2 := runUntilReady(t, []string{"--root", root}, nil)
	if err := stop2(); err != nil {
		t.Errorf("restart on the same root: %v", err)
	}
}

func TestConfigPrecedence(t *testing.T) {
	dir := t.TempDir()
	fromFile, fromEnv, fromFlag := filepath.Join(dir, "file"), filepath.Join(dir, "env"), filepath.Join(dir, "flag")
	cfg := filepath.Join(dir, "cfg.json")
	os.WriteFile(cfg, []byte(`{"root":"`+fromFile+`","logLevel":"warn"}`), 0o644)

	tests := []struct {
		name     string
		args     []string
		env      map[string]string
		wantRoot string
		wantLog  bool // expect the info-level ready line to be visible
	}{
		{"file only", []string{"--config", cfg}, nil, fromFile, false},
		{"env beats file", []string{"--config", cfg}, map[string]string{"NANOIO_ROOT": fromEnv, "NANOIO_LOG_LEVEL": "info"}, fromEnv, true},
		{"flag beats env", []string{"--config", cfg, "--root", fromFlag}, map[string]string{"NANOIO_ROOT": fromEnv, "NANOIO_LOG_LEVEL": "info"}, fromFlag, true},
		{"config path from env", nil, map[string]string{"NANOIO_CONFIG_FILE": cfg, "NANOIO_LOG_LEVEL": "info"}, fromFile, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.wantLog {
				// logLevel=warn hides the ready line, so wait on the file instead.
				ctx, cancel := context.WithCancel(context.Background())
				result := make(chan error, 1)
				var out syncBuf
				go func() { result <- run(ctx, tt.args, env(tt.env), &out) }()
				deadline := time.Now().Add(5 * time.Second)
				for {
					if _, err := os.Stat(filepath.Join(tt.wantRoot, ".nanoio.sys", "format.json")); err == nil {
						break
					}
					if time.Now().After(deadline) {
						cancel()
						t.Fatalf("root %s never initialised:\n%s", tt.wantRoot, out.String())
					}
					time.Sleep(5 * time.Millisecond)
				}
				cancel()
				if err := <-result; err != nil {
					t.Fatal(err)
				}
				if strings.Contains(out.String(), "nanoio ready") {
					t.Error("info line logged despite logLevel=warn")
				}
				return
			}
			out, stop := runUntilReady(t, tt.args, tt.env)
			if !strings.Contains(out.String(), tt.wantRoot) {
				t.Errorf("ready line does not name root %s:\n%s", tt.wantRoot, out.String())
			}
			if err := stop(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRefusesRootInUse(t *testing.T) {
	root := t.TempDir()
	_, stop := runUntilReady(t, []string{"--root", root}, nil)
	defer stop()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var out syncBuf
	err := run(ctx, []string{"--root", root}, env(nil), &out)
	if err == nil || !strings.Contains(err.Error(), "in use") {
		t.Errorf("second server error = %v, want in-use error", err)
	}
}

const (
	testUser   = "testroot"
	testSecret = "testroot-secret-1"
)

// signedDo sends a request signed as the given credential.
func signedDo(t *testing.T, base, ak, sk, method, path, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, base+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(body))
	auth.Signer{AccessKey: ak, SecretKey: sk}.Sign(req, hex.EncodeToString(sum[:]), time.Now())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

var addrRE = regexp.MustCompile(`address=(\S+)`)

func TestServesS3OverHTTP(t *testing.T) {
	root := t.TempDir()
	out, stop := runUntilReady(t, []string{"--root", root}, nil)
	m := addrRE.FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("no address in log:\n%s", out.String())
	}
	base := "http://" + m[1]
	do := func(method, path, body string) (int, string) {
		t.Helper()
		return signedDo(t, base, testUser, testSecret, method, path, body)
	}
	if st, b := do("PUT", "/smoke", ""); st != 200 {
		t.Fatalf("create bucket: %d %s", st, b)
	}
	if st, b := do("PUT", "/smoke/hello.txt", "hello"); st != 200 {
		t.Fatalf("put: %d %s", st, b)
	}
	if st, b := do("GET", "/smoke/hello.txt", ""); st != 200 || b != "hello" {
		t.Errorf("get: %d %q", st, b)
	}
	if st, b := do("GET", "/smoke?list-type=2", ""); st != 200 || !strings.Contains(b, "<Key>hello.txt</Key>") {
		t.Errorf("list: %d %s", st, b)
	}
	if err := stop(); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	// Data written over HTTP persisted to the root.
	if _, err := os.Stat(filepath.Join(root, "smoke", "hello.txt", "xl.meta")); err != nil {
		t.Errorf("object not on disk: %v", err)
	}
	// And the listener is gone.
	if _, err := http.Get(base + "/"); err == nil {
		t.Error("listener still accepting after shutdown")
	}
}

func TestWarnsWhenExposedBeyondLoopback(t *testing.T) {
	tests := []struct {
		addr     string
		wantWarn bool
	}{
		{"127.0.0.1:0", false},
		{"[::1]:0", false},
		{"0.0.0.0:0", true},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			out, stop := runUntilReady(t, []string{"--root", t.TempDir(), "--address", tt.addr, "--insecure-no-auth"}, nil)
			warned := strings.Contains(out.String(), "NO authentication")
			if err := stop(); err != nil {
				t.Fatal(err)
			}
			if warned != tt.wantWarn {
				t.Errorf("warned = %v, want %v\n%s", warned, tt.wantWarn, out.String())
			}
		})
	}
}

func TestShutdownDrainsInFlightRequests(t *testing.T) {
	root := t.TempDir()
	out, stop := runUntilReady(t, []string{"--root", root}, nil)
	base := "http://" + addrRE.FindStringSubmatch(out.String())[1]
	if st, b := signedDo(t, base, testUser, testSecret, "PUT", "/drain", ""); st != 200 {
		t.Fatalf("setup: %d %s", st, b)
	}
	// A slow upload that is mid-body when shutdown begins must complete.
	pr, pw := io.Pipe()
	req, _ := http.NewRequest("PUT", base+"/drain/slow", pr)
	req.ContentLength = 8
	auth.Signer{AccessKey: testUser, SecretKey: testSecret}.Sign(req, auth.PayloadUnsigned, time.Now())
	result := make(chan int, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			result <- -1
			return
		}
		resp.Body.Close()
		result <- resp.StatusCode
	}()
	pw.Write([]byte("half"))
	time.Sleep(100 * time.Millisecond)
	stopped := make(chan error, 1)
	go func() { stopped <- stop() }()
	time.Sleep(100 * time.Millisecond)
	pw.Write([]byte("done"))
	pw.Close()
	if st := <-result; st != 200 {
		t.Errorf("in-flight upload status = %d, want 200", st)
	}
	if err := <-stopped; err != nil {
		t.Errorf("shutdown: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(root, "drain", "slow")); err == nil {
		t.Errorf("unexpected plain file %q", b)
	}
	entries, _ := os.ReadDir(filepath.Join(root, "drain", "slow"))
	if len(entries) == 0 {
		t.Error("drained upload was not committed")
	}
}

func TestAuthIsRequiredByDefault(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		args    []string
		wantErr string
	}{
		{"no credentials", map[string]string{"NANOIO_ROOT_USER": "", "NANOIO_ROOT_PASSWORD": ""}, nil, "NANOIO_ROOT_USER"},
		{"user without password", map[string]string{"NANOIO_ROOT_PASSWORD": ""}, nil, "NANOIO_ROOT_PASSWORD"},
		{"weak password", map[string]string{"NANOIO_ROOT_PASSWORD": "short"}, nil, "secret key must be"},
		{"bad access key", map[string]string{"NANOIO_ROOT_USER": "a b"}, nil, "access key"},
		{"missing iam file", map[string]string{"NANOIO_IAM_FILE": "/nonexistent/iam.json"}, nil, "no such file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var out syncBuf
			// env() would substitute defaults for empty values, so wrap it.
			getenv := func(k string) string {
				if v, ok := tt.env[k]; ok {
					return v
				}
				return env(nil)(k)
			}
			err := run(ctx, append([]string{"--root", t.TempDir()}, tt.args...), getenv, &out)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestAuthenticationEnforcedOverHTTP(t *testing.T) {
	dir := t.TempDir()
	iamFile := filepath.Join(dir, "iam.json")
	os.WriteFile(iamFile, []byte(`{"users":[
		{"accessKey":"reader","secretKey":"reader-secret-1","policies":["readonly"]},
		{"accessKey":"off","secretKey":"off-secret-1234","status":"disabled","policies":["readwrite"]}]}`), 0o600)
	out, stop := runUntilReady(t, []string{"--root", filepath.Join(dir, "data")}, map[string]string{"NANOIO_IAM_FILE": iamFile})
	defer stop()
	base := "http://" + addrRE.FindStringSubmatch(out.String())[1]
	if !strings.Contains(out.String(), "authentication enabled") || strings.Contains(out.String(), testSecret) ||
		strings.Contains(out.String(), "reader-secret-1") {
		t.Fatalf("startup log wrong or leaks secrets:\n%s", out.String())
	}

	if st, b := signedDo(t, base, testUser, testSecret, "PUT", "/shared", ""); st != 200 {
		t.Fatalf("root create bucket: %d %s", st, b)
	}
	if st, b := signedDo(t, base, testUser, testSecret, "PUT", "/shared/doc.txt", "contents"); st != 200 {
		t.Fatalf("root put: %d %s", st, b)
	}
	tests := []struct {
		name         string
		ak, sk       string
		method, path string
		body         string
		status       int
		code         string
	}{
		{"reader may get", "reader", "reader-secret-1", "GET", "/shared/doc.txt", "", 200, ""},
		{"reader may list", "reader", "reader-secret-1", "GET", "/shared?list-type=2", "", 200, ""},
		{"reader may not put", "reader", "reader-secret-1", "PUT", "/shared/new.txt", "x", 403, "AccessDenied"},
		{"reader may not delete", "reader", "reader-secret-1", "DELETE", "/shared/doc.txt", "", 403, "AccessDenied"},
		{"reader may not create buckets", "reader", "reader-secret-1", "PUT", "/another", "", 403, "AccessDenied"},
		{"wrong secret", "reader", "not-the-secret-1", "GET", "/shared/doc.txt", "", 403, "SignatureDoesNotMatch"},
		{"unknown key", "ghost", "ghost-secret-12", "GET", "/shared/doc.txt", "", 403, "InvalidAccessKeyId"},
		{"disabled user", "off", "off-secret-1234", "GET", "/shared/doc.txt", "", 403, "InvalidAccessKeyId"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st, body := signedDo(t, base, tt.ak, tt.sk, tt.method, tt.path, tt.body)
			if st != tt.status || (tt.code != "" && !strings.Contains(body, "<Code>"+tt.code+"</Code>")) {
				t.Errorf("got %d %s, want %d %s", st, body, tt.status, tt.code)
			}
		})
	}
	t.Run("anonymous request", func(t *testing.T) {
		resp, err := http.Get(base + "/shared/doc.txt")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 403 || !strings.Contains(string(b), "<Code>AccessDenied</Code>") {
			t.Errorf("anonymous: %d %s", resp.StatusCode, b)
		}
	})
	t.Run("denied reader does not learn whether a key exists", func(t *testing.T) {
		_, a := signedDo(t, base, "reader", "reader-secret-1", "PUT", "/shared/doc.txt", "x")
		_, b := signedDo(t, base, "reader", "reader-secret-1", "PUT", "/nosuchbucket/doc.txt", "x")
		if !strings.Contains(a, "AccessDenied") || !strings.Contains(b, "AccessDenied") {
			t.Errorf("existing bucket: %s\nmissing bucket: %s", a, b)
		}
	})
}

func TestInsecureNoAuthServesAnonymously(t *testing.T) {
	out, stop := runUntilReady(t, []string{"--root", t.TempDir(), "--insecure-no-auth"},
		map[string]string{"NANOIO_ROOT_USER": "", "NANOIO_ROOT_PASSWORD": ""})
	defer stop()
	if !strings.Contains(out.String(), "AUTHENTICATION IS DISABLED") {
		t.Errorf("no loud warning:\n%s", out.String())
	}
	base := "http://" + addrRE.FindStringSubmatch(out.String())[1]
	req, _ := http.NewRequest("PUT", base+"/anon", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("anonymous create bucket: %d", resp.StatusCode)
	}
}

func driveList(t *testing.T, n int) (string, []string) {
	t.Helper()
	base := t.TempDir()
	dirs := make([]string, n)
	for i := range dirs {
		dirs[i] = filepath.Join(base, fmt.Sprintf("drive%d", i))
	}
	return strings.Join(dirs, ","), dirs
}

func TestErasureBackendServesAndSurvivesDriveLoss(t *testing.T) {
	list, dirs := driveList(t, 6)
	out, stop := runUntilReady(t, []string{"--drives", list, "--parity", "2"}, nil)
	log := out.String()
	for _, want := range []string{"erasure-coded backend", "data=4", "parity=2", "backend=xl"} {
		if !strings.Contains(log, want) {
			t.Errorf("startup log missing %q:\n%s", want, log)
		}
	}
	base := "http://" + addrRE.FindStringSubmatch(log)[1]
	do := func(method, path, body string) (int, string) {
		t.Helper()
		return signedDo(t, base, testUser, testSecret, method, path, body)
	}
	if st, b := do("PUT", "/erasure", ""); st != 200 {
		t.Fatalf("mb: %d %s", st, b)
	}
	payload := strings.Repeat("erasure coded payload ", 100000) // ~2.2 MB: several 1 MiB blocks
	if st, b := do("PUT", "/erasure/big.txt", payload); st != 200 {
		t.Fatalf("put: %d %s", st, b)
	}
	if st, b := do("GET", "/erasure/big.txt", ""); st != 200 || b != payload {
		t.Fatalf("get: %d, %d bytes", st, len(b))
	}

	// Two drives die under the running server; reads and listings go on.
	os.RemoveAll(dirs[1])
	os.RemoveAll(dirs[4])
	if st, b := do("GET", "/erasure/big.txt", ""); st != 200 || b != payload {
		t.Fatalf("get with 2 of 6 drives gone: %d, %d bytes", st, len(b))
	}
	if st, b := do("GET", "/erasure?list-type=2", ""); st != 200 || !strings.Contains(b, "<Key>big.txt</Key>") {
		t.Errorf("list with drives gone: %d %s", st, b)
	}
	if st, b := do("PUT", "/erasure/more.txt", "written while degraded"); st != 200 {
		t.Errorf("degraded write: %d %s", st, b)
	}
	if err := stop(); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	// Restart with two blank replacement drives: they are formatted, and
	// after a heal pass everything is whole again.
	for _, i := range []int{1, 4} {
		os.MkdirAll(dirs[i], 0o755)
	}
	out2, stop2 := runUntilReady(t, []string{"--drives", list, "--parity", "2"}, map[string]string{
		"NANOIO_GC_INTERVAL": "50ms"})
	defer stop2()
	base2 := "http://" + addrRE.FindStringSubmatch(out2.String())[1]
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, e1 := os.Stat(filepath.Join(dirs[1], "erasure", "more.txt", "xl.meta"))
		_, e4 := os.Stat(filepath.Join(dirs[4], "erasure", "big.txt", "xl.meta"))
		if e1 == nil && e4 == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("replacement drives were not repopulated within 10s")
		}
		time.Sleep(25 * time.Millisecond)
	}
	if st, b := signedDo(t, base2, testUser, testSecret, "GET", "/erasure/more.txt", ""); st != 200 || b != "written while degraded" {
		t.Errorf("after restart: %d %q", st, b)
	}
}

func TestBackendSelectionErrors(t *testing.T) {
	list, _ := driveList(t, 4)
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"root and drives together", []string{"--root", t.TempDir(), "--drives", list}, "not both"},
		{"one drive", []string{"--drives", filepath.Join(t.TempDir(), "only")}, "2 to 32"},
		{"parity above data", []string{"--drives", list, "--parity", "3"}, "parity"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var out syncBuf
			err := run(ctx, tt.args, env(nil), &out)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want containing %q", err, tt.want)
			}
		})
	}
}
