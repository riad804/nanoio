package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nanoio/internal/auth"
)

func signedWith(t *testing.T, base, method, path, body string, h map[string]string) (int, http.Header, string) {
	t.Helper()
	req, err := http.NewRequest(method, base+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range h {
		req.Header.Set(k, v)
	}
	sum := sha256.Sum256([]byte(body))
	auth.Signer{AccessKey: testUser, SecretKey: testSecret}.Sign(req, hex.EncodeToString(sum[:]), time.Now())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(b)
}

func b64key() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func TestEncryptionAtRestEndToEnd(t *testing.T) {
	data := filepath.Join(t.TempDir(), "data")
	secret := "master:" + b64key()
	kmsEnv := map[string]string{
		"NANOIO_KMS_BACKEND": "local", "NANOIO_KMS_DEFAULT_KEY": "master", "NANOIO_KMS_SECRET_KEY": secret,
	}
	out, stop := runUntilReady(t, []string{"--root", data}, kmsEnv)
	base := "http://" + addrRE.FindStringSubmatch(out.String())[1]
	if !strings.Contains(out.String(), "kms ready") {
		t.Errorf("log does not report the KMS:\n%s", out.String())
	}
	if st, _, b := signedWith(t, base, "PUT", "/enc", "", nil); st != 200 {
		t.Fatalf("create bucket: %d %s", st, b)
	}
	plain := strings.Repeat("top secret ", 5000)
	st, hdr, b := signedWith(t, base, "PUT", "/enc/o", plain, map[string]string{"x-amz-server-side-encryption": "AES256"})
	if st != 200 || hdr.Get("x-amz-server-side-encryption") != "AES256" {
		t.Fatalf("PUT: %d %v %s", st, hdr, b)
	}
	if st, _, b := signedWith(t, base, "GET", "/enc/o", "", nil); st != 200 || b != plain {
		t.Fatalf("GET: %d equal=%v", st, b == plain)
	}
	// Run the rewrap command against the live server: a no-op here, but it
	// exercises the signed admin path end to end.
	var rewrapOut bytes.Buffer
	cfgEnv := env(map[string]string{"NANOIO_KMS_BACKEND": "local", "NANOIO_KMS_DEFAULT_KEY": "master", "NANOIO_KMS_SECRET_KEY": secret})
	if err := runAdmin(context.Background(), []string{"rewrap", "--endpoint", base}, cfgEnv, &rewrapOut, io.Discard); err != nil {
		t.Fatalf("admin rewrap: %v", err)
	}
	if !strings.Contains(rewrapOut.String(), `"encrypted":1`) {
		t.Errorf("rewrap output = %s", rewrapOut.String())
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	// Nothing on disk holds the plaintext.
	filepath.WalkDir(data, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if b, _ := os.ReadFile(p); bytes.Contains(b, []byte("top secret")) {
				t.Errorf("plaintext found in %s", p)
			}
		}
		return nil
	})

	// A restart with the same key reads it.
	out2, stop2 := runUntilReady(t, []string{"--root", data}, kmsEnv)
	base2 := "http://" + addrRE.FindStringSubmatch(out2.String())[1]
	if st, _, b := signedWith(t, base2, "GET", "/enc/o", "", nil); st != 200 || b != plain {
		t.Errorf("GET after restart: %d", st)
	}
	stop2()

	// A different key under the same name cannot: the wrap does not open.
	other := map[string]string{
		"NANOIO_KMS_BACKEND": "local", "NANOIO_KMS_DEFAULT_KEY": "master", "NANOIO_KMS_SECRET_KEY": "master:" + b64key(),
	}
	out3, stop3 := runUntilReady(t, []string{"--root", data}, other)
	base3 := "http://" + addrRE.FindStringSubmatch(out3.String())[1]
	if st, _, _ := signedWith(t, base3, "GET", "/enc/o", "", nil); st != 500 {
		t.Errorf("GET with the wrong master key = %d, want 500", st)
	}
	stop3()
}

func TestSSECOverHTTPIsRefusedByDefault(t *testing.T) {
	out, stop := runUntilReady(t, []string{"--root", t.TempDir()}, nil)
	base := "http://" + addrRE.FindStringSubmatch(out.String())[1]
	signedWith(t, base, "PUT", "/cbk", "", nil)
	key := make([]byte, 32)
	rand.Read(key)
	sum := md5.Sum(key)
	h := map[string]string{
		"x-amz-server-side-encryption-customer-algorithm": "AES256",
		"x-amz-server-side-encryption-customer-key":       base64.StdEncoding.EncodeToString(key),
		"x-amz-server-side-encryption-customer-key-MD5":   base64.StdEncoding.EncodeToString(sum[:]),
	}
	if st, _, b := signedWith(t, base, "PUT", "/cbk/o", "x", h); st != 400 || !strings.Contains(b, "secure connection") {
		t.Errorf("SSE-C over HTTP = %d %s", st, b)
	}
	stop()

	out2, stop2 := runUntilReady(t, []string{"--root", t.TempDir()}, map[string]string{"NANOIO_ALLOW_INSECURE_SSEC": "true"})
	base2 := "http://" + addrRE.FindStringSubmatch(out2.String())[1]
	if !strings.Contains(out2.String(), "SSE-C keys are accepted over connections that are not TLS") {
		t.Error("no warning logged for allowInsecureSSEC")
	}
	signedWith(t, base2, "PUT", "/cbk", "", nil)
	if st, _, b := signedWith(t, base2, "PUT", "/cbk/o", "x", h); st != 200 {
		t.Errorf("SSE-C with the flag = %d %s", st, b)
	}
	stop2()
}

func TestStartupRefusesBadKMSConfig(t *testing.T) {
	dir := t.TempDir()
	for name, tc := range map[string]struct {
		env     map[string]string
		wantErr string
	}{
		"unknown default key": {map[string]string{
			"NANOIO_KMS_BACKEND": "local", "NANOIO_KMS_DEFAULT_KEY": "missing", "NANOIO_KMS_SECRET_KEY": "present:" + b64key()},
			`default key "missing"`},
		"local without keys":   {map[string]string{"NANOIO_KMS_BACKEND": "local", "NANOIO_KMS_DEFAULT_KEY": "k"}, "keyFile"},
		"no default key":       {map[string]string{"NANOIO_KMS_BACKEND": "local", "NANOIO_KMS_SECRET_KEY": "k:" + b64key()}, "defaultKey"},
		"unknown backend":      {map[string]string{"NANOIO_KMS_BACKEND": "vault", "NANOIO_KMS_DEFAULT_KEY": "k"}, "must be"},
		"kes without endpoint": {map[string]string{"NANOIO_KMS_BACKEND": "kes", "NANOIO_KMS_DEFAULT_KEY": "k"}, "endpoint"},
		"bad secret":           {map[string]string{"NANOIO_KMS_BACKEND": "local", "NANOIO_KMS_DEFAULT_KEY": "k", "NANOIO_KMS_SECRET_KEY": "k:short"}, "32 bytes"},
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var logs syncBuf
			err := run(ctx, []string{"--root", dir}, env(tc.env), &logs)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("err = %v, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}
