package rpc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nanoio/internal/cluster/rpcauth"
)

const secret = "rpc-test-secret-0123456789"

func echoServer(t *testing.T, requireCert bool) *Server {
	keys, _ := rpcauth.NewKeyring(secret)
	s := NewServer(ServerConfig{Self: "srv", Keys: keys, RequireClientCert: requireCert,
		Known: func(n string) bool { return n == "cli" },
		Encode: func(err error) (int, string) {
			if strings.Contains(err.Error(), "nope") {
				return 404, "notfound"
			}
			return 500, "internal"
		}})
	s.Handle("echo", func(_ context.Context, from string, args, body []byte) ([]byte, error) {
		return append([]byte(from+":"), body...), nil
	})
	s.Handle("fail", func(context.Context, string, []byte, []byte) ([]byte, error) {
		return nil, errors.New("nope")
	})
	return s
}

func client(t *testing.T, addr string, hc *http.Client, tlsOn bool) *Client {
	keys, _ := rpcauth.NewKeyring(secret)
	c, err := NewClient(Config{Self: "cli", Keys: keys, Peers: map[string]string{"srv": addr}, HTTP: hc, TLS: tlsOn})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCallAndErrors(t *testing.T) {
	ts := httptest.NewServer(echoServer(t, false))
	defer ts.Close()
	c := client(t, strings.TrimPrefix(ts.URL, "http://"), nil, false)

	out, err := c.Do(context.Background(), "srv", "echo", []byte(`{"a":1}`), []byte("hi"))
	if err != nil || string(out) != "cli:hi" {
		t.Fatalf("echo = %q, %v", out, err)
	}
	_, err = c.Do(context.Background(), "srv", "fail", nil, nil)
	var re *Error
	if !errors.As(err, &re) || re.Code != "notfound" || re.Status != 404 {
		t.Errorf("err = %v, want remote notfound", err)
	}
	_, err = c.Do(context.Background(), "srv", "missing", nil, nil)
	if !errors.As(err, &re) || re.Status != 404 {
		t.Errorf("unknown op = %v", err)
	}
	if _, err := c.Do(context.Background(), "ghost", "echo", nil, nil); err == nil {
		t.Error("an unknown peer was dialled")
	}
}

func TestUnknownSenderDenied(t *testing.T) {
	ts := httptest.NewServer(echoServer(t, false))
	defer ts.Close()
	keys, _ := rpcauth.NewKeyring(secret)
	c, _ := NewClient(Config{Self: "intruder", Keys: keys, Peers: map[string]string{"srv": strings.TrimPrefix(ts.URL, "http://")}})
	_, err := c.Do(context.Background(), "srv", "echo", nil, nil)
	var re *Error
	// The refusal is unauthenticated (the server will not sign for a
	// stranger), which the client reports as a failed response check.
	if err == nil || errors.As(err, &re) && re.Status != http.StatusUnauthorized {
		t.Errorf("err = %v", err)
	}
}

func TestTLSRequiredFailsClosed(t *testing.T) {
	keys, _ := rpcauth.NewKeyring(secret)
	if _, err := NewClient(Config{Self: "cli", Keys: keys, RequireTLS: true}); err == nil {
		t.Fatal("a plaintext client was built although TLS is required")
	}
	if _, err := NewClient(Config{Self: "cli", Keys: keys, RequireTLS: true, TLS: true}); err != nil {
		t.Fatal(err)
	}
}

// pki makes a CA and a leaf signed by it (usable as server and client).
func pki(t *testing.T, dir, name string, ca *x509.Certificate, caKey *ecdsa.PrivateKey) (certFile, keyFile string, cert *x509.Certificate, key *ecdsa.PrivateKey) {
	t.Helper()
	key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, IsCA: ca == nil, BasicConstraintsValid: true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"},
	}
	parent, signer := tmpl, key
	if ca != nil {
		parent, signer = ca, caKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ = x509.ParseCertificate(der)
	kb, _ := x509.MarshalECPrivateKey(key)
	certFile, keyFile = filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key")
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	return
}

func TestMutualTLS(t *testing.T) {
	dir := t.TempDir()
	caCrt, _, ca, caKey := pki(t, dir, "ca", nil, nil)
	srvCrt, srvKey, _, _ := pki(t, dir, "srv", ca, caKey)
	cliCrt, cliKey, _, _ := pki(t, dir, "cli", ca, caKey)
	_, _, otherCA, otherKey := pki(t, dir, "otherca", nil, nil)
	rogueCrt, rogueKey, _, _ := pki(t, dir, "rogue", otherCA, otherKey)
	otherCAFile := filepath.Join(dir, "otherca.crt")

	serverCfg, err := TLSServerConfig(srvCrt, srvKey, caCrt)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(echoServer(t, true))
	ts.TLS = serverCfg
	ts.StartTLS()
	defer ts.Close()
	addr := strings.TrimPrefix(ts.URL, "https://")

	httpc := func(cert, key, ca string) *http.Client {
		cfg, err := TLSClientConfig(cert, key, ca)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
	}
	call := func(hc *http.Client) error {
		_, err := client(t, addr, hc, true).Do(context.Background(), "srv", "echo", nil, []byte("x"))
		return err
	}

	if err := call(httpc(cliCrt, cliKey, caCrt)); err != nil {
		t.Errorf("a peer with a valid certificate was refused: %v", err)
	}
	// No client certificate: the handshake succeeds (S3 clients have none)
	// but the RPC endpoint refuses.
	if err := call(httpc("", "", caCrt)); err == nil {
		t.Error("a peer without a client certificate was served")
	}
	// A certificate from another CA is not a verified chain.
	if err := call(httpc(rogueCrt, rogueKey, caCrt)); err == nil {
		t.Error("a peer with a certificate from a foreign CA was served")
	}
	// The client refuses a server whose certificate it cannot verify.
	otherPool := httpc(cliCrt, cliKey, otherCAFile)
	if err := call(otherPool); err == nil {
		t.Error("the client accepted a server certificate from an unknown CA")
	}
	_ = tls.VersionTLS12
}
