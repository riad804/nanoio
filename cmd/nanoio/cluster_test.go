package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"crypto/sha256"
	"encoding/hex"
	"nanoio/internal/auth"
)

const clusterSecret = "main-test-cluster-secret-0123456789"

// freeAddrs reserves n loopback addresses.
func freeAddrs(t *testing.T, n int) []string {
	t.Helper()
	var ls []net.Listener
	var out []string
	for i := 0; i < n; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ls = append(ls, l)
		out = append(out, l.Addr().String())
	}
	for _, l := range ls {
		l.Close()
	}
	return out
}

type tnode struct {
	id     string
	addr   string
	cfg    string
	out    *syncBuf
	stop   context.CancelFunc
	result chan error
}

// writePKI creates a CA and one server/client certificate valid for
// 127.0.0.1, returning file paths.
func writePKI(t *testing.T, dir string) (cert, key, ca string) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "nanoio-test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, BasicConstraintsValid: true}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "node"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	kb, _ := x509.MarshalECPrivateKey(leafKey)
	write := func(name string, typ string, der []byte) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600)
		return p
	}
	return write("node.crt", "CERTIFICATE", leafDER), write("node.key", "EC PRIVATE KEY", kb), write("ca.crt", "CERTIFICATE", caDER)
}

// startNodes launches n nodes of one cluster, each through run() as its own
// process-equivalent, and waits for all of them to report ready.
func startNodes(t *testing.T, n int, withTLS bool, extra func(*map[string]any)) (nodes []*tnode, base string, client *http.Client) {
	t.Helper()
	dir := t.TempDir()
	addrs := freeAddrs(t, n)
	peers := map[string]string{}
	for i, a := range addrs {
		peers[fmt.Sprintf("n%d", i)] = a
	}
	var set []string
	for i := 0; i < n; i++ {
		for j := 0; j < 2; j++ {
			set = append(set, fmt.Sprintf("n%d:%s", i, filepath.Join(dir, fmt.Sprintf("n%d", i), fmt.Sprintf("d%d", j))))
		}
	}
	var cert, key, ca string
	if withTLS {
		cert, key, ca = writePKI(t, dir)
	}
	client = &http.Client{Timeout: 20 * time.Second}
	if withTLS {
		pool := x509.NewCertPool()
		pem, _ := os.ReadFile(ca)
		pool.AppendCertsFromPEM(pem)
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}
	}
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("n%d", i)
		cluster := map[string]any{
			"node": id, "nodes": peers, "secrets": []string{clusterSecret},
			"pools":     []map[string]any{{"sets": [][]string{set}}},
			"lockTTL":   "300ms",
			"heartbeat": "200ms", "listTimeout": "3s", "startupTimeout": "30s",
		}
		if withTLS {
			cluster["tls"] = map[string]string{"cert": cert, "key": key, "ca": ca}
		} else {
			cluster["tlsRequired"] = false
		}
		cfg := map[string]any{"address": addrs[i], "cluster": cluster, "parity": 2, "gcInterval": "0s"}
		if extra != nil {
			extra(&cfg)
		}
		b, _ := json.Marshal(cfg)
		path := filepath.Join(dir, id+".json")
		os.WriteFile(path, b, 0o600)
		out := &syncBuf{}
		ctx, cancel := context.WithCancel(context.Background())
		nd := &tnode{id: id, addr: addrs[i], cfg: path, out: out, stop: cancel, result: make(chan error, 1)}
		go func() {
			nd.result <- run(ctx, []string{"--config", path}, env(map[string]string{"NANOIO_ADDRESS": addrs[i]}), out)
		}()
		nodes = append(nodes, nd)
		t.Cleanup(func() {
			cancel()
			select {
			case <-nd.result:
			case <-time.After(10 * time.Second):
			}
		})
	}
	scheme := "http"
	if withTLS {
		scheme = "https"
	}
	for _, nd := range nodes {
		deadline := time.Now().Add(40 * time.Second)
		for !strings.Contains(nd.out.String(), "nanoio ready") {
			select {
			case err := <-nd.result:
				t.Fatalf("%s exited: %v\n%s", nd.id, err, allLogs(nodes))
			default:
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s never became ready:\n%s", nd.id, allLogs(nodes))
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	return nodes, scheme + "://", client
}

func s3(t *testing.T, c *http.Client, base, addr, method, path, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, base+addr+path, strings.NewReader(body))
	sum := sha256.Sum256([]byte(body))
	auth.Signer{AccessKey: testUser, SecretKey: testSecret}.Sign(req, hex.EncodeToString(sum[:]), time.Now())
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func plainGet(t *testing.T, c *http.Client, url string) (int, string) {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func clusterScenario(t *testing.T, withTLS bool) {
	nodes, base, c := startNodes(t, 3, withTLS, nil)

	// An object written through one node is served by every node.
	if st, b := s3(t, c, base, nodes[0].addr, "PUT", "/dist", ""); st != 200 {
		t.Fatalf("create bucket: %d %s", st, b)
	}
	payload := strings.Repeat("distributed payload ", 5000)
	if st, b := s3(t, c, base, nodes[0].addr, "PUT", "/dist/obj", payload); st != 200 {
		t.Fatalf("put: %d %s", st, b)
	}
	for _, nd := range nodes {
		if st, b := s3(t, c, base, nd.addr, "GET", "/dist/obj", ""); st != 200 || b != payload {
			t.Fatalf("get via %s: %d (%d bytes)", nd.id, st, len(b))
		}
	}

	// The reserved namespace is served unauthenticated for health, and
	// refuses unsigned RPC.
	for _, p := range []string{"live", "ready"} {
		if st, b := plainGet(t, c, base+nodes[1].addr+"/_nanoio/health/"+p); st != 200 {
			t.Errorf("health/%s = %d %s", p, st, b)
		}
	}
	if st, b := plainGet(t, c, base+nodes[1].addr+"/_nanoio/health/cluster"); st != 200 || !strings.Contains(b, `"ok"`) {
		t.Errorf("health/cluster = %d %s", st, b)
	}
	req, _ := http.NewRequest("POST", base+nodes[1].addr+"/_nanoio/rpc/v1/disk.ready", strings.NewReader("{}"))
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
		t.Errorf("an unsigned RPC got status %d", resp.StatusCode)
	}

	// The operator CLI reaches a node with the cluster secret.
	var out strings.Builder
	if err := runAdmin(context.Background(), []string{"status", "--config", nodes[2].cfg}, env(nil), &out, io.Discard); err != nil {
		t.Fatalf("admin status: %v", err)
	}
	if !strings.Contains(out.String(), `"status": "ok"`) {
		t.Errorf("admin status = %s", out.String())
	}

	// Losing a node leaves reads and writes available (4 of 6 drives).
	nodes[2].stop()
	select {
	case err := <-nodes[2].result:
		if err != nil {
			t.Fatalf("node 2 shutdown: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("node 2 did not stop")
	}
	if st, b := s3(t, c, base, nodes[0].addr, "GET", "/dist/obj", ""); st != 200 || b != payload {
		t.Errorf("read with a node down: %d", st)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		st, b := s3(t, c, base, nodes[1].addr, "PUT", "/dist/while-down", "still writable")
		if st == 200 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("write with a node down: %d %s", st, b)
		}
		time.Sleep(200 * time.Millisecond)
	}
	if st, b := s3(t, c, base, nodes[0].addr, "GET", "/dist?list-type=2", ""); st != 200 ||
		!strings.Contains(b, "<Key>obj</Key>") || !strings.Contains(b, "<Key>while-down</Key>") {
		t.Errorf("list with a node down: %d %s", st, b)
	}
	// And health reports it.
	deadline = time.Now().Add(10 * time.Second)
	for {
		_, b := plainGet(t, c, base+nodes[0].addr+"/_nanoio/health/cluster")
		if strings.Contains(b, "degraded") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("cluster health never reported the lost node: %s", b)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestClusterOverTLS(t *testing.T)          { clusterScenario(t, true) }
func TestClusterPlaintextDevMode(t *testing.T) { clusterScenario(t, false) }

func TestClusterRefusesPlaintextByDefault(t *testing.T) {
	dir := t.TempDir()
	cfg := map[string]any{
		"address": "127.0.0.1:0",
		"cluster": map[string]any{
			"node": "a", "nodes": map[string]string{"a": "127.0.0.1:1", "b": "127.0.0.1:2"},
			"secrets": []string{clusterSecret},
			"pools":   []map[string]any{{"sets": [][]string{{"a:" + dir + "/1", "b:" + dir + "/2"}}}},
		},
	}
	b, _ := json.Marshal(cfg)
	path := filepath.Join(dir, "c.json")
	os.WriteFile(path, b, 0o600)
	err := run(context.Background(), []string{"--config", path}, env(nil), io.Discard)
	if err == nil || !strings.Contains(err.Error(), "inter-node TLS is required") {
		t.Fatalf("err = %v, want a refusal naming inter-node TLS", err)
	}
	// The flag waives it explicitly.
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	// It then starts and waits for peers that never come, until ctx ends.
	err = run(ctx, []string{"--config", path, "--inter-node-tls-required=false"}, env(nil), io.Discard)
	if err != nil && strings.Contains(err.Error(), "inter-node TLS is required") {
		t.Errorf("the waiver was ignored: %v", err)
	}
}

func allLogs(nodes []*tnode) string {
	var b strings.Builder
	for _, nd := range nodes {
		fmt.Fprintf(&b, "---- %s ----\n%s\n", nd.id, nd.out.String())
	}
	return b.String()
}
