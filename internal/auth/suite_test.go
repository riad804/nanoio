package auth

import (
	"bytes"
	"errors"
	"io/fs"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// Credentials and clock of the official AWS SigV4 test suite.
const (
	suiteAccessKey = "AKIDEXAMPLE"
	suiteSecretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	suiteRegion    = "us-east-1"
	suiteService   = "service"
)

var suiteNow = time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)

type suiteRequest struct {
	method, target string
	headers        []struct{ name, value string }
	body           []byte
}

// parseSuiteRequest reads a .req file. net/http cannot be used: vectors
// contain unescaped spaces in the request target and obs-fold continuation
// lines.
func parseSuiteRequest(t *testing.T, raw []byte) suiteRequest {
	t.Helper()
	head, body, _ := bytes.Cut(raw, []byte("\n\n"))
	lines := strings.Split(strings.ReplaceAll(string(head), "\r\n", "\n"), "\n")
	first := lines[0]
	sp1, sp2 := strings.Index(first, " "), strings.LastIndex(first, " ")
	if sp1 < 0 || sp2 <= sp1 {
		t.Fatalf("bad request line %q", first)
	}
	req := suiteRequest{method: first[:sp1], target: first[sp1+1 : sp2], body: bytes.TrimRight(body, "\n")}
	for _, l := range lines[1:] {
		if l == "" {
			continue
		}
		if l[0] == ' ' || l[0] == '\t' { // obs-fold: continuation of the previous header
			last := &req.headers[len(req.headers)-1]
			last.value += " " + strings.TrimSpace(l)
			continue
		}
		name, value, ok := strings.Cut(l, ":")
		if !ok {
			t.Fatalf("bad header line %q", l)
		}
		req.headers = append(req.headers, struct{ name, value string }{name, value})
	}
	return req
}

func (r suiteRequest) headerSet() headerSet {
	h := headerSet{}
	for _, kv := range r.headers {
		n := strings.ToLower(kv.name)
		h[n] = append(h[n], kv.value)
	}
	return h
}

func (r suiteRequest) httpRequest() *http.Request {
	path, query, _ := strings.Cut(r.target, "?")
	hdr := http.Header{}
	host := ""
	for _, kv := range r.headers {
		if strings.EqualFold(kv.name, "host") {
			host = kv.value
			continue
		}
		k := textproto.CanonicalMIMEHeaderKey(kv.name)
		hdr[k] = append(hdr[k], kv.value)
	}
	decoded, err := url.PathUnescape(path)
	if err != nil {
		decoded = path
	}
	return &http.Request{
		Method: r.method, Host: host, Header: hdr, RequestURI: r.target,
		URL:           &url.URL{Path: decoded, RawQuery: query},
		ContentLength: int64(len(r.body)),
	}
}

type staticCreds map[string]string

func (s staticCreds) SecretKey(ak string) (string, bool) { v, ok := s[ak]; return v, ok }

func suiteVectors(t *testing.T) []string {
	t.Helper()
	var out []string
	root := filepath.Join("testdata", "aws4_testsuite")
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".req") {
			out = append(out, strings.TrimSuffix(p, ".req"))
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func readTrim(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimRight(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
}

func TestOfficialSuite(t *testing.T) {
	vectors := suiteVectors(t)
	if len(vectors) < 30 {
		t.Fatalf("found %d vectors; the vendored suite is incomplete", len(vectors))
	}
	t.Logf("running %d official AWS SigV4 vectors", len(vectors))

	for _, base := range vectors {
		name := strings.TrimPrefix(base, filepath.Join("testdata", "aws4_testsuite")+string(filepath.Separator))
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(base + ".req")
			if err != nil {
				t.Fatal(err)
			}
			req := parseSuiteRequest(t, raw)
			wantCreq := readTrim(t, base+".creq")
			wantSts := readTrim(t, base+".sts")
			wantAuthz := readTrim(t, base+".authz")

			// Pull the signed header list out of the expected Authorization.
			var signed []string
			for _, part := range strings.Split(strings.TrimPrefix(wantAuthz, Algorithm+" "), ",") {
				if k, v, _ := strings.Cut(strings.TrimSpace(part), "="); k == "SignedHeaders" {
					signed = strings.Split(v, ";")
				}
			}
			if len(signed) == 0 {
				t.Fatal("no SignedHeaders in .authz")
			}
			hs := req.headerSet()
			// get-vanilla-with-session-token ships a .req without the
			// X-Amz-Security-Token header that its .creq and .authz sign.
			// The value exists only in the .creq; recover it from there
			// (this vector only) so the rest of the derivation is checked.
			if _, present := hs["x-amz-security-token"]; !present && slices.Contains(signed, "x-amz-security-token") {
				for _, l := range strings.Split(wantCreq, "\n") {
					if v, ok := strings.CutPrefix(l, "x-amz-security-token:"); ok {
						hs["x-amz-security-token"] = []string{v}
						req.headers = append(req.headers, struct{ name, value string }{"X-Amz-Security-Token", v})
						t.Logf("vector omits X-Amz-Security-Token from .req; value taken from its .creq")
					}
				}
			}
			amzDate := hs["x-amz-date"][0]
			path, query, _ := strings.Cut(req.target, "?")

			// 1. Canonical request.
			hdrs, ok := canonicalHeaders(hs, signed)
			if !ok {
				t.Fatal("signed header missing from request")
			}
			creq := canonicalRequest(req.method, canonicalURIGeneric(path), canonicalQuery(query, nil),
				hdrs, signed, sha256Hex(req.body))
			if creq != wantCreq {
				t.Errorf("canonical request mismatch\n got: %q\nwant: %q", creq, wantCreq)
			}
			// 2. String to sign.
			scope := scopeString(amzDate[:8], suiteRegion, suiteService)
			sts := stringToSign(amzDate, scope, creq)
			if sts != wantSts {
				t.Errorf("string to sign mismatch\n got: %q\nwant: %q", sts, wantSts)
			}
			// 3. Authorization header.
			sig := hexMAC(signingKey(suiteSecretKey, amzDate[:8], suiteRegion, suiteService), sts)
			authz := Algorithm + " Credential=" + suiteAccessKey + "/" + scope +
				", SignedHeaders=" + strings.Join(signed, ";") + ", Signature=" + sig
			if authz != wantAuthz {
				t.Errorf("authorization mismatch\n got: %s\nwant: %s", authz, wantAuthz)
			}

			// 4. The same request, end to end through the verifier.
			v := &Verifier{
				Provider: staticCreds{suiteAccessKey: suiteSecretKey},
				Region:   suiteRegion,
				Now:      func() time.Time { return suiteNow },
				service:  suiteService, generic: true,
				payloadHash: func(*http.Request) string { return sha256Hex(req.body) },
			}
			r := req.httpRequest()
			r.Header.Set("Authorization", wantAuthz)
			res, err := v.Authenticate(r)
			if err != nil {
				t.Fatalf("Authenticate rejected the official vector: %v", err)
			}
			if res.AccessKey != suiteAccessKey {
				t.Errorf("AccessKey = %q", res.AccessKey)
			}

			// 5. And a one-character tamper must be refused.
			r2 := req.httpRequest()
			i := strings.LastIndex(wantAuthz, "Signature=") + len("Signature=")
			flipped := []byte(wantAuthz)
			if flipped[i] == '0' {
				flipped[i] = '1'
			} else {
				flipped[i] = '0'
			}
			r2.Header.Set("Authorization", string(flipped))
			if _, err := v.Authenticate(r2); !errors.Is(err, ErrSignatureDoesNotMatch) {
				t.Errorf("tampered signature error = %v, want ErrSignatureDoesNotMatch", err)
			}
		})
	}
}

// The generic canonicalisation must differ from S3's exactly where AWS
// documents that it does (normalize-path.txt): S3 keeps "//" and "..".
func TestS3PathIsNotNormalised(t *testing.T) {
	tests := []struct {
		in          string
		wantS3      string
		wantGeneric string
	}{
		{"/", "/", "/"},
		{"/my-object//example//photo.user", "/my-object//example//photo.user", "/my-object/example/photo.user"},
		{"/a/../b", "/a/../b", "/b"},
		{"/a/./b", "/a/./b", "/a/b"},
		{"/a b/c", "/a%20b/c", "/a%20b/c"},
		{"/ሴ", "/%E1%88%B4", "/%E1%88%B4"},
		{"/a+b", "/a%2Bb", "/a%2Bb"},
		{"", "/", "/"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := canonicalURIS3(tt.in); got != tt.wantS3 {
				t.Errorf("S3 = %q, want %q", got, tt.wantS3)
			}
			if got := canonicalURIGeneric(tt.in); got != tt.wantGeneric {
				t.Errorf("generic = %q, want %q", got, tt.wantGeneric)
			}
		})
	}
}
