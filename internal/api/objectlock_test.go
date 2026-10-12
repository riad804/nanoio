package api

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

const lockBucket = "lockapi"

// newLockEnv serves a bucket created through the API with object lock.
func newLockEnv(t *testing.T) *testEnv {
	t.Helper()
	e := newEnv(t)
	resp, b := e.do("PUT", "/"+lockBucket, nil, hdr{"x-amz-bucket-object-lock-enabled": "true"})
	if resp.StatusCode != 200 {
		t.Fatalf("create lock bucket: %d %s", resp.StatusCode, b)
	}
	return e
}

func inHours(n int) string {
	return time.Now().Add(time.Duration(n) * time.Hour).UTC().Format("2006-01-02T15:04:05.000Z")
}

func retentionXML(mode, until string) string {
	if mode == "" {
		return `<Retention xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></Retention>`
	}
	return `<Retention xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Mode>` + mode +
		`</Mode><RetainUntilDate>` + until + `</RetainUntilDate></Retention>`
}

func holdXML(status string) string {
	return `<LegalHold xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>` + status + `</Status></LegalHold>`
}

// lockState is what an object is created with in the matrix tests.
type lockState struct {
	name string
	hdrs hdr
}

var lockStates = map[string]lockState{
	"none":       {"none", hdr{}},
	"compliance": {"compliance", hdr{hdrLockMode: "COMPLIANCE", hdrLockUntil: inHours(48)}},
	"governance": {"governance", hdr{hdrLockMode: "GOVERNANCE", hdrLockUntil: inHours(48)}},
	"hold":       {"legal hold", hdr{hdrLockHold: "ON"}},
	"gov+hold":   {"governance + hold", hdr{hdrLockMode: "GOVERNANCE", hdrLockUntil: inHours(48), hdrLockHold: "ON"}},
}

// What a refused request looks like. A lock refusal and an IAM refusal are
// both 403 AccessDenied; the message tells them apart.
const (
	ok204    = "204"
	ok200    = "200"
	byLock   = "403 lock"
	byPolicy = "403 policy"
)

func checkOutcome(t *testing.T, resp *http.Response, body []byte, want string) {
	t.Helper()
	switch want {
	case ok204, ok200:
		if fmt.Sprint(resp.StatusCode) != want {
			t.Errorf("status = %d, want %s\n%s", resp.StatusCode, want, body)
		}
	case byLock:
		er := wantError(t, resp, body, 403, "AccessDenied")
		if !strings.Contains(er.Message, "object lock") {
			t.Errorf("message = %q, want the object lock refusal", er.Message)
		}
	case byPolicy:
		er := wantError(t, resp, body, 403, "AccessDenied")
		if strings.Contains(er.Message, "object lock") {
			t.Errorf("message = %q, want the plain IAM refusal", er.Message)
		}
	default:
		t.Fatalf("bad expectation %q", want)
	}
}

// TestObjectLockDeleteMatrix is the enforcement matrix for removing a
// version: every principal (root, one who holds
// s3:BypassGovernanceRetention, one who does not), with and without the
// bypass header, against every lock state.
func TestObjectLockDeleteMatrix(t *testing.T) {
	e := newLockEnv(t)
	tests := []struct {
		state     string
		principal string
		bypass    bool
		want      string
	}{
		// COMPLIANCE: nobody, ever. Not even root, not even with the
		// permission and the header.
		{"compliance", "root", false, byLock},
		{"compliance", "root", true, byLock},
		{"compliance", "governor", false, byLock},
		{"compliance", "governor", true, byLock},
		{"compliance", "locker", false, byLock},
		{"compliance", "locker", true, byPolicy},

		// GOVERNANCE: the header and the permission, both.
		{"governance", "root", false, byLock},
		{"governance", "root", true, ok204},
		{"governance", "governor", false, byLock},
		{"governance", "governor", true, ok204},
		{"governance", "locker", false, byLock},
		{"governance", "locker", true, byPolicy},

		// A legal hold blocks deletion whatever else is true.
		{"hold", "root", false, byLock},
		{"hold", "root", true, byLock},
		{"hold", "governor", true, byLock},
		{"hold", "locker", false, byLock},

		// Retention bypassed, hold still there.
		{"gov+hold", "root", true, byLock},
		{"gov+hold", "governor", true, byLock},
		{"gov+hold", "governor", false, byLock},

		// No lock: an ordinary delete. Asking for a bypass one may not
		// have is refused all the same.
		{"none", "root", false, ok204},
		{"none", "locker", false, ok204},
		{"none", "governor", true, ok204},
		{"none", "locker", true, byPolicy},
	}
	for i, tt := range tests {
		name := fmt.Sprintf("%s/%s/bypass=%v", tt.state, tt.principal, tt.bypass)
		t.Run(name, func(t *testing.T) {
			e.t = t
			key := fmt.Sprintf("del-%d", i)
			resp := e.put("/"+lockBucket+"/"+key, "payload", lockStates[tt.state].hdrs)
			if resp.StatusCode != 200 {
				t.Fatalf("put: %d", resp.StatusCode)
			}
			vid := resp.Header.Get("x-amz-version-id")
			h := hdr{}
			if tt.bypass {
				h[hdrBypass] = "true"
			}
			path := "/" + lockBucket + "/" + key + "?versionId=" + vid
			var r *http.Response
			var b []byte
			if tt.principal == "root" {
				r, b = e.do("DELETE", path, nil, h)
			} else {
				r, b = e.doAs(tt.principal, "DELETE", path, nil, h)
			}
			checkOutcome(t, r, b, tt.want)

			stillThere := tt.want != ok204
			got, _ := e.do("GET", path, nil, nil)
			if stillThere && got.StatusCode != 200 {
				t.Errorf("a refused DELETE removed the version: GET = %d", got.StatusCode)
			}
			if !stillThere && got.StatusCode == 200 {
				t.Errorf("version survived an allowed DELETE")
			}
		})
	}
}

// TestObjectLockRetentionChangeMatrix is the other half: PutObjectRetention
// against an existing retention.
func TestObjectLockRetentionChangeMatrix(t *testing.T) {
	e := newLockEnv(t)
	later, sooner := inHours(96), inHours(24)
	tests := []struct {
		name      string
		state     string
		principal string
		bypass    bool
		mode      string // "" removes
		until     string
		want      string
	}{
		{"compliance extend", "compliance", "root", false, "COMPLIANCE", later, ok200},
		{"compliance shorten", "compliance", "root", false, "COMPLIANCE", sooner, byLock},
		{"compliance shorten, root with bypass", "compliance", "root", true, "COMPLIANCE", sooner, byLock},
		{"compliance remove", "compliance", "root", false, "", "", byLock},
		{"compliance remove, root with bypass", "compliance", "root", true, "", "", byLock},
		{"compliance downgrade to governance", "compliance", "governor", true, "GOVERNANCE", later, byLock},

		{"governance extend", "governance", "locker", false, "GOVERNANCE", later, ok200},
		{"governance upgrade to compliance", "governance", "locker", false, "COMPLIANCE", sooner, byLock},
		{"governance upgrade to compliance, later", "governance", "locker", false, "COMPLIANCE", later, ok200},
		{"governance shorten, no bypass", "governance", "governor", false, "GOVERNANCE", sooner, byLock},
		{"governance shorten, bypass", "governance", "governor", true, "GOVERNANCE", sooner, ok200},
		{"governance shorten, bypass without permission", "governance", "locker", true, "GOVERNANCE", sooner, byPolicy},
		{"governance remove, no bypass", "governance", "governor", false, "", "", byLock},
		{"governance remove, bypass", "governance", "governor", true, "", "", ok200},
		{"governance remove, bypass without permission", "governance", "locker", true, "", "", byPolicy},

		{"none -> compliance", "none", "locker", false, "COMPLIANCE", later, ok200},
		{"none -> governance", "none", "locker", false, "GOVERNANCE", later, ok200},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e.t = t
			key := fmt.Sprintf("ret-%d", i)
			resp := e.put("/"+lockBucket+"/"+key, "payload", lockStates[tt.state].hdrs)
			vid := resp.Header.Get("x-amz-version-id")
			h := hdr{}
			if tt.bypass {
				h[hdrBypass] = "true"
			}
			path := "/" + lockBucket + "/" + key + "?retention&versionId=" + vid
			body := strings.NewReader(retentionXML(tt.mode, tt.until))
			var r *http.Response
			var b []byte
			if tt.principal == "root" {
				r, b = e.do("PUT", path, body, h)
			} else {
				r, b = e.doAs(tt.principal, "PUT", path, body, h)
			}
			checkOutcome(t, r, b, tt.want)

			// What is stored afterwards.
			g, gb := e.do("GET", path, nil, nil)
			wantMode, wantUntil := lockStates[tt.state].hdrs[hdrLockMode], lockStates[tt.state].hdrs[hdrLockUntil]
			if tt.want == ok200 {
				wantMode, wantUntil = tt.mode, tt.until
			}
			if wantMode == "" {
				wantError(t, g, gb, 404, "NoSuchObjectLockConfiguration")
				return
			}
			if g.StatusCode != 200 || !strings.Contains(string(gb), "<Mode>"+wantMode+"</Mode>") ||
				!strings.Contains(string(gb), "<RetainUntilDate>"+wantUntil+"</RetainUntilDate>") {
				t.Errorf("retention afterwards = %d %s, want %s until %s", g.StatusCode, gb, wantMode, wantUntil)
			}
		})
	}
}

// TestObjectLockDeleteWithoutVersionIDMakesMarker pins the rule that only
// versions are protected: a plain DELETE succeeds under every lock state
// and leaves the locked version readable.
func TestObjectLockDeleteWithoutVersionIDMakesMarker(t *testing.T) {
	e := newLockEnv(t)
	for _, name := range []string{"compliance", "governance", "hold", "gov+hold"} {
		t.Run(name, func(t *testing.T) {
			e.t = t
			key := "marker-" + strings.ReplaceAll(name, "+", "-")
			vid := e.put("/"+lockBucket+"/"+key, "protected", lockStates[name].hdrs).Header.Get("x-amz-version-id")

			resp, b := e.do("DELETE", "/"+lockBucket+"/"+key, nil, nil)
			if resp.StatusCode != 204 {
				t.Fatalf("DELETE without versionId = %d, want 204\n%s", resp.StatusCode, b)
			}
			if resp.Header.Get("x-amz-delete-marker") != "true" {
				t.Error("no x-amz-delete-marker on the response")
			}
			mid := resp.Header.Get("x-amz-version-id")
			if len(mid) != 36 || mid == vid {
				t.Errorf("marker version id = %q (object was %q)", mid, vid)
			}
			// The key reads as deleted...
			if r, _ := e.do("GET", "/"+lockBucket+"/"+key, nil, nil); r.StatusCode != 404 {
				t.Errorf("GET latest = %d, want 404", r.StatusCode)
			}
			// ...and the protected version is intact.
			if got, _ := e.get("/" + lockBucket + "/" + key + "?versionId=" + vid); got != "protected" {
				t.Errorf("locked version reads %q", got)
			}
			// It is listed as noncurrent, still locked.
			r, lb := e.do("HEAD", "/"+lockBucket+"/"+key+"?versionId="+vid, nil, nil)
			if r.StatusCode != 200 || (name != "hold" && r.Header.Get(hdrLockMode) == "") {
				t.Errorf("HEAD version = %d %v %s", r.StatusCode, r.Header, lb)
			}
		})
	}
}

func TestObjectLockHeadersAndDocuments(t *testing.T) {
	e := newLockEnv(t)
	until := inHours(30)
	resp := e.put("/"+lockBucket+"/doc", "x", hdr{hdrLockMode: "GOVERNANCE", hdrLockUntil: until, hdrLockHold: "ON"})
	if resp.StatusCode != 200 {
		t.Fatalf("put: %d", resp.StatusCode)
	}
	vid := resp.Header.Get("x-amz-version-id")

	for _, method := range []string{"GET", "HEAD"} {
		r, _ := e.do(method, "/"+lockBucket+"/doc", nil, nil)
		if r.Header.Get(hdrLockMode) != "GOVERNANCE" || r.Header.Get(hdrLockUntil) != until || r.Header.Get(hdrLockHold) != "ON" {
			t.Errorf("%s lock headers = %q %q %q", method, r.Header.Get(hdrLockMode), r.Header.Get(hdrLockUntil), r.Header.Get(hdrLockHold))
		}
	}

	r, b := e.do("GET", "/"+lockBucket+"/doc?retention", nil, nil)
	if r.StatusCode != 200 || !strings.Contains(string(b), "<Mode>GOVERNANCE</Mode>") ||
		!strings.Contains(string(b), "<RetainUntilDate>"+until+"</RetainUntilDate>") || r.Header.Get("x-amz-version-id") != vid {
		t.Errorf("GetObjectRetention = %d %s %v", r.StatusCode, b, r.Header)
	}
	r, b = e.do("GET", "/"+lockBucket+"/doc?legal-hold&versionId="+vid, nil, nil)
	if r.StatusCode != 200 || !strings.Contains(string(b), "<Status>ON</Status>") {
		t.Errorf("GetObjectLegalHold = %d %s", r.StatusCode, b)
	}
	if r, b = e.do("PUT", "/"+lockBucket+"/doc?legal-hold", strings.NewReader(holdXML("OFF")), nil); r.StatusCode != 200 {
		t.Fatalf("PutObjectLegalHold OFF = %d %s", r.StatusCode, b)
	}
	r, b = e.do("GET", "/"+lockBucket+"/doc?legal-hold", nil, nil)
	if !strings.Contains(string(b), "<Status>OFF</Status>") {
		t.Errorf("hold after OFF: %s", b)
	}
	if r, _ = e.do("HEAD", "/"+lockBucket+"/doc", nil, nil); r.Header.Get(hdrLockHold) != "" {
		t.Errorf("legal-hold header after OFF = %q", r.Header.Get(hdrLockHold))
	}
	// Retention is untouched by turning the hold off.
	if r, _ = e.do("HEAD", "/"+lockBucket+"/doc", nil, nil); r.Header.Get(hdrLockMode) != "GOVERNANCE" {
		t.Error("turning the legal hold off dropped the retention")
	}

	// Nothing set: retention is a 404, a legal hold reads OFF.
	e.put("/"+lockBucket+"/plain", "x", nil)
	r, b = e.do("GET", "/"+lockBucket+"/plain?retention", nil, nil)
	wantError(t, r, b, 404, "NoSuchObjectLockConfiguration")
	r, b = e.do("GET", "/"+lockBucket+"/plain?legal-hold", nil, nil)
	if r.StatusCode != 200 || !strings.Contains(string(b), "<Status>OFF</Status>") {
		t.Errorf("legal hold of a plain object = %d %s", r.StatusCode, b)
	}
}

func TestObjectLockBucketConfiguration(t *testing.T) {
	e := newLockEnv(t)

	r, b := e.do("GET", "/"+lockBucket+"?object-lock", nil, nil)
	if r.StatusCode != 200 || !strings.Contains(string(b), "<ObjectLockEnabled>Enabled</ObjectLockEnabled>") ||
		strings.Contains(string(b), "<Rule>") {
		t.Errorf("fresh lock bucket config = %d %s", r.StatusCode, b)
	}
	// Created versioned.
	r, b = e.do("GET", "/"+lockBucket+"?versioning", nil, nil)
	if !strings.Contains(string(b), "<Status>Enabled</Status>") {
		t.Errorf("versioning of a lock bucket: %s", b)
	}

	put := func(body string) (*http.Response, []byte) {
		return e.do("PUT", "/"+lockBucket+"?object-lock", strings.NewReader(body), nil)
	}
	cfg := func(inner string) string {
		return `<ObjectLockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><ObjectLockEnabled>Enabled</ObjectLockEnabled>` +
			inner + `</ObjectLockConfiguration>`
	}
	rule := func(mode, amount string) string {
		return `<Rule><DefaultRetention><Mode>` + mode + `</Mode>` + amount + `</DefaultRetention></Rule>`
	}
	if r, b = put(cfg(rule("GOVERNANCE", "<Days>3</Days>"))); r.StatusCode != 200 {
		t.Fatalf("put config: %d %s", r.StatusCode, b)
	}
	r, b = e.do("GET", "/"+lockBucket+"?object-lock", nil, nil)
	if !strings.Contains(string(b), "<Mode>GOVERNANCE</Mode>") || !strings.Contains(string(b), "<Days>3</Days>") {
		t.Errorf("config after put: %s", b)
	}
	// A new object picks the default up.
	vid := e.put("/"+lockBucket+"/defaulted", "x", nil).Header.Get("x-amz-version-id")
	r, b = e.do("GET", "/"+lockBucket+"/defaulted?retention&versionId="+vid, nil, nil)
	if r.StatusCode != 200 || !strings.Contains(string(b), "<Mode>GOVERNANCE</Mode>") {
		t.Errorf("default retention not applied: %d %s", r.StatusCode, b)
	}
	r, b = e.do("DELETE", "/"+lockBucket+"/defaulted?versionId="+vid, nil, nil)
	checkOutcome(t, r, b, byLock)

	for _, tt := range []struct{ name, body string }{
		{"days and years", cfg(rule("GOVERNANCE", "<Days>1</Days><Years>1</Years>"))},
		{"neither", cfg(rule("GOVERNANCE", ""))},
		{"zero days", cfg(rule("GOVERNANCE", "<Days>0</Days>"))},
		{"unknown mode", cfg(rule("LOOSE", "<Days>1</Days>"))},
		{"rule without retention", cfg(`<Rule></Rule>`)},
		{"not enabled", strings.Replace(cfg(""), "Enabled</ObjectLockEnabled>", "Disabled</ObjectLockEnabled>", 1)},
		{"not xml", "nope"},
	} {
		t.Run("rejects "+tt.name, func(t *testing.T) {
			e.t = t
			r, b := put(tt.body)
			wantError(t, r, b, 400, "MalformedXML")
		})
	}
	// Clearing the default is a configuration with no rule.
	if r, b = put(cfg("")); r.StatusCode != 200 {
		t.Fatalf("clear default: %d %s", r.StatusCode, b)
	}
	vid = e.put("/"+lockBucket+"/undefaulted", "x", nil).Header.Get("x-amz-version-id")
	r, b = e.do("GET", "/"+lockBucket+"/undefaulted?retention&versionId="+vid, nil, nil)
	wantError(t, r, b, 404, "NoSuchObjectLockConfiguration")

	// Versioning cannot be suspended.
	r, b = e.do("PUT", "/"+lockBucket+"?versioning", strings.NewReader(vcfg("Suspended")), nil)
	wantError(t, r, b, 409, "InvalidBucketState")

	// A bucket created without object lock has none, and cannot gain it.
	e.mb("plainlock")
	r, b = e.do("GET", "/plainlock?object-lock", nil, nil)
	wantError(t, r, b, 404, "ObjectLockConfigurationNotFoundError")
	r, b = e.do("PUT", "/plainlock?object-lock", strings.NewReader(cfg("")), nil)
	wantError(t, r, b, 409, "InvalidBucketState")
	r, b = e.do("PUT", "/plainlock/k", strings.NewReader("x"), hdr{hdrLockHold: "ON"})
	wantError(t, r, b, 400, "InvalidRequest")
	e.put("/plainlock/k", "x", nil)
	r, b = e.do("GET", "/plainlock/k?retention", nil, nil)
	wantError(t, r, b, 400, "InvalidRequest")
	r, b = e.do("PUT", "/plainlock/k?legal-hold", strings.NewReader(holdXML("ON")), nil)
	wantError(t, r, b, 400, "InvalidRequest")

	// The creation header is validated.
	r, b = e.do("PUT", "/badhdr", nil, hdr{"x-amz-bucket-object-lock-enabled": "maybe"})
	wantError(t, r, b, 400, "InvalidArgument")
	r, b = e.do("PUT", "/falsehdr", nil, hdr{"x-amz-bucket-object-lock-enabled": "false"})
	if r.StatusCode != 200 {
		t.Fatalf("create with the header false: %d %s", r.StatusCode, b)
	}
	r, b = e.do("GET", "/falsehdr?object-lock", nil, nil)
	wantError(t, r, b, 404, "ObjectLockConfigurationNotFoundError")
}

func TestObjectLockRequestValidation(t *testing.T) {
	e := newLockEnv(t)
	past := time.Now().Add(-time.Hour).UTC().Format("2006-01-02T15:04:05.000Z")
	tests := []struct {
		name string
		hdrs hdr
	}{
		// The clock-skew rule: a retain-until date that is not in the
		// future is refused, for COMPLIANCE and for GOVERNANCE.
		{"compliance in the past", hdr{hdrLockMode: "COMPLIANCE", hdrLockUntil: past}},
		{"governance in the past", hdr{hdrLockMode: "GOVERNANCE", hdrLockUntil: past}},
		{"mode without date", hdr{hdrLockMode: "COMPLIANCE"}},
		{"date without mode", hdr{hdrLockUntil: inHours(1)}},
		{"unknown mode", hdr{hdrLockMode: "LOOSE", hdrLockUntil: inHours(1)}},
		{"date not ISO 8601", hdr{hdrLockMode: "COMPLIANCE", hdrLockUntil: "tomorrow"}},
		{"bad legal hold", hdr{hdrLockHold: "MAYBE"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e.t = t
			r, b := e.do("PUT", "/"+lockBucket+"/invalid", strings.NewReader("x"), tt.hdrs)
			wantError(t, r, b, 400, "InvalidArgument")
		})
	}
	if r, _ := e.do("HEAD", "/"+lockBucket+"/invalid", nil, nil); r.StatusCode != 404 {
		t.Errorf("a refused PUT created the object (HEAD = %d)", r.StatusCode)
	}

	// The same through PutObjectRetention.
	vid := e.put("/"+lockBucket+"/target", "x", nil).Header.Get("x-amz-version-id")
	for _, mode := range []string{"COMPLIANCE", "GOVERNANCE"} {
		r, b := e.do("PUT", "/"+lockBucket+"/target?retention&versionId="+vid, strings.NewReader(retentionXML(mode, past)), nil)
		wantError(t, r, b, 400, "InvalidArgument")
	}
	for _, body := range []string{
		`<Retention><Mode>COMPLIANCE</Mode></Retention>`,
		`<Retention><RetainUntilDate>` + inHours(1) + `</RetainUntilDate></Retention>`,
		`<Retention><Mode>LOOSE</Mode><RetainUntilDate>` + inHours(1) + `</RetainUntilDate></Retention>`,
		`<Retention><Mode>COMPLIANCE</Mode><RetainUntilDate>soon</RetainUntilDate></Retention>`,
		`nope`,
	} {
		r, b := e.do("PUT", "/"+lockBucket+"/target?retention&versionId="+vid, strings.NewReader(body), nil)
		wantError(t, r, b, 400, "MalformedXML")
	}
	r, b := e.do("PUT", "/"+lockBucket+"/target?legal-hold", strings.NewReader(holdXML("MAYBE")), nil)
	wantError(t, r, b, 400, "MalformedXML")
}

func TestObjectLockPermissionsForLockHeaders(t *testing.T) {
	e := newLockEnv(t)
	// "locker" holds PutObjectRetention and PutObjectLegalHold; "scoped"
	// may PutObject under pub/ and nothing more. Sending lock headers needs
	// the lock actions on top of s3:PutObject.
	r, b := e.doAs("locker", "PUT", "/"+lockBucket+"/a", strings.NewReader("x"),
		hdr{hdrLockMode: "COMPLIANCE", hdrLockUntil: inHours(2), hdrLockHold: "ON"})
	if r.StatusCode != 200 {
		t.Fatalf("locker put with lock headers: %d %s", r.StatusCode, b)
	}

	e.mb("scoped")
	if r, _ = e.doAs("scoped", "PUT", "/scoped/pub/plain", strings.NewReader("x"), nil); r.StatusCode != 200 {
		t.Fatalf("scoped plain put = %d", r.StatusCode)
	}
	r, b = e.doAs("scoped", "PUT", "/scoped/pub/locked", strings.NewReader("x"), hdr{hdrLockHold: "ON"})
	wantError(t, r, b, 403, "AccessDenied")
	r, b = e.doAs("scoped", "PUT", "/scoped/pub/locked", strings.NewReader("x"),
		hdr{hdrLockMode: "GOVERNANCE", hdrLockUntil: inHours(1)})
	wantError(t, r, b, 403, "AccessDenied")
	if r, _ = e.do("HEAD", "/scoped/pub/locked", nil, nil); r.StatusCode != 404 {
		t.Errorf("a refused PUT created the object (HEAD = %d)", r.StatusCode)
	}
	// And the lock operations themselves are separately authorised.
	for _, c := range []struct{ method, path, body string }{
		{"PUT", "/scoped/pub/plain?retention", retentionXML("GOVERNANCE", inHours(1))},
		{"GET", "/scoped/pub/plain?retention", ""},
		{"PUT", "/scoped/pub/plain?legal-hold", holdXML("ON")},
		{"GET", "/scoped/pub/plain?legal-hold", ""},
		{"PUT", "/scoped?object-lock", `<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>`},
		{"GET", "/scoped?object-lock", ""},
	} {
		r, b := e.doAs("scoped", c.method, c.path, strings.NewReader(c.body), nil)
		if r.StatusCode != 403 {
			t.Errorf("%s %s = %d, want 403\n%s", c.method, c.path, r.StatusCode, b)
		}
	}
}

func TestObjectLockMultiDelete(t *testing.T) {
	e := newLockEnv(t)
	locked := e.put("/"+lockBucket+"/md-locked", "a", lockStates["compliance"].hdrs).Header.Get("x-amz-version-id")
	gov := e.put("/"+lockBucket+"/md-gov", "b", lockStates["governance"].hdrs).Header.Get("x-amz-version-id")
	free := e.put("/"+lockBucket+"/md-free", "c", nil).Header.Get("x-amz-version-id")

	body := fmt.Sprintf(`<Delete><Object><Key>md-locked</Key><VersionId>%s</VersionId></Object>`+
		`<Object><Key>md-gov</Key><VersionId>%s</VersionId></Object>`+
		`<Object><Key>md-free</Key><VersionId>%s</VersionId></Object></Delete>`, locked, gov, free)

	// Without the header only the unprotected version goes.
	r, b := e.do("POST", "/"+lockBucket+"?delete", strings.NewReader(body), nil)
	if r.StatusCode != 200 {
		t.Fatalf("multi-delete: %d %s", r.StatusCode, b)
	}
	var res deleteResult
	mustXML(t, b, &res)
	if len(res.Deleted) != 1 || res.Deleted[0].Key != "md-free" || len(res.Errors) != 2 {
		t.Fatalf("result = %+v", res)
	}
	for _, de := range res.Errors {
		if de.Code != "AccessDenied" {
			t.Errorf("error entry %+v, want AccessDenied", de)
		}
	}
	// With the header, governance goes and compliance stays.
	body = fmt.Sprintf(`<Delete><Object><Key>md-locked</Key><VersionId>%s</VersionId></Object>`+
		`<Object><Key>md-gov</Key><VersionId>%s</VersionId></Object></Delete>`, locked, gov)
	r, b = e.do("POST", "/"+lockBucket+"?delete", strings.NewReader(body), hdr{hdrBypass: "true"})
	res = deleteResult{}
	mustXML(t, b, &res)
	if len(res.Deleted) != 1 || res.Deleted[0].Key != "md-gov" || len(res.Errors) != 1 || res.Errors[0].Key != "md-locked" {
		t.Fatalf("bypass result = %+v\n%s", res, b)
	}
	// A principal without the permission gets the per-key refusal.
	gov2 := e.put("/"+lockBucket+"/md-gov2", "b", lockStates["governance"].hdrs).Header.Get("x-amz-version-id")
	body = fmt.Sprintf(`<Delete><Object><Key>md-gov2</Key><VersionId>%s</VersionId></Object></Delete>`, gov2)
	r, b = e.doAs("locker", "POST", "/"+lockBucket+"?delete", strings.NewReader(body), hdr{hdrBypass: "true"})
	res = deleteResult{}
	mustXML(t, b, &res)
	if len(res.Deleted) != 0 || len(res.Errors) != 1 {
		t.Fatalf("no-permission result = %+v\n%s", res, b)
	}
	if got, _ := e.get("/" + lockBucket + "/md-gov2?versionId=" + gov2); got != "b" {
		t.Errorf("version after a refused bypass: %q", got)
	}
}

func TestObjectLockMultipartHeaders(t *testing.T) {
	e := newLockEnv(t)
	until := inHours(5)
	id := e.initiate(lockBucket, "mp", hdr{hdrLockMode: "COMPLIANCE", hdrLockUntil: until})
	resp, _ := e.do("PUT", "/"+lockBucket+"/mp?partNumber=1&uploadId="+id, strings.NewReader("part-one"), nil)
	etag := resp.Header.Get("ETag")
	resp, b := e.do("POST", "/"+lockBucket+"/mp?uploadId="+id, strings.NewReader(completeXML([2]string{"1", etag})), nil)
	if resp.StatusCode != 200 {
		t.Fatalf("complete: %d %s", resp.StatusCode, b)
	}
	vid := resp.Header.Get("x-amz-version-id")
	r, _ := e.do("HEAD", "/"+lockBucket+"/mp?versionId="+vid, nil, nil)
	if r.Header.Get(hdrLockMode) != "COMPLIANCE" || r.Header.Get(hdrLockUntil) != until {
		t.Errorf("completed upload lock headers: %v", r.Header)
	}
	r, b = e.do("DELETE", "/"+lockBucket+"/mp?versionId="+vid, nil, hdr{hdrBypass: "true"})
	checkOutcome(t, r, b, byLock)
}

func TestObjectLockOnMarkersAndMissing(t *testing.T) {
	e := newLockEnv(t)
	e.put("/"+lockBucket+"/gone", "x", nil)
	r, _ := e.do("DELETE", "/"+lockBucket+"/gone", nil, nil)
	mark := r.Header.Get("x-amz-version-id")

	ret := strings.NewReader(retentionXML("GOVERNANCE", inHours(1)))
	r, b := e.do("PUT", "/"+lockBucket+"/gone?retention", ret, nil)
	wantError(t, r, b, 404, "NoSuchKey")
	r, b = e.do("PUT", "/"+lockBucket+"/gone?retention&versionId="+mark, strings.NewReader(retentionXML("GOVERNANCE", inHours(1))), nil)
	wantError(t, r, b, 405, "MethodNotAllowed")
	r, b = e.do("PUT", "/"+lockBucket+"/never?retention", strings.NewReader(retentionXML("GOVERNANCE", inHours(1))), nil)
	wantError(t, r, b, 404, "NoSuchKey")
	r, b = e.do("PUT", "/"+lockBucket+"/gone?legal-hold&versionId=11111111-2222-4333-8444-555555555555", strings.NewReader(holdXML("ON")), nil)
	wantError(t, r, b, 404, "NoSuchVersion")
	// Unsupported verbs on the subresources.
	r, b = e.do("DELETE", "/"+lockBucket+"/gone?retention", nil, nil)
	wantError(t, r, b, 405, "MethodNotAllowed")
	r, b = e.do("POST", "/"+lockBucket+"?object-lock", nil, nil)
	wantError(t, r, b, 405, "MethodNotAllowed")
}

func TestObjectLockForcedBucketDeletionIsNotPossibleOverHTTP(t *testing.T) {
	e := newLockEnv(t)
	e.put("/"+lockBucket+"/k", "x", lockStates["compliance"].hdrs)
	r, b := e.do("DELETE", "/"+lockBucket, nil, nil)
	wantError(t, r, b, 409, "BucketNotEmpty")
}

func TestObjectLockClockSkewTolerance(t *testing.T) {
	// A date barely in the future is accepted; barely in the past is not.
	e := newLockEnv(t)
	soon := time.Now().Add(10 * time.Second).UTC().Format(time.RFC3339Nano)
	r, b := e.do("PUT", "/"+lockBucket+"/skew", strings.NewReader("x"), hdr{hdrLockMode: "COMPLIANCE", hdrLockUntil: soon})
	if r.StatusCode != 200 {
		t.Errorf("a date 10s ahead: %d %s", r.StatusCode, b)
	}
	justPast := time.Now().Add(-1 * time.Second).UTC().Format(time.RFC3339Nano)
	r, b = e.do("PUT", "/"+lockBucket+"/skew2", strings.NewReader("x"), hdr{hdrLockMode: "COMPLIANCE", hdrLockUntil: justPast})
	wantError(t, r, b, 400, "InvalidArgument")
}

func mustXML(t *testing.T, b []byte, v any) {
	t.Helper()
	if err := xml.Unmarshal(b, v); err != nil {
		t.Fatalf("not XML: %v\n%s", err, b)
	}
}
