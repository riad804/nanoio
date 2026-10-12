package api

import (
	"encoding/xml"
	"io"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func vcfg(status string) string {
	if status == "" {
		return `<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></VersioningConfiguration>`
	}
	return `<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>` + status + `</Status></VersioningConfiguration>`
}

func TestBucketVersioningConfiguration(t *testing.T) {
	e := newEnv(t)
	e.mb("vbucket")

	status := func() string {
		t.Helper()
		resp, b := e.do("GET", "/vbucket?versioning", nil, nil)
		if resp.StatusCode != 200 {
			t.Fatalf("GET ?versioning = %d %s", resp.StatusCode, b)
		}
		s := string(b)
		if !strings.Contains(s, `xmlns="http://s3.amazonaws.com/doc/2006-03-01/"`) || !strings.Contains(s, "VersioningConfiguration") {
			t.Errorf("response is not a VersioningConfiguration: %s", s)
		}
		if i := strings.Index(s, "<Status>"); i >= 0 {
			return s[i+len("<Status>") : strings.Index(s, "</Status>")]
		}
		return ""
	}

	if got := status(); got != "" {
		t.Fatalf("a new bucket reports status %q, want an empty configuration", got)
	}
	tests := []struct {
		name   string
		body   string
		status int
		code   string
		after  string
	}{
		{"enable", vcfg("Enabled"), 200, "", "Enabled"},
		{"enable again", vcfg("Enabled"), 200, "", "Enabled"},
		{"suspend", vcfg("Suspended"), 200, "", "Suspended"},
		{"re-enable", vcfg("Enabled"), 200, "", "Enabled"},
		{"unknown status", vcfg("Paused"), 400, "MalformedXML", "Enabled"},
		{"empty status", vcfg(""), 400, "MalformedXML", "Enabled"},
		{"not xml", "Enabled", 400, "MalformedXML", "Enabled"},
		{"mfa delete", `<VersioningConfiguration><Status>Enabled</Status><MfaDelete>Enabled</MfaDelete></VersioningConfiguration>`, 501, "NotImplemented", "Enabled"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, b := e.do("PUT", "/vbucket?versioning", strings.NewReader(tt.body), nil)
			if resp.StatusCode != tt.status || (tt.code != "" && !strings.Contains(string(b), "<Code>"+tt.code+"</Code>")) {
				t.Errorf("PUT = %d %s, want %d %s", resp.StatusCode, b, tt.status, tt.code)
			}
			if got := status(); got != tt.after {
				t.Errorf("status afterwards = %q, want %q", got, tt.after)
			}
		})
	}

	t.Run("the path never goes back to unversioned", func(t *testing.T) {
		// There is no Status value for it; the only way to ask is an empty
		// configuration, which is a schema error.
		resp, _ := e.do("PUT", "/vbucket?versioning", strings.NewReader(vcfg("")), nil)
		if resp.StatusCode != 400 {
			t.Errorf("status %d", resp.StatusCode)
		}
		if got := status(); got == "" {
			t.Error("bucket became unversioned")
		}
	})
	t.Run("missing bucket", func(t *testing.T) {
		for _, m := range []string{"GET", "PUT"} {
			var body io.Reader
			if m == "PUT" {
				body = strings.NewReader(vcfg("Enabled"))
			}
			resp, b := e.do(m, "/nosuchbucket?versioning", body, nil)
			if resp.StatusCode != 404 || !strings.Contains(string(b), "NoSuchBucket") {
				t.Errorf("%s = %d %s", m, resp.StatusCode, b)
			}
		}
	})
	t.Run("other methods", func(t *testing.T) {
		resp, _ := e.do("DELETE", "/vbucket?versioning", nil, nil)
		if resp.StatusCode != 405 {
			t.Errorf("DELETE ?versioning = %d, want 405 (it must not delete the bucket)", resp.StatusCode)
		}
		if resp, _ := e.do("HEAD", "/vbucket", nil, nil); resp.StatusCode != 200 {
			t.Errorf("bucket gone after DELETE ?versioning: %d", resp.StatusCode)
		}
	})
	t.Run("authorization", func(t *testing.T) {
		resp, _ := e.doAs("nobody", "GET", "/vbucket?versioning", nil, nil)
		if resp.StatusCode != 403 {
			t.Errorf("GET as a user without grants = %d", resp.StatusCode)
		}
		resp, _ = e.doAs("nobody", "PUT", "/vbucket?versioning", strings.NewReader(vcfg("Suspended")), nil)
		if resp.StatusCode != 403 {
			t.Errorf("PUT as a user without grants = %d", resp.StatusCode)
		}
		if got := status(); got != "Enabled" {
			t.Errorf("a denied request changed the state to %q", got)
		}
		resp, _ = e.doAnon("PUT", "/vbucket?versioning", strings.NewReader(vcfg("Suspended")), nil)
		if resp.StatusCode != 403 {
			t.Errorf("anonymous PUT = %d", resp.StatusCode)
		}
	})
}

func enableVersioning(t *testing.T, e *testEnv, bucket, status string) {
	t.Helper()
	resp, b := e.do("PUT", "/"+bucket+"?versioning", strings.NewReader(vcfg(status)), nil)
	if resp.StatusCode != 200 {
		t.Fatalf("PUT ?versioning=%s: %d %s", status, resp.StatusCode, b)
	}
}

func TestVersionedObjectLifecycle(t *testing.T) {
	e := newEnv(t)
	e.mb("vobj")

	// While unversioned there are no version headers.
	r := e.put("/vobj/plain", "p", nil)
	if v := r.Header.Get("x-amz-version-id"); v != "" {
		t.Errorf("unversioned PUT sent x-amz-version-id %q", v)
	}
	if _, resp := e.get("/vobj/plain"); resp.Header.Get("x-amz-version-id") != "" {
		t.Errorf("unversioned GET sent x-amz-version-id %q", resp.Header.Get("x-amz-version-id"))
	}

	enableVersioning(t, e, "vobj", "Enabled")
	// The object that was there is now the null version.
	if body, resp := e.get("/vobj/plain"); body != "p" || resp.Header.Get("x-amz-version-id") != "null" {
		t.Errorf("pre-existing object: %q version %q", body, resp.Header.Get("x-amz-version-id"))
	}

	v1 := e.put("/vobj/k", "one", nil).Header.Get("x-amz-version-id")
	v2 := e.put("/vobj/k", "two", nil).Header.Get("x-amz-version-id")
	if len(v1) != 36 || len(v2) != 36 || v1 == v2 {
		t.Fatalf("version IDs %q %q", v1, v2)
	}
	if body, resp := e.get("/vobj/k"); body != "two" || resp.Header.Get("x-amz-version-id") != v2 {
		t.Errorf("latest = %q @ %q", body, resp.Header.Get("x-amz-version-id"))
	}
	if body, resp := e.get("/vobj/k?versionId=" + v1); body != "one" || resp.Header.Get("x-amz-version-id") != v1 {
		t.Errorf("v1 = %q @ %q", body, resp.Header.Get("x-amz-version-id"))
	}
	if resp, _ := e.do("HEAD", "/vobj/k?versionId="+v1, nil, nil); resp.StatusCode != 200 || resp.Header.Get("x-amz-version-id") != v1 {
		t.Errorf("HEAD v1 = %d @ %q", resp.StatusCode, resp.Header.Get("x-amz-version-id"))
	}

	// DELETE without a version adds a marker.
	resp, _ := e.do("DELETE", "/vobj/k", nil, nil)
	marker := resp.Header.Get("x-amz-version-id")
	if resp.StatusCode != 204 || resp.Header.Get("x-amz-delete-marker") != "true" || len(marker) != 36 {
		t.Fatalf("DELETE = %d marker=%q dm=%q", resp.StatusCode, marker, resp.Header.Get("x-amz-delete-marker"))
	}
	// GET/HEAD of the key: 404 identifying the marker.
	resp, body := e.do("GET", "/vobj/k", nil, nil)
	wantError(t, resp, body, 404, "NoSuchKey")
	if resp.Header.Get("x-amz-delete-marker") != "true" || resp.Header.Get("x-amz-version-id") != marker {
		t.Errorf("GET on a marker: dm=%q version=%q", resp.Header.Get("x-amz-delete-marker"), resp.Header.Get("x-amz-version-id"))
	}
	resp, _ = e.do("HEAD", "/vobj/k", nil, nil)
	if resp.StatusCode != 404 || resp.Header.Get("x-amz-delete-marker") != "true" {
		t.Errorf("HEAD on a marker = %d dm=%q", resp.StatusCode, resp.Header.Get("x-amz-delete-marker"))
	}
	// Naming the marker is "method not allowed".
	resp, body = e.do("GET", "/vobj/k?versionId="+marker, nil, nil)
	wantError(t, resp, body, 405, "MethodNotAllowed")
	if resp.Header.Get("x-amz-delete-marker") != "true" || resp.Header.Get("x-amz-version-id") != marker ||
		resp.Header.Get("Last-Modified") == "" {
		t.Errorf("GET marker@id headers: %v", resp.Header)
	}
	resp, _ = e.do("HEAD", "/vobj/k?versionId="+marker, nil, nil)
	if resp.StatusCode != 405 {
		t.Errorf("HEAD marker@id = %d", resp.StatusCode)
	}
	// Old versions are still there.
	if body, _ := e.get("/vobj/k?versionId=" + v2); body != "two" {
		t.Errorf("v2 = %q", body)
	}

	// Removing the marker undeletes.
	resp, _ = e.do("DELETE", "/vobj/k?versionId="+marker, nil, nil)
	if resp.StatusCode != 204 || resp.Header.Get("x-amz-delete-marker") != "true" || resp.Header.Get("x-amz-version-id") != marker {
		t.Errorf("DELETE marker@id = %d %v", resp.StatusCode, resp.Header)
	}
	if body, resp := e.get("/vobj/k"); body != "two" || resp.Header.Get("x-amz-version-id") != v2 {
		t.Errorf("after undelete: %q @ %q", body, resp.Header.Get("x-amz-version-id"))
	}
	// Removing a version permanently.
	resp, _ = e.do("DELETE", "/vobj/k?versionId="+v1, nil, nil)
	if resp.StatusCode != 204 || resp.Header.Get("x-amz-version-id") != v1 || resp.Header.Get("x-amz-delete-marker") != "" {
		t.Errorf("DELETE v1 = %d %v", resp.StatusCode, resp.Header)
	}
	resp, body = e.do("GET", "/vobj/k?versionId="+v1, nil, nil)
	wantError(t, resp, body, 404, "NoSuchVersion")
	// Removing it again is not an error.
	if resp, _ = e.do("DELETE", "/vobj/k?versionId="+v1, nil, nil); resp.StatusCode != 204 {
		t.Errorf("second DELETE v1 = %d", resp.StatusCode)
	}
	// Malformed IDs.
	resp, body = e.do("DELETE", "/vobj/k?versionId=bogus", nil, nil)
	wantError(t, resp, body, 400, "InvalidArgument")

	enableVersioning(t, e, "vobj", "Suspended")
	r = e.put("/vobj/s", "null-body", nil)
	if r.Header.Get("x-amz-version-id") != "null" {
		t.Errorf("suspended PUT version = %q, want null", r.Header.Get("x-amz-version-id"))
	}
	resp, _ = e.do("DELETE", "/vobj/s", nil, nil)
	if resp.Header.Get("x-amz-delete-marker") != "true" || resp.Header.Get("x-amz-version-id") != "null" {
		t.Errorf("suspended DELETE headers: %v", resp.Header)
	}
}

type listedVersions struct {
	Name                string `xml:"Name"`
	KeyMarker           string `xml:"KeyMarker"`
	VersionIDMarker     string `xml:"VersionIdMarker"`
	NextKeyMarker       string `xml:"NextKeyMarker"`
	NextVersionIDMarker string `xml:"NextVersionIdMarker"`
	MaxKeys             int    `xml:"MaxKeys"`
	IsTruncated         bool   `xml:"IsTruncated"`
	Versions            []struct {
		Key       string `xml:"Key"`
		VersionID string `xml:"VersionId"`
		IsLatest  bool   `xml:"IsLatest"`
		ETag      string `xml:"ETag"`
		Size      int64  `xml:"Size"`
	} `xml:"Version"`
	Markers []struct {
		Key       string `xml:"Key"`
		VersionID string `xml:"VersionId"`
		IsLatest  bool   `xml:"IsLatest"`
	} `xml:"DeleteMarker"`
	Prefixes []string `xml:"CommonPrefixes>Prefix"`
}

func TestListObjectVersionsAPI(t *testing.T) {
	e := newEnv(t)
	e.mb("vlistapi")
	enableVersioning(t, e, "vlistapi", "Enabled")
	a1 := e.put("/vlistapi/a", "a1", nil).Header.Get("x-amz-version-id")
	a2 := e.put("/vlistapi/a", "a22", nil).Header.Get("x-amz-version-id")
	resp, _ := e.do("DELETE", "/vlistapi/a", nil, nil)
	am := resp.Header.Get("x-amz-version-id")
	b1 := e.put("/vlistapi/dir/b", "b1", nil).Header.Get("x-amz-version-id")

	list := func(q string) (listedVersions, []byte) {
		t.Helper()
		resp, b := e.do("GET", "/vlistapi?versions"+q, nil, nil)
		if resp.StatusCode != 200 {
			t.Fatalf("GET ?versions%s = %d %s", q, resp.StatusCode, b)
		}
		var l listedVersions
		if err := xml.Unmarshal(b, &l); err != nil {
			t.Fatalf("bad XML: %v\n%s", err, b)
		}
		return l, b
	}
	l, raw := list("")
	if l.Name != "vlistapi" || l.IsTruncated || l.MaxKeys != 1000 {
		t.Errorf("header fields: %+v", l)
	}
	if len(l.Versions) != 3 || len(l.Markers) != 1 {
		t.Fatalf("%d versions, %d markers\n%s", len(l.Versions), len(l.Markers), raw)
	}
	// Document order: versions and markers interleaved, newest first.
	order := regexp.MustCompile(`<(Version|DeleteMarker)><Key>([^<]*)</Key><VersionId>([^<]*)</VersionId>`).FindAllStringSubmatch(string(raw), -1)
	var got []string
	for _, m := range order {
		got = append(got, m[1]+":"+m[2]+"@"+m[3])
	}
	want := []string{"DeleteMarker:a@" + am, "Version:a@" + a2, "Version:a@" + a1, "Version:dir/b@" + b1}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("order\n got %v\nwant %v", got, want)
	}
	if !l.Markers[0].IsLatest || l.Versions[0].IsLatest || !l.Versions[2].IsLatest {
		t.Errorf("IsLatest: marker %v, a2 %v, b1 %v", l.Markers[0].IsLatest, l.Versions[0].IsLatest, l.Versions[2].IsLatest)
	}
	if l.Versions[0].ETag != `"`+md5hex("a22")+`"` || l.Versions[0].Size != 3 {
		t.Errorf("version fields: %+v", l.Versions[0])
	}

	// Pagination with key-marker / version-id-marker, one entry per page.
	var walked []string
	km, vm := "", ""
	for pages := 0; pages < 10; pages++ {
		q := "&max-keys=1"
		if km != "" {
			q += "&key-marker=" + km + "&version-id-marker=" + vm
		}
		pg, _ := list(q)
		for _, v := range pg.Versions {
			walked = append(walked, "Version:"+v.Key+"@"+v.VersionID)
		}
		for _, m := range pg.Markers {
			walked = append(walked, "DeleteMarker:"+m.Key+"@"+m.VersionID)
		}
		if !pg.IsTruncated {
			break
		}
		if pg.NextKeyMarker == "" || pg.NextVersionIDMarker == "" {
			t.Fatalf("truncated page without markers: %+v", pg)
		}
		km, vm = pg.NextKeyMarker, pg.NextVersionIDMarker
	}
	sort.Strings(walked)
	sort.Strings(want)
	if strings.Join(walked, ",") != strings.Join(want, ",") {
		t.Errorf("paged walk\n got %v\nwant %v", walked, want)
	}

	t.Run("delimiter, prefix, encoding", func(t *testing.T) {
		l, _ := list("&delimiter=/")
		if len(l.Prefixes) != 1 || l.Prefixes[0] != "dir/" || len(l.Versions)+len(l.Markers) != 3 {
			t.Errorf("delimiter: %+v", l)
		}
		l, _ = list("&prefix=dir/")
		if len(l.Versions) != 1 || l.Versions[0].Key != "dir/b" {
			t.Errorf("prefix: %+v", l)
		}
		e.put("/vlistapi/sp%20ace", "x", nil)
		_, raw := list("&encoding-type=url&prefix=sp")
		if !strings.Contains(string(raw), "<Key>sp%20ace</Key>") {
			t.Errorf("url encoding: %s", raw)
		}
	})
	t.Run("bad parameters", func(t *testing.T) {
		resp, b := e.do("GET", "/vlistapi?versions&version-id-marker="+a1, nil, nil)
		wantError(t, resp, b, 400, "InvalidArgument")
		resp, b = e.do("GET", "/vlistapi?versions&key-marker=a&version-id-marker=bogus", nil, nil)
		wantError(t, resp, b, 400, "InvalidArgument")
		resp, b = e.do("GET", "/vlistapi?versions&max-keys=-1", nil, nil)
		wantError(t, resp, b, 400, "InvalidArgument")
		resp, b = e.do("GET", "/nosuchbucketx?versions", nil, nil)
		wantError(t, resp, b, 404, "NoSuchBucket")
		l, _ := list("&max-keys=0")
		if len(l.Versions)+len(l.Markers) != 0 || l.IsTruncated {
			t.Errorf("max-keys=0: %+v", l)
		}
	})
}

func TestMultiDeleteWithVersions(t *testing.T) {
	e := newEnv(t)
	e.mb("vmulti")
	enableVersioning(t, e, "vmulti", "Enabled")
	v1 := e.put("/vmulti/k", "one", nil).Header.Get("x-amz-version-id")
	e.put("/vmulti/k", "two", nil)
	e.put("/vmulti/other", "x", nil)

	body := `<Delete><Object><Key>k</Key><VersionId>` + v1 + `</VersionId></Object><Object><Key>other</Key></Object></Delete>`
	resp, b := e.do("POST", "/vmulti?delete", strings.NewReader(body), nil)
	if resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	var r deleteResult
	if err := xml.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Errors) != 0 || len(r.Deleted) != 2 {
		t.Fatalf("result = %+v", r)
	}
	if r.Deleted[0].Key != "k" || r.Deleted[0].VersionID != v1 || r.Deleted[0].DeleteMarker {
		t.Errorf("version removal entry = %+v", r.Deleted[0])
	}
	if r.Deleted[1].Key != "other" || !r.Deleted[1].DeleteMarker || len(r.Deleted[1].DeleteMarkerVersionID) != 36 {
		t.Errorf("marker entry = %+v", r.Deleted[1])
	}
	if body, _ := e.get("/vmulti/k"); body != "two" {
		t.Errorf("k = %q", body)
	}
	resp, _ = e.do("GET", "/vmulti/other", nil, nil)
	if resp.StatusCode != 404 || resp.Header.Get("x-amz-delete-marker") != "true" {
		t.Errorf("other = %d %v", resp.StatusCode, resp.Header)
	}
}

func TestVersionedMultipartHeader(t *testing.T) {
	e := newEnv(t)
	e.mb("vmpapi")
	enableVersioning(t, e, "vmpapi", "Enabled")
	id := e.initiate("vmpapi", "obj", nil)
	resp, _ := e.do("PUT", "/vmpapi/obj?partNumber=1&uploadId="+id, strings.NewReader("part-one"), nil)
	etag := resp.Header.Get("ETag")
	resp, b := e.do("POST", "/vmpapi/obj?uploadId="+id, strings.NewReader(completeXML([2]string{"1", etag})), nil)
	if resp.StatusCode != 200 || len(resp.Header.Get("x-amz-version-id")) != 36 {
		t.Fatalf("complete = %d version %q\n%s", resp.StatusCode, resp.Header.Get("x-amz-version-id"), b)
	}
}

func TestVersionActionsAreSeparatelyAuthorized(t *testing.T) {
	e := newEnv(t)
	e.mb("scoped")
	enableVersioning(t, e, "scoped", "Enabled")
	vid := e.put("/scoped/pub/obj", "data", nil).Header.Get("x-amz-version-id")

	// "scoped" may GetObject/PutObject/DeleteObject under pub/ but holds no
	// *Version actions and no bucket-level version permissions.
	if resp, _ := e.doAs("scoped", "GET", "/scoped/pub/obj", nil, nil); resp.StatusCode != 200 {
		t.Fatalf("plain GET = %d", resp.StatusCode)
	}
	if resp, _ := e.doAs("scoped", "GET", "/scoped/pub/obj?versionId="+vid, nil, nil); resp.StatusCode != 403 {
		t.Errorf("GET ?versionId = %d, want 403 (s3:GetObjectVersion)", resp.StatusCode)
	}
	if resp, _ := e.doAs("scoped", "DELETE", "/scoped/pub/obj?versionId="+vid, nil, nil); resp.StatusCode != 403 {
		t.Errorf("DELETE ?versionId = %d, want 403 (s3:DeleteObjectVersion)", resp.StatusCode)
	}
	if resp, _ := e.doAs("scoped", "GET", "/scoped?versions&prefix=pub/", nil, nil); resp.StatusCode != 403 {
		t.Errorf("GET ?versions = %d, want 403 (s3:ListBucketVersions)", resp.StatusCode)
	}
	if resp, _ := e.doAs("scoped", "PUT", "/scoped?versioning", strings.NewReader(vcfg("Suspended")), nil); resp.StatusCode != 403 {
		t.Errorf("PUT ?versioning = %d, want 403", resp.StatusCode)
	}
	// The denied delete did not happen.
	if body, _ := e.get("/scoped/pub/obj?versionId=" + vid); body != "data" {
		t.Errorf("version after a denied delete: %q", body)
	}
}
