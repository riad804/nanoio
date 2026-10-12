package api

import (
	"encoding/xml"
	"fmt"
	"strings"
	"testing"
)

func taggingXML(kv ...string) string {
	var b strings.Builder
	b.WriteString("<Tagging><TagSet>")
	for i := 0; i+1 < len(kv); i += 2 {
		fmt.Fprintf(&b, "<Tag><Key>%s</Key><Value>%s</Value></Tag>", kv[i], kv[i+1])
	}
	b.WriteString("</TagSet></Tagging>")
	return b.String()
}

func parseTags(t *testing.T, body []byte) map[string]string {
	t.Helper()
	var out struct {
		Tags []struct{ Key, Value string } `xml:"TagSet>Tag"`
	}
	if err := xml.Unmarshal(body, &out); err != nil {
		t.Fatalf("%v\n%s", err, body)
	}
	m := map[string]string{}
	for _, tg := range out.Tags {
		m[tg.Key] = tg.Value
	}
	return m
}

func TestObjectTaggingLifecycle(t *testing.T) {
	e := newEnv(t)
	e.mb("tagbkt")
	// Header on PUT.
	r := e.put("/tagbkt/o", "tagged body", hdr{"x-amz-tagging": "env=prod&team=a%20b"})
	if r.StatusCode != 200 {
		t.Fatal(r.StatusCode)
	}
	gr, _ := e.do("HEAD", "/tagbkt/o", nil, nil)
	if gr.Header.Get("x-amz-tagging-count") != "2" {
		t.Errorf("x-amz-tagging-count = %q", gr.Header.Get("x-amz-tagging-count"))
	}
	resp, b := e.do("GET", "/tagbkt/o?tagging", nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	if got := parseTags(t, b); got["env"] != "prod" || got["team"] != "a b" || len(got) != 2 {
		t.Errorf("tags = %v", got)
	}
	// Replace.
	if r, b := e.do("PUT", "/tagbkt/o?tagging", strings.NewReader(taggingXML("k1", "v1")), nil); r.StatusCode != 200 {
		t.Fatalf("%d %s", r.StatusCode, b)
	}
	_, b = e.do("GET", "/tagbkt/o?tagging", nil, nil)
	if got := parseTags(t, b); len(got) != 1 || got["k1"] != "v1" {
		t.Errorf("after replace = %v", got)
	}
	// Body and ETag are untouched.
	if got, hr := e.get("/tagbkt/o"); got != "tagged body" || hr.Header.Get("x-amz-tagging-count") != "1" {
		t.Errorf("GET: %q count=%q", got, hr.Header.Get("x-amz-tagging-count"))
	}
	// Delete.
	if r, _ := e.do("DELETE", "/tagbkt/o?tagging", nil, nil); r.StatusCode != 204 {
		t.Errorf("DELETE ?tagging = %d", r.StatusCode)
	}
	hr, _ := e.do("HEAD", "/tagbkt/o", nil, nil)
	if hr.Header.Get("x-amz-tagging-count") != "" {
		t.Errorf("count after delete = %q", hr.Header.Get("x-amz-tagging-count"))
	}
	_, b = e.do("GET", "/tagbkt/o?tagging", nil, nil)
	if got := parseTags(t, b); len(got) != 0 {
		t.Errorf("tags after delete = %v", got)
	}
	// Missing object.
	r2, b := e.do("GET", "/tagbkt/missing?tagging", nil, nil)
	wantError(t, r2, b, 404, "NoSuchKey")
}

func TestObjectTagValidation(t *testing.T) {
	e := newEnv(t)
	e.mb("tagval")
	e.put("/tagval/o", "x", nil)
	many := make([]string, 0, 22)
	for i := 0; i < 11; i++ {
		many = append(many, fmt.Sprintf("k%d", i), "v")
	}
	bad := map[string]string{
		"11 tags":         taggingXML(many...),
		"duplicate keys":  taggingXML("a", "1", "a", "2"),
		"aws: prefix":     taggingXML("aws:thing", "1"),
		"empty key":       taggingXML("", "1"),
		"key too long":    taggingXML(strings.Repeat("k", 129), "1"),
		"value too long":  taggingXML("k", strings.Repeat("v", 257)),
		"bad key chars":   taggingXML("a&lt;b", "1"),
		"bad value chars": taggingXML("k", "a#b"),
		"not xml":         "nope",
	}
	for name, doc := range bad {
		t.Run(name, func(t *testing.T) {
			r, b := e.do("PUT", "/tagval/o?tagging", strings.NewReader(doc), nil)
			if r.StatusCode != 400 {
				t.Errorf("status %d: %s", r.StatusCode, b)
			}
		})
	}
	// 10 is the limit and 128/256 are allowed.
	ok := make([]string, 0, 20)
	for i := 0; i < 10; i++ {
		ok = append(ok, fmt.Sprintf("k%d", i), "v")
	}
	if r, b := e.do("PUT", "/tagval/o?tagging", strings.NewReader(taggingXML(ok...)), nil); r.StatusCode != 200 {
		t.Errorf("10 tags: %d %s", r.StatusCode, b)
	}
	if r, b := e.do("PUT", "/tagval/o?tagging", strings.NewReader(taggingXML(strings.Repeat("k", 128), strings.Repeat("v", 256))), nil); r.StatusCode != 200 {
		t.Errorf("max length: %d %s", r.StatusCode, b)
	}
	// Header forms.
	for h, want := range map[string]int{"a=1&a=2": 400, "aws:x=1": 400, "k=" + strings.Repeat("v", 257): 400, "a=1;b=2": 400, "ok=1&also=2": 200} {
		r, _ := e.do("PUT", "/tagval/h", strings.NewReader("x"), hdr{"x-amz-tagging": h})
		if r.StatusCode != want {
			t.Errorf("x-amz-tagging %q = %d, want %d", h, r.StatusCode, want)
		}
	}
}

func TestTaggingFollowsVersionsCopiesAndMultipart(t *testing.T) {
	e := newEnv(t)
	e.mb("tagver")
	e.do("PUT", "/tagver?versioning", strings.NewReader(`<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`), nil)
	r1 := e.put("/tagver/o", "one", hdr{"x-amz-tagging": "v=1"})
	r2 := e.put("/tagver/o", "two", hdr{"x-amz-tagging": "v=2"})
	v1, v2 := r1.Header.Get("x-amz-version-id"), r2.Header.Get("x-amz-version-id")
	for vid, want := range map[string]string{v1: "1", v2: "2"} {
		_, b := e.do("GET", "/tagver/o?tagging&versionId="+vid, nil, nil)
		if got := parseTags(t, b); got["v"] != want {
			t.Errorf("version %s tags = %v", vid, got)
		}
	}
	// Tag one version; the other is untouched, no new version appears.
	pr, b := e.do("PUT", "/tagver/o?tagging&versionId="+v1, strings.NewReader(taggingXML("v", "1b")), nil)
	if pr.StatusCode != 200 || pr.Header.Get("x-amz-version-id") != v1 {
		t.Fatalf("%d %v %s", pr.StatusCode, pr.Header, b)
	}
	_, b = e.do("GET", "/tagver/o?tagging", nil, nil)
	if got := parseTags(t, b); got["v"] != "2" {
		t.Errorf("latest tags = %v", got)
	}
	_, vb := e.do("GET", "/tagver?versions", nil, nil)
	if n := strings.Count(string(vb), "<Version>"); n != 2 {
		t.Errorf("versions = %d", n)
	}
	// Copy: COPY (default) keeps tags, REPLACE takes the header (none = none).
	if r, b := e.copyObj("/tagver/c1", "/tagver/o", nil); r.StatusCode != 200 {
		t.Fatalf("%d %s", r.StatusCode, b)
	}
	_, b = e.do("GET", "/tagver/c1?tagging", nil, nil)
	if got := parseTags(t, b); got["v"] != "2" {
		t.Errorf("copied tags = %v", got)
	}
	if r, b := e.copyObj("/tagver/c2", "/tagver/o", hdr{"x-amz-tagging-directive": "REPLACE", "x-amz-tagging": "n=new"}); r.StatusCode != 200 {
		t.Fatalf("%d %s", r.StatusCode, b)
	}
	_, b = e.do("GET", "/tagver/c2?tagging", nil, nil)
	if got := parseTags(t, b); len(got) != 1 || got["n"] != "new" {
		t.Errorf("replaced tags = %v", got)
	}
	if r, b := e.copyObj("/tagver/c3", "/tagver/o", hdr{"x-amz-tagging-directive": "REPLACE"}); r.StatusCode != 200 {
		t.Fatalf("%d %s", r.StatusCode, b)
	}
	_, b = e.do("GET", "/tagver/c3?tagging", nil, nil)
	if got := parseTags(t, b); len(got) != 0 {
		t.Errorf("REPLACE without a header kept tags: %v", got)
	}
	// Multipart carries the initiate request's tags.
	_, b = e.do("POST", "/tagver/mp?uploads", nil, hdr{"x-amz-tagging": "from=initiate"})
	var init initiateMultipartUploadResult
	xml.Unmarshal(b, &init)
	pp, _ := e.do("PUT", "/tagver/mp?partNumber=1&uploadId="+init.UploadID, strings.NewReader("part"), nil)
	done := `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>` + pp.Header.Get("ETag") + `</ETag></Part></CompleteMultipartUpload>`
	if r, b := e.do("POST", "/tagver/mp?uploadId="+init.UploadID, strings.NewReader(done), nil); r.StatusCode != 200 {
		t.Fatalf("%d %s", r.StatusCode, b)
	}
	_, b = e.do("GET", "/tagver/mp?tagging", nil, nil)
	if got := parseTags(t, b); got["from"] != "initiate" {
		t.Errorf("multipart tags = %v", got)
	}
}

func TestBucketTagging(t *testing.T) {
	e := newEnv(t)
	e.mb("tagbucket")
	r, b := e.do("GET", "/tagbucket?tagging", nil, nil)
	wantError(t, r, b, 404, "NoSuchTagSet")
	if r, b := e.do("PUT", "/tagbucket?tagging", strings.NewReader(taggingXML("owner", "team-x", "cost", "42")), nil); r.StatusCode != 204 {
		t.Fatalf("%d %s", r.StatusCode, b)
	}
	_, b = e.do("GET", "/tagbucket?tagging", nil, nil)
	if got := parseTags(t, b); got["owner"] != "team-x" || got["cost"] != "42" {
		t.Errorf("tags = %v", got)
	}
	// Up to 50.
	many := make([]string, 0, 100)
	for i := 0; i < 51; i++ {
		many = append(many, fmt.Sprintf("k%d", i), "v")
	}
	if r, _ := e.do("PUT", "/tagbucket?tagging", strings.NewReader(taggingXML(many...)), nil); r.StatusCode != 400 {
		t.Errorf("51 tags = %d", r.StatusCode)
	}
	if r, _ := e.do("PUT", "/tagbucket?tagging", strings.NewReader(taggingXML()), nil); r.StatusCode != 400 {
		t.Errorf("empty tag set = %d", r.StatusCode)
	}
	if r, _ := e.doAs("nobody", "GET", "/tagbucket?tagging", nil, nil); r.StatusCode != 403 {
		t.Errorf("nobody GET = %d", r.StatusCode)
	}
	if r, _ := e.do("DELETE", "/tagbucket?tagging", nil, nil); r.StatusCode != 204 {
		t.Errorf("DELETE = %d", r.StatusCode)
	}
	r, b = e.do("GET", "/tagbucket?tagging", nil, nil)
	wantError(t, r, b, 404, "NoSuchTagSet")
	// Tags go when the bucket does.
	e.do("PUT", "/tagbucket?tagging", strings.NewReader(taggingXML("a", "b")), nil)
	e.do("DELETE", "/tagbucket", nil, nil)
	e.mb("tagbucket")
	r, b = e.do("GET", "/tagbucket?tagging", nil, nil)
	wantError(t, r, b, 404, "NoSuchTagSet")
}

// Tags as policy condition keys: s3:ExistingObjectTag/<key> on reads and
// deletes, s3:RequestObjectTag/<key> on writes.
func TestTagConditionKeysInPolicies(t *testing.T) {
	e := newEnv(t)
	e.mb("tagpol")
	e.put("/tagpol/public-doc", "p", hdr{"x-amz-tagging": "classification=public"})
	e.put("/tagpol/secret-doc", "s", hdr{"x-amz-tagging": "classification=secret"})
	e.put("/tagpol/untagged", "u", nil)
	pol := `{"Version":"2012-10-17","Statement":[
	  {"Sid":"read-public","Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::tagpol/*",
	   "Condition":{"StringEquals":{"s3:ExistingObjectTag/classification":"public"}}},
	  {"Sid":"nobody-writes-only-draft","Effect":"Allow","Principal":{"AWS":"nobody"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::tagpol/*",
	   "Condition":{"StringEquals":{"s3:RequestObjectTag/status":"draft"}}},
	  {"Sid":"nobody-retags-draft","Effect":"Allow","Principal":{"AWS":"nobody"},"Action":"s3:PutObjectTagging","Resource":"arn:aws:s3:::tagpol/*",
	   "Condition":{"StringEquals":{"s3:RequestObjectTag/status":"draft"}}},
	  {"Sid":"never-delete-secret","Effect":"Deny","Principal":"*","Action":"s3:DeleteObject","Resource":"arn:aws:s3:::tagpol/*",
	   "Condition":{"StringEquals":{"s3:ExistingObjectTag/classification":"secret"}}},
	  {"Sid":"nobody-deletes","Effect":"Allow","Principal":{"AWS":"nobody"},"Action":"s3:DeleteObject","Resource":"arn:aws:s3:::tagpol/*"}
	]}`
	if r, b := e.do("PUT", "/tagpol?policy", strings.NewReader(pol), nil); r.StatusCode != 204 {
		t.Fatalf("%d %s", r.StatusCode, b)
	}
	cases := []struct {
		name, who, method, path string
		h                       hdr
		body                    string
		want                    int
	}{
		{"anon GET public-tagged", "", "GET", "/tagpol/public-doc", nil, "", 200},
		{"anon GET secret-tagged", "", "GET", "/tagpol/secret-doc", nil, "", 403},
		{"anon GET untagged", "", "GET", "/tagpol/untagged", nil, "", 403},
		{"anon GET missing", "", "GET", "/tagpol/nothing", nil, "", 403},
		{"nobody GET public-tagged", "nobody", "GET", "/tagpol/public-doc", nil, "", 200},
		{"nobody PUT without tag", "nobody", "PUT", "/tagpol/n1", nil, "x", 403},
		{"nobody PUT status=draft", "nobody", "PUT", "/tagpol/n2", hdr{"x-amz-tagging": "status=draft"}, "x", 200},
		{"nobody PUT status=final", "nobody", "PUT", "/tagpol/n3", hdr{"x-amz-tagging": "status=final"}, "x", 403},
		{"nobody retag to draft", "nobody", "PUT", "/tagpol/n2?tagging", nil, taggingXML("status", "draft"), 200},
		{"nobody retag to final", "nobody", "PUT", "/tagpol/n2?tagging", nil, taggingXML("status", "final"), 403},
		{"nobody DELETE untagged (Allow)", "nobody", "DELETE", "/tagpol/untagged", nil, "", 204},
		{"nobody DELETE secret-tagged (Deny on existing tag)", "nobody", "DELETE", "/tagpol/secret-doc", nil, "", 403},
		{"root DELETE secret-tagged", "root", "DELETE", "/tagpol/secret-doc", nil, "", 204},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var status int
			switch c.who {
			case "":
				r, _ := e.doAnon(c.method, c.path, strings.NewReader(c.body), c.h)
				status = r.StatusCode
			case "root":
				r, _ := e.do(c.method, c.path, strings.NewReader(c.body), c.h)
				status = r.StatusCode
			default:
				r, _ := e.doAs(c.who, c.method, c.path, strings.NewReader(c.body), c.h)
				status = r.StatusCode
			}
			if status != c.want {
				t.Errorf("%s %s = %d, want %d", c.method, c.path, status, c.want)
			}
		})
	}
}

func TestTaggingIsNotLeakedByMetadata(t *testing.T) {
	e := newEnv(t)
	e.mb("tagleak")
	e.put("/tagleak/o", "x", hdr{"x-amz-tagging": "a=b"})
	r, _ := e.do("GET", "/tagleak/o", nil, nil)
	for k := range r.Header {
		if strings.HasPrefix(strings.ToLower(k), "x-nanoio-internal") {
			t.Errorf("internal header %s leaked", k)
		}
	}
}
