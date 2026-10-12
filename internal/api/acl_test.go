package api

import (
	"encoding/xml"
	"strings"
	"testing"
)

const xsiNS = "http://www.w3.org/2001/XMLSchema-instance"

func aclXML(grants ...string) string {
	return `<AccessControlPolicy xmlns:xsi="` + xsiNS + `"><Owner><ID>nanoio</ID></Owner><AccessControlList>` +
		strings.Join(grants, "") + `</AccessControlList></AccessControlPolicy>`
}

func userGrant(id, perm string) string {
	return `<Grant><Grantee xsi:type="CanonicalUser"><ID>` + id + `</ID></Grantee><Permission>` + perm + `</Permission></Grant>`
}

func groupGrant(uri, perm string) string {
	return `<Grant><Grantee xsi:type="Group"><URI>` + uri + `</URI></Grantee><Permission>` + perm + `</Permission></Grant>`
}

const (
	allUsers  = "http://acs.amazonaws.com/groups/global/AllUsers"
	authUsers = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
)

func TestACLAuthorizationMatrix(t *testing.T) {
	e := newEnv(t)
	e.mb("aclbkt")
	for _, k := range []string{"o1", "o2", "star*", "starfish"} {
		e.put("/aclbkt/"+k, "body of "+k, nil)
	}
	setBucketACL := func(canned string) {
		t.Helper()
		if r, b := e.do("PUT", "/aclbkt?acl", nil, hdr{"x-amz-acl": canned}); r.StatusCode != 200 {
			t.Fatalf("PUT ?acl %s: %d %s", canned, r.StatusCode, b)
		}
	}
	setObjectACL := func(key, canned string) {
		t.Helper()
		if r, b := e.do("PUT", "/aclbkt/"+key+"?acl", nil, hdr{"x-amz-acl": canned}); r.StatusCode != 200 {
			t.Fatalf("PUT %s?acl %s: %d %s", key, canned, r.StatusCode, b)
		}
	}
	type tc struct {
		name, principal, method, path string
		hdr                           hdr
		body                          string
		want                          int
	}
	run := func(cases []tc) {
		t.Helper()
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				body := strings.NewReader(c.body)
				var status int
				switch c.principal {
				case "":
					r, _ := e.doAnon(c.method, c.path, body, c.hdr)
					status = r.StatusCode
				case "root":
					r, _ := e.do(c.method, c.path, body, c.hdr)
					status = r.StatusCode
				default:
					r, _ := e.doAs(c.principal, c.method, c.path, body, c.hdr)
					status = r.StatusCode
				}
				if status != c.want {
					t.Errorf("%s %s as %q = %d, want %d", c.method, c.path, c.principal, status, c.want)
				}
			})
		}
	}

	t.Run("private bucket", func(t *testing.T) {
		setBucketACL("private")
		run([]tc{
			{"anon list", "", "GET", "/aclbkt?list-type=2", nil, "", 403},
			{"anon GET", "", "GET", "/aclbkt/o1", nil, "", 403},
			{"authenticated user without policy lists", "nobody", "GET", "/aclbkt?list-type=2", nil, "", 403},
			{"anon read the ACL", "", "GET", "/aclbkt?acl", nil, "", 403},
		})
	})
	t.Run("public-read bucket lists but does not expose objects", func(t *testing.T) {
		setBucketACL("public-read")
		run([]tc{
			{"anon list", "", "GET", "/aclbkt?list-type=2", nil, "", 200},
			{"anon GET object (bucket READ is not object READ)", "", "GET", "/aclbkt/o1", nil, "", 403},
			{"anon PUT", "", "PUT", "/aclbkt/new", nil, "x", 403},
			{"anon DELETE", "", "DELETE", "/aclbkt/o1", nil, "", 403},
			{"nobody list", "nobody", "GET", "/aclbkt?list-type=2", nil, "", 200},
			{"anon read the ACL (READ_ACP not granted)", "", "GET", "/aclbkt?acl", nil, "", 403},
			{"anon rewrite the ACL", "", "PUT", "/aclbkt?acl", hdr{"x-amz-acl": "public-read-write"}, "", 403},
		})
	})
	t.Run("public-read-write bucket", func(t *testing.T) {
		setBucketACL("public-read-write")
		run([]tc{
			{"anon list", "", "GET", "/aclbkt?list-type=2", nil, "", 200},
			{"anon PUT", "", "PUT", "/aclbkt/anon-up", nil, "from anon", 200},
			{"anon DELETE", "", "DELETE", "/aclbkt/anon-up", nil, "", 204},
			{"anon GET existing (WRITE is not READ)", "", "GET", "/aclbkt/o1", nil, "", 403},
			{"anon rewrite the ACL (WRITE_ACP not granted)", "", "PUT", "/aclbkt?acl", hdr{"x-amz-acl": "private"}, "", 403},
		})
	})
	t.Run("authenticated-read bucket", func(t *testing.T) {
		setBucketACL("authenticated-read")
		run([]tc{
			{"anon list", "", "GET", "/aclbkt?list-type=2", nil, "", 403},
			{"nobody list", "nobody", "GET", "/aclbkt?list-type=2", nil, "", 200},
			{"reader list", "reader", "GET", "/aclbkt?list-type=2", nil, "", 200},
			{"nobody PUT", "nobody", "PUT", "/aclbkt/nb", nil, "x", 403},
		})
	})
	t.Run("object ACLs", func(t *testing.T) {
		setBucketACL("private")
		setObjectACL("o1", "public-read")
		setObjectACL("o2", "authenticated-read")
		run([]tc{
			{"anon GET public-read object", "", "GET", "/aclbkt/o1", nil, "", 200},
			{"anon HEAD public-read object", "", "HEAD", "/aclbkt/o1", nil, "", 200},
			{"anon GET another object", "", "GET", "/aclbkt/starfish", nil, "", 403},
			{"anon GET authenticated-read object", "", "GET", "/aclbkt/o2", nil, "", 403},
			{"nobody GET authenticated-read object", "nobody", "GET", "/aclbkt/o2", nil, "", 200},
			{"anon read object ACL", "", "GET", "/aclbkt/o1?acl", nil, "", 403},
			{"anon change object ACL", "", "PUT", "/aclbkt/o1?acl", hdr{"x-amz-acl": "private"}, "", 403},
			{"anon DELETE public-read object", "", "DELETE", "/aclbkt/o1", nil, "", 403},
		})
		// A key with glob characters is matched literally.
		setObjectACL("star*", "public-read")
		run([]tc{
			{"anon GET the starred key", "", "GET", "/aclbkt/star%2A", nil, "", 200},
			{"anon GET a key the glob would match", "", "GET", "/aclbkt/starfish", nil, "", 403},
		})
	})
	t.Run("explicit grants", func(t *testing.T) {
		setBucketACL("private")
		put := func(path, body string) {
			t.Helper()
			if r, b := e.do("PUT", path, strings.NewReader(body), nil); r.StatusCode != 200 {
				t.Fatalf("PUT %s: %d %s", path, r.StatusCode, b)
			}
		}
		put("/aclbkt/o1?acl", aclXML(userGrant("nobody", "READ"), userGrant("writer", "WRITE_ACP")))
		run([]tc{
			{"granted user reads", "nobody", "GET", "/aclbkt/o1", nil, "", 200},
			{"ungranted user", "scoped", "GET", "/aclbkt/o1", nil, "", 403},
			{"anonymous", "", "GET", "/aclbkt/o1", nil, "", 403},
			{"WRITE_ACP user rewrites the object ACL", "writer", "PUT", "/aclbkt/o1?acl", hdr{"x-amz-acl": "public-read"}, "", 200},
			{"…and now anyone reads", "", "GET", "/aclbkt/o1", nil, "", 200},
			{"WRITE_ACP does not allow reading the ACL", "writer", "GET", "/aclbkt/o1?acl", nil, "", 403},
		})
	})
}

func TestACLXMLRoundTripAndValidation(t *testing.T) {
	e := newEnv(t)
	e.mb("aclxml")
	e.put("/aclxml/k", "v", nil)
	// Default ACL: the owner's FULL_CONTROL only.
	r, b := e.do("GET", "/aclxml?acl", nil, nil)
	if r.StatusCode != 200 {
		t.Fatalf("%d %s", r.StatusCode, b)
	}
	var def struct {
		Owner struct{ ID string }
		Grant []struct {
			Permission string
			Grantee    struct {
				ID  string
				URI string
			}
		} `xml:"AccessControlList>Grant"`
	}
	if err := xml.Unmarshal(b, &def); err != nil || len(def.Grant) != 1 || def.Grant[0].Permission != "FULL_CONTROL" || def.Owner.ID != "nanoio" {
		t.Fatalf("default ACL = %+v (%v)\n%s", def, err, b)
	}
	// Set grants by XML and read them back.
	body := aclXML(userGrant("nobody", "READ"), groupGrant(allUsers, "READ_ACP"), groupGrant(authUsers, "WRITE"))
	if r, b := e.do("PUT", "/aclxml?acl", strings.NewReader(body), nil); r.StatusCode != 200 {
		t.Fatalf("PUT: %d %s", r.StatusCode, b)
	}
	_, b = e.do("GET", "/aclxml?acl", nil, nil)
	for _, want := range []string{"<ID>nobody</ID>", "<URI>" + allUsers + "</URI>", "<URI>" + authUsers + "</URI>",
		"<Permission>READ_ACP</Permission>", "<Permission>WRITE</Permission>", `xsi:type="Group"`, `xsi:type="CanonicalUser"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("GET ?acl lacks %q:\n%s", want, b)
		}
	}
	// Grant headers work too.
	if r, b := e.do("PUT", "/aclxml/k?acl", nil, hdr{"x-amz-grant-read": `id="nobody", uri="` + authUsers + `"`, "x-amz-grant-full-control": `id="reader"`}); r.StatusCode != 200 {
		t.Fatalf("grant headers: %d %s", r.StatusCode, b)
	}
	_, b = e.do("GET", "/aclxml/k?acl", nil, nil)
	if !strings.Contains(string(b), "<ID>reader</ID>") || !strings.Contains(string(b), "FULL_CONTROL") {
		t.Errorf("object ACL: %s", b)
	}
	// Setting private clears the grants.
	e.do("PUT", "/aclxml/k?acl", nil, hdr{"x-amz-acl": "private"})
	_, b = e.do("GET", "/aclxml/k?acl", nil, nil)
	if strings.Count(string(b), "<Grant>") != 1 {
		t.Errorf("private ACL still has grants:\n%s", b)
	}

	bad := []struct {
		name, path, body string
		h                hdr
		status           int
	}{
		{"not xml", "/aclxml?acl", "nope", nil, 400},
		{"unknown permission", "/aclxml?acl", aclXML(userGrant("nobody", "SUPER")), nil, 400},
		{"unknown group", "/aclxml?acl", aclXML(groupGrant("http://example.com/g", "READ")), nil, 400},
		{"email grantee", "/aclxml?acl", aclXML(`<Grant><Grantee xsi:type="AmazonCustomerByEmail"><EmailAddress>a@b.c</EmailAddress></Grantee><Permission>READ</Permission></Grant>`), nil, 501},
		{"canned and body", "/aclxml?acl", aclXML(), hdr{"x-amz-acl": "private"}, 400},
		{"canned and grant header", "/aclxml?acl", "", hdr{"x-amz-acl": "private", "x-amz-grant-read": `id="x"`}, 400},
		{"unsupported canned", "/aclxml?acl", "", hdr{"x-amz-acl": "bucket-owner-read"}, 400},
		{"nothing at all", "/aclxml?acl", "", nil, 400},
		{"object: unknown canned", "/aclxml/k?acl", "", hdr{"x-amz-acl": "wide-open"}, 400},
		{"object ACL on a missing key", "/aclxml/ghost?acl", "", hdr{"x-amz-acl": "public-read"}, 404},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			r, b := e.do("PUT", c.path, strings.NewReader(c.body), c.h)
			if r.StatusCode != c.status {
				t.Errorf("status %d, want %d: %s", r.StatusCode, c.status, b)
			}
		})
	}
	// Reserved headers cannot smuggle an ACL in.
	r, b = e.do("PUT", "/aclxml/smuggled", strings.NewReader("x"), hdr{"x-nanoio-internal-acl": `{"grants":[{"group":"` + allUsers + `","perm":"READ"}]}`})
	wantError(t, r, b, 400, "InvalidArgument")
}

func TestACLOnWritesCopiesVersionsAndMultipart(t *testing.T) {
	e := newEnv(t)
	e.mb("aclwrite")
	// x-amz-acl on PUT sets the object's ACL (and needs s3:PutObjectAcl).
	e.put("/aclwrite/pub", "public", hdr{"x-amz-acl": "public-read"})
	if r, _ := e.doAnon("GET", "/aclwrite/pub", nil, nil); r.StatusCode != 200 {
		t.Errorf("anon GET of an object PUT with public-read = %d", r.StatusCode)
	}
	// A principal without s3:PutObjectAcl cannot attach one (writer has PutObject only; scoped none here).
	if r, _ := e.doAs("writer", "PUT", "/aclwrite/w", strings.NewReader("x"), hdr{"x-amz-acl": "public-read"}); r.StatusCode != 403 {
		t.Errorf("PUT with x-amz-acl without s3:PutObjectAcl = %d", r.StatusCode)
	}
	if r, _ := e.doAs("writer", "PUT", "/aclwrite/w", strings.NewReader("x"), nil); r.StatusCode != 200 {
		t.Errorf("plain PUT by writer = %d", r.StatusCode)
	}
	// A copy does not carry the ACL; the request's header sets one.
	if r, b := e.copyObj("/aclwrite/copy", "/aclwrite/pub", nil); r.StatusCode != 200 {
		t.Fatalf("copy: %d %s", r.StatusCode, b)
	}
	if r, _ := e.doAnon("GET", "/aclwrite/copy", nil, nil); r.StatusCode != 403 {
		t.Errorf("the copy inherited the source's ACL: %d", r.StatusCode)
	}
	if r, b := e.copyObj("/aclwrite/copy2", "/aclwrite/pub", hdr{"x-amz-acl": "public-read"}); r.StatusCode != 200 {
		t.Fatalf("copy with ACL: %d %s", r.StatusCode, b)
	}
	if r, _ := e.doAnon("GET", "/aclwrite/copy2", nil, nil); r.StatusCode != 200 {
		t.Errorf("copy with x-amz-acl not public: %d", r.StatusCode)
	}
	// Multipart: the initiate request carries it.
	_, b := e.do("POST", "/aclwrite/mp?uploads", nil, hdr{"x-amz-acl": "public-read"})
	var init initiateMultipartUploadResult
	xml.Unmarshal(b, &init)
	pr, _ := e.do("PUT", "/aclwrite/mp?partNumber=1&uploadId="+init.UploadID, strings.NewReader("only part"), nil)
	done := `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>` + pr.Header.Get("ETag") + `</ETag></Part></CompleteMultipartUpload>`
	if r, b := e.do("POST", "/aclwrite/mp?uploadId="+init.UploadID, strings.NewReader(done), nil); r.StatusCode != 200 {
		t.Fatalf("complete: %d %s", r.StatusCode, b)
	}
	if r, _ := e.doAnon("GET", "/aclwrite/mp", nil, nil); r.StatusCode != 200 {
		t.Errorf("multipart object with x-amz-acl not public: %d", r.StatusCode)
	}
	// CreateBucket with an ACL header.
	if r, b := e.do("PUT", "/aclnewbkt", nil, hdr{"x-amz-acl": "public-read"}); r.StatusCode != 200 {
		t.Fatalf("create bucket with ACL: %d %s", r.StatusCode, b)
	}
	if r, _ := e.doAnon("GET", "/aclnewbkt?list-type=2", nil, nil); r.StatusCode != 200 {
		t.Errorf("anon list of a public-read bucket created with the header = %d", r.StatusCode)
	}
	// Deleting the bucket removes its ACL; a new bucket of that name is private.
	e.do("DELETE", "/aclnewbkt", nil, nil)
	e.mb("aclnewbkt")
	if r, _ := e.doAnon("GET", "/aclnewbkt?list-type=2", nil, nil); r.StatusCode != 403 {
		t.Errorf("a recreated bucket inherited the old ACL: %d", r.StatusCode)
	}
	// Versions: each has its own ACL.
	e.do("PUT", "/aclwrite?versioning", strings.NewReader(`<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`), nil)
	r1 := e.put("/aclwrite/ver", "one", nil)
	e.put("/aclwrite/ver", "two", nil)
	v1 := r1.Header.Get("x-amz-version-id")
	if r, b := e.do("PUT", "/aclwrite/ver?acl&versionId="+v1, nil, hdr{"x-amz-acl": "public-read"}); r.StatusCode != 200 {
		t.Fatalf("version ACL: %d %s", r.StatusCode, b)
	}
	if r, _ := e.doAnon("GET", "/aclwrite/ver?versionId="+v1, nil, nil); r.StatusCode != 200 {
		t.Errorf("anon GET of the public version = %d", r.StatusCode)
	}
	if r, _ := e.doAnon("GET", "/aclwrite/ver", nil, nil); r.StatusCode != 403 {
		t.Errorf("anon GET of the latest (private) version = %d", r.StatusCode)
	}
	// An ACL change keeps the data and ETag.
	g1, _ := e.get("/aclwrite/pub")
	if g1 != "public" {
		t.Errorf("body after ACL changes = %q", g1)
	}
}

func TestACLOfEncryptedObjectSurvivesAndStaysPrivateFromMetadata(t *testing.T) {
	e := sseEnv(t, "fs")
	e.mb("aclenc")
	e.put("/aclenc/o", "secret", hdr{"x-amz-server-side-encryption": "AES256"})
	if r, b := e.do("PUT", "/aclenc/o?acl", nil, hdr{"x-amz-acl": "public-read"}); r.StatusCode != 200 {
		t.Fatalf("%d %s", r.StatusCode, b)
	}
	// Public reader gets plaintext: SSE-S3 is transparent to authorised reads.
	if r, b := e.doAnon("GET", "/aclenc/o", nil, nil); r.StatusCode != 200 || string(b) != "secret" {
		t.Errorf("anon GET = %d %q", r.StatusCode, b)
	}
	// The ACL change did not disturb the encryption metadata.
	if got, _ := e.get("/aclenc/o"); got != "secret" {
		t.Errorf("owner GET = %q", got)
	}
	_, info := e.stored("aclenc", "o")
	if info.UserDefined[aclKey] == "" {
		t.Error("ACL not stored in object metadata")
	}
}

// A grantee ID is data, not a pattern: "*" must not become "everyone".
func TestACLGranteeIDIsNotAPattern(t *testing.T) {
	e := newEnv(t)
	e.mb("aclglob")
	e.put("/aclglob/o", "v", nil)
	for _, id := range []string{"*", "a*", "?", "x/y", "a:b"} {
		r, b := e.do("PUT", "/aclglob/o?acl", strings.NewReader(aclXML(userGrant(id, "READ"))), nil)
		if r.StatusCode != 400 {
			t.Errorf("grantee %q = %d %s", id, r.StatusCode, b)
		}
	}
	if r, _ := e.doAnon("GET", "/aclglob/o", nil, nil); r.StatusCode != 403 {
		t.Errorf("anonymous GET = %d", r.StatusCode)
	}
}
