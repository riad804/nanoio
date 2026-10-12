package api

import (
	"encoding/xml"
	"fmt"
	"strings"
	"testing"
)

func TestStorageClassOnFSAcceptsOnlyStandard(t *testing.T) {
	e := newEnv(t)
	e.mb("classfs")
	for class, want := range map[string]int{"": 200, "STANDARD": 200, "REDUCED_REDUNDANCY": 400, "GLACIER": 400} {
		h := hdr(nil)
		if class != "" {
			h = hdr{"x-amz-storage-class": class}
		}
		r, b := e.do("PUT", "/classfs/"+strings.ToLower(class)+"k", strings.NewReader("x"), h)
		if r.StatusCode != want {
			t.Errorf("PUT class %q = %d, want %d (%s)", class, r.StatusCode, want, b)
		}
		if want == 400 {
			wantError(t, r, b, 400, "InvalidStorageClass")
		}
	}
	r, _ := e.do("HEAD", "/classfs/standardk", nil, nil)
	if r.Header.Get("x-amz-storage-class") != "" {
		t.Errorf("STANDARD object reports a class header: %q", r.Header.Get("x-amz-storage-class"))
	}
}

func TestStorageClassOnErasureCodedBackend(t *testing.T) {
	e := sseEnv(t, "xl")
	e.mb("classxl")
	body := strings.Repeat("c", 150_000)
	for class, wantHdr := range map[string]string{"STANDARD": "", "REDUCED_REDUNDANCY": "REDUCED_REDUNDANCY", "LIMITED": "LIMITED"} {
		key := "obj-" + strings.ToLower(class)
		r, b := e.do("PUT", "/classxl/"+key, strings.NewReader(body), hdr{"x-amz-storage-class": class})
		if r.StatusCode != 200 {
			t.Fatalf("PUT %s: %d %s", class, r.StatusCode, b)
		}
		for _, method := range []string{"GET", "HEAD"} {
			gr, gb := e.do(method, "/classxl/"+key, nil, nil)
			if gr.StatusCode != 200 || gr.Header.Get("x-amz-storage-class") != wantHdr {
				t.Errorf("%s %s: %d class header %q, want %q", method, class, gr.StatusCode, gr.Header.Get("x-amz-storage-class"), wantHdr)
			}
			if method == "GET" && string(gb) != body {
				t.Errorf("%s body differs", class)
			}
		}
		_, info := e.stored("classxl", key)
		if info.StorageClass != canonicalClass(class) {
			t.Errorf("%s stored class %q", class, info.StorageClass)
		}
	}
	// Unknown classes are refused and leave nothing.
	r, b := e.do("PUT", "/classxl/bad", strings.NewReader("x"), hdr{"x-amz-storage-class": "GLACIER"})
	wantError(t, r, b, 400, "InvalidStorageClass")
	if hr, _ := e.do("HEAD", "/classxl/bad", nil, nil); hr.StatusCode != 404 {
		t.Error("a refused PUT left an object")
	}
	// Listings report each object's class.
	_, lb := e.do("GET", "/classxl?list-type=2", nil, nil)
	for key, class := range map[string]string{"obj-standard": "STANDARD", "obj-reduced_redundancy": "REDUCED_REDUNDANCY", "obj-limited": "LIMITED"} {
		i := strings.Index(string(lb), "<Key>"+key+"</Key>")
		if i < 0 {
			t.Fatalf("listing lacks %s", key)
		}
		seg := string(lb)[i:]
		seg = seg[:strings.Index(seg, "</Contents>")]
		if !strings.Contains(seg, "<StorageClass>"+class+"</StorageClass>") {
			t.Errorf("%s listed with %s", key, seg)
		}
	}
	// Multipart.
	_, b = e.do("POST", "/classxl/mp?uploads", nil, hdr{"x-amz-storage-class": "REDUCED_REDUNDANCY"})
	var init initiateMultipartUploadResult
	xml.Unmarshal(b, &init)
	pr, _ := e.do("PUT", "/classxl/mp?partNumber=1&uploadId="+init.UploadID, strings.NewReader("only part"), nil)
	done := `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>` + pr.Header.Get("ETag") + `</ETag></Part></CompleteMultipartUpload>`
	if r, b := e.do("POST", "/classxl/mp?uploadId="+init.UploadID, strings.NewReader(done), nil); r.StatusCode != 200 {
		t.Fatalf("complete: %d %s", r.StatusCode, b)
	}
	if hr, _ := e.do("HEAD", "/classxl/mp", nil, nil); hr.Header.Get("x-amz-storage-class") != "REDUCED_REDUNDANCY" {
		t.Errorf("multipart class header = %q", hr.Header.Get("x-amz-storage-class"))
	}
	r, b = e.do("POST", "/classxl/mp2?uploads", nil, hdr{"x-amz-storage-class": "GLACIER"})
	wantError(t, r, b, 400, "InvalidStorageClass")
}

func TestStorageClassOnCopy(t *testing.T) {
	e := sseEnv(t, "xl")
	e.mb("classcopy")
	body := strings.Repeat("k", 90_000)
	e.put("/classcopy/src", body, hdr{"x-amz-storage-class": "REDUCED_REDUNDANCY"})
	class := func(key string) string {
		hr, _ := e.do("HEAD", "/classcopy/"+key, nil, nil)
		return hr.Header.Get("x-amz-storage-class")
	}
	// A copy takes the class its request names; without one it is STANDARD.
	if r, b := e.copyObj("/classcopy/c1", "/classcopy/src", nil); r.StatusCode != 200 {
		t.Fatalf("%d %s", r.StatusCode, b)
	}
	if got := class("c1"); got != "" {
		t.Errorf("copy without a header has class %q", got)
	}
	if r, b := e.copyObj("/classcopy/c2", "/classcopy/src", hdr{"x-amz-storage-class": "LIMITED"}); r.StatusCode != 200 {
		t.Fatalf("%d %s", r.StatusCode, b)
	}
	if got := class("c2"); got != "LIMITED" {
		t.Errorf("copy with header has class %q", got)
	}
	// Self-copy that only changes metadata keeps the class (and the data).
	if r, b := e.copyObj("/classcopy/src", "/classcopy/src", hdr{"x-amz-metadata-directive": "REPLACE", "Content-Type": "text/x"}); r.StatusCode != 200 {
		t.Fatalf("%d %s", r.StatusCode, b)
	}
	if got := class("src"); got != "REDUCED_REDUNDANCY" {
		t.Errorf("metadata-only self-copy changed the class to %q", got)
	}
	// Self-copy with a different class rewrites the object into that layout.
	if r, b := e.copyObj("/classcopy/src", "/classcopy/src", hdr{"x-amz-storage-class": "STANDARD"}); r.StatusCode != 200 {
		t.Fatalf("%d %s", r.StatusCode, b)
	}
	if got := class("src"); got != "" {
		t.Errorf("class after self-copy to STANDARD = %q", got)
	}
	if got, _ := e.get("/classcopy/src"); got != body {
		t.Error("body changed")
	}
	// An encrypted object needs its encryption restated to change class.
	e.put("/classcopy/enc", body, hdr{"x-amz-server-side-encryption": "AES256"})
	r, b := e.copyObj("/classcopy/enc", "/classcopy/enc", hdr{"x-amz-storage-class": "REDUCED_REDUNDANCY"})
	wantError(t, r, b, 400, "InvalidRequest")
	if r, b := e.copyObj("/classcopy/enc", "/classcopy/enc", hdr{"x-amz-storage-class": "REDUCED_REDUNDANCY", "x-amz-server-side-encryption": "AES256"}); r.StatusCode != 200 {
		t.Fatalf("%d %s", r.StatusCode, b)
	}
	if got, _ := e.get("/classcopy/enc"); got != body {
		t.Error("encrypted body changed")
	}
	if got := class("enc"); got != "REDUCED_REDUNDANCY" {
		t.Errorf("class = %q", got)
	}
}

// s3:x-amz-storage-class as a policy condition key: principal x class x
// resource.
func TestStorageClassPolicyMatrix(t *testing.T) {
	e := sseEnv(t, "xl")
	e.mb("classpol")
	pol := `{"Version":"2012-10-17","Statement":[
	  {"Effect":"Allow","Principal":"*","Action":"s3:PutObject","Resource":"arn:aws:s3:::classpol/drop/*",
	   "Condition":{"StringEquals":{"s3:x-amz-storage-class":["STANDARD","LIMITED"]}}},
	  {"Effect":"Deny","Principal":{"AWS":"writer"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::classpol/*",
	   "Condition":{"StringEquals":{"s3:x-amz-storage-class":"REDUCED_REDUNDANCY"}}},
	  {"Effect":"Allow","Principal":{"AWS":"nobody"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::classpol/cold/*",
	   "Condition":{"StringLike":{"s3:x-amz-storage-class":"RED*"}}}
	]}`
	if r, b := e.do("PUT", "/classpol?policy", strings.NewReader(pol), nil); r.StatusCode != 204 {
		t.Fatalf("%d %s", r.StatusCode, b)
	}
	type tc struct {
		who, path, class string
		want             int
	}
	cases := []tc{
		{"", "/classpol/drop/a", "STANDARD", 200},
		{"", "/classpol/drop/b", "LIMITED", 200},
		{"", "/classpol/drop/c", "REDUCED_REDUNDANCY", 403},
		{"", "/classpol/drop/d", "", 403}, // no header: the key is absent, StringEquals fails
		{"", "/classpol/other/e", "STANDARD", 403},
		{"nobody", "/classpol/drop/f", "STANDARD", 200},
		{"nobody", "/classpol/cold/g", "REDUCED_REDUNDANCY", 200},
		{"nobody", "/classpol/cold/h", "STANDARD", 403},
		{"nobody", "/classpol/cold/i", "LIMITED", 403},
		{"writer", "/classpol/other/j", "STANDARD", 200},           // identity allows
		{"writer", "/classpol/other/k", "REDUCED_REDUNDANCY", 403}, // explicit Deny on the class
		{"writer", "/classpol/other/l", "LIMITED", 200},
		{"writer", "/classpol/drop/m", "REDUCED_REDUNDANCY", 403},
		{"reader", "/classpol/drop/n", "STANDARD", 200}, // via Principal *
		{"reader", "/classpol/other/o", "STANDARD", 403},
		{"root", "/classpol/other/p", "REDUCED_REDUNDANCY", 200},
		{"root", "/classpol/other/q", "GLACIER", 400}, // authorised, then refused by the backend
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%s %s %s", c.who, c.path, c.class), func(t *testing.T) {
			h := hdr(nil)
			if c.class != "" {
				h = hdr{"x-amz-storage-class": c.class}
			}
			var status int
			switch c.who {
			case "":
				r, _ := e.doAnon("PUT", c.path, strings.NewReader("data"), h)
				status = r.StatusCode
			case "root":
				r, _ := e.do("PUT", c.path, strings.NewReader("data"), h)
				status = r.StatusCode
			default:
				r, _ := e.doAs(c.who, "PUT", c.path, strings.NewReader("data"), h)
				status = r.StatusCode
			}
			if status != c.want {
				t.Errorf("status %d, want %d", status, c.want)
			}
		})
	}
}
