package api

import (
	"encoding/xml"
	"strings"
	"testing"
	"time"
)

func marshal(t *testing.T, v any) string {
	t.Helper()
	b, err := xml.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestXMLShapes(t *testing.T) {
	owner := placeholderOwner
	tests := []struct {
		name string
		v    any
		want string
	}{
		{"empty bucket list keeps <Buckets>", func() any {
			r := listAllMyBucketsResult{Owner: placeholderOwner}
			return &r
		}(),
			`<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Owner><ID>nanoio</ID><DisplayName>nanoio</DisplayName></Owner><Buckets></Buckets></ListAllMyBucketsResult>`},
		{"bucket list", func() any {
			r := listAllMyBucketsResult{Owner: placeholderOwner}
			r.Buckets.Bucket = []bucketEntry{{Name: "a", CreationDate: "2026-10-10T10:28:00.000Z"}}
			return &r
		}(),
			`<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Owner><ID>nanoio</ID><DisplayName>nanoio</DisplayName></Owner><Buckets><Bucket><Name>a</Name><CreationDate>2026-10-10T10:28:00.000Z</CreationDate></Bucket></Buckets></ListAllMyBucketsResult>`},
		{"list v1 with prefix", &listBucketResultV1{
			Name: "b", Prefix: "p/", Marker: "", NextMarker: "p/z", MaxKeys: 2, Delimiter: "/", IsTruncated: true,
			Contents:       []contentsEntry{{Key: "p/a", LastModified: "2026-10-10T10:28:00.000Z", ETag: `"e"`, Size: 3, Owner: &owner, StorageClass: "STANDARD"}},
			CommonPrefixes: []commonPrefix{{Prefix: "p/sub/"}},
		},
			`<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>b</Name><Prefix>p/</Prefix><Marker></Marker><NextMarker>p/z</NextMarker><MaxKeys>2</MaxKeys><Delimiter>/</Delimiter><IsTruncated>true</IsTruncated><Contents><Key>p/a</Key><LastModified>2026-10-10T10:28:00.000Z</LastModified><ETag>&#34;e&#34;</ETag><Size>3</Size><Owner><ID>nanoio</ID><DisplayName>nanoio</DisplayName></Owner><StorageClass>STANDARD</StorageClass></Contents><CommonPrefixes><Prefix>p/sub/</Prefix></CommonPrefixes></ListBucketResult>`},
		{"list v1 empty", &listBucketResultV1{Name: "b", MaxKeys: 1000},
			`<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>b</Name><Prefix></Prefix><Marker></Marker><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated></ListBucketResult>`},
		{"list v2 truncated", &listBucketResultV2{
			Name: "b", Prefix: "", MaxKeys: 1, KeyCount: 1, IsTruncated: true, NextContinuationToken: "dG9r", EncodingType: "url",
			Contents: []contentsEntry{{Key: "a%20b", LastModified: "2026-10-10T10:28:00.000Z", ETag: `"e"`, Size: 0, StorageClass: "STANDARD"}},
		},
			`<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>b</Name><Prefix></Prefix><MaxKeys>1</MaxKeys><EncodingType>url</EncodingType><KeyCount>1</KeyCount><IsTruncated>true</IsTruncated><NextContinuationToken>dG9r</NextContinuationToken><Contents><Key>a%20b</Key><LastModified>2026-10-10T10:28:00.000Z</LastModified><ETag>&#34;e&#34;</ETag><Size>0</Size><StorageClass>STANDARD</StorageClass></Contents></ListBucketResult>`},
		{"delete result", &deleteResult{
			Deleted: []deletedEntry{{Key: "a"}},
			Errors:  []deleteError{{Key: "b", Code: "AccessDenied", Message: "no"}},
		},
			`<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted><Key>a</Key></Deleted><Error><Key>b</Key><Code>AccessDenied</Code><Message>no</Message></Error></DeleteResult>`},
		{"error without bucket/key", &errorResponse{Code: "NoSuchKey", Message: "m", Resource: "/b/k", RequestID: "R", HostID: "H"},
			`<Error><Code>NoSuchKey</Code><Message>m</Message><Resource>/b/k</Resource><RequestId>R</RequestId><HostId>H</HostId></Error>`},
		{"error with bucket and key", &errorResponse{Code: "NoSuchKey", Message: "m", BucketName: "b", Key: "k", Resource: "/b/k", RequestID: "R", HostID: "H"},
			`<Error><Code>NoSuchKey</Code><Message>m</Message><BucketName>b</BucketName><Key>k</Key><Resource>/b/k</Resource><RequestId>R</RequestId><HostId>H</HostId></Error>`},
		{"location constraint", &locationConstraint{Region: "eu-west-1"},
			`<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">eu-west-1</LocationConstraint>`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := marshal(t, tt.v); got != tt.want {
				t.Errorf("XML mismatch:\n got %s\nwant %s", got, tt.want)
			}
		})
	}
}

func TestXMLRequestParsing(t *testing.T) {
	t.Run("delete request with namespace", func(t *testing.T) {
		in := `<?xml version="1.0"?><Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Quiet>true</Quiet>` +
			`<Object><Key>a</Key></Object><Object><Key>b c</Key><VersionId>v1</VersionId></Object></Delete>`
		var d deleteRequest
		if err := xml.Unmarshal([]byte(in), &d); err != nil {
			t.Fatal(err)
		}
		if !d.Quiet || len(d.Objects) != 2 || d.Objects[1].Key != "b c" || d.Objects[1].VersionID != "v1" {
			t.Errorf("parsed %+v", d)
		}
	})
	t.Run("create bucket configuration", func(t *testing.T) {
		in := `<CreateBucketConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><LocationConstraint>eu-west-1</LocationConstraint></CreateBucketConfiguration>`
		var c createBucketConfiguration
		if err := xml.Unmarshal([]byte(in), &c); err != nil || c.LocationConstraint != "eu-west-1" {
			t.Errorf("parsed %+v, %v", c, err)
		}
	})
}

func TestS3Encode(t *testing.T) {
	tests := []struct{ in, want string }{
		{"", ""},
		{"plain-key_1.txt~", "plain-key_1.txt~"},
		{"a b", "a%20b"},
		{"a+b", "a%2Bb"},
		{"dir/sub/file", "dir/sub/file"},
		{"a&b=c?d#e", "a%26b%3Dc%3Fd%23e"},
		{"100%", "100%25"},
		{"日本", "%E6%97%A5%E6%9C%AC"},
		{"tab\there", "tab%09here"},
		{"quote\"s'", "quote%22s%27"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := s3Encode(tt.in); got != tt.want {
				t.Errorf("s3Encode(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestISOTime(t *testing.T) {
	loc := time.FixedZone("x", 6*3600)
	tests := []struct {
		in   time.Time
		want string
	}{
		{time.Date(2026, 10, 10, 10, 28, 0, 123456789, time.UTC), "2026-10-10T10:28:00.123Z"},
		{time.Date(2026, 10, 10, 16, 28, 0, 0, loc), "2026-10-10T10:28:00.000Z"},
		{time.Date(2026, 1, 2, 3, 4, 5, 999999999, time.UTC), "2026-01-02T03:04:05.999Z"},
	}
	for _, tt := range tests {
		if got := isoTime(tt.in); got != tt.want {
			t.Errorf("isoTime(%v) = %q, want %q", tt.in, got, tt.want)
		}
	}
	if !strings.HasSuffix(isoTime(time.Now()), "Z") {
		t.Error("timestamp is not UTC")
	}
}
