package api

import (
	"encoding/xml"
	"strings"
	"time"
)

// xmlNS is the S3 XML namespace carried by every result document.
const xmlNS = "http://s3.amazonaws.com/doc/2006-03-01/"

// S3 timestamps are ISO 8601 with millisecond precision, always UTC.
const timeLayout = "2006-01-02T15:04:05.000Z"

func isoTime(t time.Time) string { return t.UTC().Format(timeLayout) }

// ownerEntry is the single placeholder owner: there is no IAM yet.
type ownerEntry struct {
	ID          string `xml:"ID"`
	DisplayName string `xml:"DisplayName"`
}

var placeholderOwner = ownerEntry{ID: "nanoio", DisplayName: "nanoio"}

type listAllMyBucketsResult struct {
	XMLName xml.Name   `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListAllMyBucketsResult"`
	Owner   ownerEntry `xml:"Owner"`
	Buckets struct {
		Bucket []bucketEntry `xml:"Bucket"`
	} `xml:"Buckets"`
}

type bucketEntry struct {
	Name         string `xml:"Name"`
	CreationDate string `xml:"CreationDate"`
}

type contentsEntry struct {
	Key          string      `xml:"Key"`
	LastModified string      `xml:"LastModified"`
	ETag         string      `xml:"ETag"`
	Size         int64       `xml:"Size"`
	Owner        *ownerEntry `xml:"Owner,omitempty"`
	StorageClass string      `xml:"StorageClass"`
}

type commonPrefix struct {
	Prefix string `xml:"Prefix"`
}

// listBucketResultV1 is the ListObjects (v1) response.
type listBucketResultV1 struct {
	XMLName        xml.Name        `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListBucketResult"`
	Name           string          `xml:"Name"`
	Prefix         string          `xml:"Prefix"`
	Marker         string          `xml:"Marker"`
	NextMarker     string          `xml:"NextMarker,omitempty"`
	MaxKeys        int             `xml:"MaxKeys"`
	Delimiter      string          `xml:"Delimiter,omitempty"`
	EncodingType   string          `xml:"EncodingType,omitempty"`
	IsTruncated    bool            `xml:"IsTruncated"`
	Contents       []contentsEntry `xml:"Contents"`
	CommonPrefixes []commonPrefix  `xml:"CommonPrefixes"`
}

// listBucketResultV2 is the ListObjectsV2 response.
type listBucketResultV2 struct {
	XMLName               xml.Name        `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListBucketResult"`
	Name                  string          `xml:"Name"`
	Prefix                string          `xml:"Prefix"`
	Delimiter             string          `xml:"Delimiter,omitempty"`
	MaxKeys               int             `xml:"MaxKeys"`
	EncodingType          string          `xml:"EncodingType,omitempty"`
	KeyCount              int             `xml:"KeyCount"`
	IsTruncated           bool            `xml:"IsTruncated"`
	ContinuationToken     string          `xml:"ContinuationToken,omitempty"`
	NextContinuationToken string          `xml:"NextContinuationToken,omitempty"`
	StartAfter            string          `xml:"StartAfter,omitempty"`
	Contents              []contentsEntry `xml:"Contents"`
	CommonPrefixes        []commonPrefix  `xml:"CommonPrefixes"`
}

// createBucketConfiguration is the optional CreateBucket request body.
type createBucketConfiguration struct {
	XMLName            xml.Name `xml:"CreateBucketConfiguration"`
	LocationConstraint string   `xml:"LocationConstraint"`
}

type locationConstraint struct {
	XMLName xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ LocationConstraint"`
	Region  string   `xml:",chardata"`
}

type deleteRequest struct {
	XMLName xml.Name       `xml:"Delete"`
	Quiet   bool           `xml:"Quiet"`
	Objects []deleteObject `xml:"Object"`
}

type deleteObject struct {
	Key       string `xml:"Key"`
	VersionID string `xml:"VersionId"`
}

type deleteResult struct {
	XMLName xml.Name       `xml:"http://s3.amazonaws.com/doc/2006-03-01/ DeleteResult"`
	Deleted []deletedEntry `xml:"Deleted"`
	Errors  []deleteError  `xml:"Error"`
}

type deletedEntry struct {
	Key                   string `xml:"Key"`
	VersionID             string `xml:"VersionId,omitempty"`
	DeleteMarker          bool   `xml:"DeleteMarker,omitempty"`
	DeleteMarkerVersionID string `xml:"DeleteMarkerVersionId,omitempty"`
}

type deleteError struct {
	Key     string `xml:"Key"`
	Code    string `xml:"Code"`
	Message string `xml:"Message"`
}

// s3Encode implements encoding-type=url: every byte except unreserved
// characters and '/' becomes %XX (uppercase hex), so a space is %20 and a
// literal '+' is %2B. Clients decode with a standard percent-decoder.
func s3Encode(s string) string {
	const hexdigits = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~', c == '/':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hexdigits[c>>4])
			b.WriteByte(hexdigits[c&0x0f])
		}
	}
	return b.String()
}

type initiateMultipartUploadResult struct {
	XMLName  xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ InitiateMultipartUploadResult"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	UploadID string   `xml:"UploadId"`
}

type completeMultipartUploadRequest struct {
	XMLName xml.Name       `xml:"CompleteMultipartUpload"`
	Parts   []completePart `xml:"Part"`
}

type completePart struct {
	PartNumber int    `xml:"PartNumber"`
	ETag       string `xml:"ETag"`
}

type completeMultipartUploadResult struct {
	XMLName  xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ CompleteMultipartUploadResult"`
	Location string   `xml:"Location"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	ETag     string   `xml:"ETag"`
}

type partEntry struct {
	PartNumber   int    `xml:"PartNumber"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
}

type listPartsResult struct {
	XMLName              xml.Name    `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListPartsResult"`
	Bucket               string      `xml:"Bucket"`
	Key                  string      `xml:"Key"`
	UploadID             string      `xml:"UploadId"`
	PartNumberMarker     int         `xml:"PartNumberMarker"`
	NextPartNumberMarker int         `xml:"NextPartNumberMarker,omitempty"`
	MaxParts             int         `xml:"MaxParts"`
	IsTruncated          bool        `xml:"IsTruncated"`
	Parts                []partEntry `xml:"Part"`
	Initiator            ownerEntry  `xml:"Initiator"`
	Owner                ownerEntry  `xml:"Owner"`
	StorageClass         string      `xml:"StorageClass"`
}

type uploadEntry struct {
	Key          string     `xml:"Key"`
	UploadID     string     `xml:"UploadId"`
	Initiator    ownerEntry `xml:"Initiator"`
	Owner        ownerEntry `xml:"Owner"`
	StorageClass string     `xml:"StorageClass"`
	Initiated    string     `xml:"Initiated"`
}

type listMultipartUploadsResult struct {
	XMLName            xml.Name       `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListMultipartUploadsResult"`
	Bucket             string         `xml:"Bucket"`
	KeyMarker          string         `xml:"KeyMarker"`
	UploadIDMarker     string         `xml:"UploadIdMarker"`
	NextKeyMarker      string         `xml:"NextKeyMarker,omitempty"`
	NextUploadIDMarker string         `xml:"NextUploadIdMarker,omitempty"`
	Prefix             string         `xml:"Prefix"`
	Delimiter          string         `xml:"Delimiter,omitempty"`
	MaxUploads         int            `xml:"MaxUploads"`
	IsTruncated        bool           `xml:"IsTruncated"`
	EncodingType       string         `xml:"EncodingType,omitempty"`
	Uploads            []uploadEntry  `xml:"Upload"`
	CommonPrefixes     []commonPrefix `xml:"CommonPrefixes"`
}

type copyPartResult struct {
	XMLName      xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ CopyPartResult"`
	LastModified string   `xml:"LastModified"`
	ETag         string   `xml:"ETag"`
}

// listVersionsResult is the ListObjectVersions response. Versions and
// delete markers are interleaved in listing order, which a pair of typed
// slices could not express.
type listVersionsResult struct {
	XMLName             xml.Name       `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListVersionsResult"`
	Name                string         `xml:"Name"`
	Prefix              string         `xml:"Prefix"`
	KeyMarker           string         `xml:"KeyMarker"`
	VersionIDMarker     string         `xml:"VersionIdMarker"`
	NextKeyMarker       string         `xml:"NextKeyMarker,omitempty"`
	NextVersionIDMarker string         `xml:"NextVersionIdMarker,omitempty"`
	MaxKeys             int            `xml:"MaxKeys"`
	Delimiter           string         `xml:"Delimiter,omitempty"`
	EncodingType        string         `xml:"EncodingType,omitempty"`
	IsTruncated         bool           `xml:"IsTruncated"`
	Entries             []any          `xml:",any"`
	CommonPrefixes      []commonPrefix `xml:"CommonPrefixes"`
}

type versionEntry struct {
	XMLName      xml.Name    `xml:"Version"`
	Key          string      `xml:"Key"`
	VersionID    string      `xml:"VersionId"`
	IsLatest     bool        `xml:"IsLatest"`
	LastModified string      `xml:"LastModified"`
	ETag         string      `xml:"ETag"`
	Size         int64       `xml:"Size"`
	Owner        *ownerEntry `xml:"Owner,omitempty"`
	StorageClass string      `xml:"StorageClass"`
}

type deleteMarkerEntry struct {
	XMLName      xml.Name    `xml:"DeleteMarker"`
	Key          string      `xml:"Key"`
	VersionID    string      `xml:"VersionId"`
	IsLatest     bool        `xml:"IsLatest"`
	LastModified string      `xml:"LastModified"`
	Owner        *ownerEntry `xml:"Owner,omitempty"`
}
