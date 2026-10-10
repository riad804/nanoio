package auth

import (
	"encoding/hex"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Signer signs requests as an S3 client would. It exists for tests, tools
// and health checks; the server itself only verifies.
type Signer struct {
	AccessKey string
	SecretKey string
	// Region defaults to us-east-1 and Service to s3.
	Region  string
	Service string
}

func (s Signer) regionService() (region, service string) {
	region, service = s.Region, s.Service
	if region == "" {
		region = "us-east-1"
	}
	if service == "" {
		service = "s3"
	}
	return
}

func hexMAC(key []byte, data string) string { return hex.EncodeToString(hmacSHA256(key, data)) }

// Sign adds X-Amz-Date, x-amz-content-sha256 and Authorization to r and
// returns the signature, which seeds chunk signing for streaming uploads.
// payloadHash is the hex SHA-256 of the body or one of the Payload*
// sentinels. The signed headers are host, content-md5, content-type and
// every x-amz-* header present.
func (s Signer) Sign(r *http.Request, payloadHash string, t time.Time) string {
	region, service := s.regionService()
	t = t.UTC()
	amzDate := t.Format(amzDateLayout)
	date := t.Format(scopeDateLayout)
	r.Header.Set("X-Amz-Date", amzDate)
	r.Header.Set("X-Amz-Content-Sha256", payloadHash)

	var names []string
	for k := range r.Header {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-amz-") || lk == "content-md5" || lk == "content-type" {
			names = append(names, lk)
		}
	}
	names = append(names, "host")
	signed := sortedLower(names)

	hdrs, _ := canonicalHeaders(requestHeaders(r), signed)
	creq := canonicalRequest(r.Method, canonicalURIS3(r.URL.Path),
		canonicalQuery(r.URL.RawQuery, nil), hdrs, signed, payloadHash)
	scope := scopeString(date, region, service)
	sig := hexMAC(signingKey(s.SecretKey, date, region, service), stringToSign(amzDate, scope, creq))
	r.Header.Set("Authorization", Algorithm+" Credential="+s.AccessKey+"/"+scope+
		", SignedHeaders="+strings.Join(signed, ";")+", Signature="+sig)
	return sig
}

// Presign turns r into a presigned URL valid for expires from t, by
// appending the X-Amz-* query parameters to r.URL. Only host (and any
// x-amz-* headers already on r) are signed; the payload is UNSIGNED-PAYLOAD.
func (s Signer) Presign(r *http.Request, expires time.Duration, t time.Time) {
	region, service := s.regionService()
	t = t.UTC()
	amzDate := t.Format(amzDateLayout)
	date := t.Format(scopeDateLayout)
	scope := scopeString(date, region, service)

	names := []string{"host"}
	for k := range r.Header {
		if lk := strings.ToLower(k); strings.HasPrefix(lk, "x-amz-") {
			names = append(names, lk)
		}
	}
	signed := sortedLower(names)

	q := r.URL.Query()
	q.Set("X-Amz-Algorithm", Algorithm)
	q.Set("X-Amz-Credential", s.AccessKey+"/"+scope)
	q.Set("X-Amz-Date", amzDate)
	q.Set("X-Amz-Expires", strconv.Itoa(int(expires/time.Second)))
	q.Set("X-Amz-SignedHeaders", strings.Join(signed, ";"))
	r.URL.RawQuery = q.Encode()

	hdrs, _ := canonicalHeaders(requestHeaders(r), signed)
	creq := canonicalRequest(r.Method, canonicalURIS3(r.URL.Path),
		canonicalQuery(r.URL.RawQuery, nil), hdrs, signed, PayloadUnsigned)
	sig := hexMAC(signingKey(s.SecretKey, date, region, service), stringToSign(amzDate, scope, creq))
	r.URL.RawQuery += "&" + url.QueryEscape("X-Amz-Signature") + "=" + sig
}
