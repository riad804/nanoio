package tier

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"nanoio/internal/auth"
)

const (
	// defaultPartSize is the largest object uploaded in one PUT and the
	// part size beyond it.
	defaultPartSize = 64 << 20
	s3MaxParts      = 9000
)

func (b *s3Backend) partSize() int64 {
	if b.cfg.PartSize > 0 {
		return b.cfg.PartSize
	}
	return defaultPartSize
}

type s3Backend struct {
	cfg    S3Config
	base   *url.URL
	client *http.Client
	signer auth.Signer
}

// S3Client is the S3 backend with its object-level extras (metadata on put,
// head); batch replication uses it.
type S3Client = s3Backend

// NewS3Client returns an S3 client for c.
func NewS3Client(c S3Config) (*S3Client, error) {
	be, err := NewS3(c)
	if err != nil {
		return nil, err
	}
	return be.(*s3Backend), nil
}

// NewS3 returns a tier backend for an S3-compatible endpoint. It signs with
// the in-tree SigV4 signer and speaks only the object operations it needs.
func NewS3(c S3Config) (Backend, error) {
	u, err := url.Parse(c.Endpoint)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("s3 endpoint %q is not a URL", c.Endpoint)
	}
	region := c.Region
	if region == "" {
		region = "us-east-1"
	}
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment, MaxIdleConnsPerHost: 8, IdleConnTimeout: 90 * time.Second,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: c.InsecureSkipVerify},
	}
	return &s3Backend{cfg: c, base: u, client: &http.Client{Transport: tr},
		signer: auth.Signer{AccessKey: c.AccessKey, SecretKey: c.SecretKey, Region: region}}, nil
}

func (b *s3Backend) key(name string) string { return strings.TrimPrefix(b.cfg.Prefix, "/") + name }

// request builds a signed request for object key (or the bucket if key is
// empty) with the given query.
func (b *s3Backend) request(ctx context.Context, method, key, query string, body io.Reader, size int64, hdr map[string]string) (*http.Request, error) {
	u := *b.base
	switch {
	case b.cfg.VirtualHost:
		u.Host = b.cfg.Bucket + "." + b.base.Host
		u.Path = "/" + key
	default:
		u.Path = "/" + b.cfg.Bucket
		if key != "" {
			u.Path += "/" + key
		}
	}
	u.RawQuery = query
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.ContentLength = size
		if size == 0 {
			req.Body = http.NoBody
		}
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	payload := auth.PayloadUnsigned
	if body == nil {
		payload = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" // sha256("")
	}
	b.signer.Sign(req, payload, time.Now())
	return req, nil
}

func (b *s3Backend) do(req *http.Request) (*http.Response, error) {
	resp, err := b.client.Do(req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func s3Error(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	resp.Body.Close()
	var e struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	}
	if xml.Unmarshal(body, &e) == nil && e.Code != "" {
		return fmt.Errorf("s3 tier answered %s: %s: %s", resp.Status, e.Code, e.Message)
	}
	return fmt.Errorf("s3 tier answered %s", resp.Status)
}

// ObjectMeta is what a client-side copy preserves of an object.
type ObjectMeta struct {
	ContentType string
	// Headers are the object's other headers: x-amz-meta-*, Cache-Control,
	// Content-Disposition, ... (full header names).
	Headers map[string]string
	// Tagging is the URL-encoded tag set, "" for none.
	Tagging string
}

func (b *s3Backend) putHeaders(m ObjectMeta) map[string]string {
	h := map[string]string{"Content-Type": "application/octet-stream"}
	for k, v := range m.Headers {
		h[k] = v
	}
	if m.ContentType != "" {
		h["Content-Type"] = m.ContentType
	}
	if m.Tagging != "" {
		h["x-amz-tagging"] = m.Tagging
	}
	if b.cfg.StorageClass != "" {
		h["x-amz-storage-class"] = b.cfg.StorageClass
	}
	return h
}

// Put implements Backend.
func (b *s3Backend) Put(ctx context.Context, name string, r io.Reader, size int64) (string, error) {
	_, vid, err := b.PutObject(ctx, name, r, size, ObjectMeta{})
	return vid, err
}

// PutObject uploads with metadata and returns the remote ETag and version.
func (b *s3Backend) PutObject(ctx context.Context, name string, r io.Reader, size int64, m ObjectMeta) (etag, versionID string, err error) {
	key := b.key(name)
	if size <= b.partSize() {
		req, err := b.request(ctx, http.MethodPut, key, "", r, size, b.putHeaders(m))
		if err != nil {
			return "", "", err
		}
		resp, err := b.do(req)
		if err != nil {
			return "", "", err
		}
		if resp.StatusCode/100 != 2 {
			return "", "", s3Error(resp)
		}
		resp.Body.Close()
		return resp.Header.Get("ETag"), resp.Header.Get("x-amz-version-id"), nil
	}
	vid, err := b.putMultipart(ctx, key, r, size, m)
	return "", vid, err
}

func (b *s3Backend) putMultipart(ctx context.Context, key string, r io.Reader, size int64, m ObjectMeta) (string, error) {
	req, err := b.request(ctx, http.MethodPost, key, "uploads=", nil, 0, b.putHeaders(m))
	if err != nil {
		return "", err
	}
	resp, err := b.do(req)
	if err != nil {
		return "", err
	}
	if resp.StatusCode/100 != 2 {
		return "", s3Error(resp)
	}
	var init struct {
		UploadID string `xml:"UploadId"`
	}
	err = xml.NewDecoder(resp.Body).Decode(&init)
	resp.Body.Close()
	if err != nil || init.UploadID == "" {
		return "", fmt.Errorf("s3 tier: unreadable CreateMultipartUpload answer: %v", err)
	}
	abort := func() {
		actx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if ar, err := b.request(actx, http.MethodDelete, key, "uploadId="+url.QueryEscape(init.UploadID), nil, 0, nil); err == nil {
			if rs, err := b.do(ar); err == nil {
				rs.Body.Close()
			}
		}
	}
	partSize := b.partSize()
	if need := (size + s3MaxParts - 1) / s3MaxParts; need > partSize {
		partSize = need
	}
	type donePart struct {
		N    int
		ETag string
	}
	var parts []donePart
	remaining := size
	for n := 1; remaining > 0; n++ {
		ps := min(partSize, remaining)
		q := "partNumber=" + strconv.Itoa(n) + "&uploadId=" + url.QueryEscape(init.UploadID)
		preq, err := b.request(ctx, http.MethodPut, key, q, io.LimitReader(r, ps), ps, nil)
		if err != nil {
			abort()
			return "", err
		}
		presp, err := b.do(preq)
		if err != nil {
			abort()
			return "", err
		}
		if presp.StatusCode/100 != 2 {
			abort()
			return "", s3Error(presp)
		}
		presp.Body.Close()
		parts = append(parts, donePart{n, presp.Header.Get("ETag")})
		remaining -= ps
	}
	var doc bytes.Buffer
	doc.WriteString("<CompleteMultipartUpload>")
	for _, p := range parts {
		fmt.Fprintf(&doc, "<Part><PartNumber>%d</PartNumber><ETag>%s</ETag></Part>", p.N, p.ETag)
	}
	doc.WriteString("</CompleteMultipartUpload>")
	sum := md5.Sum(doc.Bytes())
	creq, err := b.request(ctx, http.MethodPost, key, "uploadId="+url.QueryEscape(init.UploadID), bytes.NewReader(doc.Bytes()),
		int64(doc.Len()), map[string]string{"Content-Type": "application/xml", "Content-MD5": md5b64(sum[:])})
	if err != nil {
		abort()
		return "", err
	}
	cresp, err := b.do(creq)
	if err != nil {
		abort()
		return "", err
	}
	if cresp.StatusCode/100 != 2 {
		abort()
		return "", s3Error(cresp)
	}
	io.Copy(io.Discard, cresp.Body)
	cresp.Body.Close()
	return cresp.Header.Get("x-amz-version-id"), nil
}

// Do sends a signed request for an object of the client's bucket ("" for the
// bucket itself) and returns the response; the caller closes its body.
func (b *s3Backend) Do(ctx context.Context, method, name, query string, body []byte, hdr map[string]string) (*http.Response, error) {
	key := ""
	if name != "" {
		key = b.key(name)
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := b.request(ctx, method, key, query, rd, int64(len(body)), hdr)
	if err != nil {
		return nil, err
	}
	return b.do(req)
}

// HeadInfo describes a remote object.
type HeadInfo struct {
	Exists  bool
	Size    int64
	ETag    string
	Headers http.Header
}

// Head returns an object's size, ETag and headers; Exists is false for a
// missing object.
func (b *s3Backend) Head(ctx context.Context, name string) (HeadInfo, error) {
	req, err := b.request(ctx, http.MethodHead, b.key(name), "", nil, 0, nil)
	if err != nil {
		return HeadInfo{}, err
	}
	resp, err := b.do(req)
	if err != nil {
		return HeadInfo{}, err
	}
	resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return HeadInfo{}, nil
	case resp.StatusCode/100 != 2:
		return HeadInfo{}, fmt.Errorf("s3 tier answered %s", resp.Status)
	}
	return HeadInfo{Exists: true, Size: resp.ContentLength, ETag: strings.Trim(resp.Header.Get("ETag"), `"`), Headers: resp.Header}, nil
}

// Get implements Backend.
func (b *s3Backend) Get(ctx context.Context, name, versionID string, offset, length int64) (io.ReadCloser, error) {
	q := ""
	if versionID != "" {
		q = "versionId=" + url.QueryEscape(versionID)
	}
	hdr := map[string]string{}
	switch {
	case length >= 0:
		hdr["Range"] = fmt.Sprintf("bytes=%d-%d", offset, offset+length-1)
	case offset > 0:
		hdr["Range"] = fmt.Sprintf("bytes=%d-", offset)
	}
	req, err := b.request(ctx, http.MethodGet, b.key(name), q, nil, 0, hdr)
	if err != nil {
		return nil, err
	}
	resp, err := b.do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return nil, s3Error(resp)
	}
	return resp.Body, nil
}

// Delete implements Backend.
func (b *s3Backend) Delete(ctx context.Context, name, versionID string) error {
	q := ""
	if versionID != "" {
		q = "versionId=" + url.QueryEscape(versionID)
	}
	req, err := b.request(ctx, http.MethodDelete, b.key(name), q, nil, 0, nil)
	if err != nil {
		return err
	}
	resp, err := b.do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 && resp.StatusCode != http.StatusNotFound {
		return s3Error(resp)
	}
	resp.Body.Close()
	return nil
}

// Check implements Backend.
func (b *s3Backend) Check(ctx context.Context) error {
	name := "nanoio-tier-probe-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	payload := []byte("nanoio tier probe")
	vid, err := b.Put(ctx, name, bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		return err
	}
	defer b.Delete(context.Background(), name, vid)
	rc, err := b.Get(ctx, name, vid, 0, -1)
	if err != nil {
		return err
	}
	got, err := io.ReadAll(rc)
	rc.Close()
	if err != nil || !bytes.Equal(got, payload) {
		return fmt.Errorf("probe object did not read back intact (%v)", err)
	}
	return nil
}

// Close implements Backend.
func (b *s3Backend) Close() error {
	b.client.CloseIdleConnections()
	return nil
}
