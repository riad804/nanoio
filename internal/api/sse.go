package api

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"net/http"
	"strings"

	"nanoio/internal/kms"
	"nanoio/internal/sse"
	"nanoio/internal/storage"
)

// Server-side encryption request and response headers.
const (
	hSSE        = "x-amz-server-side-encryption"
	hSSEKeyID   = "x-amz-server-side-encryption-aws-kms-key-id"
	hSSEContext = "x-amz-server-side-encryption-context"

	ssecPrefix     = "x-amz-server-side-encryption-customer-"
	ssecCopyPrefix = "x-amz-copy-source-server-side-encryption-customer-"
)

// sysBucket is the reserved bucket that holds NanoIO's own per-bucket
// configuration documents. It is invisible to the S3 API.
const sysBucket = "nanoio-sys-config"

var (
	errKMSNotConfigured = &APIError{"NotImplemented", "Server side encryption specified but KMS is not configured.", http.StatusNotImplemented}
	errKMSKeyNotFound   = &APIError{"KMS.NotFoundException", "The specified KMS key does not exist.", http.StatusBadRequest}
	errKMSUnavailable   = &APIError{"ServiceUnavailable", "The key management service is unavailable. Please retry.", http.StatusServiceUnavailable}
	errSSEWrongKey      = &APIError{"AccessDenied", "The provided encryption parameters did not match the ones used originally.", http.StatusForbidden}
	errSSECRequired     = &APIError{"InvalidRequest", "The object was stored using a form of Server Side Encryption. The correct parameters must be provided to retrieve the object.", http.StatusBadRequest}
	errSSECNotApplied   = &APIError{"InvalidRequest", "The encryption parameters are not applicable to this object.", http.StatusBadRequest}
	errSSEInsecure      = &APIError{"InvalidRequest", "Requests specifying Server Side Encryption with Customer provided keys must be made over a secure connection.", http.StatusBadRequest}
	errSSEOnRead        = &APIError{"InvalidArgument", "The server side encryption header is not valid for this request; encryption is selected when an object is written.", http.StatusBadRequest}
)

// sseSpec says how a new object (or upload) is to be encrypted.
type sseSpec struct {
	mode      sse.Mode
	keyID     string
	ctxJSON   []byte // the client's JSON context, decoded
	clientKey []byte
}

// encObject is an encrypted object opened for reading: its object key, part
// layout and the size and ETag the client sees.
type encObject struct {
	meta      *sse.Meta
	key       []byte
	layout    sse.Layout
	size      int64
	etag      string // what GET, HEAD and PUT report
	storedTag string // the stored ETag (ciphertext MD5), also accepted by If-Match
	clientMD5 string // base64 MD5 of the SSE-C key, for response headers
}

func (e *encObject) close() {
	if e != nil {
		kms.Zero(e.key)
	}
}

// ssecKey parses the three customer-key headers under prefix. present is
// false when none is sent; a partial set, a bad algorithm, a key that is not
// 32 bytes and a wrong MD5 are 400s.
func (s *Server) ssecKey(q *request, prefix string) (key []byte, present bool, err *APIError) {
	h := q.r.Header
	alg, k, sum := h.Get(prefix+"algorithm"), h.Get(prefix+"key"), h.Get(prefix+"key-MD5")
	if alg == "" && k == "" && sum == "" {
		return nil, false, nil
	}
	if q.r.TLS == nil && !s.allowInsecureSSEC {
		return nil, true, errSSEInsecure
	}
	if alg == "" || k == "" || sum == "" {
		return nil, true, invalidArgument("Requests specifying Server Side Encryption with Customer provided keys must provide the algorithm, the key and the key MD5.")
	}
	if alg != "AES256" {
		return nil, true, invalidArgument("The encryption algorithm for customer provided keys must be AES256.")
	}
	raw, derr := base64.StdEncoding.DecodeString(k)
	if derr != nil || len(raw) != sse.KeySize {
		return nil, true, invalidArgument("The secret key was invalid for the specified algorithm.")
	}
	want, derr := base64.StdEncoding.DecodeString(sum)
	got := md5.Sum(raw)
	if derr != nil || subtle.ConstantTimeCompare(want, got[:]) != 1 {
		return nil, true, invalidArgument("The calculated MD5 hash of the key did not match the hash that was provided.")
	}
	return raw, true, nil
}

func hasSSECHeaders(h http.Header, prefix string) bool {
	return h.Get(prefix+"algorithm") != "" || h.Get(prefix+"key") != "" || h.Get(prefix+"key-MD5") != ""
}

// rejectSSEOnRead refuses write-side encryption headers on a read.
func rejectSSEOnRead(h http.Header) *APIError {
	if h.Get(hSSE) != "" || h.Get(hSSEKeyID) != "" || h.Get(hSSEContext) != "" {
		return errSSEOnRead
	}
	return nil
}

// rejectReservedHeaders refuses client headers in the internal namespace.
func rejectReservedHeaders(h http.Header) *APIError {
	for k := range h {
		if sse.IsReserved(k) {
			return invalidArgument("Header " + k + " is reserved.")
		}
	}
	return nil
}

// writeSpec derives how a write to bucket is encrypted from the request
// headers, or from the bucket's default encryption when it names none. A nil
// spec means "store in the clear".
func (s *Server) writeSpec(q *request, bucket string) (*sseSpec, error) {
	h := q.r.Header
	if aerr := rejectReservedHeaders(h); aerr != nil {
		return nil, aerr
	}
	alg := h.Get(hSSE)
	hasC := hasSSECHeaders(h, ssecPrefix)
	if hasC {
		if alg != "" || h.Get(hSSEKeyID) != "" || h.Get(hSSEContext) != "" {
			return nil, invalidArgument("Server side encryption with customer provided keys cannot be combined with other server side encryption headers.")
		}
		key, _, aerr := s.ssecKey(q, ssecPrefix)
		if aerr != nil {
			return nil, aerr
		}
		return &sseSpec{mode: sse.ModeC, clientKey: key}, nil
	}
	switch alg {
	case "":
		if h.Get(hSSEKeyID) != "" || h.Get(hSSEContext) != "" {
			return nil, invalidArgument("x-amz-server-side-encryption must be aws:kms when a KMS key id or context is given.")
		}
		return s.bucketDefaultSpec(q.r.Context(), bucket)
	case "AES256":
		if h.Get(hSSEKeyID) != "" || h.Get(hSSEContext) != "" {
			return nil, invalidArgument("A KMS key id or context requires x-amz-server-side-encryption: aws:kms.")
		}
		if s.kms == nil {
			return nil, errKMSNotConfigured
		}
		return &sseSpec{mode: sse.ModeS3, keyID: s.defaultKey}, nil
	case "aws:kms":
		if s.kms == nil {
			return nil, errKMSNotConfigured
		}
		spec := &sseSpec{mode: sse.ModeKMS, keyID: h.Get(hSSEKeyID)}
		spec.keyID = strings.TrimPrefix(spec.keyID, "arn:aws:kms:")
		if spec.keyID == "" {
			spec.keyID = s.defaultKey
		}
		if c := h.Get(hSSEContext); c != "" {
			raw, err := base64.StdEncoding.DecodeString(c)
			if err != nil || len(raw) > sse.MaxContextSize {
				return nil, invalidArgument("The encryption context must be base64 encoded JSON.")
			}
			if _, err := sse.KMSContext("x/x", raw); err != nil {
				return nil, invalidArgument("The encryption context must be a JSON object of string values.")
			}
			spec.ctxJSON = raw
		}
		return spec, nil
	}
	return nil, invalidArgument("The encryption method specified is not supported.")
}

// params turns a spec into sealing parameters for the object at path.
func (sp *sseSpec) params(path string) sse.Params {
	return sse.Params{Mode: sp.mode, Path: path, KeyID: sp.keyID, Context: sp.ctxJSON, ClientKey: sp.clientKey}
}

// sseError maps key-management and sealing failures to responses. mode is
// the object's mode, which decides what an unseal failure means: with SSE-C
// it is the caller's wrong key; with a KMS mode the metadata is damaged.
func (s *Server) sseError(q *request, mode sse.Mode, err error) error {
	switch {
	case errors.Is(err, sse.ErrNoKMS):
		return errKMSNotConfigured
	case errors.Is(err, kms.ErrKeyNotFound):
		return errKMSKeyNotFound
	case errors.Is(err, kms.ErrUnavailable):
		s.log.Error("kms unavailable", "id", q.id, "err", err)
		return errKMSUnavailable
	case errors.Is(err, kms.ErrDenied):
		s.log.Error("kms denied the server", "id", q.id, "err", err)
		return errKMSUnavailable
	case errors.Is(err, sse.ErrBadContext):
		return invalidArgument("The encryption context must be a JSON object of string values.")
	case errors.Is(err, sse.ErrWrongKey):
		if mode == sse.ModeC {
			return errSSEWrongKey
		}
	case errors.Is(err, kms.ErrDecrypt):
	}
	s.log.Error("encrypted object cannot be unsealed", "id", q.id, "bucket", q.bucket, "key", q.key, "mode", mode, "err", err)
	return errInternal
}

// layoutOf is the part layout of a stored encrypted object.
func layoutOf(info storage.ObjectInfo) sse.Layout {
	var sum int64
	l := make(sse.Layout, 0, len(info.Parts))
	for _, p := range info.Parts {
		l = append(l, sse.PartLayout{Number: p.Number, CipherSize: p.Size})
		sum += p.Size
	}
	if len(l) == 0 || sum != info.Size {
		return sse.SinglePart(info.Size)
	}
	return l
}

// plainSize is the plaintext size of an object as stored: the size itself
// for a plain object. It needs no key.
func plainSize(info storage.ObjectInfo) int64 {
	if !sse.Encrypted(info.UserDefined) || info.DeleteMarker {
		return info.Size
	}
	n, err := layoutOf(info).PlainSize()
	if err != nil {
		return info.Size
	}
	return n
}

// openEncrypted unseals an encrypted object. It returns (nil, nil) for an
// object that is not encrypted (after rejecting SSE-C headers sent for it).
// prefix selects the SSE-C header family (the request's own, or the
// copy-source's).
func (s *Server) openEncrypted(q *request, info storage.ObjectInfo, prefix string) (*encObject, error) {
	m, enc, err := sse.ParseMeta(info.UserDefined)
	if err != nil {
		s.log.Error("encrypted object has malformed metadata", "id", q.id, "bucket", q.bucket, "key", q.key, "err", err)
		return nil, errInternal
	}
	clientKey, given, aerr := s.ssecKey(q, prefix)
	if aerr != nil {
		return nil, aerr
	}
	if !enc {
		if given {
			return nil, errSSECNotApplied
		}
		return nil, nil
	}
	switch {
	case m.Mode == sse.ModeC && !given:
		return nil, errSSECRequired
	case m.Mode != sse.ModeC && given:
		return nil, errSSECNotApplied
	}
	path := info.Bucket + "/" + info.Name
	if info.Bucket == "" {
		path = q.bucket + "/" + q.key
	}
	key, err := sse.OpenObjectKey(q.r.Context(), s.kms, m, path, clientKey)
	if err != nil {
		return nil, s.sseError(q, m.Mode, err)
	}
	layout := layoutOf(info)
	size, err := layout.PlainSize()
	if err != nil {
		kms.Zero(key)
		s.log.Error("encrypted object has an impossible size", "id", q.id, "bucket", q.bucket, "key", q.key, "size", info.Size)
		return nil, errInternal
	}
	e := &encObject{meta: m, key: key, layout: layout, size: size, etag: info.ETag, storedTag: info.ETag}
	if len(m.ETag) > 0 {
		d, err := sse.UnsealETag(key, path, m.ETag)
		if err != nil {
			kms.Zero(key)
			s.log.Error("sealed ETag does not authenticate", "id", q.id, "bucket", q.bucket, "key", q.key)
			return nil, errInternal
		}
		e.etag = hex.EncodeToString(d)
	}
	if m.Mode == sse.ModeC {
		sum := md5.Sum(clientKey)
		e.clientMD5 = base64.StdEncoding.EncodeToString(sum[:])
		kms.Zero(clientKey)
	}
	return e, nil
}

// setSSEHeaders reports an object's encryption on a response.
func setSSEHeaders(h http.Header, m *sse.Meta, clientMD5 string) {
	switch m.Mode {
	case sse.ModeS3:
		h.Set(hSSE, "AES256")
		h.Set(hSSEKeyID, "arn:aws:kms:"+m.KeyID)
	case sse.ModeKMS:
		h.Set(hSSE, "aws:kms")
		h.Set(hSSEKeyID, "arn:aws:kms:"+m.KeyID)
		if len(m.Context) > 0 {
			h.Set(hSSEContext, base64.StdEncoding.EncodeToString(m.Context))
		}
	case sse.ModeC:
		h.Set(ssecPrefix+"algorithm", "AES256")
		if clientMD5 != "" {
			h.Set(ssecPrefix+"key-MD5", clientMD5)
		}
	}
}

// setSSEHeadersFromInfo reports the encryption recorded in stored metadata
// (no key needed; SSE-C reports only the algorithm).
func setSSEHeadersFromInfo(h http.Header, ud map[string]string) {
	if m, ok, err := sse.ParseMeta(ud); ok && err == nil {
		setSSEHeaders(h, m, "")
	}
}

// verifyReader hashes the plaintext as it streams and, at the end, checks
// the digests the client declared. A declared digest that does not match is
// returned as a storage error, so it maps like the backend's own check.
type verifyReader struct {
	r       io.Reader
	md5     hash.Hash
	sha     hash.Hash
	wantMD5 string
	wantSHA string
	done    bool
}

func newVerifyReader(r io.Reader, wantMD5, wantSHA string) *verifyReader {
	v := &verifyReader{r: r, md5: md5.New(), wantMD5: wantMD5, wantSHA: wantSHA}
	if wantSHA != "" {
		v.sha = sha256.New()
	}
	return v
}

func (v *verifyReader) Read(p []byte) (int, error) {
	n, err := v.r.Read(p)
	if n > 0 {
		v.md5.Write(p[:n])
		if v.sha != nil {
			v.sha.Write(p[:n])
		}
	}
	if err == io.EOF && !v.done {
		v.done = true
		if v.wantMD5 != "" && !strings.EqualFold(v.wantMD5, hex.EncodeToString(v.md5.Sum(nil))) {
			return n, storage.ErrBadDigest
		}
		if v.sha != nil && !strings.EqualFold(v.wantSHA, hex.EncodeToString(v.sha.Sum(nil))) {
			return n, storage.ErrSHA256Mismatch
		}
	}
	return n, err
}

// MD5 is the hex MD5 of what has been read.
func (v *verifyReader) MD5() []byte { return v.md5.Sum(nil) }

// encryptedBody prepares the plaintext body of a single-part PutObject for
// storage: it encrypts under a fresh object key sealed as spec says, and
// fills opts (metadata, size, Finalize hook). The returned finish reports
// the plaintext ETag after the write.
func (s *Server) encryptedBody(q *request, spec *sseSpec, path string, body io.Reader, size int64, opts *storage.PutOptions) (r io.Reader, cipherSize int64, finish func() string, meta *sse.Meta, err error) {
	ok, m, err := sse.NewObjectKey(q.r.Context(), s.kms, spec.params(path))
	if err != nil {
		return nil, 0, nil, nil, s.sseError(q, spec.mode, err)
	}
	vr := newVerifyReader(body, opts.ContentMD5, opts.ContentSHA256)
	opts.ContentMD5, opts.ContentSHA256 = "", ""
	ud := make(map[string]string, len(opts.UserDefined)+8)
	for k, v := range opts.UserDefined {
		ud[k] = v
	}
	m.Put(ud)
	opts.UserDefined = ud
	opts.Finalize = func() map[string]string {
		defer kms.Zero(ok)
		sealed, err := sse.SealETag(ok, path, vr.MD5())
		if err != nil {
			return nil
		}
		return map[string]string{sse.KeyETag: base64.StdEncoding.EncodeToString(sealed)}
	}
	enc := sse.NewEncrypter(vr, sse.PartKey(ok, 1))
	return enc, sse.CipherSize(size), func() string { return hex.EncodeToString(vr.MD5()) }, m, nil
}

// uploadEncryption opens the object key of an encrypted multipart upload
// from its stored metadata. It returns (nil, nil) for an unencrypted
// upload.
func (s *Server) uploadEncryption(q *request, id string, prefix string) (*encObject, map[string]string, error) {
	res, err := s.st.ListObjectParts(q.r.Context(), q.bucket, q.key, id, storage.ListPartsOptions{PartNumberMarker: 1 << 30, MaxParts: 1})
	if err != nil {
		return nil, nil, err
	}
	enc, err := s.openEncrypted(q, storage.ObjectInfo{Bucket: q.bucket, Name: q.key, UserDefined: res.UserDefined, Size: sse.CipherSize(0)}, prefix)
	return enc, res.UserDefined, err
}

// ctxFor returns q's context; a small helper to keep call sites short.
func (q *request) ctx() context.Context { return q.r.Context() }
