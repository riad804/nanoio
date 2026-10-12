package api

import (
	"encoding/xml"
	"io"
	"net/http"
	"strings"

	"nanoio/internal/kms"
	"nanoio/internal/sse"
	"nanoio/internal/storage"
)

// copyObjectResult is the CopyObject response body.
type copyObjectResult struct {
	XMLName      xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ CopyObjectResult"`
	LastModified string   `xml:"LastModified"`
	ETag         string   `xml:"ETag"`
}

// sseHeadersPresent reports whether the request itself names an encryption
// mode (as opposed to getting one from the bucket's default).
func sseHeadersPresent(h http.Header) bool {
	return h.Get(hSSE) != "" || h.Get(hSSEKeyID) != "" || h.Get(hSSEContext) != "" || hasSSECHeaders(h, ssecPrefix)
}

// copyObject implements PUT with x-amz-copy-source.
//
// Copying an object onto itself is done in place and, when the data does
// not have to change representation, without reading it: the metadata is
// updated, and the object key is re-sealed under the requested encryption
// (this is how a client rotates an SSE-C key or moves an object between
// encryption modes). Every other copy streams the source through decryption
// and the destination's encryption.
func (s *Server) copyObject(q *request) {
	h := q.r.Header
	src, aerr := parseCopySource(h.Get("x-amz-copy-source"))
	if aerr != nil {
		s.fail(q, aerr)
		return
	}
	action := "s3:GetObject"
	if src.versionID != "" {
		action = "s3:GetObjectVersion"
	}
	if !s.authorize(q, action, src.bucket, src.key, nil) {
		return
	}
	if src.bucket == sysBucket {
		s.fail(q, storage.ErrBucketNotFound)
		return
	}
	directive := strings.ToUpper(strings.TrimSpace(h.Get("x-amz-metadata-directive")))
	switch directive {
	case "":
		directive = "COPY"
	case "COPY", "REPLACE":
	default:
		s.fail(q, invalidArgument("Unknown metadata directive."))
		return
	}
	if h.Get("x-amz-tagging-directive") != "" || h.Get("x-amz-storage-class") != "" && h.Get("x-amz-storage-class") != "STANDARD" {
		s.fail(q, notImplemented("tagging directive or storage class on CopyObject"))
		return
	}
	newMeta, err := parseObjectMeta(h)
	if err != nil {
		s.fail(q, err)
		return
	}
	lock, aerr := parseLockHeaders(h)
	if aerr != nil {
		s.fail(q, aerr)
		return
	}
	if !s.authorizeLockHeaders(q, lock) {
		return
	}
	spec, err := s.writeSpec(q, q.bucket)
	if err != nil {
		s.fail(q, err)
		return
	}
	if spec != nil {
		defer kms.Zero(spec.clientKey)
	}
	explicit := sseHeadersPresent(h)

	ctx := q.r.Context()
	rc, info, err := s.st.GetObject(ctx, src.bucket, src.key, storage.GetOptions{VersionID: src.versionID})
	if err != nil {
		s.fail(q, err)
		return
	}
	defer rc.Close()
	srcEnc, err := s.openEncrypted(q, info, ssecCopyPrefix)
	if err != nil {
		s.fail(q, err)
		return
	}
	defer srcEnc.close()
	plainETag := info.ETag
	if srcEnc != nil {
		plainETag = srcEnc.etag
	}
	if copyConditionsFail(h, info, plainETag) {
		s.fail(q, errPrecondition)
		return
	}

	self := src.bucket == q.bucket && src.key == q.key
	inPlace := self && (src.versionID == "" || info.IsLatest)

	// The destination's metadata.
	var ud map[string]string
	ct := info.ContentType
	if directive == "REPLACE" {
		ud, ct = newMeta.UserDefined, newMeta.ContentType
		if ct == "" {
			ct = "binary/octet-stream"
		}
	} else {
		ud = sse.Strip(info.UserDefined)
	}

	dstPath := q.bucket + "/" + q.key
	srcVersion := info.VersionID

	if inPlace {
		changesEncryption := (srcEnc != nil && explicit) || (srcEnc == nil && spec != nil)
		if !changesEncryption && directive != "REPLACE" {
			s.fail(q, invalidRequest("This copy request is illegal because it is trying to copy an object to itself without changing the object's metadata, storage class, website redirect location or encryption attributes."))
			return
		}
		if lock.retention.Mode != "" || lock.hold {
			s.fail(q, invalidRequest("Object lock headers cannot be applied to an in-place copy."))
			return
		}
		if srcEnc != nil || spec == nil {
			// No data I/O: update the metadata, re-sealing the key if the
			// encryption changes.
			s.copyInPlace(q, info, srcEnc, spec, explicit, ud, ct, directive == "REPLACE", srcVersion, plainETag)
			return
		}
		// Plain object that must become encrypted: falls through to the
		// streaming path, which replaces it.
	}

	// Streaming copy: decrypt the source, encrypt per the destination.
	var body io.Reader = rc
	size := info.Size
	if srcEnc != nil {
		dec, err := sse.NewDecrypter(rc, srcEnc.layout, srcEnc.key, 0, srcEnc.size)
		if err != nil {
			s.fail(q, err)
			return
		}
		body, size = dec, srcEnc.size
	}
	opts := storage.PutOptions{ContentType: ct, UserDefined: ud, Retention: lock.retention, LegalHold: lock.hold}
	if self {
		opts.IfMatch = info.ETag // the object we read is the object we replace
	}
	var (
		finish func() string
		meta   *sse.Meta
	)
	if spec != nil {
		body, size, finish, meta, err = s.encryptedBody(q, spec, dstPath, body, size, &opts)
		if err != nil {
			s.fail(q, err)
			return
		}
	}
	put, err := s.st.PutObject(ctx, q.bucket, q.key, body, size, opts)
	if err != nil {
		s.fail(q, err)
		return
	}
	etag := put.ETag
	if finish != nil {
		etag = finish()
	}
	rh := q.w.Header()
	if srcVersion != "" {
		rh.Set("x-amz-copy-source-version-id", srcVersion)
	}
	if put.VersionID != "" {
		rh.Set("x-amz-version-id", put.VersionID)
	}
	if meta != nil {
		setSSEHeaders(rh, meta, ssecKeyMD5(spec))
	}
	s.writeXML(q, http.StatusOK, &copyObjectResult{LastModified: isoTime(put.ModTime), ETag: `"` + etag + `"`})
}

// copyInPlace applies a self-copy that needs no data I/O.
func (s *Server) copyInPlace(q *request, info storage.ObjectInfo, srcEnc *encObject, spec *sseSpec, explicit bool,
	ud map[string]string, ct string, replace bool, srcVersion, plainETag string) {
	out := make(map[string]string, len(ud)+8)
	for k, v := range ud {
		out[k] = v
	}
	var meta *sse.Meta
	clientMD5 := ""
	if srcEnc != nil {
		if explicit && spec != nil {
			// New encryption for the same object key: re-seal it.
			m, err := sse.Reseal(q.r.Context(), s.kms, srcEnc.key, spec.params(q.bucket+"/"+q.key))
			if err != nil {
				s.fail(q, s.sseError(q, spec.mode, err))
				return
			}
			m.ETag = srcEnc.meta.ETag
			m.Put(out)
			meta, clientMD5 = m, ssecKeyMD5(spec)
		} else {
			// Keep the encryption exactly as it is.
			for k, v := range info.UserDefined {
				if sse.IsReserved(k) {
					out[k] = v
				}
			}
			meta, clientMD5 = srcEnc.meta, srcEnc.clientMD5
		}
	}
	upd, err := s.st.UpdateObjectMetadata(q.r.Context(), q.bucket, q.key, storage.UpdateMetaOptions{
		VersionID: srcVersion, UserDefined: out, ContentType: ct, Touch: true, IfETag: info.ETag,
	})
	if err != nil {
		s.fail(q, err)
		return
	}
	h := q.w.Header()
	if srcVersion != "" {
		h.Set("x-amz-copy-source-version-id", srcVersion)
	}
	if upd.VersionID != "" {
		h.Set("x-amz-version-id", upd.VersionID)
	}
	if meta != nil {
		setSSEHeaders(h, meta, clientMD5)
	}
	s.writeXML(q, http.StatusOK, &copyObjectResult{LastModified: isoTime(upd.ModTime), ETag: `"` + plainETag + `"`})
}
