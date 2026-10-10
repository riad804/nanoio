// Package auth implements AWS Signature Version 4: verification of header
// and presigned-URL authentication, streaming (aws-chunked) payload
// signatures, and a client-side signer used by tests and tools.
//
// It knows nothing about users or policies: credentials come through the
// CredentialProvider interface and authorisation lives in package iam.
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	// Algorithm is the only signing scheme supported.
	Algorithm = "AWS4-HMAC-SHA256"
	// Terminator ends every credential scope.
	Terminator = "aws4_request"

	amzDateLayout   = "20060102T150405Z"
	scopeDateLayout = "20060102"
	emptySHA256     = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// Payload hash sentinels carried in x-amz-content-sha256.
const (
	PayloadUnsigned          = "UNSIGNED-PAYLOAD"
	PayloadStreamingSigned   = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
	PayloadStreamingTrailer  = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
	PayloadStreamingUnsigned = "STREAMING-UNSIGNED-PAYLOAD-TRAILER"
)

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// signingKey derives the SigV4 signing key for one date/region/service.
func signingKey(secret, date, region, service string) []byte {
	k := hmacSHA256([]byte("AWS4"+secret), date)
	k = hmacSHA256(k, region)
	k = hmacSHA256(k, service)
	return hmacSHA256(k, Terminator)
}

// scopeString is "<date>/<region>/<service>/aws4_request".
func scopeString(date, region, service string) string {
	return date + "/" + region + "/" + service + "/" + Terminator
}

// uriEncode percent-encodes everything but the RFC 3986 unreserved set, and
// optionally '/'. Hex digits are uppercase, as SigV4 requires.
func uriEncode(s string, keepSlash bool) string {
	const hexdigits = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		case c == '/' && keepSlash:
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hexdigits[c>>4])
			b.WriteByte(hexdigits[c&0x0f])
		}
	}
	return b.String()
}

// canonicalURIS3 is the S3 canonical path: the decoded path encoded exactly
// once, with no normalisation (S3 keys may legitimately contain "//" or
// "..").
func canonicalURIS3(decodedPath string) string {
	if decodedPath == "" {
		return "/"
	}
	return uriEncode(decodedPath, true)
}

// canonicalURIGeneric is the canonical path of every other AWS service: dot
// segments and repeated slashes are removed, then the path is encoded.
func canonicalURIGeneric(rawPath string) string {
	if rawPath == "" {
		return "/"
	}
	var stack []string
	segs := strings.Split(rawPath, "/")
	for _, s := range segs {
		switch s {
		case "", ".":
		case "..":
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		default:
			stack = append(stack, s)
		}
	}
	out := "/" + strings.Join(stack, "/")
	last := segs[len(segs)-1]
	if len(stack) > 0 && (last == "" || last == "." || last == "..") {
		out += "/"
	}
	return uriEncode(out, true)
}

// canonicalQuery sorts and re-encodes the query string. Pairs for which
// skip(name) is true are dropped (X-Amz-Signature in presigned URLs).
func canonicalQuery(rawQuery string, skip func(name string) bool) string {
	if rawQuery == "" {
		return ""
	}
	type kv struct{ k, v string }
	var pairs []kv
	for _, part := range strings.Split(rawQuery, "&") {
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		if dk, err := url.QueryUnescape(k); err == nil {
			k = dk
		}
		if dv, err := url.QueryUnescape(v); err == nil {
			v = dv
		}
		if skip != nil && skip(k) {
			continue
		}
		pairs = append(pairs, kv{uriEncode(k, false), uriEncode(v, false)})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].k != pairs[j].k {
			return pairs[i].k < pairs[j].k
		}
		return pairs[i].v < pairs[j].v
	})
	parts := make([]string, len(pairs))
	for i, p := range pairs {
		parts[i] = p.k + "=" + p.v
	}
	return strings.Join(parts, "&")
}

// headerSet maps lowercase header names to their values in arrival order.
type headerSet map[string][]string

// canonicalHeaders renders "name:value\n" for each signed header. Values are
// trimmed and runs of whitespace (including unfolded line breaks) collapse
// to one space; repeated headers are joined with ",". ok is false if a
// signed header is absent.
func canonicalHeaders(h headerSet, signed []string) (string, bool) {
	var b strings.Builder
	for _, name := range signed {
		vals, present := h[name]
		if !present {
			return "", false
		}
		norm := make([]string, len(vals))
		for i, v := range vals {
			norm[i] = strings.Join(strings.Fields(v), " ")
		}
		b.WriteString(name)
		b.WriteByte(':')
		b.WriteString(strings.Join(norm, ","))
		b.WriteByte('\n')
	}
	return b.String(), true
}

// canonicalRequest assembles the six-part canonical request.
func canonicalRequest(method, uri, query, headers string, signed []string, payloadHash string) string {
	return method + "\n" + uri + "\n" + query + "\n" + headers + "\n" +
		strings.Join(signed, ";") + "\n" + payloadHash
}

// stringToSign is the value that is actually HMAC-ed.
func stringToSign(amzDate, scope, canonical string) string {
	return Algorithm + "\n" + amzDate + "\n" + scope + "\n" + sha256Hex([]byte(canonical))
}

// sortedLower returns names lowercased, deduplicated and sorted.
func sortedLower(names []string) []string {
	seen := make(map[string]bool, len(names))
	out := make([]string, 0, len(names))
	for _, n := range names {
		n = strings.ToLower(strings.TrimSpace(n))
		if n != "" && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

func parseAmzDate(s string) (time.Time, error) {
	return time.Parse(amzDateLayout, s)
}
