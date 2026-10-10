package auth

import (
	"crypto/hmac"
	"encoding/hex"
	"time"
)

// ChunkSigner signs or verifies the chunks of a streaming
// (STREAMING-AWS4-HMAC-SHA256-PAYLOAD) upload. Each chunk signature covers
// the previous one, so a chunk cannot be dropped, reordered or replayed.
// A ChunkSigner is single-use and not safe for concurrent use.
type ChunkSigner struct {
	key     []byte
	amzDate string
	scope   string
	prev    string
	// Trailer is true for the -TRAILER variant, where a signed trailer
	// follows the final chunk.
	Trailer bool
}

func newChunkSigner(key []byte, amzDate, scope, seedSignature string, trailer bool) *ChunkSigner {
	return &ChunkSigner{key: key, amzDate: amzDate, scope: scope, prev: seedSignature, Trailer: trailer}
}

func (c *ChunkSigner) chunkSignature(data []byte) string {
	sts := "AWS4-HMAC-SHA256-PAYLOAD\n" + c.amzDate + "\n" + c.scope + "\n" +
		c.prev + "\n" + emptySHA256 + "\n" + sha256Hex(data)
	return hex.EncodeToString(hmacSHA256(c.key, sts))
}

// SignChunk returns the signature for the next chunk and advances the
// chain. Pass an empty slice for the final zero-length chunk.
func (c *ChunkSigner) SignChunk(data []byte) string {
	sig := c.chunkSignature(data)
	c.prev = sig
	return sig
}

// VerifyChunk checks sig against the next chunk and advances the chain.
func (c *ChunkSigner) VerifyChunk(data []byte, sig string) error {
	want := c.chunkSignature(data)
	if !equalHex(want, sig) {
		return ErrSignatureDoesNotMatch
	}
	c.prev = want
	return nil
}

func (c *ChunkSigner) trailerSignature(canonicalTrailer string) string {
	sts := "AWS4-HMAC-SHA256-TRAILER\n" + c.amzDate + "\n" + c.scope + "\n" +
		c.prev + "\n" + sha256Hex([]byte(canonicalTrailer))
	return hex.EncodeToString(hmacSHA256(c.key, sts))
}

// SignTrailer signs the canonical trailer ("name:value\n" per header, in
// order, without the signature header itself).
func (c *ChunkSigner) SignTrailer(canonicalTrailer string) string {
	return c.trailerSignature(canonicalTrailer)
}

// VerifyTrailer checks the x-amz-trailer-signature of a signed trailer.
func (c *ChunkSigner) VerifyTrailer(canonicalTrailer, sig string) error {
	if !equalHex(c.trailerSignature(canonicalTrailer), sig) {
		return ErrSignatureDoesNotMatch
	}
	return nil
}

// equalHex compares two hex signatures in constant time.
func equalHex(want, got string) bool {
	return hmac.Equal([]byte(want), []byte(got))
}

// NewChunkSigner starts a chunk chain for a request signed by s at time t
// whose header signature was seed. It is the client-side counterpart of
// what Verifier.Authenticate returns for streaming uploads.
func (s Signer) NewChunkSigner(seedSignature string, t time.Time, trailer bool) *ChunkSigner {
	region, service := s.regionService()
	date := t.UTC().Format(scopeDateLayout)
	return newChunkSigner(signingKey(s.SecretKey, date, region, service),
		t.UTC().Format(amzDateLayout), scopeString(date, region, service), seedSignature, trailer)
}
