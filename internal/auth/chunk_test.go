package auth

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

// The example from the AWS S3 documentation, "Signature Calculations for the
// Authorization Header: Transferring Payload in Multiple Chunks (Chunked
// Upload)": a 65536-byte chunk and a 1024-byte chunk of 'a', then the empty
// final chunk, signed with the documented example secret key.
func TestChunkChainAWSDocumentationExample(t *testing.T) {
	const (
		secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
		seed   = "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9"
	)
	at := time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)
	chunks := []struct {
		data []byte
		sig  string
	}{
		{bytes.Repeat([]byte("a"), 65536), "ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648"},
		{bytes.Repeat([]byte("a"), 1024), "0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497"},
		{nil, "b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9"},
	}
	s := Signer{AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: secret}
	t.Run("sign", func(t *testing.T) {
		cs := s.NewChunkSigner(seed, at, false)
		for i, c := range chunks {
			if got := cs.SignChunk(c.data); got != c.sig {
				t.Fatalf("chunk %d signature = %s, want %s", i, got, c.sig)
			}
		}
	})
	t.Run("verify", func(t *testing.T) {
		cs := s.NewChunkSigner(seed, at, false)
		for i, c := range chunks {
			if err := cs.VerifyChunk(c.data, c.sig); err != nil {
				t.Fatalf("chunk %d: %v", i, err)
			}
		}
	})
}

func TestChunkChainRejectsTampering(t *testing.T) {
	s := Signer{AccessKey: "alice", SecretKey: "alice-secret-key-1234"}
	seed := "00" + string(bytes.Repeat([]byte("a"), 62))
	mk := func() *ChunkSigner { return s.NewChunkSigner(seed, now, false) }
	signAll := func(parts ...string) []string {
		cs := mk()
		var sigs []string
		for _, p := range parts {
			sigs = append(sigs, cs.SignChunk([]byte(p)))
		}
		return sigs
	}
	sigs := signAll("hello", " world", "")

	t.Run("honest chain verifies", func(t *testing.T) {
		cs := mk()
		for i, p := range []string{"hello", " world", ""} {
			if err := cs.VerifyChunk([]byte(p), sigs[i]); err != nil {
				t.Fatalf("chunk %d: %v", i, err)
			}
		}
	})
	tests := []struct {
		name   string
		feed   [][2]string // data, signature
		failAt int
	}{
		{"modified data", [][2]string{{"hellp", sigs[0]}}, 0},
		{"modified later data", [][2]string{{"hello", sigs[0]}, {" w0rld", sigs[1]}}, 1},
		{"chunks reordered", [][2]string{{" world", sigs[1]}}, 0},
		{"chunk dropped", [][2]string{{"hello", sigs[0]}, {"", sigs[2]}}, 1},
		{"chunk replayed", [][2]string{{"hello", sigs[0]}, {"hello", sigs[0]}}, 1},
		{"signature garbage", [][2]string{{"hello", "zzzz"}}, 0},
		{"empty signature", [][2]string{{"hello", ""}}, 0},
		{"data appended after final", [][2]string{{"hello", sigs[0]}, {" world", sigs[1]}, {"extra", sigs[2]}}, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cs := mk()
			for i, f := range tt.feed {
				err := cs.VerifyChunk([]byte(f[0]), f[1])
				if i < tt.failAt && err != nil {
					t.Fatalf("chunk %d unexpectedly failed: %v", i, err)
				}
				if i == tt.failAt {
					if !errors.Is(err, ErrSignatureDoesNotMatch) {
						t.Fatalf("chunk %d error = %v, want ErrSignatureDoesNotMatch", i, err)
					}
					return
				}
			}
			t.Fatal("tampering was not detected")
		})
	}
	t.Run("a different request seed breaks the chain", func(t *testing.T) {
		other := s.NewChunkSigner("11"+string(bytes.Repeat([]byte("b"), 62)), now, false)
		if err := other.VerifyChunk([]byte("hello"), sigs[0]); !errors.Is(err, ErrSignatureDoesNotMatch) {
			t.Errorf("error = %v", err)
		}
	})
	t.Run("a different key breaks the chain", func(t *testing.T) {
		other := Signer{AccessKey: "alice", SecretKey: "another-secret-key"}.NewChunkSigner(seed, now, false)
		if err := other.VerifyChunk([]byte("hello"), sigs[0]); !errors.Is(err, ErrSignatureDoesNotMatch) {
			t.Errorf("error = %v", err)
		}
	})
}

func TestTrailerSignature(t *testing.T) {
	s := Signer{AccessKey: "alice", SecretKey: "alice-secret-key-1234"}
	seed := string(bytes.Repeat([]byte("c"), 64))
	trailer := "x-amz-checksum-crc32:AAAAAA==\n"

	cs := s.NewChunkSigner(seed, now, true)
	cs.SignChunk([]byte("data"))
	cs.SignChunk(nil)
	sig := cs.SignTrailer(trailer)

	v := s.NewChunkSigner(seed, now, true)
	if err := v.VerifyChunk([]byte("data"), s.NewChunkSigner(seed, now, true).SignChunk([]byte("data"))); err != nil {
		t.Fatal(err)
	}
	if err := v.VerifyChunk(nil, signFinal(s, seed)); err != nil {
		t.Fatal(err)
	}
	if err := v.VerifyTrailer(trailer, sig); err != nil {
		t.Errorf("honest trailer: %v", err)
	}
	if err := v.VerifyTrailer("x-amz-checksum-crc32:BBBBBB==\n", sig); !errors.Is(err, ErrSignatureDoesNotMatch) {
		t.Errorf("modified trailer error = %v", err)
	}
	if err := v.VerifyTrailer(trailer, "deadbeef"); !errors.Is(err, ErrSignatureDoesNotMatch) {
		t.Errorf("bad trailer signature error = %v", err)
	}
}

func signFinal(s Signer, seed string) string {
	cs := s.NewChunkSigner(seed, now, true)
	cs.SignChunk([]byte("data"))
	return cs.SignChunk(nil)
}

func TestStreamingResultCarriesChunkSigner(t *testing.T) {
	tests := []struct {
		payload     string
		wantChunk   bool
		wantTrailer bool
	}{
		{emptySHA256, false, false},
		{PayloadUnsigned, false, false},
		{PayloadStreamingUnsigned, false, false},
		{PayloadStreamingSigned, true, false},
		{PayloadStreamingTrailer, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.payload, func(t *testing.T) {
			r := newReq("PUT", "/bucket/k", map[string]string{"X-Amz-Decoded-Content-Length": "5", "Content-Encoding": "aws-chunked"})
			seed := signer.Sign(r, tt.payload, now)
			res, err := verifier().Authenticate(r)
			if err != nil {
				t.Fatal(err)
			}
			if (res.Chunk != nil) != tt.wantChunk {
				t.Fatalf("Chunk present = %v, want %v", res.Chunk != nil, tt.wantChunk)
			}
			if res.Chunk == nil {
				return
			}
			if res.Chunk.Trailer != tt.wantTrailer {
				t.Errorf("Trailer = %v", res.Chunk.Trailer)
			}
			// The chain continues from the header signature: a client that
			// signs chunks with the seed produces what the server verifies.
			client := signer.NewChunkSigner(seed, now, tt.wantTrailer)
			if err := res.Chunk.VerifyChunk([]byte("hello"), client.SignChunk([]byte("hello"))); err != nil {
				t.Errorf("client-signed chunk rejected: %v", err)
			}
		})
	}
}
