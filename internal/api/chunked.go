package api

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"nanoio/internal/auth"
)

// errChunkFormat marks a malformed aws-chunked body.
var errChunkFormat = errors.New("api: malformed aws-chunked payload")

const (
	maxChunkLine = 4096
	// maxChunkSize bounds an unsigned chunk; maxSignedChunk bounds a signed
	// one, which must be buffered whole before its signature can be checked.
	maxChunkSize   = 256 << 20
	maxSignedChunk = 16 << 20
)

// chunkedReader decodes the aws-chunked body encoding used by SigV4
// streaming uploads and by recent SDKs' trailing checksums:
//
//	<hex-size>[;chunk-signature=<sig>]\r\n<data>\r\n ... 0[;...]\r\n[trailer: v\r\n]*\r\n
//
// With a signer (STREAMING-AWS4-HMAC-SHA256-PAYLOAD[-TRAILER]) every chunk
// is buffered and its signature verified before any of its bytes is
// returned, and the final chunk and signed trailer are verified before the
// last byte is released. Without one the framing is parsed and trailers are
// skipped.
//
// When the decoded length is known (want >= 0, from
// x-amz-decoded-content-length) the reader validates the end of the stream
// before it hands over the final byte: storage stops reading at the
// declared size and would otherwise commit an object without ever seeing a
// missing terminator, a bad signature or surplus data.
type chunkedReader struct {
	br     *bufio.Reader
	signer *auth.ChunkSigner

	// Unsigned mode: bytes left in the current chunk.
	remaining int64
	// Signed mode: a verified chunk and how much of it was delivered.
	chunk    []byte
	chunkOff int

	want      int64 // declared decoded length, or -1 if unknown
	delivered int64
	done      bool
	err       error
}

func newChunkedReader(r io.Reader, want int64, signer *auth.ChunkSigner) *chunkedReader {
	return &chunkedReader{br: bufio.NewReaderSize(r, 64<<10), want: want, signer: signer}
}

func (c *chunkedReader) Read(p []byte) (int, error) {
	if c.err != nil {
		return 0, c.err
	}
	if c.done {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	var n int
	var err error
	if c.signer != nil {
		n, err = c.readSigned(p)
	} else {
		n, err = c.readUnsigned(p)
	}
	if err != nil {
		c.err = err
	}
	return n, err
}

func (c *chunkedReader) readUnsigned(p []byte) (int, error) {
	if c.remaining == 0 {
		if err := c.nextUnsignedChunk(); err != nil {
			return 0, err
		}
		if c.done {
			return 0, io.EOF
		}
	}
	if int64(len(p)) > c.remaining {
		p = p[:c.remaining]
	}
	if c.want >= 0 && int64(len(p)) > c.want-c.delivered {
		p = p[:c.want-c.delivered]
	}
	n, err := c.br.Read(p)
	c.remaining -= int64(n)
	c.delivered += int64(n)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	if err == nil && c.remaining == 0 {
		err = c.expectCRLF()
	}
	if err == nil && c.want >= 0 && c.delivered == c.want {
		if c.remaining > 0 {
			return n, fmt.Errorf("%w: chunk data exceeds x-amz-decoded-content-length", errChunkFormat)
		}
		err = c.finish()
	}
	return n, err
}

func (c *chunkedReader) readSigned(p []byte) (int, error) {
	if c.chunkOff >= len(c.chunk) {
		if err := c.loadSignedChunk(); err != nil {
			return 0, err
		}
		if c.done {
			return 0, io.EOF
		}
	}
	n := copy(p, c.chunk[c.chunkOff:])
	c.chunkOff += n
	c.delivered += int64(n)
	if c.chunkOff >= len(c.chunk) && c.want >= 0 && c.delivered == c.want {
		// All declared bytes are out: the stream must end here, with a
		// correctly signed zero-length chunk (and trailer).
		if err := c.finish(); err != nil {
			return n, err
		}
	}
	return n, nil
}

// splitChunkHeader parses "<hex-size>[;chunk-signature=<sig>]".
func splitChunkHeader(line []byte) (size int64, sig string, err error) {
	sizeField := line
	if i := bytes.IndexByte(line, ';'); i >= 0 {
		sizeField = line[:i]
		ext := strings.TrimSpace(string(line[i+1:]))
		if v, ok := strings.CutPrefix(ext, "chunk-signature="); ok {
			sig = v
		}
	}
	n, perr := strconv.ParseInt(string(bytes.TrimSpace(sizeField)), 16, 64)
	if perr != nil || n < 0 {
		return 0, "", fmt.Errorf("%w: bad chunk size %q", errChunkFormat, sizeField)
	}
	return n, sig, nil
}

func (c *chunkedReader) nextUnsignedChunk() error {
	line, err := c.readLine()
	if err != nil {
		return err
	}
	n, _, err := splitChunkHeader(line)
	if err != nil {
		return err
	}
	if n > maxChunkSize {
		return fmt.Errorf("%w: chunk size %d too large", errChunkFormat, n)
	}
	if n > 0 {
		c.remaining = n
		return nil
	}
	return c.skipTrailers()
}

// loadSignedChunk reads and verifies the next chunk. For the zero-length
// final chunk it verifies the signature and the trailer, and marks done.
func (c *chunkedReader) loadSignedChunk() error {
	line, err := c.readLine()
	if err != nil {
		return err
	}
	n, sig, err := splitChunkHeader(line)
	if err != nil {
		return err
	}
	if sig == "" {
		return fmt.Errorf("%w: chunk is missing its signature", auth.ErrSignatureDoesNotMatch)
	}
	if n == 0 {
		return c.finalSigned(sig)
	}
	if n > maxSignedChunk {
		return fmt.Errorf("%w: signed chunk of %d bytes exceeds the %d byte limit", errChunkFormat, n, maxSignedChunk)
	}
	if c.want >= 0 && c.delivered+n > c.want {
		return fmt.Errorf("%w: payload exceeds x-amz-decoded-content-length", errChunkFormat)
	}
	if cap(c.chunk) < int(n) {
		c.chunk = make([]byte, n)
	}
	c.chunk = c.chunk[:n]
	if _, err := io.ReadFull(c.br, c.chunk); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return err
	}
	if err := c.expectCRLF(); err != nil {
		return err
	}
	if err := c.signer.VerifyChunk(c.chunk, sig); err != nil {
		c.chunk = c.chunk[:0]
		return err
	}
	c.chunkOff = 0
	return nil
}

// finalSigned verifies the zero-length chunk's signature (already parsed
// from its header) and the trailer that follows it.
func (c *chunkedReader) finalSigned(sig string) error {
	if err := c.signer.VerifyChunk(nil, sig); err != nil {
		return err
	}
	c.chunk, c.chunkOff = nil, 0
	if !c.signer.Trailer {
		l, err := c.readLine()
		if err != nil {
			return err
		}
		if len(l) != 0 {
			return fmt.Errorf("%w: unexpected data after the final chunk", errChunkFormat)
		}
		c.done = true
		return nil
	}
	var canonical strings.Builder
	trailerSig := ""
	for lines := 0; ; lines++ {
		if lines > 64 {
			return fmt.Errorf("%w: too many trailer lines", errChunkFormat)
		}
		l, err := c.readLine()
		if err != nil {
			return err
		}
		if len(l) == 0 {
			break
		}
		name, value, ok := strings.Cut(string(l), ":")
		if !ok {
			return fmt.Errorf("%w: bad trailer line", errChunkFormat)
		}
		name = strings.ToLower(strings.TrimSpace(name))
		value = strings.TrimSpace(value)
		if name == "x-amz-trailer-signature" {
			trailerSig = value
			continue
		}
		canonical.WriteString(name + ":" + value + "\n")
	}
	if trailerSig == "" {
		return fmt.Errorf("%w: trailer is missing x-amz-trailer-signature", auth.ErrSignatureDoesNotMatch)
	}
	if err := c.signer.VerifyTrailer(canonical.String(), trailerSig); err != nil {
		return err
	}
	c.done = true
	return nil
}

// finish runs when the declared number of bytes has been delivered: the
// payload must end exactly here, with a zero-size chunk and its trailers.
func (c *chunkedReader) finish() error {
	line, err := c.readLine()
	if err != nil {
		return err
	}
	n, sig, err := splitChunkHeader(line)
	if err != nil {
		return err
	}
	if n != 0 {
		return fmt.Errorf("%w: payload continues past x-amz-decoded-content-length", errChunkFormat)
	}
	if c.signer != nil {
		if sig == "" {
			return fmt.Errorf("%w: final chunk is missing its signature", auth.ErrSignatureDoesNotMatch)
		}
		return c.finalSigned(sig)
	}
	return c.skipTrailers()
}

// skipTrailers consumes trailer lines through the terminating blank line.
func (c *chunkedReader) skipTrailers() error {
	for lines := 0; ; lines++ {
		if lines > 64 {
			return fmt.Errorf("%w: too many trailer lines", errChunkFormat)
		}
		l, err := c.readLine()
		if err != nil {
			return err
		}
		if len(l) == 0 {
			c.done = true
			return nil
		}
	}
}

// readLine returns one CRLF-terminated line without its terminator.
func (c *chunkedReader) readLine() ([]byte, error) {
	line, err := c.br.ReadSlice('\n')
	switch {
	case errors.Is(err, bufio.ErrBufferFull) || len(line) > maxChunkLine:
		return nil, fmt.Errorf("%w: line too long", errChunkFormat)
	case err == io.EOF:
		return nil, io.ErrUnexpectedEOF
	case err != nil:
		return nil, err
	}
	if len(line) < 2 || line[len(line)-2] != '\r' {
		return nil, fmt.Errorf("%w: line not terminated by CRLF", errChunkFormat)
	}
	return line[:len(line)-2], nil
}

func (c *chunkedReader) expectCRLF() error {
	var crlf [2]byte
	if _, err := io.ReadFull(c.br, crlf[:]); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return err
	}
	if crlf != [2]byte{'\r', '\n'} {
		return fmt.Errorf("%w: chunk data not followed by CRLF", errChunkFormat)
	}
	return nil
}
