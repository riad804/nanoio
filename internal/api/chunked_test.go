package api

import (
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

func TestChunkedReaderDecodes(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"signed chunks", "5;chunk-signature=abc\r\nhello\r\n6;chunk-signature=def\r\n world\r\n0;chunk-signature=zzz\r\n\r\n", "hello world"},
		{"unsigned with trailer", "5\r\nhello\r\n0\r\nx-amz-checksum-crc32:AAAAAA==\r\n\r\n", "hello"},
		{"signed trailer", "3;chunk-signature=a\r\nabc\r\n0;chunk-signature=b\r\nx-amz-checksum-sha256:Zm9v\r\nx-amz-trailer-signature:cc\r\n\r\n", "abc"},
		{"empty payload", "0\r\n\r\n", ""},
		{"uppercase hex size", "A\r\n0123456789\r\n0\r\n\r\n", "0123456789"},
		{"data containing CRLF", "4\r\n\r\n\r\n\r\n0\r\n\r\n", "\r\n\r\n"},
		{"many tiny chunks", strings.Repeat("1\r\nx\r\n", 100) + "0\r\n\r\n", strings.Repeat("x", 100)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := io.ReadAll(newChunkedReader(strings.NewReader(tt.in), -1, nil))
			if err != nil || string(got) != tt.want {
				t.Errorf("got %q, %v; want %q", got, err, tt.want)
			}
			// Same result when the source dribbles one byte at a time.
			got, err = io.ReadAll(newChunkedReader(iotest.OneByteReader(strings.NewReader(tt.in)), -1, nil))
			if err != nil || string(got) != tt.want {
				t.Errorf("one-byte source: got %q, %v", got, err)
			}
			// And when the consumer reads one byte at a time.
			got, err = io.ReadAll(iotest.OneByteReader(newChunkedReader(strings.NewReader(tt.in), -1, nil)))
			if err != nil || string(got) != tt.want {
				t.Errorf("one-byte consumer: got %q, %v", got, err)
			}
		})
	}
}

func TestChunkedReaderRejects(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    error
		wantGot string // bytes delivered before the error
	}{
		{"truncated inside data", "5\r\nhel", io.ErrUnexpectedEOF, "hel"},
		{"no final chunk", "5\r\nhello\r\n", io.ErrUnexpectedEOF, "hello"},
		{"empty body", "", io.ErrUnexpectedEOF, ""},
		{"trailer never terminated", "0\r\nx-amz-checksum-crc32:AA\r\n", io.ErrUnexpectedEOF, ""},
		{"non-hex size", "zz\r\nab\r\n0\r\n\r\n", errChunkFormat, ""},
		{"negative size", "-5\r\nhello\r\n", errChunkFormat, ""},
		{"empty size", ";chunk-signature=x\r\n", errChunkFormat, ""},
		{"data not followed by CRLF", "5\r\nhelloXX0\r\n\r\n", errChunkFormat, "hello"},
		{"bare LF line ending", "5\nhello\r\n0\r\n\r\n", errChunkFormat, ""},
		{"absurd chunk size", "FFFFFFFFFF\r\n", errChunkFormat, ""},
		{"size line too long", strings.Repeat("a", 70000) + "\r\n", errChunkFormat, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := io.ReadAll(newChunkedReader(strings.NewReader(tt.in), -1, nil))
			if !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
			if string(got) != tt.wantGot {
				t.Errorf("delivered %q before the error, want %q", got, tt.wantGot)
			}
			// The error is sticky.
			if _, err2 := newChunkedReader(strings.NewReader(tt.in), -1, nil).Read(make([]byte, 1)); tt.wantGot == "" && err2 == nil {
				t.Error("first read succeeded on an invalid body")
			}
		})
	}
}

func TestChunkedReaderStopsAtFinalChunk(t *testing.T) {
	r := strings.NewReader("2\r\nhi\r\n0\r\n\r\nEXTRA")
	cr := newChunkedReader(r, -1, nil)
	got, err := io.ReadAll(cr)
	if err != nil || string(got) != "hi" {
		t.Fatalf("got %q, %v", got, err)
	}
	if n, err := cr.Read(make([]byte, 8)); n != 0 || err != io.EOF {
		t.Errorf("read after end = %d, %v; want 0, EOF", n, err)
	}
}

// With a declared length the reader must reject malformed framing before
// delivering the last byte, because the consumer stops reading there.
func TestChunkedReaderValidatesAgainstDeclaredLength(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    int64
		wantErr error // nil = decodes cleanly
		wantGot string
	}{
		{"exact", "5\r\nhello\r\n0\r\n\r\n", 5, nil, "hello"},
		{"exact with trailer", "5\r\nhello\r\n0\r\nx-amz-checksum-crc32:AA==\r\n\r\n", 5, nil, "hello"},
		{"exact across chunks", "2\r\nhe\r\n3\r\nllo\r\n0\r\n\r\n", 5, nil, "hello"},
		{"zero length", "0\r\n\r\n", 0, nil, ""},
		{"terminator missing", "5\r\nhello\r\n", 5, io.ErrUnexpectedEOF, "hello"},
		{"terminator truncated", "5\r\nhello\r\n0\r\n", 5, io.ErrUnexpectedEOF, "hello"},
		{"more chunks than declared", "5\r\nhello\r\n1\r\n!\r\n0\r\n\r\n", 5, errChunkFormat, "hello"},
		{"chunk straddles declared end", "8\r\nhello!!!\r\n0\r\n\r\n", 5, errChunkFormat, "hello"},
		{"short payload", "3\r\nabc\r\n0\r\n\r\n", 5, nil, "abc"}, // storage reports IncompleteBody
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := io.ReadAll(newChunkedReader(strings.NewReader(tt.in), tt.want, nil))
			if !errors.Is(err, tt.wantErr) && !(tt.wantErr == nil && err == nil) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
			if string(got) != tt.wantGot {
				t.Errorf("got %q, want %q", got, tt.wantGot)
			}
		})
	}
	// The consumer stops at the declared size, as storage does (io.Copy over
	// a LimitReader): the error must still surface on that final read.
	cr := newChunkedReader(strings.NewReader("5\r\nhello\r\n"), 5, nil)
	n, err := io.Copy(io.Discard, io.LimitReader(cr, 5))
	if n != 5 || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("Copy = %d, %v; want 5 bytes and ErrUnexpectedEOF", n, err)
	}
}
