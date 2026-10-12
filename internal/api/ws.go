package api

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// A minimal RFC 6455 server: just enough for a one-way text stream. The
// server sends text frames and pings; it reads the client only to answer
// pings and notice a close. Fragmented messages from the client are
// ignored, which is fine because clients of the event stream send nothing.

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

const (
	wsText  = 0x1
	wsClose = 0x8
	wsPing  = 0x9
	wsPong  = 0xA
)

type wsConn struct {
	c    net.Conn
	br   *bufio.Reader
	wmu  sync.Mutex
	done chan struct{}
	once sync.Once
}

// isWebSocket reports whether r asks for a WebSocket upgrade.
func isWebSocket(r *http.Request) bool {
	return headerHasToken(r.Header, "Connection", "upgrade") && headerHasToken(r.Header, "Upgrade", "websocket")
}

func headerHasToken(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), token) {
				return true
			}
		}
	}
	return false
}

var errWSHandshake = errors.New("not a valid WebSocket handshake")

// wsAccept completes the handshake and takes over the connection.
func wsAccept(w http.ResponseWriter, r *http.Request) (*wsConn, error) {
	key := r.Header.Get("Sec-WebSocket-Key")
	if r.Method != http.MethodGet || key == "" || r.Header.Get("Sec-WebSocket-Version") != "13" {
		return nil, errWSHandshake
	}
	rc := http.NewResponseController(w)
	conn, brw, err := rc.Hijack()
	if err != nil {
		return nil, err
	}
	sum := sha1.Sum([]byte(key + wsGUID))
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + base64.StdEncoding.EncodeToString(sum[:]) + "\r\n\r\n"
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte(resp)); err != nil {
		conn.Close()
		return nil, err
	}
	conn.SetWriteDeadline(time.Time{})
	return &wsConn{c: conn, br: brw.Reader, done: make(chan struct{})}, nil
}

func (c *wsConn) writeFrame(op byte, payload []byte) error {
	var hdr [10]byte
	hdr[0] = 0x80 | op
	n := 2
	switch l := len(payload); {
	case l < 126:
		hdr[1] = byte(l)
	case l <= 0xffff:
		hdr[1] = 126
		binary.BigEndian.PutUint16(hdr[2:], uint16(l))
		n = 4
	default:
		hdr[1] = 127
		binary.BigEndian.PutUint64(hdr[2:], uint64(l))
		n = 10
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	c.c.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.c.Write(hdr[:n]); err != nil {
		return err
	}
	_, err := c.c.Write(payload)
	return err
}

// WriteText sends one text message.
func (c *wsConn) WriteText(p []byte) error { return c.writeFrame(wsText, p) }

// Close sends a close frame (best effort) and drops the connection.
func (c *wsConn) Close() {
	c.once.Do(func() {
		c.writeFrame(wsClose, []byte{0x03, 0xe8}) // 1000 normal closure
		c.c.Close()
		close(c.done)
	})
}

// Done is closed once the connection is gone.
func (c *wsConn) Done() <-chan struct{} { return c.done }

// readLoop consumes client frames until the connection ends, answering
// pings. It returns on close or error, after which the caller closes.
func (c *wsConn) readLoop() {
	defer c.Close()
	for {
		c.c.SetReadDeadline(time.Now().Add(2 * time.Minute))
		var h [2]byte
		if _, err := io.ReadFull(c.br, h[:]); err != nil {
			return
		}
		op := h[0] & 0x0f
		masked := h[1]&0x80 != 0
		l := uint64(h[1] & 0x7f)
		switch l {
		case 126:
			var b [2]byte
			if _, err := io.ReadFull(c.br, b[:]); err != nil {
				return
			}
			l = uint64(binary.BigEndian.Uint16(b[:]))
		case 127:
			var b [8]byte
			if _, err := io.ReadFull(c.br, b[:]); err != nil {
				return
			}
			l = binary.BigEndian.Uint64(b[:])
		}
		if !masked || l > 1<<20 {
			return // clients must mask; nothing legitimate is large
		}
		var mask [4]byte
		if _, err := io.ReadFull(c.br, mask[:]); err != nil {
			return
		}
		payload := make([]byte, l)
		if _, err := io.ReadFull(c.br, payload); err != nil {
			return
		}
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
		switch op {
		case wsPing:
			if c.writeFrame(wsPong, payload) != nil {
				return
			}
		case wsClose:
			return
		}
	}
}
