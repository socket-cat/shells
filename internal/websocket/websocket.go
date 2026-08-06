// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

// Package websocket implements a minimal RFC 6455 WebSocket transport using
// only the Go standard library. It provides an HTTP upgrader and a Conn type
// with a background write loop (for non-blocking sends and buffered-amount
// tracking) and a background read loop that demultiplexes data, ping/pong and
// close frames.
//
// This is the wire layer only; the shells application protocol (encrypted
// handshake, session attach, terminal relay, backpressure) lives in
// internal/wshandler.
package websocket

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// WebSocket opcodes (RFC 6455 §5.2).
const (
	OpContinuation byte = 0x0
	OpText         byte = 0x1
	OpBinary       byte = 0x2
	OpClose        byte = 0x8
	OpPing         byte = 0x9
	OpPong         byte = 0xA
)

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// MaxPayload is the hard limit on a single message (matches the JS
// WebSocketServer maxPayload of 1 MiB).
const MaxPayload = 1024 * 1024

// readDeadline caps idle time between frames. Server pings every 30 s
// (keepalive); browser auto-pongs, which readFrame sees and resets the
// deadline. 60 s is 2× the keepalive interval, giving ample margin.
const readDeadline = 60 * time.Second

// Upgrader accepts an HTTP request and negotiates the WebSocket handshake.
type Upgrader struct {
	// CheckOrigin returns true if the request origin is allowed. When nil,
	// all origins are accepted (the shells app applies its own check before
	// upgrading).
	CheckOrigin func(r *http.Request) bool
	// HandshakeTimeout bounds how long the full upgrade may take.
	HandshakeTimeout time.Duration
}

// Upgrade hijacks the underlying TCP connection, writes the 101 response, and
// returns a ready-to-use Conn. The caller sets OnMessage/OnClose and then
// calls Start to begin the I/O loops.
func (u *Upgrader) Upgrade(w http.ResponseWriter, r *http.Request) (*Conn, error) {
	if r.Method != http.MethodGet {
		http.Error(w, "WebSocket requires GET", http.StatusMethodNotAllowed)
		return nil, errors.New("websocket: method not GET")
	}
	if !headerContains(r.Header, "Connection", "upgrade") {
		http.Error(w, "missing Connection: Upgrade", http.StatusBadRequest)
		return nil, errors.New("websocket: missing Connection upgrade")
	}
	if !headerContains(r.Header, "Upgrade", "websocket") {
		http.Error(w, "missing Upgrade: websocket", http.StatusBadRequest)
		return nil, errors.New("websocket: missing Upgrade header")
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		http.Error(w, "missing Sec-WebSocket-Key", http.StatusBadRequest)
		return nil, errors.New("websocket: missing key")
	}

	if u.CheckOrigin != nil && !u.CheckOrigin(r) {
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return nil, errors.New("websocket: origin rejected")
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return nil, errors.New("websocket: hijack unsupported")
	}

	conn, brw, err := hj.Hijack()
	if err != nil {
		return nil, fmt.Errorf("websocket: hijack: %w", err)
	}

	accept := computeAccept(key)
	deadline := time.Time{}
	if u.HandshakeTimeout > 0 {
		deadline = time.Now().Add(u.HandshakeTimeout)
	}
	_ = conn.SetDeadline(deadline)
	if _, err = fmt.Fprintf(conn,
		"HTTP/1.1 101 Switching Protocols\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Accept: %s\r\n\r\n", accept); err != nil {
		conn.Close()
		return nil, fmt.Errorf("websocket: write handshake: %w", err)
	}
	_ = conn.SetDeadline(time.Time{})

	c := newConn(conn, brw.Reader)
	return c, nil
}

func computeAccept(key string) string {
	h := sha1.New()
	h.Write([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// headerContains reports whether the named header contains the token want
// (case-insensitive, comma-separated list per RFC 7230 §3.2.6).
func headerContains(h http.Header, name, want string) bool {
	for _, v := range h[http.CanonicalHeaderKey(name)] {
		for _, tok := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), want) {
				return true
			}
		}
	}
	return false
}

// Conn is a single WebSocket connection.
type Conn struct {
	conn net.Conn
	br   *bufio.Reader

	closed    atomic.Bool
	closeOnce sync.Once
	done      chan struct{}

	// Outbound queue: complete wire frames waiting for the write loop.
	queueMu  sync.Mutex
	queue    [][]byte
	cond     *sync.Cond
	closing  bool
	buffered atomic.Int64 // payload bytes queued, not yet on the wire

	// Public callbacks — set by the caller before Start.
	OnMessage func(payload []byte, isBinary bool)
	OnClose   func(code int, reason string)
}

func newConn(conn net.Conn, br *bufio.Reader) *Conn {
	setNoDelay(conn)
	c := &Conn{conn: conn, br: br, done: make(chan struct{})}
	c.cond = sync.NewCond(&c.queueMu)
	return c
}

// setNoDelay disables Nagle's algorithm on TCP-based connections so that small
// interactive frames (keystrokes, terminal echoes) are sent immediately instead
// of being held for a delayed ACK — critical for responsiveness over a tunneled
// link. It is a no-op for non-TCP conns (e.g. Unix sockets) and best-effort for
// TLS-wrapped conns.
func setNoDelay(c net.Conn) {
	type nodelayer interface{ SetNoDelay(bool) error }
	if nd, ok := c.(nodelayer); ok {
		_ = nd.SetNoDelay(true)
		return
	}
	type connGetter interface{ NetConn() net.Conn }
	if cg, ok := c.(connGetter); ok {
		if nd, ok := cg.NetConn().(nodelayer); ok {
			_ = nd.SetNoDelay(true)
		}
	}
}

// BufferedAmount returns the number of payload bytes queued for transmission
// but not yet written to the socket (mirrors ws.bufferedAmount in the JS app).
func (c *Conn) BufferedAmount() int64 { return c.buffered.Load() }

// Start launches the read and write loops. It blocks until the connection
// closes; run it in a goroutine.
func (c *Conn) Start() {
	go c.writeLoop()
	_ = c.conn.SetReadDeadline(time.Now().Add(readDeadline))
	c.readLoop()
}

// SendText enqueues a text frame. Returns false if the connection is closed.
func (c *Conn) SendText(data []byte) bool { return c.send(data, OpText) }

// SendBinary enqueues a binary frame. Returns false if closed.
func (c *Conn) SendBinary(data []byte) bool { return c.send(data, OpBinary) }

// SendPing enqueues a ping frame with the given payload (≤125 bytes).
func (c *Conn) SendPing(payload []byte) bool { return c.send(payload, OpPing) }

func (c *Conn) send(payload []byte, op byte) bool {
	if c.closed.Load() {
		return false
	}
	frame := encodeFrame(payload, op)
	c.queueMu.Lock()
	if c.closing {
		c.queueMu.Unlock()
		return false
	}
	c.queue = append(c.queue, frame)
	c.buffered.Add(int64(len(payload)))
	c.queueMu.Unlock()
	c.cond.Signal()
	return true
}

// Close sends a close frame with the given status code and reason, then
// terminates the connection.
func (c *Conn) Close(code int, reason string) {
	payload := make([]byte, 0, 2+len(reason))
	payload = binary.BigEndian.AppendUint16(payload, uint16(code))
	payload = append(payload, reason...)
	c.closeOnce.Do(func() {
		c.queueMu.Lock()
		c.closing = true
		c.queue = append(c.queue, encodeFrame(payload, OpClose))
		c.queueMu.Unlock()
		c.cond.Signal()
	})
}

// writeLoop drains the outbound queue and writes frames to the socket.
func (c *Conn) writeLoop() {
	for {
		c.queueMu.Lock()
		for len(c.queue) == 0 && !c.closing {
			c.cond.Wait()
		}
		frames := c.queue
		c.queue = nil
		shutdown := c.closing
		c.queueMu.Unlock()

		for _, f := range frames {
			if _, err := c.conn.Write(f); err != nil {
				c.terminate()
				return
			}
			c.buffered.Add(-payloadLenOf(f))
		}
		if shutdown {
			c.terminate()
			return
		}
	}
}

// payloadLenOf extracts the payload length from an encoded server frame.
func payloadLenOf(frame []byte) int64 {
	if len(frame) < 2 {
		return 0
	}
	l := frame[1] & 0x7f
	switch l {
	case 126:
		if len(frame) < 4 {
			return 0
		}
		return int64(binary.BigEndian.Uint16(frame[2:4]))
	case 127:
		if len(frame) < 10 {
			return 0
		}
		return int64(binary.BigEndian.Uint64(frame[2:10]))
	default:
		return int64(l)
	}
}

// readLoop reads inbound frames until the connection closes or errors.
func (c *Conn) readLoop() {
	var fragBuf []byte
	var fragOp byte

	for {
		_, payload, op, fin, err := readFrame(c.br)
		if err != nil {
			c.handleClose(-1, "")
			return
		}
		_ = c.conn.SetReadDeadline(time.Now().Add(readDeadline))
		switch op {
		case OpPing:
			c.send(payload, OpPong)
		case OpPong:
			// keepalive ack
		case OpClose:
			code, reason := parseClose(payload)
			c.Close(code, reason)
			c.handleClose(code, reason)
			return
		case OpText, OpBinary:
			if !fin {
				fragBuf = append(fragBuf[:0], payload...)
				fragOp = op
			} else {
				c.deliver(payload, op == OpBinary)
			}
		case OpContinuation:
			fragBuf = append(fragBuf, payload...)
			if len(fragBuf) > MaxPayload {
				c.handleClose(1009, "message too large")
				return
			}
			if fin {
				c.deliver(fragBuf, fragOp == OpBinary)
				fragBuf = fragBuf[:0]
			}
		default:
			c.handleClose(1002, "unsupported opcode")
			return
		}
	}
}

func (c *Conn) deliver(payload []byte, isBinary bool) {
	if c.OnMessage != nil {
		c.OnMessage(payload, isBinary)
	}
}

func (c *Conn) handleClose(code int, reason string) {
	c.closeOnce.Do(func() {})
	c.terminate()
	if c.OnClose != nil {
		c.OnClose(code, reason)
	}
}

func (c *Conn) terminate() {
	if !c.closed.CompareAndSwap(false, true) {
		return
	}
	c.queueMu.Lock()
	c.closing = true
	c.queueMu.Unlock()
	c.cond.Signal()
	_ = c.conn.Close()
	close(c.done)
}

// Done returns a channel closed when the connection terminates.
func (c *Conn) Done() <-chan struct{} { return c.done }

// --- frame codec ---

// encodeFrame builds a complete server→client frame (FIN=1, unmasked).
func encodeFrame(payload []byte, op byte) []byte {
	n := len(payload)
	hdr := []byte{0x80 | op} // FIN + opcode

	switch {
	case n < 126:
		hdr = append(hdr, byte(n))
	case n <= 65535:
		hdr = append(hdr, 126)
		hdr = binary.BigEndian.AppendUint16(hdr, uint16(n))
	default:
		hdr = append(hdr, 127)
		hdr = binary.BigEndian.AppendUint64(hdr, uint64(n))
	}

	frame := make([]byte, len(hdr)+n)
	copy(frame, hdr)
	copy(frame[len(hdr):], payload)
	return frame
}

// readFrame reads a single frame from the buffered reader.
func readFrame(br *bufio.Reader) (hdr []byte, payload []byte, op byte, fin bool, err error) {
	b2, err := br.Peek(2)
	if err != nil {
		return nil, nil, 0, false, err
	}
	_, _ = br.Discard(2)
	fin = b2[0]&0x80 != 0
	op = b2[0] & 0x0f
	masked := b2[1]&0x80 != 0
	length := int64(b2[1] & 0x7f)

	// RSV bits must be zero unless an extension is negotiated.
	if b2[0]&0x70 != 0 {
		return nil, nil, 0, false, fmt.Errorf("websocket: RSV bits set")
	}
	// Client-to-server frames MUST be masked (RFC 6455 §5.1).
	if !masked {
		return nil, nil, 0, false, fmt.Errorf("websocket: unmasked client frame")
	}

	switch length {
	case 126:
		var lenBuf [2]byte
		if _, err = io.ReadFull(br, lenBuf[:]); err != nil {
			return nil, nil, 0, false, err
		}
		length = int64(binary.BigEndian.Uint16(lenBuf[:]))
	case 127:
		var lenBuf [8]byte
		if _, err = io.ReadFull(br, lenBuf[:]); err != nil {
			return nil, nil, 0, false, err
		}
		rawLen := binary.BigEndian.Uint64(lenBuf[:])
		if rawLen > uint64(MaxPayload) {
			return nil, nil, 0, false, fmt.Errorf("websocket: payload %d exceeds max %d", rawLen, MaxPayload)
		}
		length = int64(rawLen)
	}
	if length > MaxPayload {
		return nil, nil, 0, false, fmt.Errorf("websocket: payload %d exceeds max %d", length, MaxPayload)
	}

	var mask [4]byte
	if masked {
		if _, err = io.ReadFull(br, mask[:]); err != nil {
			return nil, nil, 0, false, err
		}
	}

	payload = make([]byte, length)
	if length > 0 {
		if _, err = io.ReadFull(br, payload); err != nil {
			return nil, nil, 0, false, err
		}
		if masked {
			for i := range payload {
				payload[i] ^= mask[i%4]
			}
		}
	}
	return b2, payload, op, fin, nil
}

func parseClose(payload []byte) (int, string) {
	if len(payload) < 2 {
		return 1000, ""
	}
	code := int(binary.BigEndian.Uint16(payload[:2]))
	return code, string(payload[2:])
}
