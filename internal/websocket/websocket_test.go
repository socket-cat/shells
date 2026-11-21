// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package websocket

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// newTestConn builds a Conn over an in-memory net.Pipe with no I/O loops
// running. The returned cancel stops everything: terminates the Conn and
// closes both pipe halves.
func newTestConn(t *testing.T) (*Conn, net.Conn, func()) {
	t.Helper()
	peer, server := net.Pipe()
	c := newConn(server, bufio.NewReader(peer))
	cancel := func() {
		c.terminate()
		_ = peer.Close()
		_ = server.Close()
	}
	t.Cleanup(cancel)
	return c, peer, cancel
}

// countQueuedPongs snapshots the outbound queue and counts pong frames.
func countQueuedPongs(c *Conn) int {
	c.queueMu.Lock()
	defer c.queueMu.Unlock()
	n := 0
	for _, f := range c.queue {
		if f[0]&0x0f == OpPong {
			n++
		}
	}
	return n
}

// waitFor polls cond until it holds or the timeout elapses.
func waitFor(cond func() bool, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(5 * time.Millisecond)
	}
	return true
}

// TestPingFloodCapped proves M-1: a synthetic ping burst enqueues at most
// maxPendingPongs pongs without closing the connection, and after the write
// loop drains them the counter re-arms so liveness pings keep being answered.
func TestPingFloodCapped(t *testing.T) {
	c, peer, _ := newTestConn(t)

	// Burst far beyond the cap with no write loop running: pongs pile up in
	// the queue where we can count them deterministically.
	const flood = 100
	for i := 0; i < flood; i++ {
		c.handlePing([]byte("flood"))
	}
	if got := countQueuedPongs(c); got != maxPendingPongs {
		t.Fatalf("queued %d pongs after flood, want exactly %d", got, maxPendingPongs)
	}
	c.queueMu.Lock()
	closing := c.closing
	c.queueMu.Unlock()
	if closing {
		t.Fatal("connection flagged closing by the pong cap itself")
	}
	if c.closed.Load() {
		t.Fatal("connection was closed by the pong cap itself")
	}

	// Drain via the real write loop; the counter must return to zero
	// (proves the flush-side decrement) and admit fresh pongs afterwards.
	drained := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, peer)
		close(drained)
	}()
	go c.writeLoop()

	if !waitFor(func() bool { return c.pongsQueued.Load() == 0 }, 2*time.Second) {
		t.Fatal("pong counter did not drain (missing write-loop decrement)")
	}

	for i := 0; i < flood; i++ {
		c.handlePing([]byte("refill"))
	}
	if !waitFor(func() bool { return c.pongsQueued.Load() > 0 }, 2*time.Second) {
		t.Fatal("counter re-armed but new pings were refused (leaked counter)")
	}
	if got := countQueuedPongs(c); got > maxPendingPongs {
		t.Fatalf("second burst queued %d pongs, cap is %d", got, maxPendingPongs)
	}
	if c.closed.Load() {
		t.Fatal("connection was closed by the pong cap itself")
	}
}

// TestCloseFlushBeforeTCPExit proves M-2: the echo close frame lands on the
// wire BEFORE termination closes the underlying stream (RFC 6455 §5.5.1).
//
// Semantics lever: a net.Pipe write blocks until the peer reads, so with a
// quiescent peer the queued close frame cannot possibly be delivered early.
// If a regression reintroduces teardown-before-flush, the pipe closes under
// the writer and the read below fails with EOF instead of seeing the frame.
// A plain Close (a refusal, pre-auth above all) then terminates at once: a
// silent peer cannot hold the socket.
func TestCloseFlushBeforeTCPExit(t *testing.T) {
	c, peer, _ := newTestConn(t)
	go c.writeLoop()

	c.Close(1000, "bye")

	// Settle window: on the buggy ordering the connection would already be
	// torn down here, closing the pipe under the pending write.
	time.Sleep(100 * time.Millisecond)

	if op := readOneFrameOp(t, peer); op != OpClose {
		t.Fatalf("first flushed frame op = %#x, want close (%#x)", op, OpClose)
	}
	if !waitFor(func() bool { return c.closed.Load() }, 100*time.Millisecond) {
		t.Fatal("connection did not terminate after the close frame was flushed")
	}
}

// TestCloseDrainWaitsForPeer: after a CloseDrain frame the socket stays
// open, input drained and not delivered, until the peer answers (RFC 6455
// §7.1.1): closing on unread input would reset TCP and drop what the peer
// had not read yet.
func TestCloseDrainWaitsForPeer(t *testing.T) {
	peer, server := net.Pipe()
	defer peer.Close()
	c := newConn(server, bufio.NewReader(server))
	var delivered atomic.Int32
	c.OnMessage = func([]byte, bool) { delivered.Add(1) }
	go c.Start()

	c.CloseDrain(1000, "bye")
	time.Sleep(100 * time.Millisecond)
	if op := readOneFrameOp(t, peer); op != OpClose {
		t.Fatalf("first flushed frame op = %#x, want close (%#x)", op, OpClose)
	}
	time.Sleep(100 * time.Millisecond)
	if c.closed.Load() {
		t.Fatal("closed before the peer answered the close")
	}
	if _, err := peer.Write(encodeFrame([]byte("late"), OpBinary, true)); err != nil {
		t.Fatal("input after our close was not read:", err)
	}
	if _, err := peer.Write(encodeFrame([]byte{0x03, 0xe8}, OpClose, true)); err != nil {
		t.Fatal(err)
	}
	if !waitFor(func() bool { return c.closed.Load() }, 2*time.Second) {
		t.Fatal("connection did not terminate after the peer's close")
	}
	if n := delivered.Load(); n != 0 {
		t.Fatalf("%d messages delivered after our close", n)
	}
}

// TestFragmentedNotAliased: a fragmented message is handed over in a slice
// of its own; OnMessage may keep it (federate queues it) while the next one
// arrives.
func TestFragmentedNotAliased(t *testing.T) {
	peer, server := net.Pipe()
	defer peer.Close()
	c := newConn(server, bufio.NewReader(server))
	got := make(chan []byte, 2)
	c.OnMessage = func(p []byte, _ bool) { got <- p }
	go c.Start()
	defer c.Close(1000, "")
	for _, b := range []string{"AAAA", "BBBB"} {
		first := encodeFrame([]byte(b), OpBinary, true)
		first[0] &^= 0x80 // FIN off: more fragments follow
		if _, err := peer.Write(append(first, encodeFrame([]byte(b), OpContinuation, true)...)); err != nil {
			t.Fatal(err)
		}
	}
	a, b := <-got, <-got
	if string(a) != "AAAAAAAA" || string(b) != "BBBBBBBB" {
		t.Fatalf("messages = %q, %q", a, b)
	}
}

// TestClientBoundedHandshake: a peer that streams an endless 101 response
// is refused once maxHandshakeResponse is read, not after the timeout with
// all of it in memory.
func TestClientBoundedHandshake(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		s, err := ln.Accept()
		if err != nil {
			return
		}
		defer s.Close()
		line := []byte("X-Pad: " + strings.Repeat("a", 1000) + "\r\n")
		if _, err := s.Write([]byte("HTTP/1.1 101 Switching Protocols\r\n")); err != nil {
			return
		}
		for {
			if _, err := s.Write(line); err != nil {
				return
			}
		}
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	start := time.Now()
	if _, err := Client(conn, &url.URL{Scheme: "ws", Host: ln.Addr().String(), Path: "/ws"}, http.Header{}); err == nil {
		t.Fatal("an endless 101 response was accepted")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("refused after %v: the response was read unbounded", d)
	}
}

// TestTerminateAwaitedFlushDeadline proves the flush wait cannot wedge
// teardown: with a close frame queued but nobody draining the socket,
// terminate must give up after closeSendWait and finish anyway.
func TestTerminateAwaitedFlushDeadline(t *testing.T) {
	c, _, _ := newTestConn(t)
	c.closeQueued.Store(true) // white-box: pretend Close() queued a frame

	done := make(chan struct{})
	go func() {
		c.terminate()
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("terminate finished before closeSendWait expired despite dead socket")
	case <-time.After(200 * time.Millisecond):
		// Good: still awaiting the flush window.
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("terminate wedged past the closeSendWait deadline")
	}
	if !c.closed.Load() {
		t.Fatal("terminated without marking the connection closed")
	}
}

// --- small wire-format helpers (test-only) ---

// readOneFrameOp reads one full frame from peer and returns its opcode.
func readOneFrameOp(t *testing.T, peer net.Conn) byte {
	t.Helper()
	_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	defer peer.SetReadDeadline(time.Time{})
	var hdr [2]byte
	if _, err := io.ReadFull(peer, hdr[:]); err != nil {
		t.Fatalf("read frame header: %v", err)
	}
	n := int64(hdr[1] & 0x7f)
	switch n {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(peer, ext[:]); err != nil {
			t.Fatalf("read extended length: %v", err)
		}
		n = int64(ext[0])<<8 | int64(ext[1])
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(peer, ext[:]); err != nil {
			t.Fatalf("read extended length: %v", err)
		}
		n = 0
		for _, b := range ext {
			n = n<<8 | int64(b)
		}
	}
	if n > 0 {
		if _, err := io.CopyN(io.Discard, peer, n); err != nil {
			t.Fatalf("discard payload: %v", err)
		}
	}
	return hdr[0] & 0x0f
}

// TestClientEcho dials the package's own Upgrader with Client: the Origin
// header arrives, masked client frames pass the server's check, unmasked
// server frames pass the client's, at all three length encodings.
func TestClientEcho(t *testing.T) {
	origin := make(chan string, 1)
	up := &Upgrader{CheckOrigin: func(r *http.Request) bool { origin <- r.Header.Get("Origin"); return true }}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r)
		if err != nil {
			return
		}
		c.OnMessage = func(p []byte, isBinary bool) {
			if isBinary {
				c.SendBinary(p)
			} else {
				c.SendText(p)
			}
		}
		go c.Start()
	}))
	defer srv.Close()

	u, _ := url.Parse(strings.Replace(srv.URL, "http", "ws", 1) + "/ws")
	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatal(err)
	}
	c, err := Client(conn, u, http.Header{"Origin": {srv.URL}})
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan []byte, 3)
	c.OnMessage = func(p []byte, _ bool) { got <- p }
	go c.Start()
	defer c.Close(1000, "")

	if o := <-origin; o != srv.URL {
		t.Fatalf("Origin = %q", o)
	}
	for _, n := range []int{5, 300, 70000} {
		msg := bytes.Repeat([]byte{'x'}, n)
		c.SendBinary(msg)
		select {
		case p := <-got:
			if !bytes.Equal(p, msg) {
				t.Fatalf("echo of %d bytes came back as %d", n, len(p))
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("no echo for %d bytes", n)
		}
	}
}
