// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package websocket

import (
	"bufio"
	"io"
	"net"
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
	if !waitFor(func() bool { return c.closed.Load() }, 2*time.Second) {
		t.Fatal("connection did not terminate after the close frame was flushed")
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
