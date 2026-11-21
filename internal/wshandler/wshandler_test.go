// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package wshandler

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"shells/internal/auth"
	"shells/internal/config"
	"shells/internal/session"
)

func TestActivitySignalDue(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)

	tests := []struct {
		name string
		last time.Time
		now  time.Time
		want bool
	}{
		{"zero lastActSig", time.Time{}, base, true},
		{"500ms after", base, base.Add(500 * time.Millisecond), false},
		{"exactly 1s after", base, base.Add(time.Second), true},
		{"2s after", base, base.Add(2 * time.Second), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := &attachState{lastActSig: tt.last}
			if got := activitySignalDue(st, tt.now); got != tt.want {
				t.Fatalf("activitySignalDue() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLeadingEdgeDue(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	idle := &attachState{lastFlush: base}
	if !leadingEdgeDue(idle, base.Add(coalesceMs)) {
		t.Error("idle for a full window: echo must go out immediately")
	}
	if leadingEdgeDue(idle, base.Add(coalesceMs-time.Millisecond)) {
		t.Error("inside the window after a flush: must coalesce (burst)")
	}
	if leadingEdgeDue(&attachState{coalesceBuf: []byte("x")}, base) {
		t.Error("pending bytes: must coalesce to keep order")
	}
	if leadingEdgeDue(&attachState{coalesceTimer: time.NewTimer(time.Hour)}, base) {
		t.Error("timer armed: must coalesce")
	}
	if !leadingEdgeDue(&attachState{}, base) {
		t.Error("never flushed: first output must go out immediately")
	}
}

// TestPreAuthRejectClosesAtOnce: a refusal before auth (here a binary frame
// before the handshake) frees the socket at once, as v1.2.7 did, even with
// a peer that stays silent: no linger a stranger could hold sockets with
// against the 100-connection cap.
func TestPreAuthRejectClosesAtOnce(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{
		KeepaliveIntervalMs: config.KeepaliveIntervalMs, MaxSessions: 4, MaxClientsPerSession: config.MaxClientsPerSession,
		OutputBufferMax: config.OutputBufferMax, WSHWM: config.WSHWM, WSLWM: config.WSLWM, WSCWM: config.WSCWM,
		ShellEnvKeys: config.ShellEnvKeys, DefaultShell: "/bin/sh", Cwd: dir, ServerKeyDir: dir,
		BrandingFile: filepath.Join(dir, "branding.json"), SSHConnectionsFile: filepath.Join(dir, "ssh.json"),
	}
	mgr, err := session.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h := New(cfg, mgr, auth.NewStore(""))
	srv := httptest.NewServer(h)
	defer srv.Close()

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	req := "GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	if res, err := http.ReadResponse(bufio.NewReader(conn), nil); err != nil || res.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade = %v, %v", res, err)
	}
	clients := func() int {
		h.mu.Lock()
		defer h.mu.Unlock()
		return len(h.clients)
	}
	for i := 0; clients() != 1; i++ { // registered just after the 101 goes out
		if i == 100 {
			t.Fatal("the upgraded socket was never registered")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := conn.Write([]byte{0x82, 0x81, 0, 0, 0, 0, 'x'}); err != nil { // binary, masked (zero key), before any handshake
		t.Fatal(err)
	}
	start := time.Now()
	for clients() != 0 {
		if time.Since(start) > 200*time.Millisecond {
			t.Fatalf("the refused socket is still held after %v", time.Since(start))
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Logf("released after %v", time.Since(start))
}
