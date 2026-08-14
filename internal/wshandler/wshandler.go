// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

// Package wshandler implements the shells WebSocket application protocol:
// the encrypted handshake (init-crypto → crypto-ack → crypto-ready →
// auth-success), session attach/detach, terminal data relay with output
// coalescing and TCP backpressure (HWM/LWM/CWM), and multi-client fan-out.
//
// It is layered on the hand-rolled
// internal/websocket transport and internal/crypto primitives.
package wshandler

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"shells/internal/auth"
	"shells/internal/config"
	"shells/internal/crypto"
	"shells/internal/ringbuf"
	"shells/internal/session"
	"shells/internal/util"
	"shells/internal/websocket"
)

const (
	msgTypeData        byte = 0
	msgTypeControl     byte = 1
	coalesceMs              = 8 * time.Millisecond
	coalesceFlushBytes      = 32768
	lockAllMinInterval      = 5 * time.Second
)

// attachState holds the per-(client,session) relay state.
type attachState struct {
	isPaused      bool
	isThrottled   bool
	clientBuffer  *ringbuf.Buffer
	coalesceBuf   []byte
	coalesceTimer *time.Timer
	clientCols    int
	clientRows    int
	sidBuf        []byte
	cancelData    func()
	cancelExit    func()
}

// ClientConn is the per-WebSocket-connection state.
type ClientConn struct {
	ws      *websocket.Conn
	handler *Handler
	cfg     *config.Config

	state *crypto.State
	ready atomic.Bool
	token string

	handshakeDone atomic.Bool // prevents crypto-ready replay

	mu          sync.Mutex
	attached    map[string]*attachState
	closed      atomic.Bool
	lastLockAll time.Time
}

// Handler owns the WebSocket upgrader and the client registry.
type Handler struct {
	cfg     *config.Config
	manager *session.Manager
	auth    *auth.Store

	upgrader *websocket.Upgrader

	mu      sync.Mutex
	clients map[*ClientConn]struct{}
}

// New creates a WS handler bound to the given config, session manager, and
// auth store.
func New(cfg *config.Config, mgr *session.Manager, authStore *auth.Store) *Handler {
	upgrader := &websocket.Upgrader{
		HandshakeTimeout: 10 * time.Second,
	}
	if cfg.CheckOrigin {
		upgrader.CheckOrigin = authStore.HasAllowedOrigin
	}
	return &Handler{
		cfg:      cfg,
		manager:  mgr,
		auth:     authStore,
		clients:  make(map[*ClientConn]struct{}),
		upgrader: upgrader,
	}
}

// ServeHTTP handles the WebSocket upgrade at /ws.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Cap concurrent connections to limit resource consumption (pre-auth
	// DoS protection). The limit is generous — 100 simultaneous peers is
	// far beyond single-user VPS usage.
	h.mu.Lock()
	connCount := len(h.clients)
	h.mu.Unlock()
	if connCount >= 100 {
		http.Error(w, "server busy", http.StatusServiceUnavailable)
		return
	}

	conn, err := h.upgrader.Upgrade(w, r)
	if err != nil {
		return // Upgrade already wrote an error response
	}

	cc := &ClientConn{
		ws:       conn,
		handler:  h,
		cfg:      h.cfg,
		state:    crypto.NewState(),
		attached: make(map[string]*attachState),
	}

	h.mu.Lock()
	h.clients[cc] = struct{}{}
	h.mu.Unlock()

	conn.OnMessage = cc.onMessage
	conn.OnClose = cc.onClose

	keepalive := time.NewTicker(time.Duration(h.cfg.KeepaliveIntervalMs) * time.Millisecond)
	go func() {
		for range keepalive.C {
			if cc.closed.Load() {
				keepalive.Stop()
				return
			}
			cc.ws.SendPing(nil)
		}
	}()

	bpTicker := time.NewTicker(100 * time.Millisecond)
	go func() {
		for range bpTicker.C {
			if cc.closed.Load() {
				bpTicker.Stop()
				return
			}
			cc.backpressureCheck()
		}
	}()

	// Handshake timeout: the PBKDF2 (600k iterations) can take 10–30 s
	// on slow hardware. 60 s gives generous margin; if the handshake is
	// still not done, close the connection to free resources.
	go func() {
		time.Sleep(60 * time.Second)
		if !cc.ready.Load() && !cc.closed.Load() {
			cc.ws.Close(1008, "Handshake timeout")
		}
	}()

	go conn.Start()
}

// --- broadcasting ---

func (h *Handler) forEachClient(fn func(cc *ClientConn)) {
	h.mu.Lock()
	list := make([]*ClientConn, 0, len(h.clients))
	for cc := range h.clients {
		list = append(list, cc)
	}
	h.mu.Unlock()
	for _, cc := range list {
		fn(cc)
	}
}

func (h *Handler) broadcastCreated(s *session.Session) {
	inner, _ := json.Marshal(map[string]any{
		"type":     "created",
		"sid":      s.ID,
		"title":    s.GetTitle(),
		"cwd":      s.Cwd,
		"isRemote": s.IsRemote,
	})
	h.forEachClient(func(cc *ClientConn) {
		if cc.ready.Load() {
			cc.sendEncrypted(inner, nil)
		}
	})
}

func (h *Handler) notifyDestroyed(id string) {
	inner, _ := json.Marshal(map[string]any{"type": "gone", "sid": id})
	h.forEachClient(func(cc *ClientConn) {
		if !cc.ready.Load() {
			return
		}
		cc.mu.Lock()
		_, attached := cc.attached[id]
		cc.mu.Unlock()
		if attached {
			cc.sendEncrypted(inner, nil)
		}
	})
}

// broadcastLockAll relays a "lock-all" control to every other connected
// client (excluding the requester, which locks itself locally). The signal is
// re-encrypted per recipient, so it stays E2E like every other control frame.
func (h *Handler) broadcastLockAll(exclude *websocket.Conn) {
	inner, _ := json.Marshal(map[string]any{"type": "lock-all"})
	h.forEachClient(func(cc *ClientConn) {
		if !cc.ready.Load() || cc.ws == exclude {
			return
		}
		cc.sendEncrypted(inner, nil)
	})
}

func (h *Handler) broadcastPtySize(sid string, s *session.Session, exclude *websocket.Conn) {
	cols, rows := s.GetSize()
	active := s.GetActiveWS()
	inner, _ := json.Marshal(map[string]any{
		"type":     "pty-size",
		"sid":      sid,
		"cols":     cols,
		"rows":     rows,
		"isActive": false, // per-client, set below
	})
	h.forEachClient(func(cc *ClientConn) {
		if !cc.ready.Load() || cc.ws == exclude {
			return
		}
		cc.mu.Lock()
		_, ok := cc.attached[sid]
		cc.mu.Unlock()
		if !ok {
			return
		}
		// Patch isActive for this client.
		msg := make(map[string]any)
		_ = json.Unmarshal(inner, &msg)
		msg["isActive"] = (cc.ws == active)
		patched, _ := json.Marshal(msg)
		cc.sendEncrypted(patched, nil)
	})
}

// --- connection lifecycle ---

func (cc *ClientConn) onClose(code int, reason string) {
	cc.cleanup()
}

func (cc *ClientConn) cleanup() {
	if !cc.closed.CompareAndSwap(false, true) {
		return
	}

	if cc.token != "" {
		cc.handler.auth.Revoke(cc.token)
	}
	crypto.Destroy(cc.state)

	cc.mu.Lock()
	for sid, st := range cc.attached {
		if st.cancelData != nil {
			st.cancelData()
		}
		if st.cancelExit != nil {
			st.cancelExit()
		}
		if st.coalesceTimer != nil {
			st.coalesceTimer.Stop()
			st.coalesceTimer = nil
		}
		s := cc.handler.manager.Get(sid)
		if s != nil {
			s.RemoveClient()
			if s.GetActiveWS() == cc.ws {
				s.SetActiveWS(nil)
			}
		}
	}
	cc.attached = make(map[string]*attachState)
	cc.mu.Unlock()

	cc.handler.mu.Lock()
	delete(cc.handler.clients, cc)
	cc.handler.mu.Unlock()
}

// --- message dispatch ---

func (cc *ClientConn) onMessage(payload []byte, isBinary bool) {
	if !cc.ready.Load() {
		// Pre-handshake: only plaintext text JSON is accepted.
		if isBinary {
			cc.ws.Close(1008, "Encryption required")
			return
		}
		var msg map[string]any
		if err := json.Unmarshal(payload, &msg); err != nil {
			cc.ws.Close(1008, "Encryption required")
			return
		}
		cc.handlePlaintextControl(msg)
		return
	}

	if !isBinary {
		return // ignore plaintext after handshake
	}

	if len(payload) < 1 {
		return
	}
	frameType := payload[0]
	ciphertext := payload[1:]
	plaintext, err := crypto.Decrypt(cc.state, ciphertext)
	if err != nil {
		return
	}

	if frameType == msgTypeData {
		if len(plaintext) < 16 {
			return
		}
		sid := bytesToSid(plaintext[:16])
		data := plaintext[16:]
		s := cc.handler.manager.Get(sid)
		if s != nil && !s.IsDestroyed() {
			_, _ = s.Term.Write(data)
		}
		return
	}

	if frameType == msgTypeControl {
		var msg map[string]any
		if err := json.Unmarshal(plaintext, &msg); err != nil {
			return
		}
		cc.handleEncryptedControl(msg)
	}
}

func (cc *ClientConn) handlePlaintextControl(msg map[string]any) {
	msgType, _ := msg["type"].(string)

	switch msgType {
	case "init-crypto":
		clientPub, _ := msg["publicKey"].(string)
		ack, err := crypto.HandleInitCrypto(cc.state, clientPub)
		if err != nil {
			cc.ws.Close(1008, "Crypto handshake failed")
			return
		}
		ack["type"] = "crypto-ack"
		// HandleInitCrypto already includes the raw salt (hex-encoded) in the
		// ack; the browser derives the PBKDF2 secret hash from it.
		data, _ := json.Marshal(ack)
		cc.ws.SendText(data)

	case "crypto-ready":
		if !cc.handshakeDone.CompareAndSwap(false, true) {
			cc.ws.Close(1008, "Crypto handshake already completed")
			return
		}
		authProof, _ := msg["authProof"].(string)
		proofResponse, _ := msg["proofResponse"].(string)
		err := crypto.FinalizeHandshake(cc.state, authProof, proofResponse)
		if err != nil {
			cc.ws.Close(1008, "Crypto handshake failed")
			return
		}
		apiKey := cc.state.APIKey()
		if len(apiKey) == 0 {
			cc.ws.Close(1008, "Crypto handshake failed")
			return
		}
		cc.ready.Store(true)

		token := generateToken()
		if err := cc.handler.auth.Register(token, cc.ws.Done(), apiKey); err != nil {
			cc.ws.Close(1013, "Server busy") // Try Again Later
			return
		}
		cc.token = token

		inner, _ := json.Marshal(map[string]any{
			"type":         "auth-success",
			"sessionToken": token,
		})
		cc.sendEncrypted(inner, nil)

	default:
		cc.ws.Close(1008, "Encryption required")
	}
}

func (cc *ClientConn) handleEncryptedControl(msg map[string]any) {
	msgType, _ := msg["type"].(string)
	sid, _ := msg["sid"].(string)

	switch msgType {
	case "attach":
		cc.handleAttach(sid, msg)
	case "detach":
		cc.handleDetach(sid)
	case "pause":
		cc.mu.Lock()
		if st, ok := cc.attached[sid]; ok {
			st.isPaused = true
		}
		cc.mu.Unlock()
	case "resume":
		cc.mu.Lock()
		if st, ok := cc.attached[sid]; ok {
			st.isPaused = false
		}
		cc.mu.Unlock()
		cc.flushClientBuffer(sid)
	case "title":
		title, _ := msg["title"].(string)
		title = sanitizeTitle(title)
		s := cc.handler.manager.Get(sid)
		if s != nil {
			s.SetTitle(title)
		}
	case "resize":
		cc.handleResize(sid, msg)
	case "available-size":
		cols := util.IntFromAny(msg["cols"])
		rows := util.IntFromAny(msg["rows"])
		cc.mu.Lock()
		if st, ok := cc.attached[sid]; ok {
			st.clientCols = cols
			st.clientRows = rows
		}
		cc.mu.Unlock()
	case "claim-active":
		cc.handleClaimActive(sid, msg)
	case "lock-all":
		// Relay the lock signal to every other connected client, rate-limited
		// per connection so a (legit or compromised) client can't spam the
		// whole fleet into a perpetual reload loop.
		cc.mu.Lock()
		if time.Since(cc.lastLockAll) < lockAllMinInterval {
			cc.mu.Unlock()
			return
		}
		cc.lastLockAll = time.Now()
		cc.mu.Unlock()
		cc.handler.broadcastLockAll(cc.ws)
	}
}

// --- attach ---

func (cc *ClientConn) handleAttach(sid string, msg map[string]any) {
	s := cc.handler.manager.Get(sid)
	if s == nil {
		gone, _ := json.Marshal(map[string]any{"type": "gone", "sid": sid})
		cc.sendEncrypted(gone, nil)
		return
	}

	cc.mu.Lock()
	if _, exists := cc.attached[sid]; exists {
		cc.mu.Unlock()
		return
	}
	if s.ClientCount() >= cc.cfg.MaxClientsPerSession {
		cc.mu.Unlock()
		cc.ws.Close(1008, "Limit exceeded")
		return
	}

	n := s.AddClient()
	isFirst := n == 1

	cols := util.IntFromAny(msg["cols"])
	rows := util.IntFromAny(msg["rows"])
	if cols == 0 {
		cols = 80
	}
	if rows == 0 {
		rows = 24
	}

	// resume: the client re-attached after a WS drop and kept its terminal
	// content across the disconnect, so skip the reset + full replay.
	resume := false
	if v, ok := msg["resume"].(bool); ok {
		resume = v
	}

	st := &attachState{
		clientCols:   cols,
		clientRows:   rows,
		sidBuf:       sidToBytes(sid),
		clientBuffer: ringbuf.New(cc.cfg.OutputBufferMax),
	}
	cc.attached[sid] = st

	if isFirst {
		s.SetActiveWS(cc.ws)
	}

	// Subscribe to PTY output.
	sidCopy := sid
	st.cancelData = s.Term.OnData(func(data []byte) {
		cc.onPtyData(sidCopy, data)
	})
	st.cancelExit = s.Term.OnExit(func(code int, signal string) {
		if cc.closed.Load() {
			return
		}
		inner, _ := json.Marshal(map[string]any{
			"type":     "exit",
			"sid":      sidCopy,
			"exitCode": code,
			"signal":   signal,
		})
		cc.sendEncrypted(inner, nil)
	})

	// Resize if first client and dimensions provided.
	if isFirst && cols > 0 && rows > 0 {
		curCols, curRows := s.GetSize()
		clampedCols := util.ClampInt(cols, curCols, 1, 500)
		if clampedCols == 0 {
			clampedCols = 80
		}
		clampedRows := util.ClampInt(rows, curRows, 1, 200)
		if clampedRows == 0 {
			clampedRows = 24
		}
		_ = s.Term.Resize(clampedCols, clampedRows)
		s.SetSize(clampedCols, clampedRows)
	}

	// Send pty-size BEFORE replay so the client can resize its xterm.
	cols, rows = s.GetSize()
	isActive := s.GetActiveWS() == cc.ws
	ptySize, _ := json.Marshal(map[string]any{
		"type":     "pty-size",
		"sid":      sid,
		"cols":     cols,
		"rows":     rows,
		"isActive": isActive,
	})
	cc.sendEncrypted(ptySize, nil)

	// Fresh attach: clear terminal before replay so reconnecting clients don't
	// duplicate old output on top of what the terminal already shows. On
	// resume the client kept its terminal content across the disconnect, so
	// skip both the reset and the full ring replay (no wipe, no jump-to-top).
	if !resume {
		reset, _ := json.Marshal(map[string]any{"type": "reset", "sid": sid})
		cc.sendEncrypted(reset, nil)

		// Replay buffered output + title.  onPtyData cannot race here because
		// it needs cc.mu and we still hold it.  The PTY OnData callback is
		// registered above but dispatch waits for this lock to be released.
		cc.replayBuffer(sid, s, st)
	}

	// Restore active DEC modes.
	modes := s.GetRestorableDecModes(cc.cfg)
	if len(modes) > 0 {
		modeStr := "\x1b[?" + strings.Join(modes, ";") + "h"
		cc.sendEncrypted([]byte(modeStr), st.sidBuf)
	}

	// Force the foreground program to redraw its full frame on a fresh attach:
	// the replay only carries the ring's recent diffs, so a full-screen TUI —
	// alternate-screen or inline (pi/codex style ESC[2J/H/3J) — would otherwise
	// leave the client showing blank static regions with only the moving parts
	// updating. SIGWINCH triggers the full redraw and is a no-op for a plain
	// shell. Alternate-screen mode 1049 must additionally be re-entered on the
	// client (the reset above exits it).
	if !resume {
		if s.InAlternateScreen() {
			cc.sendEncrypted([]byte("\x1b[?1049h"), st.sidBuf)
		}
		_ = s.Term.SignalWinch()
	}

	cc.mu.Unlock()

	// Ready notification (slight delay to let xterm resize).
	time.AfterFunc(50*time.Millisecond, func() {
		if cc.closed.Load() {
			return
		}
		cc.mu.Lock()
		_, ok := cc.attached[sid]
		cc.mu.Unlock()
		if !ok {
			return
		}
		ready, _ := json.Marshal(map[string]any{"type": "ready", "sid": sid})
		cc.sendEncrypted(ready, nil)
	})
}

// replayBuffer sends the session title (if set) and the buffered output
// snapshot to a newly attached client, batching chunks into frames and
// throttling into the client ring when the socket write queue exceeds WSHWM.
//
// The caller must already hold cc.mu (sendEncrypted does not touch cc.mu).
func (cc *ClientConn) replayBuffer(sid string, s *session.Session, st *attachState) {
	title := s.GetTitle()
	defaultTitle := s.DefaultTitle
	chunks := s.OutputSnapshot()

	if len(chunks) == 0 && (title == "" || title == defaultTitle) {
		return
	}

	var batch [][]byte
	batchBytes := 0

	if title != "" && title != defaultTitle {
		t := []byte("\x1b]0;" + title + "\x07")
		batch = append(batch, t)
		batchBytes += len(t)
	}

	for _, chunk := range chunks {
		batch = append(batch, chunk)
		batchBytes += len(chunk)
		if batchBytes > 32768 {
			if cc.ws.BufferedAmount() > int64(cc.cfg.WSHWM) {
				// Throttle: buffer the rest.  cc.mu is already held by the
				// caller (handleAttach), so do not re-lock it here.
				st.isThrottled = true
				merged := concatBytes(batch)
				st.clientBuffer.Push(merged, len(merged))
				return
			}
			frame := concatBytes(batch)
			cc.sendEncrypted(frame, st.sidBuf)
			batch = batch[:0]
			batchBytes = 0
		}
	}

	if batchBytes > 0 {
		frame := concatBytes(batch)
		if cc.ws.BufferedAmount() > int64(cc.cfg.WSHWM) {
			// cc.mu is already held by the caller (handleAttach).
			st.isThrottled = true
			st.clientBuffer.Push(frame, len(frame))
		} else {
			cc.sendEncrypted(frame, st.sidBuf)
		}
	}
}

// --- PTY data relay + coalescing ---

func (cc *ClientConn) onPtyData(sid string, data []byte) {
	if cc.closed.Load() {
		return
	}
	cc.mu.Lock()
	defer cc.mu.Unlock()

	st, ok := cc.attached[sid]
	if !ok {
		return
	}

	if cc.ws.BufferedAmount() > int64(cc.cfg.WSHWM) {
		st.isThrottled = true
	}

	if st.isPaused || st.isThrottled {
		st.clientBuffer.Push(data, len(data))
		return
	}

	st.coalesceBuf = append(st.coalesceBuf, data...)
	if len(st.coalesceBuf) >= coalesceFlushBytes {
		if st.coalesceTimer != nil {
			st.coalesceTimer.Stop()
			st.coalesceTimer = nil
		}
		cc.flushCoalesceLocked(sid, st)
	} else if st.coalesceTimer == nil {
		sidCopy := sid
		st.coalesceTimer = time.AfterFunc(coalesceMs, func() {
			cc.mu.Lock()
			defer cc.mu.Unlock()
			st2, ok := cc.attached[sidCopy]
			if ok {
				cc.flushCoalesceLocked(sidCopy, st2)
			}
		})
	}
}

func (cc *ClientConn) flushCoalesceLocked(sid string, st *attachState) {
	if len(st.coalesceBuf) == 0 {
		st.coalesceTimer = nil
		return
	}
	chunk := make([]byte, len(st.coalesceBuf))
	copy(chunk, st.coalesceBuf)
	st.coalesceBuf = st.coalesceBuf[:0]
	st.coalesceTimer = nil

	if !st.isPaused && !st.isThrottled {
		cc.sendEncrypted(chunk, st.sidBuf)
	} else {
		st.clientBuffer.Push(chunk, len(chunk))
	}
}

func (cc *ClientConn) flushClientBuffer(sid string) {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	st, ok := cc.attached[sid]
	if !ok {
		return
	}
	s := cc.handler.manager.Get(sid)
	if s == nil || s.IsDestroyed() {
		return
	}

	cc.flushClientBufferLocked(sid, st, s)
}

// --- detach / resize / claim-active ---

func (cc *ClientConn) handleDetach(sid string) {
	cc.mu.Lock()
	st, ok := cc.attached[sid]
	if !ok {
		cc.mu.Unlock()
		return
	}
	delete(cc.attached, sid)
	if st.coalesceTimer != nil {
		st.coalesceTimer.Stop()
		st.coalesceTimer = nil
	}
	cc.mu.Unlock()

	if st.cancelData != nil {
		st.cancelData()
	}
	if st.cancelExit != nil {
		st.cancelExit()
	}
	st.coalesceBuf = nil

	s := cc.handler.manager.Get(sid)
	if s != nil {
		s.RemoveClient()
	}
}

func (cc *ClientConn) handleResize(sid string, msg map[string]any) {
	cols := util.IntFromAny(msg["cols"])
	rows := util.IntFromAny(msg["rows"])
	if cols == 0 || rows == 0 {
		return
	}
	cc.mu.Lock()
	st, ok := cc.attached[sid]
	if ok {
		st.clientCols = cols
		st.clientRows = rows
	}
	cc.mu.Unlock()
	if !ok {
		return
	}
	s := cc.handler.manager.Get(sid)
	if s == nil || s.IsDestroyed() {
		return
	}
	if s.GetActiveWS() == cc.ws {
		curCols, curRows := s.GetSize()
		c := util.ClampInt(cols, curCols, 1, 500)
		r := util.ClampInt(rows, curRows, 1, 200)
		_ = s.Term.Resize(c, r)
		s.SetSize(c, r)
		cc.handler.broadcastPtySize(sid, s, cc.ws)
	}
}

func (cc *ClientConn) handleClaimActive(sid string, msg map[string]any) {
	cols := util.IntFromAny(msg["cols"])
	rows := util.IntFromAny(msg["rows"])
	cc.mu.Lock()
	st, ok := cc.attached[sid]
	if ok {
		st.clientCols = cols
		st.clientRows = rows
	}
	cc.mu.Unlock()
	if !ok {
		return
	}
	s := cc.handler.manager.Get(sid)
	if s == nil || s.IsDestroyed() {
		return
	}
	s.SetActiveWS(cc.ws)
	c := util.ClampInt(cols, 80, 1, 500)
	r := util.ClampInt(rows, 24, 1, 200)
	_ = s.Term.Resize(c, r)
	s.SetSize(c, r)
	cc.handler.broadcastPtySize(sid, s, cc.ws)
}

// --- backpressure ---

func (cc *ClientConn) backpressureCheck() {
	if cc.ws.BufferedAmount() > int64(cc.cfg.WSCWM) {
		cc.ws.Close(1008, "Buffer exceeded limit")
		return
	}

	if cc.ws.BufferedAmount() >= int64(cc.cfg.WSLWM) {
		return
	}

	cc.mu.Lock()
	defer cc.mu.Unlock()
	for sid, st := range cc.attached {
		if st.isThrottled && !st.isPaused {
			s := cc.handler.manager.Get(sid)
			if s != nil && !s.IsDestroyed() {
				cc.flushClientBufferLocked(sid, st, s)
			}
		}
	}
}

// flushClientBufferLocked flushes buffered output for a throttled session.
//
// It drains the per-client ring of *unsent* output as ordinary data frames —
// never a destructive reset. The client's screen and scrollback stay intact;
// the worst that happens on a saturated link is a transient gap of evicted
// head bytes, which is strictly better than the old behaviour of wiping the
// terminal and replaying the whole snapshot on every LWM crossing (that wiped
// scrollback and caused a "redraw whole buffer again and again" storm).
//
// A reset+snapshot replay remains only on attach (replayBuffer), where it is
// the legitimate "clear before replay to avoid duplicated old output" case.
//
// The caller must already hold cc.mu (sendEncrypted does not touch cc.mu).
func (cc *ClientConn) flushClientBufferLocked(sid string, st *attachState, s *session.Session) {
	for st.clientBuffer.Len() > 0 {
		if cc.ws.BufferedAmount() > int64(cc.cfg.WSHWM) {
			st.isThrottled = true
			return
		}
		chunk := st.clientBuffer.Shift()
		cc.sendEncrypted(chunk, st.sidBuf)
	}
	if cc.ws.BufferedAmount() < int64(cc.cfg.WSLWM) {
		st.isThrottled = false
	}
}

// --- encrypted send ---

func (cc *ClientConn) sendEncrypted(data []byte, sidBuf []byte) {
	if cc.closed.Load() || !cc.ready.Load() {
		return
	}
	var frame []byte
	if sidBuf != nil {
		plaintext := make([]byte, 16+len(data))
		copy(plaintext[:16], sidBuf)
		copy(plaintext[16:], data)
		f, err := crypto.EncryptFrame(cc.state, plaintext, msgTypeData)
		if err != nil {
			return
		}
		frame = f
	} else {
		f, err := crypto.EncryptFrame(cc.state, data, msgTypeControl)
		if err != nil {
			return
		}
		frame = f
	}
	cc.ws.SendBinary(frame)
}

// --- helpers ---

func (h *Handler) RegisterSessionEvents() {
	h.manager.OnCreate(h.broadcastCreated)
	h.manager.OnDestroy(h.notifyDestroyed)
}

func sidToBytes(sid string) []byte {
	if sid == "" {
		return make([]byte, 16)
	}
	h := strings.ReplaceAll(sid, "-", "")
	b, err := hex.DecodeString(h)
	if err != nil || len(b) < 16 {
		padded := make([]byte, 16)
		copy(padded, b)
		return padded
	}
	return b
}

func bytesToSid(b []byte) string {
	if len(b) < 16 {
		return ""
	}
	h := hex.EncodeToString(b[:16])
	return fmt.Sprintf("%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])
}

func generateToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func sanitizeTitle(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func concatBytes(chunks [][]byte) []byte {
	var total int
	for _, c := range chunks {
		total += len(c)
	}
	out := make([]byte, 0, total)
	for _, c := range chunks {
		out = append(out, c...)
	}
	return out
}
