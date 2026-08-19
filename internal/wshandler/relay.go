// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

// PTY data relay: the byte path from session PTYs to attached clients —
// replay on attach, coalescing, pause/resume buffering with rate-limited
// activity heartbeats, and WS backpressure. Extracted from wshandler.go.
package wshandler

import (
	"encoding/json"
	"time"

	"shells/internal/session"
)

const (
	activitySigInterval = time.Second
)

// activitySignalDue reports whether a paused-session activity heartbeat is due.
func activitySignalDue(st *attachState, now time.Time) bool {
	return st.lastActSig.IsZero() || now.Sub(st.lastActSig) >= activitySigInterval
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
		if st.isPaused {
			st.pausedBytes += len(data)
			if activitySignalDue(st, time.Now()) {
				sig, _ := json.Marshal(map[string]any{"type": "activity", "sid": sid, "bytes": st.pausedBytes})
				cc.sendEncrypted(sig, nil)
				st.pausedBytes = 0
				st.lastActSig = time.Now()
			}
		}
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
