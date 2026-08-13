/**
 * @author Carles Ortega Ragull <ragull@socket.cat> (https://socket.cat)
 * @copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

// ── Shell Session Management ──

function hexToUint8Array(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

const SERVER_FINGERPRINT_KEY = 'shells-server-fingerprint';

function getStoredFingerprint() {
  try { return localStorage.getItem(SERVER_FINGERPRINT_KEY); } catch (e) { return null; }
}

function setStoredFingerprint(fp) {
  try { localStorage.setItem(SERVER_FINGERPRINT_KEY, fp); } catch (e) {}
}

function formatFingerprintForDisplay(fp) {
  const groups = fp.split(':');
  const lines = [];
  for (let i = 0; i < groups.length; i += 6) {
    lines.push(groups.slice(i, i + 6).join(':'));
  }
  return lines.join('\n');
}

function createFingerprintDialogBody(text) {
  const el = document.createElement('div');
  el.style.whiteSpace = 'pre-wrap';
  el.style.fontFamily = 'monospace';
  el.style.fontSize = '13px';
  el.textContent = text;
  return el;
}

let lockPending = false;

async function resolveSecretHash(saltHex) {
  const cachedHash = localStorage.getItem('shells-e2e-secret-hash');
  const cachedSalt = localStorage.getItem('shells-e2e-secret-salt');

  if (cachedHash && cachedSalt === saltHex) {
    return hexToUint8Array(cachedHash).buffer;
  }

  const loadScreen = document.getElementById('load-screen');
  if (loadScreen) loadScreen.style.display = 'none';

  let rawSecret = await TuiDialog.prompt('Enter E2E Secret', {
    size: 'narrow',
    inputType: 'password',
    placeholder: 'Shared secret',
    description: 'Enter the E2E secret provided by the server administrator.'
  });

  if (loadScreen) loadScreen.style.display = '';

  if (!rawSecret || rawSecret.trim().length === 0) {
    loadScreen.style.display = 'none';
    rawSecret = await TuiDialog.prompt('Enter E2E Secret', {
      size: 'narrow',
      inputType: 'password',
      placeholder: 'Shared secret',
      description: 'A secret is required. Please try again.'
    });
    if (loadScreen) loadScreen.style.display = '';
    if (!rawSecret || rawSecret.trim().length === 0) {
      window.ShellSessions._secretCancelled = true;
      return null;
    }
  }

  const saltBytes = hexToUint8Array(saltHex);
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(rawSecret),
    'PBKDF2',
    false,
    ['deriveBits']
  );

  const hashBuf = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', iterations: 600000, salt: saltBytes },
    keyMaterial,
    256
  );

  const hashU8 = new Uint8Array(hashBuf);
  let hex = '';
  for (let i = 0; i < hashU8.length; i++) {
    hex += hashU8[i].toString(16).padStart(2, '0');
  }

  if (!lockPending) {
    localStorage.setItem('shells-e2e-secret-hash', hex);
    localStorage.setItem('shells-e2e-secret-salt', saltHex);
  }

  return hashBuf;
}

// A lock requested in any tab forces every other tab of this app to reload to
// the secret prompt (localStorage is shared per origin).
window.addEventListener('storage', (e) => {
  if (e.key === 'shells-lock-req') location.reload();
});

// A frozen tab restored from the back/forward cache must not bypass a lock:
// frozen pages do not receive storage events, so re-authenticate whenever a
// lock was requested at any point after the page was loaded.
window.addEventListener('pageshow', (e) => {
  if (e.persisted && localStorage.getItem('shells-lock-req')) location.reload();
});

// ── Autolock on idle (local only, 0 = off) ──
// Only user input resets the idle clock; terminal output (e.g. a running
// htop) does not, so the user can walk away while a long task runs.
(function() {
  let lastActivity = Date.now();
  const EVENTS = ['keydown', 'mousedown', 'touchstart', 'wheel'];
  const onActivity = () => { lastActivity = Date.now(); };
  // Capture phase: xterm registers its key handler with stopPropagation, so
  // bubble-phase listeners never see terminal keystrokes. Capture fires first.
  // NOTE: 'scroll' is intentionally excluded — the terminal viewport fires
  // native scroll events on every output flow, which would reset the idle
  // clock and prevent locking. User scroll intent is covered by wheel,
  // mousedown and touchstart.
  EVENTS.forEach((t) => document.addEventListener(t, onActivity, { passive: true, capture: true }));

  const idleMinutes = () => window.ShellSessions.getAutolockMin();

  const maybeLock = () => {
    // Only once connected/authenticated: avoids a reload loop at the secret
    // prompt or during a reconnect backoff (which can exceed the threshold
    // with no input).
    if (window.ShellSessions && !window.ShellSessions._wsReady) return;
    // Only the focused window may autolock: with two visible windows of the
    // same origin, the idle one must not lock the window the user is using
    // (and thereby all tabs via the shells-lock-req storage signal). Being
    // away still counts: on regaining focus the stale clock locks within one
    // interval tick.
    if (document.visibilityState !== 'visible') return;
    if (!document.hasFocus()) return;
    // No overlay guard: autolock must fire in ANY situation once idle passes
    // the threshold. Active dialog use resets the clock through the
    // capture-phase input listeners, so an interactive dialog is never locked
    // prematurely.
    const min = idleMinutes();
    if (min <= 0) return;
    if (Date.now() - lastActivity >= min * 60000) {
      window.ShellSessions.lock();
    }
  };

  // Only the visible tab evaluates idle: a hidden tab's stale clock must not
  // lock the tab the user is actively working in (and thereby all tabs via
  // the shells-lock-req storage signal). When the active tab becomes visible
  // again, check immediately so an away-period (window minimized/behind)
  // still counts as idle instead of being erased on arrival.
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') maybeLock();
  });

  setInterval(maybeLock, 30000);
})();

window._clearTouchSelection = function(term) {
  try { term.clearSelection(); } catch (_) {}
  try {
    const selection = window.getSelection && window.getSelection();
    if (selection && selection.rangeCount > 0) selection.removeAllRanges();
  } catch (_) {}
};

window._getScaledCoords = function(term, clientX, clientY) {
  const sid = window.ShellSessions._scaleCoordSid;
  const session = sid && window.ShellSessions.sessions.get(sid);
  const sf = session?._scaleFactor;
  if (!sf || sf >= 1.0) return { clientX, clientY };
  let rect = session._cachedBodyRect;
  if (rect) session._cachedBodyRect = null;
  if (!rect) {
    const el = document.getElementById(`term-${sid}`);
    if (el) rect = el.getBoundingClientRect();
  }
  if (!rect) return { clientX, clientY };
  return {
    clientX: rect.left + (clientX - rect.left) / sf,
    clientY: rect.top + (clientY - rect.top) / sf,
  };
};

window._dispatchTerminalWheel = function(term, clientX, clientY, deltaY) {
  const target = term.element?.querySelector('.xterm-screen') || term.element;
  if (!target) return;
  const sc = window._getScaledCoords(term, clientX, clientY);
  // A full-screen TUI that enables mouse tracking receives the wheel as a mouse
  // report and scrolls with the opposite direction of the terminal's scrollback.
  // Invert the delta so swipe up/down feels consistent with plain shells.
  let d = deltaY;
  try {
    const mm = term.modes && term.modes.mouseTrackingMode;
    if (mm && mm !== 'none') d = -deltaY;
  } catch (_) {}
  window.__dbg?.trace('wheel.dispatch', { sid: term._sid || '?', deltaY: Math.round(deltaY), inverted: d !== deltaY, mouse: (() => { try { return (term.modes && term.modes.mouseTrackingMode) || 'none'; } catch (_) { return '?'; } })() });
  target.dispatchEvent(new WheelEvent('wheel', {
    clientX: sc.clientX,
    clientY: sc.clientY,
    deltaY: d,
    deltaMode: 0,
    bubbles: true,
    cancelable: true,
  }));
};

window._dispatchTerminalMouse = function(term, type, clientX, clientY, buttons) {
  const target = term.element?.querySelector('.xterm-screen') || term.element;
  if (!target) return;
  const sc = window._getScaledCoords(term, clientX, clientY);
  target.dispatchEvent(new MouseEvent(type, {
    clientX: sc.clientX,
    clientY: sc.clientY,
    button: 0,
    buttons,
    bubbles: true,
    cancelable: true,
  }));
};

window._focusWithoutScroll = function(term) {
  try {
    window.__dbg?.trace('focus.start', { sid: term._sid || '?' });
    try {
      term.focus({ preventScroll: true });
    } catch (_) {
      term.focus();
    }
    window.__dbg?.trace('focus.ok', { sid: term._sid || '?' });
  } catch (_) {
    try {
      term.focus({ preventScroll: true });
    } catch (_) {
      term.focus();
    }
  }
};

/**
 * @typedef {Object} Session
 * @property {any} term - Xterm instance
 * @property {any} fitAddon - Fit addon instance
 * @property {HTMLElement} tile - Tile DOM element
 * @property {ResizeObserver} ro - Resize observer
 * @property {boolean} isAsleep - Whether session is in sleep mode
 * @property {boolean} remotelyClosed - If session was closed from another device
 * @property {string} title - Cached title
 * @property {boolean} [mounting] - Internal flag
 */

// Printable-byte thresholds for recognizing genuine terminal output. A resize
// or prompt redraw is escape-heavy and carries few printable bytes, so gating
// activity on printable volume suppresses those false positives without any
// resize/time-based plumbing. ARM_CHARS gates the per-frame pulse; RUN_MIN_CHARS
// gates the completion bell (the run only rings if it produced real output volume,
// not just elapsed time — a sustained but low-volume redraw still can't ring it).
const ARM_CHARS = 20;
const RUN_MIN_CHARS = 400;
// Output is only recognized as real activity (pulse + run tracking) once the
// user has been silent for INPUT_IDLE_MS. While you're typing into a shell,
// its echo arrives within this window and is ignored; process output that
// arrives after it is genuine (compile/htop/etc.) — active or background.
const INPUT_IDLE_MS = 5000;
// After any bell sound the session is muted for BELL_COOLDOWN_MS, so a runaway
// stream of BELs (\a) can't beep-spam. The latched attention icon still shows.
const BELL_COOLDOWN_MS = 1500;

// Count printable bytes in a VT frame, stripping CSI/OSC/DCS/SOS/PM/APC escape
// sequences and C0/DEL controls. Stops once `cap` printable bytes are seen, so
// the "did this frame carry enough real output?" decision is bounded regardless
// of frame size. Pure byte walk — no allocation, no string decode.
function countPrintable(buf, cap) {
  const n = buf.length;
  let count = 0;
  let i = 0;
  while (i < n) {
    const b = buf[i];
    if (b === 0x1b) {
      const c = i + 1 < n ? buf[i + 1] : 0;
      if (c === 0x5b) {              // CSI: ESC '[' ... 0x40-0x7e
        i += 2;
        while (i < n && (buf[i] < 0x40 || buf[i] > 0x7e)) i++;
        i++;
      } else if (c === 0x5d) {       // OSC: ESC ']' ... BEL | ST
        i += 2;
        while (i < n && buf[i] !== 0x07 && !(buf[i] === 0x1b && i + 1 < n && buf[i + 1] === 0x5c)) i++;
        i += (i < n && buf[i] === 0x07) ? 1 : 2;
      } else if (c === 0x50 || c === 0x58 || c === 0x5e || c === 0x5f) { // DCS/SOS/PM/APC ... ST
        i += 2;
        while (i < n && !(buf[i] === 0x1b && i + 1 < n && buf[i + 1] === 0x5c)) i++;
        i += 2;
      } else {
        i += 2;                       // bare ESC + one byte
      }
      continue;
    }
    if (b >= 0x20 && b !== 0x7f) {   // printable ASCII or non-ASCII (>= 0x80)
      count++;
      if (count >= cap) return count;
    }
    i++;                             // C0 control or DEL: skip
  }
  return count;
}

window.ShellSessions = {
  sessions: new Map(),
  activeId: null,
  masterId: null,
  _bellSuppressed: true,
  layoutMode: 'auto',
  _fontSize: null,
  _searchState: null,
  _searchDecorations: null,

  ws: null,
  _wsReady: false,
  _wsPromise: null,
  _reconnectTimer: null,
  cryptoState: null,
  _sendQueue: Promise.resolve(),
  _secretHash: null,
  _secretCancelled: false,
  _loadScreenDismissed: false,
  _fullSplashTimer: null,
  _ptySizes: new Map(),
  _isActiveClient: new Map(),
  _isDeletingConn: new Set(),
};

window.ShellSessions = Object.assign(window.ShellSessions, {
  lock() {
    // Most secure lock: clear the cached secret and reload the page. This
    // destroys all in-page state — there is no modal layer to bypass via the
    // console and no secret retained in memory. The server keeps the PTYs
    // alive across the disconnect, so re-entering the secret reattaches the
    // existing terminals via restore().
    lockPending = true; // suppress any in-flight PBKDF2 continuation from re-caching the secret
    localStorage.removeItem('shells-e2e-secret-hash');
    localStorage.removeItem('shells-e2e-secret-salt');
    this._secretHash = null;
    const secure = location.protocol === 'https:' ? '; secure' : '';
    document.cookie = 'shells-token=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT' + secure;
    localStorage.setItem('shells-lock-req', String(Date.now())); // signal other tabs to lock
    location.reload();
  },

  async sendLockAll() {
    if (!this.sendWs({ type: 'lock-all' })) return false;
    try { await this._sendQueue; } catch (_) {}
    // The frame may have been dropped if the socket closed mid-queue.
    return !!(this.ws && this.ws.readyState === 1);
  },

  getAutolockMin() {
    let min = 0;
    try { min = parseInt(localStorage.getItem('shells-autolock-min'), 10) || 0; } catch (_) {}
    return min;
  },

  setAutolockMin(v) {
    const min = Math.max(0, Math.min(720, Math.round(v) || 0));
    try { localStorage.setItem('shells-autolock-min', String(min)); } catch (_) {}
    return min;
  },

  async getWs() {
    if (this.ws && this.ws.readyState === 1 && this._wsReady) return this.ws;
    if (this._wsPromise) return this._wsPromise;

    this._wsPromise = new Promise((resolve, reject) => {
      let settled = false;
      const wsProtocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
      const ws = new WebSocket(`${wsProtocol}//${location.host}/ws`);
      ws.binaryType = 'arraybuffer';
      this.ws = ws;

      this._updateLoadStatus('connecting...');
      this._setLoadProgress(5);

      ws.onopen = async () => {
        try {
          if (this._secretCancelled) { ws.close(); return; }
          this._updateLoadStatus('connected, handshaking...');
          this._setLoadProgress(15);
          this.cryptoState = await window.ShellsCrypto.createCryptoState();
          ws.send(JSON.stringify({ type: 'init-crypto', publicKey: this.cryptoState.publicKeyB64 }));
        } catch (e) {
          this._updateLoadStatus('crypto initialization failed');
          TuiDialog.toast('Crypto initialization failed', 'error');
          ws.close();
        }
      };

      ws.onmessage = async (event) => {
        try {
          let type, sid, msg, payload;

          if (typeof event.data === 'string') {
            msg = JSON.parse(event.data);
            type = msg.type;
            sid = msg.sid;
          } else {
            if (!this.cryptoState || !this.cryptoState.cryptoReady) return;
            const raw = new Uint8Array(event.data);
            const frameType = raw[0];
            const ciphertext = raw.subarray(1);
            const plaintext = await window.ShellsCrypto.decrypt(this.cryptoState, ciphertext);

            if (frameType === 0) { // MSG_TYPE_DATA
              const sidBuf = plaintext.subarray(0, 16);
              sid = window.ShellsCrypto.bufferToSid(sidBuf);
              payload = plaintext.subarray(16);

              if (this._wsReady) {
                const session = this.sessions.get(sid);
              if (session) {
                const p = countPrintable(payload, RUN_MIN_CHARS);
                window.__dbg?.trace('write.start', {
                  sid,
                  bytes: payload.length,
                  printable: p,
                  viewportY: session.term.buffer?.active?.viewportY,
                  baseY: session.term.buffer?.active?.baseY,
                  ydisp: session.term.buffer?.active?.ydisp,
                  active: this.activeId === sid,
                  head: payload.subarray(0, 48).length ? String.fromCharCode.apply(null, payload.subarray(0, 48)).replace(/[^\x20-\x7e]/g, (c) => '<' + c.charCodeAt(0).toString(16) + '>') : '',
                });
                if (p >= ARM_CHARS && Date.now() - (session.lastInputAt || 0) >= INPUT_IDLE_MS) {
                  session.lastOutputAt = Date.now();
                  session.runPrintable = Math.min(RUN_MIN_CHARS, session.runPrintable + p);
                }
                session.term.write(payload, () => {
                  if (this._pendingSwitcherSessions) this._checkAllReady();
                  window.__dbg?.trace('write.done', {
                    sid,
                    viewportY: session.term.buffer?.active?.viewportY,
                    baseY: session.term.buffer?.active?.baseY,
                    cols: session.term.cols,
                    rows: session.term.rows,
                  });
                });
              }
              }
              return;
            } else if (frameType === 1) { // MSG_TYPE_CONTROL
              const decoded = new TextDecoder().decode(plaintext);
              msg = JSON.parse(decoded);
              type = msg.type;
              sid = msg.sid;
              payload = decoded;
            } else {
              return;
            }
          }

          if (type === 'crypto-ack') {
            try {
              if (!msg.authProof || !msg.authChallenge) {
                this._updateLoadStatus('server security update required');
                TuiDialog.toast('Server requires a security update', 'error');
                ws.close(4002, 'Server security update required');
                return;
              }

              this._updateLoadStatus('verifying server identity...');
              this._setLoadProgress(25);
              const stored = getStoredFingerprint();

              if (!stored) {
                const fpDisplay = formatFingerprintForDisplay(msg.fingerprint);
                const bodyEl = createFingerprintDialogBody(
                  'The authenticity of host can\'t be established.\n\n' +
                  'SHA256 key fingerprint is:\n\n' +
                  fpDisplay + '\n\n' +
                  'Are you sure you want to continue connecting?'
                );
                const confirmed = await TuiDialog.confirm(
                  'New Server Connection',
                  bodyEl,
                  { confirmText: 'Yes', cancelText: 'No', size: 'medium' }
                );

                if (!confirmed) {
                  this._updateLoadStatus('connection cancelled');
                  ws.close(4000, 'Connection rejected');
                  return;
                }

                setStoredFingerprint(msg.fingerprint);
              } else if (stored !== msg.fingerprint) {
                const oldFp = formatFingerprintForDisplay(stored);
                const newFp = formatFingerprintForDisplay(msg.fingerprint);

                const bodyEl = createFingerprintDialogBody(
                  '@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n' +
                  '@    WARNING: HOST KEY CHANGED    @\n' +
                  '@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n\n' +
                  'It is possible that someone is doing something nasty!\n\n' +
                  'Someone could be eavesdropping on you right now\n' +
                  '(man-in-the-middle attack)!\n\n' +
                  'Expected:\n' + oldFp + '\n\nActual:\n' + newFp + '\n\n' +
                  'Are you sure you want to continue connecting?'
                );
                const confirmed = await TuiDialog.confirm(
                  'WARNING: HOST KEY CHANGED',
                  bodyEl,
                  { confirmText: 'Yes', cancelText: 'No', size: 'medium', dangerous: true }
                );

                if (!confirmed) {
                  this._updateLoadStatus('fingerprint mismatch');
                  ws.close(4001, 'Fingerprint mismatch');
                  return;
                }

                setStoredFingerprint(msg.fingerprint);
              }

              this._updateLoadStatus('authenticating...');
              this._setLoadProgress(35);
              if (!this._secretHash) {
                this._secretHash = await resolveSecretHash(msg.salt);
                if (!this._secretHash) {
                  this._updateLoadStatus('secret entry cancelled');
                  ws.close();
                  return;
                }
              }

              this._updateLoadStatus('verifying server proof...');
              this._setLoadProgress(50);
              await window.ShellsCrypto.handleCryptoAck(
                this.cryptoState,
                msg.publicKey,
                this._secretHash,
                msg.authProof
              );

              this._updateLoadStatus('sending credentials...');
              this._setLoadProgress(60);

              const clientAuthProof = await window.ShellsCrypto.generateHMACProof(
                this.cryptoState,
                this.cryptoState.rawPublicKey
              );

              const proofResponse = await window.ShellsCrypto.generateHMACProof(
                this.cryptoState,
                new TextEncoder().encode(msg.authChallenge)
              );

              ws.send(JSON.stringify({
                type: 'crypto-ready',
                authProof: clientAuthProof,
                proofResponse: proofResponse
              }));
            } catch (e) {
              const msg = e.message || 'Unknown error';
              this._updateLoadStatus('handshake failed: ' + msg);
              TuiDialog.toast('Handshake failed: ' + msg, 'error');
              if (msg === 'Server authentication failed') {
                localStorage.removeItem('shells-e2e-secret-hash');
                localStorage.removeItem('shells-e2e-secret-salt');
                this._secretHash = null;
              }
              ws.close();
            }
            return;
          }

          if (!this.cryptoState || !this.cryptoState.cryptoReady) return;

          // Pre-auth: handle auth-success
          if (!this._wsReady) {
            try {
              const inner = JSON.parse(payload);
              if (inner.type === 'auth-success') {
                this._updateLoadStatus('authenticated, syncing...');
                this._setLoadProgress(80);
                document.cookie = 'shells-token=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT' + (location.protocol === 'https:' ? '; secure' : '');
                var _secure = location.protocol === 'https:' ? '; secure' : '';
                document.cookie = `shells-token=${inner.sessionToken}; path=/; samesite=strict` + _secure;

                this.sessionToken = inner.sessionToken;
                this._wsReady = true;
                // A lock was armed by a previous lock (any path). Now that the
                // user is authenticated again, disarm it so a later bfcache
                // restore doesn't bounce an already-unlocked page back to the
                // secret prompt.
                try { localStorage.removeItem('shells-lock-req'); } catch (_) {}
                this._reconnectDelay = null;
                this._wsPromise = null;
                if (this._fullSplashTimer) {
                  clearTimeout(this._fullSplashTimer);
                  this._fullSplashTimer = null;
                }
                if (this._reconnectTimer) {
                  clearTimeout(this._reconnectTimer);
                  this._reconnectTimer = null;
                }

                // Sessions present before sync() survived the disconnect: their
                // xterm content is still intact, so re-attach with resume to
                // skip the server-side reset + full replay (no jump-to-top).
                const resumed = new Set(this.sessions.keys());

                await new Promise(r => setTimeout(r, 50));
                await this.sync();

                for (const [sid, s] of this.sessions) {
                  await this.sendWs({ type: 'attach', sid, cols: s.term.cols, rows: s.term.rows, resume: resumed.has(sid) });
                  if (s.isAsleep) await this.sendWs({ type: 'pause', sid });
                }
                this._setLoadProgress(100);
                this._dismissLoadScreen();
                settled = true;
                resolve(ws);
                return;
              }
            } catch (e) {
              this._updateLoadStatus('authentication failed');
              TuiDialog.toast('Authentication failed', 'error');
              localStorage.removeItem('shells-e2e-secret-hash');
              localStorage.removeItem('shells-e2e-secret-salt');
              this._secretHash = null;
              this._secretCancelled = false;
              this.cryptoState = null;
              ws.close(4001, 'Wrong secret');
            }
            return;
          }

          // Authenticated: control messages
          try {
            const inner = JSON.parse(payload);

            if (inner.type === 'created') {
              if (!this.sessions.has(inner.sid)) {
                this.mount(inner.sid, inner.title, inner.cwd, inner.isRemote ? this._getRemoteBadgeFromTitle(inner.title) : null);
              }
              return;
            }

            if (inner.type === 'lock-all') {
              // Another device requested a global lock: lock this client too.
              this.lock();
              return;
            }

            const session = this.sessions.get(inner.sid);
            if (!session) return;

            if (inner.type === 'pty-size') {
              this._handlePtySize(inner.sid, inner.cols, inner.rows, inner.isActive);
            } else if (inner.type === 'reset') {
              window.__dbg?.trace('term.reset', { sid: inner.sid, reason: 'server-reset', viewportY: session.term.buffer?.active?.viewportY, baseY: session.term.buffer?.active?.baseY });
              session.term.reset();
            } else if (inner.type === 'exit') {
              if (session.remotelyClosed) return;
              this._showTuiStatus(inner.sid, `Process Exited (code ${inner.exitCode}) · Click to discard`, 'error');
            } else if (inner.type === 'gone') {
              if (session.remotelyClosed) return;
              session.remotelyClosed = true;
              this._showTuiStatus(inner.sid, 'Session Closed Remotely · Click to discard', 'info');
            } else if (inner.type === 'error') {
              session.term.write(`\r\n[Error: ${inner.message}]\r\n`);
            }
          } catch (e) {}
        } catch (e) {
          console.error('[WS] Message error:', e);
          if (!settled) {
            settled = true;
            reject(e);
          }
        }
      };

      ws.onclose = () => {
        this._wsReady = false;
        this._wsPromise = null;
        this.cryptoState = null;
        if (!settled) {
          settled = true;
          reject(new Error('WebSocket closed before authentication'));
        }
        if (this._secretCancelled) {
          this._updateLoadStatus('secret entry cancelled');
          for (const sid of Array.from(this.sessions.keys())) {
            this.destroy(sid, false);
          }
          this._secretCancelled = false;
          this._secretHash = null;
          return;
        }
        this._showLoadScreen(true);
        this._setLoadProgress(0);
        if (!this._reconnectDelay) this._reconnectDelay = 1000;
        else this._reconnectDelay = Math.min(this._reconnectDelay * 2, 30000);
        const delay = Math.round(this._reconnectDelay / 1000);
        this._updateLoadStatus(`reconnecting in ${delay}s...`);
        if (this._fullSplashTimer) clearTimeout(this._fullSplashTimer);
        this._fullSplashTimer = setTimeout(() => {
          if (!this._wsReady) this._showLoadScreen(false);
        }, 4000);

        if (this._reconnectTimer) clearTimeout(this._reconnectTimer);
        this._reconnectTimer = setTimeout(() => {
          this.getWs().catch(() => {});
        }, 2000);
      };

      ws.onerror = () => {
        this._updateLoadStatus('connection failed');
        TuiDialog.toast('Connection failed — server may be unavailable', 'error');
        this._wsPromise = null;
        if (!settled) {
          settled = true;
          reject(new Error('WebSocket connection failed'));
        }
      };
    });

    return this._wsPromise;
  },

  async sendWs(msg) {
    if (this.ws && this.ws.readyState === 1 && this._wsReady) {
      if (msg.type === 'data') {
        const payload = msg.data;
        const sid = msg.sid;

        this._sendQueue = this._sendQueue.then(async () => {
          try {
            const sidBuf = window.ShellsCrypto.sidToBuffer(sid);
            const dataBuf = (typeof payload === 'string') ? new TextEncoder().encode(payload) : payload;
            const plaintext = new Uint8Array(16 + dataBuf.length);
            plaintext.set(sidBuf);
            plaintext.set(dataBuf, 16);

            const encrypted = await window.ShellsCrypto.encrypt(this.cryptoState, plaintext);
            const frame = new Uint8Array(1 + encrypted.length);
            frame[0] = 0; // MSG_TYPE_DATA
            frame.set(encrypted, 1);
            if (this.ws && this.ws.readyState === 1) {
              this.ws.send(frame.buffer);
            }
          } catch (e) {
            console.error('[WS] Encryption error:', e);
          }
        }).catch(err => {
          console.error('[WS] Queue error:', err);
        });
        return true;
      }
      
      if (msg.type === 'resize' || msg.type === 'available-size' || msg.type === 'claim-active' || msg.type === 'attach' || msg.type === 'detach' || msg.type === 'pause' || msg.type === 'resume') {
        window.__dbg?.trace('sendWs', { type: msg.type, sid: msg.sid, cols: msg.cols, rows: msg.rows, wsReady: !!(this.ws && this.ws.readyState === 1 && this._wsReady) });
      }

      this._sendQueue = this._sendQueue.then(async () => {
        try {
          const encrypted = await window.ShellsCrypto.encrypt(this.cryptoState, JSON.stringify(msg));
          const frame = new Uint8Array(1 + encrypted.length);
          frame[0] = 1; // MSG_TYPE_CONTROL
          frame.set(encrypted, 1);
          if (this.ws && this.ws.readyState === 1) {
            this.ws.send(frame.buffer);
          }
        } catch (e) {
          console.error('[WS] Encryption error:', e);
        }
      }).catch(err => {
        console.error('[WS] Queue error:', err);
      });
      return true;
    }
    return false;
  },

  /**
   * Syncs the local terminal list with the server's master list.
   * Useful for catching up after a reconnection.
   */
  async sync() {
    try {
      const { ok, data: list } = await this.encryptedFetch('/api/sessions', { _method: 'GET' });
      if (!ok) return;

      await this.fetchSshConnections();

      // Update existing or add new
      for (const s of list) {
        if (!this.sessions.has(s.id)) {
          this.mount(s.id, s.title, s.cwd, s.isRemote ? this._getRemoteBadgeFromTitle(s.title) : null);
        }
      }

      // Cleanup local sessions that no longer exist on server
      const serverIds = new Set(list.map(s => s.id));
      const destroyPromises = [];
      for (const localId of Array.from(this.sessions.keys())) {
        if (!serverIds.has(localId)) {
          const s = this.sessions.get(localId);
          if (s && !s.mounting) {
            destroyPromises.push(this.destroy(localId, false));
          }
        }
      }
      await Promise.all(destroyPromises);

      // If everything was wiped (e.g. server restart), create a fresh one
      console.log(`[Sync] Server sessions: ${list.length}, Local sessions: ${this.sessions.size}`);
      if (this.sessions.size === 0) {
        console.log('[Sync] No sessions, opening new shell dialog');
        const result = await this.promptCreate();
        if (!result && this.sessions.size === 0) this.showEmptyState();
        this._dismissLoadScreen();
      }
    } catch (e) {
      console.error('[Sync] Error:', e);
    }
  },

  STORAGE_KEYS: {
    ACTIVE_ID: 'shells-active-id',
    MASTER_ID: 'shells-master-id',
    LAYOUT_MODE: 'shells-layout-mode',
    SESSION_ORDER: 'shells-session-order',
  },

  _recentPaths: [],
  _sshRecentPaths: {},

  _backendKey(backend) {
    if (!backend) return 'local';
    return backend.connectionId || `${backend.user}@${backend.host}:${backend.port || 22}`;
  },

  _normalizePath(path, keepTrailingSlash) {
    if (!path || path === '/') return '/';
    const hadTrailing = keepTrailingSlash && path.endsWith('/') && path.length > 1;
    const parts = path.split('/');
    const stack = [];
    for (const part of parts) {
      if (part === '..') stack.pop();
      else if (part !== '.' && part !== '') stack.push(part);
    }
    const res = (path.startsWith('/') ? '/' : '') + stack.join('/');
    return (hadTrailing && res.length > 1) ? res + '/' : (res || '/');
  },

  async fetchRecentPaths() {
    try {
      const { ok, data } = await this.encryptedFetch('/api/recent-paths', { _method: 'GET' });
      if (ok && Array.isArray(data)) this._recentPaths = data.map(p => this._normalizePath(p, true));
    } catch (e) {}
    return this._recentPaths;
  },

  async _saveRecentPath(p) {
    if (!p) return;
    let normalized = this._normalizePath(p, true);
    if (!normalized.endsWith('/')) normalized += '/';
    this._recentPaths = this._recentPaths.filter(rp => this._normalizePath(rp) !== normalized && this._normalizePath(rp) !== normalized.slice(0, -1));
    this._recentPaths.unshift(normalized);
    this._recentPaths = this._recentPaths.slice(0, 10);
    
    try {
      await this.encryptedFetch('/api/recent-paths', { paths: this._recentPaths });
    } catch (e) {}
  },

  async _removeRecentPath(path) {
    if (!path) return;
    const normalized = this._normalizePath(path);
    this._recentPaths = this._recentPaths.filter(p => this._normalizePath(p) !== normalized);

    try {
      await this.encryptedFetch('/api/recent-paths', { paths: this._recentPaths });
    } catch (e) {}
  },

  async _fetchSshRecentPaths(backend) {
    const key = this._backendKey(backend);
    try {
      const raw = localStorage.getItem('shells-ssh-paths-' + key);
      const parsed = raw ? JSON.parse(raw) : [];
      this._sshRecentPaths[key] = Array.isArray(parsed) ? parsed : [];
    } catch { this._sshRecentPaths[key] = []; }
    return this._sshRecentPaths[key];
  },

  _saveSshRecentPath(backend, p) {
    if (!p) return;
    const key = this._backendKey(backend);
    let list = this._sshRecentPaths[key] || [];
    const norm = this._normalizePath(p, true);
    list = list.filter(rp => this._normalizePath(rp) !== this._normalizePath(norm));
    list.unshift(norm);
    list = list.slice(0, 10);
    this._sshRecentPaths[key] = list;
    try { localStorage.setItem('shells-ssh-paths-' + key, JSON.stringify(list)); } catch {}
  },

  _removeSshRecentPath(backend, p) {
    if (!p) return;
    const key = this._backendKey(backend);
    const normalized = this._normalizePath(p);
    let list = (this._sshRecentPaths[key] || []).filter(rp => this._normalizePath(rp) !== normalized);
    this._sshRecentPaths[key] = list;
    try { localStorage.setItem('shells-ssh-paths-' + key, JSON.stringify(list)); } catch {}
  },

  _recentCommands: [],
  _recentBackends: [],

  async _fetchRecentBackends() {
    try {
      const raw = localStorage.getItem('shells-recent-backends');
      if (raw) {
        const parsed = JSON.parse(raw);
        this._recentBackends = Array.isArray(parsed) ? parsed : [];
      } else {
        const old = localStorage.getItem('shells-last-backend');
        if (old) {
          this._recentBackends = [old === 'Local' ? 'localhost' : old];
          localStorage.removeItem('shells-last-backend');
          localStorage.setItem('shells-recent-backends', JSON.stringify(this._recentBackends));
        }
      }
    } catch {}
    return this._recentBackends;
  },

  _saveRecentBackend(label) {
    this._recentBackends = [label, ...this._recentBackends.filter(b => b !== label)].slice(0, 10);
    try { localStorage.setItem('shells-recent-backends', JSON.stringify(this._recentBackends)); } catch {}
  },

  _removeRecentBackend(label) {
    this._recentBackends = this._recentBackends.filter(b => b !== label);
    try { localStorage.setItem('shells-recent-backends', JSON.stringify(this._recentBackends)); } catch {}
  },

  async fetchRecentCommands() {
    try {
      const { ok, data } = await this.encryptedFetch('/api/recent-commands', { _method: 'GET' });
      if (ok && Array.isArray(data)) this._recentCommands = data;
    } catch (e) {}
    return this._recentCommands;
  },

  async _saveRecentCommand(cmd) {
    if (!cmd || /\s/.test(cmd)) return;
    this._recentCommands = this._recentCommands.filter(c => c !== cmd);
    this._recentCommands.unshift(cmd);
    this._recentCommands = this._recentCommands.slice(0, 20);
    try {
      await this.encryptedFetch('/api/recent-commands', { commands: this._recentCommands });
    } catch (e) {}
  },

  async _removeRecentCommand(cmd) {
    if (!cmd) return;
    this._recentCommands = this._recentCommands.filter(c => c !== cmd);
    try {
      await this.encryptedFetch('/api/recent-commands', { commands: this._recentCommands });
    } catch (e) {}
  },

  _sshRecentCommands: {},

  async _fetchSshRecentCommands(backend) {
    const key = this._backendKey(backend);
    try {
      const raw = localStorage.getItem('shells-ssh-cmds-' + key);
      const parsed = raw ? JSON.parse(raw) : [];
      this._sshRecentCommands[key] = Array.isArray(parsed) ? parsed : [];
    } catch { this._sshRecentCommands[key] = []; }
    return this._sshRecentCommands[key];
  },

  _saveSshRecentCommand(backend, cmd) {
    if (!cmd) return;
    const key = this._backendKey(backend);
    let list = this._sshRecentCommands[key] || [];
    list = list.filter(c => c !== cmd);
    list.unshift(cmd);
    list = list.slice(0, 20);
    this._sshRecentCommands[key] = list;
    try { localStorage.setItem('shells-ssh-cmds-' + key, JSON.stringify(list)); } catch {}
  },

  _removeSshRecentCommand(backend, cmd) {
    if (!cmd) return;
    const key = this._backendKey(backend);
    let list = (this._sshRecentCommands[key] || []).filter(c => c !== cmd);
    this._sshRecentCommands[key] = list;
    try { localStorage.setItem('shells-ssh-cmds-' + key, JSON.stringify(list)); } catch {}
  },

  _sshConnections: [],
  _isDeletingConn: new Set(),

  async fetchSshConnections() {
    try {
      if (!this.sessionToken) return;
      const { ok, data } = await this.encryptedFetch('/api/ssh-connections', { _method: 'GET' });
      if (ok) this._sshConnections = data;
    } catch {}
  },

  async _saveSshConnections() {
    try {
      if (!this.sessionToken) return;
      await this.encryptedFetch('/api/ssh-connections', { connections: this._sshConnections });
    } catch {}
  },

  _parseSSHInput(input) {
    const trimmed = (input || '').trim();
    if (!trimmed || !trimmed.includes('@')) return null;
    const atIndex = trimmed.lastIndexOf('@');
    const user = trimmed.substring(0, atIndex);
    const hostPort = trimmed.substring(atIndex + 1);
    let host, port;
    if (hostPort.includes(':')) {
      const lastColon = hostPort.lastIndexOf(':');
      host = hostPort.substring(0, lastColon);
      port = parseInt(hostPort.substring(lastColon + 1)) || 22;
    } else {
      host = hostPort;
      port = 22;
    }
    if (!user || !host) return null;
    return { user, host, port };
  },

  _connLabel(c) {
    return c.port === 22 ? `${c.user}@${c.host}` : `${c.user}@${c.host}:${c.port}`;
  },

  async _sshLsAutocomplete(val, backend, lsCache, recent, backendBadge) {
    if (!backend || !backend.connectionId) return [];
    const { connectionId } = backend;

    let base, filter, prefix;
    if (val.startsWith('/')) {
      const parts = val.split('/');
      filter = parts.pop().toLowerCase();
      base = parts.join('/') || '/';
      prefix = base === '/' ? '/' : base + '/';
    } else {
      return [];
    }

    const raw = lsCache.has(base) ? lsCache.get(base) : null;
    let folders;
    if (raw) {
      folders = Array.isArray(raw) ? raw : (raw.folders || []);
    } else {
      if (!this._wsReady || !this.sessionToken) return [];
      try {
        const { ok, data } = await this.encryptedFetch('/api/ssh-ls', { connectionId, path: base });
        folders = ok ? (data.folders || []) : [];
        lsCache.set(base, folders);
      } catch {
        return [];
      }
    }

    const suggestions = [];
    const seen = new Set();

    folders
      .filter(f => !filter || f.toLowerCase().startsWith(filter))
      .forEach(f => {
        const fullPath = prefix + f + '/';
        suggestions.push({ text: fullPath, canDelete: false, badge: [backendBadge, this._getBadgeInfo(fullPath)] });
        seen.add(f);
      });

    if (recent) {
      recent
        .filter(r => r !== val && r.toLowerCase().includes(val.toLowerCase()))
        .forEach(r => {
          if (!suggestions.find(s => s.text === r)) {
            suggestions.push({ text: r, canDelete: true, badge: [backendBadge, this._getBadgeInfo(r)] });
          }
        });
    }

    return suggestions;
  },

  saveState() {
    try {
      localStorage.setItem(this.STORAGE_KEYS.ACTIVE_ID, this.activeId || '');
      localStorage.setItem(this.STORAGE_KEYS.MASTER_ID, this.masterId || '');
      localStorage.setItem(this.STORAGE_KEYS.LAYOUT_MODE, this.layoutMode);
      localStorage.setItem(this.STORAGE_KEYS.SESSION_ORDER, JSON.stringify(Array.from(this.sessions.keys())));
    } catch (e) {
      console.warn('Failed to save state to localStorage:', e);
    }
  },

  setLayout(modeId) {
    this.layoutMode = modeId;
    this.saveState();
    window.ShellLayout.updateGrid(this.sessions, this.layoutMode);
    window.TuiDialog.toast('Layout: ' + this.layoutMode.charAt(0).toUpperCase() + this.layoutMode.slice(1), 'success');
  },

  cycleLayout(triggerEl) {
    if (window.ShellLayout && window.ShellLayout.picker) {
      window.ShellLayout.picker.open(triggerEl);
    }
  },

  promoteToMaster(id) {
    this.masterId = id;
    this.saveState();
    window.ShellLayout.updateGrid(this.sessions, this.layoutMode);
    window.ShellLayout.updateActiveHighlight(this.activeId, this.masterId);
  },

  headers() {
    return this.sessionToken ? { 'X-Shells-Token': this.sessionToken } : {};
  },

  async encryptedFetch(url, params = {}) {
    if (!this.cryptoState || !this.cryptoState.apiKey) {
      throw new Error('Encryption not ready');
    }
    const plaintext = JSON.stringify(params);
    const enc = await window.ShellsCrypto.encryptPayload(this.cryptoState.apiKey, plaintext);
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Shells-Encrypted': '1', ...this.headers() },
      body: JSON.stringify(enc),
    });
    if (res.status === 204) return { ok: true, status: 204, data: null };
    try {
      if (res.headers.get('x-shells-encrypted') === '1') {
        const raw = await res.json();
        const decrypted = await window.ShellsCrypto.decryptPayload(this.cryptoState.apiKey, raw.nonce, raw.ciphertext);
        const data = JSON.parse(decrypted);
        if (data && data.error) return { ok: false, status: res.status, data, error: data.error };
        if (!res.ok) return { ok: false, status: res.status, data, error: (data && data.error) || `HTTP ${res.status}` };
        return { ok: true, status: res.status, data };
      }
      const data = await res.json();
      if (data && data.error) return { ok: false, status: res.status, data, error: data.error };
      if (!res.ok) return { ok: false, status: res.status, data, error: (data && data.error) || `HTTP ${res.status}` };
      return { ok: true, status: res.status, data };
    } catch (e) {
      return { ok: false, status: res.status, data: null, error: e.message };
    }
  },

  _getBadgeInfo(path) {
    if (!path) return { text: '??', color: '#888' };
    const p = this._normalizePath(path);
    const parts = p.split('/').filter(Boolean);
    const last = parts.length > 0 ? parts[parts.length - 1] : 'ROOT';
    
    let text;
    if (last === 'ROOT') text = 'RO';
    else if (last.length === 1) text = (last[0] + last[0]).toUpperCase();
    else text = (last[0] + last[last.length - 1]).toUpperCase();

    // Deterministic color
    let hash = 0;
    for (let i = 0; i < p.length; i++) {
      hash = p.charCodeAt(i) + ((hash << 5) - hash);
    }
    const h = Math.abs(hash % 360);
    // Use high saturation and light enough background for black text
    const color = `hsl(${h}, 70%, 70%)`;

    return { text, color };
  },

  _makeBadge(color, text, zeroMargin) {
    const el = document.createElement('span');
    el.className = 'project-badge';
    el.style.backgroundColor = color;
    if (zeroMargin) el.style.marginRight = '0';
    el.textContent = text;
    return el;
  },

  _getBackendBadge(conn) {
    if (!conn) return { text: '??', color: 'hsl(0, 0%, 70%)' };

    const rawHost = conn.hostname || conn.host || '';
    const host = rawHost.split(':')[0];
    const segments = host.split('.');
    const isIP = /^\d+(\.\d+){3}$/.test(host);
    const part = isIP ? segments[segments.length - 1] : segments[0];

    let text;
    if (!part) text = '??';
    else if (part.length === 1) text = (part + part).toUpperCase();
    else text = (part[0] + part.slice(-1)).toUpperCase();

    const label = this._connLabel(conn);
    let hash = 0;
    for (let i = 0; i < label.length; i++) {
        hash = label.charCodeAt(i) + ((hash << 5) - hash);
    }
    const h = Math.abs(hash % 360);

    return { text, color: `hsl(${h}, 70%, 70%)` };
  },

  _getRemoteBadgeFromTitle(title) {
    if (!title) return null;
    // Server titles: "ssh: user@host" or "ssh: hostname" (when hostname is known).
    const body = title.startsWith('ssh: ') ? title.slice(5) : title;
    const match = body.match(/([a-zA-Z0-9_.-]+)@([a-zA-Z0-9.-]+)/);
    if (match) return this._getBackendBadge({ user: match[1], host: match[2], port: 22 });
    const host = body.trim();
    if (host && /^[a-zA-Z0-9.-]+$/.test(host)) return this._getBackendBadge({ host, port: 22 });
    return null;
  },

  async create(cols = 80, rows = 24, command, cwd, backend) {
    const body = { cols, rows };
    if (command) body.command = command;
    if (cwd) body.cwd = cwd;
    if (backend) body.backend = backend;
    const { ok, data, error } = await this.encryptedFetch('/api/sessions', body);
    if (!ok) throw new Error(error || 'Failed to create shell session');
    const { id, cwd: finalCwd } = data;
    if (!this.masterId) this.masterId = id;

    let sessionTitle;
    if (backend && backend.type === 'ssh') {
      const label = `${backend.user}@${backend.hostname || backend.host}`;
      const folder = finalCwd ? finalCwd.split('/').filter(Boolean).pop() || '/' : '/';
      sessionTitle = command ? `${label} > ${folder} > ${command}` : `${label} > ${folder}`;
    } else {
      const dirName = finalCwd ? finalCwd.split('/').filter(Boolean).pop() || '/' : '/';
      sessionTitle = command ? `${dirName} > ${command}` : null;
    }

    const backendBadge = backend ? this._getBackendBadge(backend) : null;
    this.mount(id, sessionTitle, finalCwd, backendBadge);
    this.setActive(id);
    return id;
  },

  async promptCreate() {
    await this._fetchRecentBackends();

    const updateCheckRow = document.createElement('label');
    updateCheckRow.className = 'tui-dialog-footer-extra-check';
    const updateCb = document.createElement('input');
    updateCb.type = 'checkbox';
    updateCb.checked = localStorage.getItem('shells-update-check') !== '0';
    updateCb.addEventListener('change', () => {
      try { localStorage.setItem('shells-update-check', updateCb.checked ? '1' : '0'); } catch (_) {}
    });
    const updateLabel = document.createElement('span');
    updateLabel.textContent = 'Automatically check GitHub releases for updates';
    updateCheckRow.appendChild(updateCb);
    updateCheckRow.appendChild(updateLabel);

    const backendInput = await window.TuiDialog.prompt('Backend', {
      placeholder: 'user@host[:port] or localhost',
      footerExtra: updateCheckRow,
      autocomplete: async (val) => {
        const connections = this._sshConnections || [];
        const q = (val || '').toLowerCase();

        const localhost = { text: 'localhost', canDelete: false, badge: { text: 'LO', color: '#4CAF50' }, description: (window.__HOSTNAME__ && !window.__HOSTNAME__.includes('{{')) ? window.__HOSTNAME__ : null };
        const all = [localhost];
        for (const conn of connections) {
          const label = this._connLabel(conn);
          const s = { text: label, canDelete: true, badge: this._getBackendBadge(conn) };
          if (conn.hostname) s.description = conn.hostname;
          all.push(s);
        }

        if (!q) {
          all.sort((a, b) => {
            const ai = this._recentBackends.indexOf(a.text);
            const bi = this._recentBackends.indexOf(b.text);
            if (ai === -1 && bi === -1) return a.text.localeCompare(b.text);
            if (ai === -1) return 1;
            if (bi === -1) return -1;
            return ai - bi;
          });
          return all;
        }

        const filtered = all.filter(s => s.text.toLowerCase().includes(q));
        filtered.sort((a, b) => {
          const aStarts = a.text.toLowerCase().startsWith(q) ? 0 : 1;
          const bStarts = b.text.toLowerCase().startsWith(q) ? 0 : 1;
          return aStarts - bStarts;
        });
        return filtered;
      },
      onDelete: async (val) => {
        const conn = this._sshConnections.find(c => this._connLabel(c) === val);
        if (!conn) return;
        if (this._isDeletingConn.has(conn.id)) return;
        this._isDeletingConn.add(conn.id);

        try {
        const label = this._connLabel(conn);

        const message = document.createElement('div');
        message.style.lineHeight = '1.6';

        const intro = document.createElement('div');
        intro.textContent = 'This will permanently remove:';
        message.appendChild(intro);
        message.appendChild(document.createElement('br'));

        const items = [];
        if (conn.hasOurKey) items.push('Public key from remote server');
        items.push('SSH keys from this server');
        items.push('Recent paths and commands');

        for (const item of items) {
          const row = document.createElement('div');
          row.style.paddingLeft = '12px';
          row.textContent = '\u2022 ' + item;
          message.appendChild(row);
        }

        message.appendChild(document.createElement('br'));
        const warn = document.createElement('div');
        warn.style.fontStyle = 'italic';
        warn.style.opacity = '0.7';
        warn.textContent = 'This cannot be undone.';
        message.appendChild(warn);

        const confirmed = await window.TuiDialog.confirm('Remove SSH Connection', message, {
          dangerous: true,
          confirmText: 'Yes, remove',
          size: 'small',
        });

        if (!confirmed) return;

        const statusClose = window.TuiDialog.status('Removing...', 'Removing ' + label + '...');

        let ok = false;
        let data;
        try {
          const res = await this.encryptedFetch(`/api/ssh-connections/${conn.id}`, { _method: 'DELETE' });
          ok = res?.ok ?? false;
          data = res?.data;
        } catch (err) {
          console.error('Remove connection failed:', err);
          window.TuiDialog.toast('Network error removing connection', 'error');
          try { statusClose(); } catch (e) { console.error('statusClose failed:', e); }
          return;
        }

        let mutationError;
        try {
          if (ok && data?.removed) {
            this._sshConnections = this._sshConnections.filter(c => c.id !== conn.id);
            this._removeRecentBackend(label);

            try { localStorage.removeItem('shells-ssh-paths-' + conn.id); } catch {}
            try { localStorage.removeItem('shells-ssh-cmds-' + conn.id); } catch {}

            delete this._sshRecentPaths[conn.id];
            delete this._sshRecentCommands[conn.id];
          }
        } catch (err) {
          mutationError = err;
          console.error('Local state mutation failed after connection removal:', err);
        } finally {
          try { statusClose(); } catch (e) { console.error('statusClose failed:', e); }
        }

        if (mutationError) {
          window.TuiDialog.toast('Connection removed from server, but local cleanup failed', 'warning');
        } else if (ok && data?.removed) {
          if (conn.hasOurKey && data.remoteKeyRemoved === false) {
            window.TuiDialog.toast('Connection removed \u2014 public key may still exist on ' + label, 'warning');
          } else {
            window.TuiDialog.toast('Connection removed', 'success');
          }
        } else {
          window.TuiDialog.toast('Failed to remove connection', 'error');
        }

        } finally {
          this._isDeletingConn.delete(conn.id);
        }
      },
    });

    if (backendInput === null) return;

    this._saveRecentBackend(backendInput.toLowerCase() === 'localhost' ? 'localhost' : backendInput);

    let backend = null;
    const parsed = this._parseSSHInput(backendInput);

    if (parsed) {
      const { user, host, port } = parsed;
      let conn = this._sshConnections.find(c => c.host === host && c.user === user && c.port === port);

      if (conn) {
        backend = { type: 'ssh', connectionId: conn.id, host, user, port, hostname: conn.hostname };
      } else {
        let statusClose = TuiDialog.status('Probing SSH...', `Checking connectivity to ${host}...`);
        let setupStatusClose = null;
        try {
          const probeRes = await this.encryptedFetch('/api/ssh-probe', { host, user, port });
          statusClose();
          statusClose = null;
          const probeData = probeRes.data || {};

          if (probeRes.error && probeRes.error.includes('not available')) {
            window.TuiDialog.toast('SSH not available on server', 'error');
            return;
          }

          if (probeRes.ok && probeData.keyReady) {
            conn = this._sshConnections.find(c => c.id === probeData.id);
            if (!conn) {
              conn = { id: probeData.id, host, user, port, hasOurKey: probeData.hasOurKey, hostname: probeData.hostname };
              this._sshConnections.push(conn);
              await this._saveSshConnections();
            }
            backend = { type: 'ssh', connectionId: conn.id, host, user, port, hostname: conn.hostname };
          } else if (probeData.unreachable) {
            const errBody = createFingerprintDialogBody(
              `Could not reach ${host}:${port}\n\n` +
              `Possible causes:\n` +
              `  - Wrong hostname or IP address\n` +
              `  - SSH service not running on the host\n` +
              `  - Firewall blocking port ${port}`
            );
            await window.TuiDialog.alert('Connection Failed', errBody, { size: 'medium' });
            return;
          } else {
            let setupOk = false;
            while (!setupOk) {
              const password = await window.TuiDialog.prompt('SSH Password', {
                description: `No SSH keys found for ${host}.\nEnter your password to install a public key.\nFuture connections will not require a password.`,
                inputType: 'password',
                placeholder: 'password',
              });
              if (!password) return;

              setupStatusClose = TuiDialog.status('Installing key...', `Setting up SSH for ${user}@${host}...`);
              const setupRes = await this.encryptedFetch('/api/ssh-setup', { host, user, port, password });
              setupStatusClose();
              setupStatusClose = null;
              const setupData = setupRes.data || {};

              if (setupRes.ok) {
                conn = { id: setupData.id, host, user, port, hasOurKey: true, hostname: setupData.hostname };
                this._sshConnections.push(conn);
                await this._saveSshConnections();
                backend = { type: 'ssh', connectionId: conn.id, host, user, port, hostname: conn.hostname };
                setupOk = true;
              } else {
                const hint = setupData.code === 'max_attempts' ? 'The password was incorrect.'
                  : setupData.code === 'timeout' ? 'The connection timed out.'
                  : setupData.code === 'install_failed' ? 'The server rejected key installation.'
                  : '';
                const errBody = createFingerprintDialogBody(
                  `Failed to set up SSH for ${user}@${host}\n\n` +
                  (setupData.error || 'Unknown error') +
                  (hint ? '\n\n' + hint : '\n\nYou can try:\n  - Check the password is correct\n  - Verify SSH is running on the host')
                );
                const retry = await window.TuiDialog.confirm('SSH Setup Failed', errBody, {
                  confirmText: 'Retry',
                  cancelText: 'Cancel',
                  size: 'medium',
                  dangerous: true,
                });
                if (!retry) return;
              }
            }
          }
        } catch (err) {
          if (statusClose) { statusClose(); }
          if (setupStatusClose) { setupStatusClose(); }
          const errBody = createFingerprintDialogBody(
            `SSH connection to ${user}@${host} failed\n\n` +
            (err.message || 'Unknown error') +
            '\n\nYou can try:\n  - Verify the hostname and port\n  - Check that SSH is running on the host'
          );
          await window.TuiDialog.alert('Connection Failed', errBody, { size: 'medium' });
          return;
        }
      }
    }

    // Step 2: Folder picker
    const lsCache = new Map();
    const isSSH = backend && backend.type === 'ssh' && backend.connectionId;

    let loadStatusClose = isSSH ? window.TuiDialog.status('Connecting...', `Loading paths from ${backend.user}@${backend.host}...`) : null;

    const loadPath = async (p) => {
      if (lsCache.has(p)) return lsCache.get(p);
      try {
        if (isSSH) {
          const { ok, data } = await this.encryptedFetch('/api/ssh-ls', { connectionId: backend.connectionId, path: p || '' });
          if (!ok) return null;
          lsCache.set(p, data);
          return data;
        }
        const { ok, data } = await this.encryptedFetch('/api/ls', { path: p || '' });
        if (!ok) return null;
        lsCache.set(p, data);
        return data;
      } catch (e) { return null; }
    };

    let recent;
    let home;
    if (isSSH) {
      recent = await this._fetchSshRecentPaths(backend);
      const sshHome = await loadPath('');
      if (!sshHome) {
        if (loadStatusClose) { loadStatusClose(); }
        const errBody = createFingerprintDialogBody(
          `Could not connect to ${backend.user}@${backend.host}\n\n` +
          `The SSH connection failed. The host may be unreachable or the SSH service may not be running.\n\n` +
          `You can try:\n  - Verify the host is reachable\n  - Check that SSH is running on the host\n  - Remove and re-add the connection`
        );
        await window.TuiDialog.alert('Connection Failed', errBody, { size: 'medium' });
        return;
      }
      home = sshHome.path;
    } else {
      const initialData = await loadPath('');
      home = initialData ? initialData.path : '/';
      recent = await this.fetchRecentPaths();
    }
    recent = Array.isArray(recent) ? recent : [];

    if (loadStatusClose) { loadStatusClose(); }

    const backendBadge = isSSH ? this._getBackendBadge(backend) : null;
    const autocomplete = isSSH
      ? async (val) => {
        if (!val) {
          const recentSuggestions = recent.map(p => ({ text: p, canDelete: true, badge: [backendBadge, this._getBadgeInfo(p)] }));
          if (recentSuggestions.length > 0) return recentSuggestions;
          return this._sshLsAutocomplete(home + '/', backend, lsCache, recent, backendBadge);
        }
        return this._sshLsAutocomplete(val, backend, lsCache, recent, backendBadge);
      }
      : async (val) => {
      if (!val) return recent.map(p => ({ text: p, canDelete: true, badge: this._getBadgeInfo(p) }));
      
      let base, filter, prefix;
      if (val.startsWith('/')) {
        const parts = val.split('/');
        filter = parts.pop().toLowerCase();
        base = parts.join('/') || '/';
        prefix = base === '/' ? '/' : base + '/';
      } else {
        const parts = val.split('/');
        filter = parts.pop().toLowerCase();
        const sub = parts.join('/');
        base = sub ? `${home}/${sub}` : home;
        prefix = sub ? sub + '/' : '';
      }
      
      const ls = await loadPath(base);
      const suggestions = [];
      if (ls) {
        ls.folders
          .filter(f => f.toLowerCase().startsWith(filter))
          .forEach(f => {
            const fullPath = prefix + f + '/';
            const absPath = (base === '/' ? '' : base) + '/' + f;
            suggestions.push({ text: fullPath, canDelete: false, badge: this._getBadgeInfo(absPath) });
          });
      }

      recent
        .filter(r => r !== val && r.toLowerCase().includes(val.toLowerCase()))
        .forEach(r => {
          if (!suggestions.find(s => s.text === r)) {
            suggestions.push({ text: r, canDelete: true, badge: this._getBadgeInfo(r) });
          }
        });

      return suggestions;
    };

    const defaultPath = recent.length > 0 ? recent[0] : home;    const folderDesc = isSSH ? `${backend.user}@${backend.host}` : null;
    const cwd = await window.TuiDialog.prompt('Project folder', {
      description: folderDesc,
      placeholder: `Folder name or Enter to open in ${defaultPath}`,
      autocomplete: autocomplete,
      onDelete: async (p) => {
        if (isSSH) {
          await this._removeSshRecentPath(backend, p);
          recent = await this._fetchSshRecentPaths(backend);
        } else {
          await this._removeRecentPath(p);
          recent = await this.fetchRecentPaths();
        }
      },
      value: ''
    });

    if (cwd === null) return;
    let final = cwd.trim();
    if (!final) final = defaultPath;
    else if (!final.startsWith('/')) {
      if (final.startsWith('~/')) final = home + final.substring(1);
      else final = `${home}/${final}`;
    }
    
    if (isSSH) {
      this._saveSshRecentPath(backend, final);
    } else {
      await this._saveRecentPath(final);
    }

    let recentCmds = isSSH ? await this._fetchSshRecentCommands(backend) : await this.fetchRecentCommands();
    recentCmds = Array.isArray(recentCmds) ? recentCmds : [];
    const defaultCommand = recentCmds.length > 0 ? recentCmds[0] : 'bash';

    const commandAutocomplete = async (val) => {
      const suggestions = [];
      const seen = new Set();

      if (!val) {
        for (const c of recentCmds) {
          if (!seen.has(c)) { seen.add(c); suggestions.push({ text: c, canDelete: true }); }
        }
        return suggestions;
      }

      for (const c of recentCmds) {
        if (c.toLowerCase().startsWith(val.toLowerCase()) && !seen.has(c)) {
          seen.add(c);
          suggestions.push({ text: c, canDelete: true });
        }
      }

      try {
        const endpoint = isSSH ? '/api/ssh-which' : '/api/which';
        const params = isSSH ? { connectionId: backend.connectionId, q: val } : { q: val };
        const { ok, data } = await this.encryptedFetch(endpoint, params);
        if (ok) {
          const matches = data.matches || [];
          for (const m of matches) {
            if (!seen.has(m)) { seen.add(m); suggestions.push({ text: m, canDelete: false }); }
          }
        }
      } catch {}

      return suggestions;
    };

    const cmdDesc = isSSH ? `${backend.user}@${backend.host} — ${final}` : final;
    const cmd = await window.TuiDialog.prompt('Command', {
      description: cmdDesc,
      placeholder: `Command or Enter for ${defaultCommand}`,
      autocomplete: commandAutocomplete,
      onDelete: async (c) => {
        if (isSSH) {
          await this._removeSshRecentCommand(backend, c);
          recentCmds = await this._fetchSshRecentCommands(backend);
        } else {
          await this._removeRecentCommand(c);
          recentCmds = await this.fetchRecentCommands();
        }
      },
      value: ''
    });

    if (cmd === null) return;

    const finalCmd = cmd.trim() || null;
    if (finalCmd) {
      if (isSSH) {
        this._saveSshRecentCommand(backend, finalCmd);
      } else {
        await this._saveRecentCommand(finalCmd);
      }
    }

    return this.create(80, 24, finalCmd, final, backend);
  },

  // Per-second evaluator. Two windows, decoupled:
  //  • PULSE_MS — badge pulse ("running now"). Snappy so a finished shell
  //    clears quickly.
  //  • RUN_GRACE_MS — run tracking for the completion bell. Longer than the
  //    refresh interval of slow apps (top refreshes every ~3s on Linux) so a
  //    continuous run doesn't oscillate busy/idle and reset the run timer.
  // The bell fires on run-end (busy→idle after RUN_GRACE_MS of silence) only
  // if the run lasted ≥ MIN_RUN_MS AND produced ≥ RUN_MIN_CHARS printable output
  // (see countPrintable) — so a resize/prompt redraw, which is escape-heavy and
  // carries little printable volume, can't ring it. Only real activity arms the
  // run (see INPUT_IDLE_MS: output echoing your own typing is ignored), so a
  // process running in the active terminal also notifies on completion. The
  // accent bell icon latches on until the shell is activated (attention marker);
  // BELL_COOLDOWN_MS then mutes the session so a BEL stream can't beep-spam.
  // Output-only heuristic: silent commands (sleep, idle vim) read as idle.
  _evalBusy() {
    const now = Date.now();
    const PULSE_MS = 1500;
    const RUN_GRACE_MS = 5000;
    const MIN_RUN_MS = 10000;
    for (const [id, s] of this.sessions) {
      if (!s.term || !s.tile) continue;
      const pulsing = now - s.lastOutputAt < PULSE_MS;
      s._busy = pulsing;
      const showPulse = pulsing && id !== this.activeId;
      s.tile.classList.toggle('tile--busy', showPulse);
      const card = document.querySelector(`.switcher-card[data-sid="${id}"]`);
      if (card) card.classList.toggle('switcher-card--busy', pulsing);
      s.tile.classList.toggle('tile--bell', s._bellLatched);
      if (card) card.classList.toggle('switcher-card--bell', s._bellLatched);
      const inRun = now - s.lastOutputAt < RUN_GRACE_MS;
      if (inRun && !s._inRun) { s._runStart = now; s.runPrintable = 0; }
      if (s._inRun && !inRun && now - s._runStart >= MIN_RUN_MS && s.runPrintable >= RUN_MIN_CHARS && !this._bellSuppressed && now >= s._suppressBellUntil) {
        if (id !== this.activeId) s._bellLatched = true;
        s.tile.classList.add('bell-flash');
        setTimeout(() => { s.tile.classList.remove('bell-flash'); }, 200);
        if (typeof window.playBellSound === 'function') window.playBellSound();
        s._suppressBellUntil = now + BELL_COOLDOWN_MS;
      }
      s._inRun = inRun;
    }
  },

  // ── Self-update check ──
  _updateOptIn() {
    try { return localStorage.getItem('shells-update-check') !== '0'; } catch (_) { return true; }
  },

  // Auto checks are at most daily, and only while the tab is visible and the
  // user has been active recently — never from a hidden/idle page, so the
  // GitHub API is never hammered by background tabs. Manual checks are always
  // allowed (and re-show a known update instantly).
  _scheduleUpdateCheck() {
    if (this._updateScheduled) return;
    this._updateScheduled = true;
    const interval = 24 * 60 * 60 * 1000; // daily
    const activityWindow = 30 * 60 * 1000; // ignore idle beyond 30 min
    this._updateLastRun = Date.now();
    this._lastActivity = Date.now();
    let settle = null;
    const tryRun = () => {
      if (document.hidden) return;
      if (Date.now() - this._lastActivity > activityWindow) return;
      if (Date.now() - this._updateLastRun < interval) return;
      this._updateLastRun = Date.now();
      this._checkForUpdates().catch(() => {});
    };
    const bump = () => {
      this._lastActivity = Date.now();
      if (settle) return;
      settle = setTimeout(() => { settle = null; tryRun(); }, 10000);
    };
    for (const ev of ['pointerdown', 'pointermove', 'keydown']) {
      document.addEventListener(ev, bump, { passive: true });
    }
    document.addEventListener('visibilitychange', () => { if (!document.hidden) tryRun(); });
    setInterval(tryRun, interval);
  },

  async _checkForUpdates({ manual = false } = {}) {
    // The auto check honors the opt-out; a manual click always checks.
    if (!manual && !this._updateOptIn()) return null;
    // If we already know an update is available (e.g. the modal was dismissed
    // or missed), a manual re-check re-shows it immediately — the cooldown
    // must never lock the user out of an update they already have.
    if (manual && this._pendingUpdate) {
      this._showUpdateModal(this._pendingUpdate);
      return this._pendingUpdate;
    }
    if (manual) {
      try {
        const last = parseInt(localStorage.getItem('shells-update-last') || '0', 10);
        if (Date.now() - last < 120000) {
          window.TuiDialog.toast('Already checked recently', 'info');
          return null;
        }
        localStorage.setItem('shells-update-last', String(Date.now()));
      } catch (_) {}
    }
    try {
      const res = await this.encryptedFetch('/api/update-check', { _method: 'GET', force: !!manual });
      // A verificationFailed result carries an error field, so encryptedFetch
      // marks it ok:false — read data directly or the alarm never fires.
      const info = res?.data || null;
      if (!info || info.error) {
        if (info && info.verificationFailed) {
          this._showVerificationAlarm(info, manual);
          return null;
        }
        if (manual) window.TuiDialog.toast('Update check failed', 'warning');
        return null;
      }
      if (info.updateAvailable) {
        this._pendingUpdate = info;
        this._showUpdateModal(info);
      } else if (manual) {
        this._pendingUpdate = null;
        window.TuiDialog.toast('You are up to date', 'success');
      }
      return info;
    } catch (_) {
      if (manual) window.TuiDialog.toast('Update check failed', 'warning');
      return null;
    }
  },

  // Supply-chain alarm: the release on GitHub failed to verify against the
  // socket.cat signature. Persistent red bar (auto + manual) + a modal on
  // manual checks so it cannot be missed.
  _showVerificationAlarm(info, manual) {
    // Centered in-app modal for both auto and manual checks — never a
    // persistent top bar (it blocks the view).
    if (this._updateModalShown) return;
    this._updateModalShown = true;
    const message = document.createElement('div');
    message.style.lineHeight = '1.6';
    const warn = document.createElement('div');
    warn.style.fontStyle = 'italic';
    warn.style.opacity = '0.9';
    warn.textContent = 'A release published on GitHub failed to verify against the signature on socket.cat. This may indicate tampering or a compromised channel. Do not install updates until this is resolved.';
    message.appendChild(warn);
    window.TuiDialog.alert('Update verification FAILED ☠', message, { size: 'small' }).then(() => {
      this._updateModalShown = false;
    });
  },

  // Update notification: a centered in-app dialog using the existing TuiDialog
  // design — confirm with Update & Restart.
  _showUpdateModal(info) {
    if (this._updateModalShown) return;
    this._updateModalShown = true;
    const message = document.createElement('div');
    message.style.lineHeight = '1.6';
    const line1 = document.createElement('div');
    line1.textContent = `v${info.currentVersion} → v${info.latest} is available.`;
    message.appendChild(line1);
    const warn = document.createElement('div');
    warn.style.fontStyle = 'italic';
    warn.style.opacity = '0.8';
    warn.textContent = 'Update & Restart downloads the verified version and restarts the server. Running shells will be terminated.';
    message.appendChild(warn);
    window.TuiDialog.confirm('Update available', message, {
      confirmText: 'Update & Restart',
      size: 'small',
    }).then((ok) => {
      this._updateModalShown = false;
      if (ok) this._applyUpdate(info);
    });
  },

  async _applyUpdate(info) {
    const n = this.sessions.size;
    if (n > 0) {
      const message = document.createElement('div');
      message.style.lineHeight = '1.6';
      const warn = document.createElement('div');
      warn.style.fontStyle = 'italic';
      warn.style.opacity = '0.8';
      warn.textContent = `Restarting will terminate ${n} running shell${n === 1 ? '' : 's'}.`;
      message.appendChild(warn);
      const ok = await window.TuiDialog.confirm('Update & Restart', message, {
        confirmText: 'Update & Restart',
        size: 'small',
      });
      if (!ok) return;
    }
    const statusClose = window.TuiDialog.status('Updating...', 'Downloading and verifying new version...');
    try {
      const res = await this.encryptedFetch('/api/update', { _method: 'POST' });
      statusClose();
      if (res?.ok && res.data?.applied) {
        window.TuiDialog.toast('Server restarting...', 'success');
        // Seamless: reload onto the new version with no manual refresh.
        if (window.pwaReloadAfterUpdate) window.pwaReloadAfterUpdate();
      } else if (res?.data?.verificationFailed) {
        this._showVerificationAlarm(res.data, true);
      } else {
        window.TuiDialog.toast((res?.data?.error) || 'Update failed — restart manually', 'warning');
      }
    } catch (_) {
      statusClose();
      window.TuiDialog.toast('Update failed — restart manually', 'warning');
    }
  },

  async restore() {
    if (!this._busyTimer) this._busyTimer = setInterval(() => this._evalBusy(), 1000);
    this._updateLoadStatus('authenticating');
    try {
      this.sessions.clear();
      document.querySelectorAll('.shell-tile').forEach(t => t.remove());
      if (this._switcherFallbackTimer) clearTimeout(this._switcherFallbackTimer);
      this._pendingSwitcherSessions = null;

      let savedLayout = localStorage.getItem(this.STORAGE_KEYS.LAYOUT_MODE);
      let savedMaster = localStorage.getItem(this.STORAGE_KEYS.MASTER_ID);
      let savedActive = localStorage.getItem(this.STORAGE_KEYS.ACTIVE_ID);
      let orderRaw = localStorage.getItem(this.STORAGE_KEYS.SESSION_ORDER);
      if (savedLayout) this.layoutMode = savedLayout;

      // Authenticate via WebSocket first to get the shells-token cookie.
      // Retry a few times — on PWA cold start the first WS attempt may fail
      // due to network stack initialization or SW spin-up.
      let wsOk = false;
      for (let attempt = 0; attempt < 3 && !wsOk; attempt++) {
        try {
          await this.getWs();
          wsOk = true;
        } catch (e) {
          if (attempt < 2) {
            this._updateLoadStatus('retrying connection...');
            await new Promise(r => setTimeout(r, 1500));
          } else {
            throw e;
          }
        }
      }

      this._updateLoadStatus('fetching sessions');
      this._setLoadProgress(85);

      // Sync branding from the server now that we're authenticated.
      if (window.ShellTheme && window.ShellTheme.syncFromServer) window.ShellTheme.syncFromServer();

      const { ok, data: list } = await this.encryptedFetch('/api/sessions', { _method: 'GET' });
      if (!ok) throw new Error('Failed to list sessions');
      
      console.log(`[Restore] Server reported ${list.length} sessions`);

      if (list.length === 0) {
        this._updateLoadStatus('waiting for path');
        const result = await this.promptCreate();
        if (!result && this.sessions.size === 0) this.showEmptyState();
        this._dismissLoadScreen();
        return;
      }

      if (orderRaw) {
        try {
          const order = JSON.parse(orderRaw);
          if (Array.isArray(order)) {
            list.sort((a, b) => {
              const ia = order.indexOf(a.id);
              const ib = order.indexOf(b.id);
              if (ia === -1 && ib === -1) return 0;
              if (ia === -1) return 1;
              if (ib === -1) return -1;
              return ia - ib;
            });
          }
        } catch (_) {}
      }

      this._updateLoadStatus(`restoring ${list.length} sessions`);
      this._setLoadProgress(90);

      for (const session of list) {
        if (!this.sessions.has(session.id)) {
          this.mount(session.id, session.title, session.cwd, session.isRemote ? this._getRemoteBadgeFromTitle(session.title) : null);
        }
      }

      if (savedMaster && list.some(s => String(s.id) === savedMaster)) {
        this.masterId = isNaN(Number(savedMaster)) ? savedMaster : Number(savedMaster);
      } else {
        this.masterId = list[list.length - 1].id;
      }

      if (savedActive && list.some(s => String(s.id) === savedActive)) {
        this.setActive(isNaN(Number(savedActive)) ? savedActive : Number(savedActive));
      } else {
        this.setActive(list[list.length - 1].id);
      }


      if (this.sessions.size > 0) {
        this._updateLoadStatus('rendering terminals');
        this._setLoadProgress(95);
        this._pendingSwitcherSessions = new Set(this.sessions.keys());
        this._switcherFallbackTimer = setTimeout(() => {
          this._pendingSwitcherSessions = null;
          this._dismissLoadScreen();
        }, 5000);
        this._checkAllReady();
      } else {
        this._dismissLoadScreen();
      }
    } catch (err) {
      console.error('Restore error:', err);
      if (this.sessions.size === 0) {
        const result = await this.promptCreate().catch(() => null);
        if (!result && this.sessions.size === 0) this.showEmptyState();
      }
      this._dismissLoadScreen();
    }
    // Fire-and-forget: notify about a verified newer release (opt-out aware).
    this._checkForUpdates().catch(() => {});
    // Daily auto checks, only while the user is active.
    this._scheduleUpdateCheck();
  },

  _isMobile() {
    return window.matchMedia('(max-width: 768px)').matches || ('ontouchstart' in window && window.innerWidth <= 768);
  },

  _pendingSwitcherSessions: null,
  _loadDotFrame: 0,
  _loadDotTimer: null,

  _dismissLoadScreen() {
    if (this._loadScreenDismissed) return;
    this._loadScreenDismissed = true;
    const el = document.getElementById('load-screen');
    if (!el) return;

    const forceRefit = () => {
      window.dispatchEvent(new Event('resize'));
    };

    setTimeout(() => {
      el.classList.add('fade-out');
      forceRefit();
      setTimeout(forceRefit, 100);
      setTimeout(forceRefit, 400);
      if (this.activeId) {
        const s = this.sessions.get(this.activeId);
        if (s && s.term) s.term.focus();
      }
      setTimeout(() => el.remove(), 1000);
      setTimeout(() => { this._bellSuppressed = false; }, 2000);
    }, 200);
  },

  _showLoadScreen(compact = false) {
    if (!this._loadScreenDismissed && !document.getElementById('load-screen')) return;
    this._loadScreenDismissed = false;

    let el = document.getElementById('load-screen');
    if (!el) {
      el = document.createElement('div');
      el.id = 'load-screen';
      el.innerHTML = `
        <div class="load-splash">
          <img class="load-icon" src="${(window.ShellTheme && window.ShellTheme.accent) ? window.ShellTheme.svgDataUrl(window.ShellTheme.accent) : '/icon.svg'}" alt="" width="128" height="128">
          <div class="load-app-name">Shells</div>
          <div class="load-bar"><div class="load-bar-fill" id="load-bar-fill"></div></div>
          <div id="load-status">connecting</div>
          <a id="load-force-reload" class="hidden" href="#" role="button">Stuck? Force reload</a>
          <div class="load-sig">Shells v${document.body.dataset.version || ''} · <a href="https://socket.cat" target="_blank" rel="noopener">socket.cat</a></div>
        </div>
      `;
      document.body.appendChild(el);
      const loadName = el.querySelector('.load-app-name');
      if (loadName) loadName.textContent = window.ShellTheme?.appName || 'Shells';
    }

    el.classList.remove('fade-out');
    el.classList.toggle('compact', !!compact);
    el.style.display = '';
  },

  _updateLoadStatus(text) {
    const el = document.getElementById('load-status');
    if (el) el.textContent = text;
  },

  _setLoadProgress(pct) {
    const bar = document.getElementById('load-bar-fill');
    if (bar) bar.style.width = pct + '%';
  },

  _checkAllReady() {
    if (!this._pendingSwitcherSessions) return;
    const activeSession = this.activeId ? this.sessions.get(this.activeId) : null;
    const activeReady = activeSession && activeSession.term && activeSession.term.element;
    if (!activeReady) return;
    this._pendingSwitcherSessions = null;
    clearTimeout(this._switcherFallbackTimer);
    this._dismissLoadScreen();
    if (this._isMobile() && window.ShellLayout?.switcher && this.sessions.size > 1) {
      setTimeout(() => window.ShellLayout.switcher.show(), 200);
    }
  },

  _switcherFallbackTimer: null,

  _clearScalingStyles(id, term) {
    const body = document.getElementById(`term-${id}`);
    if (body) {
      body.classList.remove('pty-scaled');
      body.style.overflow = '';
      const interceptor = body.querySelector('.pty-scale-interceptor');
      if (interceptor) interceptor.style.display = 'none';
    }
    const xtermEl = term.element;
    if (xtermEl) {
      xtermEl.style.width = '';
      xtermEl.style.height = '';
      xtermEl.style.right = '';
      xtermEl.style.bottom = '';
      xtermEl.style.transform = '';
      xtermEl.style.transformOrigin = '';
      xtermEl.style.pointerEvents = '';
    }
  },

  _claimActiveIfNeeded(id, session, term, fitAddon) {
    this._isActiveClient.set(id, true);
    this._clearScalingStyles(id, term);
    session._scaleFactor = 1.0;
    requestAnimationFrame(() => {
      if (fitAddon) {
        window.__dbg?.trace('fit.call', { sid: String(id), source: 'claim-active' });
        try { fitAddon.fit(); } catch (_) {}
        window.__dbg?.trace('fit.done', { sid: String(id), source: 'claim-active' });
      }
    });
    if (!this._lastClaimActive) this._lastClaimActive = new Map();
    const now = Date.now();
    const lastClaim = this._lastClaimActive.get(id) || 0;
    if (now - lastClaim < 300) return;
    this._lastClaimActive.set(id, now);
    const proposed = fitAddon.proposeDimensions();
    this.sendWs({
      type: 'claim-active',
      sid: id,
      cols: proposed?.cols || term.cols,
      rows: proposed?.rows || term.rows,
    });
  },

  _handlePtySize(sid, cols, rows, isActive) {
    const session = this.sessions.get(sid);
    if (!session || !session.term || !session.term.element) {
      this._pendingPtySize = this._pendingPtySize || new Map();
      this._pendingPtySize.set(sid, { cols, rows, isActive });
      return;
    }
    window.__dbg?.trace('ptySize.recv', { sid, cols, rows, isActive });

    this._ptySizes.set(sid, { cols, rows });
    this._isActiveClient.set(sid, !!isActive);

    if (isActive) {
      this._clearScalingStyles(sid, session.term);
      session._scaleFactor = 1.0;
      requestAnimationFrame(() => {
        if (session.fitAddon) {
          window.__dbg?.trace('fit.call', { sid: String(sid), source: 'pty-size-active' });
          try { session.fitAddon.fit(); } catch (_) {}
          window.__dbg?.trace('fit.done', { sid: String(sid), source: 'pty-size-active' });
        }
      });
    } else {
      requestAnimationFrame(() => {
        // A non-active client must not resize its terminal to the active client's
        // size: that reflows the whole scrollback every time the active role
        // switches between devices (the observed scroll loop). Keep the local
        // size and just scale the incoming frame down to fit this tile.
        this._applyScaling(session, sid, cols, rows);
      });
    }
  },

  _applyScaling(session, sid, ptyCols, ptyRows, retryCount = 0) {
    if (retryCount > 10) return;
    const body = document.getElementById(`term-${sid}`);
    const xtermEl = session.term.element;
    if (!body || !xtermEl) return;

    const dims = session.term._core?._renderService?.dimensions;
    if (!dims || dims.css.cell.width === 0 || dims.css.cell.height === 0) {
      window.__dbg?.trace('applyScaling.retry', { sid, retryCount });
      setTimeout(() => this._applyScaling(session, sid, ptyCols, ptyRows, retryCount + 1), 100 * Math.pow(1.5, retryCount));
      return;
    }

    const cellW = dims.css.cell.width;
    const cellH = dims.css.cell.height;
    const ptyPixelWidth = ptyCols * cellW;
    const ptyPixelHeight = ptyRows * cellH;
    const availableWidth = body.clientWidth;
    const availableHeight = body.clientHeight;

    const scaleFactor = Math.min(
      availableWidth / ptyPixelWidth,
      availableHeight / ptyPixelHeight,
      1.0
    );
    window.__dbg?.trace('applyScaling', { sid, pty: ptyCols + 'x' + ptyRows, avail: availableWidth + 'x' + availableHeight, scale: scaleFactor });

    session._scaleFactor = scaleFactor;
    session._cachedBodyRect = null;

    if (scaleFactor < 1.0) {
      xtermEl.style.width = ptyPixelWidth + 'px';
      xtermEl.style.height = ptyPixelHeight + 'px';
      xtermEl.style.right = 'auto';
      xtermEl.style.bottom = 'auto';
      xtermEl.style.transform = `scale(${scaleFactor})`;
      xtermEl.style.transformOrigin = 'top left';
      xtermEl.style.pointerEvents = 'none';
      body.classList.add('pty-scaled');
      body.style.overflow = 'visible';

      let interceptor = body.querySelector('.pty-scale-interceptor');
      if (!interceptor) {
        interceptor = document.createElement('div');
        interceptor.className = 'pty-scale-interceptor';
        body.appendChild(interceptor);
        this._setupScaleInterceptor(interceptor, session, sid);
      }
      interceptor.style.display = '';
    } else {
      xtermEl.style.width = '';
      xtermEl.style.height = '';
      xtermEl.style.right = '';
      xtermEl.style.bottom = '';
      xtermEl.style.transform = '';
      xtermEl.style.transformOrigin = '';
      xtermEl.style.pointerEvents = '';
      body.classList.remove('pty-scaled');
      body.style.overflow = '';

      const interceptor = body.querySelector('.pty-scale-interceptor');
      if (interceptor) interceptor.style.display = 'none';
    }
  },

  _setupScaleInterceptor(interceptor, session, sid) {
    const getAdjustedCoords = (clientX, clientY) => {
      const sf = session._scaleFactor;
      if (!sf || sf >= 1.0) return { clientX, clientY };
      let rect = session._cachedBodyRect;
      if (rect) session._cachedBodyRect = null;
      if (!rect) {
        const el = document.getElementById(`term-${sid}`);
        if (el) rect = el.getBoundingClientRect();
      }
      if (!rect) return { clientX, clientY };
      return {
        clientX: rect.left + (clientX - rect.left) / sf,
        clientY: rect.top + (clientY - rect.top) / sf,
      };
    };

    const getXtermTarget = () => session.term.element?.querySelector('.xterm-screen') || session.term.element;

    const dispatch = (type, e, extra) => {
      const target = getXtermTarget();
      if (!target) return;
      const { clientX, clientY } = getAdjustedCoords(e.clientX, e.clientY);
      target.dispatchEvent(new MouseEvent(type, { clientX, clientY, bubbles: true, cancelable: true, ...extra }));
    };

    let dragging = false;

    const docMouseMove = (e) => {
      e.stopImmediatePropagation();
      const target = getXtermTarget();
      if (!target) return;
      const { clientX, clientY } = getAdjustedCoords(e.clientX, e.clientY);
      target.dispatchEvent(new MouseEvent('mousemove', { clientX, clientY, bubbles: true, cancelable: true, button: e.button, buttons: e.buttons }));
    };

    const docMouseUp = (e) => {
      dragging = false;
      document.removeEventListener('mousemove', docMouseMove, true);
      document.removeEventListener('mouseup', docMouseUp, true);
      session._dragCleanup = null;
      e.stopImmediatePropagation();
      const target = getXtermTarget();
      if (!target) return;
      const { clientX, clientY } = getAdjustedCoords(e.clientX, e.clientY);
      target.dispatchEvent(new MouseEvent('mouseup', { clientX, clientY, bubbles: true, cancelable: true, button: e.button, buttons: 0 }));
    };

    session._dragCleanup = () => {
      if (!dragging) return;
      dragging = false;
      document.removeEventListener('mousemove', docMouseMove, true);
      document.removeEventListener('mouseup', docMouseUp, true);
    };

    interceptor.addEventListener('mousedown', (e) => {
      e.preventDefault(); e.stopPropagation();
      this.setActive(sid);
      if (!dragging) {
        dragging = true;
        document.addEventListener('mousemove', docMouseMove, true);
        document.addEventListener('mouseup', docMouseUp, true);
      }
      dispatch('mousedown', e, { button: e.button, buttons: e.buttons });
    });
    interceptor.addEventListener('mousemove', (e) => {
      e.preventDefault(); e.stopPropagation();
      dispatch('mousemove', e, { button: e.button, buttons: e.buttons });
    });
    interceptor.addEventListener('mouseup', (e) => {
      e.preventDefault(); e.stopPropagation();
      dispatch('mouseup', e, { button: e.button, buttons: 0 });
    });
    interceptor.addEventListener('click', (e) => {
      e.preventDefault(); e.stopPropagation();
      dispatch('click', e, { button: e.button });
    });
    interceptor.addEventListener('dblclick', (e) => {
      e.preventDefault(); e.stopPropagation();
      dispatch('dblclick', e, { button: e.button });
    });
    interceptor.addEventListener('wheel', (e) => {
      e.preventDefault(); e.stopPropagation();
      const { clientX, clientY } = getAdjustedCoords(e.clientX, e.clientY);
      const target = getXtermTarget();
      if (!target) return;
      target.dispatchEvent(new WheelEvent('wheel', {
        clientX, clientY,
        deltaY: e.deltaY,
        deltaMode: e.deltaMode,
        bubbles: true,
        cancelable: true,
      }));
    });
    interceptor.addEventListener('contextmenu', (e) => {
      e.preventDefault(); e.stopPropagation();
      dispatch('contextmenu', e, { button: 2 });
    });
  },

  async destroy(id, callServer = true) {
    const session = this.sessions.get(id);
    if (!session) return;
    
    if (callServer) {
      try {
        await this.encryptedFetch(`/api/sessions/${id}`, { _method: 'DELETE' });
      } catch (_) {}
    }

    if (session.ro) session.ro.disconnect();
    if (session._dragCleanup) session._dragCleanup();
    await this.sendWs({ type: 'detach', sid: id });
    if (session.term) session.term.dispose();
    
    const tile = document.getElementById(`tile-${id}`);
    const cmdBar = document.getElementById('cmd-bar');
    if (cmdBar && tile && tile.contains(cmdBar)) document.getElementById('app').appendChild(cmdBar);
    if (tile) tile.remove();
    
    this.sessions.delete(id);
    this._ptySizes.delete(id);
    this._isActiveClient.delete(id);
    if (this._lastClaimActive) this._lastClaimActive.delete(id);
    if (this.masterId === id) {
      const remaining = [...this.sessions.keys()];
      this.masterId = remaining.length > 0 ? remaining[remaining.length - 1] : null;
    }
    if (this.activeId === id) {
      const remaining = [...this.sessions.keys()];
      const nextId = remaining.length > 0 ? remaining[remaining.length - 1] : null;
      this.setActive(nextId);
    } else {
      window.ShellLayout.updateActiveHighlight(this.activeId, this.masterId);
    }
    this.saveState();
    this.updateGrid();
    this._refreshFsTabs();
    if (this.sessions.size === 0) {
      this.promptCreate().then(result => {
        if (!result && this.sessions.size === 0) this.showEmptyState();
      });
    }
  },

  mount(id, title, cwd, backendBadge) {
    if (this.sessions.has(id) || document.getElementById(`tile-${id}`)) {
      console.log(`[Mount] Session ${id} already mounted, skipping.`);
      return;
    }
    this.sessions.set(id, { mounting: true, cwd, backendBadge: backendBadge || null });

    const container = document.getElementById('shell-grid');
    const emptyState = document.getElementById('empty-state');
    if (emptyState) emptyState.remove();

    const tile = document.createElement('div');
    tile.className = 'shell-tile';
    tile.id = `tile-${id}`;

    const header = document.createElement('div');
    header.className = 'tile-header';

    const createBtn = (title, action, shellId, icon, extraClass = '') => {
      const btn = document.createElement('button');
      btn.title = title;
      btn.setAttribute('data-action', action);
      if (shellId) btn.setAttribute('data-shell-id', shellId);
      if (extraClass) btn.classList.add(extraClass);
      btn.innerHTML = icon;
      return btn;
    };

    const switcherBtn = createBtn(window.ShellTheme?.appName || 'Shells', 'show-switcher', null, `<svg viewBox="0 0 512 512" style="width:16px;height:16px"><path d="M256 96 L394.56 176 L394.56 336 L256 416 L117.44 336 L117.44 176 Z" fill="none" stroke="var(--accent)" stroke-width="32" stroke-linejoin="round"/></svg>`, 'tile-logo');

    const bellIcon = document.createElement('span');
    bellIcon.className = 'tile-bell-icon';
    bellIcon.innerHTML = window.Icons.bell;
    header.appendChild(bellIcon);

    if (backendBadge) {
      header.appendChild(this._makeBadge(backendBadge.color, backendBadge.text, true));
    }
    if (cwd) {
      const badge = this._getBadgeInfo(cwd);
      header.appendChild(this._makeBadge(badge.color, badge.text));
    }

    const titleSpan = document.createElement('span');
    titleSpan.className = 'tile-title';
    titleSpan.textContent = title || `shell #${id}`;

    const actions = document.createElement('div');
    actions.className = 'tile-actions';

    const mobile = this._isMobile();
    const moreWrap = mobile ? document.createElement('span') : null;
    if (moreWrap) moreWrap.className = 'tile-more';
    const more = (btn) => (moreWrap || actions).appendChild(btn);

    actions.appendChild(switcherBtn);
    const isStandalone = window.isStandalonePWA ? window.isStandalonePWA() : false;
    if (!isStandalone) actions.appendChild(createBtn('Install app', 'install-pwa', null, window.Icons.download, 'install-btn'));
    if (!mobile) actions.appendChild(createBtn('Promote to Master', 'promote-master', id, window.Icons.promote));
    actions.appendChild(createBtn('New shell', 'new-shell', null, window.Icons.plus));
    if (!mobile) actions.appendChild(createBtn('Cycle Layout', 'cycle-layout', null, window.Icons.layout));
    if (mobile) {
      const moreBtn = createBtn('More', 'toggle-overflow', null, window.Icons.overflow, 'tile-more-btn');
      const onOutside = (e) => {
        if (!actions.contains(e.target)) {
          actions.classList.remove('more-open');
          document.removeEventListener('click', onOutside, true);
        }
      };
      moreBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        actions.classList.add('more-open');
        setTimeout(() => document.addEventListener('click', onOutside, true), 0);
      });
      actions.appendChild(moreBtn);
    }
    more(createBtn('Choose Theme', 'toggle-theme', null, window.Icons.themeCircle));
    more(createBtn('Smaller font', 'font-minus', null, '<span class="fs-a">A</span>'));
    more(createBtn('Bigger font', 'font-plus', null, '<span class="fs-a fs-a--lg">A</span>'));
    more(createBtn('Search', 'open-search', id, window.Icons.search));
    if (mobile) more(createBtn('Keyboard', 'open-keyboard', id, window.Icons.keyboard));
    more(createBtn('Fullscreen', 'toggle-fullscreen', id, window.Icons.maximize));
    if (moreWrap) actions.appendChild(moreWrap);
    actions.appendChild(createBtn('Close', 'destroy-shell', id, window.Icons.close));
    actions.appendChild(createBtn('Lock', 'lock', null, window.Icons.lock));

    header.appendChild(titleSpan);
    header.appendChild(actions);

    const body = document.createElement('div');
    body.className = 'tile-body';
    body.id = `term-${id}`;

    tile.appendChild(header);
    tile.appendChild(body);

    tile.addEventListener('mousedown', (e) => {
      if (e.target.closest('.fs-tab-bar')) return;
      this.setActive(id);
      if (e.target && e.target.closest('#cmd-bar, #cmd-input, textarea, input, button, [contenteditable="true"]')) return;
      window._focusWithoutScroll(term);
      if (!this._isActiveClient.get(id)) {
        window.__dbg?.trace('claim', { sid: String(id), reason: 'mousedown' });
        this._claimActiveIfNeeded(id, session, term, fitAddon);
      }
    });
    container.appendChild(tile);
    this._refreshFsTabs();

    const term = new Terminal({
      cursorBlink: true,
      fontSize: this._getFontSize(),
      lineHeight: 1,
      fontFamily: "'Fira Code', monospace",
      fontLigatures: true,
      // mobile gets a lighter scrollback so resizes don't re-wrap a huge buffer (the full 5000 stays on desktop)
      scrollback: this._isMobile() ? 1500 : 5000,
      theme: (window.ShellTheme && window.ShellTheme.xtermTheme) || window.darkTheme || { background: '#000000' },
      allowTransparency: false,
      allowProposedApi: true,
      drawBoldTextInBrightColors: true,
      minimumContrastRatio: 4.5,
      scrollOnUserInput: false,
      smoothScrollDuration: 0,
      fastScrollModifier: 'alt',
      fastScrollSensitivity: 5,
      scrollSensitivity: 1,
    });

    const fitAddon = new FitAddon.FitAddon();
    term.loadAddon(fitAddon);
    term.open(body);
    term._sid = id;

    const vpEl = term.element?.querySelector('.xterm-viewport');
    if (vpEl) {
      vpEl.addEventListener('scroll', () => {
        window.__dbg?.trace('viewport.scroll', {
          sid: String(id),
          scrollTop: Math.round(vpEl.scrollTop),
          clientHeight: vpEl.clientHeight,
          scrollHeight: vpEl.scrollHeight,
          viewportY: term.buffer?.active?.viewportY,
          baseY: term.buffer?.active?.baseY,
        });
      }, { passive: true });
    }

    try {
      const webglAddon = new WebglAddon.WebglAddon();
      webglAddon.onContextLoss(() => {
        try { webglAddon.dispose(); } catch (_) {}
        term._webglAddon = null;
        window.__dbg?.trace('renderer.contextloss', { sid: String(id) });
      });
      term.loadAddon(webglAddon);
      term._webglAddon = webglAddon;
      window.__dbg?.trace('renderer', { sid: String(id), type: 'webgl' });
    } catch (e) {
      console.log('[xterm] WebGL2 not available, using canvas renderer:', e.message);
      term._webglAddon = null;
      window.__dbg?.trace('renderer', { sid: String(id), type: 'canvas', reason: e.message });
    }

    term.loadAddon(new Unicode11Addon.Unicode11Addon());
    term.unicode.activeVersion = '11';

    term.loadAddon(new ClipboardAddon.ClipboardAddon());
    term.loadAddon(new WebLinksAddon.WebLinksAddon());

    let searchAddon = null;
    if (window.SearchAddon && window.SearchAddon.SearchAddon) {
      try {
        searchAddon = new SearchAddon.SearchAddon();
        term.loadAddon(searchAddon);
      } catch (_) { searchAddon = null; }
    }

    term.attachCustomKeyEventHandler((e) => {
      if (e.key === 'Enter' && e.shiftKey) {
        if (e.type === 'keydown') {
          this.sendWs({ type: 'data', sid: id, data: '\n' });
        }
        return false;
      }
      return true;
    });

    const gestureLayer = document.createElement('div');
    gestureLayer.className = 'mobile-gesture-layer';
    body.appendChild(gestureLayer);

      let _realFocus = null;
      if (this._isMobile()) {
        const textarea = term.element?.querySelector('textarea.xterm-helper-textarea');
        if (textarea) {
          textarea.setAttribute('autocapitalize', 'none');
          textarea.focus = () => {};
          _realFocus = () => { textarea.blur(); HTMLElement.prototype.focus.call(textarea); };
        }
      }

      let touchGesture = { active: false, mode: 'idle', startX: 0, startY: 0, lastY: 0, longPressTimer: null, allowNativeSelection: false, lastTapTime: 0, lastTapX: 0, lastTapY: 0 };
      const resetTouchGesture = () => {
        clearTimeout(touchGesture.longPressTimer);
        touchGesture.active = false;
        touchGesture.mode = 'idle';
        touchGesture.allowNativeSelection = false;
        gestureLayer.classList.remove('selection-mode');
      };

      gestureLayer.addEventListener('touchstart', (e) => {
        if (e.touches.length !== 1) { resetTouchGesture(); return; }
        e.preventDefault(); e.stopPropagation();
        window._clearTouchSelection(term);
        this.setActive(id);
        if (!this._isActiveClient.get(id)) {
          window.__dbg?.trace('claim', { sid: String(id), reason: 'touchstart' });
          this._claimActiveIfNeeded(id, session, term, fitAddon);
        }
        window.ShellSessions._scaleCoordSid = id;
        const touch = e.touches[0];
        touchGesture.active = true; touchGesture.mode = 'tap';
        touchGesture.startX = touch.clientX; touchGesture.startY = touch.clientY; touchGesture.lastY = touch.clientY;
        touchGesture.longPressTimer = setTimeout(() => {
          if (!touchGesture.active || touchGesture.mode !== 'tap') return;
          touchGesture.allowNativeSelection = true; touchGesture.mode = 'select';
          gestureLayer.classList.add('selection-mode');
          const target = term.element?.querySelector('.xterm-screen') || term.element;
          if (target) target.dispatchEvent(new MouseEvent('mousedown', { clientX: touch.clientX, clientY: touch.clientY, button: 0, buttons: 1, bubbles: true, cancelable: true }));
        }, 450);
      }, { capture: true, passive: false });

      gestureLayer.addEventListener('touchmove', (e) => {
        if (!touchGesture.active || e.touches.length !== 1) return;
        const touch = e.touches[0];
        const dx = touch.clientX - touchGesture.startX;
        const dy = touch.clientY - touchGesture.startY;
        if (touchGesture.allowNativeSelection) return;
        e.preventDefault(); e.stopPropagation();
        window.ShellSessions._scaleCoordSid = id;
        if (touchGesture.mode === 'tap') {
          if (Math.abs(dx) < 10 && Math.abs(dy) < 10) return;
          clearTimeout(touchGesture.longPressTimer);
          touchGesture.mode = Math.abs(dx) > Math.abs(dy) * 1.25 ? 'horizontal' : 'vertical';
        }
        if (touchGesture.mode === 'vertical') {
          const deltaY = touchGesture.lastY - touch.clientY;
          touchGesture.lastY = touch.clientY;
          if (Math.abs(deltaY) >= 1) window._dispatchTerminalWheel(term, touch.clientX, touch.clientY, deltaY * 3);
        }
      }, { capture: true, passive: false });

      gestureLayer.addEventListener('touchend', (e) => {
        clearTimeout(touchGesture.longPressTimer);
        window.ShellSessions._scaleCoordSid = id;
        if (touchGesture.allowNativeSelection) {
          e.preventDefault(); e.stopPropagation();
          const touch = e.changedTouches[0];
          const target = term.element?.querySelector('.xterm-screen') || term.element;
          if (target && touch) target.dispatchEvent(new MouseEvent('mouseup', { clientX: touch.clientX, clientY: touch.clientY, button: 0, buttons: 0, bubbles: true, cancelable: true }));
          resetTouchGesture(); return;
        }
        e.preventDefault(); e.stopPropagation();
        const touch = e.changedTouches[0];
        const dx = touch ? touch.clientX - touchGesture.startX : 0;
        const dy = touch ? touch.clientY - touchGesture.startY : 0;
        if (touchGesture.mode === 'tap' && touch) {
          const now = Date.now();
          const isDoubleTap = (now - touchGesture.lastTapTime) < 300
            && Math.abs(touch.clientX - touchGesture.lastTapX) < 30
            && Math.abs(touch.clientY - touchGesture.lastTapY) < 30;
          if (isDoubleTap) {
            touchGesture.lastTapTime = 0;
          } else {
            touchGesture.lastTapTime = now;
            touchGesture.lastTapX = touch.clientX;
            touchGesture.lastTapY = touch.clientY;
          }
          window._dispatchTerminalMouse(term, 'mousedown', touch.clientX, touch.clientY, 1);
          window._dispatchTerminalMouse(term, 'mouseup', touch.clientX, touch.clientY, 0);
          window._dispatchTerminalMouse(term, 'click', touch.clientX, touch.clientY, 0);
          if (isDoubleTap && _realFocus) {
            // Fullscreen on double-tap only makes sense with a single
            // terminal; with several, lateral swipe switches instead.
            // NOTE: a single tap must never focus the hidden textarea —
            // that would pop the native keyboard on mobile.
            if (this.sessions.size <= 1) {
              const wasFs = tile.classList.contains('fullscreen');
              if (!wasFs) {
                this.toggleFullscreen(id);
                tile.dataset.autoFs = '1';
              }
            }
            _realFocus();
          }
          resetTouchGesture();
        } else if (touchGesture.mode === 'horizontal' && Math.abs(dx) > 80 && Math.abs(dy) < 60) {
          if (this.sessions.size > 1) {
            if (dx > 0) this.previous(); else this.next();
          }
          resetTouchGesture();
        } else {
          resetTouchGesture();
        }
      }, { capture: true });
      gestureLayer.addEventListener('touchcancel', resetTouchGesture, { capture: true });

    const fitPreservingView = () => {
      const b = term.buffer && term.buffer.active;
      const vy = b ? b.viewportY : 0;
      const by = b ? b.baseY : 0;
      window.__dbg?.trace('fit.call', { sid: String(id), source: 'ro-active' });
      try { fitAddon.fit(); } catch (_) {}
      window.__dbg?.trace('fit.done', { sid: String(id), source: 'ro-active' });
      // A rows-only resize does not rewrap content: restore the viewport so the
      // user keeps seeing the same content (baseY unchanged proves no reflow).
      requestAnimationFrame(() => {
        const b2 = term.buffer && term.buffer.active;
        if (b2 && b2.baseY === by && b2.viewportY !== vy) {
          try { term.scrollLines(vy - b2.viewportY); } catch (_) {}
        }
      });
    };

    const ro = new ResizeObserver(() => {
      try {
        const isActive = this._isActiveClient.get(id);
        window.__dbg?.trace('resizeObserver', { sid: String(id), isActive, bodyW: body.clientWidth, bodyH: body.clientHeight, termCols: term.cols, termRows: term.rows });
        if (isActive !== false) {
          clearTimeout(session._fitSettle);
          session._fitSettle = setTimeout(() => {
            requestAnimationFrame(() => {
              fitPreservingView();
            });
          }, 300);
        } else {
          requestAnimationFrame(() => {
            const proposed = fitAddon.proposeDimensions();
            if (proposed && proposed.cols && proposed.rows) {
              this.sendWs({ type: 'available-size', sid: id, cols: proposed.cols, rows: proposed.rows });
            }
            const ptySize = this._ptySizes.get(id);
            if (ptySize) {
              this._applyScaling(session, id, ptySize.cols, ptySize.rows);
            }
          });
        }
      } catch (_) {}
    });
    ro.observe(body);

    const session = { term, fitAddon, searchAddon, tile, cwd, ro, backendBadge: backendBadge || null, isAsleep: false, title: title || `shell #${id}`, _suppressBellUntil: Date.now() + 3000, _scaleFactor: 1.0, _cachedBodyRect: null, lastOutputAt: 0, _busy: false, _inRun: false, _runStart: 0, runPrintable: 0, lastInputAt: 0, _bellLatched: false, _fitSettle: null };

    term.onBell(() => {
      if (this._bellSuppressed || Date.now() < session._suppressBellUntil) return;
      if (id !== this.activeId) session._bellLatched = true;
      tile.classList.add('bell-flash');
      setTimeout(() => { tile.classList.remove('bell-flash'); }, 200);
      if (typeof window.playBellSound === 'function') window.playBellSound();
      session._suppressBellUntil = Date.now() + BELL_COOLDOWN_MS;
    });

    term.onTitleChange((t) => {
      const newTitle = t || `shell #${id}`;
      if (newTitle === session.title) return;
      session.title = newTitle;

      const el = tile.querySelector('.tile-title');
      if (el) el.textContent = newTitle;
      this._updateFsTabTitle(id, newTitle);
      if (id === this.activeId) document.title = `${window.ShellTheme?.appName || 'Shells'} - ${newTitle}`;
      this.sendWs({ type: 'title', sid: id, title: t });
    });

    term.onData((data) => {
      session.lastInputAt = Date.now();
      this.sendWs({ type: 'data', sid: id, data });
    });
    term.onResize(({ cols, rows }) => {
      window.__dbg?.trace('term.onResize', { sid: String(id), cols, rows, isActive: this._isActiveClient.get(id) });
      if (this._isActiveClient.get(id) !== false) {
        this.sendWs({ type: 'resize', sid: id, cols, rows });
      }
    });
    this.sessions.set(id, session);

    if (this._pendingPtySize?.has(id)) {
      const pending = this._pendingPtySize.get(id);
      this._pendingPtySize.delete(id);
      this._handlePtySize(id, pending.cols, pending.rows, pending.isActive);
    }
    
    this.getWs().then(() => {
      this.sendWs({ type: 'attach', sid: id, cols: term.cols, rows: term.rows });
    }).catch(() => {});

    this.updateFontWeights();
    this.updateGrid();
    if (this.activeId === id) window._focusWithoutScroll(term);
  },

  updateFontWeights() {
    const type = document.documentElement.dataset.themeType || 'dark';
    const isDesktop = window.innerWidth > 768;
    const normalWeight = (type === 'light' && isDesktop) ? 300 : 400;
    const boldWeight = (type === 'light' && isDesktop) ? 500 : 700;
    for (const s of this.sessions.values()) {
      if (s.term) {
        s.term.options.fontWeight = normalWeight;
        s.term.options.fontWeightBold = boldWeight;
      }
    }
  },

  setActive(id, slideDir) {
    const prev = this.activeId ? this.sessions.get(this.activeId) : null;
    const wasFullscreen = this.activeId && prev?.tile.classList.contains('fullscreen');
    this.activeId = id;
    if (this._searchState && this._searchState.sid !== id) this.closeSearch();
    const session = this.sessions.get(id);
    if (session) {
      session._bellLatched = false;
      session.tile.classList.remove('tile--bell');
      session.tile.classList.remove('tile--busy');
    }
    this.saveState();
    document.title = session?.title ? `${window.ShellTheme?.appName || 'Shells'} - ${session.title}` : (window.ShellTheme?.appName || 'Shells');
    window.ShellLayout.updateActiveHighlight(this.activeId, this.masterId);
    const cmdBar = document.getElementById('cmd-bar');
    if (cmdBar) {
      if (this._isMobile() && this._wsReady) {
        cmdBar.style.display = '';
        const tile = id ? document.getElementById(`tile-${id}`) : null;
        if (tile) tile.appendChild(cmdBar); else document.getElementById('app').appendChild(cmdBar);
      } else {
        cmdBar.style.display = 'none';
      }
    }
    if (wasFullscreen) {
      document.querySelectorAll('.shell-tile').forEach(t => {
        t.classList.remove('fullscreen');
        this._removeFsTabs(t);
      });
      const session = this.sessions.get(id);
      if (session) {
        session.tile.classList.add('fullscreen');
        this._renderFsTabs(session.tile);
        if (slideDir && prev && prev.tile !== session.tile) {
          const dir = slideDir === 'left' ? -1 : 1;
          const enterFrom = dir * 100;
          const exitTo = -dir * 100;
          prev.tile.style.transition = 'none';
          prev.tile.style.transform = `translateX(0)`;
          prev.tile.style.zIndex = '1000';
          session.tile.style.transition = 'none';
          session.tile.style.transform = `translateX(${enterFrom}%)`;
          session.tile.style.zIndex = '1001';
          session.tile.offsetHeight;
          prev.tile.style.transition = 'transform 0.2s ease-out';
          prev.tile.style.transform = `translateX(${exitTo}%)`;
          session.tile.style.transition = 'transform 0.2s ease-out';
          session.tile.style.transform = 'translateX(0)';
          const cleanup = () => {
            [prev.tile, session.tile].forEach(t => {
              t.style.transition = '';
              t.style.transform = '';
              t.style.zIndex = '';
            });
            prev.tile.classList.remove('fullscreen');
          };
          session.tile.addEventListener('transitionend', cleanup, { once: true });
          setTimeout(cleanup, 250);
        }
      }
    }
    this.updateSleepState();
    this._ensureFullscreenMobile(id);
    if (session?.term) window._focusWithoutScroll(session.term);
  },

  _ensureFullscreenMobile(id) {
    if (!this._isMobile() || this.sessions.size <= 1) return;
    const target = id || this.activeId;
    const session = this.sessions.get(target);
    if (!session || !session.tile) return;
    if (session.tile.classList.contains('fullscreen')) return;
    this.toggleFullscreen(target);
  },

  toggleFullscreen(id) {
    const session = this.sessions.get(id);
    if (!session) return;
    const entering = !session.tile.classList.contains('fullscreen');
    session.tile.classList.toggle('fullscreen');
    if (!entering) {
      session.tile.style.height = '';
      this._removeFsTabs(session.tile);
    } else {
      this._renderFsTabs(session.tile);
    }
    this.updateSleepState();
  },

  _renderFsTabs(tile) {
    if (this.sessions.size <= 1) return;
    let tabBar = tile.querySelector('.fs-tab-bar');
    if (!tabBar) {
      tabBar = document.createElement('div');
      tabBar.className = 'fs-tab-bar';
      const header = tile.querySelector('.tile-header');
      const actions = header.querySelector('.tile-actions');
      header.insertBefore(tabBar, actions);
    }
    tabBar.innerHTML = '';
    for (const [sid, s] of this.sessions) {
      const tab = document.createElement('button');
      tab.className = 'fs-tab' + (sid === this.activeId ? ' active' : '');
      tab.dataset.sessionId = sid;

      if (s.backendBadge) {
        const rbb = document.createElement('span');
        rbb.className = 'fs-tab-badge';
        rbb.style.backgroundColor = s.backendBadge.color;
        rbb.style.color = '#000';
        rbb.style.marginRight = '0';
        rbb.textContent = s.backendBadge.text;
        tab.appendChild(rbb);
      }
      if (s.cwd) {
        const badge = this._getBadgeInfo(s.cwd);
        const badgeEl = document.createElement('span');
        badgeEl.className = 'fs-tab-badge';
        badgeEl.style.backgroundColor = badge.color;
        badgeEl.style.color = '#000';
        badgeEl.textContent = badge.text;
        tab.appendChild(badgeEl);
      }

      const titleEl = document.createElement('span');
      titleEl.className = 'fs-tab-title';
      titleEl.textContent = s.title || `shell #${sid}`;
      tab.appendChild(titleEl);

      tab.addEventListener('click', (e) => {
        if (sid !== this.activeId) this.setActive(sid);
      });

      tabBar.appendChild(tab);
    }
  },

  _removeFsTabs(tile) {
    const tabBar = tile.querySelector('.fs-tab-bar');
    if (tabBar) tabBar.remove();
  },

  _refreshFsTabs() {
    const fsTile = document.querySelector('.shell-tile.fullscreen');
    if (!fsTile) return;
    if (this.sessions.size <= 1) {
      this._removeFsTabs(fsTile);
      return;
    }
    this._renderFsTabs(fsTile);
  },

  _updateFsTabTitle(id, title) {
    const fsTile = document.querySelector('.shell-tile.fullscreen');
    if (!fsTile) return;
    const tab = fsTile.querySelector(`.fs-tab[data-session-id="${id}"] .fs-tab-title`);
    if (tab) tab.textContent = title;
  },

  updateSleepState() {
    const activeSession = this.activeId ? this.sessions.get(this.activeId) : null;
    const fullscreenSessionId = (activeSession && activeSession.tile.classList.contains('fullscreen')) ? this.activeId : null;
    for (const [sid, session] of this.sessions) {
      if (fullscreenSessionId && sid !== fullscreenSessionId) {
        if (!session.isAsleep) { session.isAsleep = true; this.sendWs({ type: 'pause', sid }); }
      } else if (session.isAsleep) {
        session.isAsleep = false; this.sendWs({ type: 'resume', sid });
      }
    }
  },

  updateGrid() {
    window.ShellLayout.updateGrid(this.sessions, this.layoutMode);
  },

  showEmptyState() {
    if (document.getElementById('empty-state')) return;
    if (this.sessions.size > 0) return;
    const grid = document.getElementById('shell-grid');
    const es = document.createElement('div');
    es.id = 'empty-state';
    es.innerHTML = `
      <img class="empty-icon" src="${(window.ShellTheme && window.ShellTheme.accent) ? window.ShellTheme.svgDataUrl(window.ShellTheme.accent) : '/icon.svg'}" alt="" width="128" height="128">
      <div class="empty-app-name">Shells</div>
      <button class="empty-new-btn" data-action="new-shell">New Shell</button>
      <button class="empty-new-btn empty-lock-btn" data-action="lock">Lock</button>
      <button class="empty-appearance-btn" data-action="toggle-theme" title="Appearance">◐ Appearance</button>
      <div class="empty-shortcut">alt+n</div>
      <div class="empty-sig">Shells v${document.body.dataset.version || ''} · <a href="https://socket.cat" target="_blank" rel="noopener">socket.cat</a></div>
    `;
    grid.appendChild(es);
    const emptyName = es.querySelector('.empty-app-name');
    if (emptyName) emptyName.textContent = window.ShellTheme?.appName || 'Shells';
  },

  writeActive(data) {
    if (!this.activeId) return false;
    return this.sendWs({ type: 'data', sid: this.activeId, data });
  },

  _getFontSize() {
    if (this._fontSize === null) {
      let v = 14;
      try {
        const s = parseInt(localStorage.getItem('shells-font-size'), 10);
        if (s >= 8 && s <= 32) v = s;
      } catch (_) {}
      this._fontSize = v;
    }
    return this._fontSize;
  },

  setFontSize(delta) {
    const next = Math.max(8, Math.min(32, this._getFontSize() + delta));
    if (next === this._getFontSize()) return;
    this._fontSize = next;
    try { localStorage.setItem('shells-font-size', String(next)); } catch (_) {}
    this.sessions.forEach((s, sid) => {
      if (s.term) {
        try {
          s.term.options.fontSize = next;
          if (s.fitAddon) {
            window.__dbg?.trace('fit.call', { sid: String(sid), source: 'font-size' });
            s.fitAddon.fit();
            window.__dbg?.trace('fit.done', { sid: String(sid), source: 'font-size' });
          }
        } catch (_) {}
      }
    });
  },

  // Suspends or restores the WebGL renderer on every terminal. Disposing the
  // WebGL addon drops the terminal to the lightweight canvas renderer (the
  // buffer/scrollback are untouched, just one frame re-render). Used around
  // PWA install, where Chrome's GPU sync with active WebGL contexts can hang
  // the renderer for the whole origin (RESULT_CODE_HUNG).
  setWebglEnabled(enabled) {
    const Addon = window.WebglAddon && window.WebglAddon.WebglAddon;
    this.sessions.forEach((s, sid) => {
      const term = s.term;
      if (!term) return;
      if (enabled) {
        if (term._webglAddon || !Addon) return;
        try {
          const w = new Addon();
          w.onContextLoss(() => { try { w.dispose(); } catch (_) {} term._webglAddon = null; });
          term.loadAddon(w);
          term._webglAddon = w;
          if (s.fitAddon) {
            window.__dbg?.trace('fit.call', { sid: String(sid), source: 'webgl' });
            try { s.fitAddon.fit(); } catch (_) {}
            window.__dbg?.trace('fit.done', { sid: String(sid), source: 'webgl' });
          }
          try { term.refresh(0, term.rows - 1); } catch (_) {}
        } catch (_) { term._webglAddon = null; }
      } else if (term._webglAddon) {
        try { term._webglAddon.dispose(); } catch (_) {}
        term._webglAddon = null;
      }
    });
  },

  // ── In-terminal search (active tile) ──
  openSearch() {
    if (!this.activeId) return;
    const session = this.sessions.get(this.activeId);
    if (!session || !session.searchAddon) return;
    // Already open: just refocus, don't wipe the query.
    if (this._searchState) {
      const input = document.querySelector('#term-search-bar input');
      if (input) { input.focus(); input.select(); }
      return;
    }

    const tile = session.tile;
    const body = tile.querySelector('.tile-body');
    if (!body) return;

    const accent = (getComputedStyle(document.documentElement).getPropertyValue('--accent') || '').trim() || '#fab283';
    this._searchDecorations = {
      matchBackground: '#fd8f8f',
      matchForeground: '#1a1a1a',
      activeMatchBackground: accent,
      activeMatchForeground: '#000000',
      matchOverviewRuler: '#fd8f8f',
      activeMatchColorOverviewRuler: accent,
    };

    const bar = document.createElement('div');
    bar.id = 'term-search-bar';
    bar.className = 'term-search-bar';

    const input = document.createElement('input');
    input.type = 'text';
    input.placeholder = 'Search';
    input.maxLength = 512;
    input.autocomplete = 'off';
    input.autocapitalize = 'none';
    input.autocorrect = 'off';
    input.spellcheck = false;
    input.setAttribute('aria-label', 'Search terminal');

    const caseBtn = document.createElement('button');
    caseBtn.type = 'button';
    caseBtn.className = 'tsb-toggle';
    caseBtn.textContent = 'Aa';
    caseBtn.title = 'Match case';
    caseBtn.addEventListener('click', () => { caseBtn.classList.toggle('active'); run(); });

    const regexBtn = document.createElement('button');
    regexBtn.type = 'button';
    regexBtn.className = 'tsb-toggle';
    regexBtn.textContent = '.*';
    regexBtn.title = 'Regular expression';
    regexBtn.addEventListener('click', () => { regexBtn.classList.toggle('active'); run(); });

    const prevBtn = document.createElement('button');
    prevBtn.type = 'button';
    prevBtn.className = 'tsb-nav';
    prevBtn.textContent = '\u25B2';
    prevBtn.title = 'Previous (Shift+Enter)';
    prevBtn.addEventListener('click', () => this.searchPrev());

    const nextBtn = document.createElement('button');
    nextBtn.type = 'button';
    nextBtn.className = 'tsb-nav';
    nextBtn.textContent = '\u25BC';
    nextBtn.title = 'Next (Enter)';
    nextBtn.addEventListener('click', () => this.searchNext());

    const count = document.createElement('span');
    count.className = 'tsb-count';

    const closeBtn = document.createElement('button');
    closeBtn.type = 'button';
    closeBtn.className = 'tsb-close';
    closeBtn.textContent = '\u00D7';
    closeBtn.title = 'Close (Esc)';
    closeBtn.addEventListener('click', () => this.closeSearch());

    bar.appendChild(input);
    bar.appendChild(caseBtn);
    bar.appendChild(regexBtn);
    bar.appendChild(prevBtn);
    bar.appendChild(nextBtn);
    bar.appendChild(count);
    bar.appendChild(closeBtn);
    body.appendChild(bar);

    this._searchState = {
      sid: this.activeId,
      query: '',
      opts: { caseSensitive: false, regex: false },
      count: 0,
      index: 0,
      lastFound: null,
      regexError: false,
      unsub: null,
    };

    if (typeof session.searchAddon.onDidChangeResults === 'function') {
      this._searchState.unsub = session.searchAddon.onDidChangeResults((data) => {
        if (!this._searchState || this._searchState.sid !== this.activeId) return;
        if (data && typeof data.resultCount === 'number') {
          this._searchState.count = data.resultCount;
          this._searchState.index = data.resultCount ? data.resultIndex + 1 : 0;
          this._updateSearchCount();
        }
      });
    }

    const run = (dir = 1) => {
      if (!this._searchState) return;
      this._searchState.query = input.value;
      this._searchState.opts.caseSensitive = caseBtn.classList.contains('active');
      this._searchState.opts.regex = regexBtn.classList.contains('active');
      if (dir > 0) this.searchNext(); else this.searchPrev();
    };

    let debounce = null;
    input.addEventListener('input', () => {
      clearTimeout(debounce);
      debounce = setTimeout(run, 150);
    });
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        clearTimeout(debounce);
        run(e.shiftKey ? -1 : 1);
      } else if (e.key === 'Escape') {
        e.preventDefault();
        this.closeSearch();
      }
    });

    input.focus();
  },

  closeSearch() {
    const bar = document.getElementById('term-search-bar');
    if (bar) bar.remove();
    if (this._searchState) {
      const sid = this._searchState.sid;
      if (this._searchState.unsub) {
        try { this._searchState.unsub.dispose(); } catch (_) { try { this._searchState.unsub(); } catch (_2) {} }
      }
      this._clearSearch();
      const session = this.sessions.get(sid);
      if (session && session.term) window._focusWithoutScroll(session.term);
    }
    this._searchState = null;
  },

  _searchSession() {
    if (!this._searchState) return null;
    const s = this.sessions.get(this._searchState.sid);
    return s && s.searchAddon ? s : null;
  },

  _searchOptions() {
    const opts = { caseSensitive: this._searchState.opts.caseSensitive, regex: this._searchState.opts.regex };
    if (this._searchDecorations) opts.decorations = this._searchDecorations;
    return opts;
  },

  _clearSearch() {
    const s = this._searchSession();
    if (s && s.searchAddon && typeof s.searchAddon.clearDecorations === 'function') {
      try { s.searchAddon.clearDecorations(); } catch (_) {}
    }
  },

  // Single search path for both directions (dedupes searchNext/searchPrev and
  // validates the query — an invalid regex must not reach the addon, which
  // would throw an uncaught SyntaxError and permanently disable highlights).
  _runSearch(dir) {
    const s = this._searchSession();
    if (!s) return;
    const st = this._searchState;
    const q = st.query;
    if (!q) {
      this._clearSearch();
      st.lastFound = true;
      st.regexError = false;
      this._updateSearchCount();
      return;
    }
    if (st.opts.regex) {
      try { new RegExp(q); } catch (_) {
        st.regexError = true;
        st.lastFound = false;
        this._updateSearchCount();
        return;
      }
    }
    st.regexError = false;
    const opts = this._searchOptions();
    let res = null;
    try {
      res = dir > 0 ? s.searchAddon.findNext(q, opts) : s.searchAddon.findPrevious(q, opts);
    } catch (_) {
      // Decorations unsupported on this xterm: drop them for good and retry.
      this._searchDecorations = null;
      const plain = { caseSensitive: st.opts.caseSensitive, regex: st.opts.regex };
      try { res = dir > 0 ? s.searchAddon.findNext(q, plain) : s.searchAddon.findPrevious(q, plain); } catch (_2) { res = null; }
    }
    st.lastFound = !!(res && res.found);
    this._updateSearchCount();
  },

  searchNext() { this._runSearch(1); },
  searchPrev() { this._runSearch(-1); },

  _updateSearchCount() {
    const count = document.querySelector('#term-search-bar .tsb-count');
    if (!count || !this._searchState) return;
    const st = this._searchState;
    if (!st.query) { count.textContent = ''; return; }
    if (st.regexError) { count.textContent = 'bad regex'; return; }
    if (st.count > 0) {
      count.textContent = `${st.index}/${st.count}`;
    } else if (st.lastFound === false) {
      count.textContent = 'no results';
    } else {
      count.textContent = '';
    }
  },

  next() {
    const ids = Array.from(this.sessions.keys());
    if (ids.length <= 1) return;
    const idx = (ids.indexOf(this.activeId) + 1) % ids.length;
    this.setActive(ids[idx], 'left');
  },

  previous() {
    const ids = Array.from(this.sessions.keys());
    if (ids.length <= 1) return;
    const idx = (ids.indexOf(this.activeId) - 1 + ids.length) % ids.length;
    this.setActive(ids[idx], 'right');
  },

  _showTuiStatus(id, text, type = 'info') {
    const tile = document.getElementById(`tile-${id}`);
    if (!tile) return;
    
    // Hide cmd-bar if it's currently in this tile
    const cmdBar = document.getElementById('cmd-bar');
    if (cmdBar && tile.contains(cmdBar)) {
      cmdBar.style.display = 'none';
    }

    // Remove any existing status bar
    const old = tile.querySelector('.tui-status-bar');
    if (old) old.remove();

    const bar = document.createElement('div');
    bar.className = `tui-status-bar ${type}`;
    bar.textContent = text;
    // Stop propagation so clicking the bar doesn't trigger setActive/focus on the dead terminal
    bar.onmousedown = (e) => e.stopPropagation();
    bar.onclick = (e) => {
      e.stopPropagation();
      this.destroy(id, false);
    };
    tile.appendChild(bar);
  },
});
