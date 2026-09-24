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

// ── PTY scaling + active-client arbitration ──
// Extracted from shell-sessions.js. Maps the PTY grid onto
// differently-sized client tiles (font scaling, coordinate translation,
// touch/wheel interceptors) and claims which client is active for a
// session across devices. State (_ptySizes/_isActiveClient) stays
// declared once in the core literal; core's window._getScaledCoords
// bridge calls _scaledCoords here (sanctioned per plan).

window.ShellSessions = Object.assign(window.ShellSessions, {
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

  _claimActiveIfNeeded(id) {
    const session = this.sessions.get(id);
    if (!session || !session.term || !session.fitAddon || this._isActiveClient.get(id)) return;
    const term = session.term;
    const fitAddon = session.fitAddon;
    this._isActiveClient.set(id, true);
    this._clearScalingStyles(id, term);
    session._scaleFactor = 1.0;
    requestAnimationFrame(() => {
      try { fitAddon.fit(); } catch (_) {}
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
    this._ptySizes.set(sid, { cols, rows });
    this._isActiveClient.set(sid, !!isActive);

    if (isActive) {
      this._clearScalingStyles(sid, session.term);
      session._scaleFactor = 1.0;
      requestAnimationFrame(() => {
        if (session.fitAddon) {
          try { session.fitAddon.fit(); } catch (_) {}
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

    // Fresh-load reclaim: this pty-size is the attach-ack (the server sends it
    // only once the client is attached), so it is safe to claim now. If another
    // device holds the active role, take it over for this session.
    if (this._pendingClaimSids && this._pendingClaimSids.has(sid)) {
      this._pendingClaimSids.delete(sid);
      if (!isActive) {
        this._claimActiveIfNeeded(sid);
      }
    }
  },

  _applyScaling(session, sid, ptyCols, ptyRows, retryCount = 0) {
    if (retryCount > 10) return;
    // Never scale an active tile: a fresh-load claim may have flipped this
    // client to active after the rAF was queued, and scaling must not
    // overwrite the cleared styles (guards the retry path too).
    if (this._isActiveClient.get(sid)) return;
    const body = document.getElementById(`term-${sid}`);
    const xtermEl = session.term.element;
    if (!body || !xtermEl) return;

    const dims = session.term._core?._renderService?.dimensions;
    if (!dims || dims.css.cell.width === 0 || dims.css.cell.height === 0) {
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

  _scaledCoords(session, sid, clientX, clientY) {
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
  },

  _setupScaleInterceptor(interceptor, session, sid) {
    const getAdjustedCoords = (clientX, clientY) => this._scaledCoords(session, sid, clientX, clientY);

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
      this._claimActiveIfNeeded(sid);
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
});
