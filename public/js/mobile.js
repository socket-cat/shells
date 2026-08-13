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

// ── Mobile Features and Helpers ──
// ShellSwitcher moved to window.ShellSwitcher in switcher.js

// ── Swipe navigation for mobile ──
(function() {
  let touchStartX = 0;
  let touchStartY = 0;
  let touchStartX2 = 0;
  let touchStartY2 = 0;
  let multiTouch = false;
  let twoFingerFired = false;


  const inExcludedTarget = (t) => !!(t && t.closest && (
    t.closest('.tui-overlay') ||
    t.closest('.fs-tab-bar') ||
    t.closest('#shell-switcher')
  ));

  const sendKey = (data) => {
    const s = window.ShellSessions;
    if (s && typeof s.writeActive === 'function') s.writeActive(data);
  };

  document.addEventListener('touchstart', (e) => {
    if (e.touches.length === 1) {
      touchStartX = e.touches[0].clientX;
      touchStartY = e.touches[0].clientY;
    } else if (e.touches.length === 2) {
      multiTouch = true;
      twoFingerFired = false;
      touchStartX2 = (e.touches[0].clientX + e.touches[1].clientX) / 2;
      touchStartY2 = (e.touches[0].clientY + e.touches[1].clientY) / 2;
    }
  }, { passive: true });

  document.addEventListener('touchmove', (e) => {
    // Fire the two-finger gesture mid-swipe: some browsers cancel the touch
    // (touchcancel) once they decide the gesture is not theirs, so we must
    // act before touchend may or may not arrive.
    if (!multiTouch || twoFingerFired || e.touches.length !== 2) return;
    if (inExcludedTarget(e.target)) return;
    const avgX = (e.touches[0].clientX + e.touches[1].clientX) / 2;
    const avgY = (e.touches[0].clientY + e.touches[1].clientY) / 2;
    const dx = avgX - touchStartX2;
    const dy = avgY - touchStartY2;
    if (Math.abs(dx) > 60 && Math.abs(dy) < 80) {
      twoFingerFired = true;
      if (dx > 0) {
        sendKey('\t');
      } else {
        sendKey('\x1b');
      }
    }
  }, { passive: true });

  document.addEventListener('touchend', (e) => {
    // A text-selection gesture is in progress on a terminal: do not let the
    // stale-start coords of this touchend trigger a shell switch.
    if (document.querySelector('.mobile-gesture-layer.selection-mode')) return;
    // Ignore swipes inside dialogs, the fs tab bar (it scrolls horizontally
    // itself) and the switcher panel.
    const target = e.target;
    if (inExcludedTarget(target)) return;

    const doSwipe = (dx, dy, onLeft, onRight) => {
      if (Math.abs(dx) > 100 && Math.abs(dy) < 50) {
        if (dx > 0) { onRight(); } else { onLeft(); }
      }
    };

    const doSwipe2 = (dx, dy) => {
      if (twoFingerFired) return;
      if (Math.abs(dx) > 60 && Math.abs(dy) < 80) {
        twoFingerFired = true;
        if (dx > 0) {
          sendKey('\t');
        } else {
          sendKey('\x1b');
        }
      }
    };

    if (e.changedTouches.length === 2) {
      // Both fingers lifted: two-finger gesture (TAB / ESC).
      if (multiTouch) {
        const endX = (e.changedTouches[0].clientX + e.changedTouches[1].clientX) / 2;
        const endY = (e.changedTouches[0].clientY + e.changedTouches[1].clientY) / 2;
        doSwipe2(endX - touchStartX2, endY - touchStartY2);
      }
      multiTouch = false;
      twoFingerFired = false;
      return;
    }

    if (e.changedTouches.length !== 1) return;
    const touchEndX = e.changedTouches[0].clientX;
    const touchEndY = e.changedTouches[0].clientY;

    if (e.touches.length > 0) {
      // One finger still down: part of a multi-touch gesture; wait for the
      // final finger to lift before evaluating it.
      return;
    }

    if (multiTouch) {
      // Staggered two-finger lift: evaluate as a two-finger gesture.
      doSwipe2(touchEndX - touchStartX2, touchEndY - touchStartY2);
      multiTouch = false;
      twoFingerFired = false;
      return;
    }

    // Single-finger lateral swipe switches terminals even in grid mode (no
    // fullscreen required).
    const dx = touchEndX - touchStartX;
    const dy = touchEndY - touchStartY;
    if (Math.abs(dx) > 100 && Math.abs(dy) < 50) {
      if (dx > 0) {
        window.ShellSessions.previous();
      } else {
        window.ShellSessions.next();
      }
    }
  }, { passive: true });

  document.addEventListener('touchcancel', () => {
    multiTouch = false;
    twoFingerFired = false;
  }, { passive: true });

  // ── Mobile Viewport / Keyboard Handling ──
  if (window.visualViewport && window.ShellSessions && window.ShellSessions._isMobile()) {
    let vvRaf = null;
    let refitSettle = null;
    let lastVvWidth = null;
    let lastVvHeight = null;

    const syncAppPosition = () => {
      const vv = window.visualViewport;
      const app = document.getElementById('app');
      if (!app) return false;
      const isKeyboardOpen = window.innerHeight - vv.height > 60;
      if (isKeyboardOpen) {
        app.style.position = 'fixed';
        app.style.top = vv.offsetTop + 'px';
        app.style.left = vv.offsetLeft + 'px';
        app.style.width = vv.width + 'px';
        app.style.height = vv.height + 'px';
      } else {
        app.style.position = '';
        app.style.top = '';
        app.style.left = '';
        app.style.width = '';
        app.style.height = '';
      }
      return isKeyboardOpen;
    };

    const refitAllTerms = () => {
      if (!window.ShellSessions || !window.ShellSessions.sessions) return;
      window.ShellSessions.sessions.forEach((session) => {
        if (session && session.fitAddon && session.tile && session.tile.offsetWidth > 0) {
          try { session.fitAddon.fit(); } catch (_) {}
        }
      });
    };

    const doViewportUpdate = () => {
      const vv = window.visualViewport;
      syncAppPosition();
      const currentWidth = Math.round(vv.width);
      const currentHeight = Math.round(vv.height);
      const isFirstMeasure = lastVvWidth === null || lastVvHeight === null;
      if (currentWidth !== lastVvWidth || currentHeight !== lastVvHeight) {
        const prevWidth = lastVvWidth;
        const prevHeight = lastVvHeight;
        lastVvWidth = currentWidth;
        lastVvHeight = currentHeight;
        const widthDelta = prevWidth === null ? 0 : Math.abs(currentWidth - prevWidth);
        const heightDelta = prevHeight === null ? 0 : Math.abs(currentHeight - prevHeight);
        if (isFirstMeasure || widthDelta >= 2 || heightDelta >= 6) {
          if (!isFirstMeasure && heightDelta >= 60 && currentHeight > prevHeight) {
            document.querySelectorAll('.shell-tile[data-auto-fs]').forEach(t => {
              t.classList.remove('fullscreen');
              delete t.dataset.autoFs;
            });
          }
          clearTimeout(refitSettle);
          refitSettle = setTimeout(() => {
            requestAnimationFrame(() => { refitAllTerms(); });
          }, 300);
        }
      }
    };

    const scheduleViewportUpdate = () => {
      if (vvRaf) cancelAnimationFrame(vvRaf);
      vvRaf = requestAnimationFrame(doViewportUpdate);
    };

    window.visualViewport.addEventListener('scroll', () => {
      syncAppPosition();
    });
    window.visualViewport.addEventListener('resize', () => {
      scheduleViewportUpdate();
    });
    doViewportUpdate();
  }

  // ── Auto layout based on orientation ──
  let savedDesktopLayout = null;

  function applyMobileLayout() {
    if (!window.ShellSessions || !window.ShellLayout) return;
    const isMobile = window.ShellSessions._isMobile();
    if (isMobile) {
      if (!savedDesktopLayout) savedDesktopLayout = window.ShellSessions.layoutMode;
      // +120 hysteresis: URL-bar / keyboard height flapping must not flip orientation.
      const isLandscape = window.innerWidth > window.innerHeight + 120;
      const mode = isLandscape ? 'columns' : 'rows';
      if (window.ShellSessions.layoutMode !== mode) {
        window.ShellSessions.layoutMode = mode;
        window.ShellLayout.updateGrid(window.ShellSessions.sessions, mode);
      }
    } else if (savedDesktopLayout) {
      const mode = savedDesktopLayout;
      savedDesktopLayout = null;
      window.ShellSessions.layoutMode = mode;
      // Leaving mobile: undo any forced fullscreen so tiles are not stuck
      // overlaying the desktop grid after a window resize.
      document.querySelectorAll('.shell-tile.fullscreen').forEach((t) => {
        t.classList.remove('fullscreen');
        if (window.ShellSessions._removeFsTabs) window.ShellSessions._removeFsTabs(t);
      });
      window.ShellLayout.updateGrid(window.ShellSessions.sessions, mode);
    }
  }
  applyMobileLayout();
  window.addEventListener('resize', applyMobileLayout);
  if (screen.orientation) {
    screen.orientation.addEventListener('change', applyMobileLayout);
  }

  // Initial switchers
  if (window.ShellSwitcher) {
    window.ShellSwitcher.init();
  }

  // ── On-screen gesture hints (mobile, first run) ──
  (function() {
    const ROWS = [
      ['← →', '1 finger swipe', 'switch shell'],
      ['↔', '2 fingers swipe', 'ESC / TAB'],
      ['↕', '2 fingers', 'previews / keyboard'],
      ['2×', 'double tap', 'mobile keyboard'],
    ];

    function show() {
      if (document.getElementById('gesture-hints')) return;
      const overlay = TuiDialog._createOverlay({ id: 'gesture-hints' });
      const close = () => { if (overlay._unbind) overlay._unbind(); overlay.remove(); };
      overlay._unbind = TuiDialog._bindOverlay(overlay, close);

      const modal = TuiDialog._createDialog('small');
      modal.appendChild(TuiDialog._createBrandBar());
      modal.appendChild(TuiDialog._createHeader('Gestures', close));

      const body = document.createElement('div');
      body.className = 'tui-dialog-body';
      body.style.padding = '4px 32px 12px';

      ROWS.forEach(([glyph, act, res]) => {
        const row = document.createElement('div');
        row.className = 'gh-row';
        const g = document.createElement('span');
        g.className = 'gh-gesture';
        g.textContent = glyph;
        const a = document.createElement('span');
        a.className = 'gh-act';
        a.textContent = act;
        const r = document.createElement('span');
        r.className = 'gh-res';
        r.textContent = res;
        row.appendChild(g);
        row.appendChild(a);
        row.appendChild(r);
        body.appendChild(row);
      });

      modal.appendChild(body);
      overlay.appendChild(modal);
    }

    function maybeShow() {
      if (!window.ShellSessions || !window.ShellSessions._isMobile()) return;
      const tick = setInterval(() => {
        if (window.ShellSessions._wsReady && window.ShellSessions.sessions.size > 0) {
          clearInterval(tick);
          setTimeout(show, 400);
        }
      }, 300);
      setTimeout(() => clearInterval(tick), 20000);
    }
    maybeShow();
  })();

})();
