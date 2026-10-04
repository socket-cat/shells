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

window.__HOSTNAME__ = document.body.dataset.hostname;
window.__APP_VERSION__ = document.body.dataset.version || '';

// ── Global Shortcuts ──
// Alt+letter shortcuts fire only when the key yields that plain letter, so
// characters composed with Alt still reach the shell: macOS Option+N is the
// ñ dead key, Option+Q types œ, Windows AltGr (Ctrl+Alt) +Q types @.
const altLetter = (e, letter) => e.altKey && !e.ctrlKey && e.key.toLowerCase() === letter;
// Ctrl+W is readline delete-word, but a browser tab closes on it: ask first. Programmatic reloads set _unloadOk.
window.addEventListener('beforeunload', (e) => {
  if (!window._unloadOk && window.ShellSessions?.sessions.size) { e.preventDefault(); e.returnValue = ''; }
});
// Keyboard lock (Chromium): in page fullscreen Ctrl+W/T/N and Esc reach the
// shell instead of the browser; hold Esc to leave. Browser F11 fullscreen
// doesn't count, so F11 is taken over to enter page fullscreen.
if (navigator.keyboard?.lock) {
  navigator.keyboard.lock().catch(() => {});
  window.addEventListener('keydown', (e) => {
    if (e.key !== 'F11' || e.ctrlKey || e.altKey || e.metaKey || e.shiftKey) return;
    e.preventDefault();
    if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
    else document.documentElement.requestFullscreen().then(() => navigator.keyboard.lock()).catch(() => {});
  });
}
window.addEventListener('keydown', (e) => {
  // Ctrl/Cmd +/-/0 zoom the terminal font, not the whole page.
  const zoom = window.ShellSessions.fontZoomDelta(e);
  if (zoom !== null) {
    e.preventDefault();
    window.ShellSessions.setFontSize(zoom);
  }
  if (altLetter(e, 'q')) {
    e.preventDefault();
    const ss = window.ShellSessions;
    const tile = ss.activeId && ss.sessions.get(ss.activeId)?.tile;
    // Same confirmation as the Close button: destroying kills running jobs.
    if (tile) TuiDialog.confirmDestroy(ss.activeId, tile.querySelector('.tile-title')?.textContent || 'this shell', tile);
  }
  if (altLetter(e, 'n')) {
    e.preventDefault();
    window.ShellSessions.promptCreate();
  }
  // Alt+Shift+←/→ like native terminals leave Alt+←/→ to the shell (word movement).
  if (e.altKey && e.shiftKey && e.code === 'ArrowRight') {
    e.preventDefault();
    window.ShellSessions.next();
  }
  if (e.altKey && e.shiftKey && e.code === 'ArrowLeft') {
    e.preventDefault();
    window.ShellSessions.previous();
  }
  if (e.ctrlKey && e.code === 'Tab') {
    e.preventDefault();
    if (e.shiftKey) window.ShellSessions.previous();
    else window.ShellSessions.next();
  }
  if (e.ctrlKey && e.shiftKey && e.code === 'KeyF' && !e.altKey) {
    // Ctrl+Shift+F: in-terminal search when the terminal itself is focused
    // (the xterm textarea), as in native terminals — plain Ctrl+F stays with
    // the shell (vim/less/htop page-down). Other inputs (search bar, cmd bar,
    // dialogs) keep the browser's behavior; AltGr combos pass through. Esc
    // closes the bar and returns focus.
    const ss = window.ShellSessions;
    const session = ss && ss.activeId ? ss.sessions.get(ss.activeId) : null;
    if (session && session.searchAddon) {
      const ae = document.activeElement;
      // Intentionally NOT TuiDialog.isEditableTarget: this variant must treat the xterm helper textarea as pass-through (Ctrl+Shift+F in terminal) and ignores contentEditable.
      const inInput = !!(ae && (ae.tagName === 'INPUT' || ae.tagName === 'TEXTAREA'));
      const isTerminalInput = inInput && ae.classList && ae.classList.contains('xterm-helper-textarea');
      if (!inInput || isTerminalInput) {
        e.preventDefault();
        e.stopPropagation();
        ss.openSearch();
      }
    }
  }
}, true);

// ── Grid Click Delegation ──
document.getElementById('shell-grid').addEventListener('click', (e) => {
  const switcherBtn = e.target.closest('[data-action="show-switcher"]');
  if (switcherBtn) { window.ShellLayout.switcher.show(); return; }
  const newBtn = e.target.closest('[data-action="new-shell"]');
  if (newBtn) { window.ShellSessions.promptCreate(); return; }
  const layoutBtn = e.target.closest('[data-action="cycle-layout"]');
  if (layoutBtn) { window.ShellSessions.cycleLayout(); return; }
  const promoteBtn = e.target.closest('[data-action="promote-master"]');
  if (promoteBtn) { window.ShellSessions.promoteToMaster(promoteBtn.dataset.shellId); window.ShellSessions.refocus(); return; }
  const kbBtn = e.target.closest('[data-action="open-keyboard"]');
  if (kbBtn) { window.ShellKeyboard.open(); return; }
  const searchBtn = e.target.closest('[data-action="open-search"]');
  if (searchBtn) { window.ShellSessions.openSearch(); return; }
  const themeBtn = e.target.closest('[data-action="toggle-theme"]');
  if (themeBtn) {
    window.ShellTheme.toggle();
    return;
  }
  const fontMinusBtn = e.target.closest('[data-action="font-minus"]');
  if (fontMinusBtn) { window.ShellSessions.setFontSize(-1); window.ShellSessions.refocus(); return; }
  const fontPlusBtn = e.target.closest('[data-action="font-plus"]');
  if (fontPlusBtn) { window.ShellSessions.setFontSize(1); window.ShellSessions.refocus(); return; }
  const btn = e.target.closest('[data-action="toggle-fullscreen"]');
  if (btn) { window.ShellSessions.toggleFullscreen(btn.dataset.shellId); window.ShellSessions.refocus(); return; }
  const lockBtn = e.target.closest('[data-action="lock"]');
  if (lockBtn) {
    const tile = lockBtn.closest('.shell-tile');
    const message = document.createElement('div');
    message.style.lineHeight = '1.4';
    message.appendChild(document.createTextNode('Lock this session?'));
    message.appendChild(document.createElement('br'));
    const sub = document.createElement('span');
    sub.style.color = 'var(--text)';
    sub.textContent = 'Terminals keep running. You will need to re-enter the shared secret to unlock.';
    message.appendChild(sub);

    // "Lock all devices" — off by default, only manual, never from autolock.
    const allDevices = document.createElement('label');
    allDevices.style.cssText = 'display:flex;align-items:center;gap:8px;margin-top:12px;font-family:var(--font-mono);font-size:12px;color:var(--text);cursor:pointer';
    const allCb = document.createElement('input');
    allCb.type = 'checkbox';
    allCb.style.cssText = 'accent-color:var(--accent);width:15px;height:15px;flex-shrink:0';
    allDevices.appendChild(allCb);
    allDevices.appendChild(document.createTextNode('Lock all devices'));
    message.appendChild(allDevices);

    // Autolock after N min idle (0 = off), persisted even if the dialog is
    // dismissed without locking.
    const idleRow = document.createElement('div');
    idleRow.style.cssText = 'display:flex;align-items:center;gap:8px;margin-top:8px;font-family:var(--font-mono);font-size:12px;color:var(--text-muted)';
    idleRow.appendChild(document.createTextNode('Autolock after'));
    const idleInput = document.createElement('input');
    idleInput.type = 'number';
    idleInput.min = '0';
    idleInput.max = '720';
    let idleVal = window.ShellSessions.getAutolockMin ? window.ShellSessions.getAutolockMin() : 0;
    idleInput.value = String(idleVal);
    idleInput.style.cssText = 'width:56px;background:var(--bg-surface);border:1px solid var(--border);border-radius:0;color:var(--text);font-family:var(--font-mono);font-size:12px;padding:2px 6px;text-align:center';
    idleInput.addEventListener('change', () => {
      idleInput.value = String(window.ShellSessions.setAutolockMin(parseInt(idleInput.value, 10)));
    });
    idleInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        // Never let Enter in this field submit the dialog (which would lock).
        e.preventDefault();
        e.stopPropagation();
        idleInput.blur();
      }
    });
    idleRow.appendChild(idleInput);
    idleRow.appendChild(document.createTextNode('min idle (0 = off)'));
    message.appendChild(idleRow);

    TuiDialog.confirm('Lock Session', message, {
      dangerous: true,
      confirmText: 'Yes, lock',
      parent: tile || undefined,
      size: 'small',
      onConfirm: () => {
        if (allCb.checked) {
          window.ShellSessions.sendLockAll().then((ok) => {
            if (!ok && window.TuiDialog) window.TuiDialog.toast('Could not reach server — other devices were not locked', 'error');
            window.ShellSessions.lock();
          });
        } else {
          window.ShellSessions.lock();
        }
      },
    });
    return;
  }
  const destroyBtn = e.target.closest('[data-action="destroy-shell"]');
  if (destroyBtn) {
    const shellId = destroyBtn.dataset.shellId;
    const tile = destroyBtn.closest('.shell-tile');
    const titleText = tile.querySelector('.tile-title')?.textContent || 'this shell';
    
    TuiDialog.confirmDestroy(shellId, titleText, tile);
    return;
  }
});

// ── Init ──
(async () => {
  try {
    if (window.GridResizer) window.GridResizer.init();
    window.ShellTheme.init();
    if (!window.ShellSessions) throw new Error('ShellSessions failed to load');
    await window.ShellSessions.restore();
  } catch (err) {
    if (window.ShellSessions && window.ShellSessions._dismissLoadScreen) {
      window.ShellSessions._dismissLoadScreen();
    } else {
      const loadScreen = document.getElementById('load-screen');
      if (loadScreen) loadScreen.classList.add('hidden');
    }
    // Centered in-app modal, like every other message. Native alert only if
    // the dialog system itself failed to load.
    if (window.TuiDialog && window.TuiDialog.alert) {
      window.TuiDialog.alert('Startup failed', String(err), { size: 'small' });
    } else {
      window.alert(String(err));
    }
    console.error('Startup failed:', err);
  }
})();
