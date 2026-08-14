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
window.addEventListener('keydown', (e) => {
  if (e.altKey && e.code === 'KeyQ') {
    e.preventDefault();
    if (window.ShellSessions.activeId) window.ShellSessions.destroy(window.ShellSessions.activeId);
  }
  if (e.altKey && e.code === 'KeyN') {
    e.preventDefault();
    window.ShellSessions.promptCreate();
  }
  if (e.altKey && e.code === 'ArrowRight') {
    e.preventDefault();
    window.ShellSessions.next();
  }
  if (e.altKey && e.code === 'ArrowLeft') {
    e.preventDefault();
    window.ShellSessions.previous();
  }
  if (e.ctrlKey && e.code === 'Tab') {
    e.preventDefault();
    if (e.shiftKey) window.ShellSessions.previous();
    else window.ShellSessions.next();
  }
  if (e.ctrlKey && e.code === 'KeyF' && !e.altKey) {
    // In-terminal search when the terminal itself is focused (the xterm
    // textarea). Other inputs (search bar, cmd bar, dialogs) keep the
    // browser's native find; AltGr combos pass through. With terminal focus
    // this intentionally overrides vim/less/htop's Ctrl+F (page-down) — Esc
    // closes the bar and returns focus.
    const ss = window.ShellSessions;
    const session = ss && ss.activeId ? ss.sessions.get(ss.activeId) : null;
    if (session && session.searchAddon) {
      const ae = document.activeElement;
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
  if (layoutBtn) { window.ShellSessions.cycleLayout(layoutBtn); return; }
  const promoteBtn = e.target.closest('[data-action="promote-master"]');
  if (promoteBtn) { window.ShellSessions.promoteToMaster(promoteBtn.dataset.shellId); return; }
  const kbBtn = e.target.closest('[data-action="open-keyboard"]');
  if (kbBtn) { window.ShellKeyboard.open(kbBtn); return; }
  const searchBtn = e.target.closest('[data-action="open-search"]');
  if (searchBtn) { window.ShellSessions.openSearch(); return; }
  const themeBtn = e.target.closest('[data-action="toggle-theme"]');
  if (themeBtn) {
    window.ShellTheme.toggle(themeBtn);
    return;
  }
  const fontMinusBtn = e.target.closest('[data-action="font-minus"]');
  if (fontMinusBtn) { window.ShellSessions.setFontSize(-1); return; }
  const fontPlusBtn = e.target.closest('[data-action="font-plus"]');
  if (fontPlusBtn) { window.ShellSessions.setFontSize(1); return; }
  const btn = e.target.closest('[data-action="toggle-fullscreen"]');
  if (btn) { window.ShellSessions.toggleFullscreen(btn.dataset.shellId); return; }
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
    
    const message = document.createElement('div');
    message.style.lineHeight = '1.4';
    message.appendChild(document.createTextNode('Permanently destroy:'));
    message.appendChild(document.createElement('br'));
    const strong = document.createElement('strong');
    strong.style.color = 'var(--text)';
    strong.textContent = titleText;
    message.appendChild(strong);
    message.appendChild(document.createTextNode('?'));

    TuiDialog.confirm('Destroy Shell', message, {
      dangerous: true,
      confirmText: 'Yes, destroy',
      parent: tile,
      size: 'small',
      onConfirm: () => { window.ShellSessions.destroy(shellId); },
    });
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
