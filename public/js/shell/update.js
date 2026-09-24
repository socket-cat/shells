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

// ── Self-update check ──
// Extracted from shell-sessions.js. Owns the update opt-in,
// scheduled + manual release checks, verification-failure alarm, update
// modal and verified self-apply. Timers are module-private here.

window.ShellSessions = Object.assign(window.ShellSessions, {
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
        // Flag the new version so the post-reload toast says "Updated to vX".
        try { sessionStorage.setItem('shells-updated-to', info.latest); } catch (_) {}
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

});
