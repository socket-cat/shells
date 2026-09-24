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

// ── Load screen ──
// Extracted from shell-sessions.js. Boot splash, load status
// text/progress and the all-sessions-ready check that dismisses it.

window.ShellSessions = Object.assign(window.ShellSessions, {
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
          ${this._versionSig('load-sig')}
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
    if (this.isMobile() && window.ShellLayout?.switcher && this.sessions.size > 1) {
      setTimeout(() => window.ShellLayout.switcher.show(), 200);
    }
  },
});
