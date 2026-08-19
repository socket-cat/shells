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

// ── Recents: recent paths, commands and backends (local + SSH) ──
// Extracted from shell-sessions.js. Owns the localStorage/API
// CRUD for recently-used project folders, commands and SSH backend labels.
// SSH connection storage (_sshConnections CRUD) intentionally NOT here —
// it lives with the backend creation flows (shell/backends.js).

window.ShellSessions = Object.assign(window.ShellSessions, {
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
});
