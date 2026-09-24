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

// ── Backend creation flows (local + SSH) ──
// Extracted from shell-sessions.js. Local shell creation
// (create/promptCreate) and the full SSH backend chain: connection
// storage + CRUD, user@host input parsing, probe/key-install flows and
// remote ls autocomplete. _sshConnections state is module-owned here.
// Fingerprint dialog helpers stay core (used by WS host-key verify).

window.ShellSessions = Object.assign(window.ShellSessions, {
  _sshConnections: [],

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

  _splitPath(val, home) {
    const parts = val.split('/');
    const filter = parts.pop().toLowerCase();
    const sub = parts.join('/');
    if (val.startsWith('/')) {
      const base = sub || '/';
      return { base, filter, prefix: base === '/' ? '/' : base + '/' };
    }
    return {
      base: sub ? `${home}/${sub}` : home,
      filter,
      prefix: sub ? sub + '/' : '',
    };
  },

  async _sshLsAutocomplete(val, backend, lsCache, recent, backendBadge) {
    if (!backend || !backend.connectionId) return [];
    const { connectionId } = backend;
    if (!val.startsWith('/')) return [];

    const { base, filter, prefix } = this._splitPath(val);

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

    folders
      .filter(f => !filter || f.toLowerCase().startsWith(filter))
      .forEach(f => {
        const fullPath = prefix + f + '/';
        suggestions.push({ text: fullPath, canDelete: false, badge: [backendBadge, this._getBadgeInfo(fullPath)] });
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

  async create(cols = 80, rows = 24, command, cwd, backend) {
    const body = { cols, rows };
    if (command) body.command = command;
    if (cwd) body.cwd = cwd;
    if (backend) body.backend = backend;
    const { ok, data, error } = await this.encryptedFetch('/api/sessions', body);
    if (!ok) {
      const err = new Error(error || 'Failed to create shell session');
      err.code = (data && data.code) || 'create_failed';
      throw err;
    }
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
      
      const { base, filter, prefix } = this._splitPath(val, home);
      
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

    try {
      return await this.create(80, 24, finalCmd, final, backend);
    } catch (err) {
      // Fail loud: never let a bad folder or missing binary silently open a
      // session somewhere else. Prune the offender from recents — it is
      // proven unusable.
      const detail = (err && err.message) || '';
      let title = 'Could not start session';
      let message = detail;
      if (err && err.code === 'cwd_unusable') {
        title = 'Folder not accessible';
        message = `"${final}" is not a valid folder.` + (detail ? `\n\n${detail}` : '');
        try {
          if (isSSH) this._removeSshRecentPath(backend, final);
          else await this._removeRecentPath(final);
        } catch (_) {}
      } else if (err && err.code === 'command_not_found') {
        title = 'Command not found';
        message = `"${finalCmd}" is not installed on this machine.` + (detail ? `\n\n${detail}` : '');
        if (finalCmd) {
          try {
            if (isSSH) this._removeSshRecentCommand(backend, finalCmd);
            else await this._removeRecentCommand(finalCmd);
          } catch (_) {}
        }
      }
      try {
        window.TuiDialog.alert(title, message);
      } catch (_) {}
      return null;
    }
  },
});
