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

// ── Mobile Switcher ──

window.ShellSwitcher = {
  visible: false,
  _touchState: null,
  _retryTimer: null,

  init() {
    const app = document.getElementById('app');
    if (!app) return;

    let twoFingerStartY = 0;

    app.addEventListener('touchstart', (e) => {
      if (e.touches.length !== 2) return;
      twoFingerStartY = (e.touches[0].clientY + e.touches[1].clientY) / 2;
      this._touchState = { startY: twoFingerStartY, tracking: true, fired: false };
    }, { passive: true });

    app.addEventListener('touchmove', (e) => {
      if (!this._touchState || !this._touchState.tracking || this._touchState.fired) return;
      if (e.touches.length !== 2) return;
      const avgY = (e.touches[0].clientY + e.touches[1].clientY) / 2;
      const dy = avgY - this._touchState.startY;
      if (dy < -80) {
        this._touchState.fired = true;
        if (this.visible) { this.hide(); } else { this.show(); }
      } else if (dy > 80) {
        this._touchState.fired = true;
        if (window.ShellKeyboard) window.ShellKeyboard.open();
      }
    }, { passive: true });

    app.addEventListener('touchend', (e) => {
      this._touchState = null;
    }, { passive: true });
  },

  show() {
    if (this.visible) return;
    if (window.ShellSessions.sessions.size === 0) return;
    this.visible = true;

    const overlay = document.createElement('div');
    overlay.id = 'shell-switcher';

    const cards = document.createElement('div');
    cards.className = 'switcher-cards';

    // Brand header: [logo + app name] top-left, [version + socket.cat] top-right.
    const brand = document.createElement('div');
    brand.className = 'switcher-brand';

    const brandLeft = document.createElement('div');
    brandLeft.className = 'switcher-brand-left';

    const logo = document.createElement('span');
    logo.className = 'switcher-logo';
    logo.innerHTML = '<svg viewBox="0 0 512 512" style="width:24px;height:24px"><path d="M256 96 L394.56 176 L394.56 336 L256 416 L117.44 336 L117.44 176 Z" fill="none" stroke="var(--accent)" stroke-width="32" stroke-linejoin="round"/></svg>';
    brandLeft.appendChild(logo);

    const appName = document.createElement('div');
    appName.className = 'switcher-app-name';
    appName.textContent = window.ShellTheme?.appName || 'Shells';
    brandLeft.appendChild(appName);
    brand.appendChild(brandLeft);

    const credits = document.createElement('div');
    credits.className = 'switcher-credits';
    const ver = document.createElement('span');
    // "Shells" is the fixed product identity (the app name above may be renamed).
    ver.textContent = 'Shells v' + window.__APP_VERSION__;
    credits.appendChild(ver);
    const link = document.createElement('a');
    link.href = 'https://socket.cat';
    link.target = '_blank';
    link.rel = 'noopener';
    link.textContent = 'socket.cat';
    credits.appendChild(link);
    brand.appendChild(credits);

    const sessionEntries = [...window.ShellSessions.sessions.entries()];

    sessionEntries.forEach(([id, session], i) => {
      const card = document.createElement('div');
      card.className = 'switcher-card' + (id === window.ShellSessions.activeId ? ' active-card' : '') + (session._busy ? ' switcher-card--busy' : '') + (session._bellLatched ? ' switcher-card--bell' : '');
      card.dataset.sid = id;
      card.style.animationDelay = `${i * 50}ms`;

      const header = document.createElement('div');
      header.className = 'switcher-card-header';

      const title = document.createElement('span');
      title.className = 'switcher-card-title';

      if (session.cwd) {
        if (session.backendBadge) {
          title.appendChild(window.ShellSessions._makeBadge(session.backendBadge.color, session.backendBadge.text, true));
        }
        const badge = window.ShellSessions._getBadgeInfo(session.cwd);
        title.appendChild(window.ShellSessions._makeBadge(badge.color, badge.text));
      }

      const titleText = document.createElement('span');
      const tileTitle = session.tile.querySelector('.tile-title');
      titleText.textContent = tileTitle ? tileTitle.textContent : `shell #${id}`;
      title.appendChild(titleText);

      const closeBtn = document.createElement('button');
      closeBtn.className = 'switcher-card-close';
      closeBtn.innerHTML = window.Icons.close;
      closeBtn.title = 'Close shell';
      closeBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        this.hide();
        setTimeout(() => {
          const shellId = String(id);
          const titleText = tileTitle ? tileTitle.textContent : `shell #${shellId}`;
          
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
            size: 'small',
            onConfirm: () => { window.ShellSessions.destroy(shellId); },
          });
        }, 220);
      });

      const bell = document.createElement('span');
      bell.className = 'switcher-card-bell';
      bell.innerHTML = window.Icons.bell;
      header.appendChild(bell);
      header.appendChild(title);
      header.appendChild(closeBtn);

      const preview = document.createElement('div');
      preview.className = 'switcher-card-preview';
      preview.dataset.sessionId = id;

      const skeleton = document.createElement('div');
      skeleton.className = 'switcher-skeleton';
      for (let r = 0; r < 6; r++) {
        const row = document.createElement('div');
        row.className = 'switcher-skeleton-row';
        row.style.width = (40 + Math.random() * 50) + '%';
        skeleton.appendChild(row);
      }
      preview.appendChild(skeleton);

      this._refreshPreview(preview, session);

      card.appendChild(header);
      card.appendChild(preview);

      card.addEventListener('click', () => {
        window.ShellSessions.setActive(id);
        this.hide();
        if (window.ShellSessions._isMobile()) {
          const tile = window.ShellSessions.sessions.get(id)?.tile;
          // The active tile is usually already fullscreen via
          // _ensureFullscreenMobile; only force it when it is not (single
          // terminal), and re-check inside the timeout to never fight it.
          if (tile && !tile.classList.contains('fullscreen')) {
            setTimeout(() => {
              if (tile && !tile.classList.contains('fullscreen')) {
                window.ShellSessions.toggleFullscreen(id);
              }
            }, 220);
          }
        }
      });

      cards.appendChild(card);
    });

    overlay.appendChild(brand);
    overlay.appendChild(cards);

    const footer = document.createElement('div');
    footer.className = 'switcher-footer';
    const updateBtn = document.createElement('button');
    updateBtn.type = 'button';
    updateBtn.className = 'switcher-update-check';
    updateBtn.textContent = 'Check for updates';
    updateBtn.addEventListener('click', () => {
      if (window.ShellSessions && window.ShellSessions._checkForUpdates) {
        window.ShellSessions._checkForUpdates({ manual: true });
      }
    });
    footer.appendChild(updateBtn);
    const credit = document.createElement('span');
    credit.textContent = 'By Carles Ortega Ragull';
    footer.appendChild(credit);
    overlay.appendChild(footer);

    overlay.addEventListener('click', (e) => {
      if (e.target === overlay || e.target === cards) this.hide();
    });

    document.body.appendChild(overlay);

    requestAnimationFrame(() => {
      overlay.classList.add('visible');
      const activeCard = cards.querySelector('.active-card');
      if (activeCard) activeCard.scrollIntoView({ behavior: 'smooth', inline: 'nearest', block: 'center' });
    });

    this._retryTimer = setTimeout(() => this._refreshAllPreviews(), 600);
  },

  hide() {
    clearTimeout(this._retryTimer);
    const overlay = document.getElementById('shell-switcher');
    if (!overlay) return;
    overlay.classList.remove('visible');
    setTimeout(() => {
      overlay.remove();
    }, 200);
    this.visible = false;
  },

  _capturePreview(term) {
    try {
      if (!term?.buffer?.active) return null;
      const buffer = term.buffer.active;
      const lineCount = 32;
      const start = buffer.viewportY;
      const end = Math.min(buffer.length, start + lineCount);

      const cellData = { getCell: undefined };
      const lines = [];
      let foundContent = false;

      // Helper to convert xterm.js color bits to CSS
      const getColorCSS = (color, isFg) => {
        if (color === -1) return null; // Default
        
        // Check for 16-color/256-color palette
        // 16777216 is the bitmask for "Color is an index" in xterm.js
        if (color < 256) {
          const palette = [
            '#000000', '#cd0000', '#00cd00', '#cdcd00', '#0000ee', '#cd00cd', '#00cdcd', '#e5e5e5',
            '#7f7f7f', '#ff0000', '#00ff00', '#ffff00', '#5c5cff', '#ff00ff', '#00ffff', '#ffffff'
          ];
          if (color < 16) return palette[color];
          
          // 256-color cube / grayscale
          if (color < 232) {
            const r = Math.floor((color - 16) / 36);
            const g = Math.floor(((color - 16) % 36) / 6);
            const b = (color - 16) % 6;
            const toHex = (v) => (v === 0 ? 0 : v * 40 + 55).toString(16).padStart(2, '0');
            return `#${toHex(r)}${toHex(g)}${toHex(b)}`;
          } else {
            const gray = (color - 232) * 10 + 8;
            const hex = gray.toString(16).padStart(2, '0');
            return `#${hex}${hex}${hex}`;
          }
        }
        
        // RGB Color (extracted from 24-bit integer)
        const r = (color >> 16) & 0xFF;
        const g = (color >> 8) & 0xFF;
        const b = color & 0xFF;
        return `rgb(${r},${g},${b})`;
      };

      for (let i = start; i < end; i++) {
        const line = buffer.getLine(i);
        if (!line) continue;
        
        const lineSegments = [];
        let currentText = '';
        let lastFg = -1;
        let lastBg = -1;
        let lastBold = false;

        for (let col = 0; col < line.length; col++) {
          const cell = line.getCell(col, cellData.getCell);
          if (!cell) {
            currentText += ' ';
            continue;
          }

          const fg = cell.getFgColor();
          const bg = cell.getBgColor();
          const bold = !!cell.isBold();

          if (fg !== lastFg || bg !== lastBg || bold !== lastBold) {
            if (currentText) {
              lineSegments.push({
                text: currentText,
                fg: getColorCSS(lastFg, true),
                bg: getColorCSS(lastBg, false),
                bold: lastBold
              });
            }
            currentText = '';
            lastFg = fg;
            lastBg = bg;
            lastBold = bold;
          }
          currentText += cell.getChars() || ' ';
        }

        if (currentText) {
          lineSegments.push({
            text: currentText,
            fg: getColorCSS(lastFg, true),
            bg: getColorCSS(lastBg, false),
            bold: lastBold
          });
        }

        if (lineSegments.some(s => s.text.trim().length)) foundContent = true;
        lines.push(lineSegments);
      }

      while (lines.length > 1 && lines[0].every(s => s.text.trim() === '')) lines.shift();
      return foundContent ? { lines } : null;
    } catch (e) {
      console.error('[Switcher] Capture error:', e);
      return null;
    }
  },

  _refreshPreview(preview, session) {
    try {
      const term = session.term;
      if (!term || !term.element) return false;
      const captured = this._capturePreview(term);
      if (!captured) return false;
      const skeleton = preview.querySelector('.switcher-skeleton');
      if (skeleton) {
        skeleton.style.opacity = '0';
        setTimeout(() => skeleton.remove(), 200);
      }
      let pre = preview.querySelector('.switcher-preview-text');
      if (!pre) {
        pre = document.createElement('pre');
        pre.className = 'switcher-preview-text';
        preview.appendChild(pre);
      }

      // Clear and rebuild colored HTML
      pre.innerHTML = '';
      captured.lines.forEach((lineSegments, i) => {
        lineSegments.forEach((seg) => {
          const span = document.createElement('span');
          span.textContent = seg.text;
          if (seg.fg) span.style.color = seg.fg;
          if (seg.bg) span.style.backgroundColor = seg.bg;
          if (seg.bold) span.style.fontWeight = 'bold';
          pre.appendChild(span);
        });
        if (i < captured.lines.length - 1) {
          pre.appendChild(document.createTextNode('\n'));
        }
      });

      return true;
    } catch (e) {
      console.error('[Switcher] Refresh error:', e);
      return false;
    }
  },

  _refreshAllPreviews() {
    const overlay = document.getElementById('shell-switcher');
    if (!overlay) return;
    let anyEmpty = false;
    overlay.querySelectorAll('.switcher-card-preview').forEach((preview) => {
      const rawId = preview.dataset.sessionId;
      const session = window.ShellSessions.sessions.get(Number(rawId)) || window.ShellSessions.sessions.get(rawId);
      if (!session) return;
      const hasContent = preview.querySelector('.switcher-preview-text');
      if (hasContent) return;
      if (!this._refreshPreview(preview, session)) {
        anyEmpty = true;
      }
    });
    if (anyEmpty) {
      this._retryTimer = setTimeout(() => this._refreshAllPreviews(), 500);
    }
  },
};
