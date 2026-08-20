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

// TuiDialog DOM factories — overlay/dialog/header/brand-bar builders and overlay binding. Extracted from tui-dialog.js.

window.TuiDialog = Object.assign(window.TuiDialog, {
  _createOverlay(opts = {}) {
    const overlay = document.createElement('div');
    overlay.className = 'tui-overlay';
    if (opts.parent && opts.parent !== document.body) {
      overlay.classList.add('tui-overlay--absolute');
    }
    if (opts.id) overlay.id = opts.id;
    if (opts.transparent) overlay.classList.add('tui-overlay--transparent');
    if (opts.top) {
      overlay.classList.add('tui-overlay--top');
    }
    if (opts.zIndex) overlay.style.zIndex = opts.zIndex;
    (opts.parent || document.body).appendChild(overlay);
    return overlay;
  },

  _createBrandBar() {
    const bar = document.createElement('div');
    bar.className = 'tui-dialog-brand';
    const left = document.createElement('div');
    left.className = 'tui-dialog-brand-left';
    const logo = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    logo.setAttribute('class', 'tui-dialog-brand-logo');
    logo.setAttribute('viewBox', '0 0 512 512');
    logo.setAttribute('aria-hidden', 'true');
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', 'M256 96 L394.56 176 L394.56 336 L256 416 L117.44 336 L117.44 176 Z');
    path.setAttribute('fill', 'none');
    path.setAttribute('stroke', 'var(--accent)');
    path.setAttribute('stroke-width', '32');
    path.setAttribute('stroke-linejoin', 'round');
    logo.appendChild(path);
    const name = document.createElement('span');
    // Keep the custom (possibly renamed) app name here; the product identity
    // "Shells v<version>" is shown next to the socket.cat credit below.
    name.textContent = (window.ShellTheme && window.ShellTheme.appName) || 'Shells';
    left.appendChild(logo);
    left.appendChild(name);
    const right = document.createElement('div');
    right.className = 'tui-dialog-brand-right';
    const ver = document.createElement('span');
    ver.textContent = 'Shells v' + window.__APP_VERSION__;
    const link = document.createElement('a');
    link.href = 'https://socket.cat';
    link.target = '_blank';
    link.rel = 'noopener';
    link.textContent = 'socket.cat';
    right.appendChild(ver);
    right.appendChild(link);
    bar.appendChild(left);
    bar.appendChild(right);
    return bar;
  },

  _createDialog(size) {
    const el = document.createElement('div');
    el.className = 'tui-dialog tui-dialog--' + (size || 'medium');
    el.setAttribute('role', 'dialog');
    el.setAttribute('aria-modal', 'true');
    return el;
  },

  _createHeader(titleText, closeFn) {
    const header = document.createElement('div');
    header.className = 'tui-dialog-header';
    const title = document.createElement('h3');
    title.className = 'tui-dialog-title';
    title.textContent = titleText;
    const closeBtn = document.createElement('button');
    closeBtn.className = 'tui-dialog-close';
    closeBtn.type = 'button';
    closeBtn.setAttribute('aria-label', 'Close');
    closeBtn.textContent = 'esc';
    closeBtn.addEventListener('click', closeFn);
    header.appendChild(title);
    header.appendChild(closeBtn);
    return header;
  },

  _bindOverlay(overlay, closeFn) {
    const escHandler = (e) => {
      if (e.key === 'Escape') { e.preventDefault(); closeFn(); }
    };
    const clickHandler = (e) => { if (e.target === overlay) closeFn(); };
    document.addEventListener('keydown', escHandler);
    overlay.addEventListener('click', clickHandler);
    return () => {
      document.removeEventListener('keydown', escHandler);
      overlay.removeEventListener('click', clickHandler);
    };
  },

  _cleanup(overlay, unbind) {
    unbind();
    overlay.remove();
  },
});