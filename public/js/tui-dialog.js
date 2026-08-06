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

// ── TUI Dialog System (OpenTUI-compatible) ──

// Dialog-level key shortcuts (Enter/Space/arrows) must not fire while the
// user is typing in a text field inside the dialog.
function isEditableTarget(t) {
  return !!t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.isContentEditable);
}

window.TuiDialog = {
  _toastTimer: null,

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
    ver.textContent = 'Shells v' + (document.body.dataset.version || '');
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

  // ── Alert ──
  alert(title, message, opts = {}) {
    return new Promise((resolve) => {
      const overlay = this._createOverlay({ parent: opts.parent });
      const dialog = this._createDialog(opts.size || 'medium');
      const header = this._createHeader(title, done);
      const body = document.createElement('div');
      body.className = 'tui-dialog-body';
      const msg = document.createElement('div');
      msg.className = 'tui-dialog-desc';
      if (typeof message === 'string') msg.textContent = message;
      else msg.appendChild(message);
      body.appendChild(msg);

      const footer = document.createElement('div');
      footer.className = 'tui-dialog-footer';
      const ok = document.createElement('button');
      ok.type = 'button';
      ok.className = 'tui-dialog-choice';
      ok.dataset.active = 'true';
      ok.textContent = 'OK';
      ok.addEventListener('click', done);
      footer.appendChild(ok);

      const hints = document.createElement('div');
      hints.className = 'tui-dialog-hints';
      hints.innerHTML = '<div class="tui-dialog-hint">enter <span>done</span></div>';
      body.appendChild(hints);

      dialog.appendChild(this._createBrandBar());
      dialog.appendChild(header);
      dialog.appendChild(body);
      dialog.appendChild(footer);
      overlay.appendChild(dialog);

      const keyHandler = (e) => {
        if (isEditableTarget(e.target)) return;
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); done(); }
      };
      document.addEventListener('keydown', keyHandler);

      const unbind = this._bindOverlay(overlay, done);
      function done() {
        document.removeEventListener('keydown', keyHandler);
        TuiDialog._cleanup(overlay, unbind);
        resolve(true);
      }
      requestAnimationFrame(() => ok.focus());
    });
  },

  // ── Confirm ──
  confirm(title, message, opts = {}) {
    return new Promise((resolve) => {
      const overlay = this._createOverlay({ parent: opts.parent });
      const dialog = this._createDialog(opts.size || 'medium');
      const header = this._createHeader(title, cancel);
      const body = document.createElement('div');
      body.className = 'tui-dialog-body';
      const msg = document.createElement('div');
      msg.className = 'tui-dialog-desc';
      if (typeof message === 'string') msg.textContent = message;
      else msg.appendChild(message);
      body.appendChild(msg);

      const footer = document.createElement('div');
      footer.className = 'tui-dialog-footer';

      let activeChoice = 'confirm';
      const cancelBtn = document.createElement('button');
      cancelBtn.type = 'button';
      cancelBtn.className = 'tui-dialog-choice';
      cancelBtn.textContent = opts.cancelText || 'Cancel';
      cancelBtn.addEventListener('click', cancel);

      const confirmBtn = document.createElement('button');
      confirmBtn.type = 'button';
      confirmBtn.className = 'tui-dialog-choice';
      if (opts.dangerous) confirmBtn.classList.add('tui-dialog-choice--dangerous');
      confirmBtn.textContent = opts.confirmText || (opts.dangerous ? 'Yes, delete' : 'Confirm');
      confirmBtn.addEventListener('click', confirm);

      const updateChoices = () => {
        cancelBtn.dataset.active = activeChoice === 'cancel' ? 'true' : 'false';
        confirmBtn.dataset.active = activeChoice === 'confirm' ? 'true' : 'false';
        if (activeChoice === 'cancel') cancelBtn.focus();
        else confirmBtn.focus();
      };

      footer.appendChild(cancelBtn);
      footer.appendChild(confirmBtn);

      const hints = document.createElement('div');
      hints.className = 'tui-dialog-hints';
      hints.innerHTML = `
        <div class="tui-dialog-hint">&leftarrow;&rightarrow; <span>move</span></div>
        <div class="tui-dialog-hint">enter <span>submit</span></div>
      `;
      body.appendChild(hints);

      dialog.appendChild(this._createBrandBar());
      dialog.appendChild(header);
      dialog.appendChild(body);
      dialog.appendChild(footer);
      overlay.appendChild(dialog);

      const keyHandler = (e) => {
        if (isEditableTarget(e.target)) return;
        if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') {
          e.preventDefault();
          activeChoice = activeChoice === 'confirm' ? 'cancel' : 'confirm';
          updateChoices();
        }
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          if (activeChoice === 'confirm') confirm();
          else cancel();
        }
      };
      document.addEventListener('keydown', keyHandler);

      const unbind = this._bindOverlay(overlay, cancel);
      function confirm() { cleanup(); if (opts.onConfirm) opts.onConfirm(); resolve(true); }
      function cancel() { cleanup(); if (opts.onCancel) opts.onCancel(); resolve(false); }
      function cleanup() {
        document.removeEventListener('keydown', keyHandler);
        TuiDialog._cleanup(overlay, unbind);
      }
      requestAnimationFrame(updateChoices);
    });
  },

  // ── Prompt ──
  prompt(title, opts = {}) {
    return new Promise((resolve) => {
      const overlay = this._createOverlay({ parent: opts.parent });
      const dialog = this._createDialog(opts.size || 'large');
      const header = this._createHeader(title, cancel);
      const body = document.createElement('div');
      body.className = 'tui-dialog-body';
      if (opts.description) {
        const desc = document.createElement('div');
        desc.className = 'tui-dialog-desc';
        desc.textContent = opts.description;
        body.appendChild(desc);
      }
      const form = document.createElement('form');
      form.autocomplete = 'off';
      form.addEventListener('submit', (e) => { e.preventDefault(); confirm(); });

      if (opts.inputType === 'password') {
        const username = document.createElement('input');
        username.type = 'text';
        username.name = 'username';
        username.autocomplete = 'username';
        username.setAttribute('aria-hidden', 'true');
        username.tabIndex = -1;
        username.style.cssText = 'position:absolute;width:0;height:0;padding:0;margin:0;border:0;opacity:0;pointer-events:none';
        form.appendChild(username);
      }

      const input = document.createElement('input');
      input.type = opts.inputType || 'text';
      input.className = 'tui-dialog-input';
      input.placeholder = opts.placeholder || '';
      input.value = opts.value || '';
      if (opts.inputType === 'password') {
        input.autocomplete = 'current-password';
      }
      if (opts.busy) {
        input.disabled = true;
        input.classList.add('opacity-60');
      }

      const suggestions = document.createElement('div');
      suggestions.className = 'tui-dialog-suggestions';
      form.appendChild(input);
      body.appendChild(form);
      body.appendChild(suggestions);

      let activeSuggestionIdx = -1;
      let currentSuggestions = [];

      const updateSuggestions = async () => {
        if (!opts.autocomplete) return;
        const val = input.value;
        const hadResults = currentSuggestions.length > 0;
        if (hadResults) {
          currentSuggestions = [{ text: 'Loading...', canDelete: false, loading: true }];
          activeSuggestionIdx = -1;
          renderSuggestions();
        }
        const res = await opts.autocomplete(val);
        currentSuggestions = (res || []).filter(s => {
          const item = typeof s === 'string' ? {} : s;
          return !item.loading;
        });
        activeSuggestionIdx = -1;
        renderSuggestions();
      };

      const renderSuggestions = () => {
        suggestions.innerHTML = '';
        if (currentSuggestions.length === 0) {
          suggestions.classList.remove('visible');
          return;
        }
        suggestions.classList.add('visible');
        currentSuggestions.forEach((s, i) => {
          const item = document.createElement('div');
          item.className = 'tui-dialog-suggestion-item';
          if (i === activeSuggestionIdx) item.classList.add('active');
          
          const val = typeof s === 'string' ? s : s.text;
          const canDelete = typeof s === 'string' ? true : s.canDelete;
          const badge = typeof s === 'string' ? null : s.badge;
          const desc = typeof s === 'string' ? null : s.description;

          if (badge) {
            const badges = Array.isArray(badge) ? badge : [badge];
            for (const bi of badges) {
              const b = document.createElement('span');
              b.className = 'project-badge';
              b.style.backgroundColor = bi.color;
              b.textContent = bi.text;
              b.style.marginRight = '2px';
              item.appendChild(b);
            }
          }

          const text = document.createElement('span');
          text.className = 'tui-dialog-suggestion-text';
          text.textContent = val;
          item.appendChild(text);

          if (desc) {
            const descEl = document.createElement('span');
            descEl.className = 'tui-dialog-suggestion-desc';
            descEl.textContent = desc;
            item.appendChild(descEl);
          }

          if (opts.onDelete) {
            const del = document.createElement('span');
            del.className = 'tui-dialog-suggestion-delete';
            if (!canDelete) del.classList.add('tui-dialog-suggestion-delete--hidden');
            del.innerHTML = '&times;';
            del.title = 'Remove from history';
            if (canDelete) {
              del.addEventListener('click', async (e) => {
                e.stopPropagation();
                await opts.onDelete(val);
                updateSuggestions();
              });
            }
            item.appendChild(del);
          }

          if (typeof s === 'object' && s.loading) {
            item.classList.add('tui-dialog-suggestion-loading');
            suggestions.appendChild(item);
            return;
          }

          item.addEventListener('click', () => {
            input.value = val;
            confirm();
          });
          suggestions.appendChild(item);
        });
      };

      let debounceTimer = null;
      input.addEventListener('input', () => {
        activeSuggestionIdx = -1;
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => updateSuggestions(), 50);
      });

      input.addEventListener('focus', () => {
        activeSuggestionIdx = -1;
        updateSuggestions();
      });

      input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          if (activeSuggestionIdx >= 0 && currentSuggestions[activeSuggestionIdx]) {
            e.preventDefault();
            const s = currentSuggestions[activeSuggestionIdx];
            const val = typeof s === 'string' ? s : s.text;
            input.value = val;
            confirm();
          } else if (currentSuggestions.length > 0 && !input.value.trim()) {
            e.preventDefault();
            const s = currentSuggestions[0];
            const val = typeof s === 'string' ? s : s.text;
            input.value = val;
            confirm();
          } else {
            e.preventDefault();
            confirm();
          }
        } else if (e.key === 'ArrowDown') {
          e.preventDefault();
          if (currentSuggestions.length > 0) {
            activeSuggestionIdx = Math.min(activeSuggestionIdx + 1, currentSuggestions.length - 1);
            renderSuggestions();
            const active = suggestions.children[activeSuggestionIdx];
            if (active) active.scrollIntoView({ block: 'nearest' });
          }
        } else if (e.key === 'ArrowUp') {
          e.preventDefault();
          if (currentSuggestions.length > 0) {
            activeSuggestionIdx = Math.max(activeSuggestionIdx - 1, -1);
            renderSuggestions();
            if (activeSuggestionIdx >= 0) {
              const active = suggestions.children[activeSuggestionIdx];
              if (active) active.scrollIntoView({ block: 'nearest' });
            }
          }
        } else if (e.key === 'Tab') {
          if (currentSuggestions.length > 0) {
            e.preventDefault();
            const s = currentSuggestions[activeSuggestionIdx >= 0 ? activeSuggestionIdx : 0];
            const val = typeof s === 'string' ? s : s.text;
            input.value = val;
            if (val.endsWith('/')) {
              activeSuggestionIdx = -1;
              updateSuggestions();
            } else {
              currentSuggestions = [];
              renderSuggestions();
            }
          }
        } else if (e.key === 'Escape') {
          if (currentSuggestions.length > 0) {
            e.preventDefault();
            currentSuggestions = [];
            renderSuggestions();
          }
        }
      });

      const hints = document.createElement('div');
      hints.className = 'tui-dialog-hints';
      if (opts.busy) {
        const hint = document.createElement('div');
        hint.className = 'tui-dialog-hint';
        const span = document.createElement('span');
        span.textContent = opts.busyText || 'Processing...';
        hint.appendChild(span);
        hints.appendChild(hint);
      } else {
        hints.innerHTML = `
          <div class="tui-dialog-hint">&uparrow;&downarrow; <span>move</span></div>
          <div class="tui-dialog-hint">tab <span>autocomplete</span></div>
          <div class="tui-dialog-hint">enter <span>submit</span></div>
        `;
      }
      body.appendChild(hints);

      if (opts.footerExtra) {
        const extra = document.createElement('div');
        extra.className = 'tui-dialog-footer-extra';
        if (typeof opts.footerExtra === 'string') extra.textContent = opts.footerExtra;
        else extra.appendChild(opts.footerExtra);
        body.appendChild(extra);
      }

      dialog.appendChild(this._createBrandBar());
      dialog.appendChild(header);
      dialog.appendChild(body);
      const footer = document.createElement('div');
      footer.className = 'tui-dialog-footer';
      const cancelBtn = document.createElement('button');
      cancelBtn.type = 'button';
      cancelBtn.className = 'tui-dialog-choice';
      cancelBtn.textContent = 'Cancel';
      cancelBtn.addEventListener('click', cancel);
      const okBtn = document.createElement('button');
      okBtn.type = 'button';
      okBtn.className = 'tui-dialog-choice';
      okBtn.dataset.active = 'true';
      okBtn.textContent = 'OK';
      okBtn.addEventListener('click', confirm);
      footer.appendChild(cancelBtn);
      footer.appendChild(okBtn);
      dialog.appendChild(footer);
      overlay.appendChild(dialog);
      const unbind = this._bindOverlay(overlay, cancel);
      function confirm() { clearTimeout(debounceTimer); TuiDialog._cleanup(overlay, unbind); resolve(input.value); }
      function cancel() { clearTimeout(debounceTimer); TuiDialog._cleanup(overlay, unbind); resolve(null); }
      requestAnimationFrame(() => { 
        input.focus(); 
        input.select();
        updateSuggestions();
      });
    });
  },

  // ── Select ──
  select(title, options, config = {}) {
    return new Promise((resolve) => {
      const overlay = this._createOverlay({ 
        id: config.overlayId, 
        transparent: config.transparent,
        parent: config.parent 
      });
      const dialog = this._createDialog(config.size || 'medium');
      dialog.setAttribute('aria-labelledby', 'tui-select-title');
      const header = this._createHeader(title, close);
      header.querySelector('.tui-dialog-title').id = 'tui-select-title';
      const body = document.createElement('div');
      body.className = 'tui-dialog-body';

      let filtered = config.filterOnly ? options.filter(o => o.alwaysShow) : [...options];
      let activeIdx = Math.max(0, filtered.findIndex(o => o.value === config.current));
      const cards = [];

      const searchInput = document.createElement('input');
      searchInput.type = 'text';
      searchInput.className = 'tui-dialog-input';
      searchInput.placeholder = config.placeholder || 'Search...';

      const grid = document.createElement('div');
      grid.className = 'tui-dialog-grid';
      grid.setAttribute('role', 'listbox');

      const renderCards = () => {
        grid.innerHTML = '';
        cards.length = 0;
        let lastCategory = null;

        filtered.forEach((opt, idx) => {
          if (opt.category && opt.category !== lastCategory) {
            const catEl = document.createElement('div');
            catEl.className = 'tui-dialog-card-category';
            catEl.textContent = opt.category;
            grid.appendChild(catEl);
            lastCategory = opt.category;
          }

          const card = document.createElement('button');
          card.type = 'button';
          card.className = 'tui-dialog-card';
          card.setAttribute('role', 'option');
          card.setAttribute('aria-selected', opt.value === config.current ? 'true' : 'false');
          card.tabIndex = idx === activeIdx ? 0 : -1;

          const wrapper = document.createElement('div');
          wrapper.className = 'flex gap-2 items-start flex-grow';

          const bullet = document.createElement('span');
          bullet.className = 'w-4 flex-shrink-0';
          bullet.textContent = opt.value === config.current ? '●' : '';

          const info = document.createElement('div');
          info.className = 'tui-dialog-card-info flex-grow';
          info.style.overflow = 'hidden';
          info.style.minWidth = '0';
          const name = document.createElement('div');
          name.className = 'tui-dialog-card-name';
          name.textContent = opt.title;
          info.appendChild(name);
          if (opt.description) {
            const desc = document.createElement('div');
            desc.className = 'tui-dialog-card-desc';
            desc.textContent = opt.description;
            info.appendChild(desc);
          }

          wrapper.appendChild(bullet);
          if (opt.gutter) {
            const gutter = document.createElement('div');
            gutter.className = 'flex-shrink-0 w-4';
            if (typeof opt.gutter === 'string') gutter.textContent = opt.gutter;
            else gutter.appendChild(opt.gutter);
            wrapper.appendChild(gutter);
          }
          wrapper.appendChild(info);
          card.appendChild(wrapper);

          if (opt.footer) {
            const footer = document.createElement('div');
            footer.className = 'tui-dialog-card-footer flex-shrink-0';
            if (typeof opt.footer === 'string') footer.textContent = opt.footer;
            else footer.appendChild(opt.footer);
            card.appendChild(footer);
          }

          if (opt.disabled) { card.disabled = true; card.classList.add('opacity-50'); }

          card.addEventListener('click', () => {
            if (opt.onSelect) opt.onSelect();
            if (config.applyImmediately) {
              config.current = opt.value;
              activeIdx = idx;
              if (config.onApply) config.onApply(opt.value);
              renderCards();
              if (cards[activeIdx]) cards[activeIdx].focus();
            } else {
              selectValue(opt.value);
            }
          });

          grid.appendChild(card);
          cards.push(card);
          if (idx === activeIdx) card.dataset.active = 'true';
        });
      };

      const setActive = (idx) => {
        if (cards.length === 0) return;
        activeIdx = ((idx % cards.length) + cards.length) % cards.length;
        cards.forEach((c, i) => {
          c.tabIndex = i === activeIdx ? 0 : -1;
          c.dataset.active = i === activeIdx ? 'true' : 'false';
        });
        if (cards[activeIdx]) cards[activeIdx].focus();
        if (config.onMove && filtered[activeIdx]) config.onMove(filtered[activeIdx]);
      };

      if (config.skipFilter) searchInput.style.display = 'none';
      else {
        searchInput.addEventListener('input', async () => {
          let q = searchInput.value;
          if (config.onInput) {
            const res = await config.onInput(q);
            if (res && res.options) {
              options = res.options;
              if (res.title) header.querySelector('.tui-dialog-title').textContent = res.title;
              if (res.query !== undefined) q = res.query;
            }
          }
          
          const qLower = q.toLowerCase();
          filtered = options.filter(o => {
            const match = o.title.toLowerCase().includes(qLower) ||
                          (o.description && o.description.toLowerCase().includes(qLower));
            if (config.filterOnly && !qLower) return o.alwaysShow;
            return match;
          });
          activeIdx = 0;
          renderCards();
        });

        searchInput.addEventListener('keydown', (e) => {
          if (e.key === 'Tab') {
            e.preventDefault();
            if (cards[activeIdx]) cards[activeIdx].click();
          }
          if (e.key === 'Enter') {
            e.preventDefault();
            if (cards[activeIdx]) cards[activeIdx].click();
          }
        });
      }

      renderCards();

      const hints = document.createElement('div');
      hints.className = 'tui-dialog-hints';
      hints.innerHTML = `
        <div class="tui-dialog-hint">&uparrow;&downarrow; <span>move</span></div>
        <div class="tui-dialog-hint">enter <span>select</span></div>
      `;
      body.appendChild(hints);

      const keyHandler = (e) => {
        if (isEditableTarget(e.target)) return;
        if (e.key === 'Escape') { e.preventDefault(); close(); return; }
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          if (cards[activeIdx]) cards[activeIdx].click();
          return;
        }
        const cols = config.singleColumnNavigation ? 1 : (window.innerWidth <= 480 ? 1 : 2);
        if (e.key === 'ArrowRight') { e.preventDefault(); setActive(activeIdx + 1); }
        if (e.key === 'ArrowLeft') { e.preventDefault(); setActive(activeIdx - 1); }
        if (e.key === 'ArrowDown') { e.preventDefault(); setActive(activeIdx + cols); }
        if (e.key === 'ArrowUp') { e.preventDefault(); setActive(activeIdx - cols); }
      };
      document.addEventListener('keydown', keyHandler);

      body.appendChild(searchInput);
      body.appendChild(grid);
      dialog.appendChild(this._createBrandBar());
      dialog.appendChild(header);
      dialog.appendChild(body);
      overlay.appendChild(dialog);

      const unbind = this._bindOverlay(overlay, close);
      function selectValue(val) { document.removeEventListener('keydown', keyHandler); TuiDialog._cleanup(overlay, unbind); resolve(val); }
      function close() { document.removeEventListener('keydown', keyHandler); TuiDialog._cleanup(overlay, unbind); resolve(null); }

      requestAnimationFrame(() => {
        if (!config.skipFilter) searchInput.focus();
        else if (cards[activeIdx]) cards[activeIdx].focus();
      });
    });
  },

  // ── Status ──
  status(title, message, opts = {}) {
    if (this._activeStatus) this._activeStatus();

    const overlay = this._createOverlay({ parent: opts.parent });
    const dialog = this._createDialog('small');
    dialog.appendChild(this._createBrandBar());

    const header = document.createElement('div');
    header.className = 'tui-dialog-header';
    const titleEl = document.createElement('h3');
    titleEl.className = 'tui-dialog-title';
    titleEl.textContent = title || '';
    header.appendChild(titleEl);
    dialog.appendChild(header);

    const body = document.createElement('div');
    body.className = 'tui-dialog-body';
    body.style.display = 'flex';
    body.style.flexDirection = 'column';
    body.style.alignItems = 'center';
    body.style.gap = '12px';
    body.style.padding = '20px';

    const spinner = document.createElement('div');
    spinner.className = 'tui-dialog-spinner';
    spinner.innerHTML = `<svg viewBox="0 0 24 24" width="32" height="32" style="animation: tui-spin 1s linear infinite; fill: var(--accent);">
      <circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="3" fill="none" stroke-dasharray="32" stroke-linecap="round"/>
    </svg>`;

    const msgEl = document.createElement('div');
    msgEl.className = 'tui-dialog-desc';
    msgEl.style.textAlign = 'center';
    msgEl.textContent = message || '';

    body.appendChild(spinner);
    body.appendChild(msgEl);
    dialog.appendChild(body);
    overlay.appendChild(dialog);

    let closed = false;
    const close = () => {
      if (closed) return;
      closed = true;
      this._activeStatus = null;
      this._cleanup(overlay, unbind);
    };

    const unbind = this._bindOverlay(overlay, close);
    this._activeStatus = close;

    return close;
  },

  // ── Toast ──
  toast(msgOrOpts, type = 'info') {
    const opts = typeof msgOrOpts === 'string' ? { message: msgOrOpts, variant: type } : msgOrOpts;
    const msg = opts.message || '';
    const variant = opts.variant || opts.type || 'info';
    const title = opts.title || '';

    let el = document.getElementById('app-toast');
    if (!el) {
      el = document.createElement('div');
      el.id = 'app-toast';
      el.className = 'tui-toast';
      document.body.appendChild(el);
    }
    clearTimeout(this._toastTimer);

    el.innerHTML = '';
    if (title) {
      const titleEl = document.createElement('div');
      titleEl.className = 'tui-toast-title';
      titleEl.textContent = title;
      el.appendChild(titleEl);
    }
    const msgEl = document.createElement('div');
    msgEl.className = 'tui-toast-message';
    msgEl.textContent = msg;
    el.appendChild(msgEl);

    el.className = 'tui-toast tui-toast--' + variant + ' tui-toast--visible';
    this._toastTimer = setTimeout(() => {
      el.classList.remove('tui-toast--visible');
    }, opts.duration || 3000);
  },
};
