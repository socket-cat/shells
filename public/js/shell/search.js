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

// ── In-terminal search (active tile) ──
// Extracted from shell-sessions.js. In-terminal Ctrl+Shift+F search
// over the active session's buffer + decorations. Search state
// (_searchState/_searchDecorations) stays declared once in the core
// literal. closeSearch calls window._focusWithoutScroll — a pinned-core
// window bridge helper (sanctioned per plan).

window.ShellSessions = Object.assign(window.ShellSessions, {
  openSearch() {
    if (!this.activeId) return;
    const session = this.sessions.get(this.activeId);
    if (!session || !session.searchAddon) return;
    // Already open: just refocus, don't wipe the query.
    if (this._searchState) {
      const input = document.querySelector('#term-search-bar input');
      if (input) { input.focus(); input.select(); }
      return;
    }

    const tile = session.tile;
    const body = tile.querySelector('.tile-body');
    if (!body) return;

    const accent = (getComputedStyle(document.documentElement).getPropertyValue('--accent') || '').trim() || '#fab283';
    this._searchDecorations = {
      matchBackground: '#fd8f8f',
      matchForeground: '#1a1a1a',
      activeMatchBackground: accent,
      activeMatchForeground: '#000000',
      matchOverviewRuler: '#fd8f8f',
      activeMatchColorOverviewRuler: accent,
    };

    const bar = document.createElement('div');
    bar.id = 'term-search-bar';
    bar.className = 'term-search-bar';

    const input = document.createElement('input');
    input.type = 'text';
    input.placeholder = 'Search';
    input.maxLength = 512;
    input.autocomplete = 'off';
    input.autocapitalize = 'none';
    input.autocorrect = 'off';
    input.spellcheck = false;
    input.setAttribute('aria-label', 'Search terminal');

    const caseBtn = document.createElement('button');
    caseBtn.type = 'button';
    caseBtn.className = 'tsb-toggle';
    caseBtn.textContent = 'Aa';
    caseBtn.title = 'Match case';
    caseBtn.addEventListener('click', () => { caseBtn.classList.toggle('active'); run(); });

    const regexBtn = document.createElement('button');
    regexBtn.type = 'button';
    regexBtn.className = 'tsb-toggle';
    regexBtn.textContent = '.*';
    regexBtn.title = 'Regular expression';
    regexBtn.addEventListener('click', () => { regexBtn.classList.toggle('active'); run(); });

    const prevBtn = document.createElement('button');
    prevBtn.type = 'button';
    prevBtn.className = 'tsb-nav';
    prevBtn.textContent = '\u25B2';
    prevBtn.title = 'Previous (Shift+Enter)';
    prevBtn.addEventListener('click', () => this.searchPrev());

    const nextBtn = document.createElement('button');
    nextBtn.type = 'button';
    nextBtn.className = 'tsb-nav';
    nextBtn.textContent = '\u25BC';
    nextBtn.title = 'Next (Enter)';
    nextBtn.addEventListener('click', () => this.searchNext());

    const count = document.createElement('span');
    count.className = 'tsb-count';

    const closeBtn = document.createElement('button');
    closeBtn.type = 'button';
    closeBtn.className = 'tsb-close';
    closeBtn.textContent = '\u00D7';
    closeBtn.title = 'Close (Esc)';
    closeBtn.addEventListener('click', () => this.closeSearch());

    bar.appendChild(input);
    bar.appendChild(caseBtn);
    bar.appendChild(regexBtn);
    bar.appendChild(prevBtn);
    bar.appendChild(nextBtn);
    bar.appendChild(count);
    bar.appendChild(closeBtn);
    body.appendChild(bar);

    this._searchState = {
      sid: this.activeId,
      query: '',
      opts: { caseSensitive: false, regex: false },
      count: 0,
      index: 0,
      lastFound: null,
      regexError: false,
      unsub: null,
    };

    if (typeof session.searchAddon.onDidChangeResults === 'function') {
      this._searchState.unsub = session.searchAddon.onDidChangeResults((data) => {
        if (!this._searchState || this._searchState.sid !== this.activeId) return;
        if (data && typeof data.resultCount === 'number') {
          this._searchState.count = data.resultCount;
          this._searchState.index = data.resultCount ? data.resultIndex + 1 : 0;
          this._updateSearchCount();
        }
      });
    }

    const run = (dir = 1) => {
      if (!this._searchState) return;
      this._searchState.query = input.value;
      this._searchState.opts.caseSensitive = caseBtn.classList.contains('active');
      this._searchState.opts.regex = regexBtn.classList.contains('active');
      if (dir > 0) this.searchNext(); else this.searchPrev();
    };

    let debounce = null;
    input.addEventListener('input', () => {
      clearTimeout(debounce);
      debounce = setTimeout(run, 150);
    });
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        clearTimeout(debounce);
        run(e.shiftKey ? -1 : 1);
      } else if (e.key === 'Escape') {
        e.preventDefault();
        this.closeSearch();
      }
    });

    input.focus();
  },

  closeSearch() {
    const bar = document.getElementById('term-search-bar');
    if (bar) bar.remove();
    if (this._searchState) {
      const sid = this._searchState.sid;
      if (this._searchState.unsub) {
        try { this._searchState.unsub.dispose(); } catch (_) { try { this._searchState.unsub(); } catch (_2) {} }
      }
      this._clearSearch();
      const session = this.sessions.get(sid);
      if (session && session.term) window._focusWithoutScroll(session.term);
    }
    this._searchState = null;
  },

  _searchSession() {
    if (!this._searchState) return null;
    const s = this.sessions.get(this._searchState.sid);
    return s && s.searchAddon ? s : null;
  },

  _searchOptions() {
    const opts = { caseSensitive: this._searchState.opts.caseSensitive, regex: this._searchState.opts.regex };
    if (this._searchDecorations) opts.decorations = this._searchDecorations;
    return opts;
  },

  _clearSearch() {
    const s = this._searchSession();
    if (s && s.searchAddon && typeof s.searchAddon.clearDecorations === 'function') {
      try { s.searchAddon.clearDecorations(); } catch (_) {}
    }
  },

  // Single search path for both directions (dedupes searchNext/searchPrev and
  // validates the query — an invalid regex must not reach the addon, which
  // would throw an uncaught SyntaxError and permanently disable highlights).
  _runSearch(dir) {
    const s = this._searchSession();
    if (!s) return;
    const st = this._searchState;
    const q = st.query;
    if (!q) {
      this._clearSearch();
      st.lastFound = true;
      st.regexError = false;
      this._updateSearchCount();
      return;
    }
    if (st.opts.regex) {
      try { new RegExp(q); } catch (_) {
        st.regexError = true;
        st.lastFound = false;
        this._updateSearchCount();
        return;
      }
    }
    st.regexError = false;
    const opts = this._searchOptions();
    let res = null;
    try {
      res = dir > 0 ? s.searchAddon.findNext(q, opts) : s.searchAddon.findPrevious(q, opts);
    } catch (_) {
      // Decorations unsupported on this xterm: drop them for good and retry.
      this._searchDecorations = null;
      const plain = { caseSensitive: st.opts.caseSensitive, regex: st.opts.regex };
      try { res = dir > 0 ? s.searchAddon.findNext(q, plain) : s.searchAddon.findPrevious(q, plain); } catch (_2) { res = null; }
    }
    st.lastFound = !!(res && res.found);
    this._updateSearchCount();
  },

  searchNext() { this._runSearch(1); },
  searchPrev() { this._runSearch(-1); },

  _updateSearchCount() {
    const count = document.querySelector('#term-search-bar .tsb-count');
    if (!count || !this._searchState) return;
    const st = this._searchState;
    if (!st.query) { count.textContent = ''; return; }
    if (st.regexError) { count.textContent = 'bad regex'; return; }
    if (st.count > 0) {
      count.textContent = `${st.index}/${st.count}`;
    } else if (st.lastFound === false) {
      count.textContent = 'no results';
    } else {
      count.textContent = '';
    }
  },
});
