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

// ── Theme Management ──

// Fallback template definitions — only used if theme-templates.js failed to
// load (offline SW cache miss, 404, blocked script). Mirrors the canonical
// set there so ShellTheme.init()/themes never dereference an undefined
// template and hard-crash the app at startup.
const __SHELLS_THEME_FALLBACK = {
  light: { label: 'Light', base: 'invert(1) hue-rotate({hue}deg) brightness({bright}) contrast({contrast})', preset: { hue: 180, brightness: 1, contrast: 1 } },
  dark:  { label: 'Dark',  base: 'hue-rotate({hue}deg) brightness({bright}) contrast({contrast})', preset: { hue: 0, brightness: 1, contrast: 1 } },
  sepia: { label: 'Sepia', base: 'invert(1) hue-rotate({hue}deg) sepia(0.5) saturate(0.75) brightness({bright}) contrast({contrast})', preset: { hue: 180, brightness: 0.75, contrast: 1.4 } },
  brown: { label: 'Dim',   base: 'sepia(0.3) saturate(0.9) hue-rotate({hue}deg) brightness({bright}) contrast({contrast})', preset: { hue: 0, brightness: 0.82, contrast: 1.05 } },
};

window.ShellTheme = {
  STORAGE_KEY: 'shells-theme',
  FALLBACK_KEY: 'shells-invert',
  // Canonical template definitions live in theme-templates.js (single source
  // of truth, shared with the index.html anti-flash). If that script is
  // unavailable we fall back to __SHELLS_THEME_FALLBACK above so the app
  // still starts. This array adds the runtime `id` and keeps the shape the
  // picker uses.
  themes: Object.keys(window.SHELLS_THEME_TEMPLATES || __SHELLS_THEME_FALLBACK).map((id) => {
    const t = (window.SHELLS_THEME_TEMPLATES || __SHELLS_THEME_FALLBACK)[id];
    return { id, label: t.label, base: t.base, preset: t.preset };
  }),

  accent: null,
  appName: 'Shells',
  xtermTheme: null,
  _activeId: 'dark',
  _tone: { hue: 180, contrast: 1, brightness: 1 },

  hexValid(hex) { return /^#[0-9a-fA-F]{6}$/.test(hex); },

  luminance(hex) {
    const h = hex.replace('#', '');
    const r = parseInt(h.substring(0, 2), 16) / 255;
    const g = parseInt(h.substring(2, 4), 16) / 255;
    const b = parseInt(h.substring(4, 6), 16) / 255;
    return 0.2126 * r + 0.7152 * g + 0.0722 * b;
  },

  hexToRgba(hex, alpha) {
    const h = hex.replace('#', '');
    return `rgba(${parseInt(h.substring(0,2),16)}, ${parseInt(h.substring(2,4),16)}, ${parseInt(h.substring(4,6),16)}, ${alpha})`;
  },

  lighten(hex, amt) {
    const h = hex.replace('#', '');
    const c = (i) => Math.min(255, Math.round(parseInt(h.substring(i, i+2), 16) + (255 - parseInt(h.substring(i, i+2), 16)) * amt));
    return '#' + [0, 2, 4].map((i) => c(i).toString(16).padStart(2, '0')).join('');
  },

  buildXtermTheme(accent) {
    const t = Object.assign({}, window.darkTheme);
    t.cursor = accent;
    t.selectionBackground = this.hexToRgba(accent, 0.25);
    t.cursorAccent = this.luminance(accent) > 0.5 ? '#0a0a0a' : '#eeeeee';
    return t;
  },

  accentSvg(color) {
    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512"><path d="M256 52 L432.67 154 L432.67 358 L256 460 L79.33 358 L79.33 154 Z" fill="none" stroke="${color}" stroke-width="44" stroke-linejoin="round"/></svg>`;
  },

  svgDataUrl(color) {
    return 'data:image/svg+xml;base64,' + btoa(unescape(encodeURIComponent(this.accentSvg(color))));
  },

  _themeById(id) {
    return this.themes.find((t) => t.id === id) || null;
  },

  _setTheme(themeId) {
    const theme = this._themeById(themeId) || this._themeById('dark');
    this._activeId = theme.id;
    // Snap the sliders to the template's preset.
    this._tone = Object.assign({}, theme.preset);
    return this._applyTheme(theme);
  },

  _composeFilter(theme) {
    return theme.base
      .replace('{hue}', this._tone.hue)
      .replace('{bright}', this._tone.brightness)
      .replace('{contrast}', this._tone.contrast);
  },

  _applyTheme(theme, persist = true) {
    const root = document.documentElement;
    const t = theme || this._themeById(this._activeId) || this._themeById('dark');
    root.dataset.theme = t.id;

    const isLight = t.base.includes('invert(1)');
    root.dataset.themeType = isLight ? 'light' : 'dark';

    const themeColorMeta = document.querySelector('meta[name="theme-color"]');
    if (themeColorMeta) {
      themeColorMeta.setAttribute('content', isLight ? '#cccccc' : '#0a0a0a');
    }

    // The CSS filter (html.invert) is driven entirely by --theme-filter.
    root.classList.add('invert');
    root.style.setProperty('--theme-filter', this._composeFilter(t));
    if (persist) {
      localStorage.setItem(this.STORAGE_KEY, t.id);
      try {
        localStorage.setItem('shells-theme-hue', String(this._tone.hue));
        localStorage.setItem('shells-theme-contrast', String(this._tone.contrast));
        localStorage.setItem('shells-theme-brightness', String(this._tone.brightness));
      } catch (_) {}
    }

    if (window.ShellSessions && typeof window.ShellSessions.updateFontWeights === 'function') {
      window.ShellSessions.updateFontWeights();
    }

    return t;
  },

  // Live slider updates (drag): re-render; persisted on slider 'change'.
  setTone(hue, contrast, brightness, persist = true) {
    this._tone = { hue, contrast, brightness };
    this._applyTheme(null, persist);
  },

  init() {
    let activeId = null;
    const storedTheme = localStorage.getItem(this.STORAGE_KEY);
    if (storedTheme && this._themeById(storedTheme)) {
      activeId = storedTheme;
    } else {
      const legacyInvert = localStorage.getItem(this.FALLBACK_KEY);
      if (legacyInvert === 'true') {
        activeId = 'light';
      } else if (legacyInvert === 'false') {
        activeId = 'dark';
      } else {
        const prefersLight = window.matchMedia('(prefers-color-scheme: light)').matches;
        activeId = prefersLight ? 'light' : 'dark';
      }
    }
    this._activeId = activeId;
    const theme = this._themeById(activeId) || this._themeById('dark');

    // Restore any persisted slider values (clamped to the slider ranges),
    // falling back to the template preset.
    const clamp = (v, lo, hi, dflt) => (v !== null ? Math.max(lo, Math.min(hi, v)) : dflt);
    const readTone = (key) => {
      try {
        const v = parseFloat(localStorage.getItem(key));
        return isNaN(v) ? null : v;
      } catch (_) { return null; }
    };
    const hue = readTone('shells-theme-hue');
    const contrast = readTone('shells-theme-contrast');
    const brightness = readTone('shells-theme-brightness');
    this._tone = {
      hue: clamp(hue, 0, 360, theme.preset.hue),
      contrast: clamp(contrast, 0.5, 1.5, theme.preset.contrast),
      brightness: clamp(brightness, 0.5, 1.5, theme.preset.brightness),
    };

    this._applyTheme(theme);
    this.initBranding();
  },

  currentTheme() {
    const id = document.documentElement.dataset.theme || 'dark';
    return this._themeById(id) || this._themeById('dark');
  },

  async openPicker(triggerEl) {
    const box = document.createElement('div');
    // min-width:0 + width:100% so the content never overflows the dialog on
    // narrow (mobile) viewports — a fixed min-width clips on the right.
    box.style.cssText = 'display:flex;flex-direction:column;gap:12px;padding:2px 0;width:100%;min-width:0;max-height:70vh;overflow-y:auto';

    const sectionLabel = (t, extra = '') => {
      const el = document.createElement('div');
      el.textContent = t;
      el.style.cssText = 'font-size:10px;color:var(--text-muted);letter-spacing:1px' + (extra ? ';' + extra : '');
      return el;
    };

    // ── App name (top: how users tell tenants/dev environments apart) ──
    box.appendChild(sectionLabel('APP NAME'));
    const input = document.createElement('input');
    input.type = 'text';
    input.maxLength = 40;
    input.value = this.appName;
    input.style.cssText = 'width:100%;box-sizing:border-box;background:var(--bg-surface);border:1px solid var(--border);color:var(--text);padding:8px 10px;font-size:13px;font-family:var(--font-mono)';
    input.addEventListener('input', () => this.applyAppName(input.value, true));
    box.appendChild(input);

    // ── Accent color ──
    box.appendChild(sectionLabel('ACCENT COLOR'));
    const swatches = [
      '#fab283', '#ffd54f', '#81d4fa', '#a5d6a7', '#ce93d8', '#f48fb1', '#ff8a65', '#4db6ac', '#90a4ae', '#fff59d',
      '#ea580c', '#ef4444', '#f59e0b', '#10b981', '#0ea5e9', '#6366f1', '#a855f7', '#ec4899',
    ];
    const row = document.createElement('div');
    row.style.cssText = 'display:flex;flex-wrap:wrap;gap:8px';
    const paintSwatches = () => {
      Array.from(row.children).forEach((sw, i) => {
        sw.style.border = swatches[i].toLowerCase() === this.accent.toLowerCase() ? '2px solid #fff' : '2px solid transparent';
      });
    };
    swatches.forEach((c) => {
      const sw = document.createElement('button');
      sw.type = 'button';
      sw.title = c;
      sw.style.cssText = `width:26px;height:26px;border-radius:4px;background:${c};border:2px solid transparent;cursor:pointer`;
      sw.addEventListener('click', () => { this.applyAccent(c, false); paintSwatches(); });
      row.appendChild(sw);
    });
    box.appendChild(row);
    paintSwatches();
    box.appendChild(sectionLabel('Custom', 'margin-top:2px'));

    const custom = document.createElement('input');
    custom.type = 'color';
    custom.value = this.accent;
    custom.style.cssText = 'width:100%;box-sizing:border-box;height:32px;background:transparent;border:1px solid var(--border);cursor:pointer';
    custom.addEventListener('input', () => this.applyAccent(custom.value, true));
    box.appendChild(custom);

    // ── Theme ──
    box.appendChild(sectionLabel('THEME'));
    const themeList = document.createElement('div');
    themeList.style.cssText = 'display:grid;grid-template-columns:1fr 1fr;gap:6px';
    const paintThemes = () => {
      const active = this.currentTheme().id;
      themeList.querySelectorAll('button').forEach((b) => {
        const isActive = b.dataset.themeId === active;
        b.style.background = isActive ? 'var(--accent)' : 'var(--bg-surface)';
        b.style.color = isActive ? 'var(--accent-text)' : 'var(--text)';
        b.style.borderColor = isActive ? 'var(--accent)' : 'var(--border)';
      });
    };
    this.themes.forEach((t) => {
      const b = document.createElement('button');
      b.type = 'button';
      b.dataset.themeId = t.id;
      b.textContent = t.label;
      b.style.cssText = 'padding:6px 8px;font-size:11px;font-family:var(--font-mono);border:1px solid var(--border);cursor:pointer;text-align:left';
      b.addEventListener('click', () => { this._setTheme(t.id); paintThemes(); renderSliders(); });
      themeList.appendChild(b);
    });
    box.appendChild(themeList);
    paintThemes();

    // ── Tone (sliders) — fine-tune the active template ──
    box.appendChild(sectionLabel('TONE'));
    const sliderRows = [];
    const addSlider = (label, min, max, step, get, set, fmt) => {
      const row = document.createElement('div');
      row.style.cssText = 'display:flex;align-items:center;gap:8px';
      const lbl = document.createElement('span');
      lbl.style.cssText = 'font-family:var(--font-mono);font-size:10px;color:var(--text-muted);width:70px;flex-shrink:0';
      lbl.textContent = label;
      const input = document.createElement('input');
      input.type = 'range';
      input.min = String(min);
      input.max = String(max);
      input.step = String(step);
      input.style.cssText = 'flex:1;min-width:0;accent-color:var(--accent);cursor:pointer';
      const val = document.createElement('span');
      val.style.cssText = 'font-family:var(--font-mono);font-size:10px;color:var(--text);width:46px;text-align:right;flex-shrink:0';
      const render = () => {
        input.value = String(get());
        val.textContent = fmt(get());
      };
      // Live preview on input; persist only on change (avoids a localStorage
      // write + full re-render on every drag tick).
      input.addEventListener('input', () => { set(parseFloat(input.value)); render(); });
      input.addEventListener('change', () => { this._applyTheme(null, true); });
      row.appendChild(lbl);
      row.appendChild(input);
      row.appendChild(val);
      box.appendChild(row);
      sliderRows.push(render);
    };

    addSlider('Hue', 0, 360, 1,
      () => this._tone.hue,
      (v) => this.setTone(v, this._tone.contrast, this._tone.brightness, false),
      (v) => v + '°');
    addSlider('Contrast', 0.5, 1.5, 0.01,
      () => this._tone.contrast,
      (v) => this.setTone(this._tone.hue, v, this._tone.brightness, false),
      (v) => v.toFixed(2));
    addSlider('Brightness', 0.5, 1.5, 0.01,
      () => this._tone.brightness,
      (v) => this.setTone(this._tone.hue, this._tone.contrast, v, false),
      (v) => v.toFixed(2));

    const renderSliders = () => sliderRows.forEach((r) => r());
    renderSliders();

    const resetBtn = document.createElement('button');
    resetBtn.type = 'button';
    resetBtn.textContent = 'reset to template';
    resetBtn.style.cssText = 'align-self:flex-end;background:none;border:none;color:var(--text-muted);font-family:var(--font-mono);font-size:10px;cursor:pointer;text-decoration:underline;padding:0';
    resetBtn.addEventListener('click', () => {
      this._setTheme(this._activeId);
      paintThemes();
      renderSliders();
    });
    box.appendChild(resetBtn);

    await TuiDialog.confirm('Appearance', box, {
      confirmText: 'Done',
      size: 'medium',
      onConfirm: () => {
        this.applyAppName(input.value, true);
        // Persist server-side so the served manifest/icon reflect it and the
        // browser updates the installed PWA's name/icon on the OS.
        this.saveBrandingServer();
      },
    });

    if (triggerEl && typeof triggerEl.focus === 'function') triggerEl.focus();
  },

  async toggle(triggerEl) {
    await this.openPicker(triggerEl);
    return this.currentTheme().id !== 'dark';
  },

  applyAccent(color, silent) {
    if (!this.hexValid(color)) return;
    this.accent = color;
    const root = document.documentElement;
    root.style.setProperty('--accent', color);
    root.style.setProperty('--accent-hover', this.lighten(color, 0.12));
    root.style.setProperty('--accent-text', this.luminance(color) > 0.5 ? '#0a0a0a' : '#ffffff');
    this.xtermTheme = this.buildXtermTheme(color);
    if (window.ShellSessions && window.ShellSessions.sessions) {
      window.ShellSessions.sessions.forEach((s) => {
        if (s.term) { try { s.term.options.theme = this.xtermTheme; } catch (_) {} }
      });
    }
    const url = this.svgDataUrl(color);
    const fav = document.querySelector('link[rel="icon"]');
    if (fav) { fav.removeAttribute('integrity'); fav.removeAttribute('crossorigin'); fav.href = url; }
    const at = document.querySelector('link[rel="apple-touch-icon"]');
    if (at) { at.removeAttribute('integrity'); at.removeAttribute('crossorigin'); at.href = url; }
    document.querySelectorAll('img[src="/icon.svg"]').forEach((img) => { img.src = url; });
    try { localStorage.setItem('shells-accent', color); } catch (_) {}
    if (!silent && window.TuiDialog) window.TuiDialog.toast('Accent: ' + color, 'success');
  },

  applyAppName(name, silent) {
    const clean = (name || '').trim();
    this.appName = clean ? clean : 'Shells';
    document.querySelectorAll('.load-app-name, .empty-app-name').forEach((el) => { el.textContent = this.appName; });
    try { localStorage.setItem('shells-app-name', this.appName); } catch (_) {}
    if (!silent && window.TuiDialog) window.TuiDialog.toast('App name: ' + this.appName, 'success');
  },

  initBranding() {
    let accent = null;
    try { accent = localStorage.getItem('shells-accent'); } catch (_) {}
    if (!this.hexValid(accent)) accent = document.body.dataset.accent || '#fab283';
    this.applyAccent(accent, true);
    let name = null;
    try { name = localStorage.getItem('shells-app-name'); } catch (_) {}
    if (!name || !name.trim()) name = document.body.dataset.appName || 'Shells';
    this.applyAppName(name, true);
  },

  // Pull the authoritative branding from the server (called after auth) and
  // apply it, syncing the local cache. The server is the source of truth so
  // the served manifest/icon (and thus the installed PWA) track it.
  async syncFromServer() {
    try {
      const { ok, data } = await window.ShellSessions.encryptedFetch('/api/branding', { _method: 'GET' });
      if (!ok || !data) return;
      if (this.hexValid(data.accent)) this.applyAccent(data.accent, true);
      if (data.appName && String(data.appName).trim()) this.applyAppName(data.appName, true);
    } catch (_) {}
  },

  // Push the current branding to the server (persisted → manifest/icon update).
  async saveBrandingServer() {
    try {
      await window.ShellSessions.encryptedFetch('/api/branding', {
        _method: 'POST', appName: this.appName, accent: this.accent,
      });
    } catch (_) {}
  },
};