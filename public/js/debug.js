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

// ── Client-side diagnostic harness (OPT-IN, off by default) ──
// Enabled only by `?debug=1` or localStorage['shells-debug']==='1'. When
// disabled, `window.__dbg` is NOT defined, so every `window.__dbg?.trace(...)`
// call site in the app short-circuits BEFORE its arguments are evaluated —
// zero allocation, zero DOM reads, zero behavior change on a normal load.

(function() {
  let enabled = false;
  try {
    enabled = new URLSearchParams(location.search).get('debug') === '1' ||
      localStorage.getItem('shells-debug') === '1';
  } catch (_) {}
  if (!enabled) return;

  const CAP = 6000;
  const ring = new Array(CAP);
  let head = 0;
  let size = 0;

  // Streaming: events pending server-side delivery. Newest entries are the
  // valuable ones right before a freeze, so when the cap is hit we drop the
  // OLDEST. Zero cost while disabled (this whole IIFE only runs when enabled).
  let unsent = [];

  const trace = (tag, data) => {
    const entry = { t: Date.now(), m: Math.round(performance.now()), tag };
    if (data) Object.assign(entry, data);
    ring[head] = entry;
    head = (head + 1) % CAP;
    if (size < CAP) size++;
    unsent.push(entry);
    if (unsent.length > 400) unsent.splice(0, unsent.length - 400);
  };

  const ordered = (i) => ring[(head - size + i + CAP) % CAP];

  const dump = () => {
    const out = [];
    for (let i = 0; i < size; i++) out.push(ordered(i));
    return JSON.stringify(out);
  };

  const last = (n) => {
    const out = [];
    for (let i = Math.max(0, size - n); i < size; i++) out.push(ordered(i));
    return JSON.stringify(out);
  };

  // Best-effort push of pending events to the server. sendBeacon is
  // fire-and-forget: it does not block the page and survives pagehide/freezes
  // better than fetch. If a batch is over ~60KB, trim from the FRONT (oldest)
  // by halving the retained count until it fits.
  const streamFlush = () => {
    if (!unsent.length) return;
    const batch = unsent;
    unsent = [];
    let keep = batch.length;
    let payload = JSON.stringify({ url: location.href, t: Date.now(), events: batch });
    while (payload.length > 60000 && keep > 1) {
      keep = Math.ceil(keep / 2);
      payload = JSON.stringify({ url: location.href, t: Date.now(), events: batch.slice(-keep) });
    }
    try {
      navigator.sendBeacon('/api/dbg', new Blob([payload], { type: 'text/plain' }));
    } catch (_) {}
  };

  // Flush every 2s, and opportunistically when the page is hidden or unloaded.
  setInterval(streamFlush, 2000);
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'hidden') streamFlush();
  });
  window.addEventListener('pagehide', streamFlush);

  // Page-level cascade triggers (passive, trace-only).
  window.addEventListener('resize', () => trace('window.resize', { w: window.innerWidth, h: window.innerHeight }), { passive: true });
  window.addEventListener('orientationchange', () => trace('window.orientationchange', { type: (screen.orientation && screen.orientation.type) || '' }), { passive: true });
  window.addEventListener('pageshow', (e) => trace('window.pageshow', { persisted: !!e.persisted }), { passive: true });
  document.addEventListener('visibilitychange', () => trace('doc.visibilitychange', { state: document.visibilityState }), { passive: true });
  document.addEventListener('focus', () => trace('doc.focus', {}), { passive: true, capture: true });
  document.addEventListener('blur', () => trace('doc.blur', {}), { passive: true, capture: true });

  // ── Floating panel (built lazily, only when enabled) ──
  const BTN_CSS = 'position:fixed;right:12px;bottom:10px;z-index:2147483000;width:42px;height:32px;border:1px solid #555;border-radius:8px;background:#111;color:#f0b98a;font:12px monospace;cursor:pointer;opacity:.85';
  const PANEL_CSS = 'position:fixed;right:12px;bottom:46px;z-index:2147483000;width:min(480px,calc(100vw - 24px));max-height:62vh;display:none;flex-direction:column;background:#111;color:#ddd;border:1px solid #555;border-radius:8px;font:11px/1.45 ui-monospace,monospace;box-shadow:0 6px 24px rgba(0,0,0,.55);overflow:hidden';

  let panel = null;
  let pre = null;
  let keyHandler = null;
  let refreshTimer = null;

  const fallbackCopy = (text) => {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.cssText = 'position:fixed;opacity:0';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); } catch (_) {}
    ta.remove();
  };

  const refresh = () => {
    if (pre) pre.textContent = last(1500);
  };

  const buildPanel = () => {
    if (panel) return;
    panel = document.createElement('div');
    panel.id = 'shells-dbg-panel';
    panel.style.cssText = PANEL_CSS;

    const bar = document.createElement('div');
    bar.style.cssText = 'display:flex;gap:6px;align-items:center;padding:6px 8px;border-bottom:1px solid #333;flex:none';
    const title = document.createElement('span');
    title.textContent = 'shells debug';
    title.style.cssText = 'flex:1;font-weight:bold';
    const copyBtn = document.createElement('button');
    copyBtn.type = 'button';
    copyBtn.textContent = 'Copy';
    const dlBtn = document.createElement('button');
    dlBtn.type = 'button';
    dlBtn.textContent = '.json';
    dlBtn.title = 'Download log as JSON';
    const closeBtn = document.createElement('button');
    closeBtn.type = 'button';
    closeBtn.textContent = '\u00D7';
    closeBtn.title = 'Close (Esc)';
    for (const b of [copyBtn, dlBtn, closeBtn]) {
      b.style.cssText = 'border:1px solid #444;border-radius:5px;background:#1c1c1c;color:#ddd;padding:2px 8px;cursor:pointer';
    }
    bar.appendChild(title);
    bar.appendChild(copyBtn);
    bar.appendChild(dlBtn);
    bar.appendChild(closeBtn);

    pre = document.createElement('pre');
    pre.style.cssText = 'flex:1;overflow:auto;margin:0;padding:8px;white-space:pre-wrap;word-break:break-all';

    copyBtn.onclick = () => {
      const text = dump();
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).catch(() => fallbackCopy(text));
      } else {
        fallbackCopy(text);
      }
    };
    dlBtn.onclick = () => {
      const blob = new Blob([dump()], { type: 'application/json' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'shells-debug-' + Date.now() + '.json';
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 5000);
    };
    closeBtn.onclick = hide;

    panel.appendChild(bar);
    panel.appendChild(pre);
    document.body.appendChild(panel);
  };

  const show = () => {
    buildPanel();
    panel.style.display = 'flex';
    refresh();
    if (!refreshTimer) refreshTimer = setInterval(refresh, 700);
    if (!keyHandler) {
      keyHandler = (e) => {
        if (e.key === 'Escape') {
          e.preventDefault();
          e.stopImmediatePropagation();
          hide();
        }
      };
      document.addEventListener('keydown', keyHandler, true);
    }
  };

  const hide = () => {
    if (!panel) return;
    panel.style.display = 'none';
    if (refreshTimer) { clearInterval(refreshTimer); refreshTimer = null; }
    if (keyHandler) {
      document.removeEventListener('keydown', keyHandler, true);
      keyHandler = null;
    }
  };

  const btn = document.createElement('button');
  btn.type = 'button';
  btn.textContent = 'dbg';
  btn.title = 'shells debug (Esc closes)';
  btn.style.cssText = BTN_CSS;
  btn.addEventListener('click', () => {
    if (panel && panel.style.display !== 'none') hide();
    else show();
  });
  document.body.appendChild(btn);

  window.__dbg = { trace, dump };
})();
