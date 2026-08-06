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

// ── Global Error Tracking ──
window.addEventListener('error', (e) => {
  const msg = {
    type: 'error',
    message: e.message,
    file: e.filename,
    line: e.lineno,
    col: e.colno,
    url: location.href
  };
  try {
    navigator.sendBeacon('/api/errors', JSON.stringify(msg));
  } catch(_) {}
  console.error('[Uncaught Error]', e.message);
});

window.addEventListener('unhandledrejection', (e) => {
  let reason = e.reason;
  if (reason instanceof Error) {
    reason = reason.message + (reason.stack ? '\n' + reason.stack : '');
  } else if (reason instanceof Event) {
    reason = `Event: ${reason.type} on ${reason.target?.constructor?.name || 'unknown'}`;
  } else if (typeof reason === 'object' && reason !== null) {
    try {
      reason = JSON.stringify(reason);
    } catch (_) {
      reason = String(reason);
    }
  } else {
    reason = String(reason);
  }

  const msg = {
    type: 'unhandledrejection',
    reason: reason,
    url: location.href
  };
  try {
    navigator.sendBeacon('/api/errors', JSON.stringify(msg));
  } catch(_) {}
  console.error('[Unhandled Rejection]', e.reason);
});

// ── Performance Metrics ──
if ('PerformanceObserver' in window) {
  const obs = new PerformanceObserver((list) => {
    for (const entry of list.getEntries()) {
      console.debug('[perf]', entry.name, entry.startTime.toFixed(1) + 'ms');
    }
  });
  obs.observe({ type: 'largest-contentful-paint', buffered: true });
  obs.observe({ type: 'first-input', buffered: true });
  try { obs.observe({ type: 'paint', buffered: true }); } catch(_) {}
}
