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

// PWA, Service Worker, and Header Collapse Logic

// 1. Service Worker Registration
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js').then((registration) => {
      registration.update().catch(() => {});
    }).catch((err) => {
      console.error('ServiceWorker registration failed: ', err);
    });
  });
}

// 1b. Update available → top bar with an Update button (code-server style)
(function () {
  if (!('serviceWorker' in navigator)) return;

  let updateWorker = null;
  let updateRequested = false;
  let reloading = false;
  let updateModalShown = false;

  navigator.serviceWorker.addEventListener('controllerchange', () => {
    if ((!updateRequested && !window.__shellsAutoReload) || reloading) return;
    reloading = true;
    window.location.reload();
  });

  // Prompt for a waiting service worker on load too, so a deferred update
  // re-surfaces on the next visit instead of being silently stuck.
  const promptWaiting = (registration) => {
    if (registration.waiting && registration.waiting.state === 'installed') {
      updateWorker = registration.waiting;
      showUpdateBar();
    }
  };

  navigator.serviceWorker.ready.then((registration) => {
    promptWaiting(registration);
    registration.addEventListener('updatefound', () => {
      const newWorker = registration.installing;
      if (!newWorker) return;
      updateWorker = newWorker;
      newWorker.addEventListener('statechange', () => {
        if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
          showUpdateBar();
        }
      });
    });
  });

  // Centered in-app modal (not a top bar), like the GitHub-release update.
  function showUpdateBar() {
    if (updateModalShown || !window.TuiDialog) return;
    updateModalShown = true;
    const message = document.createElement('div');
    message.style.lineHeight = '1.6';
    const line = document.createElement('div');
    line.textContent = 'A new version of the app is ready.';
    message.appendChild(line);
    // Show "prev → new" versions when health is reachable.
    fetch('/api/health', { cache: 'no-store' }).then((r) => r.ok ? r.json() : null).then((h) => {
      if (!h) return;
      const newV = String(h.version || '').replace(/^v/, '');
      const oldV = document.body.dataset.version || '';
      if (newV && newV !== oldV) line.textContent = `v${oldV} → v${newV}`;
    }).catch(() => {});
    window.TuiDialog.confirm('Update available', message, {
      confirmText: 'Update',
      cancelText: 'Later',
      size: 'small',
    }).then((ok) => {
      updateModalShown = false;
      if (ok) {
        updateRequested = true;
        if (updateWorker) { try { updateWorker.postMessage('SKIP_WAITING'); } catch (_) {} }
      }
    });
  }
})();

// 1c. Seamless self-update reload. After the server applies a verified update
// and restarts, drive the SW update + activation automatically so the user
// lands on the new version with no manual refresh (desktop or mobile PWA).
window.pwaReloadAfterUpdate = async function pwaReloadAfterUpdate() {
  // Wait for the server to come back (health is unencrypted).
  const up = await new Promise((resolve) => {
    let tries = 0;
    const tick = async () => {
      try {
        const r = await fetch('/api/health', { cache: 'no-store' });
        if (r.ok) return resolve(true);
      } catch (_) {}
      tries += 1;
      if (tries >= 50) return resolve(false); // ~25s cap
      setTimeout(tick, 500);
    };
    tick();
  });
  if (!up) {
    if (window.TuiDialog && window.TuiDialog.toast) {
      window.TuiDialog.toast("Server is restarting — reload when it's back", 'warning');
    }
    return;
  }
  if ('serviceWorker' in navigator && navigator.serviceWorker.controller) {
    window.__shellsAutoReload = true; // controllerchange → reload (see 1b)
    try {
      const reg = await navigator.serviceWorker.getRegistration();
      if (!reg) { window.location.reload(); return; }
      const activate = (worker) => {
        if (worker && worker.state === 'installed') {
          try { worker.postMessage('SKIP_WAITING'); } catch (_) {}
        }
      };
      const onFound = () => {
        const w = reg.installing || reg.waiting;
        if (!w) return;
        activate(w);
        w.addEventListener('statechange', () => { if (w.state === 'installed') activate(w); });
      };
      reg.addEventListener('updatefound', onFound);
      activate(reg.waiting);
      await reg.update();
      // Fallback: if the new SW never activates, clear the flag and reload.
      setTimeout(() => {
        if (!window.__shellsAutoReloaded) {
          window.__shellsAutoReloaded = true;
          window.__shellsAutoReload = false;
          window.location.reload();
        }
      }, 8000);
    } catch (_) {
      window.__shellsAutoReload = false;
      window.location.reload();
    }
  } else {
    window.location.reload();
  }
};

// 2. PWA Installability Logic
let deferredPrompt = null;

// Pure check: is the app running in an installed/standalone display mode?
// No side effects — syncPWAVisibility() keeps the state mutations.
function isStandalonePWA() {
  return window.matchMedia('(display-mode: standalone)').matches ||
         window.matchMedia('(display-mode: minimal-ui)').matches ||
         window.matchMedia('(display-mode: window-controls-overlay)').matches ||
         window.matchMedia('(display-mode: fullscreen)').matches ||
         window.navigator.standalone === true ||
         localStorage.getItem('pwa-installed') === 'true';
}
window.isStandalonePWA = isStandalonePWA;

function syncPWAVisibility() {
  const isStandalone = isStandalonePWA();
  if (isStandalone) {
    if (localStorage.getItem('pwa-installed') !== 'true') {
      localStorage.setItem('pwa-installed', 'true');
    }
    deferredPrompt = null;
    document.body.classList.remove('pwa-installable');
    return true;
  }
  return false;
}

// Watch for standalone mode changes
window.matchMedia('(display-mode: standalone)').addEventListener('change', syncPWAVisibility);

// Chrome's install pipeline runs a GPU/rendering sync while the dialog shows;
// active xterm WebGL contexts can hang the renderer for the whole origin
// (RESULT_CODE_HUNG). Dropping to the canvas renderer around the install moment
// avoids it — buffer/scrollback are preserved.
const suspendWebgl = () => { if (window.ShellSessions && window.ShellSessions.setWebglEnabled) window.ShellSessions.setWebglEnabled(false); };
const restoreWebgl = () => { if (window.ShellSessions && window.ShellSessions.setWebglEnabled) window.ShellSessions.setWebglEnabled(true); };

// dispose() only queues GL destruction to the GPU process; yield so it drains
// before the install dialog fires its GPU sync. The setTimeout fallback guards
// against rAF stalling if the tab is backgrounded between click and prompt.
const yieldGpu = () => new Promise(resolve => {
  let done = false;
  const finish = () => { if (!done) { done = true; resolve(); } };
  requestAnimationFrame(() => requestAnimationFrame(() => setTimeout(finish, 250)));
  setTimeout(finish, 1000);
});

window.addEventListener('beforeinstallprompt', (e) => {
  e.preventDefault();
  if (localStorage.getItem('pwa-installed') === 'true') return;
  deferredPrompt = e;
  if (!syncPWAVisibility()) {
    document.body.classList.add('pwa-installable');
  }
});

window.addEventListener('appinstalled', () => {
  deferredPrompt = null;
  document.body.classList.remove('pwa-installable');
  localStorage.setItem('pwa-installed', 'true');
});

// Initial check
syncPWAVisibility();

// 3. Global Click Events for PWA & Header Logic
document.addEventListener('click', (e) => {
  // Handle PWA Install Button Click
  const installBtn = e.target.closest('[data-action="install-pwa"]');
  if (installBtn) {
    (async () => {
      if (!deferredPrompt) {
        document.body.classList.remove('pwa-installable');
        return;
      }
      const promptEvent = deferredPrompt;
      deferredPrompt = null;
      document.body.classList.remove('pwa-installable');

      // Suspend first and arm the safety net before yielding, so WebGL can
      // never be left off if anything below throws or the promise rejects.
      suspendWebgl();
      setTimeout(restoreWebgl, 10000);
      await yieldGpu();
      try { promptEvent.prompt(); } catch (_) {}
      const done = () => { setTimeout(restoreWebgl, 300); };
      promptEvent.userChoice.then((result) => {
        if (result.outcome === 'accepted') {
          localStorage.setItem('pwa-installed', 'true');
        }
        done();
      }).catch(done);
    })();
    return;
  }
});

