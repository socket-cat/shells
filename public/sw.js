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

const CACHE_NAME = 'shells-static-{{VERSION}}';

// Brand identity (name | accent). Baked into the SW so the browser detects a
// service-worker update — and prompts to update the installed PWA — whenever
// the app name or accent color change at deploy time. (Any byte change in
// sw.js triggers the SW update lifecycle; this comment is that change.)
// identity: {{APP_NAME_JSON}} | {{ACCENT}}

const HTML_URLS = ['/', '/index.html'];
const STATIC_ASSETS = [
  '/css/base.css',
  '/css/load-screen.css',
  '/css/shell-grid.css',
  '/css/mobile.css',
  '/css/components.css',
  '/css/tui-dialog.css',
  '/js/app.js',
  '/pwa.js',
  '/js/icons.js',
  '/js/audio.js',
  '/js/tui-dialog.js',
  '/js/crypto.js',
  '/js/shell-sessions.js',
  '/js/theme.js',
  '/js/theme-templates.js',
  '/js/grid-resizer.js',
  '/js/layout.js',
  '/js/switcher.js',
  '/js/mobile.js',
  '/js/keyboard-picker.js',
  '/js/telemetry.js',
  '/js/input.js',
  '/js/xterm.js',
  '/js/xterm-addon-fit.js',
  '/js/xterm-addon-webgl.js',
  '/js/xterm-addon-unicode11.js',
  '/js/xterm-addon-clipboard.js',
  '/js/xterm-addon-web-links.js',
  '/js/xterm-addon-search.js',
  '/css/xterm.css',
  '/fonts/fira-code/index.css',
  '/fonts/fira-code/files/fira-code-cyrillic-300-normal.woff2',
  '/fonts/fira-code/files/fira-code-cyrillic-400-normal.woff2',
  '/fonts/fira-code/files/fira-code-cyrillic-500-normal.woff2',
  '/fonts/fira-code/files/fira-code-cyrillic-600-normal.woff2',
  '/fonts/fira-code/files/fira-code-cyrillic-700-normal.woff2',
  '/fonts/fira-code/files/fira-code-cyrillic-ext-300-normal.woff2',
  '/fonts/fira-code/files/fira-code-cyrillic-ext-400-normal.woff2',
  '/fonts/fira-code/files/fira-code-cyrillic-ext-500-normal.woff2',
  '/fonts/fira-code/files/fira-code-cyrillic-ext-600-normal.woff2',
  '/fonts/fira-code/files/fira-code-cyrillic-ext-700-normal.woff2',
  '/fonts/fira-code/files/fira-code-greek-300-normal.woff2',
  '/fonts/fira-code/files/fira-code-greek-400-normal.woff2',
  '/fonts/fira-code/files/fira-code-greek-500-normal.woff2',
  '/fonts/fira-code/files/fira-code-greek-600-normal.woff2',
  '/fonts/fira-code/files/fira-code-greek-700-normal.woff2',
  '/fonts/fira-code/files/fira-code-greek-ext-300-normal.woff2',
  '/fonts/fira-code/files/fira-code-greek-ext-400-normal.woff2',
  '/fonts/fira-code/files/fira-code-greek-ext-500-normal.woff2',
  '/fonts/fira-code/files/fira-code-greek-ext-600-normal.woff2',
  '/fonts/fira-code/files/fira-code-greek-ext-700-normal.woff2',
  '/fonts/fira-code/files/fira-code-latin-300-normal.woff2',
  '/fonts/fira-code/files/fira-code-latin-400-normal.woff2',
  '/fonts/fira-code/files/fira-code-latin-500-normal.woff2',
  '/fonts/fira-code/files/fira-code-latin-600-normal.woff2',
  '/fonts/fira-code/files/fira-code-latin-700-normal.woff2',
  '/fonts/fira-code/files/fira-code-latin-ext-300-normal.woff2',
  '/fonts/fira-code/files/fira-code-latin-ext-400-normal.woff2',
  '/fonts/fira-code/files/fira-code-latin-ext-500-normal.woff2',
  '/fonts/fira-code/files/fira-code-latin-ext-600-normal.woff2',
  '/fonts/fira-code/files/fira-code-latin-ext-700-normal.woff2',
  '/fonts/fira-code/files/fira-code-symbols2-300-normal.woff2',
  '/fonts/fira-code/files/fira-code-symbols2-400-normal.woff2',
  '/fonts/fira-code/files/fira-code-symbols2-500-normal.woff2',
  '/fonts/fira-code/files/fira-code-symbols2-600-normal.woff2',
  '/fonts/fira-code/files/fira-code-symbols2-700-normal.woff2',
];
const ASSETS_TO_CACHE = [...HTML_URLS, ...STATIC_ASSETS];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return Promise.allSettled(
        ASSETS_TO_CACHE.map(url => cache.add(url))
      );
    })
  );
});

// A waiting service worker activates only when the user chooses to update
// (the page posts SKIP_WAITING), giving a code-server-style update prompt.
self.addEventListener('message', (event) => {
  if (event.data === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keyList) => {
      return Promise.all(keyList.map((key) => {
        if (key !== CACHE_NAME) {
          return caches.delete(key);
        }
      }));
    })
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  
  // Do not cache API or WebSocket requests
  if (url.pathname.startsWith('/api/') || url.pathname === '/ws') {
    return;
  }

  // Cache-First for HTML: keeps the page and its asset SRI hashes consistent
  // during SW updates. (Network-first HTML with new SRI hashes + old cached
  // assets makes the browser reject the assets.) Fresh HTML arrives once the
  // new SW activates, i.e. after the user applies the update.
  if (HTML_URLS.includes(url.pathname)) {
    event.respondWith(
      caches.match(event.request).then((cachedResponse) => {
        if (cachedResponse) {
          return cachedResponse;
        }
        return fetch(event.request).then((networkResponse) => {
          if (networkResponse && networkResponse.status === 200) {
            const responseToCache = networkResponse.clone();
            caches.open(CACHE_NAME).then((cache) => {
              cache.put(event.request, responseToCache);
            });
          }
          return networkResponse;
        });
      })
    );
    return;
  }
  
  // Cache-First for static assets
  if (STATIC_ASSETS.includes(url.pathname)) {
    event.respondWith(
      caches.match(event.request, { ignoreSearch: true }).then((cachedResponse) => {
        if (cachedResponse) {
          return cachedResponse;
        }
        
        return fetch(event.request).then((networkResponse) => {
          if (networkResponse && networkResponse.status === 200) {
            const responseToCache = networkResponse.clone();
            caches.open(CACHE_NAME).then((cache) => {
              cache.put(event.request, responseToCache);
            });
          }
          return networkResponse;
        });
      })
    );
    return;
  }
  
  // Network-First for other requests (fallback)
  event.respondWith(
    fetch(event.request).then((networkResponse) => {
      return networkResponse;
    }).catch(() => {
      return new Response('{}', {
        status: 503,
        statusText: 'Service Unavailable',
        headers: new Headers({ 'Content-Type': 'application/json' })
      });
    })
  );
});
