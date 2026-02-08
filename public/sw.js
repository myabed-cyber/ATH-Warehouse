/* Minimal SW (v4) — caches static assets (excluding HTML) to avoid update traps */
// Updated cache version after changing assets (logo image). Increment version to bust old caches.
const CACHE = 'gs1hub-shell-v13';
const ASSETS = [
  './ui.css',
  './app.js',
  './wow-bindings.js',
  './wow-app.js',
  './sfx.js',
  './manifest.webmanifest',
  './responsive-enhancements.css',
  './assets/logo.svg',
  './assets/designer-12.png',
  './assets/ath-medical-division.png',
  './assets/icon-192.png',
  './assets/icon-512.png',
  './vendor/zxing-umd.min.js',
  './logo.png',
  './logo_header.png',
];

self.addEventListener('install', (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE);
    await cache.addAll(ASSETS.filter(Boolean));
    self.skipWaiting();
  })());
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.map(k => (k !== CACHE) ? caches.delete(k) : null));
    self.clients.claim();
  })());
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (event.request.method !== 'GET') return;
  if (url.pathname.startsWith('/api/')) return;

  const isHTML = event.request.mode === 'navigate' ||
    (event.request.headers.get('accept') || '').includes('text/html');
  if (isHTML) return; // Let the browser handle HTML (always fresh)

  const isCode = url.pathname.endsWith('.js') || url.pathname.endsWith('.css') || url.pathname.endsWith('.webmanifest');

  event.respondWith((async () => {
    const cache = await caches.open(CACHE);

    // For code assets, prefer network (so updates ship), fallback to cache offline.
    if (isCode) {
      try {
        const res = await fetch(event.request, { cache: 'no-store' });
        if (res && res.ok && url.origin === location.origin) {
          cache.put(event.request, res.clone());
        }
        return res;
      } catch (e) {
        const cached = await cache.match(event.request);
        if (cached) return cached;
        throw e;
      }
    }

    // For images/static assets, cache-first for speed
    const cached = await cache.match(event.request);
    if (cached) return cached;

    const res = await fetch(event.request);
    if (res.ok && url.origin === location.origin) {
      cache.put(event.request, res.clone());
    }
    return res;
  })());
});
