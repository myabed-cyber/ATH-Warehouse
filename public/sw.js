/* Minimal SW (v4) — caches static assets (excluding HTML) to avoid update traps */
// Updated cache version after changing assets (logo image). Increment version to bust old caches.
const CACHE = 'gs1hub-shell-v12';
const ASSETS = [
  './ui.css',
  './app.js',
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
  if(event.request.method !== 'GET') return;
  if(url.pathname.startsWith('/api/')) return;

  const isHTML = event.request.mode === 'navigate' ||
    (event.request.headers.get('accept') || '').includes('text/html');
  if(isHTML) return;

  event.respondWith((async () => {
    const cache = await caches.open(CACHE);
    const cached = await cache.match(event.request);
    if(cached) return cached;

    const res = await fetch(event.request);
    if(res.ok && url.origin === location.origin){
      cache.put(event.request, res.clone());
    }
    return res;
  })());
});
