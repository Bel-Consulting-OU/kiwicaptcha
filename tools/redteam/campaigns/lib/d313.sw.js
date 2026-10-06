// The D3.13 MITM service worker: rewrites every widget asset response
// with tampered bytes. The widget's integrity attributes must refuse
// the payloads and the widget must fail closed; this file exists so
// the campaign can prove exactly that refusal in a real chromium.
self.addEventListener('install', (event) => { self.skipWaiting(); });
self.addEventListener('activate', (event) => { event.waitUntil(self.clients.claim()); });
self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (url.pathname.startsWith('/kiwi-captcha/assets/')) {
    event.respondWith(new Response('// tampered by the MITM service worker', {
      status: 200,
      headers: { 'content-type': 'text/javascript; charset=utf-8' },
    }));
  }
});
