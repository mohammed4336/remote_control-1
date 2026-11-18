const CACHE = "remote-control-v4";

self.addEventListener("install", (event) => {
  event.waitUntil(self.skipWaiting());
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((key) => key !== CACHE).map((key) => caches.delete(key)))
    ).then(() => self.clients.claim())
  );
});

// Keep the last successfully loaded UI available on the phone.
// The WebSocket is deliberately excluded: authentication and control always use live data.
self.addEventListener("fetch", (event) => {
  const request = event.request;
  const url = new URL(request.url);

  if (request.method !== "GET" || url.origin !== self.location.origin) return;
  if (
    url.pathname.startsWith("/download") ||
    url.pathname.startsWith("/seller") ||
    url.pathname.startsWith("/admin") ||
    url.pathname === "/ws" ||
    url.pathname === "/health"
  ) return;

  const cachePromise = caches.open(CACHE);
  const networkPromise = cachePromise.then((cache) =>
    fetch(request).then((response) => {
      if (response && response.ok) {
        cache.put(request, response.clone()).catch(() => {});
      }
      return response;
    })
  );

  // Refresh the cached copy in the background without delaying the page.
  event.waitUntil(networkPromise.then(() => undefined).catch(() => undefined));

  event.respondWith(
    cachePromise.then(async (cache) => {
      const cached = await cache.match(request);
      if (cached) return cached;
      return networkPromise;
    })
  );
});
