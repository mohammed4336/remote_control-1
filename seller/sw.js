const CACHE = "remote-control-v3";

self.addEventListener("install", (e) => {
  e.waitUntil(self.skipWaiting());
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys.filter((key) => key !== CACHE).map((key) => caches.delete(key))
      )
    ).then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);

  if (
    e.request.method !== "GET" ||
    url.origin !== self.location.origin ||
    url.pathname.startsWith("/seller")
  ) {
    return;
  }

  e.respondWith(
    caches.open(CACHE).then(async (cache) => {
      try {
        const response = await fetch(e.request);

        if (response && response.ok) {
          await cache.put(e.request, response.clone());
        }

        return response;
      } catch (error) {
        const cached = await cache.match(e.request);
        if (cached) return cached;
        throw error;
      }
    })
  );
});
