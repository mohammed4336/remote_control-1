const CACHE = "remote-control-v3";

self.addEventListener("install", () => {
  self.skipWaiting();
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

// كاش ديناميكي: يخزن أي صفحة/ملف يفتح بنجاح، ويرجع له لو النت انقطع
// اتصال WebSocket ما يمر من هنا أبدًا (مو GET عادي)
// الشبكة أول، لكن بمهلة 4 ثواني: لو السيرفر نايم/بطيء نفتح النسخة المخزّنة فورًا بدل ما تعلق الصفحة
function fetchTimeout(req, ms) {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error("timeout")), ms);
    fetch(req).then((r) => { clearTimeout(t); resolve(r); }, (e) => { clearTimeout(t); reject(e); });
  });
}

self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  if (e.request.method !== "GET" || url.origin !== location.origin) return;
  if (url.pathname.startsWith("/download") || url.pathname.startsWith("/seller") ||
      url.pathname.startsWith("/admin") || url.pathname === "/ws") return;

  e.respondWith(
    caches.open(CACHE).then(async (cache) => {
      try {
        const fresh = await fetchTimeout(e.request, 4000);
        if (fresh && fresh.ok) cache.put(e.request, fresh.clone());
        return fresh;
      } catch (err) {
        const cached = await cache.match(e.request);
        if (cached) return cached;
        return fetch(e.request);   // ما في نسخة مخزّنة: ننتظر السيرفر
      }
    })
  );
});
