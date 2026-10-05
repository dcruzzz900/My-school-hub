/* ONLINE-ONLY build: this service worker caches nothing and intercepts nothing.
   Devices that installed an earlier offline-capable worker receive this file on
   their next visit; it deletes every cache the old worker created, unregisters
   itself, and reloads open tabs so they talk to the server directly. */
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => {
  event.waitUntil((async () => {
    try { const keys = await caches.keys(); await Promise.all(keys.map((k) => caches.delete(k))); } catch (e) {}
    try { await self.registration.unregister(); } catch (e) {}
    try {
      const clients = await self.clients.matchAll({ type: "window" });
      clients.forEach((c) => { try { c.navigate(c.url); } catch (e) {} });
    } catch (e) {}
  })());
});
