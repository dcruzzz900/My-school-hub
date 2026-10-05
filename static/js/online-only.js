/* Online-only support script.
   1. Removes anything left behind by the retired offline mode (service workers, caches,
      IndexedDB stores, queued-form storage) so no stale local data is ever used.
   2. Shows a clear connection error when the server cannot be reached, and blocks
      form submission instead of silently queueing it. There is no offline fallback. */
(function () {
  "use strict";
  function purgeLegacy() {
    try {
      if ("serviceWorker" in navigator) {
        navigator.serviceWorker.getRegistrations().then(function (regs) { regs.forEach(function (r) { r.unregister(); }); });
      }
      if (window.caches && caches.keys) { caches.keys().then(function (ks) { ks.forEach(function (k) { caches.delete(k); }); }); }
      if (window.indexedDB && indexedDB.databases) {
        indexedDB.databases().then(function (dbs) { (dbs || []).forEach(function (d) { if (d && d.name) { try { indexedDB.deleteDatabase(d.name); } catch (e) {} } }); }).catch(function () {});
      }
      var legacy = /offline|pending|queue|srs[-_]|device[-_]?(id|secret)|sync/i;
      Object.keys(localStorage).forEach(function (k) { if (legacy.test(k)) { localStorage.removeItem(k); } });
    } catch (e) { /* storage may be unavailable; nothing to purge */ }
  }
  purgeLegacy();

  var bannerId = "connectionErrorBanner";
  function showBanner(msg) {
    var b = document.getElementById(bannerId);
    if (!b) {
      b = document.createElement("div");
      b.id = bannerId; b.setAttribute("role", "alert");
      b.style.cssText = "position:fixed;top:0;left:0;right:0;z-index:99999;background:#b3261e;color:#fff;padding:.7rem 1rem;text-align:center;font-weight:600;box-shadow:0 2px 8px rgba(0,0,0,.3)";
      document.body.appendChild(b);
    }
    b.textContent = msg;
  }
  function hideBanner() { var b = document.getElementById(bannerId); if (b) { b.remove(); } }
  var MSG = "Cannot reach the server. Check your internet connection. Nothing is saved until the connection returns.";
  window.addEventListener("offline", function () { showBanner(MSG); });
  window.addEventListener("online", hideBanner);
  if (navigator.onLine === false) { document.addEventListener("DOMContentLoaded", function () { showBanner(MSG); }); }

  document.addEventListener("submit", function (ev) {
    if (navigator.onLine === false) {
      ev.preventDefault(); ev.stopImmediatePropagation();
      showBanner(MSG);
    }
  }, true);
})();
