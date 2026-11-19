// Analytics with consent. Google Analytics loads only after the visitor allows it.
// Cloudflare Web Analytics is cookieless and loads when a token is configured.
(function () {
  var S = (window.Sentinel = window.Sentinel || {});
  var cfg = S.cfg();
  var KEY = "sentinel_consent_v1";

  function read() { try { return localStorage.getItem(KEY); } catch (e) { return null; } }
  function write(v) { try { localStorage.setItem(KEY, v); } catch (e) { /* private mode */ } }

  function loadCloudflare() {
    if (!cfg.cfBeaconToken) return;
    var s = document.createElement("script");
    s.defer = true;
    s.src = "https://static.cloudflareinsights.com/beacon.min.js";
    s.setAttribute("data-cf-beacon", JSON.stringify({ token: cfg.cfBeaconToken }));
    document.head.appendChild(s);
  }

  function loadGoogle() {
    if (!cfg.gaId || window.gtag) return;
    window.dataLayer = window.dataLayer || [];
    window.gtag = function () { window.dataLayer.push(arguments); };
    var s = document.createElement("script");
    s.async = true;
    s.src = "https://www.googletagmanager.com/gtag/js?id=" + encodeURIComponent(cfg.gaId);
    document.head.appendChild(s);
    window.gtag("js", new Date());
    window.gtag("config", cfg.gaId);
  }

  function banner() {
    var el = document.createElement("div");
    el.className = "consent-banner";
    el.setAttribute("role", "region");
    el.setAttribute("aria-label", "Analytics consent");
    el.innerHTML =
      '<p class="text-sm text-slate-200 mb-3">Can Sentinel use Google Analytics to see which pages are used? ' +
      'Nothing is sent unless you allow it. <a class="text-teal underline" href="/privacy">Privacy policy</a></p>' +
      '<div class="flex gap-2">' +
      '<button type="button" id="consentAllow" class="px-4 py-2 rounded-xl bg-white text-ink font-bold text-sm">Allow</button>' +
      '<button type="button" id="consentDeny" class="px-4 py-2 rounded-xl border border-white/15 text-sm text-white hover:bg-white/5">No thanks</button>' +
      "</div>";
    document.body.appendChild(el);
    el.querySelector("#consentAllow").addEventListener("click", function () {
      write("granted"); el.remove(); loadGoogle();
    });
    el.querySelector("#consentDeny").addEventListener("click", function () {
      write("denied"); el.remove();
    });
  }

  S.analytics = {
    reopen: function () { try { localStorage.removeItem(KEY); } catch (e) { /* ignore */ } banner(); }
  };

  loadCloudflare();
  var choice = read();
  if (choice === "granted") loadGoogle();
  else if (choice !== "denied") document.addEventListener("DOMContentLoaded", banner);
})();
