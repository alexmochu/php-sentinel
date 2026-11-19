// Shared helpers. Every other script hangs its API off window.Sentinel.
(function () {
  var S = (window.Sentinel = window.Sentinel || {});

  /** Escape text for safe use in HTML text and attribute values. */
  S.esc = function (value) {
    return String(value == null ? "" : value)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  };

  S.$ = function (id) { return document.getElementById(id); };

  S.setText = function (id, value) {
    var el = S.$(id);
    if (el) el.textContent = value || 0;
  };

  S.INPUT_CLASS =
    "w-full rounded-xl bg-white/5 border border-white/10 px-3 py-2.5 text-sm text-white placeholder:text-slate-600 focus:outline-none focus:border-teal/50";

  S.state = { lastResultText: "", lastBadgeHtml: "" };

  S.postJSON = function (url, body) {
    return fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    }).then(function (res) {
      return res.json().catch(function () { return {}; }).then(function (json) {
        return { ok: res.ok, status: res.status, body: json };
      });
    });
  };

  S.track = function (name, params) {
    if (typeof window.gtag === "function") window.gtag("event", name, params || {});
  };

  S.copy = function (text) {
    if (navigator.clipboard && navigator.clipboard.writeText) return navigator.clipboard.writeText(text);
    return new Promise(function (resolve, reject) {
      try {
        var ta = document.createElement("textarea");
        ta.value = text;
        ta.setAttribute("readonly", "");
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
        resolve();
      } catch (e) { reject(e); }
    });
  };

  var toastTimer = null;
  S.toast = function (message) {
    var el = S.$("toast");
    if (!el) {
      el = document.createElement("div");
      el.id = "toast";
      el.className = "toast";
      el.setAttribute("role", "status");
      document.body.appendChild(el);
    }
    el.textContent = message;
    el.style.display = "block";
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { el.style.display = "none"; }, 2200);
  };

  /** Tiny DOM builder: h("p", {class: "x"}, ["text", node]). Text is always inserted as text. */
  S.h = function (tag, attrs, children) {
    var el = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      if (k === "class") el.className = attrs[k];
      else if (k === "text") el.textContent = attrs[k];
      else if (k.indexOf("on") === 0 && typeof attrs[k] === "function") el.addEventListener(k.slice(2), attrs[k]);
      else if (attrs[k] !== false && attrs[k] != null) el.setAttribute(k, attrs[k]);
    });
    (children || []).forEach(function (c) {
      if (c == null || c === false) return;
      el.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
    });
    return el;
  };

  /** Only allow cal.com style https links built from our own config. */
  S.cfg = function () { return window.SENTINEL || {}; };
})();
