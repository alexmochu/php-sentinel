// Admin dashboard. The key lives in memory only and is sent in a header, never in the URL.
(function () {
  var key = "";
  var $ = function (id) { return document.getElementById(id); };
  function esc(v) {
    return String(v == null ? "" : v).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }
  function api(path) {
    return fetch(path, { headers: { "X-Admin-Key": key } }).then(function (res) {
      if (res.status === 401) throw new Error("Wrong admin key.");
      if (res.status === 429) throw new Error("Too many attempts. Wait ten minutes.");
      if (res.status === 503) throw new Error("ADMIN_SECRET is not configured on the server.");
      if (!res.ok) throw new Error("Request failed (" + res.status + ").");
      return res.json();
    });
  }
  function rows(id, items, cols, empty) {
    var tb = $(id);
    if (!items.length) { tb.innerHTML = '<tr><td class="py-3 text-slate-500" colspan="' + cols.length + '">' + empty + "</td></tr>"; return; }
    tb.innerHTML = items.map(function (r) {
      return '<tr class="border-t border-white/5 align-top">' + cols.map(function (c) {
        return '<td class="py-2 pr-3 text-slate-300 max-w-[22rem] break-words">' + esc(typeof c === "function" ? c(r) : r[c]) + "</td>";
      }).join("") + "</tr>";
    }).join("");
  }
  $("loginForm").addEventListener("submit", function (ev) {
    ev.preventDefault();
    key = $("adminKey").value;
    $("adminKey").value = "";
    $("adminStatus").textContent = "Loading…";
    Promise.all([api("/api/admin/scans"), api("/api/admin/inbox")]).then(function (out) {
      var scans = out[0], inbox = out[1];
      $("adminCounts").innerHTML = (scans.counts || []).map(function (c) {
        return '<div class="glass rounded-2xl p-4"><p class="text-xs text-slate-400">' + esc(c.status) + '</p><p class="text-2xl font-black text-white">' + esc(c.c) + "</p></div>";
      }).join("");
      rows("scanRows", scans.scans || [], ["created_at", "normalized_url", "status", "php_version", "framework", "country"], "No checks yet.");
      rows("waitRows", inbox.waitlist || [], ["created_at", "email", "role", "interests", "site_url"], "No signups yet.");
      rows("msgRows", inbox.messages || [], ["created_at", "email", function (r) { return r.wants_call ? "yes" : ""; }, "source", "message"], "No messages yet.");
      rows("reportRows", inbox.reports || [], ["created_at", "kind", "domain", "email", "details"], "No reports yet.");
      $("adminBody").classList.remove("hidden");
      $("adminStatus").textContent = "Loaded " + new Date().toLocaleTimeString();
    }).catch(function (err) {
      $("adminBody").classList.add("hidden");
      $("adminStatus").textContent = err.message;
    });
  });
})();
