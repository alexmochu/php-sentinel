// Loads /api/stats and fills the "Live platform pulse" section and the ticker.
(function () {
  var S = (window.Sentinel = window.Sentinel || {});
  var KEY = "sentinel_stats_v2";
  var TTL = 0 * 60 * 1000;

  /** Get stats. force=true skips both the local cache and the browser HTTP cache. */
  function load(force) {
    if (!force) {
      try {
        var cached = localStorage.getItem(KEY);
        if (cached) {
          var parsed = JSON.parse(cached);
          if (Date.now() - parsed.fetched_at < TTL) return Promise.resolve(parsed.data);
        }
      } catch (e) { /* ignore */ }
    }
    return fetch("/api/stats", force ? { cache: "no-store" } : undefined).then(function (res) {
      if (!res.ok) throw new Error("stats failed");
      return res.json();
    }).then(function (data) {
      // An empty result is never cached, so the first scan shows up straight away.
      var empty = !data.totals || !data.totals.scans;
      try {
        if (empty) localStorage.removeItem(KEY);
        else localStorage.setItem(KEY, JSON.stringify({ fetched_at: Date.now(), data: data }));
      } catch (e) { /* ignore */ }
      return data;
    });
  }

  function flag(code) {
    if (!code || code === "Unknown" || String(code).length !== 2) return "🌐";
    var cc = String(code).trim().toLowerCase().replace(/[^a-z]/g, "");
    return '<img src="https://flagcdn.com/w40/' + cc + '.png" width="20" height="15" class="inline-block rounded-sm mr-1.5 align-middle" alt="" loading="lazy" referrerpolicy="no-referrer" />';
  }

  function ranked(id, rows, color, withFlags) {
    var el = S.$(id);
    if (!el) return;
    if (!rows || !rows.length) { el.innerHTML = '<p class="text-slate-500">No data yet</p>'; return; }
    var max = Math.max.apply(null, rows.map(function (r) { return r.c; }).concat([1]));
    el.innerHTML = rows.map(function (r) {
      var pct = Math.max(6, Math.round((100 * r.c) / max));
      var label = withFlags
        ? (!r.name || r.name === "Unknown" ? "Unknown" : String(r.name).toUpperCase())
        : String(r.name);
      var prefix = withFlags ? flag(r.name) + " " : "";
      return "<div>" +
        '<div class="flex justify-between mb-1 text-slate-200"><span>' + prefix + S.esc(label) + '</span><span class="font-semibold text-white">' + S.esc(r.c) + "</span></div>" +
        '<div class="bar"><span data-w="' + pct + '" style="background:' + S.esc(color) + '"></span></div></div>';
    }).join("");
    requestAnimationFrame(function () {
      el.querySelectorAll(".bar > span").forEach(function (s) { s.style.width = s.getAttribute("data-w") + "%"; });
    });
  }

  function render(data) {
    var t = data.totals || {}, s = data.status || {}, risk = data.risk || {}, derived = data.derived || {};
    S.setText("mTotal", t.scans);
    S.setText("mSites", t.unique_sites);
    S.setText("mUsers", t.unique_users);
    S.setText("m24", t.last_24h);
    S.setText("m7", t.last_7d);
    S.setText("m30", t.last_30d);
    S.setText("mVuln", s.vulnerable);
    S.setText("mHidden", s.hidden);
    S.setText("mSafe", s.safe);
    S.setText("mNoPhp", s.no_php);
    S.setText("mVulnPct", risk.vulnerable_pct);
    S.setText("mRepeat", derived.repeat_check_rate);
    S.setText("mHiddenRate", derived.hidden_rate_among_php);

    var updated = S.$("statsUpdated");
    if (updated) updated.textContent = data.updated_at ? "Updated " + new Date(data.updated_at).toLocaleString() : "—";
    var since = S.$("statsSince");
    if (since && t.first_scan_at) since.textContent = "Since " + new Date(t.first_scan_at.replace(" ", "T") + "Z").toLocaleDateString();

    var wl = S.$("waitlistCount");
    if (wl && data.waitlist > 0) {
      wl.textContent = data.waitlist + (data.waitlist === 1 ? " person is" : " people are") + " on the Pro waitlist.";
      wl.classList.remove("hidden");
    }

    if (S.charts) S.charts.render(data);
    ranked("topCountries", data.countries || [], "#2dd4bf", true);
    ranked("topFrameworks", data.frameworks || [], "#818cf8", false);
    ranked("topSignals", data.top_tech_signals || [], "#38bdf8", false);

    var ticker = S.$("tickerText");
    if (ticker) {
      ticker.textContent = (t.scans || 0) === 0
        ? "No checks yet. Be the first to run one. · "
        : "Total " + (t.scans || 0) + " · Unique sites " + (t.unique_sites || 0) + " · Vulnerable " + (s.vulnerable || 0) +
        " · Hidden " + (s.hidden || 0) + " · Safe " + (s.safe || 0) + " · No PHP " + (s.no_php || 0) + " · ";
    }
  }

  function loadAdvisory() {
    var el = S.$("advisoryVersions");
    if (!el) return Promise.resolve();
    return fetch("/api/advisory").then(function (r) { return r.json(); }).then(function (a) {
      var list = Object.keys(a.fixed_versions || {}).map(function (k) { return a.fixed_versions[k]; });
      if (list.length) el.textContent = "Patched PHP: " + list.join(", ") + ".";
    }).catch(function () { /* keep the fallback text */ });
  }

  S.stats = {
    init: function () {
      load().then(render).catch(function () {
        var t = S.$("tickerText");
        if (t) t.textContent = "Live stats are unavailable right now.";
      });
      loadAdvisory();
    },
    /** Call after a scan: drops the cache and reloads the numbers. */
    refresh: function () {
      try { localStorage.removeItem(KEY); } catch (e) { /* ignore */ }
      return load(true).then(render).catch(function () { /* keep what is on screen */ });
    },
    render: render
  };
})();