// Builds the result card HTML. Every dynamic value goes through S.esc().
(function () {
  var S = (window.Sentinel = window.Sentinel || {});
  var e = S.esc;

  function chip(ok, label) {
    return '<span class="inline-flex items-center px-2.5 py-1 rounded-lg text-xs font-medium ' + (ok ? "chip-ok" : "chip-bad") + '">' + (ok ? "✓" : "✗") + " " + e(label) + "</span>";
  }

  function list(title, items) {
    if (!items || !items.length) return "";
    return '<div class="mt-4 text-sm text-slate-300"><p class="text-white font-medium mb-1">' + e(title) + '</p><ul class="list-disc list-inside">' +
      items.map(function (i) { return "<li>" + e(i) + "</li>"; }).join("") + "</ul></div>";
  }

  function meta(status) {
    var m = {
      vulnerable: ["border-rose-500/40", "text-rose-300", "Vulnerable – Action Required"],
      hidden: ["border-amber-500/40", "text-amber-300", "PHP Detected – Version Hidden"],
      safe: ["border-emerald-500/40", "text-emerald-300", "Looks Safe"],
      error: ["border-rose-500/40", "text-rose-300", "Could not scan"]
    };
    return m[status] || ["border-white/10", "text-white", "No PHP Detected"];
  }

  function headersBlock(sh, tls) {
    return '<div class="mt-4 p-4 rounded-2xl bg-white/5 border border-white/10"><p class="text-white font-medium mb-3">Security headers snapshot</p>' +
      '<div class="flex flex-wrap gap-2">' +
      chip(!!sh.https, "HTTPS") + chip(!!sh.hsts, "HSTS") + chip(!!sh.csp, "CSP") + chip(!!sh.x_frame_options, "X-Frame-Options") +
      chip(!!sh.x_content_type_options, "X-Content-Type-Options") + chip(!!sh.referrer_policy, "Referrer-Policy") + "</div>" +
      '<div class="mt-3 flex flex-wrap gap-2 text-xs">' +
      '<span class="' + (tls.https ? "chip-ok" : "chip-bad") + ' px-2 py-1 rounded-lg">TLS: ' + (tls.https ? "HTTPS URL" : "Not HTTPS") + "</span>" +
      '<span class="' + (tls.redirects_to_https ? "chip-ok" : "chip-mute") + ' px-2 py-1 rounded-lg">HTTP to HTTPS redirect: ' +
      (tls.redirects_to_https === true ? "Yes" : tls.redirects_to_https === false ? "No" : "Unknown") + "</span>" +
      '<span class="' + (tls.mixed_content_hint ? "chip-warn" : "chip-ok") + ' px-2 py-1 rounded-lg">Mixed content hints: ' +
      (tls.mixed_content_hint ? "Possible" : "None spotted") + "</span></div></div>";
  }

  function errorCard(message) {
    return '<div class="glass-strong rounded-3xl p-6 border border-rose-500/40" role="alert">' +
      '<h3 class="text-xl font-semibold text-rose-300 mb-2">Couldn’t run the check</h3>' +
      '<p class="text-slate-200">' + e(message) + "</p></div>";
  }

  /** @returns {{html: string, text: string, badge: string, ok: boolean}} */
  function build(data, secondary) {
    if (data && data.error && !data.status) {
      return { html: errorCard(data.error), text: "", badge: "", ok: false };
    }
    var m = meta(data.status), border = m[0], color = m[1], title = m[2];
    var sh = data.security_headers || {}, tls = data.tls || {};
    var toolUrl = S.cfg().toolUrl;
    var badge = '<!-- Sentinel --><a href="' + toolUrl + '" rel="noopener">Checked with Sentinel</a>';
    var text = title + "\n" + (data.message || "") + "\n" + (data.php_version ? "Version: " + data.php_version : "") +
      "\n\nChecked with Sentinel -> " + toolUrl;

    var metaBits = "";
    if (data.php_version) metaBits += '<span>Version: <code class="text-teal">' + e(data.php_version) + "</code></span>";
    if (data.framework) metaBits += "<span>Framework: " + e(data.framework) + "</span>";
    if (data.support_status) metaBits += "<span>" + e(data.support_status) + "</span>";

    var api = "";
    if (data.status === "no_php" && data.api_suggestion) {
      api = '<div class="mt-4 p-4 rounded-2xl bg-indigo-500/10 border border-indigo-400/20 text-sm text-slate-300">' +
        '<p class="text-white font-medium mb-1">Check your API domain too</p>' +
        '<p class="mb-2">Frontends often hide the PHP backend. Try: <code class="text-teal">' + e(data.api_suggestion) + "</code></p>" +
        '<button type="button" class="text-teal underline text-sm" id="useApiSuggestion">Use this API URL</button></div>';
    }

    var second = "";
    if (secondary) {
      second = '<div class="mt-4 p-4 rounded-2xl glass border border-white/10 text-sm"><p class="text-white font-medium mb-1">API / backend comparison</p>' +
        '<p class="text-slate-300">Status: <strong class="text-white">' + e(secondary.status || "error") + "</strong>" +
        (secondary.php_version ? " · PHP " + e(secondary.php_version) : "") + (secondary.framework ? " · " + e(secondary.framework) : "") + "</p>" +
        '<p class="text-slate-400 mt-1">' + e(secondary.message || secondary.error || "") + "</p></div>";
    }

    var note = function (cls, label, value) {
      return value ? '<div class="mt-' + cls + ' p-4 rounded-2xl text-sm bg-white/5 border border-white/10"><strong class="text-white">' + label + "</strong> " + e(value) + "</div>" : "";
    };

    var html =
      '<div class="glass-strong rounded-3xl p-6 ' + border + '">' +
      '<h3 class="text-xl font-semibold ' + color + ' mb-2">' + e(title) + "</h3>" +
      '<p class="text-slate-200 mb-2">' + e(data.message || data.error || "") + "</p>" +
      (data.details ? '<p class="text-sm text-slate-400 mb-2">' + e(data.details) + "</p>" : "") +
      '<div class="text-sm text-slate-300 flex flex-wrap gap-3">' + metaBits + "</div>" +
      (data.hygiene ? '<div class="mt-3 p-3 rounded-xl text-sm text-amber-200 bg-amber-500/10 border border-amber-500/20">' + e(data.hygiene) + "</div>" : "") +
      note("4", "What to do next:", data.tip) +
      (data.caveat ? '<div class="mt-3 p-4 rounded-2xl text-xs text-slate-400 bg-white/[0.03] border border-white/10"><strong class="text-slate-300">Heads-up:</strong> ' + e(data.caveat) + "</div>" : "") +
      note("3", "Host guidance:", data.host_guidance) +
      (data.status !== "error" ? headersBlock(sh, tls) : "") +
      list("CMS signals", data.cms_signals) + list("What we found", data.tech_signals) +
      (data.playbook && data.playbook.length
        ? '<div class="mt-4 p-4 rounded-2xl bg-amber-500/10 border border-amber-500/20"><p class="text-amber-200 font-medium mb-2">Hidden PHP playbook</p><ul class="list-disc list-inside text-sm text-slate-300 space-y-1">' +
          data.playbook.map(function (i) { return "<li>" + e(i) + "</li>"; }).join("") + "</ul></div>"
        : "") +
      api + second +
      '<div id="fixMount"></div>' +
      '<div class="mt-4 p-4 rounded-2xl bg-white/5 border border-white/10 text-sm"><p class="text-white font-medium mb-2">Embeddable badge</p>' +
      '<code id="badgeCode" class="block text-xs text-slate-400 break-all mb-2"></code>' +
      '<button type="button" id="copyBadgeBtn" class="text-teal text-xs underline">Copy badge HTML</button></div>' +
      '<div class="mt-4 p-4 rounded-2xl bg-white/5 border border-white/10 text-sm"><p class="text-white font-medium mb-2">Email me this report</p>' +
      '<div class="flex flex-col sm:flex-row gap-2"><label class="sr-only" for="emailReport">Your email</label>' +
      '<input id="emailReport" type="email" placeholder="you@company.com" class="flex-1 px-3 py-2 rounded-xl bg-black/40 border border-white/10 text-white text-sm" />' +
      '<button type="button" id="emailReportBtn" class="px-4 py-2 rounded-xl bg-white/10 border border-white/15 text-sm text-white">Send copy</button></div>' +
      '<p class="text-[11px] text-slate-500 mt-2">No account. Opens your email client with the report text.</p></div></div>' +
      '<div class="flex flex-wrap gap-3">' +
      '<button type="button" id="copyResultBtn" class="px-4 py-2.5 glass rounded-xl text-sm">Copy result</button>' +
      '<a id="shareXBtn" href="#" target="_blank" rel="noopener" class="px-4 py-2.5 glass rounded-xl text-sm">Share on X</a>' +
      '<button type="button" id="checkAnotherBtn" class="px-4 py-2.5 bg-white text-ink font-semibold rounded-xl text-sm">Check another site</button></div>';

    return { html: html, text: text, badge: badge, ok: true };
  }

  S.resultView = { build: build, errorCard: errorCard };
})();
