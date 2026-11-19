import { JSDOM, VirtualConsole } from "jsdom";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
const ROOT = fileURLToPath(new URL("../public", import.meta.url));
const errors = [];
const results = [];
const ok = (cond, msg) => { results.push([cond ? "PASS" : "FAIL", msg]); };

function bootPage(file, scripts, fetchImpl) {
  let html = fs.readFileSync(path.join(ROOT, file), "utf8");
  html = html.replace(/<script[^>]*src="https?:[^"]*"[^>]*><\/script>/g, "").replace(/<script[^>]*src="\/vendor\/[^"]*"[^>]*><\/script>/g, "").replace(/<script[^>]*src="[^"]*"[^>]*><\/script>/g, "");
  const vc = new VirtualConsole();
  vc.on("jsdomError", (e) => errors.push(`${file}: ${e.message}`));
  vc.on("error", (e) => errors.push(`${file} console.error: ${e}`));
  const dom = new JSDOM(html, { url: "https://sentinel.kejanigarage.com/", runScripts: "outside-only", pretendToBeVisual: true, virtualConsole: vc });
  const w = dom.window;
  w.fetch = fetchImpl;
  w.Chart = function () { return { destroy() {} }; };
  w.scrollTo = () => {};
  for (const s of scripts) {
    try { w.eval(fs.readFileSync(path.join(ROOT, "js", s), "utf8")); } catch (e) { errors.push(`${file}/${s}: ${e.stack || e}`); }
  }
  return dom;
}
const wait = (ms = 20) => new Promise((r) => setTimeout(r, ms));
const calls = [];
const evil = '<img src=x onerror="window.__pwned=1">';
const fetchMock = async (url, opts = {}) => {
  const body = opts.body ? JSON.parse(opts.body) : null;
  calls.push([url, body]);
  const j = (data, status = 200) => ({ ok: status < 400, status, json: async () => data });
  if (url === "/api/stats") return j({ updated_at: "2026-11-18T10:00:00Z", totals: { scans: 250, unique_sites: 120, unique_users: 80, last_24h: 5, last_7d: 40, last_30d: 210, first_scan_at: "2026-10-18 09:00:00" },
    status: { vulnerable: 10, hidden: 50, safe: 20, no_php: 150, error: 0 }, frameworks: [{ name: evil, c: 3 }], countries: [{ name: "KE", c: 9 }], daily: [{ d: "2026-11-17", c: 4 }], top_tech_signals: [{ name: "Nginx", c: 7 }],
    risk: { vulnerable_pct: 4 }, derived: { repeat_check_rate: 52, hidden_rate_among_php: 62 }, waitlist: 3 });
  if (url === "/api/advisory") return j({ fixed_versions: { "8.3": "8.3.36" }, ids: [] });
  if (url === "/api/scan") {
    if (body.url === "bad") return j({ error: "Local or private addresses are not allowed." }, 400);
    return j({ status: "vulnerable", php_version: "8.3.20", php_branch: "8.3", support_status: evil, framework: "WordPress", tech_signals: [evil, "Nginx"], cms_signals: ["Generator: " + evil],
      security_headers: { https: true, hsts: false, csp: false, x_frame_options: false, x_content_type_options: true, referrer_policy: false }, tls: { https: true, redirects_to_https: false, mixed_content_hint: false },
      x_powered_by_exposed: true, message: evil, details: evil, tip: evil, caveat: evil, hygiene: evil, host_guidance: evil, playbook: [evil], url: "https://victim.example.com" });
  }
  if (url === "/api/remediate") return j({ stack: body.stack, plan: { source: "rules", summary: "Do these.", steps: [{ id: "a", title: evil, priority: "high", why: evil, how: ["step <b>1</b>"], snippet: { label: "nginx", language: "nginx", code: "add_header X \"y\";" } }], verify: ["v"], notes: ["n"] } });
  if (url === "/api/waitlist" || url === "/api/message" || url === "/api/report") return j({ ok: true });
  return j({}, 404);
};

// ---- index page
const idx = bootPage("index.html", ["config.js","util.js","analytics.js","layout.js","contact.js","charts.js","stats.js","results-view.js","remediation.js","waitlist.js","results-cta.js","checker.js","main.js"], fetchMock);
const d = idx.window.document;
await wait(80);
ok(!!d.getElementById("talkBtn") && !!d.querySelector("footer"), "layout renders header and footer");
ok(d.querySelector('a[href="/terms"]') && d.querySelector('a[href="/privacy"]') && d.querySelector('a[href="/abuse"]'), "footer links to terms, privacy, abuse");
ok(d.getElementById("mTotal").textContent === "250" && d.getElementById("m7").textContent === "40", "stats render (total 250, last 7d 40)");
ok(!d.getElementById("waitlistCount").classList.contains("hidden"), "waitlist count shows when > 0");
ok(d.getElementById("advisoryVersions").textContent.includes("8.3.36"), "advisory text loaded from API");
ok(!d.querySelector("#topFrameworks img"), "stats ranked list escapes hostile framework name");
d.getElementById("urlInput").value = "victim.example.com";
d.getElementById("checkBtn").click();
await wait(150);
const res = d.getElementById("result");
ok(!res.classList.contains("hidden") && res.textContent.includes("Vulnerable"), "result renders");
ok(!idx.window.__pwned && !res.querySelector("img"), "XSS payloads from API are escaped (no <img>, no execution)");
ok(res.querySelector("#fixMount #fixBtn"), "AI fix plan panel mounted");
d.getElementById("fixBtn").click();
await wait(100);
ok(d.querySelector("#fixOut .fix-step") && d.querySelector("#fixOut pre code").textContent.includes("add_header"), "fix plan renders with code snippet");
ok(!d.querySelector("#fixOut img") && !idx.window.__pwned, "fix plan text is inserted safely");
const remCall = calls.find((c) => c[0] === "/api/remediate");
ok(remCall && !("cms_signals" in remCall[1].findings) && !("message" in remCall[1].findings), "remediate request sends findings only (no site text)");
ok(!d.getElementById("ctaSection").classList.contains("hidden") && d.getElementById("waitlistMini"), "CTA and compact waitlist shown");
d.querySelector("#waitlistMini [name=email]").value = "a@b.co";
d.querySelector("#waitlistMini [name=consent]").checked = true;
d.getElementById("waitlistMini").dispatchEvent(new idx.window.Event("submit", { cancelable: true }));
await wait(60);
const wl = calls.filter((c) => c[0] === "/api/waitlist");
ok(wl.length === 1 && wl[0][1].consent === true && wl[0][1].source === "result_card", "compact waitlist posts with consent");
// full waitlist form without consent is blocked
const full = d.getElementById("waitlistForm");
full.querySelector("[name=email]").value = "c@d.co";
full.dispatchEvent(new idx.window.Event("submit", { cancelable: true }));
await wait(30);
ok(calls.filter((c) => c[0] === "/api/waitlist").length === 1 && full.querySelector("[data-status]").textContent.includes("Tick"), "full waitlist requires consent");
full.querySelector("[name=consent]").checked = true;
full.dispatchEvent(new idx.window.Event("submit", { cancelable: true }));
await wait(60);
ok(calls.filter((c) => c[0] === "/api/waitlist").length === 2 && !d.getElementById("waitlistDone").classList.contains("hidden"), "full waitlist posts and shows thanks");
// message modal
d.getElementById("navOpenMsg").click();
ok(d.getElementById("msgModal").classList.contains("open"), "message modal opens from nav");
d.getElementById("gMsgEmail").value = "x@y.co"; d.getElementById("gMsgBody").value = "hello there";
d.getElementById("globalMsgForm").dispatchEvent(new idx.window.Event("submit", { cancelable: true }));
await wait(60);
ok(calls.some((c) => c[0] === "/api/message" && c[1].source === "checker_modal"), "message modal posts with page source");
// error response shows a real error card, not "No PHP Detected"
d.getElementById("checkAnotherBtn").click();
d.getElementById("urlInput").value = "bad";
d.getElementById("checkBtn").click();
await wait(120);
ok(d.getElementById("result").textContent.includes("Couldn’t run the check") && !d.getElementById("result").textContent.includes("No PHP Detected"), "API error shows an error card");

// ---- other pages load without script errors
for (const [file, scripts] of [["threats.html", ["config.js","util.js","analytics.js","layout.js","contact.js"]], ["terms.html", ["config.js","util.js","analytics.js","layout.js","contact.js"]], ["privacy.html", ["config.js","util.js","analytics.js","layout.js","contact.js"]], ["abuse.html", ["config.js","util.js","analytics.js","layout.js","contact.js","abuse.js"]]]) {
  const p = bootPage(file, scripts, fetchMock);
  await wait(30);
  ok(!!p.window.document.getElementById("talkBtn") && !!p.window.document.querySelector("footer"), `${file}: shared layout renders`);
  if (file === "abuse.html") {
    const dd = p.window.document;
    dd.getElementById("reportEmail").value = "o@w.co"; dd.getElementById("reportDomain").value = "example.com"; dd.getElementById("reportDetails").value = "please do not scan";
    dd.getElementById("reportForm").dispatchEvent(new p.window.Event("submit", { cancelable: true }));
    await wait(60);
    ok(calls.some((c) => c[0] === "/api/report" && c[1].kind === "opt_out"), "abuse form posts a report");
  }
}
// threats.js needs its own markup; run it against threats.html
const t = bootPage("threats.html", ["config.js","util.js","analytics.js","layout.js","contact.js"], (u, o) => fetchMock(u, o));
t.window.fetch = async (u) => ({ ok: true, json: async () => JSON.parse(fs.readFileSync(path.join(ROOT, "data/threats-2026.json"), "utf8")) });
try { t.window.eval(fs.readFileSync(path.join(ROOT, "js/threats.js"), "utf8")); } catch (e) { errors.push("threats.js: " + e.stack); }
await wait(200);
const rendered = t.window.document.querySelectorAll("#timeline > *, #timeline article, #timeline li").length;
ok(rendered > 0, `threats page renders events (${rendered} nodes)`);

for (const [s, m] of results) console.log(s, m);
console.log("SCRIPT ERRORS:", errors.length ? errors : "none");
process.exit(results.some((r) => r[0] === "FAIL") || errors.length ? 1 : 0);
