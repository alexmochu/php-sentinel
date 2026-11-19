// POST /api/scan  { url }  -> passive public-signal check.

import { json, readJson, getIp, hashIp } from "../_lib/http.js";
import { parseTargetUrl, hostCandidates } from "../_lib/validate.js";
import { hit } from "../_lib/ratelimit.js";
import { fetchGuarded, probeHttpRedirect, analyzeSecurity, GuardError } from "../_lib/scanner.js";
import { extractPhpVersion, detectFrameworks, detectIsPhp, detectTechSignals } from "../_lib/detect.js";
import { buildVerdict } from "../_lib/verdict.js";

async function isOptedOut(env, hostname) {
  if (!env.DB) return false;
  try {
    const candidates = hostCandidates(hostname);
    const marks = candidates.map(() => "?").join(",");
    const row = await env.DB.prepare(`SELECT domain FROM opt_outs WHERE domain IN (${marks}) LIMIT 1`).bind(...candidates).first();
    return !!row;
  } catch (err) {
    console.error("opt-out lookup failed", err);
    return false;
  }
}

export async function onRequestPost(context) {
  const { request, env } = context;
  const ipHash = await hashIp(getIp(request), env);

  const rl = await hit(env, `scan:${ipHash}`, 8, 60);
  if (!rl.allowed) return json({ error: "Too many requests. Please wait a minute and try again." }, 429);

  const parsed = await readJson(request, 4096);
  if (!parsed.ok) return json({ error: parsed.error }, parsed.status);

  const target = parseTargetUrl(parsed.body.url);
  if (!target.ok) return json({ error: target.error }, 400);
  const url = target.url;

  if (await isOptedOut(env, url.hostname)) {
    return json({ error: "The owner of this site has asked Sentinel not to check it.", code: "opted_out" }, 403);
  }

  const normalized = url.origin + (url.pathname === "/" ? "" : url.pathname);
  const isHttps = url.protocol === "https:";

  const redirectsToHttps = isHttps ? await probeHttpRedirect(url.host, url.pathname) : null;

  let page;
  try {
    page = await fetchGuarded(normalized);
  } catch (err) {
    const blocked = err instanceof GuardError;
    return json({
      status: "error",
      message: blocked ? err.message : "Could not reach the website. It may be down or blocking requests.",
      tip: "Check the URL and try again.",
      url: normalized,
      tech_signals: [],
      security_headers: null,
      tls: { https: isHttps, redirects_to_https: redirectsToHttps },
    });
  }

  const { headers, cookies, text: bodyText } = page;
  const bodyLower = bodyText.toLowerCase();
  const xPoweredByExposed = (headers["x-powered-by"] || "").toLowerCase().includes("php") ? 1 : 0;

  const phpVersion = extractPhpVersion(headers);
  const { frameworks, cms_signals } = detectFrameworks(bodyText, bodyLower, headers, cookies);
  const framework = frameworks[0] || null;
  const isPhp = detectIsPhp({ phpVersion, headers, frameworks, cookies, bodyLower });
  const uniqueSignals = detectTechSignals({ framework, isPhp, bodyLower, headers });
  const { security_headers, mixed_content_hint } = analyzeSecurity(headers, isHttps, bodyLower);
  const verdict = buildVerdict({ phpVersion, isPhp, framework, uniqueSignals });

  const hygiene = xPoweredByExposed
    ? "Security hygiene: The X-Powered-By header is exposed. Consider turning expose_php off in php.ini."
    : null;
  const api_suggestion = verdict.status === "no_php" ? `https://api.${url.hostname.replace(/^www\./, "")}` : null;

  if (env.DB) {
    try {
      // Data minimisation: store the URL without query string and a salted hash instead of the IP.
      await env.DB.prepare(
        `INSERT INTO scans (url, normalized_url, status, php_version, php_branch, support_status,
           framework, x_powered_by, tech_signals, details, user_agent, ip, country)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
        .bind(
          normalized, normalized, verdict.status, phpVersion, verdict.php_branch, verdict.support_status,
          framework, xPoweredByExposed, JSON.stringify(uniqueSignals), verdict.details,
          (request.headers.get("User-Agent") || "").slice(0, 200), ipHash, request.headers.get("CF-IPCountry") || null
        )
        .run();
    } catch (err) {
      console.error("D1 save error", err);
    }
  }

  return json({
    status: verdict.status,
    php_version: phpVersion,
    php_branch: verdict.php_branch,
    support_status: verdict.support_status,
    framework,
    tech_signals: uniqueSignals,
    cms_signals,
    security_headers,
    tls: { https: isHttps, redirects_to_https: redirectsToHttps, mixed_content_hint },
    x_powered_by_exposed: !!xPoweredByExposed,
    message: verdict.message,
    details: verdict.details,
    tip: verdict.tip,
    caveat: verdict.caveat,
    hygiene,
    playbook: verdict.playbook,
    host_guidance: verdict.host_guidance,
    api_suggestion,
    url: normalized,
    checked_at: new Date().toISOString(),
  });
}
