// GET /api/stats -> public platform numbers. Owner traffic can be excluded with EXCLUDE_IPS.

import { json, hashIp } from "../_lib/http.js";

async function excludedHashes(env) {
  const raw = String(env.EXCLUDE_IPS || "").split(",").map((s) => s.trim()).filter(Boolean);
  return Promise.all(raw.map((ip) => hashIp(ip, env)));
}

export async function onRequestGet(context) {
  const { env } = context;
  try {
    const hashes = await excludedHashes(env);
    const where = hashes.length ? `WHERE (ip IS NULL OR ip NOT IN (${hashes.map(() => "?").join(",")}))` : "";
    const and = where ? where.replace("WHERE", "AND") : "";
    const q = (sql, extra = []) => env.DB.prepare(sql).bind(...hashes, ...extra);

    const [total, sites, users, last24, last7, last30, first, byStatus, byFramework, byCountry, daily, signals] =
      await env.DB.batch([
        q(`SELECT COUNT(*) AS c FROM scans ${where}`),
        q(`SELECT COUNT(DISTINCT normalized_url) AS c FROM scans ${where}`),
        q(`SELECT COUNT(DISTINCT ip) AS c FROM scans ${where}`),
        q(`SELECT COUNT(*) AS c FROM scans WHERE created_at > datetime('now','-1 day') ${and}`),
        q(`SELECT COUNT(*) AS c FROM scans WHERE created_at > datetime('now','-7 day') ${and}`),
        q(`SELECT COUNT(*) AS c FROM scans WHERE created_at > datetime('now','-30 day') ${and}`),
        q(`SELECT MIN(created_at) AS t FROM scans ${where}`),
        q(`SELECT status, COUNT(*) AS c FROM scans ${where} GROUP BY status`),
        q(`SELECT COALESCE(NULLIF(framework,''),'Unknown / none') AS name, COUNT(*) AS c FROM scans ${where} GROUP BY 1 ORDER BY c DESC LIMIT 8`),
        q(`SELECT COALESCE(NULLIF(country,''),'Unknown') AS name, COUNT(*) AS c FROM scans ${where} GROUP BY 1 ORDER BY c DESC LIMIT 10`),
        q(`SELECT date(created_at) AS d, COUNT(*) AS c FROM scans WHERE created_at >= datetime('now','-30 day') ${and} GROUP BY d ORDER BY d`),
        q(`SELECT tech_signals FROM scans WHERE tech_signals IS NOT NULL AND tech_signals NOT IN ('', '[]') ${and} ORDER BY id DESC LIMIT 300`),
      ]);
    let waitlistCount = 0;
    try {
      const w = await env.DB.prepare("SELECT COUNT(*) AS c FROM waitlist").first();
      waitlistCount = (w && w.c) || 0;
    } catch { /* table appears after migration 0003 */ }

    const one = (r, k = "c") => (r.results && r.results[0] && r.results[0][k]) || 0;
    const statusMap = Object.fromEntries((byStatus.results || []).map((r) => [r.status, r.c]));
    const scans = one(total);
    const uniqueSites = one(sites);
    const phpRelated = (statusMap.vulnerable || 0) + (statusMap.hidden || 0) + (statusMap.safe || 0);

    const counts = {};
    for (const row of signals.results || []) {
      try {
        const arr = JSON.parse(row.tech_signals || "[]");
        if (Array.isArray(arr)) for (const s of arr) if (s) counts[s] = (counts[s] || 0) + 1;
      } catch { /* skip malformed row */ }
    }

    return json(
      {
        updated_at: new Date().toISOString(),
        totals: {
          scans,
          unique_sites: uniqueSites,
          unique_users: one(users),
          last_24h: one(last24),
          last_7d: one(last7),
          last_30d: one(last30),
          first_scan_at: first.results && first.results[0] ? first.results[0].t : null,
        },
        status: {
          vulnerable: statusMap.vulnerable || 0,
          hidden: statusMap.hidden || 0,
          safe: statusMap.safe || 0,
          no_php: statusMap.no_php || 0,
          error: statusMap.error || 0,
        },
        frameworks: byFramework.results || [],
        countries: byCountry.results || [],
        daily: daily.results || [],
        php_vs_other: { php_related: phpRelated, no_php: statusMap.no_php || 0, errors: statusMap.error || 0 },
        risk: {
          vulnerable: statusMap.vulnerable || 0,
          total: scans,
          vulnerable_pct: scans > 0 ? Math.round((100 * (statusMap.vulnerable || 0)) / scans) : 0,
        },
        derived: {
          repeat_check_rate: scans > 0 ? Math.round((1 - uniqueSites / scans) * 100) : 0,
          hidden_rate_among_php: phpRelated > 0 ? Math.round((100 * (statusMap.hidden || 0)) / phpRelated) : 0,
        },
        top_tech_signals: Object.entries(counts).map(([name, c]) => ({ name, c })).sort((a, b) => b.c - a.c).slice(0, 8),
        waitlist: waitlistCount,
      },
      200,
      { "Cache-Control": "public, max-age=60" }
    );
  } catch (err) {
    console.error(err);
    return json({ error: "stats_unavailable" }, 500);
  }
}
