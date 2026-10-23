export async function onRequestGet(context) {
  const { env } = context;

  try {
    const totalRow = await env.DB.prepare(
      `SELECT COUNT(*) as total FROM scans`
    ).first();

    const uniqueSites = await env.DB.prepare(
      `SELECT COUNT(DISTINCT normalized_url) as c FROM scans`
    ).first();

    const uniqueUsers = await env.DB.prepare(
      `SELECT COUNT(DISTINCT ip) as c FROM scans`
    ).first();

    const last24h = await env.DB.prepare(
      `SELECT COUNT(*) as c FROM scans WHERE created_at > datetime('now', '-1 day')`
    ).first();

    const byStatus = await env.DB.prepare(
      `SELECT status, COUNT(*) as c FROM scans GROUP BY status`
    ).all();

    const byFramework = await env.DB.prepare(
      `SELECT COALESCE(NULLIF(framework, ''), 'Unknown / none') as name, COUNT(*) as c
       FROM scans
       GROUP BY COALESCE(NULLIF(framework, ''), 'Unknown / none')
       ORDER BY c DESC
       LIMIT 8`
    ).all();

    const byCountry = await env.DB.prepare(
      `SELECT COALESCE(NULLIF(country, ''), 'Unknown') as name, COUNT(*) as c
       FROM scans
       GROUP BY COALESCE(NULLIF(country, ''), 'Unknown')
       ORDER BY c DESC
       LIMIT 10`
    ).all();

    const phpVsOther = await env.DB.prepare(
      `SELECT
         SUM(CASE WHEN status IN ('vulnerable', 'hidden', 'safe') THEN 1 ELSE 0 END) as php_related,
         SUM(CASE WHEN status = 'no_php' THEN 1 ELSE 0 END) as no_php,
         SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END) as errors
       FROM scans`
    ).first();

    const vulnerableShare = await env.DB.prepare(
      `SELECT
         SUM(CASE WHEN status = 'vulnerable' THEN 1 ELSE 0 END) as vulnerable,
         COUNT(*) as total
       FROM scans`
    ).first();

    const hiddenRow = await env.DB.prepare(
      `SELECT COUNT(*) as c FROM scans WHERE status = 'hidden'`
    ).first();

    // Top tech signals from recent rows that stored JSON
    const topSignalsRows = await env.DB.prepare(
      `SELECT tech_signals FROM scans
       WHERE tech_signals IS NOT NULL
         AND tech_signals != ''
         AND tech_signals != '[]'
       ORDER BY id DESC
       LIMIT 300`
    ).all();

    const signalCounts = {};
    for (const row of topSignalsRows.results || []) {
      try {
        const arr = JSON.parse(row.tech_signals || "[]");
        if (Array.isArray(arr)) {
          for (const s of arr) {
            if (!s) continue;
            signalCounts[s] = (signalCounts[s] || 0) + 1;
          }
        }
      } catch (_) {}
    }

    const top_tech_signals = Object.entries(signalCounts)
      .map(([name, c]) => ({ name, c }))
      .sort((a, b) => b.c - a.c)
      .slice(0, 8);

    const totals = {
      scans: totalRow?.total || 0,
      unique_sites: uniqueSites?.c || 0,
      unique_users: uniqueUsers?.c || 0,
      last_24h: last24h?.c || 0,
    };

    const statusMap = Object.fromEntries(
      (byStatus.results || []).map((r) => [r.status, r.c])
    );

    const phpRelated = phpVsOther?.php_related || 0;
    const hiddenCount = hiddenRow?.c || statusMap.hidden || 0;

    const payload = {
      updated_at: new Date().toISOString(),
      totals,
      status: {
        vulnerable: statusMap.vulnerable || 0,
        hidden: statusMap.hidden || 0,
        safe: statusMap.safe || 0,
        no_php: statusMap.no_php || 0,
        error: statusMap.error || 0,
      },
      frameworks: byFramework.results || [],
      countries: byCountry.results || [],
      php_vs_other: {
        php_related: phpRelated,
        no_php: phpVsOther?.no_php || 0,
        errors: phpVsOther?.errors || 0,
      },
      risk: {
        vulnerable: vulnerableShare?.vulnerable || 0,
        total: vulnerableShare?.total || 0,
        vulnerable_pct:
          vulnerableShare?.total > 0
            ? Math.round(
                (100 * (vulnerableShare.vulnerable || 0)) / vulnerableShare.total
              )
            : 0,
      },
      derived: {
        repeat_check_rate:
          totals.scans > 0
            ? Math.round((1 - totals.unique_sites / totals.scans) * 100)
            : 0,
        hidden_rate_among_php:
          phpRelated > 0 ? Math.round((100 * hiddenCount) / phpRelated) : 0,
      },
      top_tech_signals,
    };

    return new Response(JSON.stringify(payload), {
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "public, max-age=60",
        "Access-Control-Allow-Origin": "*",
      },
    });
  } catch (e) {
    console.error(e);
    return new Response(JSON.stringify({ error: "stats_unavailable" }), {
      status: 500,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
      },
    });
  }
}