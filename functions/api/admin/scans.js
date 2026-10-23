export async function onRequestGet(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const key = url.searchParams.get("key") || request.headers.get("X-Admin-Key");

  if (!key || key !== env.ADMIN_SECRET) {
    return new Response(JSON.stringify({ error: "Unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json" }
    });
  }

  const { results } = await env.DB.prepare(
    `SELECT id, url, normalized_url, status, php_version, framework, country, created_at
     FROM scans ORDER BY created_at DESC LIMIT 100`
  ).all();

  const counts = await env.DB.prepare(
    `SELECT status, COUNT(*) as c FROM scans GROUP BY status`
  ).all();

  return new Response(JSON.stringify({ counts: counts.results, scans: results }), {
    headers: { "Content-Type": "application/json" }
  });
}