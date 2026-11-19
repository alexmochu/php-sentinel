// GET /api/admin/scans -> recent scans and counts. Header auth only.
import { json } from "../../_lib/http.js";
import { requireAdmin } from "../../_lib/auth.js";

export async function onRequestGet({ request, env }) {
  const denied = await requireAdmin(request, env);
  if (denied) return denied;
  const counts = await env.DB.prepare("SELECT status, COUNT(*) AS c FROM scans GROUP BY status").all();
  const scans = await env.DB.prepare(
    `SELECT id, normalized_url, status, php_version, framework, country, created_at
     FROM scans ORDER BY created_at DESC LIMIT 100`
  ).all();
  return json({ counts: counts.results, scans: scans.results });
}
