// GET /api/admin/inbox -> latest messages, waitlist signups and reports. Header auth only.
import { json } from "../../_lib/http.js";
import { requireAdmin } from "../../_lib/auth.js";

export async function onRequestGet({ request, env }) {
  const denied = await requireAdmin(request, env);
  if (denied) return denied;
  const safe = async (sql) => {
    try { return (await env.DB.prepare(sql).all()).results || []; } catch { return []; }
  };
  return json({
    messages: await safe("SELECT id, email, site_url, phone, wants_call, source, created_at, substr(message,1,300) AS message FROM messages ORDER BY id DESC LIMIT 50"),
    waitlist: await safe("SELECT id, email, role, interests, site_url, source, created_at FROM waitlist ORDER BY id DESC LIMIT 100"),
    reports: await safe("SELECT id, kind, email, domain, status, created_at, substr(details,1,300) AS details FROM reports ORDER BY id DESC LIMIT 50"),
  });
}
