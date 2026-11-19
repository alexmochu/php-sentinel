// POST /api/admin/anonymize -> one-time job: replace raw IPs stored by older versions with salted hashes.
// Call repeatedly until it returns remaining: 0. Header auth only.
import { json, hashIp } from "../../_lib/http.js";
import { requireAdmin } from "../../_lib/auth.js";

const BATCH = 200;

export async function onRequestPost({ request, env }) {
  const denied = await requireAdmin(request, env);
  if (denied) return denied;
  const out = {};
  for (const table of ["scans", "messages"]) {
    try {
      // A salted SHA-256 hex digest is exactly 64 characters; anything else is a raw IP.
      const rows = await env.DB.prepare(
        `SELECT id, ip FROM ${table} WHERE ip IS NOT NULL AND length(ip) <> 64 LIMIT ${BATCH}`
      ).all();
      const statements = [];
      for (const r of rows.results || []) {
        statements.push(env.DB.prepare(`UPDATE ${table} SET ip = ? WHERE id = ?`).bind(await hashIp(r.ip, env), r.id));
      }
      if (statements.length) await env.DB.batch(statements);
      const left = await env.DB.prepare(`SELECT COUNT(*) AS c FROM ${table} WHERE ip IS NOT NULL AND length(ip) <> 64`).first();
      out[table] = { updated: statements.length, remaining: (left && left.c) || 0 };
    } catch (err) {
      out[table] = { error: String(err && err.message ? err.message : err) };
    }
  }
  return json(out);
}
