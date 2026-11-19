import { json, getIp, hashIp } from "./http.js";
import { hit } from "./ratelimit.js";

async function digest(value) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return new Uint8Array(buf);
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * Admin check. The secret is accepted in the X-Admin-Key header only, never in the URL.
 * Also protect /admin and /api/admin/* with Cloudflare Access.
 * Returns a Response to send when access is denied, or null when allowed.
 */
export async function requireAdmin(request, env) {
  if (!env.ADMIN_SECRET) return json({ error: "Admin access is not configured." }, 503);
  const ipHash = await hashIp(getIp(request), env);
  const rl = await hit(env, `admin:${ipHash}`, 10, 600);
  if (!rl.allowed) return json({ error: "Too many attempts." }, 429);
  const supplied = request.headers.get("X-Admin-Key") || "";
  const ok = timingSafeEqual(await digest(supplied), await digest(env.ADMIN_SECRET));
  return ok ? null : json({ error: "Unauthorized" }, 401);
}
