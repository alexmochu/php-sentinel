// Shared HTTP helpers for Pages Functions.

const BASE_HEADERS = {
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store",
};

/** JSON response. Same-origin only: no CORS headers are added on purpose. */
export function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...BASE_HEADERS, ...extra },
  });
}

/** Read a JSON body with a hard size cap. */
export async function readJson(request, maxBytes = 16384) {
  const declared = Number(request.headers.get("content-length") || 0);
  if (declared > maxBytes) return { ok: false, status: 413, error: "Request is too large." };
  let text;
  try {
    text = await request.text();
  } catch {
    return { ok: false, status: 400, error: "Could not read the request." };
  }
  if (text.length > maxBytes) return { ok: false, status: 413, error: "Request is too large." };
  try {
    const body = JSON.parse(text);
    if (body === null || typeof body !== "object" || Array.isArray(body)) {
      return { ok: false, status: 400, error: "Invalid JSON body." };
    }
    return { ok: true, body };
  } catch {
    return { ok: false, status: 400, error: "Invalid JSON body." };
  }
}

export function getIp(request) {
  return request.headers.get("CF-Connecting-IP") || "unknown";
}

export async function sha256Hex(input) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Salted SHA-256 of the visitor IP. We never store raw IPs.
 * Set IP_SALT as a secret in production; the fallback exists only so local dev works.
 */
export async function hashIp(ip, env) {
  const salt = (env && env.IP_SALT) || "sentinel-dev-salt";
  return sha256Hex(`${salt}:${ip}`);
}
