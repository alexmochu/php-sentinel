// Passive page fetch with SSRF guards. Only GET requests, only public http(s) hosts.

import { checkUrl } from "./validate.js";

export const USER_AGENT = "Sentinel/1.1 (+https://sentinel.kejanigarage.com/abuse)";
const MAX_BODY_BYTES = 200_000;

export class GuardError extends Error {}

function lowerHeaders(res) {
  return Object.fromEntries([...res.headers].map(([k, v]) => [k.toLowerCase(), v]));
}

function cookiesOf(res) {
  if (typeof res.headers.getSetCookie === "function") return res.headers.getSetCookie().join("; ");
  return res.headers.get("set-cookie") || "";
}

async function readLimited(res, maxBytes) {
  if (!res.body) return "";
  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;
  while (total < maxBytes) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    total += value.length;
  }
  try { await reader.cancel(); } catch { /* ignore */ }
  const merged = new Uint8Array(Math.min(total, maxBytes));
  let offset = 0;
  for (const c of chunks) {
    const slice = c.subarray(0, Math.max(0, merged.length - offset));
    merged.set(slice, offset);
    offset += slice.length;
    if (offset >= merged.length) break;
  }
  return new TextDecoder("utf-8", { fatal: false }).decode(merged);
}

/**
 * GET a page, following up to maxRedirects redirects. Every hop is re-validated,
 * so a public site cannot bounce us to a private address.
 */
export async function fetchGuarded(startUrl, { timeoutMs = 9000, maxRedirects = 3 } = {}) {
  let current = new URL(startUrl);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    for (let hop = 0; hop <= maxRedirects; hop++) {
      const check = checkUrl(current);
      if (!check.ok) throw new GuardError(check.error);
      const res = await fetch(current.toString(), {
        method: "GET",
        redirect: "manual",
        signal: controller.signal,
        headers: { "User-Agent": USER_AGENT, Accept: "text/html,application/xhtml+xml" },
      });
      const location = res.headers.get("location");
      if (res.status >= 300 && res.status < 400 && location && hop < maxRedirects) {
        current = new URL(location, current);
        continue;
      }
      const headers = lowerHeaders(res);
      const text = await readLimited(res, MAX_BODY_BYTES);
      return { status: res.status, headers, cookies: cookiesOf(res), text, finalUrl: current };
    }
    throw new GuardError("Too many redirects.");
  } finally {
    clearTimeout(timer);
  }
}

/** Does plain http:// redirect to https://? true / false / null (unknown). */
export async function probeHttpRedirect(host, pathname) {
  try {
    const httpUrl = new URL(`http://${host}${pathname === "/" ? "" : pathname}`);
    if (!checkUrl(httpUrl).ok) return null;
    const res = await fetch(httpUrl.toString(), {
      method: "GET",
      redirect: "manual",
      signal: AbortSignal.timeout(6000),
      headers: { "User-Agent": USER_AGENT },
    });
    const loc = res.headers.get("location") || "";
    return res.status >= 300 && res.status < 400 && /^https:\/\//i.test(loc);
  } catch {
    return null;
  }
}

export function analyzeSecurity(headers, isHttps, bodyLower) {
  const security_headers = {
    https: isHttps,
    hsts: !!headers["strict-transport-security"],
    csp: !!(headers["content-security-policy"] || headers["content-security-policy-report-only"]),
    x_frame_options: !!headers["x-frame-options"],
    x_content_type_options: !!headers["x-content-type-options"],
    referrer_policy: !!headers["referrer-policy"],
  };
  const mixed_content_hint =
    isHttps && (bodyLower.includes('src="http://') || bodyLower.includes('href="http://') || bodyLower.includes("src='http://"));
  return { security_headers, mixed_content_hint };
}
