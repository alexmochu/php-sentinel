// Input validation and SSRF guards.

export function isValidEmail(email) {
  return (
    typeof email === "string" &&
    email.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())
  );
}

export function cleanText(value, max) {
  if (typeof value !== "string") return "";
  // eslint-disable-next-line no-control-regex
  return value.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, "").trim().slice(0, max);
}

export function cleanPhone(value) {
  if (typeof value !== "string") return "";
  return value.trim().replace(/[^\d+\s\-()]/g, "").slice(0, 40);
}

export function pick(value, allowed, fallback) {
  return allowed.includes(value) ? value : fallback;
}

const BLOCKED_SUFFIXES = [
  ".local", ".localhost", ".internal", ".lan", ".home",
  ".corp", ".intranet", ".test", ".invalid", ".example",
];

export function isPrivateIPv4(host) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!m) return false;
  const a = Number(m[1]);
  const b = Number(m[2]);
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 192 && b === 0) ||
    (a === 198 && (b === 18 || b === 19))
  );
}

/** Check an already-parsed URL. Used for the first request and for every redirect hop. */
export function checkUrl(url) {
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return { ok: false, error: "Only http and https addresses can be checked." };
  }
  if (url.username || url.password) {
    return { ok: false, error: "Addresses with a username or password are not allowed." };
  }
  if (url.port && url.port !== "80" && url.port !== "443") {
    return { ok: false, error: "Only standard web ports (80 and 443) are allowed." };
  }
  const host = url.hostname.toLowerCase().replace(/\.$/, "");
  if (host.startsWith("[")) {
    return { ok: false, error: "IPv6 addresses are not allowed. Use a domain name." };
  }
  if (isPrivateIPv4(host)) {
    return { ok: false, error: "Local or private addresses are not allowed." };
  }
  if (!host.includes(".") || BLOCKED_SUFFIXES.some((s) => host.endsWith(s))) {
    return { ok: false, error: "Local or private addresses are not allowed." };
  }
  return { ok: true };
}

/** Turn what the visitor typed into a safe URL object. */
export function parseTargetUrl(raw) {
  let input = String(raw == null ? "" : raw).trim();
  if (!input) return { ok: false, error: "Please enter a website URL." };
  if (input.length > 2048) return { ok: false, error: "That address is too long." };
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(input) && !/^https?:\/\//i.test(input)) {
    return { ok: false, error: "Only http and https addresses can be checked." };
  }
  if (!/^https?:\/\//i.test(input)) input = "https://" + input;
  let url;
  try {
    url = new URL(input);
  } catch {
    return { ok: false, error: "Invalid URL. Example: example.com or https://shop.example.com" };
  }
  const check = checkUrl(url);
  if (!check.ok) return check;
  return { ok: true, url };
}

/** Is this hostname (or a parent domain) on the opt-out list? */
export function hostCandidates(hostname) {
  const parts = hostname.toLowerCase().replace(/\.$/, "").split(".");
  const out = [];
  for (let i = 0; i < parts.length - 1; i++) out.push(parts.slice(i).join("."));
  return out;
}
