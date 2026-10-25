/**
 * Cloudflare Pages Function: POST /api/message
 * Saves contact notes to D1 and notifies you via Resend.
 *
 * Deploy as: functions/api/message.js
 *
 * Required secrets / vars:
 *   RESEND_API_KEY   (secret)
 *   NOTIFY_EMAIL     (e.g. alex@kejanigarage.com)
 *   EMAIL_FROM       (verified Resend sender, e.g. Sentinel <noreply@kejanigarage.com>)
 *   DB               (D1 binding: php-sentinel-db)
 *
 * Optional:
 *   CORS_ORIGIN      (default *)
 */

const RATE_WINDOW_MS = 15 * 60 * 1000;
const RATE_MAX = 5;
const ipHits = new Map();

function corsHeaders(origin) {
  return {
    "Access-Control-Allow-Origin": origin || "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Content-Type": "application/json",
  };
}

function json(body, status, origin) {
  return new Response(JSON.stringify(body), {
    status,
    headers: corsHeaders(origin),
  });
}

function isValidEmail(email) {
  return typeof email === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim()) && email.length <= 254;
}

function cleanText(s, max) {
  if (typeof s !== "string") return "";
  return s.trim().slice(0, max);
}

function rateLimit(ip) {
  const now = Date.now();
  let entry = ipHits.get(ip);
  if (!entry || now - entry.start > RATE_WINDOW_MS) {
    entry = { start: now, count: 0 };
    ipHits.set(ip, entry);
  }
  entry.count += 1;
  return entry.count <= RATE_MAX;
}

async function sendResend({ apiKey, from, to, subject, html, text, replyTo }) {
  if (!apiKey) {
    return { ok: false, error: "RESEND_API_KEY not configured" };
  }
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from,
      to: [to],
      reply_to: replyTo || undefined,
      subject,
      html,
      text,
    }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    return { ok: false, error: data?.message || res.statusText, data };
  }
  return { ok: true, data };
}

export async function onRequestOptions(context) {
  const origin = context.env.CORS_ORIGIN || "*";
  return new Response(null, { status: 204, headers: corsHeaders(origin) });
}

export async function onRequestPost(context) {
  const { request, env } = context;
  const origin = env.CORS_ORIGIN || "*";

  try {
    const ip =
      request.headers.get("CF-Connecting-IP") ||
      request.headers.get("X-Forwarded-For")?.split(",")[0]?.trim() ||
      "unknown";

    if (!rateLimit(ip)) {
      return json({ ok: false, error: "Too many messages. Try again in a bit." }, 429, origin);
    }

    let body;
    try {
      body = await request.json();
    } catch {
      return json({ ok: false, error: "Invalid JSON body" }, 400, origin);
    }

    // Honeypot — bots fill this; humans never see it
    if (body.website || body.company_url || body.hp) {
      return json({ ok: true, id: 0 }, 200, origin);
    }

    const email = cleanText(body.email || "", 254);
    const message = cleanText(body.message || "", 4000);
    const siteUrl = cleanText(body.site_url || body.url || "", 500);
    const scanStatus = cleanText(body.scan_status || "", 40);
    const source = cleanText(body.source || "checker", 40) || "checker";
    const wantsCall = body.wants_call === true || body.wants_call === 1 || body.wants_call === "1" ? 1 : 0;

    if (!isValidEmail(email)) {
      return json({ ok: false, error: "Please enter a valid email." }, 400, origin);
    }
    if (!message || message.length < 5) {
      return json({ ok: false, error: "Please write a short message (at least a few words)." }, 400, origin);
    }

    if (!env.DB) {
      return json({ ok: false, error: "Database not configured" }, 500, origin);
    }

    const ua = (request.headers.get("User-Agent") || "").slice(0, 300);

    const insert = await env.DB.prepare(
      `INSERT INTO messages (email, message, site_url, scan_status, wants_call, source, ip, user_agent)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(email, message, siteUrl || null, scanStatus || null, wantsCall, source, ip, ua)
      .run();

    const id = insert?.meta?.last_row_id || null;

    const notifyTo = env.NOTIFY_EMAIL || "alex@kejanigarage.com";
    const from = env.EMAIL_FROM || "Sentinel <noreply@kejanigarage.com>";
    const subject = wantsCall
      ? `[Sentinel] Call requested · ${siteUrl || email}`
      : `[Sentinel] New message · ${siteUrl || email}`;

    const text = [
      "New Sentinel message",
      "-------------------",
      `From: ${email}`,
      siteUrl ? `Site: ${siteUrl}` : null,
      scanStatus ? `Scan status: ${scanStatus}` : null,
      `Wants call: ${wantsCall ? "YES" : "no"}`,
      `Source: ${source}`,
      `IP: ${ip}`,
      "",
      message,
      "",
      id ? `DB id: ${id}` : null,
    ]
      .filter(Boolean)
      .join("\n");

    const html = `
      <div style="font-family:system-ui,sans-serif;max-width:560px;line-height:1.5;color:#0f172a">
        <h2 style="margin:0 0 12px">New Sentinel message</h2>
        <p style="margin:0 0 8px"><strong>From:</strong> ${escapeHtml(email)}</p>
        ${siteUrl ? `<p style="margin:0 0 8px"><strong>Site:</strong> ${escapeHtml(siteUrl)}</p>` : ""}
        ${scanStatus ? `<p style="margin:0 0 8px"><strong>Scan status:</strong> ${escapeHtml(scanStatus)}</p>` : ""}
        <p style="margin:0 0 8px"><strong>Wants call:</strong> ${wantsCall ? "YES" : "no"}</p>
        <p style="margin:0 0 16px"><strong>Source:</strong> ${escapeHtml(source)}</p>
        <div style="padding:12px 14px;background:#f8fafc;border-radius:8px;border:1px solid #e2e8f0;white-space:pre-wrap">${escapeHtml(message)}</div>
        ${id ? `<p style="margin:16px 0 0;color:#64748b;font-size:12px">DB id: ${id}</p>` : ""}
      </div>
    `;

    const mailed = await sendResend({
      apiKey: env.RESEND_API_KEY,
      from,
      to: notifyTo,
      replyTo: email,
      subject,
      html,
      text,
    });

    if (mailed.ok && id) {
      try {
        await env.DB.prepare(`UPDATE messages SET notified = 1 WHERE id = ?`).bind(id).run();
      } catch (_) {}
    } else if (!mailed.ok) {
      console.error("Resend failed", mailed.error || mailed.data);
    }

    return json(
      {
        ok: true,
        id,
        wants_call: !!wantsCall,
        notified: !!mailed.ok,
      },
      200,
      origin
    );
  } catch (err) {
    console.error(err);
    return json({ ok: false, error: "Something went wrong. Try again or book a call." }, 500, origin);
  }
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
