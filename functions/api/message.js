// POST /api/message -> contact form. Stored in D1, emailed to the owner through Resend.

import { json, readJson, getIp, hashIp } from "../_lib/http.js";
import { isValidEmail, cleanText, cleanPhone } from "../_lib/validate.js";
import { hit } from "../_lib/ratelimit.js";
import { sendEmail, notificationBody } from "../_lib/email.js";

export async function onRequestPost({ request, env }) {
  try {
    const ipHash = await hashIp(getIp(request), env);
    const rl = await hit(env, `message:${ipHash}`, 5, 900);
    if (!rl.allowed) return json({ ok: false, error: "Too many messages. Try again in a bit." }, 429);

    const parsed = await readJson(request, 12000);
    if (!parsed.ok) return json({ ok: false, error: parsed.error }, parsed.status);
    const body = parsed.body;

    if (body.website || body.company_url || body.hp) return json({ ok: true, id: 0 }); // honeypot

    const email = cleanText(body.email, 254);
    const message = cleanText(body.message, 4000);
    const siteUrl = cleanText(body.site_url || body.url, 500);
    const phone = cleanPhone(body.phone || body.whatsapp);
    const scanStatus = cleanText(body.scan_status, 40);
    const source = cleanText(body.source, 40) || "checker";
    const wantsCall = body.wants_call === true || body.wants_call === 1 || body.wants_call === "1" ? 1 : 0;

    if (!isValidEmail(email)) return json({ ok: false, error: "Please enter a valid email." }, 400);
    if (message.length < 5) return json({ ok: false, error: "Please write a short message (at least a few words)." }, 400);
    if (!env.DB) return json({ ok: false, error: "Database not configured." }, 500);

    const insert = await env.DB.prepare(
      `INSERT INTO messages (email, message, site_url, phone, scan_status, wants_call, source, ip, user_agent)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(email, message, siteUrl || null, phone || null, scanStatus || null, wantsCall, source, ipHash,
        (request.headers.get("User-Agent") || "").slice(0, 200))
      .run();
    const id = (insert && insert.meta && insert.meta.last_row_id) || null;

    const subject = wantsCall
      ? `[Sentinel] Call requested · ${siteUrl || email}`
      : `[Sentinel] New message · ${siteUrl || email}`;
    const { text, html } = notificationBody(
      "New Sentinel message",
      [["From", email], ["Phone / WhatsApp", phone], ["Site", siteUrl], ["Scan status", scanStatus],
        ["Wants call", wantsCall ? "YES" : "no"], ["Source", source], ["DB id", id]],
      message
    );
    const mailed = await sendEmail({
      apiKey: env.RESEND_API_KEY,
      from: env.EMAIL_FROM || "Sentinel <noreply@kejanigarage.com>",
      to: env.NOTIFY_EMAIL || "alex@kejanigarage.com",
      replyTo: email, subject, html, text,
    });
    if (mailed.ok && id) {
      try { await env.DB.prepare("UPDATE messages SET notified = 1 WHERE id = ?").bind(id).run(); } catch { /* non-fatal */ }
    } else if (!mailed.ok) {
      console.error("Resend failed", mailed.error);
    }
    return json({ ok: true, id, wants_call: !!wantsCall, notified: !!mailed.ok });
  } catch (err) {
    console.error(err);
    return json({ ok: false, error: "Something went wrong. Try again or book a call." }, 500);
  }
}
