// POST /api/report -> removal requests, scan opt-outs, abuse reports, security reports about Sentinel itself.

import { json, readJson, getIp, hashIp } from "../_lib/http.js";
import { isValidEmail, cleanText, pick } from "../_lib/validate.js";
import { hit } from "../_lib/ratelimit.js";
import { sendEmail, notificationBody } from "../_lib/email.js";

const KINDS = ["removal", "opt_out", "abuse", "security", "other"];

export async function onRequestPost({ request, env }) {
  try {
    const ipHash = await hashIp(getIp(request), env);
    const rl = await hit(env, `report:${ipHash}`, 5, 3600);
    if (!rl.allowed) return json({ ok: false, error: "Too many reports. Try again later." }, 429);

    const parsed = await readJson(request, 8000);
    if (!parsed.ok) return json({ ok: false, error: parsed.error }, parsed.status);
    const b = parsed.body;
    if (b.website || b.hp) return json({ ok: true });

    const kind = pick(b.kind, KINDS, "other");
    const email = cleanText(b.email, 254);
    const domain = cleanText(b.domain, 253).toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
    const details = cleanText(b.details, 4000);
    if (!isValidEmail(email)) return json({ ok: false, error: "Please enter a valid email so we can reply." }, 400);
    if (details.length < 5) return json({ ok: false, error: "Please add a few details." }, 400);
    if ((kind === "removal" || kind === "opt_out") && !domain) {
      return json({ ok: false, error: "Please enter the domain this request is about." }, 400);
    }
    if (!env.DB) return json({ ok: false, error: "Database not configured." }, 500);

    const res = await env.DB.prepare(
      "INSERT INTO reports (kind, email, domain, details, ip) VALUES (?, ?, ?, ?, ?)"
    ).bind(kind, email, domain || null, details, ipHash).run();
    const id = (res && res.meta && res.meta.last_row_id) || null;

    const { text, html } = notificationBody(
      `Sentinel report: ${kind}`,
      [["From", email], ["Domain", domain], ["Report id", id]],
      details
    );
    const mailed = await sendEmail({
      apiKey: env.RESEND_API_KEY,
      from: env.EMAIL_FROM || "Sentinel <noreply@kejanigarage.com>",
      to: env.NOTIFY_EMAIL || "alex@kejanigarage.com",
      replyTo: email, subject: `[Sentinel] Report (${kind}) · ${domain || email}`, html, text,
    });
    if (!mailed.ok) console.error("Resend failed", mailed.error);
    return json({ ok: true, id });
  } catch (err) {
    console.error(err);
    return json({ ok: false, error: "Something went wrong. Please email us directly." }, 500);
  }
}
