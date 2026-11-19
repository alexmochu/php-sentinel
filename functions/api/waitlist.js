// POST /api/waitlist -> Sentinel Pro waitlist. Explicit consent required.

import { json, readJson, getIp, hashIp } from "../_lib/http.js";
import { isValidEmail, cleanText, pick } from "../_lib/validate.js";
import { hit } from "../_lib/ratelimit.js";
import { sendEmail, notificationBody } from "../_lib/email.js";

const ROLES = ["site_owner", "agency", "freelancer", "host", "security", "other"];
const INTERESTS = ["ai_fixes", "monitoring", "reports", "api"];

export async function onRequestPost({ request, env }) {
  try {
    const ipHash = await hashIp(getIp(request), env);
    const rl = await hit(env, `waitlist:${ipHash}`, 5, 3600);
    if (!rl.allowed) return json({ ok: false, error: "Too many attempts. Try again later." }, 429);

    const parsed = await readJson(request, 4000);
    if (!parsed.ok) return json({ ok: false, error: parsed.error }, parsed.status);
    const b = parsed.body;
    if (b.website || b.hp) return json({ ok: true }); // honeypot

    const email = cleanText(b.email, 254).toLowerCase();
    if (!isValidEmail(email)) return json({ ok: false, error: "Please enter a valid email." }, 400);
    if (b.consent !== true) return json({ ok: false, error: "Please tick the box to agree to be emailed about Sentinel Pro." }, 400);

    const role = pick(b.role, ROLES, "other");
    const interests = (Array.isArray(b.interests) ? b.interests : []).filter((i) => INTERESTS.includes(i));
    const siteUrl = cleanText(b.site_url, 300);
    const source = cleanText(b.source, 40) || "waitlist";

    if (!env.DB) return json({ ok: false, error: "Database not configured." }, 500);
    const res = await env.DB.prepare(
      `INSERT OR IGNORE INTO waitlist (email, role, interests, site_url, source, consent, ip)
       VALUES (?, ?, ?, ?, ?, 1, ?)`
    ).bind(email, role, interests.join(","), siteUrl || null, source, ipHash).run();

    const isNew = !!(res && res.meta && res.meta.changes > 0);
    if (isNew) {
      const { text, html } = notificationBody(
        "New Sentinel Pro waitlist signup",
        [["Email", email], ["Role", role], ["Interested in", interests.join(", ")], ["Site", siteUrl], ["Source", source]]
      );
      const mailed = await sendEmail({
        apiKey: env.RESEND_API_KEY,
        from: env.EMAIL_FROM || "Sentinel <noreply@kejanigarage.com>",
        to: env.NOTIFY_EMAIL || "alex@kejanigarage.com",
        replyTo: email, subject: `[Sentinel] Waitlist · ${email}`, html, text,
      });
      if (!mailed.ok) console.error("Resend failed", mailed.error);
    }
    // Same answer for new and existing emails, so the form cannot be used to probe the list.
    return json({ ok: true });
  } catch (err) {
    console.error(err);
    return json({ ok: false, error: "Something went wrong. Please try again." }, 500);
  }
}
