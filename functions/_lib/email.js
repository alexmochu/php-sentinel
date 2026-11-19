// Transactional email through Resend.

export function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export async function sendEmail({ apiKey, from, to, subject, html, text, replyTo }) {
  if (!apiKey) return { ok: false, error: "RESEND_API_KEY not configured" };
  try {
    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
      body: JSON.stringify({ from, to: [to], reply_to: replyTo || undefined, subject, html, text }),
      signal: AbortSignal.timeout(8000),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) return { ok: false, error: (data && data.message) || res.statusText };
    return { ok: true };
  } catch (err) {
    return { ok: false, error: String(err && err.message ? err.message : err) };
  }
}

/** Plain admin notification: escaped HTML plus a text version. */
export function notificationBody(title, fields, message) {
  const rows = fields.filter((f) => f[1] !== null && f[1] !== undefined && f[1] !== "");
  const text = [title, "-".repeat(title.length), ...rows.map(([k, v]) => `${k}: ${v}`), "", message || ""].join("\n");
  const html =
    `<div style="font-family:system-ui,sans-serif;max-width:560px;line-height:1.5;color:#0f172a">` +
    `<h2 style="margin:0 0 12px">${escapeHtml(title)}</h2>` +
    rows.map(([k, v]) => `<p style="margin:0 0 8px"><strong>${escapeHtml(k)}:</strong> ${escapeHtml(v)}</p>`).join("") +
    (message
      ? `<div style="margin-top:12px;padding:12px 14px;background:#f8fafc;border-radius:8px;border:1px solid #e2e8f0;white-space:pre-wrap">${escapeHtml(message)}</div>`
      : "") +
    `</div>`;
  return { text, html };
}
