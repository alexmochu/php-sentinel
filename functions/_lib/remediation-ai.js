// Optional AI refinement of the baseline plan, through the Anthropic Messages API.
// Safety: the model only ever sees whitelisted, structured findings. Free text from the scanned
// website (generator tags, page content) is never passed in, which blocks prompt injection from target sites.

const SYSTEM = `You are Sentinel's remediation assistant for website owners.
You receive structured findings from a passive, outside-in scan and a baseline fix plan.
Return a clearer, stack-specific version of that plan.

Rules:
- Use only the findings provided. Do not invent versions, vulnerabilities or findings.
- Prefer the baseline snippets verbatim unless the chosen stack needs a change.
- Defensive guidance only. Never include exploit steps, payloads or ways to attack a site.
- Every step must be small, reversible and say how to check it worked. Tell the user to back up first.
- Write plain language for a non-expert. No marketing tone.
- Respond with JSON only, no markdown fences, in exactly this shape:
{"summary": string, "steps": [{"id": string, "title": string, "priority": "high"|"medium"|"low", "why": string, "how": [string], "snippet": {"label": string, "language": string, "code": string} | null}], "verify": [string], "notes": [string]}
- At most 8 steps, at most 6 "how" lines per step.`;

function clip(value, max) {
  return String(value == null ? "" : value).replace(/<[^>]*>/g, "").slice(0, max);
}

export function validatePlan(raw) {
  if (!raw || typeof raw !== "object" || !Array.isArray(raw.steps) || raw.steps.length === 0) return null;
  const steps = [];
  for (const s of raw.steps.slice(0, 8)) {
    if (!s || typeof s.title !== "string" || typeof s.why !== "string" || !Array.isArray(s.how)) return null;
    const step = {
      id: clip(s.id || `step-${steps.length + 1}`, 40),
      title: clip(s.title, 140),
      priority: ["high", "medium", "low"].includes(s.priority) ? s.priority : "medium",
      why: clip(s.why, 600),
      how: s.how.slice(0, 6).map((h) => clip(h, 400)).filter(Boolean),
    };
    if (s.snippet && typeof s.snippet.code === "string") {
      step.snippet = { label: clip(s.snippet.label, 120), language: clip(s.snippet.language, 20) || "text", code: String(s.snippet.code).slice(0, 2000) };
    }
    steps.push(step);
  }
  const list = (v, n) => (Array.isArray(v) ? v.slice(0, n).map((x) => clip(x, 300)).filter(Boolean) : []);
  return { summary: clip(raw.summary, 400), steps, verify: list(raw.verify, 6), notes: list(raw.notes, 6) };
}

export async function refinePlanWithAI(env, findings, stack, baseline) {
  if (!env.ANTHROPIC_API_KEY) return null;
  const model = env.ANTHROPIC_MODEL || "claude-haiku-5-5";
  try {
    const res = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-api-key": env.ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model,
        max_tokens: 2000,
        system: SYSTEM,
        messages: [{ role: "user", content: JSON.stringify({ stack, findings, baseline_plan: baseline }) }],
      }),
      signal: AbortSignal.timeout(25000),
    });
    if (!res.ok) {
      console.error("AI request failed", res.status);
      return null;
    }
    const data = await res.json();
    const text = (data.content || []).filter((b) => b.type === "text").map((b) => b.text).join("").trim();
    const cleaned = text.replace(/^```(?:json)?/i, "").replace(/```$/, "").trim();
    return validatePlan(JSON.parse(cleaned));
  } catch (err) {
    console.error("AI refinement failed", err && err.message);
    return null;
  }
}
