// POST /api/remediate  { findings, stack }  -> fix plan (AI beta, with built-in rules fallback).

import { json, readJson, getIp, hashIp } from "../_lib/http.js";
import { pick } from "../_lib/validate.js";
import { sanitizeFindings } from "../_lib/findings.js";
import { hit } from "../_lib/ratelimit.js";
import { STACKS, buildRulesPlan } from "../_lib/remediation-rules.js";
import { refinePlanWithAI } from "../_lib/remediation-ai.js";

export async function onRequestPost({ request, env }) {
  const ipHash = await hashIp(getIp(request), env);
  const perIp = await hit(env, `ai:${ipHash}`, 5, 3600);
  if (!perIp.allowed) return json({ error: "You have reached the hourly limit for fix plans. Try again later." }, 429);

  const parsed = await readJson(request, 6000);
  if (!parsed.ok) return json({ error: parsed.error }, parsed.status);

  const findings = sanitizeFindings(parsed.body.findings);
  const stack = pick(parsed.body.stack, STACKS, "unknown");
  const baseline = buildRulesPlan(findings, stack);

  // Global daily cap so a spike cannot create a surprise bill.
  const dailyCap = Number(env.AI_DAILY_LIMIT || 200);
  const global = await hit(env, "ai:global", dailyCap, 86400);
  if (!global.allowed || !env.ANTHROPIC_API_KEY) {
    return json({ plan: baseline, stack });
  }
  const refined = await refinePlanWithAI(env, findings, stack, baseline);
  return json({ plan: refined ? { ...refined, source: "ai" } : baseline, stack });
}
