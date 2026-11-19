// D1-backed rate limiting. Works across Worker instances, unlike an in-memory Map.

export async function hit(env, key, limit, windowSeconds) {
  if (!env.DB) return { allowed: true, count: 0 };
  try {
    await env.DB.prepare("INSERT INTO rate_events (key) VALUES (?)").bind(key).run();
    const row = await env.DB
      .prepare("SELECT COUNT(*) AS c FROM rate_events WHERE key = ? AND created_at > datetime('now', ?)")
      .bind(key, `-${windowSeconds} seconds`)
      .first();
    const count = (row && row.c) || 0;
    if (Math.random() < 0.02) {
      await env.DB.prepare("DELETE FROM rate_events WHERE created_at < datetime('now', '-2 days')").run();
    }
    return { allowed: count <= limit, count };
  } catch (err) {
    // Fail open: a broken limiter must not take the site down.
    console.error("rate limit error", err);
    return { allowed: true, count: 0, error: true };
  }
}
