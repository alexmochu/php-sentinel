# Sentinel

Free website risk checker by [Kejani Garage](https://kejanigarage.com). Paste a URL and get public PHP risk signals, security header and TLS basics, and tech fingerprints. Includes an AI fix plan (beta), a Sentinel Pro waitlist, and the 2026 threat timeline.

Live: https://sentinel.kejanigarage.com

## What it does (and does not)

- Makes one passive GET to the page you enter, plus one request to the `http://` version to test the redirect. Follows at most three redirects and re-checks every hop.
- Never logs in, crawls, or sends exploit code. Identifies itself as `Sentinel/1.1 (+https://sentinel.kejanigarage.com/abuse)`.
- Verdicts use the version the server **reports**. Hosts that backport patches without changing the version can look vulnerable, so results are indicators, not an audit.
- Stores a salted hash of the visitor IP, never the raw IP.

## Stack

Cloudflare Pages (static `public/`) + Pages Functions (`functions/`) + D1 (SQLite). No build step. Tailwind runs from the pinned play CDN; Chart.js is vendored in `public/vendor/`.

## Layout

```
functions/
  _lib/            shared server code (http, validate, ratelimit, auth, email,
                   scanner, detect, verdict, patch-data, findings,
                   remediation-rules, remediation-ai)
  api/             scan, stats, advisory, message, waitlist, report, remediate
  api/admin/       scans, inbox, anonymize  (header auth only)
migrations/        D1 schema, applied in order
public/
  index.html threats.html terms.html privacy.html abuse.html admin.html
  css/             theme, layout, checker, threats, legal
  js/              one file per job (see below)
  data/            threats-2026.json
  vendor/          chart.umd.js (Chart.js 4.4.1)
  _headers robots.txt sitemap.xml .well-known/security.txt
tests/             node --test
```

Front-end scripts are plain classic scripts that share one namespace, `window.Sentinel`. They load with `defer`, in the order listed in `index.html`:
`config, util, analytics, layout, contact, charts, stats, results-view, remediation, waitlist, results-cta, checker, main`.

## Setup

```bash
npm install
cp .dev.vars.example .dev.vars        # then fill in values
npm run db:migrate:local
npm run dev                            # http://localhost:8788
npm test
```

## Deploy

```bash
npm run db:migrate                     # apply new migrations to the remote D1 database
wrangler pages secret put ADMIN_SECRET
wrangler pages secret put IP_SALT
wrangler pages secret put RESEND_API_KEY
wrangler pages secret put ANTHROPIC_API_KEY
npm run deploy
```

Then, once, anonymise raw IPs saved by the old version (repeat until `remaining` is 0):

```bash
curl -X POST https://sentinel.kejanigarage.com/api/admin/anonymize -H "X-Admin-Key: $ADMIN_SECRET"
```

Set `IP_SALT` **before** running this and do not change it afterwards, or visitor counts will reset.

## Configuration

| Name | Kind | Purpose |
| --- | --- | --- |
| `ADMIN_SECRET` | secret | Admin API key, sent in the `X-Admin-Key` header |
| `IP_SALT` | secret | Salt for IP hashing |
| `RESEND_API_KEY` | secret | Notification emails |
| `ANTHROPIC_API_KEY` | secret | AI fix plans. Without it the built-in rules plan is returned |
| `NOTIFY_EMAIL`, `EMAIL_FROM` | variable | Where notifications go and who they come from |
| `ANTHROPIC_MODEL` | variable | Defaults to `claude-haiku-5-5`. Check the name in the Anthropic console |
| `AI_DAILY_LIMIT` | variable | Global cap on AI calls per day (default 200); per visitor it is 5 per hour |
| `EXCLUDE_IPS` | variable | Your own IPs, left out of public stats |

Front-end settings (Cal.com link, WhatsApp, LinkedIn, analytics IDs) are in `public/js/config.js`.

## Routine maintenance

1. **Advisory data.** Before each PHP release cycle, confirm the IDs and fixed versions in `functions/_lib/patch-data.js` against php.net, then set `last_verified`.
2. **Retention.** The privacy policy promises scan records are kept up to 12 months and messages and reports up to 24. Run quarterly:
   ```sql
   DELETE FROM scans    WHERE created_at < datetime('now','-12 months');
   DELETE FROM messages WHERE created_at < datetime('now','-24 months');
   DELETE FROM reports  WHERE created_at < datetime('now','-24 months');
   ```
   `wrangler d1 execute php-sentinel-db --remote --command "<sql>"`
3. **Opt-outs.** After verifying ownership of the domain:
   ```sql
   INSERT INTO opt_outs (domain, note) VALUES ('example.com', 'verified by email 2026-11-20');
   DELETE FROM scans WHERE normalized_url LIKE 'https://example.com%' OR normalized_url LIKE 'https://%.example.com%';
   ```
4. **Protect `/admin` and `/api/admin/*`** with Cloudflare Access (Zero Trust, free tier).
5. **Content-Security-Policy** ships as `Report-Only` in `public/_headers`. Watch the browser console for violations, then rename it to `Content-Security-Policy`.

## Known limits and next steps

- Tailwind still loads from the play CDN. A compiled stylesheet would be faster and let you tighten the CSP (`unsafe-eval` can go).
- DNS names that resolve to private addresses cannot be checked from a Worker. Cloudflare Workers cannot reach private networks, which limits the impact.
- The Pro waitlist collects demand only. No pricing is published.
