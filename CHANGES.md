# Sentinel v2: change manifest

Apply by copying this folder over your repo, then delete the files listed under DELETE.
Every file is complete (no snippets or "…rest unchanged").

## DELETE (old files that this version replaces)

| File | Why |
| --- | --- |
| `schema.sql` | Moved to `migrations/0001_init.sql` |
| `public/threats-2026.json` | Moved to `public/data/threats-2026.json` |
| `.wrangler/` and `.env`, if they were ever committed | Local state and a secret. They were inside the zip you sent. They should not be in git (`.gitignore` already lists them) |

## MOVE / RENAME

| From | To |
| --- | --- |
| `schema.sql` | `migrations/0001_init.sql` |
| `public/threats-2026.json` | `public/data/threats-2026.json` (the page now fetches `/data/threats-2026.json`) |
| Element ids `adLeft`, `adRight` | `sideHelp`, `sideAbout` (they were not ads) |
| URLs `/threats.html` | `/threats` (Cloudflare Pages already redirects `.html` to the clean URL, so canonical and sitemap were pointing at a redirect) |
| Inline `<style>` and `<script>` in `index.html` and `threats.html` | `public/css/*.css` and `public/js/*.js` |

## ADD

**Server**
- `functions/_lib/`: `http.js`, `validate.js`, `ratelimit.js`, `auth.js`, `email.js`, `patch-data.js`, `detect.js`, `verdict.js`, `scanner.js`, `findings.js`, `remediation-rules.js`, `remediation-ai.js`
- `functions/api/`: `advisory.js`, `waitlist.js`, `report.js`, `remediate.js`
- `functions/api/admin/`: `inbox.js`, `anonymize.js`
- `migrations/0002_messages.sql`, `migrations/0003_waitlist_reports_limits.sql`

**Front end**
- `public/terms.html`, `public/privacy.html`, `public/abuse.html`
- `public/css/`: `theme.css`, `layout.css`, `checker.css`, `threats.css`, `legal.css`
- `public/js/`: `config.js`, `util.js`, `analytics.js`, `layout.js`, `contact.js`, `charts.js`, `stats.js`, `results-view.js`, `remediation.js`, `waitlist.js`, `results-cta.js`, `checker.js`, `main.js`, `abuse.js`, `admin.js`, `threats.js`, `tailwind-config.js`
- `public/vendor/chart.umd.js` (Chart.js 4.4.1, self-hosted)
- `public/_headers`, `public/.well-known/security.txt`

**Project**
- `README.md` (the old one was empty), `CHANGES.md`, `.dev.vars.example`, `tests/` (21 API and unit tests, plus a browser-DOM smoke test)

## CHANGE (full replacement)

| File | What changed |
| --- | --- |
| `functions/api/scan.js` | Split into modules. SSRF guard on every redirect hop. D1 rate limit. Stores no raw IP and no query string. Opt-out list. Honest "appears" wording plus a backport caveat. Stricter detection (no more matching the word "react" or "laravel" in page text) |
| `functions/api/stats.js` | Excludes your own IPs (`EXCLUDE_IPS`). Adds a real 30-day daily series, 7-day and 30-day counts, first-scan date, waitlist count |
| `functions/api/message.js` | D1 rate limit (the old in-memory one reset per Worker instance). No IP in the notification email. Same-origin only |
| `functions/api/admin/scans.js` | Header-only auth, constant-time compare, brute-force limit. The key is no longer accepted in the URL |
| `public/index.html` | Slim shell. Pro waitlist section, fix-plan panel, "what Sentinel does" notice. Sidebar swapped to put the product first |
| `public/threats.html` | Slim shell. Shared header, footer and modal |
| `public/admin.html` | Key kept in memory and sent in a header. Shows waitlist, messages, reports |
| `public/robots.txt`, `public/sitemap.xml` | Disallow `/admin` and `/api/`. Sitemap lists every page with clean URLs |
| `package.json` | ESM, scripts for migrations, tests, deploy |
| `wrangler.toml` | One line added (`migrations_dir`) plus a comment. Your `database_id` is unchanged |
| `.gitignore` | Also ignores `.env.*`, `*.zip` |

## Fixed on the way

- **XSS:** text from the scanned site (for example the generator meta tag) and API fields were inserted with `innerHTML` unescaped. Everything dynamic is now escaped, the server also strips risky characters, and tests prove a hostile payload does not execute.
- Error responses (rate limit, bad URL) used to show a "No PHP Detected" card. They now show a real error.
- `messages` table was missing from `schema.sql`. It is now in a migration.
- Favicon pointed at `og-image.png`. It now uses `favicon.png`.
- Cloudflare beacon had a `YOUR_CLOUDFLARE_TOKEN` placeholder. It loads only when a token is set in `config.js`.
- Google Fonts moved from a render-blocking `@import` to `<link>` tags. Tailwind CDN is pinned to 3.4.17.
- Hardcoded patched-version text in the page now comes from `/api/advisory`.
- The "trend" chart was a fake line across categories. It is now checks per day over 30 days.
- "Repeat rate" is relabelled "Repeat site checks" (it never measured user retention). "Unique users" is now "Unique visitors (approx.)".
- Added keyboard focus styles, a skip link, `prefers-reduced-motion`, modal and chart accessibility labels.
- The three copies of the message form logic are now one (`contact.js`). Theme differences between the two pages (gradient strength, hover lift) are unified.

## Design

The look is unchanged: same colours, glass cards, fonts and layout. Additions reuse the existing styles (chips, glass, teal accent). The AI fix plan and waitlist use the same card and input styling.

## Before you deploy (needs you)

1. `public/js/config.js`: check the WhatsApp number (it had 11 digits; Kenyan numbers have 12 with the 254 prefix), add your LinkedIn URL and optional Cloudflare Web Analytics token. The LinkedIn button stays hidden until set.
2. `functions/_lib/patch-data.js`: verify the CVE IDs and fixed versions against php.net, then set `last_verified`.
3. Set secrets: `ADMIN_SECRET`, `IP_SALT`, `RESEND_API_KEY`, `ANTHROPIC_API_KEY` (see README). Confirm the model name in `ANTHROPIC_MODEL`.
4. Run `npm run db:migrate`, deploy, then call `/api/admin/anonymize` until `remaining` is 0.
5. Put `/admin*` and `/api/admin/*` behind Cloudflare Access.
6. Set `EXCLUDE_IPS` to your own IPs so your testing does not inflate the public numbers.
7. Have a lawyer review the Terms and Privacy pages. They are plain-language drafts, not legal advice. Check whether you need to register with Kenya's Data Protection Commissioner as a data controller. The retention periods in the policy are only true if you run the cleanup SQL in the README.
8. The consent banner, Content-Security-Policy (Report-Only) and `_headers` are new: test the site in a browser before relying on them.
