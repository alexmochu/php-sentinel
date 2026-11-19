// Built-in remediation plans. Deterministic, reviewed config snippets.
// The AI layer (remediate.js) can refine these; if it is unavailable or returns something invalid,
// this plan is returned as-is, so the feature keeps working.

import { ADVISORY } from "./patch-data.js";

export const STACKS = ["unknown", "cpanel", "nginx", "apache", "cloudflare", "wordpress", "laravel"];

const HEADER_VALUES = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "SAMEORIGIN",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Strict-Transport-Security": "max-age=86400",
};

function headerSnippet(stack, missing) {
  const names = missing.filter((n) => HEADER_VALUES[n]);
  if (!names.length) return null;
  const lines = (fmt) => names.map(fmt).join("\n");
  if (stack === "nginx") {
    return { label: "Nginx server block", language: "nginx", code: lines((n) => `add_header ${n} "${HEADER_VALUES[n]}" always;`) };
  }
  if (stack === "apache" || stack === "cpanel") {
    return {
      label: ".htaccess or Apache config (needs mod_headers)",
      language: "apache",
      code: `<IfModule mod_headers.c>\n${lines((n) => `  Header always set ${n} "${HEADER_VALUES[n]}"`)}\n</IfModule>`,
    };
  }
  if (stack === "cloudflare") {
    return {
      label: "Cloudflare: Rules → Transform Rules → Modify Response Header",
      language: "text",
      code: lines((n) => `Set static  ${n}: ${HEADER_VALUES[n]}`),
    };
  }
  if (stack === "wordpress") {
    return {
      label: "WordPress: add to a small plugin or your child theme's functions.php",
      language: "php",
      code: `add_action('send_headers', function () {\n${lines((n) => `    header('${n}: ${HEADER_VALUES[n]}');`)}\n});`,
    };
  }
  if (stack === "laravel") {
    return {
      label: "Laravel: app/Http/Middleware/SecurityHeaders.php (then register it)",
      language: "php",
      code:
        `public function handle($request, \\Closure $next)\n{\n    $response = $next($request);\n` +
        lines((n) => `    $response->headers->set('${n}', '${HEADER_VALUES[n]}');`) +
        `\n    return $response;\n}`,
    };
  }
  return { label: "Generic: set these response headers in your server or CDN", language: "text", code: lines((n) => `${n}: ${HEADER_VALUES[n]}`) };
}

function upgradeSteps(stack) {
  const common = ["Back up the site and database first.", "Test the new PHP version on a staging copy if you can."];
  if (stack === "cpanel") return [...common, "cPanel → Software → MultiPHP Manager, choose the domain, pick a patched PHP version.", "Re-run Sentinel to confirm."];
  if (stack === "nginx" || stack === "apache") {
    return [...common, "On the server run php -v to see the real version.", "Update through your package manager or runtime image, then restart PHP-FPM or Apache.", "Re-run Sentinel to confirm."];
  }
  if (stack === "wordpress") return [...common, "In Site Health → Info → Server, check the PHP version.", "Change it in your host's panel, not inside WordPress.", "Re-run Sentinel to confirm."];
  return [...common, "Find the real PHP version in your hosting panel or with php -v.", "Upgrade to a supported branch.", "Re-run Sentinel to confirm."];
}

/** Build the baseline plan from sanitized findings. */
export function buildRulesPlan(f, stack) {
  const steps = [];
  const sh = f.security_headers || {};
  const tls = f.tls || {};
  const fixedList = Object.values(ADVISORY.fixed_versions).join(", ");

  if (f.status === "vulnerable" || f.status === "hidden") {
    steps.push({
      id: "php-version",
      title: f.status === "vulnerable" ? "Upgrade PHP to a patched version" : "Confirm the real PHP version",
      priority: "high",
      why:
        f.status === "vulnerable"
          ? `The reported version (${f.php_version || "unknown"}) is behind the fixed releases (${fixedList}). Remote code execution flaws are the most serious kind.`
          : `PHP is present but the version is hidden. Hiding it is good, but you still need to know it is at or above ${fixedList}.`,
      how: upgradeSteps(stack),
    });
  }
  if (f.x_powered_by_exposed) {
    steps.push({
      id: "expose-php",
      title: "Stop advertising the PHP version",
      priority: "medium",
      why: "The X-Powered-By header tells everyone which PHP version you run, which helps attackers pick targets.",
      how: ["Set expose_php = Off in php.ini (or your host's PHP options).", "Restart PHP-FPM or Apache.", "Re-run Sentinel and check the header is gone."],
      snippet: { label: "php.ini", language: "ini", code: "expose_php = Off" },
    });
  }
  if (tls.https === false || tls.redirects_to_https === false) {
    steps.push({
      id: "https-redirect",
      title: "Redirect all HTTP traffic to HTTPS",
      priority: "high",
      why: "Without a redirect, visitors can end up on an unencrypted version of your site.",
      how: ["Make sure a valid TLS certificate is installed.", "Add a permanent (301) redirect from http:// to https://.", "Re-run Sentinel."],
    });
  }
  const missing = [];
  if (sh.hsts === false) missing.push("Strict-Transport-Security");
  if (sh.x_content_type_options === false) missing.push("X-Content-Type-Options");
  if (sh.x_frame_options === false) missing.push("X-Frame-Options");
  if (sh.referrer_policy === false) missing.push("Referrer-Policy");
  if (missing.length) {
    const snippet = headerSnippet(stack, missing);
    steps.push({
      id: "headers",
      title: `Add ${missing.length} missing security header${missing.length > 1 ? "s" : ""}`,
      priority: "medium",
      why: "These headers are low-effort protections against clickjacking, content sniffing and leaky referrers.",
      how: [
        "Add the snippet below where your stack sets response headers.",
        missing.includes("Strict-Transport-Security")
          ? "HSTS starts at one day on purpose. Raise max-age to 31536000 (one year) once everything works over HTTPS."
          : "Reload the server and re-run Sentinel.",
      ],
      ...(snippet ? { snippet } : {}),
    });
  }
  if (sh.csp === false) {
    steps.push({
      id: "csp",
      title: "Start a Content-Security-Policy in report-only mode",
      priority: "low",
      why: "A CSP limits where scripts can load from. Start in report-only mode so nothing breaks while you tune it.",
      how: ["Send Content-Security-Policy-Report-Only with a policy that matches your assets.", "Watch the browser console for violations, fix them, then switch to enforcing."],
    });
  }
  if (tls.mixed_content_hint) {
    steps.push({
      id: "mixed-content",
      title: "Fix mixed content",
      priority: "medium",
      why: "Some resources appear to load over http:// on an https:// page, which browsers may block or flag.",
      how: ["Search your templates and database for http:// links to your own domain.", "Change them to https:// or protocol-relative paths."],
    });
  }
  if (!steps.length) {
    steps.push({
      id: "keep-patched",
      title: "Keep your stack patched",
      priority: "low",
      why: "Nothing urgent stands out from public signals. Most incidents come from falling behind on updates.",
      how: ["Turn on automatic security updates where your host allows it.", "Re-run Sentinel after major upgrades."],
    });
  }
  return {
    source: "rules",
    summary: steps.some((s) => s.priority === "high")
      ? "Start with the high-priority items. Each step below is small and reversible."
      : "No urgent problems found from public signals. These steps tighten what is left.",
    steps,
    verify: ["Re-run Sentinel after each change.", "Open the site in a private window and check key pages still work."],
    notes: ["Back up before changing server configuration.", "Sentinel only sees public signals. It cannot confirm what is inside your server."],
  };
}
