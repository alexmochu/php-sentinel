export async function onRequestPost(context) {
  const { request, env } = context;
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";

  try {
    const recent = await env.DB.prepare(
      "SELECT COUNT(*) as c FROM scans WHERE ip = ? AND created_at > datetime('now', '-1 minute')"
    ).bind(ip).first();
    if ((recent?.c || 0) >= 8) {
      return json({ error: "Too many requests. Please wait a minute and try again." }, 429);
    }
  } catch (_) {}

  try {
    const body = await request.json();
    let rawUrl = (body.url || "").trim();
    if (!rawUrl) return json({ error: "Please enter a website URL" }, 400);

    let url;
    try {
      if (!/^https?:\/\//i.test(rawUrl)) rawUrl = "https://" + rawUrl;
      url = new URL(rawUrl);
      if (
        url.hostname === "localhost" ||
        url.hostname.endsWith(".local") ||
        /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)/.test(url.hostname)
      ) {
        return json({ error: "Local or private addresses are not allowed" }, 400);
      }
    } catch {
      return json({ error: "Invalid URL. Example: example.com or https://shop.example.com" }, 400);
    }

    const normalized = url.origin + (url.pathname === "/" ? "" : url.pathname);
    const isHttps = url.protocol === "https:";

    // Optional HTTP→HTTPS redirect probe
    let redirectsToHttps = null;
    if (isHttps) {
      try {
        const httpUrl = "http://" + url.host + (url.pathname === "/" ? "" : url.pathname);
        const httpRes = await fetch(httpUrl, {
          method: "GET",
          redirect: "manual",
          headers: { "User-Agent": "Sentinel/1.0 (+https://sentinel.kejanigarage.com)" },
        });
        const loc = httpRes.headers.get("location") || "";
        redirectsToHttps =
          httpRes.status >= 300 &&
          httpRes.status < 400 &&
          /^https:\/\//i.test(loc);
      } catch {
        redirectsToHttps = null;
      }
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 9000);

    let response;
    try {
      response = await fetch(normalized, {
        method: "GET",
        redirect: "follow",
        signal: controller.signal,
        headers: {
          "User-Agent": "Sentinel/1.0 (+https://sentinel.kejanigarage.com)",
          Accept: "text/html,application/xhtml+xml",
        },
      });
    } catch {
      clearTimeout(timeout);
      return json({
        status: "error",
        message: "Could not reach the website. It may be down or blocking requests.",
        tip: "Check the URL and try again.",
        url: normalized,
        tech_signals: [],
        security_headers: null,
        tls: { https: isHttps, redirects_to_https: redirectsToHttps },
      });
    }
    clearTimeout(timeout);

    const headers = Object.fromEntries(
      [...response.headers].map(([k, v]) => [k.toLowerCase(), v])
    );
    const poweredBy = (headers["x-powered-by"] || "").toLowerCase();
    const serverHdr = (headers["server"] || "").toLowerCase();
    const xPoweredByExposed = poweredBy.includes("php") ? 1 : 0;

    let bodyText = "";
    try {
      bodyText = (await response.text()).slice(0, 160000);
    } catch {
      bodyText = "";
    }
    const bodyLower = bodyText.toLowerCase();

    // Security headers snapshot
    const security_headers = {
      https: isHttps,
      hsts: !!(headers["strict-transport-security"]),
      csp: !!(headers["content-security-policy"] || headers["content-security-policy-report-only"]),
      x_frame_options: !!(headers["x-frame-options"]),
      x_content_type_options: !!(headers["x-content-type-options"]),
      referrer_policy: !!(headers["referrer-policy"]),
    };

    const mixedContentHint =
      isHttps &&
      (bodyLower.includes("src=\"http://") ||
        bodyLower.includes("href=\"http://") ||
        bodyLower.includes("src='http://"));

    const tls = {
      https: isHttps,
      redirects_to_https: redirectsToHttps,
      mixed_content_hint: mixedContentHint,
    };

    // PHP version
    let phpVersion = null;
    const versionMatch = (poweredBy + " " + serverHdr).match(
      /php\/([0-9]+\.[0-9]+\.[0-9]+)/i
    );
    if (versionMatch) phpVersion = versionMatch[1];

    // Frameworks + CMS age signals (non-invasive)
    const frameworks = [];
    const cms_signals = [];

    if (
      bodyLower.includes("wp-content") ||
      bodyLower.includes("wp-includes") ||
      bodyLower.includes("wordpress")
    ) {
      frameworks.push("WordPress");
      const gen = bodyText.match(
        /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i
      ) || bodyText.match(
        /content=["']([^"']*WordPress[^"']*)["'][^>]+name=["']generator["']/i
      );
      if (gen && gen[1]) cms_signals.push(`Generator: ${gen[1].slice(0, 80)}`);
      else cms_signals.push("WordPress paths detected (generator meta not public)");
    }
    if (bodyLower.includes("laravel")) frameworks.push("Laravel");
    if (bodyLower.includes("joomla") || bodyLower.includes("/media/system/")) {
      frameworks.push("Joomla");
      cms_signals.push("Joomla-style paths detected");
    }
    if (bodyLower.includes("magento") || bodyLower.includes("mage/")) {
      frameworks.push("Magento");
      cms_signals.push("Magento-style signals detected");
    }
    if (bodyLower.includes("drupal") || bodyLower.includes("data-drupal-")) {
      frameworks.push("Drupal");
      cms_signals.push("Drupal-style signals detected");
    }

    const framework = frameworks[0] || null;
    const isPhp =
      !!phpVersion ||
      poweredBy.includes("php") ||
      frameworks.length > 0 ||
      bodyLower.includes("phpsessid") ||
      bodyLower.includes("php/");

    const techSignals = [];
    if (framework) techSignals.push(framework);
    if (bodyLower.includes("__next") || bodyLower.includes("_next/static"))
      techSignals.push("JavaScript frontend (React/Next-style signals)");
    else if (bodyLower.includes("data-reactroot") || bodyLower.includes("react"))
      techSignals.push("JavaScript frontend (React-style signals)");
    if (bodyLower.includes("__nuxt") || bodyLower.includes("nuxt"))
      techSignals.push("JavaScript frontend (Vue/Nuxt-style signals)");
    if (bodyLower.includes("ng-version"))
      techSignals.push("JavaScript frontend (Angular-style signals)");
    if (serverHdr.includes("cloudflare") || headers["cf-ray"])
      techSignals.push("Cloudflare");
    if (serverHdr.includes("nginx")) techSignals.push("Nginx");
    if (serverHdr.includes("apache")) techSignals.push("Apache");
    if (isPhp && !framework) techSignals.push("PHP application signals");

    const uniqueSignals = [...new Set(techSignals)];
    const techSignalsJson = JSON.stringify(uniqueSignals);

    const fixed = {
      "8.5": "8.5.12",
      "8.4": "8.4.27",
      "8.3": "8.3.36",
      "8.2": "8.2.35",
    };

    let status = "no_php";
    let message = "";
    let details = "";
    let tip = "";
    let supportStatus = null;
    let phpBranch = null;
    let playbook = null;
    let host_guidance = null;

    if (phpVersion) {
      const parts = phpVersion.split(".").map(Number);
      const maj = parts[0], min = parts[1], pat = parts[2] || 0;
      phpBranch = `${maj}.${min}`;
      if (maj === 8 && min >= 4) supportStatus = "Active";
      else if (maj === 8 && min === 3) supportStatus = "Security-only";
      else if (maj === 8 && min === 2) supportStatus = "Security-only (EOL Dec 2026)";
      else supportStatus = "End-of-Life";

      const fixedVer = fixed[phpBranch];
      if (fixedVer && pat >= parseInt(fixedVer.split(".")[2], 10)) {
        status = "safe";
        message =
          "The detected PHP version includes the official patches for the recent critical vulnerabilities (CVE-2026-109618 and CVE-2026-109619).";
        details = `Detected PHP ${phpVersion}.`;
        tip = "Keep PHP updated. For hardening or modernization help, book a free strategy call below.";
        host_guidance =
          "On shared hosting, use the panel’s PHP selector and stay on a supported branch. On a VPS, pin a supported package source and automate patching.";
      } else {
        status = "vulnerable";
        message =
          "This site appears to be running an unpatched version of PHP affected by critical remote code execution flaws (CVE-2026-109618 and CVE-2026-109619).";
        details = fixedVer
          ? `Detected PHP ${phpVersion}. Upgrade to at least PHP ${fixedVer}.`
          : `Detected PHP ${phpVersion}.`;
        tip =
          "Upgrade to PHP 8.2.35, 8.3.36, 8.4.27 or 8.5.12 as soon as possible. If you need help, book a free call below.";
        host_guidance =
          "Shared hosting: switch PHP version in cPanel/Plesk, then retest. VPS: update packages or rebuild the runtime, then restart PHP-FPM/Apache.";
      }
    } else if (isPhp) {
      status = "hidden";
      message =
        "We detected that this site is running PHP, but the exact version is not shown publicly. That is common and often intentional, but it does not mean the site is patched.";
      details = framework
        ? `Framework signal: ${framework}.`
        : "PHP signals were found without a public version header.";
      tip =
        "Confirm the PHP version on the server. You need 8.2.35, 8.3.36, 8.4.27 or 8.5.12 (or higher).";
      playbook = [
        "cPanel: MultiPHP Manager or Select PHP Version",
        "Plesk: PHP Settings for the domain",
        "SSH/VPS: run php -v",
        "WordPress: Site Health → Info → Server (if available)",
        "After upgrading, re-run this check",
      ];
      host_guidance =
        "Hiding the version is good hygiene. Still verify the real version in the panel or via SSH so you are not stuck on an unpatched build.";
    } else {
      status = "no_php";
      message = "No clear signs of PHP were found on this URL.";
      details = uniqueSignals.length
        ? "Other public technology signals were found (see below)."
        : "Public headers and page signals did not clearly indicate PHP.";
      tip =
        "This only checks the URL you entered. If you use a separate backend (for example Laravel behind Vue or React), check that domain too.";
      host_guidance =
        "If this is a JS frontend with a separate API, run Sentinel on the API host as well (for example api.yourdomain.com).";
    }

    const hygiene = xPoweredByExposed
      ? "Security hygiene: The X-Powered-By header is exposed. Consider turning expose_php off in php.ini."
      : null;

    // Suggest API host when no_php
    let api_suggestion = null;
    if (status === "no_php") {
      const host = url.hostname.replace(/^www\./, "");
      api_suggestion = `https://api.${host}`;
    }

    try {
      await env.DB.prepare(
        `INSERT INTO scans (
          url, normalized_url, status, php_version, php_branch, support_status,
          framework, x_powered_by, tech_signals, details, user_agent, ip, country
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
        .bind(
          rawUrl,
          normalized,
          status,
          phpVersion,
          phpBranch,
          supportStatus,
          framework,
          xPoweredByExposed,
          techSignalsJson,
          details,
          request.headers.get("User-Agent") || "",
          ip,
          request.headers.get("CF-IPCountry") || null
        )
        .run();
    } catch (e) {
      console.error("D1 save error", e);
    }

    return json({
      status,
      php_version: phpVersion,
      php_branch: phpBranch,
      support_status: supportStatus,
      framework,
      tech_signals: uniqueSignals,
      cms_signals,
      security_headers,
      tls,
      x_powered_by_exposed: !!xPoweredByExposed,
      message,
      details,
      tip,
      hygiene,
      playbook,
      host_guidance,
      api_suggestion,
      url: normalized,
      checked_at: new Date().toISOString(),
    });
  } catch (err) {
    console.error(err);
    return json({ error: "Something went wrong while scanning. Please try again." }, 500);
  }
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
    },
  });
}