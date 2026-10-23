export async function onRequestPost(context) {
  const { request, env } = context;
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";

  // Rate limit
  try {
    const recent = await env.DB.prepare(
      "SELECT COUNT(*) as c FROM scans WHERE ip = ? AND created_at > datetime('now', '-1 minute')"
    )
      .bind(ip)
      .first();
    if ((recent?.c || 0) >= 8) {
      return json({ error: "Too many requests. Please wait a minute and try again." }, 429);
    }
  } catch (e) {
    console.error("rate limit query:", e);
  }

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
      return json(
        { error: "Invalid URL. Example: example.com or https://shop.example.com" },
        400
      );
    }

    const normalized = url.origin + (url.pathname === "/" ? "" : url.pathname);

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 9000);

    let response;
    try {
      response = await fetch(normalized, {
        method: "GET",
        redirect: "follow",
        signal: controller.signal,
        headers: {
          "User-Agent": "PHP-Sentinel/1.0 (+https://sentinel.kejanigarage.com)",
          Accept: "text/html,application/xhtml+xml",
        },
      });
    } catch {
      clearTimeout(timeout);
      const errPayload = {
        status: "error",
        message: "Could not reach the website. It may be down or blocking requests.",
        tip: "Check the URL and try again.",
        url: normalized,
        tech_signals: [],
      };
      await saveScan(env, {
        rawUrl,
        normalized,
        status: "error",
        phpVersion: null,
        phpBranch: null,
        supportStatus: null,
        framework: null,
        xPoweredByExposed: 0,
        techSignalsJson: "[]",
        details: "Fetch failed",
        userAgent: request.headers.get("User-Agent") || "",
        ip,
        country: request.headers.get("CF-IPCountry") || null,
      });
      return json(errPayload);
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
      bodyText = (await response.text()).slice(0, 140000).toLowerCase();
    } catch {
      bodyText = "";
    }

    let phpVersion = null;
    const versionMatch = (poweredBy + " " + serverHdr).match(
      /php\/([0-9]+\.[0-9]+\.[0-9]+)/i
    );
    if (versionMatch) phpVersion = versionMatch[1];

    const frameworks = [];
    if (
      bodyText.includes("wp-content") ||
      bodyText.includes("wp-includes") ||
      bodyText.includes("wordpress")
    )
      frameworks.push("WordPress");
    if (bodyText.includes("laravel")) frameworks.push("Laravel");
    if (bodyText.includes("joomla") || bodyText.includes("/media/system/"))
      frameworks.push("Joomla");
    if (bodyText.includes("magento") || bodyText.includes("mage/"))
      frameworks.push("Magento");
    if (bodyText.includes("drupal") || bodyText.includes("data-drupal-"))
      frameworks.push("Drupal");

    const framework = frameworks[0] || null;
    const isPhp =
      !!phpVersion ||
      poweredBy.includes("php") ||
      frameworks.length > 0 ||
      bodyText.includes("phpsessid") ||
      bodyText.includes("php/");

    const techSignals = [];
    if (framework) techSignals.push(framework);
    if (
      bodyText.includes("__next") ||
      bodyText.includes("_next/static") ||
      bodyText.includes("next.js")
    )
      techSignals.push("JavaScript frontend (React/Next-style signals)");
    else if (bodyText.includes("react") || bodyText.includes("data-reactroot"))
      techSignals.push("JavaScript frontend (React-style signals)");
    if (bodyText.includes("nuxt") || bodyText.includes("__nuxt"))
      techSignals.push("JavaScript frontend (Vue/Nuxt-style signals)");
    else if (bodyText.includes("data-v-") && bodyText.includes("vue"))
      techSignals.push("JavaScript frontend (Vue-style signals)");
    if (bodyText.includes("ng-version"))
      techSignals.push("JavaScript frontend (Angular-style signals)");
    if (serverHdr.includes("cloudflare") || headers["cf-ray"])
      techSignals.push("Cloudflare");
    if (serverHdr.includes("nginx")) techSignals.push("Nginx");
    if (serverHdr.includes("apache")) techSignals.push("Apache");
    if (poweredBy.includes("express") || serverHdr.includes("express"))
      techSignals.push("Node.js / Express-style signals");
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

    if (phpVersion) {
      const parts = phpVersion.split(".").map(Number);
      const maj = parts[0];
      const min = parts[1];
      const pat = parts[2] || 0;
      phpBranch = `${maj}.${min}`;

      if (maj === 8 && min >= 4) supportStatus = "Active";
      else if (maj === 8 && min === 3) supportStatus = "Security-only";
      else if (maj === 8 && min === 2)
        supportStatus = "Security-only (EOL Dec 2026)";
      else supportStatus = "End-of-Life";

      const fixedVer = fixed[phpBranch];
      if (fixedVer) {
        const fixedPat = parseInt(fixedVer.split(".")[2], 10);
        if (pat >= fixedPat) {
          status = "safe";
          message =
            "The detected PHP version includes the official patches for the recent critical vulnerabilities (CVE-2026-109618 and CVE-2026-109619).";
          details = `Detected PHP ${phpVersion}.`;
          tip =
            "Keep PHP updated. If you want help with hardening or modernization, book a free strategy call below.";
        } else {
          status = "vulnerable";
          message =
            "This site appears to be running an unpatched version of PHP affected by critical remote code execution flaws (CVE-2026-109618 and CVE-2026-109619).";
          details = `Detected PHP ${phpVersion}. Upgrade to at least PHP ${fixedVer}.`;
          tip =
            "Upgrade to PHP 8.2.35, 8.3.36, 8.4.27 or 8.5.12 as soon as possible. If you need help, book a free call below.";
        }
      } else {
        status = "vulnerable";
        message =
          "This site appears to be running an unpatched or unsupported PHP version affected by critical remote code execution flaws.";
        details = `Detected PHP ${phpVersion}.`;
        tip =
          "Upgrade to PHP 8.2.35, 8.3.36, 8.4.27 or 8.5.12 as soon as possible. If you need help, book a free call below.";
      }
    } else if (isPhp) {
      status = "hidden";
      message =
        "We detected that this site is running PHP, but the exact version is not shown publicly. That is common and often intentional, but it does not mean the site is patched.";
      details = framework
        ? `Framework signal: ${framework}.`
        : "PHP signals were found without a public version header.";
      tip =
        "Confirm the PHP version in your hosting panel or server. You need 8.2.35, 8.3.36, 8.4.27 or 8.5.12 (or higher). You can also book a free verification call below.";
    } else {
      status = "no_php";
      message = "No clear signs of PHP were found on this URL.";
      details = uniqueSignals.length
        ? "Other public technology signals were found (see below)."
        : "Public headers and page signals did not clearly indicate PHP.";
      tip =
        "This only checks the URL you entered. If you use a separate backend (for example Laravel behind Vue or React), check that domain too. You can still book a free call for a broader review.";
    }

    const hygiene = xPoweredByExposed
      ? "Security hygiene: The X-Powered-By header is exposed. Consider turning expose_php off in php.ini."
      : null;

    const saveResult = await saveScan(env, {
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
      userAgent: request.headers.get("User-Agent") || "",
      ip,
      country: request.headers.get("CF-IPCountry") || null,
    });

    return json({
      status,
      php_version: phpVersion,
      php_branch: phpBranch,
      support_status: supportStatus,
      framework,
      tech_signals: uniqueSignals,
      x_powered_by_exposed: !!xPoweredByExposed,
      message,
      details,
      tip,
      hygiene,
      url: normalized,
      checked_at: new Date().toISOString(),
      saved: saveResult.ok,
      save_error: saveResult.error || null,
    });
  } catch (err) {
    console.error(err);
    return json(
      { error: "Something went wrong while scanning. Please try again." },
      500
    );
  }
}

async function saveScan(env, row) {
  try {
    await env.DB.prepare(
      `INSERT INTO scans (
        url, normalized_url, status, php_version, php_branch, support_status,
        framework, x_powered_by, tech_signals, details, user_agent, ip, country
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(
        row.rawUrl,
        row.normalized,
        row.status,
        row.phpVersion,
        row.phpBranch,
        row.supportStatus,
        row.framework,
        row.xPoweredByExposed,
        row.techSignalsJson,
        row.details,
        row.userAgent,
        row.ip,
        row.country
      )
      .run();
    return { ok: true };
  } catch (e) {
    console.error("D1 save error:", e);
    // Fallback without tech_signals if column missing
    try {
      await env.DB.prepare(
        `INSERT INTO scans (
          url, normalized_url, status, php_version, php_branch, support_status,
          framework, x_powered_by, details, user_agent, ip, country
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
        .bind(
          row.rawUrl,
          row.normalized,
          row.status,
          row.phpVersion,
          row.phpBranch,
          row.supportStatus,
          row.framework,
          row.xPoweredByExposed,
          row.details,
          row.userAgent,
          row.ip,
          row.country
        )
        .run();
      return { ok: true, error: "saved_without_tech_signals" };
    } catch (e2) {
      console.error("D1 fallback save error:", e2);
      return { ok: false, error: String(e2) };
    }
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