export async function onRequestPost(context) {
  const { request, env } = context;

  // ----- Simple rate limiting (per IP) -----
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const rateKey = `rate:${ip}`;
  const current = parseInt(await env.DB.prepare("SELECT COUNT(*) as c FROM scans WHERE ip = ? AND created_at > datetime('now', '-1 minute')").bind(ip).first().then(r => r?.c || 0));
  
  if (current >= 8) { // max 8 scans per minute per IP
    return json({ error: "Too many requests. Please wait a minute and try again." }, 429);
  }

  try {
    const body = await request.json();
    let rawUrl = (body.url || "").trim();

    if (!rawUrl) {
      return json({ error: "Please enter a website URL" }, 400);
    }

    // Normalize URL
    let url;
    try {
      if (!/^https?:\/\//i.test(rawUrl)) rawUrl = "https://" + rawUrl;
      url = new URL(rawUrl);

      if (url.hostname === "localhost" || url.hostname.endsWith(".local") ||
          /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)/.test(url.hostname)) {
        return json({ error: "Local or private addresses are not allowed" }, 400);
      }
    } catch {
      return json({ error: "Invalid URL. Example: example.com or https://shop.example.com" }, 400);
    }

    const normalized = url.origin + (url.pathname === "/" ? "" : url.pathname);

    // Fetch
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
          "Accept": "text/html,application/xhtml+xml",
        },
      });
    } catch (err) {
      clearTimeout(timeout);
      return json({
        status: "error",
        message: "Could not reach the website. It may be down or blocking requests.",
        url: normalized
      });
    }
    clearTimeout(timeout);

    const headers = Object.fromEntries([...response.headers].map(([k, v]) => [k.toLowerCase(), v]));
    const poweredBy = (headers["x-powered-by"] || "").toLowerCase();
    const serverHdr = (headers["server"] || "").toLowerCase();
    const xPoweredByExposed = poweredBy.includes("php") ? 1 : 0;

    let bodyText = "";
    try {
      bodyText = (await response.text()).slice(0, 140000).toLowerCase();
    } catch {}

    // Detect version
    let phpVersion = null;
    const versionMatch = (poweredBy + " " + serverHdr).match(/php\/([0-9]+\.[0-9]+\.[0-9]+)/i);
    if (versionMatch) phpVersion = versionMatch[1];

    // Framework detection
    const frameworks = [];
    if (bodyText.includes("wp-content") || bodyText.includes("wp-includes") || bodyText.includes("wordpress")) frameworks.push("WordPress");
    if (bodyText.includes("laravel") || bodyText.includes("csrf-token")) frameworks.push("Laravel");
    if (bodyText.includes("joomla") || bodyText.includes("/media/system/")) frameworks.push("Joomla");
    if (bodyText.includes("magento") || bodyText.includes("mage/")) frameworks.push("Magento");
    if (bodyText.includes("drupal") || bodyText.includes("data-drupal-")) frameworks.push("Drupal");

    const framework = frameworks[0] || null;
    const isPhp = !!phpVersion || poweredBy.includes("php") || frameworks.length > 0 || bodyText.includes("phpsessid");

    // Support status calculation
    let supportStatus = null;
    let phpBranch = null;
    if (phpVersion) {
      const [maj, min] = phpVersion.split(".").map(Number);
      phpBranch = `${maj}.${min}`;
      if (maj === 8 && min >= 4) supportStatus = "Active";
      else if (maj === 8 && min === 3) supportStatus = "Security-only";
      else if (maj === 8 && min === 2) supportStatus = "Security-only (EOL Dec 2026)";
      else supportStatus = "End-of-Life";
    }

    // Decision
    let status = "no_php";
    let message = "";
    let details = "";
    let tip = "";

    const fixed = { "8.5": "8.5.12", "8.4": "8.4.27", "8.3": "8.3.36", "8.2": "8.2.35" };

    if (phpVersion) {
      const [maj, min, pat] = phpVersion.split(".").map(Number);
      const branch = `${maj}.${min}`;
      const fixedVer = fixed[branch];

      if (fixedVer) {
        const fixedPat = parseInt(fixedVer.split(".")[2]);
        if (pat >= fixedPat) {
          status = "safe";
          message = `Your site is running PHP ${phpVersion}. This version includes the official patches for CVE-2026-109618 and CVE-2026-109619 (PHP2Shell).`;
          details = `Patched version detected.`;
          tip = "Keep your PHP version updated and consider hiding the X-Powered-By header for better security hygiene.";
        } else {
          status = "vulnerable";
          message = `Your site is running PHP ${phpVersion}, which is vulnerable to the critical PHP2Shell remote code execution flaws.`;
          details = `Upgrade immediately to at least PHP ${fixedVer}.`;
          tip = "Contact your hosting provider or developer right away. Unauthenticated attackers can run code on your server.";
        }
      } else {
        status = "vulnerable";
        message = `Your site is running PHP ${phpVersion}. This version is no longer supported and is vulnerable to PHP2Shell.`;
        details = "Upgrade to PHP 8.2.35, 8.3.36, 8.4.27 or 8.5.12 as soon as possible.";
        tip = "Older PHP versions no longer receive security patches. This is a high-priority upgrade.";
      }
    } else if (isPhp) {
      status = "hidden";
      message = framework
        ? `We detected ${framework} (which runs on PHP). The exact PHP version is hidden.`
        : "We detected clear signs that this site runs on PHP, but the exact version is hidden.";
      details = "Hiding the version is good practice, but you must still verify on the server that you are on a patched release.";
      tip = "Log into your hosting panel or server and confirm the PHP version is 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 or higher.";
    } else {
      status = "no_php";
      message = "No clear evidence that this website is running PHP was found.";
      details = "It may be a static site, Node.js, Python, or another stack.";
      tip = "If you expected PHP, double-check the URL or try the main domain.";
    }

    // Hygiene note
    let hygiene = null;
    if (xPoweredByExposed) {
      hygiene = "Security hygiene: The X-Powered-By header is exposed. Consider setting expose_php = Off in php.ini.";
    }

    // Save to D1
    try {
      await env.DB.prepare(`
        INSERT INTO scans 
        (url, normalized_url, status, php_version, php_branch, support_status, framework, x_powered_by, details, user_agent, ip, country)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        rawUrl,
        normalized,
        status,
        phpVersion,
        phpBranch,
        supportStatus,
        framework,
        xPoweredByExposed,
        details,
        request.headers.get("User-Agent") || "",
        ip,
        request.headers.get("CF-IPCountry") || null
      ).run();
    } catch (dbErr) {
      console.error("D1 save error:", dbErr);
    }

    return json({
      status,
      php_version: phpVersion,
      php_branch: phpBranch,
      support_status: supportStatus,
      framework,
      x_powered_by_exposed: !!xPoweredByExposed,
      message,
      details,
      tip,
      hygiene,
      url: normalized,
      checked_at: new Date().toISOString()
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