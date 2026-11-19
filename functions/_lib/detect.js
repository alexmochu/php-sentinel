// Passive technology detection from public response headers and HTML.

export function extractPhpVersion(headers) {
  const hay = `${headers["x-powered-by"] || ""} ${headers["server"] || ""}`;
  const m = /php\/(\d+\.\d+\.\d+)/i.exec(hay);
  return m ? m[1] : null;
}

/** Keep only plain characters from text that came from someone else's website. */
export function sanitizeSignal(value) {
  return String(value || "").replace(/[^\w .\-+/()]/g, "").replace(/\s+/g, " ").trim().slice(0, 80);
}

function generatorMeta(bodyText) {
  const m =
    /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i.exec(bodyText) ||
    /<meta[^>]+content=["']([^"']+)["'][^>]+name=["']generator["']/i.exec(bodyText);
  return m ? sanitizeSignal(m[1]) : "";
}

export function detectFrameworks(bodyText, bodyLower, headers, cookies) {
  const frameworks = [];
  const cms = [];
  const gen = generatorMeta(bodyText);
  const cookieLower = String(cookies || "").toLowerCase();

  if (/wp-content|wp-includes|\/wp-json\//.test(bodyLower) || /wordpress/i.test(gen)) {
    frameworks.push("WordPress");
    cms.push(/wordpress/i.test(gen) ? `Generator: ${gen}` : "WordPress paths detected (generator meta not public)");
  }
  if (cookieLower.includes("laravel_session") || bodyLower.includes("/vendor/laravel")) {
    frameworks.push("Laravel");
  }
  if (/joomla/i.test(gen) || bodyLower.includes("/media/system/js/")) {
    frameworks.push("Joomla");
    cms.push("Joomla-style paths detected");
  }
  if (
    Object.keys(headers).some((h) => h.startsWith("x-magento-")) ||
    bodyLower.includes("mage/cookies") ||
    bodyLower.includes("magento_")
  ) {
    frameworks.push("Magento");
    cms.push("Magento-style signals detected");
  }
  if (/drupal/i.test(gen) || bodyLower.includes("data-drupal-") || bodyLower.includes("drupal-settings-json")) {
    frameworks.push("Drupal");
    cms.push("Drupal-style signals detected");
  }
  return { frameworks, cms_signals: cms };
}

export function detectIsPhp({ phpVersion, headers, frameworks, cookies, bodyLower }) {
  const poweredBy = (headers["x-powered-by"] || "").toLowerCase();
  return (
    !!phpVersion ||
    poweredBy.includes("php") ||
    frameworks.length > 0 ||
    String(cookies || "").toLowerCase().includes("phpsessid") ||
    /href=["'][^"']+\.php(\?|["'#])/.test(bodyLower)
  );
}

export function detectTechSignals({ framework, isPhp, bodyLower, headers }) {
  const out = [];
  const server = (headers["server"] || "").toLowerCase();
  if (framework) out.push(framework);
  if (bodyLower.includes("_next/static") || bodyLower.includes("__next_data__")) {
    out.push("JavaScript frontend (React/Next-style signals)");
  } else if (bodyLower.includes("data-reactroot")) {
    out.push("JavaScript frontend (React-style signals)");
  }
  if (bodyLower.includes("/_nuxt/") || bodyLower.includes("__nuxt")) {
    out.push("JavaScript frontend (Vue/Nuxt-style signals)");
  }
  if (bodyLower.includes("ng-version")) out.push("JavaScript frontend (Angular-style signals)");
  if (server.includes("cloudflare") || headers["cf-ray"]) out.push("Cloudflare");
  if (server.includes("nginx")) out.push("Nginx");
  if (server.includes("apache")) out.push("Apache");
  if (isPhp && !framework) out.push("PHP application signals");
  return [...new Set(out)];
}
