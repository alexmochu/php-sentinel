// Whitelist and normalise scan findings before they reach the rules engine or the AI model.
// Nothing free-form from the scanned website survives this function.

import { pick } from "./validate.js";

const STATUSES = ["vulnerable", "hidden", "safe", "no_php"];
const FRAMEWORKS = ["WordPress", "Laravel", "Joomla", "Magento", "Drupal"];
const bool = (v) => (v === true ? true : v === false ? false : null);

export function sanitizeFindings(input) {
  const f = input && typeof input === "object" ? input : {};
  const sh = f.security_headers && typeof f.security_headers === "object" ? f.security_headers : {};
  const tls = f.tls && typeof f.tls === "object" ? f.tls : {};
  const version = typeof f.php_version === "string" && /^\d{1,2}\.\d{1,2}\.\d{1,3}$/.test(f.php_version) ? f.php_version : null;
  return {
    status: pick(f.status, STATUSES, "no_php"),
    php_version: version,
    framework: pick(f.framework, FRAMEWORKS, null),
    x_powered_by_exposed: f.x_powered_by_exposed === true,
    security_headers: {
      https: bool(sh.https), hsts: bool(sh.hsts), csp: bool(sh.csp),
      x_frame_options: bool(sh.x_frame_options), x_content_type_options: bool(sh.x_content_type_options),
      referrer_policy: bool(sh.referrer_policy),
    },
    tls: { https: bool(tls.https), redirects_to_https: bool(tls.redirects_to_https), mixed_content_hint: tls.mixed_content_hint === true },
  };
}

