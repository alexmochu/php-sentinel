// Turns detection results into a status and human-readable guidance.

import { ADVISORY, supportStatusFor } from "./patch-data.js";

const CAVEAT =
  "This verdict uses the version the server reports. Some hosts (for example Debian, Ubuntu and cPanel builds) " +
  "backport fixes without changing the version string, so confirm the real patch level on the server.";

export function buildVerdict({ phpVersion, isPhp, framework, uniqueSignals }) {
  const fixed = ADVISORY.fixed_versions;
  const ids = ADVISORY.ids.join(" and ");
  const list = Object.values(fixed).join(", ");
  const v = {
    status: "no_php",
    message: "",
    details: "",
    tip: "",
    caveat: null,
    support_status: null,
    php_branch: null,
    playbook: null,
    host_guidance: null,
  };

  if (phpVersion) {
    const [maj, min, pat] = phpVersion.split(".").map(Number);
    v.php_branch = `${maj}.${min}`;
    v.support_status = supportStatusFor(maj, min);
    const fixedVer = fixed[v.php_branch];
    if (fixedVer && pat >= parseInt(fixedVer.split(".")[2], 10)) {
      v.status = "safe";
      v.message = `The reported PHP version includes the official patches for the recent critical vulnerabilities (${ids}).`;
      v.details = `Detected PHP ${phpVersion}.`;
      v.tip = "Keep PHP updated. For hardening or modernization help, book a free strategy call below.";
      v.host_guidance =
        "On shared hosting, use the panel's PHP selector and stay on a supported branch. On a VPS, pin a supported package source and automate patching.";
    } else {
      v.status = "vulnerable";
      v.message = `This site appears to run a PHP version that is behind the fixes for critical remote code execution flaws (${ids}).`;
      v.details = fixedVer ? `Detected PHP ${phpVersion}. Upgrade to at least PHP ${fixedVer}.` : `Detected PHP ${phpVersion}.`;
      v.tip = `Upgrade to PHP ${list.replace(/, ([^,]*)$/, " or $1")} as soon as possible. If you need help, book a free call below.`;
      v.caveat = CAVEAT;
      v.host_guidance =
        "Shared hosting: switch PHP version in cPanel/Plesk, then retest. VPS: update packages or rebuild the runtime, then restart PHP-FPM/Apache.";
    }
  } else if (isPhp) {
    v.status = "hidden";
    v.message =
      "We detected that this site is running PHP, but the exact version is not shown publicly. That is common and often intentional, but it does not mean the site is patched.";
    v.details = framework ? `Framework signal: ${framework}.` : "PHP signals were found without a public version header.";
    v.tip = `Confirm the PHP version on the server. You need ${list.replace(/, ([^,]*)$/, " or $1")} (or higher).`;
    v.playbook = [
      "cPanel: MultiPHP Manager or Select PHP Version",
      "Plesk: PHP Settings for the domain",
      "SSH/VPS: run php -v",
      "WordPress: Site Health → Info → Server (if available)",
      "After upgrading, re-run this check",
    ];
    v.host_guidance =
      "Hiding the version is good hygiene. Still verify the real version in the panel or via SSH so you are not stuck on an unpatched build.";
  } else {
    v.status = "no_php";
    v.message = "No clear signs of PHP were found on this URL.";
    v.details = uniqueSignals.length
      ? "Other public technology signals were found (see below)."
      : "Public headers and page signals did not clearly indicate PHP.";
    v.tip =
      "This only checks the URL you entered. If you use a separate backend (for example Laravel behind Vue or React), check that domain too.";
    v.host_guidance =
      "If this is a JS frontend with a separate API, run Sentinel on the API host as well (for example api.yourdomain.com).";
  }
  return v;
}
