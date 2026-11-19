// Single source of truth for PHP advisory data.
//
// BEFORE EACH RELEASE: confirm these IDs and versions against https://www.php.net/supported-versions.php
// and https://www.php.net/ChangeLog-8.php, then set last_verified to today's date.

export const ADVISORY = {
  last_verified: null, // e.g. "2026-11-18" once you have checked the values below
  ids: ["CVE-2026-109618", "CVE-2026-109619"],
  fixed_versions: { "8.5": "8.5.12", "8.4": "8.4.27", "8.3": "8.3.36", "8.2": "8.2.35" },
};

export function supportStatusFor(major, minor) {
  if (major === 8 && minor >= 4) return "Active";
  if (major === 8 && minor === 3) return "Security-only";
  if (major === 8 && minor === 2) return "Security-only (EOL Dec 2026)";
  return "End-of-Life";
}

export function fixedVersionList() {
  return Object.values(ADVISORY.fixed_versions);
}
