-- 0001: scans table (moved from schema.sql). Safe to run on an existing database.
CREATE TABLE IF NOT EXISTS scans (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  url            TEXT NOT NULL,
  normalized_url TEXT NOT NULL,
  status         TEXT NOT NULL CHECK(status IN ('vulnerable','hidden','safe','no_php','error')),
  php_version    TEXT,
  php_branch     TEXT,               -- e.g. 8.3
  support_status TEXT,               -- Active / Security-only / End-of-Life
  framework      TEXT,
  x_powered_by   INTEGER DEFAULT 0,  -- 1 if the header was exposed
  tech_signals   TEXT,
  details        TEXT,
  user_agent     TEXT,
  ip             TEXT,               -- salted SHA-256 hash of the visitor IP (never the raw IP)
  country        TEXT,               -- from CF-IPCountry
  created_at     DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_scans_created    ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_status     ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_normalized ON scans(normalized_url);
CREATE INDEX IF NOT EXISTS idx_scans_ip         ON scans(ip);
