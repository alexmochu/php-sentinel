-- Drop if exists (only for clean start – remove after first successful run)
-- DROP TABLE IF EXISTS scans;

CREATE TABLE IF NOT EXISTS scans (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  url           TEXT NOT NULL,
  normalized_url TEXT NOT NULL,
  status        TEXT NOT NULL CHECK(status IN ('vulnerable','hidden','safe','no_php','error')),
  php_version   TEXT,
  php_branch    TEXT,               -- e.g. 8.3
  support_status TEXT,              -- Active / Security-only / End-of-Life
  framework     TEXT,
  x_powered_by  INTEGER DEFAULT 0,  -- 1 if header was exposed
  tech_signals TEXT,
  details       TEXT,
  user_agent    TEXT,
  ip            TEXT,
  country       TEXT,               -- from CF-IPCountry
  created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_scans_created   ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_status    ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_normalized ON scans(normalized_url);