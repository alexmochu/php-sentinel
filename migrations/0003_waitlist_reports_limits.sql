-- 0003: Pro waitlist, abuse/removal reports, scan opt-outs, rate limiting.

CREATE TABLE IF NOT EXISTS waitlist (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  email      TEXT NOT NULL UNIQUE,
  role       TEXT,                -- site_owner | agency | freelancer | host | security | other
  interests  TEXT,                -- comma list: ai_fixes,monitoring,reports,api
  site_url   TEXT,
  source     TEXT,
  consent    INTEGER NOT NULL DEFAULT 1,
  ip         TEXT,                -- salted hash
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS reports (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  kind       TEXT NOT NULL,       -- removal | opt_out | abuse | security | other
  email      TEXT NOT NULL,
  domain     TEXT,
  details    TEXT NOT NULL,
  status     TEXT NOT NULL DEFAULT 'open',   -- open | done | rejected
  ip         TEXT,                -- salted hash
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Domains whose owners asked us not to scan them. Add rows by hand after verifying the request.
CREATE TABLE IF NOT EXISTS opt_outs (
  domain     TEXT PRIMARY KEY,    -- lowercase, no scheme, no path. Subdomains are covered too.
  note       TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS rate_events (
  key        TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_rate_key_time ON rate_events(key, created_at);
