-- 0002: contact messages. message.js already wrote to this table, but it was missing from schema.sql.
-- IF NOT EXISTS keeps this safe if production already has it.
CREATE TABLE IF NOT EXISTS messages (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  email       TEXT NOT NULL,
  message     TEXT NOT NULL,
  site_url    TEXT,
  phone       TEXT,
  scan_status TEXT,
  wants_call  INTEGER DEFAULT 0,
  source      TEXT,
  ip          TEXT,               -- salted hash
  user_agent  TEXT,
  notified    INTEGER DEFAULT 0,
  created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_messages_created ON messages(created_at DESC);
