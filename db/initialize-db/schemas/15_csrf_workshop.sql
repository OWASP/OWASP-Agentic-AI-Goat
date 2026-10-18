-- ============================================================================
-- CSRF Workshop database (csrf_workshop.db)
-- ----------------------------------------------------------------------------
-- Per-user wallet, objective progress, and a durable activity log so the
-- "Tool Activity" panel survives a refresh and an instructor view can replay
-- each student's session later.
--
-- Mirrors the CREATE TABLE statements in server/database/csrfWorkshopDb.js so
-- `npm run db:initialize-all` reproduces this DB from scratch.
-- ============================================================================

CREATE TABLE IF NOT EXISTS csrf_workshop_wallets (
  user_key   TEXT PRIMARY KEY NOT NULL,
  balance    INTEGER NOT NULL DEFAULT 10000,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS csrf_workshop_progress (
  user_key     TEXT NOT NULL,
  objective_id TEXT NOT NULL,
  completed    INTEGER DEFAULT 0,
  completed_at DATETIME,
  created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_key, objective_id)
);

CREATE TABLE IF NOT EXISTS csrf_workshop_tool_log (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  user_key        TEXT NOT NULL,
  exercise_id     TEXT,
  tool_name       TEXT NOT NULL,
  args            TEXT,
  result_summary  TEXT,
  flag            TEXT,
  success         INTEGER DEFAULT 1,
  created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_csrf_tool_log_user
  ON csrf_workshop_tool_log(user_key, id DESC);
