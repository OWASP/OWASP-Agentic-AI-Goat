-- ============================================================================
-- MCP Workshop database (mcp_workshop.db)
-- ----------------------------------------------------------------------------
-- Per-user objective progress and a durable tool-call activity log.
-- Mirrors CREATE TABLE statements in server/database/mcpWorkshopDb.js.
-- ============================================================================

CREATE TABLE IF NOT EXISTS mcp_workshop_progress (
  user_key     TEXT NOT NULL,
  objective_id TEXT NOT NULL,
  completed    INTEGER DEFAULT 0,
  completed_at DATETIME,
  created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_key, objective_id)
);

CREATE TABLE IF NOT EXISTS mcp_workshop_tool_log (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  user_key        TEXT NOT NULL,
  tool_name       TEXT NOT NULL,
  args            TEXT,
  result_summary  TEXT,
  outcome         TEXT,
  success         INTEGER DEFAULT 1,
  created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_mcp_tool_log_user
  ON mcp_workshop_tool_log(user_key, id DESC);
