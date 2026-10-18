-- SecureShop v2 M4 admin additions — applied against secureshop_agents.db.
--
-- mcp_schema_history — every schema-hash change per MCP registry entry is
-- appended here. This is what powers the MCP page's "rug-pull timeline".

CREATE TABLE IF NOT EXISTS mcp_schema_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  schema_hash TEXT NOT NULL,
  tools_json TEXT NOT NULL,
  ts DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_mcp_schema_history_name ON mcp_schema_history(name);
CREATE INDEX IF NOT EXISTS idx_mcp_schema_history_ts   ON mcp_schema_history(ts);
