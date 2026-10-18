-- secureshop_agents.db — new SQLite file for agent runtime, MCP registry, audit, vector store

CREATE TABLE IF NOT EXISTS agent_sessions (
  id TEXT PRIMARY KEY,                     -- uuid
  user_id INTEGER NOT NULL,
  role TEXT NOT NULL,                      -- customer | merchant | admin
  messages_json TEXT NOT NULL DEFAULT '[]',
  token_budget_used INTEGER NOT NULL DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS agent_trace (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL,
  step INTEGER NOT NULL,
  actor TEXT NOT NULL,                     -- supervisor | supervisor→task | task→supervisor | task→task
  kind TEXT NOT NULL,                      -- llm_call_start | mcp_call | mcp_result | final | error
  agent_ns TEXT,
  tool_name TEXT,
  params_json TEXT,
  result_json TEXT,
  latency_ms INTEGER,
  tokens_in INTEGER,
  tokens_out INTEGER,
  provider TEXT,
  ts DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (session_id) REFERENCES agent_sessions(id)
);

CREATE INDEX IF NOT EXISTS idx_agent_trace_session ON agent_trace(session_id);
CREATE INDEX IF NOT EXISTS idx_agent_trace_ts ON agent_trace(ts);

CREATE TABLE IF NOT EXISTS mcp_registry (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE NOT NULL,
  url TEXT,
  transport TEXT NOT NULL,                 -- sse | stdio
  stdio_cmd TEXT,
  status TEXT DEFAULT 'unknown',
  last_schema_hash TEXT,
  added_by INTEGER,
  added_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS mcp_tool_cache (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  server_name TEXT NOT NULL,
  tool_name TEXT NOT NULL,
  description TEXT,
  input_schema_json TEXT,
  cached_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(server_name, tool_name)
);

CREATE TABLE IF NOT EXISTS audit_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT,
  params_json TEXT,
  ip TEXT,
  user_agent TEXT,
  ts DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_audit_events_ts ON audit_events(ts);

CREATE TABLE IF NOT EXISTS vector_documents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source_kind TEXT NOT NULL,               -- review | manual | policy | product_desc
  source_id INTEGER NOT NULL,
  chunk_index INTEGER NOT NULL,
  text TEXT NOT NULL,
  embedding_json TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_vector_documents_source ON vector_documents(source_kind, source_id);

CREATE TABLE IF NOT EXISTS vector_index_meta (
  corpus TEXT PRIMARY KEY,                 -- reviews | manuals | policies | products
  dim INTEGER NOT NULL,
  count INTEGER NOT NULL DEFAULT 0,
  last_rebuilt_at DATETIME,
  embedder_model TEXT
);

CREATE TABLE IF NOT EXISTS background_jobs (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  payload_json TEXT,
  status TEXT DEFAULT 'pending',           -- pending | running | done | failed
  result_json TEXT,
  error_text TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  started_at DATETIME,
  finished_at DATETIME
);

CREATE TABLE IF NOT EXISTS agent_provider_state (
  role TEXT PRIMARY KEY,                   -- customer | merchant | admin
  active_provider TEXT,
  last_success_at DATETIME,
  fallback_cursor INTEGER DEFAULT 0
);
