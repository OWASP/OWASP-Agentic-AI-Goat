-- Supply Chain RCE Lab workshop database schema

CREATE TABLE IF NOT EXISTS sc_progress (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  objective_id TEXT NOT NULL,
  status TEXT DEFAULT 'pending',
  completed_at DATETIME,
  UNIQUE(user_id, objective_id)
);

CREATE TABLE IF NOT EXISTS sc_solution_visibility (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  objective_id TEXT UNIQUE NOT NULL,
  solutions_enabled INTEGER DEFAULT 1,
  enabled_by TEXT,
  enabled_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sc_solutions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  objective_id TEXT UNIQUE NOT NULL,
  title TEXT,
  difficulty TEXT,
  hints TEXT,
  examples TEXT,
  approach TEXT,
  tips TEXT,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO sc_solution_visibility (objective_id, solutions_enabled)
  VALUES ('clean_request', 1), ('tool_list', 1), ('pkg_discover', 1), ('rce_env', 1), ('rce_ssh', 1);
