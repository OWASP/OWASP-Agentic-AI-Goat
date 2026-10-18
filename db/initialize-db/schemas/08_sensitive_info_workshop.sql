-- sensitive_info_workshop.db: FinFlow VaultCorp workshop tables (all 4 finflow_ tables live here)

-- User objective completion tracking
CREATE TABLE IF NOT EXISTS finflow_progress (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  objective_id TEXT NOT NULL,
  completed INTEGER DEFAULT 0,
  completed_at DATETIME,
  UNIQUE(user_id, objective_id)
);

-- Audit log of all VaultCorp tool calls
CREATE TABLE IF NOT EXISTS finflow_tool_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  tool_name TEXT NOT NULL,
  params TEXT,
  result_summary TEXT,
  security_flag TEXT,
  mode TEXT,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Admin toggle: which objectives have solutions shown to students
CREATE TABLE IF NOT EXISTS finflow_solution_visibility (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  objective_id TEXT NOT NULL UNIQUE,
  solutions_enabled INTEGER DEFAULT 1,
  enabled_by INTEGER,
  enabled_at DATETIME,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO finflow_solution_visibility (objective_id, solutions_enabled) VALUES
  ('tool_enum',1),('llm_identify',1),('tool_version',1),('traversal_secrets',1),
  ('traversal_passwd',1),('traversal_llm',1),('ssrf_oob',1),('ssrf_internal',1),
  ('ssrf_ollama',1),('error_leak',1),('admin_enum',1),
  ('admin_backup',1),('admin_dl_backup',1),('admin_read_logs',1),('admin_llm_logs',1),
  ('admin_modify_logs',1),('admin_secrets',1),('admin_dirlist',1);

-- Student-facing solution content (seeded by 08_sensitive_info_workshop.js)
CREATE TABLE IF NOT EXISTS finflow_solutions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  objective_id TEXT NOT NULL UNIQUE,
  title TEXT NOT NULL,
  difficulty TEXT,
  hints TEXT,    -- JSON array
  examples TEXT, -- JSON array of {prompt, explanation}
  approach TEXT,
  tips TEXT,     -- JSON array
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Legacy workshop tables (kept for backward compatibility)
CREATE TABLE IF NOT EXISTS workshop_progress (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  level INTEGER NOT NULL,
  challenge_name TEXT NOT NULL,
  status TEXT DEFAULT 'locked',
  attempts INTEGER DEFAULT 0,
  hints_used INTEGER DEFAULT 0,
  milestones TEXT DEFAULT '{}',
  time_spent INTEGER DEFAULT 0,
  completed_at DATETIME,
  UNIQUE(user_id, level)
);

CREATE TABLE IF NOT EXISTS workshop_achievements (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  achievement_name TEXT NOT NULL,
  achievement_description TEXT,
  earned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id, achievement_name)
);

CREATE TABLE IF NOT EXISTS workshop_chat_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  level INTEGER NOT NULL,
  message_type TEXT NOT NULL,
  message TEXT,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS extracted_files (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  level INTEGER NOT NULL,
  file_path TEXT NOT NULL,
  file_content TEXT,
  extraction_method TEXT,
  flag_found TEXT,
  extracted_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS file_registry (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  file_path TEXT UNIQUE NOT NULL,
  tier TEXT NOT NULL,
  flag TEXT,
  description TEXT,
  requires_bypass TEXT
);
