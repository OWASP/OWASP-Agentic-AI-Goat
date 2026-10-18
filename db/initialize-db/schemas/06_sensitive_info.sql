-- sensitive_info.db: file access logs, documents (sensitive info challenge)

CREATE TABLE IF NOT EXISTS file_access_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  file_path TEXT NOT NULL,
  access_type TEXT DEFAULT 'read',
  status TEXT DEFAULT 'success',
  ip_address TEXT,
  user_agent TEXT,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS documents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  filename TEXT NOT NULL,
  file_path TEXT NOT NULL,
  category TEXT DEFAULT 'public',
  access_level TEXT DEFAULT 'user',
  description TEXT,
  uploaded_by INTEGER,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Existing legacy namespace; no canonical FinFlow objective aliases.
CREATE TABLE IF NOT EXISTS challenge_progress (
 id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,challenge_type TEXT NOT NULL,
 flag_found TEXT,exploit_used TEXT,payload TEXT,success INTEGER DEFAULT 0,
 run_id TEXT,judgment TEXT,timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(run_id,challenge_type)
);
