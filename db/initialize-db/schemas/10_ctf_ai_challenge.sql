-- ctf_ai_challenge.db: isolated CTF AI interaction logs
CREATE TABLE IF NOT EXISTS ctf_ai_interactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL,
  level_id INTEGER NOT NULL,
  user_prompt TEXT NOT NULL,
  ai_response TEXT,
  secret_extracted INTEGER DEFAULT 0,
  extraction_method TEXT,
  success INTEGER DEFAULT 0,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ctf_level_attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL,
  level_id INTEGER NOT NULL,
  attempt_number INTEGER DEFAULT 1,
  success INTEGER DEFAULT 0,
  time_taken INTEGER,
  hints_used INTEGER DEFAULT 0,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ctf_leaderboard (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  anonymous_id TEXT NOT NULL,
  levels_completed INTEGER DEFAULT 0,
  total_time INTEGER DEFAULT 0,
  total_attempts INTEGER DEFAULT 0,
  completion_date DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
