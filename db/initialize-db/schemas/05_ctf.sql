-- ctf.db: CTF config, participants, stages, progress, attempts, leaderboard, adaptive blocklists
CREATE TABLE IF NOT EXISTS ctf_config (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key TEXT UNIQUE NOT NULL,
  value TEXT NOT NULL,
  description TEXT,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ctf_participants (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER UNIQUE NOT NULL,
  username TEXT NOT NULL,
  email TEXT,
  team_name TEXT,
  started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
  is_active INTEGER DEFAULT 1,
  total_completion_time INTEGER DEFAULT 0,
  final_position INTEGER,
  completed_at DATETIME,
  FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE TABLE IF NOT EXISTS ctf_stages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  stage_number INTEGER UNIQUE NOT NULL,
  stage_name TEXT NOT NULL,
  stage_description TEXT,
  difficulty_level TEXT DEFAULT 'medium',
  ai_guardian_name TEXT,
  ai_guardian_personality TEXT,
  system_prompt TEXT,
  success_criteria TEXT,
  hints TEXT,
  max_attempts INTEGER DEFAULT -1,
  time_penalty_per_wrong_attempt INTEGER DEFAULT 0,
  is_active INTEGER DEFAULT 1,
  stage_order INTEGER NOT NULL,
  difficulty TEXT DEFAULT 'easy',
  defense_style TEXT DEFAULT '[]',
  adaptive_mode TEXT DEFAULT 'none',
  level_score INTEGER DEFAULT 100,
  time_bonus_seconds INTEGER DEFAULT 300,
  feedback_mode TEXT DEFAULT 'reason',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ctf_progress (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  participant_id INTEGER NOT NULL,
  stage_id INTEGER NOT NULL,
  status TEXT DEFAULT 'not_started',
  started_at DATETIME,
  completed_at DATETIME,
  completion_time INTEGER,
  attempts_count INTEGER DEFAULT 0,
  successful_attempts INTEGER DEFAULT 0,
  failed_attempts INTEGER DEFAULT 0,
  hints_used INTEGER DEFAULT 0,
  hint_penalty_total INTEGER DEFAULT 0,
  time_penalties INTEGER DEFAULT 0,
  final_payload TEXT,
  techniques_used TEXT DEFAULT '[]',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (participant_id) REFERENCES ctf_participants (id),
  FOREIGN KEY (stage_id) REFERENCES ctf_stages (id),
  UNIQUE(participant_id, stage_id)
);

CREATE TABLE IF NOT EXISTS ctf_attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  participant_id INTEGER NOT NULL,
  stage_id INTEGER NOT NULL,
  attempt_number INTEGER NOT NULL,
  payload TEXT NOT NULL,
  ai_response TEXT,
  was_successful INTEGER DEFAULT 0,
  response_time INTEGER,
  technique_tag TEXT,
  technique_confidence REAL,
  blocked INTEGER DEFAULT 0,
  block_reason TEXT,
  payload_hash TEXT,
  attempt_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
  session_id TEXT,
  client_ip TEXT,
  user_agent TEXT,
  FOREIGN KEY (participant_id) REFERENCES ctf_participants (id),
  FOREIGN KEY (stage_id) REFERENCES ctf_stages (id)
);

CREATE TABLE IF NOT EXISTS ctf_leaderboard (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  participant_id INTEGER UNIQUE NOT NULL,
  username TEXT NOT NULL,
  team_name TEXT,
  total_stages_completed INTEGER DEFAULT 0,
  total_completion_time INTEGER DEFAULT 0,
  average_stage_time REAL DEFAULT 0,
  fastest_stage_time INTEGER DEFAULT 0,
  slowest_stage_time INTEGER DEFAULT 0,
  total_attempts INTEGER DEFAULT 0,
  success_rate REAL DEFAULT 0,
  total_score INTEGER DEFAULT 0,
  last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
  rank_position INTEGER,
  is_completed INTEGER DEFAULT 0,
  completion_timestamp DATETIME,
  FOREIGN KEY (participant_id) REFERENCES ctf_participants (id)
);

CREATE TABLE IF NOT EXISTS ctf_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT NOT NULL,
  participant_id INTEGER,
  stage_id INTEGER,
  event_data TEXT,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
  is_public INTEGER DEFAULT 1,
  FOREIGN KEY (participant_id) REFERENCES ctf_participants (id),
  FOREIGN KEY (stage_id) REFERENCES ctf_stages (id)
);

CREATE TABLE IF NOT EXISTS ctf_sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  participant_id INTEGER NOT NULL,
  session_token TEXT UNIQUE NOT NULL,
  started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  last_heartbeat DATETIME DEFAULT CURRENT_TIMESTAMP,
  ended_at DATETIME,
  total_active_time INTEGER DEFAULT 0,
  is_active INTEGER DEFAULT 1,
  client_ip TEXT,
  user_agent TEXT,
  FOREIGN KEY (participant_id) REFERENCES ctf_participants (id)
);

-- Adaptive defense: per-user technique memory
CREATE TABLE IF NOT EXISTS ctf_technique_blocklist (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  participant_id INTEGER NOT NULL,
  stage_id INTEGER NOT NULL,
  technique_tag TEXT NOT NULL,
  first_used_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (participant_id) REFERENCES ctf_participants (id),
  FOREIGN KEY (stage_id) REFERENCES ctf_stages (id),
  UNIQUE(participant_id, stage_id, technique_tag)
);

-- Adaptive defense: global winning payload memory
CREATE TABLE IF NOT EXISTS ctf_payload_blocklist (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  stage_id INTEGER NOT NULL,
  payload_hash TEXT NOT NULL,
  normalized_snippet TEXT,
  first_winner_participant_id INTEGER,
  first_won_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  hit_count INTEGER DEFAULT 0,
  FOREIGN KEY (stage_id) REFERENCES ctf_stages (id),
  FOREIGN KEY (first_winner_participant_id) REFERENCES ctf_participants (id),
  UNIQUE(stage_id, payload_hash)
);

-- Admin moderation
CREATE TABLE IF NOT EXISTS ctf_bans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  banned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  reason TEXT,
  banned_by INTEGER,
  FOREIGN KEY (user_id) REFERENCES users (id)
);

-- Native CTF grading receipts; no workshop objective IDs.
CREATE TABLE IF NOT EXISTS ctf_judgments (
  run_id TEXT PRIMARY KEY,
  attempt_id INTEGER,
  participant_id INTEGER NOT NULL,
  stage_id INTEGER NOT NULL,
  progress_id INTEGER NOT NULL,
  stage_digest TEXT NOT NULL,
  verdict TEXT NOT NULL,
  accepted INTEGER NOT NULL DEFAULT 0,
  metadata TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS ctf_judgments_attempt ON ctf_judgments(attempt_id);
