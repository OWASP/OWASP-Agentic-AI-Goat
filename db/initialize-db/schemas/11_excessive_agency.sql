-- excessive_agency.db: Excessive Agency + BOLA Lab
-- NOTE: This lab primarily uses in-memory storage (server/database/excessiveAgencyLabDb.js)
-- for workshop isolation. This SQLite schema provides persistence if needed.

-- Lab users (separate from main workshop users)
CREATE TABLE IF NOT EXISTS lab_users (
  user_id TEXT PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  email TEXT,
  role TEXT DEFAULT 'user',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- User notes (for BOLA testing)
CREATE TABLE IF NOT EXISTS notes (
  id TEXT PRIMARY KEY,
  owner_user_id TEXT NOT NULL,
  title TEXT NOT NULL,
  body TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (owner_user_id) REFERENCES lab_users(user_id)
);

-- Orders (for Unsafe Decisioning testing)
CREATE TABLE IF NOT EXISTS orders (
  order_id TEXT PRIMARY KEY,
  owner_user_id TEXT NOT NULL,
  description TEXT NOT NULL,
  amount_cents INTEGER NOT NULL,
  status TEXT DEFAULT 'completed',
  refundable_until DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (owner_user_id) REFERENCES lab_users(user_id)
);

-- Refunds ledger
CREATE TABLE IF NOT EXISTS refunds (
  refund_id TEXT PRIMARY KEY,
  order_id TEXT NOT NULL,
  amount_cents INTEGER NOT NULL,
  reason TEXT,
  status TEXT DEFAULT 'pending',
  requested_by TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME,
  FOREIGN KEY (order_id) REFERENCES orders(order_id)
);

-- Audit log for forensics
CREATE TABLE IF NOT EXISTS audit_log (
  id TEXT PRIMARY KEY,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
  session_user_id TEXT,
  tool_name TEXT,
  target_resource TEXT,
  authorization_decision TEXT,
  details TEXT
);

-- User progress tracking (9 objectives: 1-4 Fixed Mode, 5-9 Vulnerable Mode)
CREATE TABLE IF NOT EXISTS user_progress (
  user_id TEXT PRIMARY KEY,
  objective_1 INTEGER DEFAULT 0,
  objective_2 INTEGER DEFAULT 0,
  objective_3 INTEGER DEFAULT 0,
  objective_4 INTEGER DEFAULT 0,
  objective_5 INTEGER DEFAULT 0,
  objective_6 INTEGER DEFAULT 0,
  objective_7 INTEGER DEFAULT 0,
  objective_8 INTEGER DEFAULT 0,
  objective_9 INTEGER DEFAULT 0,
  completed_at_1 DATETIME,
  completed_at_2 DATETIME,
  completed_at_3 DATETIME,
  completed_at_4 DATETIME,
  completed_at_5 DATETIME,
  completed_at_6 DATETIME,
  completed_at_7 DATETIME,
  completed_at_8 DATETIME,
  completed_at_9 DATETIME
);
