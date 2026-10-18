-- xss_challenge.db: deliberately vulnerable XSS practice
CREATE TABLE IF NOT EXISTS vulnerable_comments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_name TEXT,
  comment_content TEXT,
  product_id INTEGER,
  is_approved INTEGER DEFAULT 1,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS vulnerable_posts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT,
  content TEXT,
  author TEXT,
  views INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS vulnerable_profiles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  display_name TEXT,
  bio TEXT,
  website TEXT,
  social_links TEXT
);

-- XSS Workshop runtime tables (profiles, emails, progress)
-- Also created by server/database/xssWorkshopDb.js on startup.

CREATE TABLE IF NOT EXISTS xss_workshop_profiles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_key TEXT NOT NULL UNIQUE,
  name TEXT DEFAULT 'Security Student',
  bio TEXT DEFAULT 'Learning about web security.',
  website TEXT DEFAULT 'https://example.com',
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS xss_workshop_emails (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  subject TEXT NOT NULL,
  sender TEXT NOT NULL,
  body TEXT NOT NULL,
  user_key TEXT,
  received_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS xss_workshop_progress (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_key TEXT NOT NULL,
  objective_id TEXT NOT NULL,
  completed INTEGER DEFAULT 0,
  completed_at DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_key, objective_id)
);
