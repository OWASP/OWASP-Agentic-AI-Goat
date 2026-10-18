-- platform_secure.db: secure platform (platform_users, permissions, progress)
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS platform_users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  salt TEXT NOT NULL,
  role TEXT DEFAULT 'student' CHECK (role IN ('student', 'admin', 'super_admin')),
  admin_level INTEGER DEFAULT 0 CHECK (admin_level BETWEEN 0 AND 2),
  full_name TEXT,
  phone TEXT,
  department TEXT,
  profile_image TEXT,
  email_verified INTEGER DEFAULT 0,
  is_active INTEGER DEFAULT 1,
  account_locked_until DATETIME,
  login_attempts INTEGER DEFAULT 0,
  last_login DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS admin_permissions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  admin_id INTEGER NOT NULL,
  permission_name TEXT NOT NULL CHECK (permission_name IN (
    'user_management', 'challenge_management', 'system_config',
    'view_analytics', 'manage_progress', 'send_notifications',
    'export_data', 'system_logs', 'database_access'
  )),
  granted_by INTEGER,
  granted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  expires_at DATETIME,
  is_active INTEGER DEFAULT 1,
  FOREIGN KEY (admin_id) REFERENCES platform_users (id) ON DELETE CASCADE,
  FOREIGN KEY (granted_by) REFERENCES platform_users (id),
  UNIQUE(admin_id, permission_name)
);

CREATE TABLE IF NOT EXISTS student_progress (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  student_id INTEGER NOT NULL,
  challenge_key TEXT NOT NULL,
  challenge_name TEXT NOT NULL,
  category TEXT NOT NULL,
  status TEXT DEFAULT 'not_started',
  score INTEGER DEFAULT 0,
  max_score INTEGER DEFAULT 100,
  attempts INTEGER DEFAULT 0,
  time_spent INTEGER DEFAULT 0,
  hints_used INTEGER DEFAULT 0,
  started_at DATETIME,
  completed_at DATETIME,
  last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
  notes TEXT,
  FOREIGN KEY (student_id) REFERENCES platform_users (id),
  UNIQUE(student_id, challenge_key)
);
