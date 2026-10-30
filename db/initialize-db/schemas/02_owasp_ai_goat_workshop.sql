-- owasp-ai-goat.db: vulnerable workshop + admin tables (demo data only)
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  role TEXT DEFAULT 'student',
  admin_level INTEGER DEFAULT 0,
  full_name TEXT,
  email_verified INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  is_active INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  description TEXT,
  price REAL,
  category TEXT,
  image_url TEXT
);

CREATE TABLE IF NOT EXISTS comments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  content TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE TABLE IF NOT EXISTS reviews (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  product_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  rating INTEGER NOT NULL,
  comment TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (product_id) REFERENCES products (id),
  FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE TABLE IF NOT EXISTS cart (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  product_id INTEGER NOT NULL,
  quantity INTEGER DEFAULT 1,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users (id),
  FOREIGN KEY (product_id) REFERENCES products (id)
);

CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  total_amount REAL NOT NULL,
  payment_method TEXT,
  shipping_address TEXT,
  status TEXT DEFAULT 'pending',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE TABLE IF NOT EXISTS order_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id INTEGER NOT NULL,
  product_id INTEGER NOT NULL,
  quantity INTEGER NOT NULL,
  price REAL NOT NULL,
  FOREIGN KEY (order_id) REFERENCES orders (id),
  FOREIGN KEY (product_id) REFERENCES products (id)
);

CREATE TABLE IF NOT EXISTS workshop_progress (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  challenge_id TEXT NOT NULL,
  status TEXT DEFAULT 'locked',
  completed_at DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE TABLE IF NOT EXISTS session_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  token TEXT UNIQUE NOT NULL,
  expires_at DATETIME NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE TABLE IF NOT EXISTS challenge_visibility (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  challenge_key TEXT UNIQUE NOT NULL,
  challenge_name TEXT NOT NULL,
  challenge_description TEXT,
  category TEXT DEFAULT 'web',
  difficulty TEXT DEFAULT 'intermediate',
  is_visible INTEGER DEFAULT 1,
  show_solutions INTEGER DEFAULT 0,
  route TEXT,
  updated_by INTEGER,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (updated_by) REFERENCES users (id)
);

CREATE TABLE IF NOT EXISTS files (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  filename TEXT NOT NULL,
  original_name TEXT NOT NULL,
  file_path TEXT NOT NULL,
  file_size INTEGER,
  mime_type TEXT,
  uploaded_by INTEGER,
  uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (uploaded_by) REFERENCES users (id)
);

CREATE TABLE IF NOT EXISTS ai_conversations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  prompt TEXT NOT NULL,
  response TEXT,
  model_used TEXT DEFAULT 'llama3.1:8b',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users (id)
);

-- Admin extension tables (same owasp-ai-goat.db)
CREATE TABLE IF NOT EXISTS admin_permissions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  admin_id INTEGER NOT NULL,
  permission_name TEXT NOT NULL,
  granted_by INTEGER,
  granted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  expires_at DATETIME,
  is_active INTEGER DEFAULT 1,
  FOREIGN KEY (admin_id) REFERENCES users (id),
  FOREIGN KEY (granted_by) REFERENCES users (id),
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
  solution_data TEXT,
  notes TEXT,
  FOREIGN KEY (student_id) REFERENCES users (id),
  UNIQUE(student_id, challenge_key)
);

CREATE TABLE IF NOT EXISTS challenge_config (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  challenge_key TEXT UNIQUE NOT NULL,
  challenge_name TEXT NOT NULL,
  category TEXT NOT NULL,
  difficulty_level INTEGER DEFAULT 1,
  max_score INTEGER DEFAULT 100,
  time_limit INTEGER,
  prerequisites TEXT,
  is_enabled INTEGER DEFAULT 1,
  show_solution INTEGER DEFAULT 0,
  solution_visible_after INTEGER DEFAULT 3,
  hints TEXT,
  description TEXT,
  learning_objectives TEXT,
  tags TEXT,
  created_by INTEGER,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_by INTEGER,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (created_by) REFERENCES users (id),
  FOREIGN KEY (updated_by) REFERENCES users (id)
);

CREATE TABLE IF NOT EXISTS activity_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  action_type TEXT NOT NULL,
  action_details TEXT,
  ip_address TEXT,
  user_agent TEXT,
  session_id TEXT,
  success INTEGER DEFAULT 1,
  error_message TEXT,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE TABLE IF NOT EXISTS system_config (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  config_key TEXT UNIQUE NOT NULL,
  config_value TEXT NOT NULL,
  config_type TEXT DEFAULT 'string',
  description TEXT,
  is_public INTEGER DEFAULT 0,
  updated_by INTEGER,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (updated_by) REFERENCES users (id)
);

CREATE TABLE IF NOT EXISTS security_settings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  setting_key TEXT UNIQUE NOT NULL,
  setting_value TEXT NOT NULL,
  description TEXT,
  category TEXT DEFAULT 'general',
  is_active INTEGER DEFAULT 1,
  updated_by INTEGER,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (updated_by) REFERENCES users (id)
);

CREATE TABLE IF NOT EXISTS system_cache (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cache_key TEXT UNIQUE NOT NULL,
  cache_value TEXT NOT NULL,
  expires_at DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS challenge_solutions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  challenge_key TEXT UNIQUE NOT NULL,
  solution_type TEXT DEFAULT 'standard',
  solution_title TEXT NOT NULL,
  solution_description TEXT,
  solution_steps TEXT,
  solution_code TEXT,
  explanation TEXT,
  reference_links TEXT,
  difficulty_level INTEGER DEFAULT 1,
  estimated_time INTEGER,
  prerequisites TEXT,
  tags TEXT,
  is_public INTEGER DEFAULT 0,
  created_by INTEGER,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_by INTEGER,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (created_by) REFERENCES users (id),
  FOREIGN KEY (updated_by) REFERENCES users (id)
);

CREATE TABLE IF NOT EXISTS system_metrics (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  metric_type TEXT NOT NULL,
  metric_name TEXT NOT NULL,
  metric_value REAL NOT NULL,
  metric_unit TEXT,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS email_verification_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  token TEXT UNIQUE NOT NULL,
  expires_at DATETIME NOT NULL,
  used INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  token TEXT UNIQUE NOT NULL,
  expires_at DATETIME NOT NULL,
  used INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE TABLE IF NOT EXISTS admin_notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  admin_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  message TEXT NOT NULL,
  type TEXT DEFAULT 'info',
  priority INTEGER DEFAULT 1,
  is_read INTEGER DEFAULT 0,
  action_url TEXT,
  action_label TEXT,
  expires_at DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (admin_id) REFERENCES users (id)
);

CREATE TABLE IF NOT EXISTS challenge_submissions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  student_id INTEGER NOT NULL,
  challenge_key TEXT NOT NULL,
  submission_data TEXT NOT NULL,
  is_correct INTEGER DEFAULT 0,
  score INTEGER DEFAULT 0,
  feedback TEXT,
  execution_time INTEGER,
  submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  graded_by INTEGER,
  graded_at DATETIME,
  FOREIGN KEY (student_id) REFERENCES users (id),
  FOREIGN KEY (graded_by) REFERENCES users (id)
);

CREATE TABLE IF NOT EXISTS user_sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  session_token TEXT UNIQUE NOT NULL,
  device_info TEXT,
  ip_address TEXT,
  location TEXT,
  is_active INTEGER DEFAULT 1,
  last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
  expires_at DATETIME NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users (id)
);
