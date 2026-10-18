-- SecureShop v2 additive schema for secureshop.db
-- Extends 03_secureshop.sql. Idempotent: CREATE TABLE IF NOT EXISTS + guarded ALTERs.

-- Additive columns on shop_users (idempotence via runner's ALTER-guard; see run-all.js)
ALTER TABLE shop_users ADD COLUMN avatar_path TEXT;
ALTER TABLE shop_users ADD COLUMN session_token TEXT;
ALTER TABLE shop_users ADD COLUMN api_key TEXT;
ALTER TABLE shop_users ADD COLUMN pii_json TEXT;

-- Additive columns on products
ALTER TABLE products ADD COLUMN template_source TEXT;
ALTER TABLE products ADD COLUMN description_html TEXT;

-- Additive columns on chat_messages
ALTER TABLE chat_messages ADD COLUMN agent_trace_id TEXT;

-- New tables
CREATE TABLE IF NOT EXISTS product_images (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  product_id INTEGER NOT NULL,
  path TEXT NOT NULL,
  mime TEXT,
  uploaded_by INTEGER,
  uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (product_id) REFERENCES products(id),
  FOREIGN KEY (uploaded_by) REFERENCES shop_users(id)
);

CREATE TABLE IF NOT EXISTS product_manuals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  product_id INTEGER NOT NULL,
  path TEXT NOT NULL,
  mime TEXT,
  vector_ref TEXT,
  uploaded_by INTEGER,
  uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (product_id) REFERENCES products(id),
  FOREIGN KEY (uploaded_by) REFERENCES shop_users(id)
);

CREATE TABLE IF NOT EXISTS reviews (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  product_id INTEGER NOT NULL,
  author_id INTEGER,
  body TEXT NOT NULL,
  rating INTEGER,
  status TEXT DEFAULT 'pending',           -- pending | approved | rejected
  moderator_kind TEXT,                     -- 'manual' | 'auto' | null
  moderator_notes TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  moderated_at DATETIME,
  FOREIGN KEY (product_id) REFERENCES products(id),
  FOREIGN KEY (author_id) REFERENCES shop_users(id)
);

CREATE TABLE IF NOT EXISTS coupons (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT UNIQUE NOT NULL,
  discount_percent INTEGER,
  active INTEGER DEFAULT 1,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS support_tickets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  customer_id INTEGER NOT NULL,
  subject TEXT NOT NULL,
  body TEXT NOT NULL,
  attachments_json TEXT,
  status TEXT DEFAULT 'open',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (customer_id) REFERENCES shop_users(id)
);

CREATE TABLE IF NOT EXISTS email_threads (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  subject TEXT NOT NULL,
  participants_json TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS emails (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  thread_id INTEGER NOT NULL,
  from_addr TEXT NOT NULL,
  to_addr TEXT NOT NULL,
  subject TEXT NOT NULL,
  body_markdown TEXT NOT NULL,
  body_html TEXT NOT NULL,
  headers_raw TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (thread_id) REFERENCES email_threads(id)
);

CREATE TABLE IF NOT EXISTS policies (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE NOT NULL,
  markdown_source TEXT NOT NULL,
  injected_into_json TEXT,                 -- array of supervisor names
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
