-- SecureShop v2 — M8 Wave 5B U4 account tables.
-- Applied against secureshop.db idempotently (CREATE TABLE IF NOT EXISTS).
-- Backs the real Account page endpoints (addresses CRUD, sessions list/revoke).

CREATE TABLE IF NOT EXISTS user_addresses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  label TEXT,
  line1 TEXT NOT NULL,
  line2 TEXT,
  city TEXT,
  state TEXT,
  zip TEXT,
  phone TEXT,
  is_default INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES shop_users(id)
);

CREATE TABLE IF NOT EXISTS user_sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  ip TEXT,
  user_agent TEXT,
  token_jti TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  last_seen_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  revoked_at DATETIME,
  FOREIGN KEY (user_id) REFERENCES shop_users(id)
);
