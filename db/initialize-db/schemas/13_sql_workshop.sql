-- ARIA SQL Workshop Database Schema
-- ShopFast e-commerce agent with parameterized (safe) queries

CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  product_id TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  category TEXT NOT NULL,
  price REAL NOT NULL,
  description TEXT,
  stock INTEGER DEFAULT 100,
  available INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_number TEXT UNIQUE NOT NULL,
  user_id TEXT NOT NULL,
  product_name TEXT NOT NULL,
  quantity INTEGER DEFAULT 1,
  unit_price REAL,
  total_amount REAL,
  shipping_address TEXT,
  status TEXT DEFAULT 'pending',
  payment_method TEXT DEFAULT 'credit_card',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS receipts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_number TEXT NOT NULL,
  receipt_number TEXT UNIQUE NOT NULL,
  amount REAL,
  payment_method TEXT DEFAULT 'credit_card',
  issued_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS cart (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  product_name TEXT NOT NULL,
  quantity INTEGER DEFAULT 1,
  unit_price REAL,
  added_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS chat_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  message_type TEXT NOT NULL,
  message TEXT NOT NULL,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);
