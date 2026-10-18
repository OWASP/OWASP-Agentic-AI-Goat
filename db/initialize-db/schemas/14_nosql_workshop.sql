-- NOVA NoSQL Workshop Database Schema
-- ResearchVault academic research library assistant
-- SQLite with JSON columns simulating document-store behavior

CREATE TABLE IF NOT EXISTS papers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  paper_id TEXT UNIQUE NOT NULL,
  title TEXT NOT NULL,
  abstract TEXT,
  authors TEXT NOT NULL,       -- JSON array: ["Alice Chen", "Bob Smith"]
  topics TEXT NOT NULL,        -- JSON array: ["machine learning", "neural networks"]
  year INTEGER,
  journal TEXT,
  citations INTEGER DEFAULT 0,
  cited_by TEXT DEFAULT '[]',  -- JSON array of paper_ids that cite this paper
  url TEXT
);

CREATE TABLE IF NOT EXISTS authors (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  author_id TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  institution TEXT,
  expertise TEXT NOT NULL,     -- JSON array: ["NLP", "deep learning"]
  paper_count INTEGER DEFAULT 0,
  email TEXT,
  bio TEXT
);

CREATE TABLE IF NOT EXISTS reading_lists (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  paper_id TEXT NOT NULL,
  added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  notes TEXT,
  UNIQUE(user_id, paper_id)
);

CREATE TABLE IF NOT EXISTS chat_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  message_type TEXT NOT NULL,
  message TEXT NOT NULL,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS nosql_injection_solution_visibility (
  objective_id TEXT PRIMARY KEY,
  solutions_enabled INTEGER DEFAULT 0,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS nosql_injection_solutions (
  objective_id TEXT PRIMARY KEY,
  title TEXT,
  difficulty TEXT,
  hints TEXT DEFAULT '[]',
  examples TEXT DEFAULT '[]',
  approach TEXT,
  tips TEXT DEFAULT '[]'
);
