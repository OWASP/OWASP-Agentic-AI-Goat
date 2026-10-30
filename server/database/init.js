const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcryptjs');

/**
 * VULNERABLE WORKSHOP DATABASE (owasp-ai-goat.db)
 * ========================================
 * ⚠️  WARNING: This database is INTENTIONALLY VULNERABLE for educational purposes!
 * 
 * Purpose: Contains vulnerable data for SQL injection, XSS, and other web security workshops
 * Security: DELIBERATELY INSECURE - Used for demonstrations only
 * 
 * IMPORTANT: This database is SEPARATE from user authentication (users_auth.db)
 * - Real workshop users authenticate via users_auth.db (secure)
 * - This database contains demo data for exploitation exercises (insecure)
 * 
 * Tables in this database:
 * - users: DEMO users for SQL injection exercises (NOT real workshop users)
 * - products: Product catalog for SQL injection demos
 * - comments: XSS vulnerability demonstrations
 * - reviews: Product reviews (XSS vulnerable)
 * - cart: Shopping cart functionality
 * - orders: Order management
 * - order_items: Order details
 * - workshop_progress: Challenge progress tracking (legacy, moved to authDb)
 * - session_tokens: Demo session tokens (legacy)
 * - challenge_visibility: Challenge config (legacy, moved to authDb)
 * - files: File upload demonstrations
 * - ai_conversations: AI chat logs for demos
 * 
 * DO NOT use this database for actual user authentication!
 */

const dbPath = path.join(__dirname, 'owasp-ai-goat.db');

// Create database connection
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('❌ Error opening vulnerable workshop database:', err.message);
  } else {
    console.log('⚠️  Connected to VULNERABLE WORKSHOP database (owasp-ai-goat.db)');
    console.log('   ℹ️  This database contains DEMO DATA for security exercises');
    console.log('   ℹ️  Real users authenticate via users_auth.db (separate database)');
    initializeDatabase();
  }
});

function initializeDatabase() {
  // Use serialize to ensure tables are created before inserts
  db.serialize(() => {
    // ⚠️  VULNERABLE DEMO USERS TABLE (NOT for real workshop users!)
    // Real workshop users are stored in users_auth.db
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT DEFAULT 'student',
      full_name TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      is_active INTEGER DEFAULT 1
    )`, (err) => {
      if (!err) {
        console.log('   ✓ Demo users table created (for SQL injection exercises)');
      }
    });
  // Products table for SQL injection demos
  db.run(`CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    price REAL,
    category TEXT,
    image_url TEXT
  )`);

  // Comments table for XSS demos
  db.run(`CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    content TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
  )`);

  // Reviews table for product reviews (XSS vulnerable)
  db.run(`CREATE TABLE IF NOT EXISTS reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    rating INTEGER NOT NULL,
    comment TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (product_id) REFERENCES products (id),
    FOREIGN KEY (user_id) REFERENCES users (id)
  )`);

  // Shopping cart table
  db.run(`CREATE TABLE IF NOT EXISTS cart (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    quantity INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id),
    FOREIGN KEY (product_id) REFERENCES products (id)
  )`);

  // Orders table
  db.run(`CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    total_amount REAL NOT NULL,
    payment_method TEXT,
    shipping_address TEXT,
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
  )`);

  // Order items table
  db.run(`CREATE TABLE IF NOT EXISTS order_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    quantity INTEGER NOT NULL,
    price REAL NOT NULL,
    FOREIGN KEY (order_id) REFERENCES orders (id),
    FOREIGN KEY (product_id) REFERENCES products (id)
  )`);

  // Workshop progress table
  db.run(`CREATE TABLE IF NOT EXISTS workshop_progress (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    challenge_id TEXT NOT NULL,
    status TEXT DEFAULT 'locked',
    completed_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
  )`);

  // Session tokens table
  db.run(`CREATE TABLE IF NOT EXISTS session_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    token TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
  )`);

  // Challenge visibility management table
  db.run(`CREATE TABLE IF NOT EXISTS challenge_visibility (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    challenge_key TEXT UNIQUE NOT NULL,
    challenge_name TEXT NOT NULL,
    challenge_description TEXT,
    category TEXT DEFAULT 'web',
    difficulty TEXT DEFAULT 'intermediate',
    is_visible INTEGER DEFAULT 1,
    show_solutions INTEGER DEFAULT 0,
    show_hints INTEGER DEFAULT 0,
    route TEXT,
    updated_by INTEGER,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (updated_by) REFERENCES users (id)
  )`);

  // Migration: add show_hints column if missing (for existing databases)
  db.run(`ALTER TABLE challenge_visibility ADD COLUMN show_hints INTEGER DEFAULT 0`, (err) => {
    if (err && !err.message.includes('duplicate column')) {
      console.error('Error adding show_hints column to init db:', err);
    }
  });

  // Migration: remove deprecated exercise keys that were removed from the platform
  db.run(
    `DELETE FROM challenge_visibility WHERE challenge_key IN ('sql_injection_prompt','order_query_injection','agentic_ai_tool_extraction','file_reading_agent')`
  );

  // Insert default challenge visibility settings based on current challenges
  const challenges = [
    {
      key: 'reflected_xss_llm', 
      name: 'Reflected XSS in AI Chat Systems',
      description: 'Demonstrate and exploit Reflected XSS vulnerabilities in AI chat systems with various vectors.',
      category: 'ai',
      difficulty: 'intermediate',
      route: '/vulnerabilities/xss',
      visible: 1
    },
    { 
      key: 'direct_prompt_injection', 
      name: 'Direct Prompt Injection Attack',
      description: 'Master direct prompt injection techniques to bypass AI safety measures.',
      category: 'ai',
      difficulty: 'advanced',
      route: '/vulnerabilities/direct-prompt-injection',
      visible: 1
    },
    { 
      key: 'indirect_prompt_injection', 
      name: 'Indirect Prompt Injection via Documents',
      description: 'Learn indirect prompt injection by embedding malicious instructions in documents.',
      category: 'ai',
      difficulty: 'advanced',
      route: '/vulnerabilities/indirect-prompt-injection',
      visible: 1
    },
    {
      key: 'ctf_prompt_injection_challenge', 
      name: '🏆 CTF Prompt Injection Challenge',
      description: 'Ultimate prompt injection CTF with 8 difficulty levels and unique AI guardians.',
      category: 'ctf',
      difficulty: 'expert',
      route: '/vulnerabilities/ctf-prompt-injection',
      visible: 1
    },
    {
      key: 'sensitive_info_disclosure', 
      name: '🔓 Sensitive Information Disclosure',
      description: 'Exploit Path Traversal, SSI Injection, and combined vulnerabilities to access sensitive files. AI-assisted exploitation included!',
      category: 'web',
      difficulty: 'advanced',
      route: '/vulnerabilities/sensitive-info-disclosure',
      visible: 1
    },
    {
      key: 'csrf_prompt_injection',
      name: 'CSRF via AI Prompt Injection',
      description: 'Cross-Site Request Forgery through AI agents: direct and indirect prompt injection, and GET mutations via rendered HTML.',
      category: 'ai',
      difficulty: 'intermediate',
      route: '/vulnerabilities/csrf-via-ai',
      visible: 1
    },
  ];

  challenges.forEach(challenge => {
    db.run(`
      INSERT OR IGNORE INTO challenge_visibility (
        challenge_key, challenge_name, challenge_description, category,
        difficulty, is_visible, route, show_solutions
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 0)
    `, [
      challenge.key, challenge.name, challenge.description,
      challenge.category, challenge.difficulty, challenge.visible, challenge.route
    ]);

    // Force-update name/description for renamed challenges so existing rows are corrected
    db.run(`
      UPDATE challenge_visibility
      SET challenge_name = ?, challenge_description = ?
      WHERE challenge_key = ?
    `, [challenge.name, challenge.description, challenge.key]);
  });

  // Files table for upload vulnerabilities
  db.run(`CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    original_name TEXT NOT NULL,
    file_path TEXT NOT NULL,
    file_size INTEGER,
    mime_type TEXT,
    uploaded_by INTEGER,
    uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (uploaded_by) REFERENCES users (id)
  )`);

  // AI conversations table
  db.run(`CREATE TABLE IF NOT EXISTS ai_conversations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    prompt TEXT NOT NULL,
    response TEXT,
    model_used TEXT DEFAULT 'llama3.1:8b',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
  )`);

  // Session tokens table
  db.run(`CREATE TABLE IF NOT EXISTS session_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    token TEXT UNIQUE NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
  )`);

    // Insert default data after all tables are created
    insertDefaultData();
  }); // end serialize
}

function insertDefaultData() {
  console.log('   📝 Inserting vulnerable demo data...');
  
  // ⚠️  IMPORTANT: These are DEMO accounts for SQL injection exercises
  // They are NOT real workshop users!
  // Real workshop users are managed in users_auth.db
  
  // Insert student account
  const studentPassword = bcrypt.hashSync('student123', 10);
  db.run(`INSERT OR IGNORE INTO users (username, email, password, role) 
          VALUES ('student', 'student@owasp-ai-goat.local', ?, 'student')`, [studentPassword], (err) => {
    if (!err) console.log('   ✓ Created demo account: student / student123');
  });

  // Insert student123 account (common username format)
  db.run(`INSERT OR IGNORE INTO users (username, email, password, role) 
          VALUES ('student123', 'student123@owasp-ai-goat.local', ?, 'student')`, [studentPassword]);

  // Insert default test users
  const userPassword = bcrypt.hashSync('password', 10);
  db.run(`INSERT OR IGNORE INTO users (username, email, password, role) 
          VALUES ('user', 'user@owasp-ai-goat.local', ?, 'student')`, [userPassword]);
  
  // Insert test user
  const testPassword = bcrypt.hashSync('test123', 10);
  db.run(`INSERT OR IGNORE INTO users (username, email, password, role) 
          VALUES ('Test User', 'test@owasp-ai-goat.local', ?, 'student')`, [testPassword]);

  // Sample products for SQL injection demos
  const products = [
    ['Laptop Pro', 'High-performance laptop for professionals', 1299.99, 'Electronics', '/images/laptop.jpg'],
    ['Smartphone X', 'Latest smartphone with AI features', 899.99, 'Electronics', '/images/phone.jpg'],
    ['Coffee Maker', 'Smart coffee maker with app control', 199.99, 'Appliances', '/images/coffee.jpg'],
    ['Gaming Chair', 'Ergonomic gaming chair with RGB lighting', 299.99, 'Furniture', '/images/chair.jpg'],
    ['Wireless Headphones', 'Noise-cancelling wireless headphones', 249.99, 'Electronics', '/images/headphones.jpg']
  ];

  products.forEach(product => {
    db.run(`INSERT OR IGNORE INTO products (name, description, price, category, image_url) 
            VALUES (?, ?, ?, ?, ?)`, product);
  });

  // Sample comments for XSS demos
  const comments = [
    [1, 'Great product! Highly recommended.'],
    [2, 'Good value for money.'],
    [1, '<script>alert("XSS Vulnerability!")</script>This comment contains XSS'],
    [2, 'The delivery was fast and packaging was excellent.']
  ];

  comments.forEach(comment => {
    db.run(`INSERT OR IGNORE INTO comments (user_id, content) VALUES (?, ?)`, comment);
  });
  
  console.log('   ✓ Sample products and comments inserted');
  console.log('');
  console.log('⚠️  ============================================');
  console.log('   VULNERABLE WORKSHOP DATABASE READY');
  console.log('   Database: owasp-ai-goat.db');
  console.log('   Purpose: Demo data for security exercises');
  console.log('   Status: INTENTIONALLY VULNERABLE');
  console.log('   Note: Real users authenticate via users_auth.db');
  console.log('============================================');
}

module.exports = db;
