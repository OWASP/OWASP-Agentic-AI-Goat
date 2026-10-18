const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');

const challengeVisibility = [
  { key: 'reflected_xss_llm', name: 'Reflected XSS in AI Chat Systems', desc: 'Demonstrate Reflected XSS in AI chat.', cat: 'ai', diff: 'intermediate', route: '/vulnerabilities/xss', v: 1 },
  { key: 'direct_prompt_injection', name: 'Direct Prompt Injection Attack', desc: 'Master direct prompt injection.', cat: 'ai', diff: 'advanced', route: '/vulnerabilities/direct-prompt-injection', v: 1 },
  { key: 'indirect_prompt_injection', name: 'Indirect Prompt Injection via Documents', desc: 'Learn indirect prompt injection.', cat: 'ai', diff: 'advanced', route: '/vulnerabilities/indirect-prompt-injection', v: 1 },
  { key: 'ctf_prompt_injection_challenge', name: '🏆 CTF Prompt Injection Challenge', desc: 'Ultimate prompt injection CTF.', cat: 'ctf', diff: 'expert', route: '/vulnerabilities/ctf-prompt-injection', v: 1 },
  { key: 'sensitive_info_disclosure', name: '🔓 Sensitive Information Disclosure', desc: 'Exploit Path Traversal, SSI.', cat: 'web', diff: 'advanced', route: '/vulnerabilities/sensitive-info-disclosure', v: 1 },
];

const products = [
  ['Laptop Pro', 'High-performance laptop for professionals', 1299.99, 'Electronics', '/images/laptop.jpg'],
  ['Smartphone X', 'Latest smartphone with AI features', 899.99, 'Electronics', '/images/phone.jpg'],
  ['Coffee Maker', 'Smart coffee maker with app control', 199.99, 'Appliances', '/images/coffee.jpg'],
  ['Gaming Chair', 'Ergonomic gaming chair with RGB lighting', 299.99, 'Furniture', '/images/chair.jpg'],
  ['Wireless Headphones', 'Noise-cancelling wireless headphones', 249.99, 'Electronics', '/images/headphones.jpg'],
];

function runSeed(dbPath) {
  return new Promise((resolve, reject) => {
    const db = new sqlite3.Database(dbPath);
    const studentHash = bcrypt.hashSync('student123', 10);
    const userHash = bcrypt.hashSync('password', 10);
    const testHash = bcrypt.hashSync('test123', 10);
    const adminHash = bcrypt.hashSync('admin123!@#', 12);
    const admin2Hash = bcrypt.hashSync('admin2024$', 12);
    db.run(`INSERT OR IGNORE INTO users (username, email, password, role) VALUES (?,?,?,?)`, ['student', 'student@dvaia.local', studentHash, 'student']);
    db.run(`INSERT OR IGNORE INTO users (username, email, password, role) VALUES (?,?,?,?)`, ['student123', 'student123@dvaia.local', studentHash, 'student']);
    db.run(`INSERT OR IGNORE INTO users (username, email, password, role) VALUES (?,?,?,?)`, ['user', 'user@dvaia.local', userHash, 'student']);
    db.run(`INSERT OR IGNORE INTO users (username, email, password, role) VALUES (?,?,?,?)`, ['Test User', 'test@dvaia.local', testHash, 'student']);
    db.run(`INSERT OR IGNORE INTO users (username, email, password, role, admin_level, full_name, email_verified, is_active) VALUES (?,?,?,?,?,?,?,?)`,
      ['admin', 'admin@dvaia.local', adminHash, 'admin', 2, 'System Administrator', 1, 1]);
    db.run(`INSERT OR IGNORE INTO users (username, email, password, role, admin_level, full_name, email_verified, is_active) VALUES (?,?,?,?,?,?,?,?)`,
      ['administrator', 'administrator@dvaia.local', admin2Hash, 'admin', 1, 'Workshop Administrator', 1, 1]);
    challengeVisibility.forEach(c => {
      db.run(`INSERT OR IGNORE INTO challenge_visibility (challenge_key, challenge_name, challenge_description, category, difficulty, is_visible, route, show_solutions) VALUES (?,?,?,?,?,?,?,0)`,
        [c.key, c.name, c.desc, c.cat, c.diff, c.v, c.route]);
    });
    products.forEach(p => {
      db.run(`INSERT OR IGNORE INTO products (name, description, price, category, image_url) VALUES (?,?,?,?,?)`, p);
    });
    db.run(`INSERT OR IGNORE INTO comments (user_id, content) VALUES (?,?)`, [1, 'Great product! Highly recommended.']);
    db.run(`INSERT OR IGNORE INTO comments (user_id, content) VALUES (?,?)`, [2, 'Good value for money.']);
    db.run(`INSERT OR IGNORE INTO comments (user_id, content) VALUES (?,?)`, [1, '<script>alert("XSS")</script>This comment contains XSS']);
    db.run(`INSERT OR IGNORE INTO comments (user_id, content) VALUES (?,?)`, [2, 'The delivery was fast and packaging was excellent.']);
    const perms = ['user_management', 'challenge_management', 'system_config', 'view_analytics', 'manage_progress', 'send_notifications', 'export_data', 'system_logs'];
    perms.forEach(perm => {
      db.run(`INSERT OR IGNORE INTO admin_permissions (admin_id, permission_name, granted_by) SELECT id, ?, 1 FROM users WHERE username = 'admin'`, [perm]);
    });
    const sysConfig = [
      ['max_login_attempts', '5', 'number', 'Maximum login attempts before account lockout'],
      ['account_lockout_duration', '30', 'number', 'Account lockout duration in minutes'],
      ['session_timeout', '24', 'number', 'Session timeout in hours'],
      ['require_email_verification', 'true', 'boolean', 'Require email verification for new accounts'],
      ['allow_registration', 'true', 'boolean', 'Allow new user registration'],
      ['maintenance_mode', 'false', 'boolean', 'Enable maintenance mode'],
    ];
    sysConfig.forEach(([k, v, t, d]) => {
      db.run(`INSERT OR IGNORE INTO system_config (config_key, config_value, config_type, description, updated_by) SELECT ?,?,?,?, id FROM users WHERE username = 'admin'`, [k, v, t, d]);
    });
    db.close(resolve);
  });
}

module.exports = { runSeed };
