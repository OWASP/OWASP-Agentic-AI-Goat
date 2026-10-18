/**
 * SecureShop v2 M14 — provision the three DISTINCT student identities.
 *
 * Applies to secureshop.db. Idempotent via INSERT OR IGNORE.
 *
 * M14 replaces the "same user switches role" pattern with three separate
 * accounts. The legacy student_c / student_m / student_a rows from seed
 * 17_secureshop_v2.js remain as backwards-compat aliases (unchanged).
 *
 * Post-M14 canonical usernames:
 *   - student_customer   (role='customer')
 *   - student_merchant   (role='merchant')
 *   - student_admin      (role='admin')
 *
 * All three share the same password (`student123`) so instructors can rehearse
 * every persona quickly. The RoleSwitcher React component now maps a click
 * to logout + login-as-<target> against these accounts.
 */

const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');

function seed(dbPath) {
  const db = new Database(dbPath);
  try {
    const passwordHash = bcrypt.hashSync('student123', 10);
    const identities = [
      ['student_customer', 'student_customer@dvaia.local', 'customer', 'Student Customer',
        'sk_ss_stucust00000000abcdef', '{"phone":"555-1200","address":"120 Learner Ln","tax_id":"120-12-1200"}'],
      ['student_merchant', 'student_merchant@dvaia.local', 'merchant', 'Student Merchant',
        'sk_ss_stumerc00000000abcdef', '{"phone":"555-1201","address":"121 Learner Ln","tax_id":"121-12-1201"}'],
      ['student_admin',    'student_admin@dvaia.local',    'admin',    'Student Admin',
        'sk_ss_stuadmn00000000abcdef', '{"phone":"555-1202","address":"122 Learner Ln","tax_id":"122-12-1202"}'],
    ];

    const insertUser = db.prepare(`
      INSERT OR IGNORE INTO shop_users
        (username, email, password, role, full_name, api_key, pii_json, session_token)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    for (const [uname, email, role, full, apiKey, pii] of identities) {
      insertUser.run(uname, email, passwordHash, role, full, apiKey, pii, null);
    }
    console.log('  \u2713 seed 22_secureshop_v2_m14_identities.js applied (3 distinct student identities)');
  } finally {
    db.close();
  }
}

module.exports = seed;
module.exports.runSeed = seed;
