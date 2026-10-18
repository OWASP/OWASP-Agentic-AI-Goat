const path = require('path');
const fs = require('fs');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');

// ── Config ───────────────────────────────────────────────────────────────────
// Each ECS task runs its OWN local SQLite (no shared EFS). TEAM_ID 1..N maps to
// environment lv1..lvN; this task seeds only its environment's 100 users (exact
// usernames/passwords from bsides_users.json) plus the shared admins, and PURGES
// any student not in that dataset (stale BSides/other-level/legacy accounts).
const teamId = Math.max(parseInt(process.env.TEAM_ID || '1', 10), 1);
const level = (process.env.BSIDES_LEVEL || `lv${teamId}`).toLowerCase();
const dbPath = process.env.USERS_AUTH_DB_PATH || path.join(__dirname, 'users_auth.db');
const BCRYPT_ROUNDS = 10;

// Shared admins present in EVERY environment. Abhinav is the pre-existing owner
// admin; ashok + mukesh are the two additional event admins.
const ADMINS = [
  { username: 'Abhinav', email: 'abhinav@dvaia.local', password: 'Abh1nav@DVAIA#2026' },
  { username: 'ashok', email: 'ashok@dvaia.local', password: 'Ashok#Adm1n@DC34!' },
  { username: 'mukesh', email: 'mukesh@dvaia.local', password: 'Mukesh#Adm1n@DC34!' },
];

const ADMIN_PERMISSIONS = [
  'user_management', 'challenge_management', 'system_config', 'view_analytics',
  'manage_progress', 'send_notifications', 'export_data', 'system_logs',
];

// ── Load the baked credentials dataset ────────────────────────────────────────
function loadBsidesUsers() {
  const candidates = [
    process.env.BSIDES_USERS_JSON,
    path.join(__dirname, 'bsides_users.json'),
    '/app/database-template/bsides_users.json',
    path.join(__dirname, '..', '..', 'server', 'database', 'bsides_users.json'),
  ].filter(Boolean);
  for (const p of candidates) {
    try {
      if (fs.existsSync(p)) {
        const data = JSON.parse(fs.readFileSync(p, 'utf8'));
        return data && data.levels ? data.levels : null;
      }
    } catch (e) {
      console.error(`Failed reading credentials file ${p}: ${e.message}`);
    }
  }
  return null;
}

const levels = loadBsidesUsers();
const db = new sqlite3.Database(dbPath);

function seedStudents(stmt) {
  if (levels && Array.isArray(levels[level])) {
    const users = levels[level];
    users.forEach((u) => {
      const email = `${u.username}@bsides.local`;
      const hash = bcrypt.hashSync(u.password, BCRYPT_ROUNDS);
      stmt.run(u.username, email, hash);
    });
    console.log(`Seeded ${users.length} BSides students for environment ${level} (TEAM_ID=${teamId}).`);
    return;
  }

  // Fallback: legacy generic students (only if the dataset is missing).
  const usersPerTeam = Math.max(parseInt(process.env.USERS_PER_TEAM || '8', 10), 1);
  const fallbackPw = process.env.WORKSHOP_DEFAULT_STUDENT_PASSWORD || 'Workshop2026!';
  const hash = bcrypt.hashSync(fallbackPw, BCRYPT_ROUNDS);
  for (let i = 1; i <= usersPerTeam; i += 1) {
    stmt.run(`student_${i}`, `student_${i}@localhost.com`, hash);
  }
  console.warn(`bsides_users.json / level ${level} not found — seeded ${usersPerTeam} legacy students as fallback.`);
}

// Remove any student rows that are NOT part of this environment's dataset — e.g.
// stale BSides students baked into the users_auth.db template from an earlier
// build, other-level leftovers, or legacy fallback `student_%` accounts. Admins
// (role='admin') are never touched. Idempotent + self-healing on every start.
function purgeForeignStudents(done) {
  if (!levels || !Array.isArray(levels[level]) || levels[level].length === 0) {
    console.warn(`Skipping student purge — no dataset for level ${level}.`);
    return done();
  }
  const allowed = levels[level].map((u) => u.username);
  const placeholders = allowed.map(() => '?').join(',');
  db.run(
    `DELETE FROM users WHERE role = 'student' AND username NOT IN (${placeholders})`,
    allowed,
    function (err) {
      if (err) {
        console.error(`Failed to purge foreign students: ${err.message}`);
      } else {
        console.log(`Purged ${this.changes} non-${level} student account(s) (e.g. stale BSides users).`);
      }
      done();
    },
  );
}

function ensureAdmins(done) {
  let remaining = ADMINS.length;
  if (remaining === 0) return done();
  ADMINS.forEach((admin) => {
    const hash = bcrypt.hashSync(admin.password, BCRYPT_ROUNDS);
    db.run(
      `INSERT INTO users (username, email, password, role, admin_level, email_verified, is_active)
       VALUES (?, ?, ?, 'admin', 2, 1, 1)
       ON CONFLICT(email) DO UPDATE SET
         username = excluded.username,
         password = excluded.password,
         role = 'admin',
         admin_level = 2,
         email_verified = 1,
         is_active = 1,
         login_attempts = 0,
         account_locked_until = NULL,
         updated_at = CURRENT_TIMESTAMP`,
      [admin.username, admin.email, hash],
      (err) => {
        if (err) console.error(`Failed to upsert admin ${admin.username}: ${err.message}`);
        db.get('SELECT id FROM users WHERE email=?', [admin.email], (gErr, row) => {
          if (!gErr && row) {
            ADMIN_PERMISSIONS.forEach((p) => db.run(
              `INSERT OR IGNORE INTO admin_permissions (admin_id, permission_name, granted_by) VALUES (?,?,?)`,
              [row.id, p, row.id],
            ));
          }
          remaining -= 1;
          if (remaining === 0) {
            console.log(`Ensured ${ADMINS.length} admins: ${ADMINS.map((a) => a.username).join(', ')}.`);
            done();
          }
        });
      },
    );
  });
}

db.serialize(() => {
  const stmt = db.prepare(`
    INSERT INTO users (username, email, password, role, admin_level, email_verified, is_active)
    VALUES (?, ?, ?, 'student', 0, 1, 1)
    ON CONFLICT(email) DO UPDATE SET
      username = excluded.username,
      password = excluded.password,
      role = 'student',
      admin_level = 0,
      email_verified = 1,
      is_active = 1,
      updated_at = CURRENT_TIMESTAMP
  `);

  seedStudents(stmt);

  stmt.finalize((err) => {
    if (err) {
      console.error(`Failed to seed workshop users: ${err.message}`);
      process.exitCode = 1;
      db.close();
      return;
    }
    purgeForeignStudents(() => ensureAdmins(() => db.close()));
  });
});
