const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { ensureWorkshopConfigSchema } = require('./workshopConfigSchema');
const { seedWorkshopHintRows, migrateKnownWorkshopHintDefaults, migrateKnownCsrfSolutionDefaults } = require('./workshopHintSeedPolicy');
const { createPromptInjectionProgressService } = require('../services/promptInjectionProgressService');

/**
 * USER AUTHENTICATION DATABASE - PRODUCTION SECURITY
 * ==================================================
 * This database is SEPARATE from vulnerable workshop databases.
 * 
 * PURPOSE: Store actual workshop users who will authenticate and use the platform
 * 
 * SECURITY MEASURES IMPLEMENTED:
 * ✅ Separate database file (users_auth.db) - isolated from vulnerable demos
 * ✅ Bcrypt password hashing (cost factor 12) - industry standard
 * ✅ Prepared statements only - NO string concatenation (prevents SQL injection)
 * ✅ Session token management with expiration
 * ✅ Account lockout after failed login attempts
 * ✅ Email verification required for new accounts
 * ✅ Activity logging for security auditing
 * ✅ Foreign key constraints enforced
 * ✅ Input validation on all user inputs
 * ✅ Role-based access control (RBAC)
 * ✅ Admin permission system
 * ✅ Secure file permissions (database file should be 600)
 * 
 * ISOLATION: Completely isolated from vulnerable workshop demonstration databases
 * 
 * Tables:
 * - users: User authentication credentials and profile information
 * - user_sessions: Active user sessions with JWT tokens
 * - email_verification_tokens: Email verification for new accounts
 * - password_reset_tokens: Password reset functionality
 * - activity_logs: User activity tracking for security auditing
 * - admin_permissions: Admin role permissions
 * - student_progress: Student challenge completion tracking
 * - challenge_config: Challenge configuration and visibility
 */

const authDbPath = process.env.USERS_AUTH_DB_PATH || path.join(__dirname, 'users_auth.db');
const fs = require('fs');
let resolvePromptInjectionProgressReady;
const promptInjectionProgressReady = new Promise((resolve) => {
  resolvePromptInjectionProgressReady = resolve;
});
let promptInjectionProgressReadySettled = false;

function settlePromptInjectionProgressReady(error = null) {
  if (promptInjectionProgressReadySettled) return;
  promptInjectionProgressReadySettled = true;
  resolvePromptInjectionProgressReady({ error });
}

// Keep auth DB challenge metadata aligned with the canonical seeded challenge list.
const DEFAULT_CHALLENGES = [
  {
    key: 'reflected_xss_llm',
    name: 'XSS in AI Powered Chat System',
    description: 'Explore Cross-Site Scripting vulnerabilities in AI-powered chat applications.',
    category: 'ai',
    difficulty: 'easy',
    difficultyLevel: 1,
    route: '/vulnerabilities/xss',
    visible: 1
  },
  {
    key: 'direct_prompt_injection',
    name: 'Direct Prompt Injection Workshop',
    description: 'Master 7 distinct prompt injection techniques to bypass AI safety measures. Includes System Prompt Extraction, Jailbreak, Multi-Language, Virtualization, Role Playing, Side Stepping, and Obfuscation.',
    category: 'ai',
    difficulty: 'easy',
    difficultyLevel: 1,
    route: '/vulnerabilities/direct-prompt-injection',
    visible: 1
  },
  {
    key: 'indirect_prompt_injection',
    name: 'Indirect Prompt Injection Workshop',
    description: 'Learn indirect prompt injection through RAG documents and Email Agent attacks. Includes document poisoning and email-based AI manipulation.',
    category: 'ai',
    difficulty: 'intermediate',
    difficultyLevel: 2,
    route: '/vulnerabilities/indirect-prompt-injection',
    visible: 1
  },
  {
    key: 'mcp_server_rce',
    name: 'MCP Server Lab',
    description: 'Exploit 11 MCP (Model Context Protocol) attack techniques through a chat assistant: recon, command injection, SSRF, tool poisoning, indirect prompt injection, confused deputy, broken authorization, secret exposure, supply-chain tampering, audit-trail tampering, and shadow servers.',
    category: 'ai',
    difficulty: 'expert',
    difficultyLevel: 4,
    route: '/vulnerabilities/mcp-server',
    visible: 1
  },
  {
    key: 'ctf_prompt_injection_challenge',
    name: '🏆 CTF Prompt Injection Challenge',
    description: 'Ultimate prompt injection CTF.',
    category: 'ctf',
    difficulty: 'expert',
    difficultyLevel: 4,
    route: '/vulnerabilities/ctf-prompt-injection',
    visible: 1
  },
  {
    key: 'sensitive_info_disclosure',
    name: '🔓 Sensitive Information Disclosure',
    description: 'Exploit path traversal, SSRF, and prompt injection in the FinFlow AI banking agent. 5 user tools + 9 admin tools, 19 objectives.',
    category: 'web',
    difficulty: 'intermediate',
    difficultyLevel: 2,
    route: '/workshop/sensitive-info',
    visible: 1
  },
  {
    key: 'supply_chain_rce',
    name: '⛓️ Supply Chain RCE Lab',
    description: 'Exploit a vulnerable transitive dependency (pkg-parse@1.2.0) that calls eval() on the transform field of package.json manifests. Trigger Remote Code Execution through CodeBot AI assistant.',
    category: 'ai',
    difficulty: 'advanced',
    difficultyLevel: 3,
    route: '/workshop/supply-chain',
    visible: 1
  },
  {
    key: 'excessive_agency',
    name: '🤖 Excessive Agency Lab',
    description: 'Explore how AI agents with too many permissions can be manipulated to perform unauthorized actions.',
    category: 'ai',
    difficulty: 'intermediate',
    difficultyLevel: 2,
    route: '/vulnerabilities/excessive-agency',
    visible: 1
  },
  {
    key: 'sql_injection_workshop',
    name: '💉 SQL Injection Workshop (ARIA Agent)',
    description: 'Perform UNION-based SQL injection against the ARIA ShopFast e-commerce AI agent. 10 progressive objectives: error-based, boolean bypass, ORDER BY enumeration, UNION NULL probing, schema discovery, and data exfiltration.',
    category: 'sql_injection',
    difficulty: 'intermediate',
    difficultyLevel: 2,
    route: '/workshop/sql',
    visible: 1
  },
  {
    key: 'nosql_injection_workshop',
    name: '🍃 NoSQL Injection Workshop (NOVA Agent)',
    description: 'Perform operator-based NoSQL injection against the NOVA ResearchVault academic library AI agent. 10 progressive objectives covering boolean operators, regex injection, $where clauses, and data exfiltration.',
    category: 'nosql_injection',
    difficulty: 'intermediate',
    difficultyLevel: 2,
    route: '/workshop/nosql',
    visible: 1
  },
  {
    key: 'csrf_prompt_injection',
    name: 'CSRF via AI Prompt Injection',
    description: 'Learn how prompt injection and unsafe rendering drive Cross-Site Request Forgery: agent tools, poisoned policy documents, and GET state changes via embedded pixels.',
    category: 'ai',
    difficulty: 'intermediate',
    difficultyLevel: 2,
    route: '/vulnerabilities/csrf-via-ai',
    visible: 1
  },
];

/**
 * Check database integrity and auto-recover if corrupted
 * @returns {Promise<{ok: boolean, recovered: boolean, error?: string}>}
 */
async function checkDatabaseIntegrity() {
  return new Promise((resolve) => {
    // First check if database file exists
    if (!fs.existsSync(authDbPath)) {
      console.log('   ℹ️  Database file does not exist, will be created fresh');
      resolve({ ok: true, recovered: false, fresh: true });
      return;
    }

    // Check for WAL/SHM lock files that might indicate corruption
    const walPath = authDbPath + '-wal';
    const shmPath = authDbPath + '-shm';
    
    // Try to open and check integrity
    const testDb = new sqlite3.Database(authDbPath, sqlite3.OPEN_READONLY, (err) => {
      if (err) {
        console.error('   ⚠️  Database open error:', err.message);
        handleCorruptedDatabase(resolve);
        return;
      }

      testDb.get("PRAGMA integrity_check", (err, row) => {
        if (err) {
          console.error('   ⚠️  Integrity check failed:', err.message);
          testDb.close(() => handleCorruptedDatabase(resolve));
          return;
        }

        if (row && row.integrity_check === 'ok') {
          console.log('   ✅ Database integrity check passed');
          testDb.close(() => resolve({ ok: true, recovered: false }));
        } else {
          console.error('   ⚠️  Database integrity check failed:', row?.integrity_check);
          testDb.close(() => handleCorruptedDatabase(resolve));
        }
      });
    });
  });
}

/**
 * Handle corrupted database by backing up and recreating
 */
function handleCorruptedDatabase(resolve) {
  console.log('   🔧 Attempting database recovery...');
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const backupDir = path.join(__dirname, '..', '..', 'backups');
  
  // Create backups directory if it doesn't exist
  if (!fs.existsSync(backupDir)) {
    fs.mkdirSync(backupDir, { recursive: true });
  }
  
  // Backup corrupted files
  const filesToBackup = [
    authDbPath,
    authDbPath + '-wal',
    authDbPath + '-shm'
  ];
  
  filesToBackup.forEach(file => {
    if (fs.existsSync(file)) {
      const backupName = path.basename(file) + '.corrupted.' + timestamp;
      const backupPath = path.join(backupDir, backupName);
      try {
        fs.copyFileSync(file, backupPath);
        console.log(`   📦 Backed up: ${backupName}`);
      } catch (e) {
        console.warn(`   ⚠️  Could not backup ${file}: ${e.message}`);
      }
    }
  });
  
  // Remove corrupted files
  filesToBackup.forEach(file => {
    if (fs.existsSync(file)) {
      try {
        fs.unlinkSync(file);
      } catch (e) {
        console.warn(`   ⚠️  Could not remove ${file}: ${e.message}`);
      }
    }
  });
  
  console.log('   ✅ Corrupted database backed up and removed');
  console.log('   ℹ️  Fresh database will be created on startup');
  resolve({ ok: true, recovered: true });
}

/**
 * Verify all required tables exist and create missing ones
 */
function verifyRequiredTables(db) {
  const requiredTables = [
    'users',
    'admin_permissions', 
    'student_progress',
    'challenge_config',
    'activity_logs',
    'user_sessions',
    'email_verification_tokens',
    'password_reset_tokens',
    'challenge_visibility',
    'workshop_progress',
    'challenge_solutions',
    'prompt_injection_progress',
    'prompt_injection_solution_visibility',
    'rag_injection_progress',
    'email_agent_progress',
    'sent_emails_log',
    'prompt_injection_solutions',
    'workshop_config_revision',
    'app_change_revisions',
    'workshop_user_modes',
    'xss_workshop_solution_visibility',
    'xss_workshop_objective_solutions',
    'csrf_workshop_objective_solutions',
    'csrf_victim_state',
    'workshop_objectives_progress',
    'workshop_objective_visibility',
    'workshop_hints',
    'workshop_hint_visibility',
    'ea_solution_visibility',
    'ea_solutions',
    'ipi_solution_visibility',
    'ipi_solutions',
    'mcp_workshop_solution_visibility',
    'mcp_workshop_solutions',
    'sql_injection_solution_visibility',
    'sql_injection_solutions',
    'nosql_injection_solution_visibility',
    'nosql_injection_solutions',
    'system_config',
    'security_settings',
    'workshop_time_tracking',
  ];

  return new Promise((resolve) => {
    db.all("SELECT name FROM sqlite_master WHERE type='table'", (err, rows) => {
      if (err) {
        console.error('   ⚠️  Could not check tables:', err.message);
        resolve({ missing: requiredTables });
        return;
      }

      const existingTables = rows ? rows.map(r => r.name) : [];
      const missingTables = requiredTables.filter(t => !existingTables.includes(t));
      
      if (missingTables.length > 0) {
        console.log(`   ℹ️  Missing tables will be created: ${missingTables.join(', ')}`);
      } else {
        console.log('   ✅ All required tables exist');
      }
      
      resolve({ missing: missingTables, existing: existingTables });
    });
  });
}

// Run integrity check before creating main connection
let integrityCheckComplete = false;
checkDatabaseIntegrity().then((result) => {
  integrityCheckComplete = true;
  if (result.recovered) {
    console.log('   ℹ️  Database was recovered from corruption');
  }
}).catch((err) => {
  console.error('   ⚠️  Integrity check error:', err.message);
  integrityCheckComplete = true;
});

// Create authentication database connection with security settings
const authDb = new sqlite3.Database(authDbPath, (err) => {
  if (err) {
    console.error('❌ Error opening authentication database:', err.message);
    process.exit(1); // Critical error - cannot proceed without auth database
  } else {
    console.log('🔐 Connected to USER AUTHENTICATION database (users_auth.db)');
    console.log('   ℹ️  This database is SEPARATE from vulnerable workshop databases');
    console.log('   🔒 Security: Bcrypt hashing, prepared statements, session management');
    
    // Apply security configurations
    applySecurityConfiguration();
    
    // Verify tables and initialize
    verifyRequiredTables(authDb).then(() => {
      initializeAuthDatabase();
      // Warm the login read path so the FIRST user login doesn't pay the cold
      // EFS page-fault + WAL-init latency on users_auth.db. Fire-and-forget,
      // runs after init has created/seeded the users table. This is the DB the
      // /api/auth/login handler hits, so priming it removes the "first login is
      // slow reaching the DB" stall under a cold container.
      setTimeout(() => {
        try {
          authDb.get('SELECT id FROM users LIMIT 1', () => {});
          authDb.run('PRAGMA wal_checkpoint(PASSIVE)', () => {});
        } catch (_) { /* best-effort warm-up only */ }
      }, 2500);
    });
    
    // Set secure file permissions (Unix/Linux/Mac)
    if (process.platform !== 'win32') {
      try {
        fs.chmodSync(authDbPath, 0o600); // Read/write for owner only
        console.log('   ✅ File permissions set to 600 (owner read/write only)');
      } catch (err) {
        console.warn('   ⚠️  Could not set file permissions:', err.message);
      }
    }
  }
});

/**
 * Apply database-level security configurations
 */
function applySecurityConfiguration() {
  // Enable foreign key constraints for data integrity
  authDb.run("PRAGMA foreign_keys = ON", (err) => {
    if (err) {
      console.error('❌ Error enabling foreign keys:', err);
    } else {
      console.log('   ✅ Foreign key constraints enabled');
    }
  });
  
  // Enable Write-Ahead Logging for better concurrency and crash recovery
  authDb.run("PRAGMA journal_mode = WAL", (err) => {
    if (err) {
      console.error('❌ Error setting journal mode:', err);
    } else {
      console.log('   ✅ WAL mode enabled for better security & performance');
    }
  });
  
  // Set secure delete to overwrite deleted data
  authDb.run("PRAGMA secure_delete = ON", (err) => {
    if (err) {
      console.error('❌ Error enabling secure delete:', err);
    } else {
      console.log('   ✅ Secure delete enabled (overwrites deleted data)');
    }
  });
  
  // Enforce strict type checking
  authDb.run("PRAGMA legacy_alter_table = OFF", (err) => {
    if (!err) {
      console.log('   ✅ Strict schema enforcement enabled');
    }
  });
}

function initializeAuthDatabase() {
  console.log('   📋 Initializing secure authentication database schema...');
  
  // Users table - For actual workshop users (students, admins)
  // SECURITY: Uses prepared statements, bcrypt hashing, account lockout
  authDb.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL CHECK(length(username) >= 3 AND length(username) <= 50),
    email TEXT UNIQUE NOT NULL CHECK(email LIKE '%_@__%.__%'),
    password TEXT NOT NULL CHECK(length(password) >= 60), -- Bcrypt hash is 60 chars
    role TEXT DEFAULT 'student' CHECK (role IN ('student', 'admin', 'super_admin')),
    admin_level INTEGER DEFAULT 0 CHECK (admin_level BETWEEN 0 AND 2),
    full_name TEXT CHECK(length(full_name) <= 100),
    phone TEXT CHECK(length(phone) <= 20),
    department TEXT CHECK(length(department) <= 100),
    profile_image TEXT,
    email_verified INTEGER DEFAULT 0 CHECK (email_verified IN (0, 1)),
    is_active INTEGER DEFAULT 1 CHECK (is_active IN (0, 1)),
    account_locked_until DATETIME,
    login_attempts INTEGER DEFAULT 0 CHECK (login_attempts >= 0),
    last_login DATETIME,
    last_password_change DATETIME DEFAULT CURRENT_TIMESTAMP,
    password_reset_required INTEGER DEFAULT 0 CHECK (password_reset_required IN (0, 1)),
    two_factor_enabled INTEGER DEFAULT 0 CHECK (two_factor_enabled IN (0, 1)),
    two_factor_secret TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_by_ip TEXT,
    last_login_ip TEXT
  )`, (err) => {
    if (err) {
      console.error('❌ Error creating users table:', err);
    } else {
      console.log('   ✓ Users table created/verified (with security constraints)');
    }
  });

  // Admin permissions table
  authDb.run(`CREATE TABLE IF NOT EXISTS admin_permissions (
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
    FOREIGN KEY (admin_id) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY (granted_by) REFERENCES users (id),
    UNIQUE(admin_id, permission_name)
  )`, (err) => {
    if (err) {
      console.error('Error creating admin_permissions table:', err);
    } else {
      console.log('   ✓ Admin permissions table created/verified');
    }
  });

  // Student progress tracking table
  authDb.run(`CREATE TABLE IF NOT EXISTS student_progress (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER NOT NULL,
    challenge_key TEXT NOT NULL,
    challenge_name TEXT NOT NULL,
    category TEXT NOT NULL,
    status TEXT DEFAULT 'not_started' CHECK (status IN ('not_started', 'in_progress', 'completed', 'failed')),
    score INTEGER DEFAULT 0,
    max_score INTEGER DEFAULT 100,
    attempts INTEGER DEFAULT 0,
    time_spent INTEGER DEFAULT 0,
    hints_used INTEGER DEFAULT 0,
    started_at DATETIME,
    completed_at DATETIME,
    last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
    notes TEXT,
    FOREIGN KEY (student_id) REFERENCES users (id) ON DELETE CASCADE,
    UNIQUE(student_id, challenge_key)
  )`, (err) => {
    if (err) {
      console.error('Error creating student_progress table:', err);
    } else {
      console.log('   ✓ Student progress table created/verified');
    }
  });

  // Challenge configuration table
  authDb.run(`CREATE TABLE IF NOT EXISTS challenge_config (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    challenge_key TEXT UNIQUE NOT NULL,
    challenge_name TEXT NOT NULL,
    category TEXT NOT NULL,
    difficulty_level INTEGER DEFAULT 1,
    max_score INTEGER DEFAULT 100,
    time_limit INTEGER,
    route TEXT,
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
  )`, (err) => {
    if (err) {
      console.error('Error creating challenge_config table:', err);
    } else {
      console.log('   ✓ Challenge config table created/verified');
    }
  });

  // Activity logs for security auditing
  authDb.run(`CREATE TABLE IF NOT EXISTS activity_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action_type TEXT NOT NULL,
    action_details TEXT,
    ip_address TEXT,
    user_agent TEXT,
    session_id TEXT,
    risk_level TEXT DEFAULT 'low',
    success INTEGER DEFAULT 1,
    error_message TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
  )`, (err) => {
    if (err) {
      console.error('Error creating activity_logs table:', err);
    } else {
      console.log('   ✓ Activity logs table created/verified');
    }
  });

  // User sessions table
  authDb.run(`CREATE TABLE IF NOT EXISTS user_sessions (
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
    revoked_at DATETIME,
    revoked_by INTEGER,
    revoke_reason TEXT,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY (revoked_by) REFERENCES users (id)
  )`, (err) => {
    if (err) {
      console.error('Error creating user_sessions table:', err);
    } else {
      console.log('   ✓ User sessions table created/verified');
    }
  });

  // Email verification tokens
  authDb.run(`CREATE TABLE IF NOT EXISTS email_verification_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT UNIQUE NOT NULL,
    expires_at DATETIME NOT NULL,
    used INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
  )`, (err) => {
    if (err) {
      console.error('Error creating email_verification_tokens table:', err);
    } else {
      console.log('   ✓ Email verification tokens table created/verified');
    }
  });

  // Password reset tokens
  authDb.run(`CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT UNIQUE NOT NULL,
    expires_at DATETIME NOT NULL,
    used INTEGER DEFAULT 0,
    ip_address TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
  )`, (err) => {
    if (err) {
      console.error('Error creating password_reset_tokens table:', err);
    } else {
      console.log('   ✓ Password reset tokens table created/verified');
    }
  });

  // Challenge visibility management (migrated from vulnerable DB)
  authDb.run(`CREATE TABLE IF NOT EXISTS challenge_visibility (
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
  )`, (err) => {
    if (err) {
      console.error('Error creating challenge_visibility table:', err);
    } else {
      console.log('   ✓ Challenge visibility table created/verified');
    }
  });

  // Migration: add show_hints column if missing (for existing databases)
  authDb.run(`ALTER TABLE challenge_visibility ADD COLUMN show_hints INTEGER DEFAULT 0`, (err) => {
    if (err && !err.message.includes('duplicate column')) {
      console.error('Error adding show_hints column:', err);
    }
  });

  // Migration: remove deprecated exercise keys that were removed from the platform
  const deprecatedChallengeKeys = [
    'sql_injection_prompt',
    'order_query_injection',
    'agentic_ai_tool_extraction',
    'file_reading_agent',
    'sql_nosql_workshop',
    'xss_workshop',
    'remote_code_execution'
  ];
  authDb.run(
    `DELETE FROM challenge_visibility WHERE challenge_key IN (${deprecatedChallengeKeys.map(() => '?').join(',')})`,
    deprecatedChallengeKeys,
    (err) => {
      if (err) console.error('Error removing deprecated challenge keys:', err);
    }
  );

  // Migration: remove sql_nosql_workshop from all tables (replaced by separate ARIA/NOVA workshops)
  authDb.run(`DELETE FROM challenge_solutions WHERE challenge_key = 'sql_nosql_workshop'`);
  authDb.run(`DELETE FROM workshop_objective_visibility WHERE workshop_key = 'sql_nosql_workshop'`);
  authDb.run(`DELETE FROM workshop_hint_visibility WHERE workshop_key = 'sql_nosql_workshop'`);

  // Migration: drop deprecated sql_nosql_* tables (replaced by sql_injection_* and nosql_injection_*)
  authDb.run(`DROP TABLE IF EXISTS sql_nosql_solution_visibility`);
  authDb.run(`DROP TABLE IF EXISTS sql_nosql_solutions`);

  // Migration: remove remote_code_execution (replaced by mcp_server_rce)
  authDb.run(`DELETE FROM challenge_solutions WHERE challenge_key = 'remote_code_execution'`);
  authDb.run(`DELETE FROM workshop_objective_visibility WHERE workshop_key = 'remote_code_execution'`);
  authDb.run(`DELETE FROM workshop_hint_visibility WHERE workshop_key = 'remote_code_execution'`);
  authDb.run(`DROP TABLE IF EXISTS rce_solution_visibility`);
  authDb.run(`DROP TABLE IF EXISTS rce_solutions`);

  // Consolidation self-heal: purge stale workshop_hints for retired keys.
  authDb.run(`DELETE FROM workshop_hints WHERE workshop_key IN ('sql_nosql_workshop','remote_code_execution')`);

  // Disable visibility for objectives that have NO authored solution/hint content
  // (dead panels). They still count toward progress; just no hint/solution button.
  authDb.run(`UPDATE ea_solution_visibility SET solutions_enabled = 0 WHERE objective_id IN ('objective_7','objective_8','objective_9')`);
  authDb.run(`UPDATE ipi_solution_visibility SET solutions_enabled = 0 WHERE objective_id LIKE 'email_%'`);
  authDb.run(`UPDATE workshop_hint_visibility SET is_enabled = 0 WHERE workshop_key = 'excessive_agency' AND objective_id IN ('objective_7','objective_8','objective_9')`);
  authDb.run(`UPDATE workshop_hint_visibility SET is_enabled = 0 WHERE workshop_key = 'indirect_prompt_injection' AND objective_id LIKE 'email_%'`);
  authDb.run(`UPDATE workshop_hint_visibility SET is_enabled = 0 WHERE workshop_key = 'sensitive_info_disclosure' AND objective_id IN ('ssrf_oob','error_leak','admin_enum','admin_backup','admin_dl_backup','admin_read_logs','admin_llm_logs','admin_modify_logs','admin_secrets','admin_dirlist')`);

  // Migration: remove the pre-redesign MCP objective IDs. The MCP lab was
  // rebuilt around 7 attack techniques; earlier DBs still carry the 6 legacy
  // single-technique IDs. Seeding is INSERT OR IGNORE (never deletes), so
  // these stale rows lingered in mcp_workshop_solution_visibility /
  // mcp_workshop_solutions and polluted the admin Solutions panel.
  const staleMcpObjectiveIds = [
    'mcp_run_allowed', 'mcp_injection_bypass', 'mcp_read_secret',
    'mcp_env_leak', 'mcp_master_rce', 'mcp_discover_tools'
  ];
  const staleMcpPlaceholders = staleMcpObjectiveIds.map(() => '?').join(',');
  authDb.run(
    `DELETE FROM mcp_workshop_solution_visibility WHERE objective_id IN (${staleMcpPlaceholders})`,
    staleMcpObjectiveIds,
    (err) => { if (err && !err.message.includes('no such table')) console.error('Error pruning stale MCP solution visibility:', err); }
  );
  authDb.run(
    `DELETE FROM mcp_workshop_solutions WHERE objective_id IN (${staleMcpPlaceholders})`,
    staleMcpObjectiveIds,
    (err) => { if (err && !err.message.includes('no such table')) console.error('Error pruning stale MCP solution content:', err); }
  );

  // Migration: refresh the MCP challenge_solutions title/description to the
  // 11-technique framing (INSERT OR IGNORE never updates existing rows).
  authDb.run(
    `UPDATE challenge_solutions
     SET solution_title = 'MCP Server Lab Solutions',
         solution_description = 'Workshop solutions for all 11 MCP attack techniques: recon, command injection, SSRF, tool poisoning, indirect injection, confused deputy, broken authorization, secret exposure, supply-chain tampering, audit-trail tampering, and shadow servers'
     WHERE challenge_key = 'mcp_server_rce'
       AND solution_description NOT LIKE '%11 MCP attack techniques%'`
  );

  // Migration: fix reflected_xss_llm solution title (was "XSS in AI Powered Web App Solutions")
  authDb.run(
    `UPDATE challenge_solutions SET solution_title = 'XSS in AI Powered Chat System Solutions'
     WHERE challenge_key = 'reflected_xss_llm' AND solution_title != 'XSS in AI Powered Chat System Solutions'`
  );

  // Migration: remove stale sensitive_info_disclosure objective IDs from visibility tables
  const staleSensitiveInfoIds = [
    'traversal_config','traversal_statement','ssrf_metadata','ssrf_cloud','ssrf_custom',
    'admin_inject','admin_exfil','admin_privesc','admin_full_exfil','combined_ssrf_admin','exfiltrate_all'
  ];
  const stalePlaceholders = staleSensitiveInfoIds.map(() => '?').join(',');
  authDb.run(
    `DELETE FROM workshop_objective_visibility WHERE workshop_key = 'sensitive_info_disclosure' AND objective_id IN (${stalePlaceholders})`,
    staleSensitiveInfoIds
  );
  authDb.run(
    `DELETE FROM workshop_hint_visibility WHERE workshop_key = 'sensitive_info_disclosure' AND objective_id IN (${stalePlaceholders})`,
    staleSensitiveInfoIds
  );

  // Migration: ensure rate limiting config rows exist (disabled by default)
  authDb.run(`INSERT OR IGNORE INTO system_config (config_key, config_value, config_type, description)
    VALUES ('enable_rate_limiting', 'false', 'boolean', 'Enable API rate limiting on authentication endpoints (disable for workshops to prevent student lockouts)')`,
    (err) => { if (err && !err.message.includes('no such table')) console.error('Error seeding enable_rate_limiting:', err); }
  );
  authDb.run(`INSERT OR IGNORE INTO system_config (config_key, config_value, config_type, description)
    VALUES ('login_rate_limit_max', '20', 'number', 'Maximum login attempts per 15-minute window per IP address')`,
    (err) => { if (err && !err.message.includes('no such table')) console.error('Error seeding login_rate_limit_max:', err); }
  );
  authDb.run(`INSERT OR IGNORE INTO system_config (config_key, config_value, config_type, description, is_public)
    VALUES ('secureshop_visible', 'true', 'boolean', 'Show SecureShop Playground card on landing and workshop pages', 1)`,
    (err) => { if (err && !err.message.includes('no such table')) console.error('Error seeding secureshop_visible:', err); }
  );

  // Workshop progress table (for compatibility)
  // NOTE: UNIQUE(user_id, challenge_id) is REQUIRED — progressSync.js relies on
  // `ON CONFLICT(user_id, challenge_id)` to upsert the workshop-level status and
  // on `INSERT OR IGNORE` to avoid duplicate "in_progress" rows. Fresh DBs get
  // it from this DDL; existing DBs (created before the constraint was added) are
  // repaired by the idempotent migration below.
  authDb.run(`CREATE TABLE IF NOT EXISTS workshop_progress (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    challenge_id TEXT NOT NULL,
    status TEXT DEFAULT 'locked',
    completed_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id),
    UNIQUE(user_id, challenge_id)
  )`, (err) => {
    if (err) {
      console.error('Error creating workshop_progress table:', err);
    } else {
      console.log('   ✓ Workshop progress table created/verified');
      // ── Migration: guarantee a UNIQUE(user_id, challenge_id) index ────────
      // Older DBs created this table WITHOUT the unique constraint, so
      // `ON CONFLICT(user_id, challenge_id)` in checkAndMarkWorkshopComplete()
      // threw ("no matching PRIMARY KEY or UNIQUE constraint") and NO workshop
      // was ever marked completed, while `INSERT OR IGNORE` piled up duplicate
      // in_progress rows. Collapse duplicates (keeping any completed row), then
      // create the unique index so ON CONFLICT resolves against it.
      authDb.get(
        `SELECT COUNT(*) AS dupes FROM (
           SELECT user_id, challenge_id FROM workshop_progress
           GROUP BY user_id, challenge_id HAVING COUNT(*) > 1
         )`,
        (dupErr, row) => {
          const finishIndex = () => {
            authDb.run(
              `CREATE UNIQUE INDEX IF NOT EXISTS idx_workshop_progress_user_challenge
                 ON workshop_progress(user_id, challenge_id)`,
              (idxErr) => {
                if (idxErr) console.error('   ⚠️  workshop_progress unique index:', idxErr.message);
              }
            );
          };
          if (!dupErr && row && row.dupes > 0) {
            // Keep one row per (user_id, challenge_id): prefer a completed row,
            // then the most recent completion, then the earliest id.
            authDb.run(
              `DELETE FROM workshop_progress
                WHERE id NOT IN (
                  SELECT id FROM (
                    SELECT id, ROW_NUMBER() OVER (
                      PARTITION BY user_id, challenge_id
                      ORDER BY (status = 'completed') DESC, completed_at DESC, id ASC
                    ) AS rn
                    FROM workshop_progress
                  ) WHERE rn = 1
                )`,
              (delErr) => {
                if (delErr) console.error('   ⚠️  workshop_progress de-dupe:', delErr.message);
                else console.log(`   ✓ workshop_progress de-duplicated (${row.dupes} collided key(s))`);
                finishIndex();
              }
            );
          } else {
            finishIndex();
          }
        }
      );
    }
  });

  // Challenge solutions table
  authDb.run(`CREATE TABLE IF NOT EXISTS challenge_solutions (
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
  )`, (err) => {
    if (err) {
      console.error('Error creating challenge_solutions table:', err);
    } else {
      console.log('   ✓ Challenge solutions table created/verified');
      // Seed challenge_solutions entries for workshops that have per-objective solution tables.
      // These entries make the workshop appear in the admin solutions grid (GET /api/admin/solutions).
      // is_public defaults to 0; toggling via the admin UI syncs the per-workshop tables.
      const newWorkshopSolutions = [
        ['excessive_agency',          'Excessive Agency Exercise Solutions',         'Workshop solutions covering all 9 excessive agency objectives'],
        ['indirect_prompt_injection', 'Indirect Prompt Injection Solutions',         'Workshop solutions for RAG-based indirect prompt injection attacks'],
        ['mcp_server_rce',             'MCP Server Lab Solutions',                     'Workshop solutions for all 11 MCP attack techniques: recon, command injection, SSRF, tool poisoning, indirect injection, confused deputy, broken authorization, secret exposure, supply-chain tampering, audit-trail tampering, and shadow servers'],
        ['direct_prompt_injection',   'Direct Prompt Injection Exercise Solutions',  'Workshop solutions for all 8 direct prompt injection objectives'],
        ['reflected_xss_llm',         'XSS in AI Powered Chat System Solutions',     'Workshop solutions for reflected, stored, LLM-generated, and email XSS objectives'],
        ['sensitive_info_disclosure',  'Sensitive Information Disclosure Solutions',  'Workshop solutions for all sensitive info disclosure objectives'],
        ['supply_chain_rce',          'Supply Chain RCE Lab Solutions',              'Workshop solutions for all supply chain RCE objectives'],
        ['sql_injection_workshop',    'SQL Injection Exercise Solutions',             'Workshop solutions for all 10 SQL injection objectives covering UNION-based attacks, schema enumeration, and data exfiltration'],
        ['nosql_injection_workshop',  'NoSQL Injection Exercise Solutions',           'Workshop solutions for all 10 NoSQL injection objectives covering operator injection, regex bypass, and data exfiltration'],
        ['csrf_prompt_injection',    'CSRF via AI Prompt Injection Solutions',       'Workshop solutions for all 12 CSRF Attack Console objectives across 4 tabs: GET (g1-g3), POST (p1-p3), XSS token-bypass (x1-x3), Indirect/AI-agent (i1-i3)'],
      ];
      newWorkshopSolutions.forEach(([key, title, desc]) => {
        authDb.run(
          `INSERT OR IGNORE INTO challenge_solutions (challenge_key, solution_title, solution_description, is_public)
           VALUES (?, ?, ?, 0)`,
          [key, title, desc]
        );
      });
    }
  });

  // Prompt Injection Workshop progress (8 objectives). user_key = per user/session for isolation.
  authDb.run(`CREATE TABLE IF NOT EXISTS prompt_injection_progress (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL DEFAULT 0,
    user_key TEXT NOT NULL,
    objective_id TEXT NOT NULL,
    completed INTEGER DEFAULT 0,
    interaction_count INTEGER DEFAULT 0,
    completed_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_key, objective_id)
  )`, (err) => {
    if (err) {
      console.error('Error creating prompt_injection_progress table:', err);
    } else {
      console.log('   ✓ Prompt injection progress table created/verified');
    }
    // Migration: add user_key to existing tables that don't have it (legacy DBs)
    authDb.all('PRAGMA table_info(prompt_injection_progress)', (err2, cols) => {
      if (err2 || !cols) return;
      const hasUserKey = cols.some(c => c.name === 'user_key');
      if (hasUserKey) return;
      authDb.run('ALTER TABLE prompt_injection_progress ADD COLUMN user_key TEXT', (err3) => {
        if (err3) return;
        authDb.run(`UPDATE prompt_injection_progress SET user_key = CAST(user_id AS TEXT) WHERE user_key IS NULL OR user_key = ''`, () => {
          authDb.run('CREATE UNIQUE INDEX IF NOT EXISTS idx_pi_user_key_objective ON prompt_injection_progress(user_key, objective_id)', () => {});
        });
      });
    });
  });

  // Prompt Injection Workshop: admin-controlled solution visibility (7 objectives)
  authDb.run(`CREATE TABLE IF NOT EXISTS prompt_injection_solution_visibility (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    challenge_id TEXT NOT NULL UNIQUE,
    solutions_enabled INTEGER DEFAULT 0,
    enabled_by INTEGER,
    enabled_at DATETIME,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (enabled_by) REFERENCES users (id)
  )`, (err) => {
    if (err) {
      console.error('Error creating prompt_injection_solution_visibility table:', err);
    } else {
      console.log('   ✓ Prompt injection solution visibility table created/verified');
    }
  });

  authDb.run(`INSERT OR IGNORE INTO prompt_injection_solution_visibility (challenge_id, solutions_enabled)
    VALUES ('system_prompt', 0), ('jailbreak', 0), ('multi_language', 0), ('virtualization', 0),
            ('role_playing', 0), ('side_stepping', 0), ('obfuscation', 0)`, (err) => {
    if (err) console.error('Error seeding prompt_injection_solution_visibility:', err);
  });

  // RAG Indirect Prompt Injection progress (per user/session: rag_upload, rag_query, rag_injection)
  authDb.run(`CREATE TABLE IF NOT EXISTS rag_injection_progress (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_key TEXT NOT NULL,
    objective_id TEXT NOT NULL,
    completed INTEGER DEFAULT 0,
    completed_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_key, objective_id)
  )`, (err) => {
    if (err) {
      console.error('Error creating rag_injection_progress table:', err);
    } else {
      console.log('   ✓ RAG injection progress table created/verified');
    }
  });

  // Email Agent Indirect Prompt Injection progress (5 objectives per user/session)
  authDb.run(`CREATE TABLE IF NOT EXISTS email_agent_progress (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_key TEXT NOT NULL,
    objective_number INTEGER NOT NULL CHECK (objective_number BETWEEN 1 AND 5),
    completed INTEGER DEFAULT 0,
    user_email TEXT,
    completed_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_key, objective_number)
  )`, (err) => {
    if (err) {
      console.error('Error creating email_agent_progress table:', err);
    } else {
      console.log('   ✓ Email agent progress table created/verified');
    }
  });

  // Email Agent sent emails audit log (for reversed flow - workshop sends TO user)
  authDb.run(`CREATE TABLE IF NOT EXISTS sent_emails_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_key TEXT NOT NULL,
    recipient_email TEXT NOT NULL,
    scenario_type TEXT,
    email_subject TEXT,
    sent_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    gmail_message_id TEXT
  )`, (err) => {
    if (err) {
      console.error('Error creating sent_emails_log table:', err);
    } else {
      console.log('   ✓ Sent emails log table created/verified');
    }
  });

  // New table for Prompt Injection objective solutions content
  authDb.run(`CREATE TABLE IF NOT EXISTS prompt_injection_solutions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    challenge_id TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    difficulty TEXT,
    hints TEXT DEFAULT '[]', -- JSON array of progressive hint strings
    examples TEXT, -- JSON array of {prompt, explanation}
    approach TEXT,
    tips TEXT,     -- JSON array of strings
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`, (err) => {
    if (err) {
      console.error('Error creating prompt_injection_solutions table:', err);
    } else {
      console.log('   ✓ Prompt injection solutions content table created/verified');
      ensureWorkshopConfigSchema(authDb)
        .then(() => {
          const initialSolutions = require('../data/promptInjectionSolutions').solutions;
          const stmt = authDb.prepare(`INSERT INTO prompt_injection_solutions
            (challenge_id, title, difficulty, hints, examples, approach, tips, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(challenge_id) DO UPDATE SET
              title=excluded.title,
              difficulty=excluded.difficulty,
              hints=excluded.hints,
              examples=excluded.examples,
              approach=excluded.approach,
              tips=excluded.tips,
              updated_at=CURRENT_TIMESTAMP`);
          Object.entries(initialSolutions).forEach(([cid, s]) => {
            stmt.run(cid, s.title, s.difficulty, JSON.stringify(s.hints || []),
              JSON.stringify(s.examples || []), s.approach || '', JSON.stringify(s.tips || []));
          });
          stmt.finalize();
          console.log('   ✓ Reconciled prompt_injection_solutions to data file');
        })
        .catch((schemaError) => {
          console.error('Error ensuring workshop config schema:', schemaError);
        });
    }
  });

  // XSS Workshop: admin-controlled solution visibility (4 exercises)
  authDb.run(`CREATE TABLE IF NOT EXISTS xss_workshop_solution_visibility (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    challenge_id TEXT NOT NULL UNIQUE,
    solutions_enabled INTEGER DEFAULT 0,
    enabled_by INTEGER,
    enabled_at DATETIME,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (enabled_by) REFERENCES users (id)
  )`, (err) => {
    if (err) {
      console.error('Error creating xss_workshop_solution_visibility table:', err);
    } else {
      console.log('   ✓ XSS workshop solution visibility table created/verified');
      // Seed 4 exercise rows (idempotent)
      ['reflected', 'stored_user', 'stored_llm', 'email'].forEach(cid => {
        authDb.run(
          `INSERT OR IGNORE INTO xss_workshop_solution_visibility (challenge_id, solutions_enabled) VALUES (?, 0)`,
          [cid]
        );
      });
    }
  });

  // XSS Workshop: per-objective solution content (12 objectives)
  authDb.run(`CREATE TABLE IF NOT EXISTS xss_workshop_objective_solutions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    objective_id TEXT NOT NULL UNIQUE,
    exercise_id TEXT NOT NULL,
    title TEXT NOT NULL,
    hint TEXT,
    example TEXT,
    explanation TEXT,
    solutions_enabled INTEGER DEFAULT 1,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`, (err) => {
    if (err) {
      console.error('Error creating xss_workshop_objective_solutions table:', err);
    } else {
      console.log('   ✓ XSS workshop objective solutions table created/verified');
      // Seed 12 objective rows if table is empty
      authDb.get('SELECT COUNT(*) as count FROM xss_workshop_objective_solutions', (err2, row) => {
        if (!err2 && row && row.count === 0) {
          const { objectiveSolutions } = require('../data/xssWorkshopSolutions');
          objectiveSolutions.forEach(obj => {
            authDb.run(
              `INSERT OR IGNORE INTO xss_workshop_objective_solutions
               (objective_id, exercise_id, title, hint, example, explanation, solutions_enabled)
               VALUES (?, ?, ?, ?, ?, ?, 1)`,
              [obj.objective_id, obj.exercise_id, obj.title, obj.hint, obj.example, obj.explanation]
            );
          });
          console.log('   ✓ Seeded xss_workshop_objective_solutions (12 rows)');
        }
      });
    }
  });

  // CSRF Workshop: drop the retired tab-level solution tables (superseded by the
  // per-objective system). Self-heals any pre-existing DB that still has them.
  authDb.run(`DROP TABLE IF EXISTS csrf_workshop_solutions`);
  authDb.run(`DROP TABLE IF EXISTS csrf_workshop_solution_visibility`);

  // CSRF Workshop: persistent per-user victim state (survives server restarts).
  // One row per sandbox session_key; state_json is the full per-tab victim state.
  // Cleared only when the student hits Reset tab / Reset all.
  authDb.run(`CREATE TABLE IF NOT EXISTS csrf_victim_state (
    session_key TEXT PRIMARY KEY,
    state_json  TEXT NOT NULL,
    updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP
  )`, (err) => {
    if (err) console.error('Error creating csrf_victim_state table:', err);
    else console.log('   ✓ CSRF victim state table created/verified');
  });

  // CSRF Workshop: per-objective solution content (12 objectives)
  authDb.run(`CREATE TABLE IF NOT EXISTS csrf_workshop_objective_solutions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    objective_id TEXT NOT NULL UNIQUE,
    exercise_id TEXT NOT NULL,
    title TEXT NOT NULL,
    hint TEXT,
    example TEXT,
    explanation TEXT,
    solutions_enabled INTEGER DEFAULT 1,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`, (err) => {
    if (err) {
      console.error('Error creating csrf_workshop_objective_solutions table:', err);
    } else {
      console.log('   ✓ CSRF workshop objective solutions table created/verified');
      const { objectiveSolutions } = require('../data/csrfWorkshopSolutions');
      const validIds = objectiveSolutions.map(o => o.objective_id);
      // Purge any objective rows that are no longer defined (removes the old
      // 8-objective set and any legacy csrf_f*/csrf_a* IDs) so admin UI + stats
      // reflect exactly the current 12.
      authDb.run(
        `DELETE FROM csrf_workshop_objective_solutions WHERE objective_id NOT IN (${validIds.map(() => '?').join(',')})`,
        validIds
      );
      objectiveSolutions.forEach(obj => {
        authDb.run(
          `INSERT INTO csrf_workshop_objective_solutions
             (objective_id, exercise_id, title, hint, example, explanation, solutions_enabled)
           VALUES (?, ?, ?, ?, ?, ?, 1)
           ON CONFLICT(objective_id) DO NOTHING`,
          [obj.objective_id, obj.exercise_id, obj.title, obj.hint, obj.example, obj.explanation]
        );
      });
      migrateKnownCsrfSolutionDefaults(authDb, objectiveSolutions);
      console.log(`   ✓ Ensured csrf_workshop_objective_solutions seeded (${objectiveSolutions.length} rows)`);
    }
  });

  // Central workshop objectives progress table (synced from all workshop routes)
  authDb.run(`CREATE TABLE IF NOT EXISTS workshop_objectives_progress (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    workshop_key TEXT NOT NULL,
    objective_id TEXT NOT NULL,
    objective_label TEXT DEFAULT '',
    objective_category TEXT DEFAULT '',
    completed INTEGER DEFAULT 0,
    completed_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, workshop_key, objective_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  )`, (err) => {
    if (err) console.error('Error creating workshop_objectives_progress table:', err);
    else {
      console.log('   ✓ Workshop objectives progress table created/verified');
      authDb.run(`CREATE INDEX IF NOT EXISTS idx_wop_user ON workshop_objectives_progress(user_id)`);
      authDb.run(`CREATE INDEX IF NOT EXISTS idx_wop_workshop ON workshop_objectives_progress(workshop_key)`);
    }
  });

  // Time tracking — heartbeat-based session duration per workshop per student
  authDb.run(`CREATE TABLE IF NOT EXISTS workshop_time_tracking (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    workshop_key TEXT NOT NULL,
    session_start DATETIME NOT NULL,
    last_heartbeat DATETIME NOT NULL,
    duration_seconds INTEGER DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  )`, (err) => {
    if (err) console.error('Error creating workshop_time_tracking table:', err);
    else console.log('   ✓ Workshop time tracking table created/verified');
  });

  // Objective-level visibility — admin can disable individual objectives within a workshop
  authDb.run(`CREATE TABLE IF NOT EXISTS workshop_objective_visibility (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workshop_key TEXT NOT NULL,
    objective_id TEXT NOT NULL,
    is_enabled INTEGER DEFAULT 1,
    updated_by INTEGER,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(workshop_key, objective_id),
    FOREIGN KEY (updated_by) REFERENCES users(id)
  )`, (err) => {
    if (err) {
      console.error('Error creating workshop_objective_visibility table:', err);
      settlePromptInjectionProgressReady(err);
    }
    else {
      console.log('   ✓ Workshop objective visibility table created/verified');
      authDb.run(`CREATE INDEX IF NOT EXISTS idx_wov_workshop ON workshop_objective_visibility(workshop_key)`);
      // Seed all known objectives as enabled (INSERT OR IGNORE — idempotent)
      const KNOWN_OBJECTIVES = {
        'sensitive_info_disclosure': ['tool_enum','llm_identify','tool_version','traversal_secrets','traversal_passwd','traversal_llm','ssrf_oob','ssrf_internal','ssrf_ollama','error_leak','admin_enum','admin_backup','admin_dl_backup','admin_read_logs','admin_llm_logs','admin_modify_logs','admin_secrets','admin_dirlist'],
        'supply_chain_rce': ['tool_list','pkg_discover','clean_request','rce_env','rce_ssh','rce_cmd'],
        'excessive_agency': ['objective_1','objective_2','objective_3','objective_4','objective_5','objective_6','objective_7','objective_8','objective_9'],
        'direct_prompt_injection': ['interact','system_prompt','jailbreak','multi_language','virtualization','role_playing','side_stepping','obfuscation'],
        'indirect_prompt_injection': ['rag_upload','rag_query','rag_clean_doc','rag_injected_doc','rag_query_injection','email_create_inbox','email_send_attack','email_retrieve','email_trigger_injection','email_understand_defense'],
        'mcp_workshop': ['mcp_recon','mcp_cmd_injection','mcp_ssrf','mcp_tool_poisoning','mcp_indirect_injection','mcp_confused_deputy','mcp_broken_authz','mcp_secret_exposure','mcp_supply_chain','mcp_audit_gap','mcp_shadow_server'],
        'sql_injection_workshop': ['sqli_1','sqli_2','sqli_3','sqli_4','sqli_5','sqli_6','sqli_7','sqli_8','sqli_9','sqli_10'],
        'nosql_injection_workshop': ['nosqli_1','nosqli_2','nosqli_3','nosqli_4','nosqli_5','nosqli_6','nosqli_7','nosqli_8','nosqli_9','nosqli_10'],
        'xss_workshop': ['xss_r1','xss_r2','xss_r3','xss_s1','xss_s2','xss_s3','xss_g1','xss_g2','xss_g3','xss_e1','xss_e2','xss_e3'],
        'csrf_workshop': ['csrf_g1','csrf_g2','csrf_g3','csrf_p1','csrf_p2','csrf_p3','csrf_x1','csrf_x2','csrf_x3','csrf_i1','csrf_i2','csrf_i3'],
      };
      const stmt = authDb.prepare('INSERT OR IGNORE INTO workshop_objective_visibility (workshop_key, objective_id, is_enabled) VALUES (?, ?, 1)');
      for (const [workshopKey, objectives] of Object.entries(KNOWN_OBJECTIVES)) {
        for (const objId of objectives) {
          stmt.run(workshopKey, objId);
        }
        // Remove stale objectives no longer in the known list
        const placeholders = objectives.map(() => '?').join(',');
        authDb.run(
          `DELETE FROM workshop_objective_visibility WHERE workshop_key = ? AND objective_id NOT IN (${placeholders})`,
          [workshopKey, ...objectives]
        );
      }
      stmt.finalize(() => {
        // Self-heal: some DBs left indirect_prompt_injection objectives disabled
        // (INSERT OR IGNORE above never flips an existing is_enabled=0 back to 1).
        // The workshop is live and visible, so ensure its objectives are enabled —
        // otherwise it silently vanishes from the objective totals on all dashboards.
        authDb.run(
          `UPDATE workshop_objective_visibility SET is_enabled = 1
           WHERE workshop_key = 'indirect_prompt_injection'`,
          () => {
            // Older deployments stored DPI completion only in the local table.
            // Queue the idempotent migration after both canonical and visibility
            // tables have been created and the objective catalog has been seeded.
            createPromptInjectionProgressService(authDb).backfillCanonicalProgress()
              .then((inserted) => {
                if (inserted > 0) console.log(`   ✓ Backfilled ${inserted} DPI objective completion(s)`);
                settlePromptInjectionProgressReady();
              })
              .catch((backfillError) => {
                console.error('Error backfilling prompt injection progress:', backfillError);
                settlePromptInjectionProgressReady(backfillError);
              });
          }
        );
      });
    }
  });

  // Hint content — per-objective hint text for all workshops
  authDb.run(`CREATE TABLE IF NOT EXISTS workshop_hints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workshop_key TEXT NOT NULL,
    objective_id TEXT NOT NULL,
    title TEXT,
    hints TEXT DEFAULT '[]',
    UNIQUE(workshop_key, objective_id)
  )`, (err) => {
    if (err) console.error('Error creating workshop_hints table:', err);
    else {
      console.log('   ✓ Workshop hints table created/verified');
      authDb.get('SELECT COUNT(*) as count FROM workshop_hints', (err2, row) => {
        if (!err2 && row && row.count === 0) {
          try {
            const workshopHints = require('../data/workshopHints');
            for (const [wk, objectives] of Object.entries(workshopHints)) {
              seedWorkshopHintRows(authDb, wk, objectives);
            }
            migrateKnownWorkshopHintDefaults(authDb, workshopHints);
            console.log('   ✓ Seeded workshop_hints table');
          } catch (e) { console.error('Error seeding workshop_hints:', e.message); }
        } else if (!err2) {
          try {
            const workshopHints = require('../data/workshopHints');
            // Add any newly published hint rows without overwriting instructor edits.
            for (const [wk, objectives] of Object.entries(workshopHints)) {
              seedWorkshopHintRows(authDb, wk, objectives);
            }
            // Replace only exact legacy defaults; instructor-edited title/hint pairs survive.
            migrateKnownWorkshopHintDefaults(authDb, workshopHints);
            // Ensure newer workshops get their hints seeded even if the table already has data.
            // Editable workshop hints use INSERT OR IGNORE so admin changes survive restarts.
            // MCP and Excessive Agency remain data-file-owned and are reconciled by UPSERT.
            const csrfData = workshopHints['csrf_workshop'];
            if (csrfData) seedWorkshopHintRows(authDb, 'csrf_workshop', csrfData);
            const dpiData = workshopHints['direct_prompt_injection'];
            if (dpiData) seedWorkshopHintRows(authDb, 'direct_prompt_injection', dpiData);
            const ipiData = workshopHints['indirect_prompt_injection'];
            if (ipiData) seedWorkshopHintRows(authDb, 'indirect_prompt_injection', ipiData);
            const mcpData = workshopHints['mcp_workshop'];
            if (mcpData) seedWorkshopHintRows(authDb, 'mcp_workshop', mcpData);
            // Excessive Agency: UPSERT so the 9-objective hints always match the data
            // file. The lab grew from 6 → 9 objectives and the fixed/vuln split was
            // renumbered, so stale INSERT-OR-IGNORE rows would otherwise show the wrong
            // hint under objectives 3-6 and leave 7-9 empty. Data file is the source of truth.
            const eaData = workshopHints['excessive_agency'];
            if (eaData) seedWorkshopHintRows(authDb, 'excessive_agency', eaData);
            // Backfill SQL/NoSQL hints from their solution files (hint arrays live there,
            // NOT in workshopHints.js). Idempotent INSERT OR IGNORE.
            const stmt3 = authDb.prepare('INSERT OR IGNORE INTO workshop_hints (workshop_key, objective_id, title, hints) VALUES (?, ?, ?, ?)');
            for (const [wk, modPath] of [['sql_injection_workshop', '../data/sqlInjectionWorkshopSolutions'], ['nosql_injection_workshop', '../data/nosqlInjectionWorkshopSolutions']]) {
              try {
                const mod = require(modPath);
                for (const [objId, d] of Object.entries(mod)) {
                  stmt3.run(wk, objId, d.title || objId, JSON.stringify(d.hints || []));
                }
              } catch (_) { /* ignore */ }
            }
            stmt3.finalize();
            // Purge stale csrf/mcp hint rows not in the current objective sets.
            authDb.run(`DELETE FROM workshop_hints WHERE workshop_key = 'csrf_workshop' AND objective_id NOT IN ('csrf_g1','csrf_g2','csrf_g3','csrf_p1','csrf_p2','csrf_p3','csrf_x1','csrf_x2','csrf_x3','csrf_i1','csrf_i2','csrf_i3')`);
            authDb.run(`DELETE FROM workshop_hints WHERE workshop_key = 'mcp_workshop' AND objective_id NOT IN ('mcp_recon','mcp_cmd_injection','mcp_ssrf','mcp_tool_poisoning','mcp_indirect_injection','mcp_confused_deputy','mcp_broken_authz','mcp_secret_exposure','mcp_supply_chain','mcp_audit_gap','mcp_shadow_server')`);
          } catch (e) { /* ignore */ }
        }
      });
    }
  });

  // Hint visibility — admin controls which objectives show hints to students
  authDb.run(`CREATE TABLE IF NOT EXISTS workshop_hint_visibility (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workshop_key TEXT NOT NULL,
    objective_id TEXT NOT NULL,
    is_enabled INTEGER DEFAULT 0,
    updated_by INTEGER,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(workshop_key, objective_id),
    FOREIGN KEY (updated_by) REFERENCES users(id)
  )`, (err) => {
    if (err) console.error('Error creating workshop_hint_visibility table:', err);
    else {
      console.log('   ✓ Workshop hint visibility table created/verified');
      authDb.run(`CREATE INDEX IF NOT EXISTS idx_whv_workshop ON workshop_hint_visibility(workshop_key)`);
      // Seed all known objectives with hints disabled by default
      const KNOWN_OBJECTIVES = {
        'sensitive_info_disclosure': ['tool_enum','llm_identify','tool_version','traversal_secrets','traversal_passwd','traversal_llm','ssrf_oob','ssrf_internal','ssrf_ollama','error_leak','admin_enum','admin_backup','admin_dl_backup','admin_read_logs','admin_llm_logs','admin_modify_logs','admin_secrets','admin_dirlist'],
        'supply_chain_rce': ['tool_list','pkg_discover','clean_request','rce_env','rce_ssh','rce_cmd'],
        'excessive_agency': ['objective_1','objective_2','objective_3','objective_4','objective_5','objective_6','objective_7','objective_8','objective_9'],
        'direct_prompt_injection': ['interact','system_prompt','jailbreak','multi_language','virtualization','role_playing','side_stepping','obfuscation'],
        'indirect_prompt_injection': ['rag_upload','rag_query','rag_clean_doc','rag_injected_doc','rag_query_injection','email_create_inbox','email_send_attack','email_retrieve','email_trigger_injection','email_understand_defense'],
        'mcp_workshop': ['mcp_recon','mcp_cmd_injection','mcp_ssrf','mcp_tool_poisoning','mcp_indirect_injection','mcp_confused_deputy','mcp_broken_authz','mcp_secret_exposure','mcp_supply_chain','mcp_audit_gap','mcp_shadow_server'],
        'sql_injection_workshop': ['sqli_1','sqli_2','sqli_3','sqli_4','sqli_5','sqli_6','sqli_7','sqli_8','sqli_9','sqli_10'],
        'nosql_injection_workshop': ['nosqli_1','nosqli_2','nosqli_3','nosqli_4','nosqli_5','nosqli_6','nosqli_7','nosqli_8','nosqli_9','nosqli_10'],
        'xss_workshop': ['xss_r1','xss_r2','xss_r3','xss_s1','xss_s2','xss_s3','xss_g1','xss_g2','xss_g3','xss_e1','xss_e2','xss_e3'],
        'csrf_workshop': ['csrf_g1','csrf_g2','csrf_g3','csrf_p1','csrf_p2','csrf_p3','csrf_x1','csrf_x2','csrf_x3','csrf_i1','csrf_i2','csrf_i3'],
      };
      const stmt2 = authDb.prepare('INSERT OR IGNORE INTO workshop_hint_visibility (workshop_key, objective_id, is_enabled) VALUES (?, ?, 0)');
      for (const [workshopKey, objectives] of Object.entries(KNOWN_OBJECTIVES)) {
        for (const objId of objectives) {
          stmt2.run(workshopKey, objId);
        }
        const placeholders = objectives.map(() => '?').join(',');
        authDb.run(
          `DELETE FROM workshop_hint_visibility WHERE workshop_key = ? AND objective_id NOT IN (${placeholders})`,
          [workshopKey, ...objectives]
        );
      }
      stmt2.finalize();
    }
  });

  // Excessive Agency solution visibility
  authDb.run(`CREATE TABLE IF NOT EXISTS ea_solution_visibility (
    objective_id TEXT PRIMARY KEY,
    solutions_enabled INTEGER DEFAULT 0,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`, (err) => {
    if (err) console.error('Error creating ea_solution_visibility table:', err);
    else {
      console.log('   ✓ Excessive Agency solution visibility table created/verified');
      ['objective_1','objective_2','objective_3','objective_4','objective_5','objective_6','objective_7','objective_8','objective_9'].forEach(oid => {
        authDb.run('INSERT OR IGNORE INTO ea_solution_visibility (objective_id, solutions_enabled) VALUES (?, 0)', [oid]);
      });
    }
  });

  // Excessive Agency solution content
  authDb.run(`CREATE TABLE IF NOT EXISTS ea_solutions (
    objective_id TEXT PRIMARY KEY,
    title TEXT,
    difficulty TEXT,
    hints TEXT DEFAULT '[]',
    examples TEXT DEFAULT '[]',
    approach TEXT,
    tips TEXT DEFAULT '[]'
  )`, (err) => {
    if (err) console.error('Error creating ea_solutions table:', err);
    else {
      console.log('   ✓ Excessive Agency solutions table created/verified');
      // Reconcile (UPSERT) all 9 objectives from the data file on every startup — the
      // lab was renumbered from 6 → 9 objectives, so an INSERT-OR-IGNORE seed would
      // leave stale content under objectives 3-6 and never add 7-9. Data file is the
      // source of truth; the progressive `hints` array comes from workshopHints.js.
      try {
        const { solutions: eaSols } = require('../data/excessiveAgencySolutions');
        const eaHints = (require('../data/workshopHints').excessive_agency) || {};
        const stmt = authDb.prepare(`INSERT INTO ea_solutions (objective_id, title, difficulty, hints, examples, approach, tips)
          VALUES (?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(objective_id) DO UPDATE SET title=excluded.title, difficulty=excluded.difficulty, hints=excluded.hints, examples=excluded.examples, approach=excluded.approach, tips=excluded.tips`);
        Object.entries(eaSols).forEach(([oid, s]) => {
          const hintArr = (eaHints[oid] && eaHints[oid].hints) ? eaHints[oid].hints : [];
          stmt.run(oid, s.title, s.difficulty || 'Easy', JSON.stringify(hintArr), JSON.stringify(s.examples || []), s.approach || '', JSON.stringify(s.tips || []));
          authDb.run('INSERT OR IGNORE INTO ea_solution_visibility (objective_id, solutions_enabled) VALUES (?, 0)', [oid]);
        });
        stmt.finalize();
        console.log('   ✓ Reconciled ea_solutions (9 objectives) to data file');
      } catch (e) { console.error('Error reconciling ea_solutions:', e.message); }
    }
  });

  // Indirect Prompt Injection solution visibility
  authDb.run(`CREATE TABLE IF NOT EXISTS ipi_solution_visibility (
    objective_id TEXT PRIMARY KEY,
    solutions_enabled INTEGER DEFAULT 0,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`, (err) => {
    if (err) console.error('Error creating ipi_solution_visibility table:', err);
    else {
      console.log('   ✓ Indirect PI solution visibility table created/verified');
      ['rag_upload','rag_query','rag_clean_doc','rag_injected_doc','rag_query_injection'].forEach(oid => {
        authDb.run('INSERT OR IGNORE INTO ipi_solution_visibility (objective_id, solutions_enabled) VALUES (?, 0)', [oid]);
      });
    }
  });

  // Indirect Prompt Injection solution content
  authDb.run(`CREATE TABLE IF NOT EXISTS ipi_solutions (
    objective_id TEXT PRIMARY KEY,
    title TEXT,
    difficulty TEXT,
    hints TEXT DEFAULT '[]',
    examples TEXT DEFAULT '[]',
    approach TEXT,
    tips TEXT DEFAULT '[]'
  )`, (err) => {
    if (err) console.error('Error creating ipi_solutions table:', err);
    else {
      console.log('   ✓ Indirect PI solutions table created/verified');
      authDb.get('SELECT COUNT(*) as count FROM ipi_solutions', (err2, row) => {
        if (!err2 && row && row.count === 0) {
          try {
            const ipiSols = require('../data/indirectPromptInjectionSolutions');
            const stmt = authDb.prepare('INSERT OR IGNORE INTO ipi_solutions (objective_id, title, difficulty, hints, examples, approach, tips) VALUES (?, ?, ?, ?, ?, ?, ?)');
            Object.entries(ipiSols).forEach(([oid, s]) => {
              stmt.run(oid, s.title, s.difficulty, JSON.stringify(s.hints || []), JSON.stringify(s.examples || []), s.approach || '', JSON.stringify(s.tips || []));
            });
            stmt.finalize();
            console.log('   ✓ Seeded ipi_solutions table');
          } catch (e) { console.error('Error seeding ipi_solutions:', e.message); }
        }
      });
    }
  });

  // ── SQL Injection Workshop solution visibility ────────────────────────────────
  authDb.run(`CREATE TABLE IF NOT EXISTS sql_injection_solution_visibility (
    objective_id TEXT PRIMARY KEY,
    solutions_enabled INTEGER DEFAULT 0,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`, (err) => {
    if (err) console.error('Error creating sql_injection_solution_visibility table:', err);
    else {
      console.log('   ✓ SQL Injection solution visibility table created/verified');
      ['sqli_1','sqli_2','sqli_3','sqli_4','sqli_5','sqli_6','sqli_7','sqli_8','sqli_9','sqli_10'].forEach(oid => {
        authDb.run('INSERT OR IGNORE INTO sql_injection_solution_visibility (objective_id, solutions_enabled) VALUES (?, 0)', [oid]);
      });
    }
  });

  // ── SQL Injection Workshop solution content ───────────────────────────────────
  authDb.run(`CREATE TABLE IF NOT EXISTS sql_injection_solutions (
    objective_id TEXT PRIMARY KEY,
    title TEXT,
    difficulty TEXT,
    hints TEXT DEFAULT '[]',
    examples TEXT DEFAULT '[]',
    approach TEXT,
    tips TEXT DEFAULT '[]'
  )`, (err) => {
    if (err) console.error('Error creating sql_injection_solutions table:', err);
    else {
      console.log('   ✓ SQL Injection solutions table created/verified');
      authDb.get('SELECT COUNT(*) as count FROM sql_injection_solutions', (err2, row) => {
        if (!err2 && row && row.count === 0) {
          try {
            const sqliSols = require('../data/sqlInjectionWorkshopSolutions');
            const stmt = authDb.prepare('INSERT OR IGNORE INTO sql_injection_solutions (objective_id, title, difficulty, hints, examples, approach, tips) VALUES (?, ?, ?, ?, ?, ?, ?)');
            Object.entries(sqliSols).forEach(([oid, s]) => {
              stmt.run(oid, s.title, s.difficulty, JSON.stringify(s.hints || []), JSON.stringify(s.examples || []), s.approach || '', JSON.stringify(s.tips || []));
            });
            stmt.finalize();
            console.log('   ✓ Seeded sql_injection_solutions table');
          } catch (e) { console.error('Error seeding sql_injection_solutions:', e.message); }
        }
      });
    }
  });

  // ── NoSQL Injection Workshop solution visibility ─────────────────────────────
  authDb.run(`CREATE TABLE IF NOT EXISTS nosql_injection_solution_visibility (
    objective_id TEXT PRIMARY KEY,
    solutions_enabled INTEGER DEFAULT 0,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`, (err) => {
    if (err) console.error('Error creating nosql_injection_solution_visibility table:', err);
    else {
      console.log('   ✓ NoSQL Injection solution visibility table created/verified');
      ['nosqli_1','nosqli_2','nosqli_3','nosqli_4','nosqli_5','nosqli_6','nosqli_7','nosqli_8','nosqli_9','nosqli_10'].forEach(oid => {
        authDb.run('INSERT OR IGNORE INTO nosql_injection_solution_visibility (objective_id, solutions_enabled) VALUES (?, 0)', [oid]);
      });
    }
  });

  // ── NoSQL Injection Workshop solution content ─────────────────────────────────
  authDb.run(`CREATE TABLE IF NOT EXISTS nosql_injection_solutions (
    objective_id TEXT PRIMARY KEY,
    title TEXT,
    difficulty TEXT,
    hints TEXT DEFAULT '[]',
    examples TEXT DEFAULT '[]',
    approach TEXT,
    tips TEXT DEFAULT '[]'
  )`, (err) => {
    if (err) console.error('Error creating nosql_injection_solutions table:', err);
    else {
      console.log('   ✓ NoSQL Injection solutions table created/verified');
      authDb.get('SELECT COUNT(*) as count FROM nosql_injection_solutions', (err2, row) => {
        if (!err2 && row && row.count === 0) {
          try {
            const nosqliSols = require('../data/nosqlInjectionWorkshopSolutions');
            const stmt = authDb.prepare('INSERT OR IGNORE INTO nosql_injection_solutions (objective_id, title, difficulty, hints, examples, approach, tips) VALUES (?, ?, ?, ?, ?, ?, ?)');
            Object.entries(nosqliSols).forEach(([oid, s]) => {
              stmt.run(oid, s.title, s.difficulty, JSON.stringify(s.hints || []), JSON.stringify(s.examples || []), s.approach || '', JSON.stringify(s.tips || []));
            });
            stmt.finalize();
            console.log('   ✓ Seeded nosql_injection_solutions table');
          } catch (e) { console.error('Error seeding nosql_injection_solutions:', e.message); }
        }
      });
    }
  });

  // MCP Workshop solution visibility
  authDb.run(`CREATE TABLE IF NOT EXISTS mcp_workshop_solution_visibility (
    objective_id TEXT PRIMARY KEY,
    solutions_enabled INTEGER DEFAULT 0,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`, (err) => {
    if (err) console.error('Error creating mcp_workshop_solution_visibility table:', err);
    else {
      console.log('   ✓ MCP workshop solution visibility table created/verified');
      ['mcp_recon','mcp_cmd_injection','mcp_ssrf','mcp_tool_poisoning','mcp_indirect_injection','mcp_confused_deputy','mcp_broken_authz','mcp_secret_exposure','mcp_supply_chain','mcp_audit_gap','mcp_shadow_server'].forEach(oid => {
        authDb.run('INSERT OR IGNORE INTO mcp_workshop_solution_visibility (objective_id, solutions_enabled) VALUES (?, 0)', [oid]);
      });
    }
  });

  // MCP Workshop solution content
  authDb.run(`CREATE TABLE IF NOT EXISTS mcp_workshop_solutions (
    objective_id TEXT PRIMARY KEY,
    title TEXT,
    difficulty TEXT,
    hints TEXT DEFAULT '[]',
    examples TEXT DEFAULT '[]',
    approach TEXT,
    tips TEXT DEFAULT '[]'
  )`, (err) => {
    if (err) console.error('Error creating mcp_workshop_solutions table:', err);
    else {
      console.log('   ✓ MCP workshop solutions table created/verified');
      // Content is data-file-driven: mcpWorkshopSolutions.js is the sole source of
      // truth (admin can only toggle visibility, never edit solution text). UPSERT
      // reconciles all 11 rows to the file on every boot, so edits to the data file
      // always propagate to existing databases — no stale content can survive a
      // restart. New objectives are inserted; existing ones are refreshed in place.
      try {
        const mcpSols = require('../data/mcpWorkshopSolutions');
        const stmt = authDb.prepare(`INSERT INTO mcp_workshop_solutions
          (objective_id, title, difficulty, hints, examples, approach, tips)
          VALUES (?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(objective_id) DO UPDATE SET
            title=excluded.title, difficulty=excluded.difficulty, hints=excluded.hints,
            examples=excluded.examples, approach=excluded.approach, tips=excluded.tips`);
        Object.entries(mcpSols).forEach(([oid, s]) => {
          stmt.run(oid, s.title, s.difficulty, JSON.stringify(s.hints || []), JSON.stringify(s.examples || []), s.approach || '', JSON.stringify(s.tips || []));
        });
        stmt.finalize();
        console.log('   ✓ Reconciled mcp_workshop_solutions to data file (UPSERT)');
      } catch (e) { console.error('Error seeding mcp_workshop_solutions:', e.message); }
    }
  });

  authDb.run(`CREATE TABLE IF NOT EXISTS system_config (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    config_key TEXT UNIQUE NOT NULL,
    config_value TEXT,
    config_type TEXT DEFAULT 'string' CHECK (config_type IN ('string', 'boolean', 'number', 'json')),
    description TEXT,
    is_public INTEGER DEFAULT 0,
    updated_by INTEGER,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (updated_by) REFERENCES users (id)
  )`, (err) => {
    if (err) console.error('Error creating system_config table:', err);
    else console.log('   ✓ System config table created/verified');
  });

  authDb.run(`CREATE TABLE IF NOT EXISTS security_settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    setting_key TEXT UNIQUE NOT NULL,
    setting_value TEXT,
    description TEXT,
    category TEXT DEFAULT 'general',
    is_active INTEGER DEFAULT 1,
    updated_by INTEGER,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (updated_by) REFERENCES users (id)
  )`, (err) => {
    if (err) console.error('Error creating security_settings table:', err);
    else console.log('   ✓ Security settings table created/verified');
  });
  // Migrate pre-existing DBs whose security_settings predates the category/
  // is_active columns (CREATE TABLE IF NOT EXISTS won't add them). adminSchema.js
  // seeds INSERTs that reference `category`, so without this the seed throws
  // "no column named category" on every boot. Errors are ignored (idempotent).
  authDb.run(`ALTER TABLE security_settings ADD COLUMN category TEXT DEFAULT 'general'`, () => {});
  authDb.run(`ALTER TABLE security_settings ADD COLUMN is_active INTEGER DEFAULT 1`, () => {});

  syncDefaultChallengeMetadata();

  // Insert default data
  insertDefaultData();
}

function syncDefaultChallengeMetadata() {
  DEFAULT_CHALLENGES.forEach((challenge) => {
    authDb.run(`
      INSERT OR IGNORE INTO challenge_visibility (
        challenge_key, challenge_name, challenge_description, category,
        difficulty, is_visible, route, show_solutions
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 0)
    `, [
      challenge.key,
      challenge.name,
      challenge.description,
      challenge.category,
      challenge.difficulty,
      challenge.visible,
      challenge.route
    ]);

    // Force-update name/description for renamed challenges so existing rows are corrected
    authDb.run(`
      UPDATE challenge_visibility
      SET challenge_name = ?, challenge_description = ?
      WHERE challenge_key = ?
    `, [challenge.name, challenge.description, challenge.key]);

    authDb.run(`
      INSERT OR IGNORE INTO challenge_config (
        challenge_key, challenge_name, category, difficulty_level,
        route, is_enabled, show_solution, description
      ) VALUES (?, ?, ?, ?, ?, ?, 0, ?)
    `, [
      challenge.key,
      challenge.name,
      challenge.category,
      challenge.difficultyLevel,
      challenge.route,
      challenge.visible,
      challenge.description
    ]);

    // Force-update name/description in challenge_config for renamed challenges
    authDb.run(`
      UPDATE challenge_config
      SET challenge_name = ?, description = ?
      WHERE challenge_key = ?
    `, [challenge.name, challenge.description, challenge.key]);
  });

}

function insertDefaultData() {
  // Always ensure the admin account exists (INSERT OR IGNORE is safe)
  const adminPassword = bcrypt.hashSync('Abh1nav@OWASP-AI-GOAT#2026', 10);
  authDb.run(`INSERT OR IGNORE INTO users (username, email, password, role, admin_level, email_verified)
          VALUES ('Abhinav', 'abhinav@owasp-ai-goat.local', ?, 'admin', 2, 1)`, [adminPassword], function(err) {
    if (!err && this.changes > 0) {
      console.log('   ✓ Created admin account: Abhinav');
      const permissions = [
        'user_management', 'challenge_management', 'system_config',
        'view_analytics', 'manage_progress', 'send_notifications',
        'export_data', 'system_logs'
      ];
      permissions.forEach(permission => {
        authDb.run(`INSERT OR IGNORE INTO admin_permissions (admin_id, permission_name, granted_by) 
                VALUES (?, ?, 1)`, [this.lastID, permission]);
      });
    }
  });

  // Check if student/demo users already exist
  authDb.get('SELECT COUNT(*) as count FROM users WHERE username = ?', ['student'], (err, result) => {
    if (err || (result && result.count > 0)) {
      console.log('   ℹ️  Demo accounts already exist, skipping');
      return;
    }

    console.log('   📝 Inserting default users...');

    const studentPassword = bcrypt.hashSync('student123', 10);
    authDb.run(`INSERT OR IGNORE INTO users (username, email, password, role, admin_level) 
            VALUES ('student', 'student@owasp-ai-goat.local', ?, 'student', 0)`, [studentPassword], (err) => {
      if (!err) console.log('   ✓ Created student account: student / student123');
    });

    authDb.run(`INSERT OR IGNORE INTO users (username, email, password, role, admin_level) 
            VALUES ('student123', 'student123@owasp-ai-goat.local', ?, 'student', 0)`, [studentPassword], (err) => {
      if (!err) console.log('   ✓ Created student account: student123 / student123');
    });

    const userPassword = bcrypt.hashSync('password', 10);
    authDb.run(`INSERT OR IGNORE INTO users (username, email, password, role, admin_level) 
            VALUES ('user', 'user@owasp-ai-goat.local', ?, 'student', 0)`, [userPassword], (err) => {
      if (!err) console.log('   ✓ Created user account: user / password');
    });

    const testPassword = bcrypt.hashSync('test123', 10);
    authDb.run(`INSERT OR IGNORE INTO users (username, email, password, role, admin_level) 
            VALUES ('Test User', 'test@owasp-ai-goat.local', ?, 'student', 0)`, [testPassword], (err) => {
      if (!err) console.log('   ✓ Created test account: Test User / test123');
    });

    console.log('   ✓ Default challenge visibility configured');
  });

  console.log('');
  console.log('🔒 ============================================');
  console.log('   AUTHENTICATION DATABASE READY');
  console.log('   Database: users_auth.db');
  console.log('   Purpose: Workshop user authentication');
  console.log('   Status: ISOLATED from vulnerable workshop DBs');
  console.log('   Security: PRODUCTION-GRADE protection enabled');
  console.log('============================================');
}

/**
 * SECURITY UTILITY FUNCTIONS
 * ==========================
 * These functions provide secure database operations with built-in protection
 */

/**
 * Securely validate and sanitize username
 * @param {string} username - Username to validate
 * @returns {object} { valid: boolean, error: string }
 */
function validateUsername(username) {
  if (!username || typeof username !== 'string') {
    return { valid: false, error: 'Username is required and must be a string' };
  }
  
  const trimmed = username.trim();
  
  if (trimmed.length < 3 || trimmed.length > 50) {
    return { valid: false, error: 'Username must be between 3 and 50 characters' };
  }
  
  // Only alphanumeric, underscore, hyphen
  if (!/^[a-zA-Z0-9_-]+$/.test(trimmed)) {
    return { valid: false, error: 'Username can only contain letters, numbers, underscore, and hyphen' };
  }
  
  // Prevent SQL injection keywords in username
  const sqlKeywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER', 'UNION', '--', ';'];
  const upperUsername = trimmed.toUpperCase();
  for (const keyword of sqlKeywords) {
    if (upperUsername.includes(keyword)) {
      return { valid: false, error: 'Username contains invalid characters' };
    }
  }
  
  return { valid: true, sanitized: trimmed };
}

/**
 * Securely validate email
 * @param {string} email - Email to validate
 * @returns {object} { valid: boolean, error: string }
 */
function validateEmail(email) {
  if (!email || typeof email !== 'string') {
    return { valid: false, error: 'Email is required and must be a string' };
  }
  
  const trimmed = email.trim().toLowerCase();
  
  // RFC 5322 compliant email regex (simplified)
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(trimmed)) {
    return { valid: false, error: 'Invalid email format' };
  }
  
  if (trimmed.length > 255) {
    return { valid: false, error: 'Email is too long' };
  }
  
  return { valid: true, sanitized: trimmed };
}

/**
 * Securely validate password strength
 * @param {string} password - Password to validate
 * @returns {object} { valid: boolean, error: string, strength: string }
 */
function validatePassword(password) {
  if (!password || typeof password !== 'string') {
    return { valid: false, error: 'Password is required' };
  }
  
  if (password.length < 8) {
    return { valid: false, error: 'Password must be at least 8 characters long' };
  }
  
  if (password.length > 128) {
    return { valid: false, error: 'Password is too long (max 128 characters)' };
  }
  
  let strength = 0;
  const checks = {
    lowercase: /[a-z]/.test(password),
    uppercase: /[A-Z]/.test(password),
    numbers: /[0-9]/.test(password),
    special: /[^a-zA-Z0-9]/.test(password),
    length: password.length >= 12
  };
  
  if (!checks.lowercase) {
    return { valid: false, error: 'Password must contain at least one lowercase letter' };
  }
  if (!checks.uppercase) {
    return { valid: false, error: 'Password must contain at least one uppercase letter' };
  }
  if (!checks.numbers) {
    return { valid: false, error: 'Password must contain at least one number' };
  }
  if (!checks.special) {
    return { valid: false, error: 'Password must contain at least one special character' };
  }
  
  strength = Object.values(checks).filter(Boolean).length;
  const strengthLabel = strength >= 5 ? 'strong' : strength >= 4 ? 'medium' : 'weak';
  
  return { valid: true, strength: strengthLabel };
}

/**
 * Securely hash password using bcrypt
 * @param {string} password - Plain text password
 * @returns {Promise<string>} Hashed password
 */
async function secureHashPassword(password) {
  const saltRounds = 12; // Industry standard
  return await bcrypt.hash(password, saltRounds);
}

/**
 * Securely compare password with hash
 * @param {string} password - Plain text password
 * @param {string} hash - Bcrypt hash
 * @returns {Promise<boolean>} Match result
 */
async function secureComparePassword(password, hash) {
  return await bcrypt.compare(password, hash);
}

/**
 * Generate secure session token
 * @returns {string} Secure random token
 */
function generateSecureToken() {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Log security event (uses prepared statements)
 * @param {object} event - Event details
 */
function logSecurityEvent(event) {
  const {
    userId = null,
    actionType,
    actionDetails = '',
    ipAddress = 'unknown',
    userAgent = '',
    riskLevel = 'low',
    success = 1,
    errorMessage = null
  } = event;
  
  // SECURITY: Using prepared statement to prevent SQL injection
  authDb.run(
    `INSERT INTO activity_logs 
    (user_id, action_type, action_details, ip_address, user_agent, risk_level, success, error_message)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [userId, actionType, actionDetails, ipAddress, userAgent, riskLevel, success, errorMessage],
    (err) => {
      if (err) {
        console.error('❌ Error logging security event:', err);
      }
    }
  );
}

/**
 * Check if account is locked
 * @param {number} userId - User ID
 * @returns {Promise<object>} Lock status
 */
function checkAccountLockout(userId) {
  return new Promise((resolve, reject) => {
    authDb.get(
      'SELECT account_locked_until, login_attempts FROM users WHERE id = ?',
      [userId],
      (err, row) => {
        if (err) {
          reject(err);
        } else if (!row) {
          resolve({ locked: false });
        } else if (row.account_locked_until) {
          const lockoutTime = new Date(row.account_locked_until);
          const now = new Date();
          resolve({
            locked: lockoutTime > now,
            lockedUntil: row.account_locked_until,
            attempts: row.login_attempts
          });
        } else {
          resolve({ locked: false, attempts: row.login_attempts });
        }
      }
    );
  });
}

// Export authentication database and security utilities
module.exports = {
  authDb,
  promptInjectionProgressReady,
  
  // Security validation functions
  validateUsername,
  validateEmail,
  validatePassword,
  secureHashPassword,
  secureComparePassword,
  generateSecureToken,
  
  // Security logging
  logSecurityEvent,
  checkAccountLockout,
  
  // Database maintenance
  checkDatabaseIntegrity,
  verifyRequiredTables
};
