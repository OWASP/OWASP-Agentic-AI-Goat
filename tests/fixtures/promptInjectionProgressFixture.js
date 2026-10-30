const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const sqlite3 = require('sqlite3').verbose();
const { WORKSHOP_OBJECTIVES } = require('../../server/config/workshopCatalog');

const open = (filename) => new Promise((resolve, reject) => {
  const db = new sqlite3.Database(filename, (error) => error ? reject(error) : resolve(db));
});

const run = (db, sql, params = []) => new Promise((resolve, reject) => {
  db.run(sql, params, function onRun(error) {
    if (error) return reject(error);
    resolve({ changes: this.changes, lastID: this.lastID });
  });
});

const get = (db, sql, params = []) => new Promise((resolve, reject) => {
  db.get(sql, params, (error, row) => error ? reject(error) : resolve(row));
});

const exec = (db, sql) => new Promise((resolve, reject) => {
  db.exec(sql, (error) => error ? reject(error) : resolve());
});

const close = (db) => new Promise((resolve, reject) => {
  db.close((error) => error ? reject(error) : resolve());
});

async function createPromptInjectionProgressFixture({ enabledIds } = {}) {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'owasp-ai-goat-dpi-progress-'));
  const filename = path.join(tempDir, 'progress.db');
  const db = await open(filename);
  await exec(db, `
    PRAGMA journal_mode = WAL;
    PRAGMA busy_timeout = 5000;
    CREATE TABLE users(
      id INTEGER PRIMARY KEY,
      username TEXT NOT NULL
    );
    INSERT INTO users(id, username) VALUES(1, 'student');
    CREATE TABLE challenge_visibility(
      challenge_key TEXT PRIMARY KEY,
      is_visible INTEGER NOT NULL DEFAULT 1
    );
    INSERT INTO challenge_visibility(challenge_key, is_visible)
      VALUES('direct_prompt_injection', 1);
    CREATE TABLE workshop_objective_visibility(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      workshop_key TEXT NOT NULL,
      objective_id TEXT NOT NULL,
      is_enabled INTEGER NOT NULL DEFAULT 1,
      UNIQUE(workshop_key, objective_id)
    );
    CREATE TABLE prompt_injection_progress(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL DEFAULT 0,
      user_key TEXT NOT NULL,
      objective_id TEXT NOT NULL,
      completed INTEGER NOT NULL DEFAULT 0,
      interaction_count INTEGER NOT NULL DEFAULT 0,
      completed_at DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(user_key, objective_id)
    );
    CREATE TABLE workshop_objectives_progress(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      workshop_key TEXT NOT NULL,
      objective_id TEXT NOT NULL,
      objective_label TEXT DEFAULT '',
      objective_category TEXT DEFAULT '',
      completed INTEGER NOT NULL DEFAULT 0,
      completed_at DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(user_id, workshop_key, objective_id)
    );
    CREATE TABLE workshop_progress(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      challenge_id TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'in_progress',
      completed_at DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(user_id, challenge_id)
    );
    CREATE TABLE challenge_objectives_progress(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      challenge_id TEXT NOT NULL,
      objective_id TEXT NOT NULL,
      completed INTEGER NOT NULL DEFAULT 1,
      completed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(user_id, challenge_id, objective_id)
    );
    CREATE TABLE workshop_time_tracking(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      workshop_key TEXT NOT NULL,
      session_start DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      last_heartbeat DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      duration_seconds INTEGER NOT NULL DEFAULT 0
    );
  `);

  const enabled = new Set(enabledIds || WORKSHOP_OBJECTIVES.direct_prompt_injection.map(({ id }) => id));
  for (const { id } of WORKSHOP_OBJECTIVES.direct_prompt_injection) {
    await run(
      db,
      `INSERT INTO workshop_objective_visibility(workshop_key, objective_id, is_enabled)
       VALUES('direct_prompt_injection', ?, ?)`,
      [id, enabled.has(id) ? 1 : 0]
    );
  }

  const peerDb = await open(filename);
  await exec(peerDb, 'PRAGMA busy_timeout = 5000;');
  const { createPromptInjectionProgressService } = require('../../server/services/promptInjectionProgressService');

  return {
    db,
    service: createPromptInjectionProgressService(db),
    peerService: createPromptInjectionProgressService(peerDb),
    run: (sql, params) => run(db, sql, params),
    get: (sql, params) => get(db, sql, params),
    exec: (sql) => exec(db, sql),
    async seedCompletedProgressAndTime() {
      await exec(db, `
        INSERT INTO prompt_injection_progress(user_id, user_key, objective_id, completed, completed_at)
          VALUES(1, '1', 'interact', 1, CURRENT_TIMESTAMP);
        INSERT INTO workshop_objectives_progress
          (user_id, workshop_key, objective_id, objective_label, completed, completed_at)
          VALUES(1, 'direct_prompt_injection', 'interact', 'Interact with the AI assistant', 1, CURRENT_TIMESTAMP);
        INSERT INTO workshop_progress(user_id, challenge_id, status, completed_at)
          VALUES(1, 'direct_prompt_injection', 'completed', CURRENT_TIMESTAMP);
        INSERT INTO challenge_objectives_progress(user_id, challenge_id, objective_id, completed)
          VALUES(1, 'direct_prompt_injection', 'interact', 1);
        INSERT INTO workshop_time_tracking
          (user_id, workshop_key, session_start, last_heartbeat, duration_seconds)
          VALUES(1, 'direct_prompt_injection', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 45);
      `);
    },
    async close() {
      await close(peerDb);
      await close(db);
      fs.rmSync(tempDir, { recursive: true, force: true });
    },
  };
}

module.exports = { createPromptInjectionProgressFixture };
