'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
let isolatedPath;

/**
 * Assign one disposable auth database to a standalone test process before it
 * imports any route that loads server/database/authDb.
 */
function isolateAuthDb(label) {
  if (isolatedPath) return isolatedPath;
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), `owasp-ai-goat-${label}-`));
  const database = path.join(directory, 'users_auth.db');
  // Build from source schema only. Never copy a working DB: it may contain
  // private attendee data, and copying without its WAL is not a valid snapshot.
  const Database = require('better-sqlite3');
  const temporary = new Database(database);
  try {
    temporary.exec(fs.readFileSync(path.resolve(__dirname, '../../db/initialize-db/schemas/01_users_auth.sql'), 'utf8'));
  } finally { temporary.close(); }
  process.env.USERS_AUTH_DB_PATH = database;
  isolatedPath = database;
  process.once('exit', () => {
    try { fs.rmSync(directory, { recursive: true, force: true }); } catch {}
  });
  return database;
}

module.exports = { isolateAuthDb };
