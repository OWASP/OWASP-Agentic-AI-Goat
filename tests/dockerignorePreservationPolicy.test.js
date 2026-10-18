const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const ROOT = path.resolve(__dirname, '..');
const DOCKERIGNORE = path.join(ROOT, '.dockerignore');

function activeRules() {
  return fs.readFileSync(DOCKERIGNORE, 'utf8')
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#'));
}

const PRIVATE_SCOPE_RULES = Object.freeze([
  'backups/',
  'server/database/users_auth.db',
  'server/database/users_auth.db-*',
  'tasks/main-workspace-preservation-2026-09-28/',
]);

const SQLITE_RULES = Object.freeze([
  '**/*.db',
  '**/*.db-*',
  '**/*.sqlite',
  '**/*.sqlite-*',
  '**/*.sqlite3',
  '**/*.sqlite3-*',
]);

function isSqliteRuntimePath(filePath) {
  return /\.(?:db|sqlite|sqlite3)(?:-|$)/u.test(filePath);
}

test('Docker context excludes private preservation scopes and all SQLite runtime data', () => {
  const rules = activeRules();

  for (const required of [...PRIVATE_SCOPE_RULES, ...SQLITE_RULES]) {
    assert.equal(
      rules.filter((rule) => rule === required).length,
      1,
      `expected exactly one ${required} rule`,
    );
  }

  const databaseNegations = rules.filter((rule) => (
    rule.startsWith('!') && isSqliteRuntimePath(rule.slice(1))
  ));
  assert.deepEqual(databaseNegations, [], 'SQLite runtime data must not be re-included');

  const excludedProbes = [
    'server/database/users_auth.db',
    'server/database/users_auth.db-wal',
    'server/database/challenge.db',
    'server/database/challenge.db-shm',
    'temporary/history.sqlite',
    'temporary/history.sqlite-journal',
    'temporary/history.sqlite3',
    'temporary/history.sqlite3-wal',
  ];
  for (const probe of excludedProbes) {
    assert.equal(isSqliteRuntimePath(probe), true, `expected SQLite runtime path: ${probe}`);
  }

  const sourceProbes = [
    'server/database/postgres/workshopPlatformSeed.js',
    'db/initialize-db/schemas/01_users_auth.sql',
    'db/initialize-db/seeds/01_users_auth.js',
    'server/database/vector-indexes/.gitkeep',
  ];
  for (const probe of sourceProbes) {
    assert.equal(isSqliteRuntimePath(probe), false, `schema/source input must remain eligible: ${probe}`);
  }
});
