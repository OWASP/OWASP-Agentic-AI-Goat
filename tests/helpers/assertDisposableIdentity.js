'use strict';

// Call before initialization: these cohorts create owners and apply migrations.
module.exports = function assertDisposableIdentity(env = process.env) {
  if (env.PG_TEST_DISPOSABLE !== 'yes') throw new Error('Explicit disposable PostgreSQL opt-in required');
  let runtime, migration;
  try {
    runtime = new URL(env.IDENTITY_DATABASE_URL);
    migration = new URL(env.IDENTITY_MIGRATION_DATABASE_URL);
  } catch { throw new Error('Disposable identity database URLs required'); }
  for (const value of [runtime, migration]) {
    if (!['postgres:', 'postgresql:'].includes(value.protocol) || value.hostname !== '127.0.0.1'
        || !/^\/owasp_ai_goat_test_[a-z0-9_]+$/.test(value.pathname) || value.search || value.hash) {
      throw new Error('Only explicit loopback test identity databases are permitted');
    }
  }
  if (runtime.host !== migration.host || runtime.pathname !== migration.pathname
      || runtime.username !== 'dvaia_identity_runtime' || migration.username !== 'dvaia_identity_migration') {
    throw new Error('Disposable identity endpoints and restricted roles must match');
  }
};
