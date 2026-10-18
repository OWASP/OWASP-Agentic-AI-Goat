'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { Pool } = require('pg');
const { initializeIdentityRepository } = require('../../server/database/postgres/identityRepository');
const { createPostgresAdminRepository } = require('../../server/database/postgres/adminRepository');
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' && !!process.env.PG_LOG_RETENTION_TEST_ADMIN_URL;
test('runtime log retention removes only old activity and cannot delete arbitrary history', { skip: !enabled }, async () => {
  const url = new URL(process.env.PG_LOG_RETENTION_TEST_ADMIN_URL);
  assert.ok(['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname));
  assert.equal(url.pathname, '/postgres');
  const admin = new Pool({ connectionString: url.href });
  const name = `dvaia_test_logretention_${process.pid}_${Date.now()}`;
  let runtime, migration;
  try {
    await admin.query(`CREATE DATABASE ${name} OWNER dvaia_identity_migration`);
    await admin.query(`REVOKE CONNECT ON DATABASE ${name} FROM PUBLIC`);
    await admin.query(`GRANT CONNECT ON DATABASE ${name} TO dvaia_identity_runtime`);
    const connection = role => { const value = new URL(url); value.pathname = '/' + name; value.username = role; value.password = ''; return value.href; };
    runtime = new Pool({ connectionString: connection('dvaia_identity_runtime') });
    migration = new Pool({ connectionString: connection('dvaia_identity_migration') });
    await initializeIdentityRepository(runtime, migration);
    await migration.query("INSERT INTO identity.activity_logs(action_type,timestamp) VALUES ('old',now()-interval '8 days'),('recent',now()-interval '6 days'),('current',now())");
    const before = (await runtime.query('SELECT * FROM identity.activity_logs WHERE action_type <> $1 ORDER BY id', ['old'])).rows;
    await assert.rejects(runtime.query('DELETE FROM identity.activity_logs'), { code: '42501' });
    assert.equal(await createPostgresAdminRepository(runtime).clearOldActivityLogs(), 1);
    assert.deepEqual((await runtime.query('SELECT * FROM identity.activity_logs ORDER BY id')).rows, before);
    assert.equal(await createPostgresAdminRepository(runtime).clearOldActivityLogs(), 0);
  } finally {
    await Promise.all([runtime?.end(), migration?.end()]);
    await admin.query(`DROP DATABASE IF EXISTS ${name}`);
    await admin.end();
  }
});
