'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { Pool } = require('pg');
const { verifyServer } = require('../../server/database/postgres');
const { qualifyAuditInstructionDefaults } = require('../helpers/secureshopAuditInstructionDefaults');
const cases = [['managed', false], ['custom', true]];
for (const [kind, customBefore] of cases) {
  const connectionString = process.env[`PG_AUDIT_DEFAULTS_${kind.toUpperCase()}_TEST_URL`];
  test(`bounded Audit defaults preserve ${kind} content and replay`, {
    skip: process.env.PG_TEST_DISPOSABLE !== 'yes' || !connectionString,
    timeout: 90000,
  }, async () => {
    const url = new URL(connectionString);
    assert.equal(url.hostname, '127.0.0.1');
    assert.equal(url.username, 'dvaia_identity_migration');
    assert.equal(url.search, '');
    assert.equal(url.hash, '');
    const database = url.pathname.slice(1);
    assert.match(database, new RegExp(`^owasp_ai_goat_audit_defaults_${kind}_[a-f0-9]{12}$`));
    const migration = new Pool({ connectionString, max: 2, connectionTimeoutMillis: 5000,
      statement_timeout: 30000, lock_timeout: 5000 });
    try {
      await verifyServer(migration);
      const identity = (await migration.query('SELECT current_database() AS name, current_user AS role')).rows[0];
      assert.equal(identity.name, database);
      assert.equal(identity.role, 'dvaia_identity_migration');
      assert.equal((await migration.query("SELECT to_regnamespace('workshop_platform') AS existing")).rows[0].existing, null);
      await qualifyAuditInstructionDefaults({ migration, customBefore });
    } finally { await migration.end(); }
  });
}
