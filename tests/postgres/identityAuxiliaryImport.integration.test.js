'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { createPool } = require('../../server/database/postgres');
const { migrate } = require('../../db/postgres/migrate');
const { COLUMNS } = require('../../db/postgres/map-identity-auxiliary');
const { applyIdentityAuxiliary, INITIAL_CONFIG } = require('../../db/postgres/apply-identity-auxiliary');

const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && Boolean(process.env.PG_IDENTITY_AUXILIARY_TEST_MIGRATION_URL)
  && Boolean(process.env.PG_IDENTITY_AUXILIARY_TEST_RUNTIME_URL);
const integer = value => ({ type: 'integer', value: String(value) });
function row(table, values) {
  return Object.fromEntries(COLUMNS[table].split(' ').map(key => [key, Object.hasOwn(values, key) ? values[key] : null]));
}
function fixture() {
  const stamp = '2026-01-02 03:04:05.123456';
  return { archiveDigest: 'c'.repeat(64), naiveTimestamps: 'UTC', identityUserIds: [7], tables: {
    email_verification_tokens: [row('email_verification_tokens', { id: integer(10), user_id: integer(7), token: 'private-token', expires_at: stamp, used: integer(0), created_at: stamp })],
    email_agent_progress: [row('email_agent_progress', { id: integer(20), user_key: 'owner-7', objective_number: integer(2), completed: integer(1), user_email: 'learner@example.test', completed_at: stamp, created_at: stamp, updated_at: stamp })],
    sent_emails_log: [row('sent_emails_log', { id: integer(30), user_key: 'owner-7', recipient_email: 'recipient@example.test', scenario_type: 'invoice', email_subject: 'Fixture', sent_at: stamp, gmail_message_id: 'fixture-id' })],
    system_config: [row('system_config', { id: integer(40), config_key: 'allow_registration', config_value: 'false', config_type: 'boolean', description: 'Imported description', is_public: integer(1), updated_by: integer(7), updated_at: stamp })],
  } };
}

test('auxiliary identity rows apply atomically, preserve provenance and restart native sequences', { skip: !enabled }, async () => {
  for (const key of ['PG_IDENTITY_AUXILIARY_TEST_MIGRATION_URL', 'PG_IDENTITY_AUXILIARY_TEST_RUNTIME_URL']) {
    assert.match(new URL(process.env[key]).pathname, /^\/dvaia_test_[a-z0-9_]+$/);
  }
  const migration = createPool(process.env, 'PG_IDENTITY_AUXILIARY_TEST_MIGRATION_URL');
  const runtime = createPool(process.env, 'PG_IDENTITY_AUXILIARY_TEST_RUNTIME_URL');
  let client;
  try {
    await migrate(migration, path.join(__dirname, '../../db/postgres/identity-migrations'));
    await migration.query(`INSERT INTO identity.users(id,username,email,password) OVERRIDING SYSTEM VALUE
      VALUES(7,'aux-owner','owner@example.test','$2b$04$01234567890123456789012345678901234567890123456789012')`);
    assert.deepEqual((await migration.query('SELECT config_key,config_value,config_type,is_public FROM identity.system_config ORDER BY config_key')).rows, INITIAL_CONFIG);

    await assert.rejects(applyIdentityAuxiliary(migration, fixture()), { code: '25P01' });
    client = await migration.connect();
    await client.query('BEGIN');
    await applyIdentityAuxiliary(client, fixture());
    await client.query('ROLLBACK');
    assert.equal((await client.query('SELECT count(*)::int AS n FROM identity.email_verification_tokens')).rows[0].n, 0);
    assert.deepEqual((await client.query('SELECT config_key,config_value,config_type,is_public FROM identity.system_config ORDER BY config_key')).rows, INITIAL_CONFIG);

    await client.query('BEGIN');
    const result = await applyIdentityAuxiliary(client, fixture());
    await client.query('COMMIT');
    assert.deepEqual(result.counts, { email_verification_tokens: 1, email_agent_progress: 1, sent_emails_log: 1, system_config: 1 });
    const progress = (await client.query('SELECT * FROM identity.email_agent_progress')).rows[0];
    assert.equal(progress.legacy_id, 20);
    const config = (await client.query('SELECT * FROM identity.system_config')).rows[0];
    assert.equal(config.legacy_id, 40);
    assert.equal(config.description, 'Imported description');
    assert.equal(config.source_updated_by, 7);
    assert.equal((await client.query(`SELECT to_char(source_updated_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US') AS stamp
      FROM identity.system_config WHERE config_key='allow_registration'`)).rows[0].stamp, '2026-01-02T03:04:05.123456');

    assert.equal((await runtime.query(`INSERT INTO identity.email_verification_tokens(user_id,token_hash,expires_at)
      VALUES(7,$1,now()+interval '1 hour') RETURNING id`, ['d'.repeat(64)])).rows[0].id, 11);
    assert.equal((await runtime.query(`INSERT INTO identity.sent_emails_log(user_key,recipient_email) VALUES('owner-7','next@example.test') RETURNING id`)).rows[0].id, 31);
    await runtime.query(`UPDATE identity.system_config SET config_value='true' WHERE config_key='allow_registration'`);
    assert.equal((await client.query(`SELECT source_updated_by FROM identity.system_config WHERE config_key='allow_registration'`)).rows[0].source_updated_by, 7);
    await assert.rejects(runtime.query(`UPDATE identity.system_config SET source_updated_by=NULL WHERE config_key='allow_registration'`), { code: '42501' });
    await assert.rejects(runtime.query(`UPDATE identity.email_agent_progress SET legacy_id=21 WHERE user_key='owner-7'`), { code: '42501' });
    await assert.rejects(client.query(`UPDATE identity.system_config SET source_updated_by=NULL WHERE config_key='allow_registration'`), { code: '55000' });
    await assert.rejects(client.query(`UPDATE identity.email_agent_progress SET legacy_id=21 WHERE user_key='owner-7'`), { code: '55000' });

    await client.query('BEGIN');
    await assert.rejects(applyIdentityAuxiliary(client, fixture()), { code: 'IDENTITY_AUXILIARY_IMPORT_REQUIRES_EMPTY_TARGET' });
    await client.query('ROLLBACK');
  } finally {
    if (client) client.release();
    await Promise.all([runtime.end(), migration.end()]);
  }
});
