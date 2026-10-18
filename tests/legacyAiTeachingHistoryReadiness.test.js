'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const { assertLegacyAiTeachingHistoryReadiness, DELETION_BODY_SHA256 } = require('../server/services/legacyAiTeachingHistoryReadiness');
const migration = readFileSync(path.join(__dirname, '../db/postgres/workshop-migrations/legacy_challenge/0005_private_history_boundary.sql'), 'utf8');
const bodies = [...migration.matchAll(/AS \$\$([\s\S]*?)\$\$;/g)];
const body = bodies[0]?.[1];
function fixture(mutate = () => {}) {
  const identity = { database: 'owned_history_test', role: 'dvaia_legacy_challenge_runtime',
    session_role: 'dvaia_legacy_challenge_runtime', rolsuper: false, rolcreaterole: false,
    rolcreatedb: false, rolreplication: false, rolbypassrls: false, migration_member: false };
  const schemas = [{ name: 'legacy_challenge', present: true, runtime_usage: true, runtime_create: false },
    { name: 'legacy_ai_source_cleanup', present: true, runtime_usage: false, runtime_create: false }];
  const relations = ['ai_conversations', 'synthetic_ai_conversations'].map(name => ({
    name: `legacy_challenge.${name}`, present: true, owner: 'dvaia_legacy_challenge_migration', kind: 'r',
    table_select: name.startsWith('synthetic'), column_select: name.startsWith('synthetic'),
    table_insert: false, table_update: false, table_delete: false, table_truncate: false,
    table_references: false, table_trigger: false, column_insert: false, column_update: false, column_references: false,
  }));
  const sequence = { present: true, runtime_usage: false, runtime_select: false, runtime_update: false };
  const fn = { present: true, owner: 'dvaia_legacy_challenge_migration', security_definer: true,
    safe_search_path: true, language: 'plpgsql', body, runtime_execute: true, public_execute: false };
  const rows = { identity, schemas, relations, sequence, fn };
  mutate(rows);
  return { async query(sql) {
    if (sql.includes('current_database()')) return { rows: [identity] };
    if (sql.includes('to_regnamespace')) return { rows: schemas };
    if (sql.includes('has_table_privilege')) return { rows: relations };
    if (sql.includes('has_sequence_privilege')) return { rows: [sequence] };
    if (sql.includes('to_regprocedure')) return { rows: [fn] };
    throw new Error('Unexpected query');
  } };
}
const check = pool => assertLegacyAiTeachingHistoryReadiness({ pool, expectedDatabase: 'owned_history_test' });
const denied = pool => assert.rejects(check(pool), { code: 'LEGACY_AI_TEACHING_HISTORY_UNAVAILABLE' });
test('exact deletion body pin agrees with the forward-only boundary migration', () => {
  assert.equal(bodies.length, 1);
  assert.equal(createHash('sha256').update(body).digest('hex'), DELETION_BODY_SHA256);
});
test('readiness accepts only the intended read-only synthetic boundary', async () => {
  assert.deepEqual(await check(fixture()), { ready: true, database: 'owned_history_test',
    runtimeRole: 'dvaia_legacy_challenge_runtime', sessionRole: 'dvaia_legacy_challenge_runtime' });
});
test('runtime identity, privilege escalation and alternate database reject', async () => {
  for (const key of ['database','role','session_role']) await denied(fixture(rows => { rows.identity[key] = 'wrong'; }));
  for (const key of ['rolsuper','rolcreaterole','rolcreatedb','rolreplication','rolbypassrls','migration_member']) {
    await denied(fixture(rows => { rows.identity[key] = true; }));
  }
});
test('every source table and column privilege rejects', async () => {
  const keys = ['table_select','table_insert','table_update','table_delete','table_truncate',
    'table_references','table_trigger','column_select','column_insert','column_update','column_references'];
  for (const key of keys) await denied(fixture(rows => { rows.relations[0][key] = true; }));
});
test('synthetic must remain a migration-owned SELECT-only table', async () => {
  for (const key of ['table_insert','table_update','table_delete','table_truncate',
    'table_references','table_trigger','column_insert','column_update','column_references']) {
    await denied(fixture(rows => { rows.relations[1][key] = true; }));
  }
  for (const key of ['table_select','column_select','present']) await denied(fixture(rows => { rows.relations[1][key] = false; }));
  for (const key of ['owner','kind']) await denied(fixture(rows => { rows.relations[1][key] = 'wrong'; }));
  await denied(fixture(rows => { rows.relations.pop(); }));
  await denied(fixture(rows => { rows.relations[1] = rows.relations[0]; }));
});
test('schema creation, source cleanup visibility and sequence access reject', async () => {
  await denied(fixture(rows => { rows.schemas[0].runtime_create = true; }));
  for (const key of ['runtime_usage','runtime_create']) await denied(fixture(rows => { rows.schemas[1][key] = true; }));
  for (const key of ['runtime_usage','runtime_select','runtime_update']) await denied(fixture(rows => { rows.sequence[key] = true; }));
});
test('stale or altered definer body and unsafe capability metadata reject', async () => {
  const oldMigration = readFileSync(path.join(__dirname, '../db/postgres/workshop-migrations/legacy_challenge/0003_student_deletion.sql'), 'utf8');
  const oldBody = /AS \$\$([\s\S]*?)\$\$;/.exec(oldMigration)[1];
  await denied(fixture(rows => { rows.fn.body = oldBody; }));
  await denied(fixture(rows => { rows.fn.body += '\n'; }));
  for (const key of ['present','security_definer','safe_search_path','runtime_execute']) await denied(fixture(rows => { rows.fn[key] = false; }));
  await denied(fixture(rows => { rows.fn.public_execute = true; }));
  for (const key of ['owner','language']) await denied(fixture(rows => { rows.fn[key] = 'wrong'; }));
});
test('query failures do not leak private configuration', async () => {
  await assert.rejects(check({ query() { throw new Error('postgres://private:password@host/db'); } }), error => {
    assert.equal(error.code, 'LEGACY_AI_TEACHING_HISTORY_UNAVAILABLE');
    assert.equal(error.message, 'Synthetic AI teaching history is unavailable');
    return true;
  });
  await assert.rejects(assertLegacyAiTeachingHistoryReadiness({}), { code: 'LEGACY_AI_TEACHING_HISTORY_UNAVAILABLE' });
});
