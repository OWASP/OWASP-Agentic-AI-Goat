'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { createLegacyAiHistoryRepository } = require('../server/database/postgres/legacyAiHistoryRepository');

const ROOT = path.resolve(__dirname, '..');
const SQL_PATH = path.join(ROOT, 'docs/modernization/drafts/legacy-ai-history-protected-storage.sql');
const REPOSITORY_PATH = path.join(ROOT, 'server/database/postgres/legacyAiHistoryRepository.js');
const DELETION_REPOSITORY_PATH = path.join(ROOT, 'server/database/postgres/studentDeletionRepository.js');
const requestId = '82a4d932-5c93-4f0e-8b8a-6c44758b4f2a';
const resetId = 'cad6d6c5-491a-47b1-88db-b6c220981b7a';
const jobId = 'ca29f4d4-8ac2-45a9-9689-2b6befc97343';
const leaseToken = '7b889651-3be8-4fbf-b6a0-4ceff95352d4';
const cursorToken = `2026-09-15T01:00:00.123456Z|${requestId}`;

function fixturePool(rows = []) {
  const calls = [];
  const client = {
    async query(sql, values) {
      calls.push([sql, values]);
      if (sql === 'BEGIN' || sql === 'COMMIT' || sql === 'ROLLBACK') return { rows: [] };
      return { rows };
    },
    release(error) { calls.push(['RELEASE', error]); },
  };
  return { calls, connect: async () => client, query: async () => ({ rows: [] }) };
}

function appendInput(overrides = {}) {
  return {
    ownerId: 41,
    sessionId: 73,
    generation: 0,
    requestId,
    sourceRoute: 'prompt_injection',
    prompt: 'private prompt',
    response: 'private response',
    modelUsed: 'controlled-model',
    ...overrides,
  };
}

test('repository exposes only the fixed protected-history and deletion-cleanup operations', () => {
  const repository = createLegacyAiHistoryRepository(fixturePool());
  assert.deepEqual(Object.keys(repository).sort(), ['admit', 'append', 'cleanupForStudentDeletion', 'listAdmin', 'listOwn', 'reset']);
  assert.ok(Object.isFrozen(repository));
  assert.equal(Object.prototype.hasOwnProperty.call(repository, 'query'), false);
  assert.equal(Object.prototype.hasOwnProperty.call(repository, 'execute'), false);
  assert.equal(Object.prototype.hasOwnProperty.call(repository, 'rawSql'), false);
});

test('append binds exact owner, session, generation, request identifier and bounded bytes to one function', async () => {
  const row = { request_id: requestId, owner_id: 41, generation: '0', source_route: 'prompt_injection',
    prompt: 'private prompt', response: 'private response', model_used: 'controlled-model',
    created_at: '2026-09-15T00:00:00.000Z', cursor_token: `2026-09-15T00:00:00.000001Z|${requestId}`,
    replayed: false };
  const pool = fixturePool([row]);
  const actual = await createLegacyAiHistoryRepository(pool).append(appendInput());
  assert.deepEqual(pool.calls.slice(0, 3), [
    ['BEGIN', undefined],
    ['SELECT * FROM legacy_ai_private.append_history($1,$2,$3,$4,$5,$6,$7,$8)',
      [41, '73', '0', requestId, 'prompt_injection', 'private prompt', 'private response', 'controlled-model']],
    ['COMMIT', undefined],
  ]);
  assert.deepEqual(actual, { requestId, ownerId: 41, generation: '0', sourceRoute: 'prompt_injection',
    prompt: 'private prompt', response: 'private response', modelUsed: 'controlled-model',
    createdAt: '2026-09-15T00:00:00.000Z', cursor: `2026-09-15T00:00:00.000001Z|${requestId}`, replayed: false });
  assert.ok(Object.isFrozen(actual));
});

test('repository rejects invalid authority, stale-generation inputs and incomplete cursors before connecting', async () => {
  const pool = fixturePool();
  const repository = createLegacyAiHistoryRepository(pool);
  await assert.rejects(repository.append(appendInput({ ownerId: 0 })), /Valid legacy AI history owner required/);
  await assert.rejects(repository.append(appendInput({ sessionId: 0 })), /Valid platform session required/);
  await assert.rejects(repository.append(appendInput({ generation: -1 })), /Valid history generation required/);
  await assert.rejects(repository.append(appendInput({ requestId: 'not-a-uuid' })), /Valid history request ID required/);
  await assert.rejects(repository.append(appendInput({ sourceRoute: 'arbitrary_route' })), /Valid legacy AI source route required/);
  await assert.rejects(repository.append(appendInput({ prompt: 'x'.repeat(65537) })), /Valid history prompt required/);
  await assert.rejects(repository.listOwn({ ownerId: 41, sessionId: 73,
    beforeCursor: `2026-09-15T00:00:00.123Z|${requestId}` }), /Valid opaque history cursor required/);
  await assert.rejects(repository.listOwn({ ownerId: 41, sessionId: 73,
    beforeCreatedAt: '2026-09-15T00:00:00Z', beforeRequestId: requestId }), /Opaque history cursor required/);
  await assert.rejects(repository.listAdmin({ adminId: 41, sessionId: 73, limit: 201 }),
    /History limit must be between 1 and 200/);
  await assert.rejects(repository.reset({ ownerId: 41, sessionId: 73, generation: 0, resetRequestId: 'not-a-uuid' }),
    /Valid history reset request ID required/);
  assert.deepEqual(pool.calls, []);
});

test('owner, administrator and reset operations use fixed parameterized function calls', async () => {
  const pool = fixturePool();
  const repository = createLegacyAiHistoryRepository(pool);
  await repository.listOwn({ ownerId: 41, sessionId: 73, limit: 2,
    beforeCursor: cursorToken.replace(requestId, requestId.toUpperCase()) });
  await repository.listAdmin({ adminId: 12, sessionId: 99, limit: 1 });
  const receipt = await repository.reset({ ownerId: 41, sessionId: 73, generation: 3, resetRequestId: resetId });
  const deletion = await repository.cleanupForStudentDeletion({ ownerId: 41, jobId, leaseToken });
  const functionCalls = pool.calls.filter(([sql]) => String(sql).startsWith('SELECT *'));
  assert.deepEqual(functionCalls, [
    ['SELECT * FROM legacy_ai_private.list_own_history($1,$2,$3,$4)', [41, '73', 2, cursorToken]],
    ['SELECT * FROM legacy_ai_private.list_admin_history($1,$2,$3,$4)', [12, '99', 1, null]],
    ['SELECT * FROM legacy_ai_private.reset_history($1,$2,$3,$4)', [41, '73', '3', resetId]],
    ['SELECT * FROM legacy_ai_private.cleanup_history_for_student_deletion($1,$2,$3)', [jobId, leaseToken, 41]],
  ]);
  assert.equal(receipt, null);
  assert.equal(deletion, null);
});

test('unregistered SQL draft protects private bytes through fixed definer APIs and lossless archive primitives', () => {
  const sql = fs.readFileSync(SQL_PATH, 'utf8');
  const repository = fs.readFileSync(REPOSITORY_PATH, 'utf8');
  const deletionRepository = fs.readFileSync(DELETION_REPOSITORY_PATH, 'utf8');
  assert.match(sql, /^-- UNREGISTERED DRAFT\./);
  assert.match(sql, /CREATE SCHEMA legacy_ai_private;/);
  assert.match(sql, /CREATE TABLE legacy_ai_private\.history \(/);
  assert.match(sql, /CREATE INDEX legacy_ai_history_admin_created/);
  assert.match(sql, /ON legacy_ai_private\.history\(created_at DESC, request_id DESC\)/);
  assert.doesNotMatch(sql, /legacy_ai_history_admin_created[\s\S]*INCLUDE\(/);
  assert.match(sql, /CREATE TABLE legacy_ai_private\.import_archive \(/);
  assert.match(sql, /source_row_id bigint NOT NULL CHECK \(source_row_id BETWEEN -2147483648 AND 2147483647\)/);
  assert.doesNotMatch(sql, /requested_source_row\s*<\s*1/);
  assert.match(sql, /CREATE TABLE legacy_ai_private\.import_history_receipts \(/);
  assert.match(sql, /CREATE TABLE legacy_ai_private\.import_batch_events \(/);
  assert.match(sql, /CREATE TABLE legacy_ai_private\.deletion_receipts \(/);
  assert.match(sql, /source_record jsonb NOT NULL/);
  assert.match(sql, /classification IN \('unknown', 'conflict', 'owned', 'synthetic'\)/);
  const ownerLock = sql.indexOf('SELECT * INTO account FROM identity.users WHERE id = requested_owner FOR SHARE;');
  const deletionFence = sql.indexOf('EXISTS (SELECT 1 FROM identity.student_deletion_jobs WHERE subject_user_id = requested_owner)');
  assert.ok(ownerLock >= 0 && ownerLock < deletionFence, 'owner lock must precede deletion fence check');
  assert.doesNotMatch(sql, /LOCK TABLE identity\.student_deletion_jobs/i);
  const deletionAccountLock = deletionRepository.indexOf(
    'FROM identity.users WHERE id=ANY($1::integer[]) ORDER BY id FOR UPDATE');
  const deletionInsert = deletionRepository.indexOf(
    'INSERT INTO identity.student_deletion_jobs(job_id,subject_user_id,requested_by)');
  assert.ok(deletionAccountLock >= 0 && deletionAccountLock < deletionInsert,
    'deletion admission must lock the subject account before inserting its fence');
  assert.match(sql, /SELECT \* INTO active_session FROM identity\.user_sessions/);
  assert.match(sql, /id = requested_session AND user_id = requested_owner FOR SHARE/);
  assert.match(sql, /PERFORM 1 FROM identity\.admin_permissions permission[\s\S]*FOR SHARE;/);
  assert.match(sql, /permission_name = 'view_analytics'/);
  assert.match(sql, /CREATE FUNCTION legacy_ai_private\.append_history\(/);
  assert.match(sql, /CREATE FUNCTION legacy_ai_private\.list_own_history\(/);
  assert.match(sql, /CREATE FUNCTION legacy_ai_private\.list_admin_history\(/);
  assert.match(sql, /CREATE FUNCTION legacy_ai_private\.reset_history\(/);
  assert.match(sql, /CREATE FUNCTION legacy_ai_private\.begin_history_import\(/);
  assert.match(sql, /CREATE FUNCTION legacy_ai_private\.archive_history_import_row\(/);
  assert.match(sql, /CREATE FUNCTION legacy_ai_private\.promote_owned_history_import_row\(/);
  assert.match(sql, /CREATE FUNCTION legacy_ai_private\.verify_history_import_quarantine\(/);
  assert.match(sql, /source_record jsonb NOT NULL CHECK \(jsonb_typeof\(source_record\) = 'object'\)/);
  assert.match(sql, /Owned history exceeds application limits after lossless archive/);
  const promotion = sql.slice(sql.indexOf('CREATE FUNCTION legacy_ai_private.promote_owned_history_import_row('));
  assert.ok(promotion.indexOf('FROM identity.users import_owner') < promotion.indexOf('FROM legacy_ai_private.import_batches import_batch')
    && promotion.indexOf('FROM legacy_ai_private.import_batches import_batch') < promotion.indexOf('FROM legacy_ai_private.import_archive source_row'),
  'promotion must lock user, owner state, batch, then archive');
  assert.match(sql, /ORDER BY affected_batch\.batch_id FOR UPDATE/);
  const archiveImport = sql.slice(sql.indexOf('CREATE FUNCTION legacy_ai_private.archive_history_import_row('));
  assert.ok(archiveImport.indexOf('FROM identity.users attested_owner') < archiveImport.indexOf('FROM legacy_ai_private.import_batches located'),
    'owned archive must fence the identity user before locking its batch');
  assert.match(sql, /invalidated_by_deletion/);
  assert.match(sql, /future separately provisioned source\s+-- cleanup capability/);
  assert.match(sql, /CREATE FUNCTION legacy_ai_private\.cleanup_history_for_student_deletion\(/);
  assert.match(sql, /legacy_ai_history[\s\S]*identity[\s\S]*manifest[\s\S]*unmounted/i);
  assert.match(sql, /cleanup_step\.state NOT IN \('pending', 'failed'\)/);
  const cleanupFunction = sql.slice(sql.indexOf('CREATE FUNCTION legacy_ai_private.cleanup_history_for_student_deletion('));
  assert.match(cleanupFunction, /FROM identity\.student_deletion_jobs deletion_job\s+WHERE deletion_job\.job_id = requested_job/);
  assert.match(cleanupFunction, /deletion_job\.subject_user_id = requested_owner\s+AND deletion_job\.state = 'running'/);
  assert.match(cleanupFunction, /FROM identity\.student_deletion_steps deletion_step\s+WHERE deletion_step\.job_id = requested_job/);
  assert.match(cleanupFunction, /FROM identity\.student_deletion_steps finalizer_step\s+WHERE finalizer_step\.job_id = requested_job/);
  assert.doesNotMatch(cleanupFunction, /WHERE\s+job_id\s*=/,
    'RETURNS TABLE job_id must never shadow an unqualified deletion-fence column');
  assert.equal((sql.match(/SECURITY DEFINER/g) || []).length, 12);
  assert.match(sql, /IF current_generation <> expected_generation THEN/);
  assert.match(sql, /prior\.owner_id <> requested_owner OR prior\.generation <> expected_generation/);
  assert.match(sql, /DELETE FROM legacy_ai_private\.history item WHERE item\.owner_id = requested_owner;/);
  assert.match(sql, /archived\.classification = 'owned' AND archived\.classified_owner_id = requested_owner/);
  assert.match(sql, /REVOKE ALL ON legacy_ai_private\.owners,[\s\S]*FROM PUBLIC, dvaia_identity_runtime;/);
  assert.match(sql, /REVOKE ALL ON FUNCTION legacy_ai_private\.assert_live_session[\s\S]*FROM PUBLIC, dvaia_identity_runtime;/);
  assert.doesNotMatch(sql, /GRANT[\s\S]{0,300}dvaia_legacy_challenge_runtime/i);
  assert.doesNotMatch(sql, /legacy_challenge\.ai_conversations/i);
  assert.doesNotMatch(repository, /\b(?:rawSql|executeAiSql|pool\.query\s*\()/);
  assert.doesNotMatch(repository, /new Date\(|toISOString\(/);
  assert.deepEqual(repository.match(/SELECT \* FROM legacy_ai_private\.[a-z_]+\([^']+/g), [
    'SELECT * FROM legacy_ai_private.admit_history($1,$2)',
    'SELECT * FROM legacy_ai_private.append_history($1,$2,$3,$4,$5,$6,$7,$8)',
    'SELECT * FROM legacy_ai_private.list_own_history($1,$2,$3,$4)',
    'SELECT * FROM legacy_ai_private.list_admin_history($1,$2,$3,$4)',
    'SELECT * FROM legacy_ai_private.reset_history($1,$2,$3,$4)',
    'SELECT * FROM legacy_ai_private.cleanup_history_for_student_deletion($1,$2,$3)',
  ]);
});


test('admission commits and releases before returning server generation, and rejects mismatched authority', async () => {
  const pool = fixturePool([{ owner_id: 41, session_id: '73', generation: '5' }]);
  const admitted = await createLegacyAiHistoryRepository(pool).admit({ ownerId: 41, sessionId: 73 });
  assert.deepEqual(admitted, { ownerId: 41, sessionId: '73', generation: '5' });
  assert.ok(Object.isFrozen(admitted));
  assert.deepEqual(pool.calls.map(([sql]) => sql), ['BEGIN',
    'SELECT * FROM legacy_ai_private.admit_history($1,$2)', 'COMMIT', 'RELEASE']);
  for (const rows of [[], [{ owner_id: 42, session_id: '73', generation: '0' }],
    [{ owner_id: 41, session_id: '74', generation: '0' }]]) {
    await assert.rejects(createLegacyAiHistoryRepository(fixturePool(rows)).admit({ ownerId: 41, sessionId: 73 }),
      { code: '55000' });
  }
  const invalid = fixturePool();
  await assert.rejects(createLegacyAiHistoryRepository(invalid).admit({ ownerId: 0, sessionId: 73 }));
  assert.deepEqual(invalid.calls, []);
});
