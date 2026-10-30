'use strict';

// DRAFT-ONLY native qualification. This test deliberately loads the adjacent
// unregistered SQL through the supplied disposable migration role. It never
// changes the canonical migration registry or its ledger.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { randomBytes } = require('node:crypto');
const { createPool } = require('../../server/database/postgres');
const { readMigrations } = require('../../db/postgres/migrate');
const { createIdentityRepository, initializeIdentityRepository } = require(
  '../../server/database/postgres/identityRepository');
const { createLegacyAiHistoryRepository } = require(
  '../../server/database/postgres/legacyAiHistoryRepository');
const { createLegacyAiHistoryDraftImporter, digest: importDigestValue } = require(
  '../../server/database/postgres/legacyAiHistoryDraftImporter');
const { bindSourceStoreIdentity, computeSourceStoreDigest, computeManifestDigest,
  createLegacyAiHistoryArchiveAttestation } = require(
  '../../server/database/postgres/legacyAiHistoryArchiveAttestation');
const { createLegacyAiHistoryImportTarget } = require('../../server/database/postgres/legacyAiHistoryImportTarget');
const { createLegacyAiHistoryRequestService } = require('../../server/services/legacyAiHistoryRequestService');
const {
  assertLegacyAiProtectedHistoryReadiness,
  createLegacyAiProtectedHistoryComposition,
} = require('../../server/services/legacyAiProtectedHistoryComposition');
const { qualifyLegacyAiHistoryHttp } = require('./helpers/legacyAiHistoryHttpQualification');
const { createStudentDeletionRepository } = require(
  '../../server/database/postgres/studentDeletionRepository');

const PREFIX = 'PG_LEGACY_AI_HISTORY_';
const KEYS = ['IDENTITY_RUNTIME_URL', 'IDENTITY_MIGRATION_URL'];
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && KEYS.every(key => typeof process.env[PREFIX + key] === 'string' && process.env[PREFIX + key]);
const ROOT = path.resolve(__dirname, '../..');
const DRAFT_PATH = path.join(ROOT, 'docs/modernization/drafts/legacy-ai-history-protected-storage.sql');
const FIXTURE_HASH = '$2b$12$000000000000000000000uG3W0Jp6IPhhD1TRqN8Yc2zJQG3vVnSA';

function disposableUrl(key, expectedRole) {
  const value = new URL(process.env[PREFIX + key]);
  assert.ok(['127.0.0.1', 'localhost'].includes(value.hostname), 'disposable PostgreSQL must be loopback');
  assert.match(value.pathname, /^\/owasp_ai_goat_test_[a-z0-9_]+$/, 'disposable database name required');
  assert.equal(decodeURIComponent(value.username), expectedRole, `${key} has the wrong PostgreSQL role`);
  assert.equal(value.search, '');
  assert.equal(value.hash, '');
  return value.href;
}

function expectCode(code) {
  return error => error && error.code === code;
}

function delay(milliseconds) {
  return new Promise(resolve => setTimeout(resolve, milliseconds));
}

async function waitFor(description, predicate, timeoutMs = 5_000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (await predicate()) return;
    if (Date.now() >= deadline) throw new Error(`Timed out waiting for ${description}`);
    await delay(10);
  }
}

async function bounded(promise, description, timeoutMs = 10_000) {
  let timeout;
  try {
    return await Promise.race([
      promise,
      new Promise((resolve, reject) => {
        timeout = setTimeout(() => reject(new Error(`Timed out waiting for ${description}`)), timeoutMs);
      }),
    ]);
  } finally {
    clearTimeout(timeout);
  }
}

function pausePoolAfterQuery(pool, predicate) {
  let observedResolve;
  let observedReject;
  let releaseResolve;
  let triggered = false;
  const observed = new Promise((resolve, reject) => {
    observedResolve = resolve;
    observedReject = reject;
  });
  const released = new Promise(resolve => { releaseResolve = resolve; });
  return {
    pool: {
      query: pool.query.bind(pool),
      async connect() {
        const client = await pool.connect();
        let pid;
        try {
          pid = (await client.query('SELECT pg_backend_pid()::integer AS pid')).rows[0].pid;
        } catch (error) {
          client.release(error);
          observedReject(error);
          throw error;
        }
        return {
          async query(...args) {
            try {
              const result = await client.query(...args);
              const text = typeof args[0] === 'string' ? args[0] : args[0]?.text;
              if (!triggered && predicate(text || '', args[1])) {
                triggered = true;
                observedResolve(pid);
                await released;
              }
              return result;
            } catch (error) {
              if (!triggered) observedReject(error);
              throw error;
            }
          },
          release(error) { client.release(error); },
        };
      },
    },
    wait(description) { return bounded(observed, description); },
    release() { releaseResolve(); },
  };
}

async function assertBatchLockAvailable(pool, batchId) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await client.query(`SELECT batch_id FROM legacy_ai_private.import_batches
      WHERE batch_id=$1 FOR UPDATE NOWAIT`, [batchId]);
    assert.equal(result.rowCount, 1, 'the independently probed import batch must exist');
    await client.query('ROLLBACK');
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

async function loadDraftOnly(migration) {
  const source = await fs.readFile(DRAFT_PATH, 'utf8');
  assert.match(source, /^-- UNREGISTERED DRAFT\./);
  const client = await migration.connect();
  try {
    await client.query('BEGIN');
    await client.query(source);
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

async function createUser(repository, suffix) {
  return repository.createUser({ username: `protected-history-${suffix}`,
    email: `protected-history-${suffix}@example.invalid`, passwordHash: FIXTURE_HASH });
}

async function createSession(repository, user, token) {
  return repository.createSession({ userId: user.id, token,
    expiresAt: new Date(Date.now() + 3_600_000), expectedPasswordHash: FIXTURE_HASH,
    deviceInfo: { fixture: 'legacy-ai-history' } });
}

async function expectReadinessMutationRejected({ migration, runtime, expectedDatabase,
  apply, restore, label }) {
  await migration.query(apply);
  try {
    await assert.rejects(
      assertLegacyAiProtectedHistoryReadiness({ identityPool: runtime, expectedDatabase }),
      error => error?.code === 'LEGACY_AI_PROTECTED_HISTORY_UNAVAILABLE',
      label,
    );
  } finally {
    await migration.query(restore);
  }
  assert.equal((await assertLegacyAiProtectedHistoryReadiness({
    identityPool: runtime,
    expectedDatabase,
  })).ready, true, `${label} restoration must recover readiness`);
}

test('DRAFT ONLY: restricted identity runtime protects legacy AI history through fixed functions', {
  skip: !enabled,
  timeout: 60_000,
}, async () => {
  const runtimeUrl = disposableUrl('IDENTITY_RUNTIME_URL', 'dvaia_identity_runtime');
  disposableUrl('IDENTITY_MIGRATION_URL', 'dvaia_identity_migration');
  const expectedDatabase = decodeURIComponent(new URL(runtimeUrl).pathname.slice(1));
  const runtime = createPool(process.env, PREFIX + 'IDENTITY_RUNTIME_URL');
  // Concurrency qualification needs an importer, a lock observer and a batch
  // probe. Keep production migration pools at their normal single connection.
  const migration = createPool({ ...process.env, PG_POOL_MAX_MIGRATION: '3' },
    PREFIX + 'IDENTITY_MIGRATION_URL');
  let held;
  try {
    assert.equal((await migration.query("SELECT to_regnamespace('identity') AS schema")).rows[0].schema, null,
      'test requires a fresh owned disposable identity database');
    const registered = await readMigrations(path.join(ROOT, 'db/postgres/identity-migrations'));
    assert.equal(registered.at(-1).name, '0065_ipi_email_artifacts.sql');
    assert.ok(!registered.some(row => /legacy_ai_history|protected_storage/.test(row.name)));
    assert.deepEqual(await initializeIdentityRepository(runtime, migration), registered.map(row => row.name),
      'normal helper must apply only the registered identity prefix');
    assert.deepEqual(await initializeIdentityRepository(runtime, migration), []);
    const ledgerBefore = (await migration.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
    await loadDraftOnly(migration);
    assert.deepEqual((await migration.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows,
      ledgerBefore, 'draft SQL must not enter the canonical migration ledger');

    const identityAdapter = Object.freeze({
      pool: runtime,
      async validateSession() { return null; },
    });
    const unmounted = await createLegacyAiProtectedHistoryComposition({
    experimentAccess: (req, res, next) => next(), // Controlled enabled exercise fixture.
      identityPool: runtime,
      identityAdapter,
      expectedDatabase,
      async infer() { return { response: 'controlled response', modelUsed: 'controlled-model' }; },
    });
    assert.equal(unmounted.readiness.ready, true);
    assert.equal(unmounted.readiness.database, expectedDatabase);
    assert.equal(typeof unmounted.router, 'function');
    assert.deepEqual(Object.keys(unmounted).sort(), ['readiness', 'router'],
      'readiness composition must remain unmounted');

    await assert.rejects(
      assertLegacyAiProtectedHistoryReadiness({ identityPool: migration, expectedDatabase }),
      error => error?.code === 'LEGACY_AI_PROTECTED_HISTORY_UNAVAILABLE',
      'migration-role connections cannot satisfy runtime readiness',
    );
    await expectReadinessMutationRejected({ migration, runtime, expectedDatabase,
      label: 'direct archive read grant',
      apply: 'GRANT SELECT ON legacy_ai_private.import_archive TO dvaia_identity_runtime',
      restore: 'REVOKE SELECT ON legacy_ai_private.import_archive FROM dvaia_identity_runtime' });
    await expectReadinessMutationRejected({ migration, runtime, expectedDatabase,
      label: 'runtime schema creation grant',
      apply: 'GRANT CREATE ON SCHEMA legacy_ai_private TO dvaia_identity_runtime',
      restore: 'REVOKE CREATE ON SCHEMA legacy_ai_private FROM dvaia_identity_runtime' });
    await expectReadinessMutationRejected({ migration, runtime, expectedDatabase,
      label: 'internal function execution grant',
      apply: `GRANT EXECUTE ON FUNCTION
        legacy_ai_private.assert_live_session(integer,bigint) TO dvaia_identity_runtime`,
      restore: `REVOKE EXECUTE ON FUNCTION
        legacy_ai_private.assert_live_session(integer,bigint) FROM dvaia_identity_runtime` });
    await expectReadinessMutationRejected({ migration, runtime, expectedDatabase,
      label: 'unsafe definer search path',
      apply: `ALTER FUNCTION legacy_ai_private.admit_history(integer,bigint)
        SET search_path TO pg_catalog,legacy_ai_private`,
      restore: `ALTER FUNCTION legacy_ai_private.admit_history(integer,bigint)
        SET search_path TO pg_catalog` });

    const identities = createIdentityRepository(runtime);
    const history = createLegacyAiHistoryRepository(runtime);
    const owner = await createUser(identities, 'owner');
    const sibling = await createUser(identities, 'sibling');
    const reader = await createUser(identities, 'reader');
    const deletionAdmin = await createUser(identities, 'deletion-admin');
    const deletionOwner = await createUser(identities, 'deletion-owner');
    const paginationOwner = await createUser(identities, 'pagination-owner');
    const cleanupOwner = await createUser(identities, 'cleanup-owner');
    const archiveRaceOwner = await createUser(identities, 'archive-race-owner');
    const promotionRaceOwner = await createUser(identities, 'promotion-race-owner');
    const deletionFirstArchiveOwner = await createUser(identities, 'deletion-first-archive-owner');
    const deletionFirstPromotionOwner = await createUser(identities, 'deletion-first-promotion-owner');
    const promotionFirstResetOwner = await createUser(identities, 'promotion-first-reset-owner');
    const resetFirstPromotionOwner = await createUser(identities, 'reset-first-promotion-owner');
    const finalizerOnlyOwner = await createUser(identities, 'finalizer-only-owner');
    const ownerSession = await createSession(identities, owner, 'protected-owner-session');
    const siblingSession = await createSession(identities, sibling, 'protected-sibling-session');
    const readerSession = await createSession(identities, reader, 'protected-reader-session');
    const deletionOwnerSession = await createSession(identities, deletionOwner, 'protected-deletion-owner-session');
    const paginationSession = await createSession(identities, paginationOwner, 'protected-pagination-session');
    const cleanupSession = await createSession(identities, cleanupOwner, 'protected-cleanup-session');
    const promotionFirstResetSession = await createSession(identities, promotionFirstResetOwner,
      'protected-promotion-first-reset-session');
    const resetFirstPromotionSession = await createSession(identities, resetFirstPromotionOwner,
      'protected-reset-first-promotion-session');
    const finalizerOnlySession = await createSession(identities, finalizerOnlyOwner, 'protected-finalizer-only-session');
    await migration.query("UPDATE identity.users SET role='admin',admin_level=1 WHERE id=$1", [reader.id]);
    await migration.query("UPDATE identity.users SET role='super_admin',admin_level=2 WHERE id=$1", [deletionAdmin.id]);

    const appendRequest = {
      ownerId: owner.id, sessionId: ownerSession.id, generation: 0,
      requestId: '10000000-0000-4000-8000-000000000001', sourceRoute: 'prompt_injection',
      prompt: 'owner private prompt', response: 'owner private response', modelUsed: 'fixture-model',
    };
    assert.equal((await migration.query(
      "SELECT has_function_privilege('public','legacy_ai_private.admit_history(integer,bigint)','EXECUTE') AS allowed"
    )).rows[0].allowed, false);
    const historyAdmission = await history.admit({ ownerId: owner.id, sessionId: ownerSession.id });
    assert.deepEqual(historyAdmission, { ownerId: owner.id, sessionId: String(ownerSession.id), generation: '0' });
    await assert.rejects(history.admit({ ownerId: owner.id, sessionId: siblingSession.id }), expectCode('55000'));
    await assert.rejects(runtime.query('SELECT legacy_ai_private.assert_live_session($1,$2)',
      [owner.id, ownerSession.id]), expectCode('42501'));
    const first = await history.append(appendRequest);
    assert.equal(first.replayed, false);
    const replay = await history.append(appendRequest);
    assert.equal(replay.replayed, true);
    const siblingAppend = await history.append({
      ownerId: sibling.id, sessionId: siblingSession.id, generation: 0,
      requestId: '10000000-0000-4000-8000-000000000002', sourceRoute: 'context_stuffing',
      prompt: 'sibling private prompt', response: 'sibling private response', modelUsed: 'fixture-model',
    });
    assert.equal(siblingAppend.replayed, false);
    const ownerRows = await history.listOwn({ ownerId: owner.id, sessionId: ownerSession.id });
    assert.deepEqual(ownerRows.map(row => row.requestId), [appendRequest.requestId]);
    assert.deepEqual((await history.listOwn({ ownerId: sibling.id, sessionId: siblingSession.id }))
      .map(row => row.requestId), ['10000000-0000-4000-8000-000000000002']);

    await assert.rejects(history.listAdmin({ adminId: reader.id, sessionId: readerSession.id }), expectCode('42501'));
    await migration.query("INSERT INTO identity.admin_permissions(admin_id,permission_name,is_active) VALUES($1,'view_analytics',1)",
      [reader.id]);
    assert.deepEqual((await history.listAdmin({ adminId: reader.id, sessionId: readerSession.id, limit: 10 }))
      .map(row => row.requestId).sort(), [appendRequest.requestId, '10000000-0000-4000-8000-000000000002']);
    await migration.query("UPDATE identity.admin_permissions SET is_active=0 WHERE admin_id=$1 AND permission_name='view_analytics'", [reader.id]);
    await assert.rejects(history.listAdmin({ adminId: reader.id, sessionId: readerSession.id }), expectCode('42501'));

    const reset = await history.reset({ ownerId: owner.id, sessionId: ownerSession.id, generation: 0,
      resetRequestId: '10000000-0000-4000-8000-000000000003' });
    assert.deepEqual({ from: reset.fromGeneration, to: reset.toGeneration, removed: reset.removedCount, replayed: reset.replayed },
      { from: '0', to: '1', removed: 1, replayed: false });
    assert.equal((await history.reset({ ownerId: owner.id, sessionId: ownerSession.id, generation: 0,
      resetRequestId: '10000000-0000-4000-8000-000000000003' })).replayed, true);
    await assert.rejects(history.append(appendRequest), expectCode('55000'));
    assert.equal((await history.admit({ ownerId: owner.id, sessionId: ownerSession.id })).generation, '1');
    await history.append({ ...appendRequest, generation: 1,
      requestId: '10000000-0000-4000-8000-000000000004', prompt: 'owner post-reset prompt' });
    assert.equal((await history.listOwn({ ownerId: owner.id, sessionId: ownerSession.id })).length, 1);
    const largePrompt = randomBytes(48_000).toString('base64');
    const largeResponse = randomBytes(196_000).toString('base64');
    assert.ok(Buffer.byteLength(largePrompt) <= 65_536 && Buffer.byteLength(largeResponse) <= 262_144);
    await history.append({ ownerId: owner.id, sessionId: ownerSession.id, generation: 1,
      requestId: '10000000-0000-4000-8000-000000000013', sourceRoute: 'prompt_injection',
      prompt: largePrompt, response: largeResponse, modelUsed: 'fixture-model' });
    const largeStored = (await history.listOwn({ ownerId: owner.id, sessionId: ownerSession.id, limit: 10 }))
      .find(row => row.requestId === '10000000-0000-4000-8000-000000000013');
    assert.equal(largeStored.prompt, largePrompt);
    assert.equal(largeStored.response, largeResponse);

    // PostgreSQL timestamps retain microseconds; JavaScript Date conversion does
    // not. Insert a controlled same-millisecond pair through the migration role
    // and prove the opaque SQL cursor returns both rows without a gap.
    await migration.query('INSERT INTO legacy_ai_private.owners(owner_id,generation) VALUES($1,0)', [paginationOwner.id]);
    await migration.query(`INSERT INTO legacy_ai_private.history
      (request_id,owner_id,generation,source_route,prompt,response,model_used,created_at) VALUES
      ('10000000-0000-4000-8000-000000000005',$1,0,'prompt_injection','one','one','fixture-model','2026-09-15T02:00:00.123001Z'),
      ('10000000-0000-4000-8000-000000000006',$1,0,'prompt_injection','two','two','fixture-model','2026-09-15T02:00:00.123999Z')`,
    [paginationOwner.id]);
    const pageOne = await history.listOwn({ ownerId: paginationOwner.id, sessionId: paginationSession.id, limit: 1 });
    assert.equal(pageOne.length, 1);
    assert.match(pageOne[0].cursor, /^2026-09-15T02:00:00\.123999Z\|/);
    const pageTwo = await history.listOwn({ ownerId: paginationOwner.id, sessionId: paginationSession.id,
      limit: 1, beforeCursor: pageOne[0].cursor });
    assert.deepEqual([pageOne[0].requestId, pageTwo[0].requestId], [
      '10000000-0000-4000-8000-000000000006', '10000000-0000-4000-8000-000000000005',
    ]);

    for (const query of [
      'SELECT * FROM legacy_ai_private.history',
      'SELECT * FROM legacy_ai_private.owners',
      'SELECT * FROM legacy_ai_private.import_archive',
      'SELECT legacy_ai_private.assert_live_session($1,$2)',
      'SELECT legacy_ai_private.assert_admin_reader($1,$2)',
    ]) {
      const params = query.includes('$1') ? [owner.id, ownerSession.id] : [];
      await assert.rejects(runtime.query(query, params), expectCode('42501'));
    }
    for (const [query, params] of [
      ['SELECT * FROM legacy_ai_private.begin_history_import($1::uuid,$2::text,$3::integer,$4::text)',
        ['10000000-0000-4000-8000-000000000030', 'legacy://runtime-denied', 0, '0'.repeat(64)]],
      ['SELECT * FROM legacy_ai_private.archive_history_import_row($1::uuid,$2::bigint,$3::jsonb,$4::text,$5::text,$6::integer)',
        ['10000000-0000-4000-8000-000000000030', 1, '{}', '0'.repeat(64), 'owned', owner.id]],
      ['SELECT * FROM legacy_ai_private.promote_owned_history_import_row($1::uuid,$2::bigint,$3::integer,$4::uuid,$5::text,$6::text,$7::text,$8::text,$9::timestamptz,$10::text)',
        ['10000000-0000-4000-8000-000000000030', 1, owner.id,
          '10000000-0000-4000-8000-000000000031', 'prompt_injection', 'denied', 'denied',
          'fixture-model', '2026-09-15T00:00:00.000000Z', '0'.repeat(64)]],
      ['SELECT * FROM legacy_ai_private.verify_history_import_quarantine($1::uuid,$2::integer,$3::text)',
        ['10000000-0000-4000-8000-000000000030', 0, '0'.repeat(64)]],
    ]) {
      await assert.rejects(runtime.query(query, params), expectCode('42501'));
    }

    // Two independent clients demonstrate the intended owner-row deletion fence:
    // the protected reader holds FOR SHARE; deletion admission cannot take FOR
    // UPDATE until that function transaction commits, then revokes the session.
    held = await runtime.connect();
    await held.query('BEGIN');
    const heldPid = (await held.query('SELECT pg_backend_pid()::integer AS pid')).rows[0].pid;
    await held.query('SELECT * FROM legacy_ai_private.list_own_history($1,$2,$3,$4)',
      [deletionOwner.id, deletionOwnerSession.id, 10, null]);
    let admissionPid;
    const admissionPool = {
      query: runtime.query.bind(runtime),
      async connect() {
        const client = await runtime.connect();
        admissionPid = (await client.query('SELECT pg_backend_pid()::integer AS pid')).rows[0].pid;
        return client;
      },
    };
    const deletion = createStudentDeletionRepository(admissionPool,
      { steps: ['revoke_runs', 'legacy_ai_history', 'identity'] });
    let admissionSettled = false;
    const admission = deletion.admit({ requesterId: deletionAdmin.id, subjectId: deletionOwner.id })
      .finally(() => { admissionSettled = true; });
    await waitFor('deletion admission connection', () => admissionPid !== undefined);
    await waitFor('deletion admission blocked by the owner reader', async () => (await held.query(
      'SELECT $1::integer=ANY(pg_blocking_pids($2::integer)) AS blocked', [heldPid, admissionPid],
    )).rows[0].blocked === true);
    assert.equal(admissionSettled, false, 'blocked admission must not have committed');
    await held.query('COMMIT');
    held.release(); held = undefined;
    const admitted = await admission;
    assert.equal(admitted.replayed, false);
    await assert.rejects(history.listOwn({ ownerId: deletionOwner.id, sessionId: deletionOwnerSession.id }),
      expectCode('55000'));
    assert.equal((await runtime.query('SELECT is_active FROM identity.user_sessions WHERE id=$1',
      [deletionOwnerSession.id])).rows[0].is_active, 0);
    assert.deepEqual((await history.listOwn({ ownerId: sibling.id, sessionId: siblingSession.id }))
      .map(row => row.requestId), ['10000000-0000-4000-8000-000000000002'],
    'sibling history remains independent after target deletion admission');

    // Import primitives are migration-only. They archive exact bytes before
    // promotion, preserve microseconds, verify a durable aggregate receipt,
    // and let a completed batch replay through readback without writes.
    const importBatch = '10000000-0000-4000-8000-000000000014';
    const importDigest = 'e'.repeat(64);
    const importRowDigest = 'f'.repeat(64);
    const importHistoryDigest = '1'.repeat(64);
    const importRequest = '10000000-0000-4000-8000-000000000015';
    const importRecord = { id: 1, userId: 999, prompt: 'imported exact prompt', response: 'imported exact response',
      modelUsed: 'fixture-model', createdAt: '2026-09-15T03:04:05.123456Z', platformOwnerId: paginationOwner.id };
    assert.equal((await migration.query('SELECT * FROM legacy_ai_private.begin_history_import($1,$2,$3,$4)',
      [importBatch, 'legacy://disposable/import', 1, importDigest])).rows[0].replayed, false);
    await migration.query('SELECT * FROM legacy_ai_private.archive_history_import_row($1,$2,$3::jsonb,$4,$5,$6)',
      [importBatch, 1, JSON.stringify(importRecord), importRowDigest, 'owned', paginationOwner.id]);
    assert.equal((await migration.query('SELECT * FROM legacy_ai_private.promote_owned_history_import_row($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',
      [importBatch, 1, paginationOwner.id, importRequest, 'prompt_injection', importRecord.prompt, importRecord.response,
        importRecord.modelUsed, importRecord.createdAt, importHistoryDigest])).rows[0].replayed, false);
    const verifiedImport = (await migration.query('SELECT * FROM legacy_ai_private.verify_history_import_quarantine($1,$2,$3)',
      [importBatch, 1, importDigest])).rows[0];
    assert.equal(verifiedImport.source_removal_receipt, importDigest);
    assert.equal((await migration.query('SELECT * FROM legacy_ai_private.begin_history_import($1,$2,$3,$4)',
      [importBatch, 'legacy://disposable/import', 1, importDigest])).rows[0].state, 'verified');
    assert.deepEqual((await migration.query(`SELECT prompt,response,
      to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS created_at
      FROM legacy_ai_private.history WHERE request_id=$1`, [importRequest])).rows[0],
      { prompt: importRecord.prompt, response: importRecord.response, created_at: importRecord.createdAt });

    const composedBatch='10000000-0000-4000-8000-000000000020', composedRequest='abcdefab-abcd-4abc-8abc-abcdefabcdef';
    const composedRows=[{id:1,userId:9,prompt:'composed-owned',response:'composed-answer',modelUsed:'fixture-model',createdAt:'2026-09-15T05:06:07.123456Z',platformOwnerId:sibling.id},{id:2,userId:1,prompt:'composed-unknown',response:'quarantine',modelUsed:'fixture-model',createdAt:'2026-09-15T05:06:08.123457Z',platformOwnerId:null},{id:-2147483648,userId:0,prompt:'raw-source-domain',response:null,modelUsed:null,createdAt:'infinity',platformOwnerId:-1}];let archiveWrites=0,promotionWrites=0;
    const sourceCapability=Object.freeze({readSnapshot:async()=>({batchId:composedBatch,sourceStoreIdentity:'legacy://composed',rows:composedRows})});
    const attestationCapability=Object.freeze({attest:async value=>{const claims=[{sourceRowId:1,sourceDigest:value.rows.find(row => row.sourceRowId === 1).sourceDigest,ownerId:sibling.id,requestId:composedRequest.toUpperCase(),sourceRoute:'prompt_injection'}];const claimsDigest=importDigestValue(claims.map(claim=>({...claim,requestId:claim.requestId.toLowerCase()}))),manifestDigest='a'.repeat(64),attestationReceipt='b'.repeat(64);return{envelopeVersion:1,batchId:value.batchId,sourceStoreDigest:value.sourceStoreDigest,aggregateDigest:value.aggregateDigest,manifestDigest,claims,claimsDigest,attestationReceipt,boundSourceStoreIdentity:bindSourceStoreIdentity({sourceStoreDigest:value.sourceStoreDigest,manifestDigest,claimsDigest,attestationReceipt})};}});
    const targetAdapter = createLegacyAiHistoryImportTarget(migration, {
      database: new URL(process.env[PREFIX + 'IDENTITY_MIGRATION_URL']).pathname.slice(1),
    });
    const deniedBatch = { batchId: '10000000-0000-4000-8000-000000000030',
      sourceStoreIdentity: 'legacy://denied-adapter', expectedCount: 0, aggregateDigest: 'a'.repeat(64) };
    await assert.rejects(createLegacyAiHistoryImportTarget(runtime, {
      database: new URL(process.env[PREFIX + 'IDENTITY_RUNTIME_URL']).pathname.slice(1),
    }).begin(deniedBatch), /migration authority/);
    await assert.rejects(createLegacyAiHistoryImportTarget(migration, {
      database: 'owasp_ai_goat_test_wrong_database',
    }).begin(deniedBatch), /migration authority/);
    for (const signature of [
      'begin_history_import(uuid,text,integer,text)',
      'archive_history_import_row(uuid,bigint,jsonb,text,text,integer)',
      'promote_owned_history_import_row(uuid,bigint,integer,uuid,text,text,text,text,timestamptz,text)',
      'verify_history_import_quarantine(uuid,integer,text)',
    ]) for (const grantee of ['PUBLIC', 'dvaia_identity_runtime']) {
      // These identifiers are a fixed fixture allowlist in this disposable DB.
      await migration.query(`GRANT EXECUTE ON FUNCTION legacy_ai_private.${signature} TO ${grantee}`);
      try {
        await assert.rejects(targetAdapter.begin(deniedBatch), /ownership and ACL/);
        assert.equal((await migration.query('SELECT count(*)::integer AS n FROM legacy_ai_private.import_batches WHERE batch_id=$1',
          [deniedBatch.batchId])).rows[0].n, 0, 'failed readiness must not create an import batch');
      } finally {
        await migration.query(`REVOKE EXECUTE ON FUNCTION legacy_ai_private.${signature} FROM ${grantee}`);
      }
    }
    const targetCapability = Object.freeze({ ...targetAdapter,
      archive: async value => { archiveWrites++; return targetAdapter.archive(value); },
      promote: async value => { promotionWrites++; return targetAdapter.promote(value); },
    });
    const composed=createLegacyAiHistoryDraftImporter({sourceSnapshotCapability:sourceCapability,ownershipAttestationCapability:attestationCapability,targetImportCapability:targetCapability});
    await composed.quarantine();assert.equal(archiveWrites,3);assert.equal(promotionWrites,1);await composed.quarantine();assert.equal(archiveWrites,3);assert.equal(promotionWrites,1);

    // Exercise the concrete archive-only authority against actual target SQL.
    // Mutable legacy owner columns must not promote any of these source rows.
    const archiveOnlyBatch = '10000000-0000-4000-8000-000000000031';
    const archiveOnlyIdentity = 'legacy://reviewed-archive-only';
    const archiveOnlyRows = [...composedRows].sort((a, b) => a.id - b.id);
    const archiveOnlyDescriptors = archiveOnlyRows.map(row => ({
      sourceRowId: row.id, sourceDigest: importDigestValue(row),
    }));
    const archiveOnlyManifest = { envelopeVersion: 1, batchId: archiveOnlyBatch,
      sourceStoreIdentity: archiveOnlyIdentity,
      sourceStoreDigest: computeSourceStoreDigest(archiveOnlyIdentity),
      aggregateDigest: importDigestValue(archiveOnlyDescriptors), rows: archiveOnlyDescriptors, claims: [] };
    const archiveOnlyAuthority = receipt => createLegacyAiHistoryArchiveAttestation({
      manifest: archiveOnlyManifest, manifestDigest: computeManifestDigest(archiveOnlyManifest),
      attestationReceipt: receipt,
    });
    const archiveOnlySource = Object.freeze({ readSnapshot: async () => ({
      batchId: archiveOnlyBatch, sourceStoreIdentity: archiveOnlyIdentity, rows: archiveOnlyRows,
    }) });
    let archiveOnlyWrites = 0;
    const archiveOnlyTarget = Object.freeze({ ...targetAdapter,
      archive: async value => { archiveOnlyWrites++; return targetAdapter.archive(value); },
      promote: async () => { assert.fail('Archive-only authority must never promote history'); },
    });
    const archiveOnlyImporter = receipt => createLegacyAiHistoryDraftImporter({
      sourceSnapshotCapability: archiveOnlySource,
      ownershipAttestationCapability: archiveOnlyAuthority(receipt),
      targetImportCapability: archiveOnlyTarget,
    });
    const historyCountBefore = (await migration.query(
      'SELECT count(*)::integer AS n FROM legacy_ai_private.history')).rows[0].n;
    await archiveOnlyImporter('c'.repeat(64)).quarantine();
    assert.equal(archiveOnlyWrites, archiveOnlyRows.length);
    assert.deepEqual((await targetAdapter.readArchived({ batchId: archiveOnlyBatch })).map(row => ({
      sourceRecord: row.sourceRecord, classification: row.classification, ownerId: row.ownerId,
    })).sort((a, b) => a.sourceRecord.id - b.sourceRecord.id), archiveOnlyRows.map(sourceRecord => ({
      sourceRecord, classification: 'unknown', ownerId: null,
    })));
    const archiveOnlyState = async () => ({
      batch: (await migration.query(`SELECT source_store_identity,state,xmin::text AS revision
        FROM legacy_ai_private.import_batches WHERE batch_id=$1`, [archiveOnlyBatch])).rows,
      archive: (await migration.query(`SELECT source_row_id,source_record,source_digest,
        classification,classified_owner_id,xmin::text AS revision
        FROM legacy_ai_private.import_archive WHERE batch_id=$1 ORDER BY source_row_id`,
      [archiveOnlyBatch])).rows,
    });
    const verifiedArchiveOnly = await archiveOnlyState();
    assert.equal(verifiedArchiveOnly.batch[0].state, 'verified');
    await archiveOnlyImporter('c'.repeat(64)).quarantine();
    assert.equal(archiveOnlyWrites, archiveOnlyRows.length, 'verified replay makes no archive writes');
    assert.deepEqual(await archiveOnlyState(), verifiedArchiveOnly, 'verified replay leaves row versions intact');
    await assert.rejects(archiveOnlyImporter('d'.repeat(64)).quarantine(), {
      code: '23505', message: 'Legacy AI import batch conflicts with prior bytes',
    });
    assert.deepEqual(await archiveOnlyState(), verifiedArchiveOnly, 'changed operator record cannot rebind a batch');
    assert.equal(archiveOnlyWrites, archiveOnlyRows.length);
    assert.equal((await migration.query(
      'SELECT count(*)::integer AS n FROM legacy_ai_private.history')).rows[0].n, historyCountBefore);

    for (const race of [{ owner: archiveRaceOwner, batch: '10000000-0000-4000-8000-000000000017', request: null },
      { owner: promotionRaceOwner, batch: '10000000-0000-4000-8000-000000000018', request: '10000000-0000-4000-8000-000000000019' }]) {
      await migration.query('SELECT * FROM legacy_ai_private.begin_history_import($1,$2,$3,$4)', [race.batch, `legacy://race/${race.batch}`, 1, '4'.repeat(64)]);
      if (race.request) await migration.query('SELECT * FROM legacy_ai_private.archive_history_import_row($1,$2,$3::jsonb,$4,$5,$6)', [race.batch,1,'{"id":1,"prompt":"race","response":"race"}', '5'.repeat(64),'owned',race.owner.id]);
      held=await migration.connect();await held.query('BEGIN');const heldPid=(await held.query('SELECT pg_backend_pid()::integer AS pid')).rows[0].pid;
      if (race.request) await held.query('SELECT * FROM legacy_ai_private.promote_owned_history_import_row($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)', [race.batch,1,race.owner.id,race.request,'prompt_injection','race','race','fixture-model','2026-09-15T04:05:06.123456Z','6'.repeat(64)]);
      else await held.query('SELECT * FROM legacy_ai_private.archive_history_import_row($1,$2,$3::jsonb,$4,$5,$6)', [race.batch,1,'{"id":1,"prompt":"race","response":"race"}', '5'.repeat(64),'owned',race.owner.id]);
      let waitingPid;const racePool={query:runtime.query.bind(runtime),async connect(){const client=await runtime.connect();waitingPid=(await client.query('SELECT pg_backend_pid()::integer AS pid')).rows[0].pid;return client;}};
      const raceDeletion=createStudentDeletionRepository(racePool,{steps:['revoke_runs','legacy_ai_history','identity']});let settled=false;const admitted=raceDeletion.admit({requesterId:deletionAdmin.id,subjectId:race.owner.id}).finally(()=>{settled=true;});
      await waitFor('race deletion backend',()=>waitingPid!==undefined);await waitFor('exact import/deletion lock wait',async()=> (await held.query('SELECT $1::integer=ANY(pg_blocking_pids($2::integer)) AS blocked',[heldPid,waitingPid])).rows[0].blocked===true);assert.equal(settled,false);
      await held.query('COMMIT');held.release();held=undefined;const terminal=await admitted;assert.equal(terminal.replayed,false);
    }

    // The converse ordering is the regression that distinguishes user-first
    // import locking from the old batch-first inversion. Pause real deletion
    // admission after it owns the identity rows, then prove archive/promotion
    // cannot lock or mutate their batch while waiting on that owner fence.
    for (const race of [
      { owner: deletionFirstArchiveOwner, batch: '10000000-0000-4000-8000-000000000021', request: null },
      { owner: deletionFirstPromotionOwner, batch: '10000000-0000-4000-8000-000000000022',
        request: '10000000-0000-4000-8000-000000000023' },
    ]) {
      await migration.query('SELECT * FROM legacy_ai_private.begin_history_import($1,$2,$3,$4)',
        [race.batch, `legacy://deletion-first/${race.batch}`, 1, '7'.repeat(64)]);
      if (race.request) {
        await migration.query('SELECT * FROM legacy_ai_private.archive_history_import_row($1,$2,$3::jsonb,$4,$5,$6)',
          [race.batch, 1, '{"id":1,"prompt":"deletion-first","response":"deletion-first"}',
            '8'.repeat(64), 'owned', race.owner.id]);
      }
      const before = (await migration.query(`SELECT batch.copied_count,
        (SELECT count(*)::integer FROM legacy_ai_private.import_archive archived WHERE archived.batch_id=batch.batch_id) AS archives,
        (SELECT count(*)::integer FROM legacy_ai_private.import_history_receipts receipt WHERE receipt.batch_id=batch.batch_id) AS receipts,
        (SELECT count(*)::integer FROM legacy_ai_private.import_batch_events event WHERE event.batch_id=batch.batch_id) AS events,
        (SELECT count(*)::integer FROM legacy_ai_private.history item WHERE item.owner_id=$2) AS history
        FROM legacy_ai_private.import_batches batch WHERE batch.batch_id=$1`, [race.batch, race.owner.id])).rows[0];
      const barrier = pausePoolAfterQuery(runtime,
        text => text.includes('SELECT id,role,admin_level,is_active FROM identity.users WHERE id=ANY'));
      const raceDeletion = createStudentDeletionRepository(barrier.pool,
        { steps: ['revoke_runs', 'legacy_ai_history', 'identity'] });
      let admission;
      let importClient;
      let importOutcome;
      try {
        admission = raceDeletion.admit({ requesterId: deletionAdmin.id, subjectId: race.owner.id });
        const deletionPid = await barrier.wait('deletion-first identity owner lock');
        importClient = await migration.connect();
        const importPid = (await importClient.query('SELECT pg_backend_pid()::integer AS pid')).rows[0].pid;
        const query = race.request
          ? ['SELECT * FROM legacy_ai_private.promote_owned_history_import_row($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',
            [race.batch, 1, race.owner.id, race.request, 'prompt_injection', 'deletion-first',
              'deletion-first', 'fixture-model', '2026-09-15T06:07:08.123456Z', '9'.repeat(64)]]
          : ['SELECT * FROM legacy_ai_private.archive_history_import_row($1,$2,$3::jsonb,$4,$5,$6)',
            [race.batch, 1, '{"id":1,"prompt":"deletion-first","response":"deletion-first"}',
              '8'.repeat(64), 'owned', race.owner.id]];
        let importSettled = false;
        importOutcome = importClient.query(query[0], query[1])
          .then(value => ({ value }), error => ({ error }))
          .finally(() => { importSettled = true; });
        await waitFor('deletion-first import blocked on the exact deletion backend', async () => (await migration.query(
          'SELECT $1::integer=ANY(pg_blocking_pids($2::integer)) AS blocked',
          [deletionPid, importPid])).rows[0].blocked === true);
        assert.equal(importSettled, false);
        await assertBatchLockAvailable(migration, race.batch);
        assert.deepEqual((await migration.query(`SELECT batch.copied_count,
          (SELECT count(*)::integer FROM legacy_ai_private.import_archive archived WHERE archived.batch_id=batch.batch_id) AS archives,
          (SELECT count(*)::integer FROM legacy_ai_private.import_history_receipts receipt WHERE receipt.batch_id=batch.batch_id) AS receipts,
          (SELECT count(*)::integer FROM legacy_ai_private.import_batch_events event WHERE event.batch_id=batch.batch_id) AS events,
          (SELECT count(*)::integer FROM legacy_ai_private.history item WHERE item.owner_id=$2) AS history
          FROM legacy_ai_private.import_batches batch WHERE batch.batch_id=$1`, [race.batch, race.owner.id])).rows[0], before,
        'blocked import must not mutate archive, history, receipts, events, or copied count');
        barrier.release();
        const admitted = await bounded(admission, 'deletion-first admission commit');
        assert.equal(admitted.replayed, false);
        const outcome = await bounded(importOutcome, 'deletion-first import rejection');
        assert.equal(outcome.error?.code, '55000');
        assert.equal(outcome.value, undefined);
      } finally {
        barrier.release();
        if (admission) await bounded(Promise.allSettled([admission]), 'deletion-first admission cleanup');
        if (importOutcome) await bounded(Promise.allSettled([importOutcome]), 'deletion-first import cleanup');
        if (importClient) importClient.release();
      }
      assert.deepEqual((await migration.query(`SELECT batch.copied_count,
        (SELECT count(*)::integer FROM legacy_ai_private.import_archive archived WHERE archived.batch_id=batch.batch_id) AS archives,
        (SELECT count(*)::integer FROM legacy_ai_private.import_history_receipts receipt WHERE receipt.batch_id=batch.batch_id) AS receipts,
        (SELECT count(*)::integer FROM legacy_ai_private.import_batch_events event WHERE event.batch_id=batch.batch_id) AS events,
        (SELECT count(*)::integer FROM legacy_ai_private.history item WHERE item.owner_id=$2) AS history
        FROM legacy_ai_private.import_batches batch WHERE batch.batch_id=$1`, [race.batch, race.owner.id])).rows[0], before,
      'deletion-winning import must leave the prior batch bytes and journal unchanged');
      assert.deepEqual((await migration.query(`SELECT account.is_active,
        (SELECT count(*)::integer FROM identity.student_deletion_jobs job WHERE job.subject_user_id=account.id) AS jobs
        FROM identity.users account WHERE account.id=$1`, [race.owner.id])).rows[0],
      { is_active: 0, jobs: 1 });
    }

    // Promotion first: reset must wait on the same identity/owner lock order,
    // then advance the generation and remove the newly imported history.
    const promotionFirstBatch = '10000000-0000-4000-8000-000000000024';
    const promotionFirstRequest = '10000000-0000-4000-8000-000000000025';
    const promotionFirstReset = '10000000-0000-4000-8000-000000000026';
    await migration.query('SELECT * FROM legacy_ai_private.begin_history_import($1,$2,$3,$4)',
      [promotionFirstBatch, 'legacy://promotion-first-reset', 1, 'a'.repeat(64)]);
    await migration.query('SELECT * FROM legacy_ai_private.archive_history_import_row($1,$2,$3::jsonb,$4,$5,$6)',
      [promotionFirstBatch, 1, '{"id":1,"prompt":"promotion-first","response":"promotion-first"}',
        'b'.repeat(64), 'owned', promotionFirstResetOwner.id]);
    let resetClient;
    let resetOutcome;
    try {
      held = await migration.connect();
      await held.query('BEGIN');
      const promotionPid = (await held.query('SELECT pg_backend_pid()::integer AS pid')).rows[0].pid;
      await held.query('SELECT * FROM legacy_ai_private.promote_owned_history_import_row($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',
        [promotionFirstBatch, 1, promotionFirstResetOwner.id, promotionFirstRequest, 'prompt_injection',
          'promotion-first', 'promotion-first', 'fixture-model', '2026-09-15T07:08:09.123456Z', 'c'.repeat(64)]);
      resetClient = await runtime.connect();
      const resetPid = (await resetClient.query('SELECT pg_backend_pid()::integer AS pid')).rows[0].pid;
      let resetSettled = false;
      resetOutcome = resetClient.query('SELECT * FROM legacy_ai_private.reset_history($1,$2,$3,$4)',
        [promotionFirstResetOwner.id, promotionFirstResetSession.id, 0, promotionFirstReset])
        .then(value => ({ value }), error => ({ error }))
        .finally(() => { resetSettled = true; });
      await waitFor('promotion-first reset blocked on the exact promotion backend', async () => (await held.query(
        'SELECT $1::integer=ANY(pg_blocking_pids($2::integer)) AS blocked',
        [promotionPid, resetPid])).rows[0].blocked === true);
      assert.equal(resetSettled, false);
      await held.query('COMMIT');
      held.release();
      held = undefined;
      const outcome = await bounded(resetOutcome, 'promotion-first reset completion');
      assert.equal(outcome.error, undefined);
      assert.deepEqual({ from: outcome.value.rows[0].from_generation, to: outcome.value.rows[0].to_generation,
        removed: outcome.value.rows[0].removed_count, replayed: outcome.value.rows[0].replayed },
      { from: '0', to: '1', removed: 1, replayed: false });
    } finally {
      if (held) {
        await held.query('ROLLBACK').catch(() => {});
        held.release();
        held = undefined;
      }
      if (resetOutcome) await bounded(Promise.allSettled([resetOutcome]), 'promotion-first reset cleanup');
      if (resetClient) resetClient.release();
    }
    assert.deepEqual((await migration.query(`SELECT
      (SELECT count(*)::integer FROM legacy_ai_private.history WHERE owner_id=$1) AS history,
      (SELECT count(*)::integer FROM legacy_ai_private.reset_receipts WHERE owner_id=$1) AS resets,
      (SELECT count(*)::integer FROM legacy_ai_private.import_archive WHERE batch_id=$2) AS archives,
      (SELECT count(*)::integer FROM legacy_ai_private.import_history_receipts WHERE batch_id=$2) AS receipts,
      (SELECT count(*)::integer FROM legacy_ai_private.import_batch_events WHERE batch_id=$2 AND event_kind='promoted') AS promoted_events`,
    [promotionFirstResetOwner.id, promotionFirstBatch])).rows[0],
    { history: 0, resets: 1, archives: 1, receipts: 1, promoted_events: 1 });

    // Reset first: promotion waits before the batch lock, then must fail closed
    // against generation one without creating history, receipt, or event bytes.
    const resetFirstBatch = '10000000-0000-4000-8000-000000000027';
    const resetFirstRequest = '10000000-0000-4000-8000-000000000028';
    const resetFirstReset = '10000000-0000-4000-8000-000000000029';
    await migration.query('SELECT * FROM legacy_ai_private.begin_history_import($1,$2,$3,$4)',
      [resetFirstBatch, 'legacy://reset-first-promotion', 1, 'd'.repeat(64)]);
    await migration.query('SELECT * FROM legacy_ai_private.archive_history_import_row($1,$2,$3::jsonb,$4,$5,$6)',
      [resetFirstBatch, 1, '{"id":1,"prompt":"reset-first","response":"reset-first"}',
        'e'.repeat(64), 'owned', resetFirstPromotionOwner.id]);
    let promotionClient;
    let promotionOutcome;
    try {
      held = await runtime.connect();
      await held.query('BEGIN');
      const resetPid = (await held.query('SELECT pg_backend_pid()::integer AS pid')).rows[0].pid;
      const resetRow = (await held.query('SELECT * FROM legacy_ai_private.reset_history($1,$2,$3,$4)',
        [resetFirstPromotionOwner.id, resetFirstPromotionSession.id, 0, resetFirstReset])).rows[0];
      assert.deepEqual({ from: resetRow.from_generation, to: resetRow.to_generation,
        removed: resetRow.removed_count, replayed: resetRow.replayed },
      { from: '0', to: '1', removed: 0, replayed: false });
      promotionClient = await migration.connect();
      const promotionPid = (await promotionClient.query('SELECT pg_backend_pid()::integer AS pid')).rows[0].pid;
      let promotionSettled = false;
      promotionOutcome = promotionClient.query(
        'SELECT * FROM legacy_ai_private.promote_owned_history_import_row($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',
        [resetFirstBatch, 1, resetFirstPromotionOwner.id, resetFirstRequest, 'prompt_injection',
          'reset-first', 'reset-first', 'fixture-model', '2026-09-15T08:09:10.123456Z', 'f'.repeat(64)])
        .then(value => ({ value }), error => ({ error }))
        .finally(() => { promotionSettled = true; });
      await waitFor('reset-first promotion blocked on the exact reset backend', async () => (await held.query(
        'SELECT $1::integer=ANY(pg_blocking_pids($2::integer)) AS blocked',
        [resetPid, promotionPid])).rows[0].blocked === true);
      assert.equal(promotionSettled, false);
      await assertBatchLockAvailable(migration, resetFirstBatch);
      assert.deepEqual((await migration.query(`SELECT
        (SELECT count(*)::integer FROM legacy_ai_private.history WHERE owner_id=$1) AS history,
        (SELECT count(*)::integer FROM legacy_ai_private.import_history_receipts WHERE batch_id=$2) AS receipts,
        (SELECT count(*)::integer FROM legacy_ai_private.import_batch_events WHERE batch_id=$2 AND event_kind='promoted') AS promoted_events`,
      [resetFirstPromotionOwner.id, resetFirstBatch])).rows[0],
      { history: 0, receipts: 0, promoted_events: 0 });
      await held.query('COMMIT');
      held.release();
      held = undefined;
      const outcome = await bounded(promotionOutcome, 'reset-first promotion rejection');
      assert.equal(outcome.error?.code, '55000');
      assert.equal(outcome.value, undefined);
    } finally {
      if (held) {
        await held.query('ROLLBACK').catch(() => {});
        held.release();
        held = undefined;
      }
      if (promotionOutcome) await bounded(Promise.allSettled([promotionOutcome]), 'reset-first promotion cleanup');
      if (promotionClient) promotionClient.release();
    }
    assert.deepEqual((await migration.query(`SELECT owner.generation,
      (SELECT count(*)::integer FROM legacy_ai_private.history WHERE owner_id=$1) AS history,
      (SELECT count(*)::integer FROM legacy_ai_private.reset_receipts WHERE owner_id=$1) AS resets,
      (SELECT count(*)::integer FROM legacy_ai_private.import_archive WHERE batch_id=$2) AS archives,
      (SELECT count(*)::integer FROM legacy_ai_private.import_history_receipts WHERE batch_id=$2) AS receipts,
      (SELECT count(*)::integer FROM legacy_ai_private.import_batch_events WHERE batch_id=$2 AND event_kind='promoted') AS promoted_events
      FROM legacy_ai_private.owners owner WHERE owner.owner_id=$1`,
    [resetFirstPromotionOwner.id, resetFirstBatch])).rows[0],
    { generation: '1', history: 0, resets: 1, archives: 1, receipts: 0, promoted_events: 0 });

    const cleanupRequest = {
      ownerId: cleanupOwner.id, sessionId: cleanupSession.id, generation: 0,
      requestId: '10000000-0000-4000-8000-000000000007', sourceRoute: 'prompt_injection',
      prompt: 'cleanup owner prompt', response: 'cleanup owner response', modelUsed: 'fixture-model',
    };
    await history.append(cleanupRequest);
    await migration.query(`INSERT INTO legacy_ai_private.import_batches
      (batch_id,source_store_identity,state,expected_count,copied_count,aggregate_digest) VALUES
      ('10000000-0000-4000-8000-000000000008','owned-disposable-legacy','copying',3,0,$1)`, ['a'.repeat(64)]);
    await migration.query(`INSERT INTO legacy_ai_private.import_archive
      (batch_id,source_row_id,source_record,source_digest,classification,classified_owner_id) VALUES
      ('10000000-0000-4000-8000-000000000008',1,'{"owner":"cleanup"}'::jsonb,$1,'owned',$4),
      ('10000000-0000-4000-8000-000000000008',2,'{"owner":"sibling"}'::jsonb,$2,'owned',$5),
      ('10000000-0000-4000-8000-000000000008',3,'{"owner":"unknown"}'::jsonb,$3,'unknown',NULL)`,
    ['b'.repeat(64), 'c'.repeat(64), 'd'.repeat(64), cleanupOwner.id, sibling.id]);
    await migration.query(`UPDATE legacy_ai_private.import_batches SET state='verified',copied_count=3,verified_at=clock_timestamp()
      WHERE batch_id='10000000-0000-4000-8000-000000000008'`);
    await migration.query(`INSERT INTO legacy_ai_private.import_batches
      (batch_id,source_store_identity,state,expected_count,copied_count,aggregate_digest) VALUES
      ('10000000-0000-4000-8000-000000000016','copying-disposable-legacy','copying',1,1,$1)`, ['2'.repeat(64)]);
    await migration.query(`INSERT INTO legacy_ai_private.import_archive
      (batch_id,source_row_id,source_record,source_digest,classification,classified_owner_id) VALUES
      ('10000000-0000-4000-8000-000000000016',1,'{"owner":"cleanup-copying"}'::jsonb,$1,'owned',$2)`,
    ['3'.repeat(64), cleanupOwner.id]);
    const cleanupAdmission = await deletion.admit({ requesterId: deletionAdmin.id, subjectId: cleanupOwner.id });
    let cleanupLease = await deletion.claim(cleanupAdmission.jobId);
    assert.ok(cleanupLease);
    await deletion.acknowledge({ jobId: cleanupAdmission.jobId, leaseToken: cleanupLease.leaseToken, stepKey: 'revoke_runs' });
    await deletion.fail({ jobId: cleanupAdmission.jobId, leaseToken: cleanupLease.leaseToken, stepKey: 'legacy_ai_history' });
    cleanupLease = await deletion.claim(cleanupAdmission.jobId);
    assert.ok(cleanupLease, 'failed cleanup step must be claimed under a new current lease');
    assert.deepEqual(await deletion.nextStep({ jobId: cleanupAdmission.jobId, leaseToken: cleanupLease.leaseToken }),
      { subjectId: cleanupOwner.id, stepKey: 'legacy_ai_history' });
    await assert.rejects(history.cleanupForStudentDeletion({ ownerId: sibling.id,
      jobId: cleanupAdmission.jobId, leaseToken: cleanupLease.leaseToken }), expectCode('55000'));
    await assert.rejects(history.cleanupForStudentDeletion({ ownerId: cleanupOwner.id,
      jobId: cleanupAdmission.jobId, leaseToken: '10000000-0000-4000-8000-000000000009' }), expectCode('55000'));
    const cleanup = await history.cleanupForStudentDeletion({ ownerId: cleanupOwner.id,
      jobId: cleanupAdmission.jobId, leaseToken: cleanupLease.leaseToken });
    assert.deepEqual({ history: cleanup.historyRemoved, ownerState: cleanup.ownerStateRemoved,
      archive: cleanup.archiveRemoved, replayed: cleanup.replayed },
    { history: 1, ownerState: 1, archive: 2, replayed: false });
    assert.equal((await history.cleanupForStudentDeletion({ ownerId: cleanupOwner.id,
      jobId: cleanupAdmission.jobId, leaseToken: cleanupLease.leaseToken })).replayed, true);
    assert.equal((await migration.query('SELECT count(*)::integer AS n FROM legacy_ai_private.history WHERE owner_id=$1',
      [cleanupOwner.id])).rows[0].n, 0);
    assert.deepEqual((await migration.query(`SELECT source_row_id,classification FROM legacy_ai_private.import_archive
      WHERE batch_id='10000000-0000-4000-8000-000000000008' ORDER BY source_row_id`)).rows,
    [{ source_row_id: '2', classification: 'owned' }, { source_row_id: '3', classification: 'unknown' }]);
    assert.deepEqual((await migration.query(`SELECT batch_id,state,verified_at IS NULL AS invalidated FROM legacy_ai_private.import_batches
      WHERE batch_id IN ('10000000-0000-4000-8000-000000000008','10000000-0000-4000-8000-000000000016') ORDER BY batch_id`)).rows,
    [{ batch_id: '10000000-0000-4000-8000-000000000008', state: 'blocked', invalidated: true },
      { batch_id: '10000000-0000-4000-8000-000000000016', state: 'blocked', invalidated: true }]);
    assert.equal((await migration.query(`SELECT count(*)::integer AS n FROM legacy_ai_private.import_batch_events
      WHERE event_kind='invalidated_by_deletion' AND batch_id IN ('10000000-0000-4000-8000-000000000008','10000000-0000-4000-8000-000000000016')`)).rows[0].n, 2);
    await deletion.acknowledge({ jobId: cleanupAdmission.jobId, leaseToken: cleanupLease.leaseToken,
      stepKey: 'legacy_ai_history' });
    await assert.rejects(history.cleanupForStudentDeletion({ ownerId: cleanupOwner.id,
      jobId: cleanupAdmission.jobId, leaseToken: cleanupLease.leaseToken }), expectCode('55000'));

    // The composed service releases admission before inference. Reset must
    // finish while inference is paused, and the delayed response cannot reappear.
    const composingOwner = await createUser(identities, 'composing-owner');
    const composingSession = await createSession(identities, composingOwner, 'composing-session');
    let enteredInference;
    let releaseInference;
    const entered = new Promise(resolve => { enteredInference = resolve; });
    const released = new Promise(resolve => { releaseInference = resolve; });
    const requests = createLegacyAiHistoryRequestService({ history,
      async infer(input) {
        assert.equal(input.prompt, 'paused controlled prompt');
        assert.equal(input.sourceRoute, 'prompt_injection');
        enteredInference();
        await bounded(released, 'release composed inference');
        return { response: 'delayed controlled response', modelUsed: 'fixture-model' };
      },
    });
    const pending = requests.runAuthenticated({ ownerId: composingOwner.id,
      sessionId: composingSession.id, sourceRoute: 'prompt_injection', prompt: 'paused controlled prompt' });
    const outcome = pending.then(value => ({ value }), error => ({ error }));
    try {
      await bounded(entered, 'composed inference started');
      const resetDuringInference = await bounded(history.reset({ ownerId: composingOwner.id,
        sessionId: composingSession.id, generation: 0,
        resetRequestId: '10000000-0000-4000-8000-000000000041' }), 'reset while inference paused');
      assert.equal(resetDuringInference.toGeneration, '1');
      assert.equal(resetDuringInference.removedCount, 0);
    } finally {
      releaseInference();
    }
    assert.equal((await bounded(outcome, 'stale composed append rejected')).error?.code, '55000');
    assert.deepEqual(await history.listOwn({ ownerId: composingOwner.id, sessionId: composingSession.id }), []);

    // Current identity finalization preserves an inactive tombstone for durable
    // receipts. It therefore cannot be claimed as a private-history cleanup.
    await history.append({ ownerId: finalizerOnlyOwner.id, sessionId: finalizerOnlySession.id, generation: 0,
      requestId: '10000000-0000-4000-8000-000000000010', sourceRoute: 'prompt_injection',
      prompt: 'finalizer must not cascade', response: 'finalizer must not cascade', modelUsed: 'fixture-model' });
    const finalizerJob = '10000000-0000-4000-8000-000000000011';
    const finalizerLease = '10000000-0000-4000-8000-000000000012';
    await migration.query(`INSERT INTO identity.student_deletion_jobs
      (job_id,subject_user_id,requested_by,state,lease_token,lease_expires_at)
      VALUES($1,$2,$3,'running',$4,clock_timestamp()+interval '1 hour')`,
    [finalizerJob, finalizerOnlyOwner.id, deletionAdmin.id, finalizerLease]);
    await migration.query(`INSERT INTO identity.student_deletion_steps(job_id,step_key,ordinal,state,completed_at) VALUES
      ($1,'revoke_runs',0,'completed',clock_timestamp()),($1,'identity',1,'pending',NULL)`, [finalizerJob]);
    await migration.query('UPDATE identity.users SET is_active=0 WHERE id=$1', [finalizerOnlyOwner.id]);
    assert.equal((await runtime.query('SELECT identity.finalize_student_deletion($1::uuid,$2::uuid,$3::integer) AS finalized',
      [finalizerJob, finalizerLease, finalizerOnlyOwner.id])).rows[0].finalized, true);
    assert.equal((await migration.query('SELECT count(*)::integer AS n FROM legacy_ai_private.history WHERE owner_id=$1',
      [finalizerOnlyOwner.id])).rows[0].n, 1, 'finalizer tombstone alone leaves private history for the future cleanup step');
    await qualifyLegacyAiHistoryHttp({ identities, history, migration });
  } finally {
    if (held) {
      await held.query('ROLLBACK').catch(() => {});
      held.release();
    }
    await Promise.allSettled([runtime.end(), migration.end()]);
  }
});
