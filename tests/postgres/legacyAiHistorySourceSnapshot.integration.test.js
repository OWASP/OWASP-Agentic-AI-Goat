'use strict';

// Native-only qualification for the detached legacy AI history snapshot.
// A reviewed launcher must supply one fresh disposable legacy_challenge
// database with the exact migration and runtime roles. This test does not
// create resources, read application configuration, or activate a cutover.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');
const {
  EXPECTED_MIGRATIONS,
  createLegacyAiHistorySourceSnapshot,
} = require('../../server/database/postgres/legacyAiHistorySourceSnapshot');

const PREFIX = 'PG_LEGACY_AI_HISTORY_SOURCE_';
const KEYS = ['MIGRATION_URL', 'RUNTIME_URL'];
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && KEYS.every(key => typeof process.env[PREFIX + key] === 'string'
    && process.env[PREFIX + key].length > 0);
const ROOT = path.resolve(__dirname, '../..');
const BATCH = '71000000-0000-4000-8000-000000000001';
const SOURCE_IDENTITY = 'legacy-challenge://owned-disposable/source-snapshot';

function disposableUrl(key, role) {
  const value = new URL(process.env[PREFIX + key]);
  assert.ok(['postgres:', 'postgresql:'].includes(value.protocol));
  assert.ok(['127.0.0.1', 'localhost', '[::1]'].includes(value.hostname),
    'disposable PostgreSQL must be loopback');
  assert.match(value.pathname, /^\/owasp_ai_goat_test_[a-z0-9_]+$/,
    'owned disposable database name required');
  assert.equal(decodeURIComponent(value.username), role, `${key} role differs`);
  assert.equal(value.search, '');
  assert.equal(value.hash, '');
  return value;
}

function bounded(promise, description, timeoutMs = 10_000) {
  let timer;
  return Promise.race([
    promise,
    new Promise((resolve, reject) => {
      timer = setTimeout(() => reject(new Error(`Timed out waiting for ${description}`)), timeoutMs);
    }),
  ]).finally(() => clearTimeout(timer));
}

function pauseAfterMeasurement(pool) {
  let observedResolve;
  let observedReject;
  let releaseResolve;
  const observed = new Promise((resolve, reject) => {
    observedResolve = resolve;
    observedReject = reject;
  });
  const released = new Promise(resolve => { releaseResolve = resolve; });
  let paused = false;
  return Object.freeze({
    pool: Object.freeze({
      async connect() {
        const client = await pool.connect();
        return Object.freeze({
          async query(...args) {
            try {
              const result = await client.query(...args);
              const sql = typeof args[0] === 'string' ? args[0] : args[0]?.text;
              if (!paused && /count\(\*\)::text AS row_count/.test(sql || '')) {
                paused = true;
                observedResolve();
                await released;
              }
              return result;
            } catch (error) {
              if (!paused) observedReject(error);
              throw error;
            }
          },
          release(error) { client.release(error); },
        });
      },
    }),
    wait() { return bounded(observed, 'snapshot measurement'); },
    release() { releaseResolve(); },
  });
}

async function sourceState(pool) {
  const [rows, sequence, ledger] = await Promise.all([
    pool.query(`SELECT id::text,user_id::text,prompt,response,model_used,
      created_at::text,platform_owner_id::text,xmin::text
      FROM legacy_challenge.ai_conversations ORDER BY id`),
    pool.query(`SELECT last_value::text,is_called
      FROM legacy_challenge.ai_conversations_id_seq`),
    pool.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name'),
  ]);
  return { rows: rows.rows, sequence: sequence.rows, ledger: ledger.rows };
}

test('native detached source snapshot is lossless, read-only and transactionally consistent', {
  skip: !enabled,
  timeout: 30_000,
}, async () => {
  const migrationUrl = disposableUrl('MIGRATION_URL', 'dvaia_legacy_challenge_migration');
  const runtimeUrl = disposableUrl('RUNTIME_URL', 'dvaia_legacy_challenge_runtime');
  assert.equal(runtimeUrl.host, migrationUrl.host,
    'runtime and migration roles must target the same loopback host and port');
  assert.equal(runtimeUrl.pathname, migrationUrl.pathname,
    'runtime and migration roles must target the same owned database');
  const database = decodeURIComponent(migrationUrl.pathname.slice(1));
  const migration = new Pool({ connectionString: migrationUrl.href, max: 4 });
  const runtime = new Pool({ connectionString: runtimeUrl.href, max: 1 });
  try {
    assert.equal((await migration.query(
      "SELECT to_regnamespace('legacy_challenge') AS schema")).rows[0].schema, null,
    'test requires a fresh disposable legacy store');
    assert.deepEqual(await migrate(migration,
      path.join(ROOT, 'db/postgres/workshop-migrations/legacy_challenge')),
    EXPECTED_MIGRATIONS.map(row => row.name));
    assert.deepEqual((await migration.query(
      'SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows,
    EXPECTED_MIGRATIONS.map(row => ({ ...row })),
    'native fixture must have the exact reviewed legacy ledger');

    await migration.query(`INSERT INTO legacy_challenge.ai_conversations
      (id,user_id,prompt,response,model_used,created_at,platform_owner_id) VALUES
      (-2147483648,2147483647,$1,NULL,NULL,'-infinity',NULL),
      (-1,-2147483648,$2,$3,$4,'2026-09-17 05:34:05.123456+02:30',73),
      (0,NULL,$5,NULL,NULL,'infinity',NULL),
      (41,NULL,$6,NULL,NULL,NULL,NULL),
      (2147483647,-1,$7,$8,'historic-model','0044-03-15 00:00:00.654321 BC',91)`, [
      'signed boundary \u2603',
      'Unicode \ud83e\uddea e\u0301 \u4f8b',
      '',
      'fixture-model',
      'positive infinity',
      'null timestamp',
      'BC timestamp',
      'historic response',
    ]);

    const expectedRows = [
      { id: -2147483648, userId: 2147483647, prompt: 'signed boundary \u2603',
        response: null, modelUsed: null, createdAt: '-infinity', platformOwnerId: null },
      { id: -1, userId: -2147483648, prompt: 'Unicode \ud83e\uddea e\u0301 \u4f8b', response: '',
        modelUsed: 'fixture-model', createdAt: '2026-09-17T03:04:05.123456Z', platformOwnerId: 73 },
      { id: 0, userId: null, prompt: 'positive infinity', response: null,
        modelUsed: null, createdAt: 'infinity', platformOwnerId: null },
      { id: 41, userId: null, prompt: 'null timestamp', response: null,
        modelUsed: null, createdAt: null, platformOwnerId: null },
      { id: 2147483647, userId: -1, prompt: 'BC timestamp', response: 'historic response',
        modelUsed: 'historic-model', createdAt: '0044-03-15 00:00:00.654321 BC', platformOwnerId: 91 },
    ];
    const options = { batchId: BATCH, database, sourceStoreIdentity: SOURCE_IDENTITY };
    const before = await sourceState(migration);
    const first = await createLegacyAiHistorySourceSnapshot(migration, options).readSnapshot();
    assert.deepEqual(first, { batchId: BATCH, sourceStoreIdentity: SOURCE_IDENTITY,
      rows: expectedRows });
    assert.ok(Object.isFrozen(first) && Object.isFrozen(first.rows));
    assert.ok(first.rows.every(Object.isFrozen));
    assert.deepEqual(await sourceState(migration), before,
      'snapshot must not change rows, row versions, sequence state, or ledger');

    await assert.rejects(
      createLegacyAiHistorySourceSnapshot(runtime, options).readSnapshot(),
      error => error?.code === 'LEGACY_AI_SOURCE_SNAPSHOT_UNAVAILABLE',
      'runtime role must not satisfy migration authority');
    assert.deepEqual(await sourceState(migration), before,
      'wrong-role denial must not change the source');

    const firstMigration = EXPECTED_MIGRATIONS[0];
    await migration.query('UPDATE dvaia_migrations.ledger SET checksum=$2 WHERE name=$1',
      [firstMigration.name, '0'.repeat(64)]);
    try {
      await assert.rejects(
        createLegacyAiHistorySourceSnapshot(migration, options).readSnapshot(),
        error => error?.code === 'LEGACY_AI_SOURCE_SNAPSHOT_UNAVAILABLE',
        'altered canonical ledger must be denied');
    } finally {
      await migration.query('UPDATE dvaia_migrations.ledger SET checksum=$2 WHERE name=$1',
        [firstMigration.name, firstMigration.checksum]);
    }
    assert.deepEqual(await sourceState(migration), before,
      'ledger denial fixture must restore the exact source and ledger');

    const paused = pauseAfterMeasurement(migration);
    const pending = createLegacyAiHistorySourceSnapshot(paused.pool, options).readSnapshot();
    const pendingOutcome = pending.then(
      value => ({ status: 'fulfilled', value }),
      error => ({ status: 'rejected', error }),
    );
    let concurrencyError;
    try {
      await paused.wait();
      const writer = await migration.connect();
      try {
        await writer.query('BEGIN');
        await writer.query(`UPDATE legacy_challenge.ai_conversations
          SET prompt='committed after snapshot measurement' WHERE id=-1`);
        await writer.query(`INSERT INTO legacy_challenge.ai_conversations
          (id,user_id,prompt,response,model_used,created_at,platform_owner_id)
          VALUES(42,NULL,'committed concurrent row',NULL,NULL,'2026-09-17 03:04:06.000001+00',NULL)`);
        await writer.query('COMMIT');
      } catch (error) {
        await writer.query('ROLLBACK').catch(() => {});
        throw error;
      } finally {
        writer.release();
      }
    } catch (error) {
      concurrencyError = error;
    } finally {
      paused.release();
    }
    if (concurrencyError) {
      await bounded(pendingOutcome, 'failed snapshot cleanup').catch(() => {});
      throw concurrencyError;
    }
    const outcome = await bounded(pendingOutcome, 'repeatable-read source snapshot');
    if (outcome.status === 'rejected') throw outcome.error;
    const consistent = outcome.value;
    assert.deepEqual(consistent.rows, expectedRows,
      'one snapshot must retain its pre-commit count, values and timestamp bytes');
    const current = await migration.query(`SELECT id,prompt FROM legacy_challenge.ai_conversations
      WHERE id IN(-1,42) ORDER BY id`);
    assert.deepEqual(current.rows, [
      { id: -1, prompt: 'committed after snapshot measurement' },
      { id: 42, prompt: 'committed concurrent row' },
    ], 'the independent committed writer must become visible after the snapshot');
  } finally {
    await Promise.all([migration.end(), runtime.end()]);
  }
});
