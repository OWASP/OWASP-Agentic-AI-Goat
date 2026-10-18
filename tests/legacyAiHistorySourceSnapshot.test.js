'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const {
  EXPECTED_MIGRATIONS,
  EXPECTED_ROLE,
  MAX_PAYLOAD_BYTES,
  MAX_ROWS,
  createLegacyAiHistorySourceSnapshot,
} = require('../server/database/postgres/legacyAiHistorySourceSnapshot');

const BATCH = '10000000-0000-4000-8000-000000000041';
const OPTIONS = Object.freeze({ batchId: BATCH.toUpperCase(), database: 'legacy_owned',
  sourceStoreIdentity: 'legacy://reviewed-installation/legacy-challenge' });
const SOURCE_ROWS = [
  { id: '-2147483648', user_id: '2147483647', prompt: 'signed boundary', response: null,
    model_used: null, created_at: '-infinity', platform_owner_id: null },
  { id: '-1', user_id: '-9', prompt: 'exact \u2603 prompt', response: 'exact response',
    model_used: 'fixture-model', created_at: '2026-09-17T03:04:05.123456Z', platform_owner_id: '73' },
  { id: '0', user_id: null, prompt: 'BC timestamp', response: null,
    model_used: null, created_at: '0044-03-15 00:00:00.123456 BC', platform_owner_id: null },
];

function projected(row) {
  const integer = value => value === null ? null : Number(value);
  return { id: integer(row.id), userId: integer(row.user_id), prompt: row.prompt,
    response: row.response, modelUsed: row.model_used, createdAt: row.created_at,
    platformOwnerId: integer(row.platform_owner_id) };
}
function payloadBytes(row) {
  const value = projected(row);
  let bytes = 64 + Buffer.byteLength(String(value.id));
  for (const item of [value.userId,value.prompt,value.response,value.modelUsed,
    value.createdAt,value.platformOwnerId]) if (item !== null) bytes += Buffer.byteLength(String(item));
  return bytes;
}
function identity(overrides = {}) {
  return { database: OPTIONS.database, role: EXPECTED_ROLE, session_role: EXPECTED_ROLE,
    current_role: EXPECTED_ROLE, rolsuper: false, rolcreaterole: false, rolcreatedb: false,
    rolreplication: false, rolbypassrls: false, runtime_member: false, ...overrides };
}

function fixture({ identityRow = identity(), ledgerRows = EXPECTED_MIGRATIONS.map(row => ({ ...row })),
  measured, rows = SOURCE_ROWS, failRows } = {}) {
  const clients = [];
  const expectedBytes = rows.reduce((total, row) => total + payloadBytes(row), 0);
  const measurement = measured || { row_count: String(rows.length), payload_bytes: String(expectedBytes) };
  return {
    clients,
    async connect() {
      const client = { queries: [], released: false, releaseError: undefined };
      clients.push(client);
      client.query = async sql => {
        client.queries.push(sql);
        if (sql === 'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY'
            || sql === 'COMMIT' || sql === 'ROLLBACK') return { rows: [], rowCount: 0 };
        if (sql.includes('FROM pg_roles')) return { rows: [identityRow], rowCount: 1 };
        if (sql.includes('FROM dvaia_migrations.ledger')) return { rows: ledgerRows, rowCount: ledgerRows.length };
        if (sql.includes('count(*)::text AS row_count')) return { rows: [measurement], rowCount: 1 };
        if (sql.includes('FROM legacy_challenge.ai_conversations ORDER BY id')) {
          if (failRows) throw failRows;
          return { rows, rowCount: rows.length };
        }
        throw new Error(`Unexpected query: ${sql}`);
      };
      client.release = error => { client.released = true; client.releaseError = error; };
      return client;
    },
  };
}

test('requires fixed operator identifiers before leasing a connection', () => {
  const pool = fixture();
  for (const options of [
    {},
    { ...OPTIONS, batchId: 'not-a-uuid' },
    { ...OPTIONS, database: 'line\nbreak' },
    { ...OPTIONS, sourceStoreIdentity: '' },
    { ...OPTIONS, extra: true },
  ]) assert.throws(() => createLegacyAiHistorySourceSnapshot(pool, options), /required|Exact|Valid/);
  assert.throws(() => createLegacyAiHistorySourceSnapshot({ query() {} }, OPTIONS), /migration pool/);
  assert.equal(pool.clients.length, 0);
});

test('operator identifiers are read once before any asynchronous work', async () => {
  const reads = { batchId: 0, database: 0, sourceStoreIdentity: 0 };
  const options = {};
  for (const [key, value] of Object.entries(OPTIONS)) Object.defineProperty(options, key, {
    enumerable: true,
    get() {
      reads[key] += 1;
      return reads[key] === 1 ? value : `${value}-changed`;
    },
  });
  const snapshot = await createLegacyAiHistorySourceSnapshot(fixture(), options).readSnapshot();
  assert.deepEqual(reads, { batchId: 1, database: 1, sourceStoreIdentity: 1 });
  assert.equal(snapshot.batchId, BATCH);
  assert.equal(snapshot.sourceStoreIdentity, OPTIONS.sourceStoreIdentity);
});

test('returns the exact lossless source domain as a detached frozen snapshot', async () => {
  const databaseRows = SOURCE_ROWS.map(row => ({ ...row }));
  const pool = fixture({ rows: databaseRows });
  const capability = createLegacyAiHistorySourceSnapshot(pool, OPTIONS);
  const snapshot = await capability.readSnapshot();
  assert.deepEqual(snapshot, {
    batchId: BATCH,
    sourceStoreIdentity: OPTIONS.sourceStoreIdentity,
    rows: SOURCE_ROWS.map(projected),
  });
  assert.ok(Object.isFrozen(capability));
  assert.ok(Object.isFrozen(snapshot) && Object.isFrozen(snapshot.rows));
  assert.ok(snapshot.rows.every(Object.isFrozen));
  assert.throws(() => { snapshot.rows[1].prompt = 'changed'; }, TypeError);
  databaseRows[1].prompt = 'pool changed later';
  assert.equal(snapshot.rows[1].prompt, 'exact \u2603 prompt');

  const queries = pool.clients[0].queries;
  assert.equal(queries[0], 'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
  assert.match(queries[1], /current_database\(\).*session_user.*current_role/s);
  assert.equal(queries[2], 'SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name');
  assert.match(queries[3], /count\(\*\)::text AS row_count/);
  assert.match(queries[4], /ORDER BY id/);
  assert.match(queries[4], /YYYY-MM-DD"T"HH24:MI:SS.US"Z"/);
  assert.equal(queries[5], 'COMMIT');
  assert.equal(pool.clients[0].released, true);
  assert.equal(pool.clients[0].releaseError, undefined);
  assert.equal(queries.some(sql => /\b(?:INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|GRANT|REVOKE|TRUNCATE)\b/i.test(sql)), false);
});

test('authority and the exact canonical ledger are checked in the snapshot transaction', async t => {
  const cases = [
    ['database', identity({ database: 'other' }), EXPECTED_MIGRATIONS],
    ['role', identity({ role: 'dvaia_legacy_challenge_runtime' }), EXPECTED_MIGRATIONS],
    ['session role', identity({ session_role: 'bootstrap' }), EXPECTED_MIGRATIONS],
    ['current role', identity({ current_role: 'bootstrap' }), EXPECTED_MIGRATIONS],
    ['superuser', identity({ rolsuper: true }), EXPECTED_MIGRATIONS],
    ['runtime membership', identity({ runtime_member: true }), EXPECTED_MIGRATIONS],
    ['missing migration', identity(), EXPECTED_MIGRATIONS.slice(0, -1)],
    ['changed migration', identity(), EXPECTED_MIGRATIONS.map((row, index) => index
      ? row : { ...row, checksum: '0'.repeat(64) })],
    ['additional migration', identity(), [...EXPECTED_MIGRATIONS,
      { name: '0006_unreviewed.sql', checksum: '1'.repeat(64) }]],
  ];
  for (const [name, identityRow, ledgerRows] of cases) await t.test(name, async () => {
    const pool = fixture({ identityRow, ledgerRows });
    await assert.rejects(createLegacyAiHistorySourceSnapshot(pool, OPTIONS).readSnapshot(),
      /authority is not ready|ledger differs/);
    assert.equal(pool.clients[0].queries.at(-1), 'ROLLBACK');
    assert.equal(pool.clients[0].queries.some(sql => sql.includes('count(*)::text')), false);
  });
});

test('explicit resource ceilings reject before source rows are materialized and never truncate', async t => {
  for (const measured of [
    { row_count: String(MAX_ROWS + 1), payload_bytes: '0' },
    { row_count: '1', payload_bytes: String(MAX_PAYLOAD_BYTES + 1) },
    { row_count: 'not-an-integer', payload_bytes: '0' },
  ]) await t.test(JSON.stringify(measured), async () => {
    const pool = fixture({ measured });
    await assert.rejects(createLegacyAiHistorySourceSnapshot(pool, OPTIONS).readSnapshot(),
      /exceeds|Invalid/);
    assert.equal(pool.clients[0].queries.some(sql => sql.includes('ORDER BY id')), false);
    assert.equal(pool.clients[0].queries.at(-1), 'ROLLBACK');
  });
});

test('malformed or changed readback fails closed without returning a partial snapshot', async t => {
  const cases = [
    ['row count', { rows: SOURCE_ROWS.slice(1), measured: {
      row_count: String(SOURCE_ROWS.length), payload_bytes: String(SOURCE_ROWS.reduce((n,row)=>n+payloadBytes(row),0)) } }],
    ['duplicate ID', { rows: [SOURCE_ROWS[0], { ...SOURCE_ROWS[1], id: SOURCE_ROWS[0].id }] }],
    ['invalid field', { rows: [{ ...SOURCE_ROWS[0], prompt: null }] }],
    ['byte difference', { rows: SOURCE_ROWS, measured: { row_count: String(SOURCE_ROWS.length), payload_bytes: '1' } }],
  ];
  for (const [name, setup] of cases) await t.test(name, async () => {
    const pool = fixture(setup);
    await assert.rejects(createLegacyAiHistorySourceSnapshot(pool, OPTIONS).readSnapshot(),
      /row count changed|Duplicate|Invalid prompt|byte measurement differs/);
    assert.equal(pool.clients[0].queries.at(-1), 'ROLLBACK');
  });
});

test('query failures roll back and do not expose an alternate snapshot path', async () => {
  const fault = new Error('controlled source read failure');
  const pool = fixture({ failRows: fault });
  const capability = createLegacyAiHistorySourceSnapshot(pool, OPTIONS);
  await assert.rejects(capability.readSnapshot(), fault);
  assert.equal(pool.clients[0].queries.at(-1), 'ROLLBACK');
  assert.equal(capability.query, undefined);
  assert.equal(capability.remove, undefined);
  assert.equal(capability.attest, undefined);
});

// Pin the reviewed current source ledger independently of the mocked pool.
// A future migration must be explicitly reviewed before snapshots accept it.
test('source snapshot pins the complete registered legacy migration head through 0005', () => {
  const directory = path.join(__dirname, '../db/postgres/workshop-migrations/legacy_challenge');
  const files = fs.readdirSync(directory).filter(name => name.endsWith('.sql')).sort();
  assert.deepEqual(EXPECTED_MIGRATIONS.map(row => row.name), files);
  assert.equal(files.at(-1), '0005_private_history_boundary.sql');
  for (const migration of EXPECTED_MIGRATIONS) {
    assert.equal(migration.checksum, createHash('sha256')
      .update(fs.readFileSync(path.join(directory, migration.name))).digest('hex'));
  }
});
