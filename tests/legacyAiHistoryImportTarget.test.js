'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createLegacyAiHistoryImportTarget } = require(
  '../server/database/postgres/legacyAiHistoryImportTarget');

const BATCH = '10000000-0000-4000-8000-000000000001';
const REQUEST = '10000000-0000-4000-8000-000000000002';
const HASH_A = 'a'.repeat(64);
const HASH_B = 'b'.repeat(64);
const HASH_C = 'c'.repeat(64);
const SOURCE = Object.freeze({ id: -1, userId: -9, prompt: 'exact prompt', response: null,
  modelUsed: null, createdAt: 'infinity', platformOwnerId: 0 });
const SOURCE_BC = Object.freeze({ id: 0, userId: null, prompt: 'BC prompt', response: null,
  modelUsed: null, createdAt: '0044-03-15 00:00:00+00 BC', platformOwnerId: null });
const SOURCE_NULL = Object.freeze({ id: -2147483648, userId: 2147483647, prompt: 'null timestamp',
  response: null, modelUsed: null, createdAt: null, platformOwnerId: -2147483648 });
const PROMOTED = Object.freeze({ prompt: 'exact prompt', response: 'exact response',
  modelUsed: 'fixture-model', createdAt: '2026-09-15T03:04:05.123456Z' });

const FUNCTIONS = Object.freeze([
  Object.freeze({ signature: 'legacy_ai_private.begin_history_import(uuid,text,integer,text)',
    name: 'begin_history_import', arguments: 'uuid, text, integer, text' }),
  Object.freeze({ signature: 'legacy_ai_private.archive_history_import_row(uuid,bigint,jsonb,text,text,integer)',
    name: 'archive_history_import_row', arguments: 'uuid, bigint, jsonb, text, text, integer' }),
  Object.freeze({ signature: 'legacy_ai_private.promote_owned_history_import_row(uuid,bigint,integer,uuid,text,text,text,text,timestamp with time zone,text)',
    name: 'promote_owned_history_import_row',
    arguments: 'uuid, bigint, integer, uuid, text, text, text, text, timestamp with time zone, text' }),
  Object.freeze({ signature: 'legacy_ai_private.verify_history_import_quarantine(uuid,integer,text)',
    name: 'verify_history_import_quarantine', arguments: 'uuid, integer, text' }),
]);

function identity(overrides = {}) {
  return { current_role: 'dvaia_identity_migration', session_role: 'dvaia_identity_migration',
    database: 'owned', rolsuper: false, rolcreaterole: false, rolcreatedb: false,
    rolreplication: false, rolbypassrls: false, ...overrides };
}

function catalog(overrides = {}) {
  return FUNCTIONS.map(item => ({ signature: item.signature, schema_name: 'legacy_ai_private',
    function_name: item.name, identity_arguments: item.arguments,
    function_owner: 'dvaia_identity_migration', schema_owner: 'dvaia_identity_migration',
    migration_execute: true, runtime_execute: false, public_execute: false,
    public_schema_privilege: false, ...overrides }));
}

function fixturePool({ identityRow = identity(), catalogRows = catalog(), operation } = {}) {
  const clients = [];
  let nextId = 0;
  return {
    clients,
    async connect() {
      const client = { id: ++nextId, queries: [], released: false, releaseError: undefined };
      clients.push(client);
      client.query = async (sql, args) => {
        client.queries.push({ sql, args });
        if (sql === 'BEGIN' || sql === 'COMMIT' || sql === 'ROLLBACK') return { rows: [], rowCount: 0 };
        if (sql.includes('FROM pg_roles')) return { rows: [identityRow], rowCount: 1 };
        if (sql.includes('WITH expected(signature)')) {
          assert.deepEqual(args[0], FUNCTIONS.map(item => item.signature));
          assert.equal(args[1], 'dvaia_identity_runtime');
          return { rows: catalogRows, rowCount: catalogRows.length };
        }
        if (!operation) throw new Error('Unexpected target operation');
        return operation(sql, args, client);
      };
      client.release = error => { client.released = true; client.releaseError = error; };
      return client;
    },
  };
}

function beginInput() {
  return { batchId: BATCH, sourceStoreIdentity: 'legacy://owned/snapshot', expectedCount: 1,
    aggregateDigest: HASH_A };
}
function archiveInput() {
  return { batchId: BATCH, sourceRowId: -1, sourceRecord: { ...SOURCE }, sourceDigest: HASH_B,
    classification: 'owned', ownerId: 73 };
}
function promoteInput() {
  return { batchId: BATCH, sourceRowId: -1, sourceDigest: HASH_B, ownerId: 73,
    requestId: REQUEST, sourceRoute: 'prompt_injection', prompt: SOURCE.prompt,
    response: PROMOTED.response, modelUsed: PROMOTED.modelUsed, createdAt: PROMOTED.createdAt,
    historyDigest: HASH_C };
}

test('constructor fixes the migration role and expected database', () => {
  const pool = { connect() {} };
  assert.throws(() => createLegacyAiHistoryImportTarget(pool, { database: 'owned', role: 'caller-role' }),
    /Exact target option fields/);
  assert.throws(() => createLegacyAiHistoryImportTarget(pool, {}), /Exact target option fields/);
  assert.throws(() => createLegacyAiHistoryImportTarget({ query() {} }, { database: 'owned' }),
    /Injected migration pool/);
});

test('identity or database mismatch fails on the leased client before an operation', async () => {
  let operations = 0;
  const pool = fixturePool({ identityRow: identity({ current_role: 'caller-role' }),
    operation: async () => { operations += 1; return { rows: [] }; } });
  const target = createLegacyAiHistoryImportTarget(pool, { database: 'owned' });
  await assert.rejects(target.begin(beginInput()), /migration authority/);
  assert.equal(operations, 0);
  assert.deepEqual(pool.clients[0].queries.map(item => item.sql), [
    'BEGIN', pool.clients[0].queries[1].sql, 'ROLLBACK',
  ]);
  assert.equal(pool.clients[0].released, true);
});

test('wrong database with valid migration role fails before an import operation', async () => {
  let operations = 0;
  const pool = fixturePool({ identityRow: identity({ database: 'other-owned' }),
    operation: async () => { operations += 1; return { rows: [] }; } });
  const target = createLegacyAiHistoryImportTarget(pool, { database: 'owned' });
  await assert.rejects(target.begin(beginInput()), /migration authority/);
  assert.equal(operations, 0);
  assert.equal(pool.clients.length, 1);
  const client = pool.clients[0];
  assert.equal(client.queries.length, 3);
  assert.equal(client.queries[0].sql, 'BEGIN');
  assert.match(client.queries[1].sql, /current_database\(\)/);
  assert.equal(client.queries[2].sql, 'ROLLBACK');
  assert.equal(client.released, true);
});

test('exact schema/function ownership, signatures and effective ACLs gate every operation', async t => {
  const cases = [
    ['function owner', rows => rows.map((row, index) => index ? row : { ...row, function_owner: 'other' })],
    ['schema owner', rows => rows.map((row, index) => index ? row : { ...row, schema_owner: 'other' })],
    ['identity arguments', rows => rows.map((row, index) => index ? row : { ...row,
      identity_arguments: `${row.identity_arguments}, text` })],
    ['runtime execute', rows => rows.map((row, index) => index ? row : { ...row, runtime_execute: true })],
    ['PUBLIC execute', rows => rows.map((row, index) => index ? row : { ...row, public_execute: true })],
    ['PUBLIC schema privilege', rows => rows.map((row, index) => index ? row : { ...row,
      public_schema_privilege: true })],
    ['missing function', rows => rows.slice(1)],
  ];
  for (const [name, mutate] of cases) await t.test(name, async () => {
    let operations = 0;
    const pool = fixturePool({ catalogRows: mutate(catalog()),
      operation: async () => { operations += 1; return { rows: [] }; } });
    const target = createLegacyAiHistoryImportTarget(pool, { database: 'owned' });
    await assert.rejects(target.begin(beginInput()), /function (ownership and ACL|inventory)/);
    assert.equal(operations, 0);
    assert.equal(pool.clients[0].queries.at(-1).sql, 'ROLLBACK');
    assert.equal(pool.clients[0].released, true);
  });
});

test('all fixed operations validate and return immutable typed projections on their leased client', async () => {
  const archivedDatabaseRows = [{ source_row_id: '-2147483648', source_digest: HASH_A,
    source_record: { ...SOURCE_NULL }, classification: 'unknown', classified_owner_id: null },
  { source_row_id: '-1', source_digest: HASH_B,
    source_record: { ...SOURCE }, classification: 'owned', classified_owner_id: 73 },
  { source_row_id: '0', source_digest: HASH_C, source_record: { ...SOURCE_BC },
    classification: 'unknown', classified_owner_id: null }];
  const operation = async (sql, args) => {
    if (sql.includes('begin_history_import')) return { rows: [{ batch_id: BATCH, state: 'copying',
      expected_count: 1, aggregate_digest: HASH_A, replayed: false }] };
    if (sql.includes('archive_history_import_row')) return { rows: [{ batch_id: BATCH,
      source_row_id: '-1', source_digest: HASH_B, replayed: false }] };
    if (sql.includes('promote_owned_history_import_row')) return { rows: [{ request_id: REQUEST,
      owner_id: 73, source_row_id: '-1', replayed: false }] };
    if (sql.includes('verify_history_import_quarantine')) return { rows: [{ batch_id: BATCH,
      verified_at: new Date('2026-09-15T03:05:00.000Z'), source_removal_receipt: HASH_A }] };
    if (sql.includes('FROM legacy_ai_private.import_archive')) return { rows: archivedDatabaseRows };
    if (sql.includes('FROM legacy_ai_private.import_history_receipts')) return { rows: [{ owner_id: 73,
      request_id: REQUEST, source_route: 'prompt_injection', source_digest: HASH_B,
      history_digest: HASH_C, prompt: PROMOTED.prompt, response: PROMOTED.response,
      model_used: PROMOTED.modelUsed, created_at: PROMOTED.createdAt }] };
    throw new Error(`Unexpected SQL: ${sql}`);
  };
  const pool = fixturePool({ operation });
  const target = createLegacyAiHistoryImportTarget(pool, { database: 'owned' });
  const values = [
    await target.begin(beginInput()),
    await target.archive(archiveInput()),
    await target.promote(promoteInput()),
    await target.verify({ batchId: BATCH, expectedCount: 1, aggregateDigest: HASH_A, replayOnly: false }),
    await target.readArchived({ batchId: BATCH }),
    await target.readPromoted({ batchId: BATCH, sourceRowId: -1 }),
  ];
  assert.deepEqual(values[0], { batchId: BATCH, state: 'copying', expectedCount: 1,
    aggregateDigest: HASH_A, replayed: false });
  assert.deepEqual(values[1], { batchId: BATCH, sourceRowId: -1, sourceDigest: HASH_B, replayed: false });
  assert.deepEqual(values[2], { requestId: REQUEST, ownerId: 73, sourceRowId: -1, replayed: false });
  assert.deepEqual(values[3], { batchId: BATCH, verifiedAt: '2026-09-15T03:05:00.000Z',
    sourceRemovalReceipt: HASH_A });
  assert.deepEqual(values[4], [{ sourceRowId: -2147483648, sourceDigest: HASH_A, sourceRecord: SOURCE_NULL,
    classification: 'unknown', ownerId: null },
  { sourceRowId: -1, sourceDigest: HASH_B, sourceRecord: SOURCE,
    classification: 'owned', ownerId: 73 },
  { sourceRowId: 0, sourceDigest: HASH_C, sourceRecord: SOURCE_BC,
    classification: 'unknown', ownerId: null }]);
  assert.deepEqual(values[5], { ownerId: 73, requestId: REQUEST, sourceRoute: 'prompt_injection',
    sourceDigest: HASH_B, historyDigest: HASH_C, prompt: PROMOTED.prompt, response: PROMOTED.response,
    modelUsed: PROMOTED.modelUsed, createdAt: PROMOTED.createdAt });
  for (const value of values) assert.ok(Object.isFrozen(value));
  assert.ok(Object.isFrozen(values[4][0]) && Object.isFrozen(values[4][0].sourceRecord));
  assert.throws(() => { values[4][0].sourceRecord.prompt = 'mutated'; }, TypeError);
  archivedDatabaseRows[1].source_record.prompt = 'pool row changed later';
  assert.equal(values[4][1].sourceRecord.prompt, SOURCE.prompt);
  assert.equal(pool.clients.length, 6);
  for (const client of pool.clients) {
    assert.equal(client.queries[0].sql, 'BEGIN');
    assert.match(client.queries[1].sql, /FROM pg_roles/);
    assert.match(client.queries[2].sql, /WITH expected\(signature\)/);
    assert.equal(client.queries.at(-1).sql, 'COMMIT');
    assert.equal(client.released, true);
  }
  assert.equal(target.query, undefined);
});

test('invalid input is rejected before leasing and mutable/malformed readback fails closed', async () => {
  const unused = fixturePool();
  const target = createLegacyAiHistoryImportTarget(unused, { database: 'owned' });
  assert.throws(() => target.archive({ ...archiveInput(), sourceRecord: { ...SOURCE, injected: true } }),
    /Exact archived source record fields/);
  assert.throws(() => target.archive({ ...archiveInput(), sourceRecord: { ...SOURCE, userId: '-9' } }),
    /raw legacy user ID/);
  for (const field of ['userId', 'response', 'modelUsed', 'createdAt', 'platformOwnerId']) {
    assert.throws(() => target.archive({ ...archiveInput(), sourceRecord: { ...SOURCE, [field]: undefined } }),
      /required|raw|source/);
  }
  assert.throws(() => target.archive({ ...archiveInput(), ownerId: undefined }),
    /classified owner/);
  assert.throws(() => target.archive({ ...archiveInput(), classification: 'unknown' }),
    /Consistent source classification/);
  assert.throws(() => target.promote({ ...promoteInput(), requestId: BATCH.replace('0001', 'not-valid') }),
    /history request ID/);
  assert.equal(unused.clients.length, 0);

  const pool = fixturePool({ operation: async sql => {
    if (sql.includes('FROM legacy_ai_private.import_archive')) return { rows: [{ source_row_id: '1',
      source_digest: HASH_B, source_record: { ...SOURCE, prompt: 9 }, classification: 'owned',
      classified_owner_id: 73 }] };
    throw new Error('Unexpected operation');
  } });
  await assert.rejects(createLegacyAiHistoryImportTarget(pool, { database: 'owned' })
    .readArchived({ batchId: BATCH }), /source prompt/);
  assert.equal(pool.clients[0].queries.at(-1).sql, 'ROLLBACK');
  assert.equal(pool.clients[0].released, true);
});

test('operation receipts and archived source identity must match the exact request', async t => {
  const cases = [
    ['begin', target => target.begin(beginInput()), sql => sql.includes('begin_history_import'),
      { batch_id: REQUEST, state: 'copying', expected_count: 1, aggregate_digest: HASH_A, replayed: false }],
    ['archive', target => target.archive(archiveInput()), sql => sql.includes('archive_history_import_row'),
      { batch_id: BATCH, source_row_id: '-1', source_digest: HASH_C, replayed: false }],
    ['promote', target => target.promote(promoteInput()), sql => sql.includes('promote_owned_history_import_row'),
      { request_id: REQUEST, owner_id: 74, source_row_id: '-1', replayed: false }],
    ['verify', target => target.verify({ batchId: BATCH, expectedCount: 1, aggregateDigest: HASH_A }),
      sql => sql.includes('verify_history_import_quarantine'),
      { batch_id: BATCH, verified_at: new Date(), source_removal_receipt: HASH_B }],
  ];
  for (const [name, invoke, matches, returned] of cases) await t.test(name, async () => {
    const pool = fixturePool({ operation: async sql => {
      if (!matches(sql)) throw new Error('Unexpected operation');
      return { rows: [returned] };
    } });
    await assert.rejects(invoke(createLegacyAiHistoryImportTarget(pool, { database: 'owned' })), /differs/);
    assert.equal(pool.clients[0].queries.at(-1).sql, 'ROLLBACK');
    assert.equal(pool.clients[0].released, true);
  });

  const pool = fixturePool({ operation: async sql => {
    if (!sql.includes('FROM legacy_ai_private.import_archive')) throw new Error('Unexpected operation');
    return { rows: [{ source_row_id: '-1', source_digest: HASH_B,
      source_record: { ...SOURCE, id: 0 }, classification: 'owned', classified_owner_id: 73 }] };
  } });
  await assert.rejects(createLegacyAiHistoryImportTarget(pool, { database: 'owned' })
    .readArchived({ batchId: BATCH }), /source identity differs/);
  assert.equal(pool.clients[0].queries.at(-1).sql, 'ROLLBACK');
});

test('operation failure rolls back and releases the same leased client', async () => {
  const failure = Object.assign(new Error('target write failed'), { code: '55000' });
  const pool = fixturePool({ operation: async () => { throw failure; } });
  const target = createLegacyAiHistoryImportTarget(pool, { database: 'owned' });
  await assert.rejects(target.begin(beginInput()), error => error === failure);
  const client = pool.clients[0];
  assert.equal(client.queries.at(-1).sql, 'ROLLBACK');
  assert.equal(client.queries.some(item => item.sql === 'COMMIT'), false);
  assert.equal(client.released, true);
});
