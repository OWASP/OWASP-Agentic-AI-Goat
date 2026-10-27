'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const support = require('./adminStudentDeletionCtfSupport');
const { canonicalCtfJson, buildCtfLifecycleCommand } = require('../../server/services/ctfLifecycleCommands');
const { buildCtfProjectionResult } = require('../../server/services/ctfProjectionResults');
const { receiptFor } = require('../../server/services/ctfDeletionContract');
const sha = s => createHash('sha256').update(s).digest('hex');
const op = '11111111-1111-4111-8111-111111111111';
const jobId = '33333333-3333-4333-8333-333333333333';
const req = { headers: { authorization: 'Bearer controlled-unit-token' }, user: { id: 19 }, identitySession: { id: 21 } };
function example(owner = '19') {
  const operationId = owner === '19' ? op : '22222222-2222-4222-8222-222222222222';
  const participantId = owner === '19' ? '51' : '52';
  const command = buildCtfLifecycleCommand('register', { username: 'controlled-' + owner, email: null, teamName: null,
    teachingSessionToken: 'synthetic-teaching-token', clientIp: null, userAgent: null },
  { operationId, actorId: owner, occurredAt: '2026-01-01T00:00:00.000Z', scope: { ownerId: owner,
    ownerGeneration: '0', globalRevision: '0', participantId: null, stageId: null, stageRevision: null, progressId: null } });
  const { commandHash, ...content } = command;
  const receipt = buildCtfProjectionResult(command, owner === '19' ? '1' : '2', { admitted: true, reason: null,
    participantId, recovered: false, active: true, banned: false, registeredAt: '2026-01-01T00:00:00.000Z' });
  const row = { operation_id: operationId, kind: 'register', sequence: Number(receipt.value.sequence),
    actor_id: Number(owner), session_id: 21, command: content, canonical_command: canonicalCtfJson(content),
    command_hash: commandHash, canonical_result: receipt.canonicalResult, result_hash: receipt.resultHash, state: 'applied' };
  const mutable = Object.fromEntries(Object.keys(support.MUTABLE).map(key => [key, []]));
  mutable.participants = [{ row: { id: Number(participantId), user_id: Number(owner), is_active: 1 } }];
  mutable.events = [{ row: { id: Number(owner), participant_id: Number(participantId), event_type: 'new_participant' } }];
  mutable.sessions = [{ row: { id: Number(owner), participant_id: Number(participantId), session_token: 'synthetic-teaching-token' } }];
  return { registration: { ownerId: owner, sessionId: '21', participantId, operationId: null, recoveryReads: 0, mutationCalls: 1 },
    mutable, outbox: [{ row }], projections: [{ row: Object.fromEntries(['operation_id', 'kind', 'sequence',
      'command_hash', 'canonical_result', 'result_hash'].map(k => [k, row[k]])) }],
    binding: [{ row: { owner_id: Number(owner), participant_id: Number(participantId), owner_generation: 1,
      active: true, banned: false, applied_sequence: row.sequence, applied_operation_id: operationId, registered_at: 'unchanged' } }],
    reservations: [{ row: { operation_id: operationId, sequence: row.sequence, owner_id: Number(owner), state: 'applied', resolved_at: 'retained' } }],
    authority: [{ row: { scope_key: 'owner:' + owner, owner_generation: 1, lifecycle_state: 'ready',
      pending_operation_id: null, blocked_operation_id: null, banned: false, failure_code: null } }],
    deletionCommands: [], decisions: [], payload: [{ row: { id: 1, stage_id: 9, normalized_snippet: support.SHARED_TEXT,
      payload_hash: support.SHARED_HASH, first_winner_participant_id: 51 } }],
    identityPayload: [{ row: { memory_id: 'shared', kind: 'payload', normalized_payload: support.SHARED_TEXT } }] };
}
function deleted(before) {
  const after = structuredClone(before);
  const command = { version: 1, kind: 'student_delete', operationId: jobId, jobId, subjectId: '19', participantId: '51',
    generationBefore: '1', generationAfter: '2', globalRevision: '0', ownerRevision: '0',
    occurredAt: '2026-01-02T00:00:00.000Z', policyVersion: 'ctf-student-delete-v1' };
  const canonicalCommand = canonicalCtfJson(command), event = { command: JSON.parse(canonicalCommand), canonicalCommand, commandHash: sha(canonicalCommand), sequence: '3' };
  const receipt = receiptFor(event, Object.fromEntries(Object.keys(support.MUTABLE).map(k => [k, before.mutable[k].length])));
  const row = { operation_id: jobId, kind: 'student_delete', sequence: 3, command,
    canonical_command: canonicalCommand, command_hash: event.commandHash, state: 'applied',
    canonical_result: receipt.canonicalResult, result_hash: receipt.resultHash };
  after.outbox.push({ row }); after.projections.push({ row: Object.fromEntries(['operation_id', 'kind', 'sequence',
    'command_hash', 'canonical_result', 'result_hash'].map(k => [k, row[k]])) });
  after.deletionCommands = [{ row: { job_id: jobId, subject_id: 19, operation_id: jobId, sequence: 3 } }];
  for (const key of Object.keys(support.MUTABLE)) after.mutable[key] = [];
  Object.assign(after.binding[0].row, { active: false, banned: true, applied_sequence: 3, applied_operation_id: jobId });
  Object.assign(after.authority[0].row, { owner_generation: 2, lifecycle_state: 'blocked', pending_operation_id: null,
    blocked_operation_id: jobId, banned: true, failure_code: 'student_deleted' });
  after.payload[0].row.first_winner_participant_id = null;
  after.leaderboardProjection = [];
  return after;
}
function pair() {
  const before = example(), after = deleted(before), siblingBefore = example('20'), siblingAfter = structuredClone(siblingBefore);
  siblingAfter.payload = structuredClone(after.payload);
  const score = { participant_id: 52, username: 'controlled-20', team_name: null, total_stages_completed: 0,
    total_completion_time: 0, average_stage_time: 0, total_attempts: 0, success_rate: 0, total_score: 0, rank_position: 1 };
  siblingAfter.leaderboardProjection = [{ row: score }];
  siblingAfter.mutable.leaderboard = [{ row: { id: 99, fastest_stage_time: 0, slowest_stage_time: 0,
    is_completed: 0, completion_timestamp: null, ...score, last_updated: '2026-01-02T00:00:00.000+00:00' } }];
  return { before, after, siblingBefore, siblingAfter };
}
const verify = p => support.assertDeletionCtf(p.before, p.after, p.siblingBefore, p.siblingAfter, { jobId });
test('canonical native-shaped registration/deletion receipts retain evidence and only nullable winner changes', () => {
  const p = pair(), result = verify(p);
  assert.equal(result.nativeVerified, false); assert.equal(result.canonicalCredit, false); assert.equal(result.fullStoreCoverage, false);
  assert.equal(result.deletionReceiptValidated, true);
});
test('oracle rejects retained target rows, mutated siblings and unchanged winner link', () => {
  for (const key of Object.keys(support.MUTABLE)) {
    const p = pair(); p.after.mutable[key] = [{ row: { id: 99 } }]; assert.throws(() => verify(p), key);
  }
  for (const change of [p => p.siblingAfter.binding[0].row.active = false,
    p => p.siblingAfter.outbox[0].row.session_id++, p => p.after.payload[0].row.first_winner_participant_id = 51,
    p => p.after.payload[0].row.normalized_snippet = 'changed', p => p.after.identityPayload = [],
    p => { p.before.payload = []; p.siblingBefore.payload = []; }]) { const p = pair(); change(p); assert.throws(() => verify(p)); }
});
test('oracle rejects wrong owner/session/job/generation, invalid hashes and fabricated removal counts', () => {
  for (const change of [p => p.after.deletionCommands[0].row.subject_id = 20,
    p => p.after.deletionCommands[0].row.job_id = op, p => p.after.authority[0].row.owner_generation = 9,
    p => p.after.authority[0].row.failure_code = 'other', p => p.after.binding[0].row.banned = false,
    p => p.after.outbox[0].row.session_id++, p => p.after.outbox[0].row.canonical_command += ' ',
    p => p.after.projections[1].row.result_hash = '0'.repeat(64), p => p.after.reservations[0].row.resolved_at = 'changed',
    p => { const row = p.after.outbox[1].row, result = JSON.parse(row.canonical_result); result.data.removed.participants = 0;
      row.canonical_result = canonicalCtfJson(result); row.result_hash = sha(row.canonical_result); },
    p => p.after.outbox.splice(0, 1)]) { const p = pair(); change(p); assert.throws(() => verify(p)); }
});
test('derived sibling ranking validates real counts/score/rank and exact GREATEST timestamp without refreshing', () => {
  for (const key of ['total_stages_completed', 'total_attempts', 'total_score', 'rank_position']) {
    const p = pair(); p.siblingAfter.mutable.leaderboard[0].row[key]++;
    assert.throws(() => verify(p), key);
  }
  const p = pair(); p.siblingAfter.mutable.leaderboard[0].row.last_updated = '2026-01-02T00:00:00.001Z';
  assert.throws(() => verify(p));
  const later = pair(); later.siblingBefore.mutable.leaderboard = structuredClone(later.siblingAfter.mutable.leaderboard);
  later.siblingBefore.mutable.leaderboard[0].row.last_updated = '2026-01-03T00:00:00.123456Z';
  later.siblingAfter.mutable.leaderboard[0].row.last_updated = '2026-01-03T00:00:00.123456+00:00';
  verify(later);
  later.siblingAfter.mutable.leaderboard[0].row.last_updated = '2026-01-03T00:00:00.123455Z';
  assert.throws(() => verify(later));
  assert(!support.LEADERBOARD_SELECT.includes('refresh_authorized_leaderboard('));
  assert(support.LEADERBOARD_SELECT.includes('rank() OVER(ORDER BY total_stages_completed DESC,total_score DESC,total_completion_time ASC)'));
});
test('registration uses one mutation and only bounded recovery of the exact returned operation', async () => {
  const calls = [], pending = { status: 202, body: { operationId: op } };
  const runtime = { async mutate(args) { calls.push(['mutate', args]); return pending; },
    async recoverOperation(args) { calls.push(['recover', args]); return calls.length === 2 ? pending
      : { status: 200, body: { participantId: 51, sessionToken: 'teaching-private' } }; } };
  const result = await support.registerDeletionCtfOwner({ runtime, req });
  assert.equal(result.operationId, op); assert.equal(result.recoveryReads, 2); assert.equal(result.mutationCalls, 1);
  assert.equal(calls.filter(c => c[0] === 'mutate').length, 1);
  assert(calls.slice(1).every(c => c[1].operationId === op && c[1].req === req));
  assert(!JSON.stringify(result).includes('token')); assert.deepEqual(calls[0][1].input, {});
});
test('registration pending, changed operation, revoked authority and lost transport never resubmit', async () => {
  for (const outcome of ['pending', 'changed', 'denied', 'throw']) {
    let mutations = 0, reads = 0;
    const runtime = { async mutate() { mutations++; if (outcome === 'throw') throw Error('lost acknowledgement'); return { status: 202, body: { operationId: op } }; },
      async recoverOperation() { reads++; return outcome === 'denied' ? { status: 401, body: {} }
        : { status: 202, body: { operationId: outcome === 'changed' ? jobId : op } }; } };
    await assert.rejects(support.registerDeletionCtfOwner({ runtime, req })); assert.equal(mutations, 1); assert(reads <= 4);
  }
  const abort = new AbortController(); abort.abort(); let called = false;
  await assert.rejects(support.registerDeletionCtfOwner({ runtime: { mutate() { called = true; } }, req, signal: abort.signal }));
  assert.equal(called, false);
});
test('in-flight registration cancellation is bounded without a second dispatch', async () => {
  const controller = new AbortController(); let calls = 0;
  const runtime = { mutate() { calls++; queueMicrotask(() => controller.abort(Error('controlled cancellation'))); return new Promise(() => {}); } };
  await assert.rejects(support.registerDeletionCtfOwner({ runtime, req, signal: controller.signal }), /controlled cancellation/);
  assert.equal(calls, 1);
});
test('readback binds original owner/participant, caps snapshots and never writes', async () => {
  const calls = [], pool = { async query(sql, args) { calls.push({ sql, args }); return { rows: [] }; } };
  await support.readDeletionCtfOwner({ identityPool: pool, ctfPool: pool, registration: example().registration });
  assert(calls.every(c => (c.sql.startsWith('SELECT ') || c.sql === support.LEADERBOARD_SELECT) && c.sql.endsWith('LIMIT 257')));
  assert(calls.some(c => c.sql.includes('ctf_registration_reservations') && c.args[0] === '19'));
  assert(calls.some(c => c.sql.includes('ctf_participants') && c.args[0] === '51'));
  await assert.rejects(support.readDeletionCtfOwner({ identityPool: pool,
    ctfPool: { query: async () => ({ rows: Array.from({ length: 257 }, () => ({ row: {} })) }) }, registration: example().registration }), /bound/);
});
test('initialization is import-inert and refuses alternate environment before pool work', async () => {
  let touched = false; const p = { query() { touched = true; }, connect() { touched = true; } };
  await assert.rejects(support.initializeDeletionCtf({ identityRuntime: p, identityMigration: p, ctfRuntime: p, ctfMigration: p, env: {} }), /process environment/);
  assert.equal(touched, false);
  assert.match(support.SHARED_TEXT, /^[a-z0-9_ ]*$/); assert.equal(sha(support.SHARED_TEXT), support.SHARED_HASH);
});
function ownedEnvironment(t) {
  const { STORES } = require('./adminStudentDeletionRenderedSupport');
  const updates = { PG_TEST_DISPOSABLE: 'yes', PLATFORM_DATABASE_ENGINE: 'postgres', WORKSHOP_DATABASE_ENGINE: 'postgres',
    PG_POOL_BUDGET: '78', LEGACY_PLATFORM_LIFECYCLE_ENABLED: undefined };
  for (const store of STORES) {
    const db = 'dvaia_test_student_deletion_123456789abc_' + store.schema;
    updates[store.runtimeVariable] = `postgresql://${store.runtimeRole}@127.0.0.1:54321/${db}`;
    updates[store.migrationVariable] = `postgresql://${store.migrationRole}@127.0.0.1:54321/${db}`;
  }
  updates.CTF_DELIVERY_DATABASE_URL = updates.CTF_DATABASE_URL.replace('dvaia_ctf_runtime@', 'dvaia_ctf_delivery@');
  const old = Object.fromEntries(Object.keys(updates).map(k => [k, process.env[k]]));
  t.after(() => { for (const [key, value] of Object.entries(old)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; } });
  for (const [key, value] of Object.entries(updates)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; }
}
test('delivery admission requires exact owned database and role without URL overrides', t => {
  ownedEnvironment(t); assert.equal(support.admitCtfDelivery(), true);
  const original = process.env.CTF_DELIVERY_DATABASE_URL;
  for (const changed of [original.replace('dvaia_ctf_delivery', 'dvaia_ctf_runtime'), original + '?options=x',
    original.replace('_ctf', '_identity'), original.replace('54321', '54322')]) {
    process.env.CTF_DELIVERY_DATABASE_URL = changed; assert.throws(() => support.admitCtfDelivery());
  }
  process.env.CTF_DELIVERY_DATABASE_URL = original;
});
test('canonical initialization orders pre-bootstrap seed, real factory activation and production publication', async t => {
  ownedEnvironment(t); const calls = []; let bootstrapState = 'open';
  const names = [['identityRuntime','IDENTITY_DATABASE_URL'],['identityMigration','IDENTITY_MIGRATION_DATABASE_URL'],
    ['ctfRuntime','CTF_DATABASE_URL'],['ctfMigration','CTF_MIGRATION_DATABASE_URL']];
  const pools = Object.fromEntries(names.map(([name,key]) => [name, { connect() { throw Error('controlled factory must not allocate'); },
    async query(sql) {
      calls.push(name + ':' + sql.split(' ')[0]);
      if (sql.includes('current_database()')) { const u = new URL(process.env[key]); return { rows: [{ database: u.pathname.slice(1), role: u.username, login: u.username }] }; }
      if (sql.includes('bootstrap_control')) return { rows: [{ state: bootstrapState }] };
      if (sql.includes('normalized_snippet')) return { rows: [{ normalized_snippet: support.SHARED_TEXT }] };
      if (sql.startsWith('INSERT')) return { rows: [], rowCount: 1 };
      throw Error('unexpected controlled SQL');
    } }]));
  t.mock.method(require('../../server/database/postgres/ctfDb'), 'createCtfDb', p => ({
    async initialize(migration) { assert.equal(p,pools.ctfRuntime); assert.equal(migration,pools.ctfMigration); calls.push('initialize'); },
    async updateConfig(key,value) { assert.equal(p,pools.ctfMigration); assert.equal(value,'true'); calls.push('config:' + key); } }));
  const bootstrapRepository = {};
  t.mock.method(require('../../server/database/postgres/ctfAuthorityBootstrapRepository'), 'createCtfAuthorityBootstrapRepository', options => {
    assert.equal(options.identityPool,pools.identityMigration); assert.equal(options.ctfPool,pools.ctfMigration); return bootstrapRepository;
  });
  t.mock.method(require('../../server/services/ctfAuthorityBootstrap'), 'createCtfAuthorityBootstrap', ({repository}) => {
    assert.equal(repository,bootstrapRepository); return { async prepare({operationId,signal}) { assert.match(operationId,/^[a-f0-9-]{36}$/); assert(signal); calls.push('bootstrap'); } };
  });
  t.mock.method(require('../../server/database/postgres/ctfDeliveryActivationOperator'), 'createCtfDeliveryActivationOperator', options => {
    assert.equal(options.identityMigrationPool,pools.identityMigration); return { async activate() { calls.push('activate'); return { activation: {}, trafficStarted:false }; } };
  });
  t.mock.method(require('../../server/database/postgres/ctfDeliveryActivation'), 'createCtfDeliveryActivation', () => ({ async loadCurrent() { calls.push('verify'); return {}; } }));
  const production = require('../../server/services/ctfAuthorityProduction');
  const runtime = { async readiness() { calls.push('ready'); return {runtimeReady:true}; } };
  t.mock.method(production, 'initializeProductionCtfAuthority', async options => { assert.equal(options.env,process.env); calls.push('production'); return {runtime}; });
  t.mock.method(production, 'closeProductionCtfAuthority', async () => calls.push('close'));
  const result = await support.initializeDeletionCtf({...pools,adapter:{validateSession(){}},coordinator:{run(){}}});
  assert.equal(result.runtime,runtime); assert.equal(result.nativeVerified,false);
  assert(calls.indexOf('bootstrap') > calls.indexOf('ctfMigration:INSERT'));
  assert(calls.indexOf('activate') > calls.indexOf('bootstrap')); assert(calls.indexOf('production') > calls.indexOf('verify'));
  assert.equal(calls.filter(c => c.includes('INSERT')).length,1);
  await result.close(); assert.equal(calls.at(-1),'close');
  calls.length = 0; bootstrapState = 'prepared';
  await support.initializeDeletionCtf({...pools,adapter:{validateSession(){}},coordinator:{run(){}}});
  assert(calls.includes('verify') && calls.includes('production'));
  assert(!calls.some(c => c === 'initialize' || c === 'bootstrap' || c === 'activate' || c.startsWith('config:') || c.includes('INSERT')));
  calls.length = 0; bootstrapState = 'fenced';
  await assert.rejects(support.initializeDeletionCtf({...pools,adapter:{validateSession(){}},coordinator:{run(){}}}), /Incomplete bootstrap/);
  assert(!calls.includes('production') && !calls.includes('activate'));
  for (const [name,key] of names) {
    const bad = {...pools,[name]:{connect(){},async query(){const u=new URL(process.env[key]);return{rows:[{database:u.pathname.slice(1),role:u.username,login:'wrong'}]};}}};
    await assert.rejects(support.assertCtfPoolBindings(bad,process.env));
  }
});
