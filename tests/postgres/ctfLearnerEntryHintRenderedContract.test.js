'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const crypto = require('node:crypto');
const {
  PROFILE, POST_PATHS, FACTS, EXCLUDED, LIMITS, learnerApiAllowed,
  assertLearnerEntryHintReceipt, seedHintGateBeforeBootstrap, assertHintGate,
  outboxFor, snapshotPeerAndHistory, assertPeerAndHistory,
  joinButton, stageOneCard, hintButton, hintDialog, runCtfLearnerEntryHintFacet,
  retireLearnerListeners,
  assertLearnerDatabaseName, learnerBrowserAllowed, runCtfLearnerEntryHintRenderedCases,
} = require('./support/ctfLearnerEntryHintRenderedCases');

const id = '11111111-1111-4111-8111-111111111111';
const operation = n => ({ originalStatus: 200, resolvedStatus: 200,
  sameIdGets: 0, operationId: `${String(n).padStart(8, '0')}-1111-4111-8111-111111111111`, sequence: String(n) });
function receipt() {
  return { version: 1, profile: PROFILE, actorId: '3012', sessionId: '9',
    participantId: '3012', stageId: 1, siblingOwnerId: 1001,
    prerequisite: { hintGate: '0', source: 'pre-bootstrap-config',
      defaultAttemptGateProven: false },
    browserPosts: { register: 1, start: 1, hint: 1 },
    serverPosts: { register: 1, start: 1, hint: 1 },
    operations: { register: operation(4), start: operation(5), hint: operation(6) },
    startOperationIds: [operation(5).operationId],
    hintDialog: { cancelPosts: 0, abaPosts: 0, abaEventsObserved: 2,
      cancelStateUnchanged: true, abaStateUnchanged: true },
    storeWitness: { ownerRegistered: true, stageStarted: true,
      oneHintPurchased: true, costApplied: true, siblingBeforeNonempty: true,
      siblingUnchanged: true, attemptsUnchanged: true, judgmentsUnchanged: true,
      siblingLeaderboardUnchanged: true },
    facts: Object.fromEntries(FACTS.map(key => [key, true])), excluded: [...EXCLUDED],
    unexpectedApiPaths: [], browserActions: 32, apiRequests: 42,
    modelCalls: 0, judgeCalls: 0, genuineCredit: 0, stage: 'complete' };
}
const tamper = fn => { const value = receipt(); fn(value);
  assert.throws(() => assertLearnerEntryHintReceipt(value)); };

test('learner receipt is exact and disclaims default gate, scoring and model qualification', () => {
  assert.equal(assertLearnerEntryHintReceipt(receipt()), true);
  assert.equal(POST_PATHS.register, '/api/ctf/register');
  assert.equal(POST_PATHS.start, '/api/ctf/stage/1/start');
  assert.equal(POST_PATHS.hint, '/api/ctf/stage/1/hint');
  assert(EXCLUDED.includes('default-attempt-gate'));
  assert(EXCLUDED.includes('scored-attempt'));
  assert.equal(LIMITS.sameIdGets, 32);
  assert.equal(typeof runCtfLearnerEntryHintFacet, 'function');
  assert.equal(typeof runCtfLearnerEntryHintRenderedCases, 'function');
});

test('disposable learner database names bind state, store and one nonce', () => {
  const n = '012345abcdef';
  assert.equal(assertLearnerDatabaseName(`/dvaia_test_ctf_learner_entry_hint_f_i_${n}`,
    'FRESH', 'IDENTITY'), n);
  assert.equal(assertLearnerDatabaseName(`/dvaia_test_ctf_learner_entry_hint_p_c_${n}`,
    'POPULATED', 'CTF', n), n);
  for (const pathname of [`/dvaia_test_ctf_preview_f_i_${n}`,
    `/dvaia_test_ctf_learner_entry_hint_p_i_${n}`])
    assert.throws(() => assertLearnerDatabaseName(pathname, 'FRESH', 'IDENTITY', n));
  assert.throws(() => assertLearnerDatabaseName(`/dvaia_test_ctf_learner_entry_hint_f_c_${n}`,
    'FRESH', 'IDENTITY', n));
});

test('mounted learner browser has finite exact read and three-write admission', () => {
  for (const pathname of Object.values(POST_PATHS))
    assert.equal(learnerBrowserAllowed('POST', pathname), true);
  assert.equal(learnerBrowserAllowed('GET', '/api/ctf/leaderboard'), true);
  assert.equal(learnerBrowserAllowed('GET', '/api/ctf/config', true), true);
  for (const [method, pathname, auxiliary] of [
    ['POST', '/api/ctf/stage/1/attempt', false],
    ['POST', '/api/ctf/stage/1/hint', true],
    ['POST', '/api/ctf/heartbeat', false],
    ['GET', '/api/ctf/admin/stages', false],
    ['GET', '/api/ctf/status', true],
    ['GET', '/api/ctf/operations/foreign', false],
  ]) assert.equal(learnerBrowserAllowed(method, pathname, auxiliary), false,
    `${method} ${pathname}`);
});

test('learner receipt rejects fabricated counts, ABA, identity, projection or credit', () => {
  tamper(r => { r.browserPosts.start = 0; });
  tamper(r => { r.browserPosts.start = 4; });
  tamper(r => { r.browserPosts.start = 2; });
  tamper(r => { r.startOperationIds = []; });
  tamper(r => { r.serverPosts.hint = 0; });
  tamper(r => { r.hintDialog.abaEventsObserved = 1; });
  tamper(r => { r.hintDialog.abaPosts = 1; });
  tamper(r => { r.storeWitness.siblingBeforeNonempty = false; });
  tamper(r => { r.storeWitness.attemptsUnchanged = false; });
  tamper(r => { r.operations.start.sequence = '4'; });
  tamper(r => { r.operations.hint.originalStatus = 202; });
  tamper(r => { r.operations.hint.sameIdGets = 33; });
  tamper(r => { r.prerequisite.defaultAttemptGateProven = true; });
  tamper(r => { r.actorId = '0'; });
  tamper(r => { r.facts.automaticStart = false; });
  tamper(r => { r.modelCalls = 1; });
  tamper(r => { r.genuineCredit = 1; });
  tamper(r => { r.unexpectedApiPaths.push('/api/ctf/admin/reset'); });
  tamper(r => { r.extra = true; });
});

test('authority refresh may remount automatic start, but every bounded physical start needs a distinct operation', () => {
  const value = receipt();
  value.browserPosts.start = 2; value.serverPosts.start = 2;
  value.startOperationIds.push('22222222-2222-4222-8222-222222222222');
  assert.equal(assertLearnerEntryHintReceipt(value), true);
  value.startOperationIds[1] = id;
  assert.equal(assertLearnerEntryHintReceipt(value), true);
  value.startOperationIds[1] = value.operations.register.operationId;
  assert.throws(() => assertLearnerEntryHintReceipt(value));
  value.startOperationIds[1] = value.operations.hint.operationId;
  assert.throws(() => assertLearnerEntryHintReceipt(value));
});

test('learner cleanup preserves primary and attempts both listener removals after auxiliary close failure', async () => {
  const calls = [], primary = Error('primary');
  const page = { off(event) { calls.push(event); } };
  const other = { async close() { calls.push('close'); throw Error('close failure'); } };
  await assert.rejects(retireLearnerListeners(page, other, () => {}, () => {}, primary), error => {
    assert(error instanceof AggregateError);
    assert.equal(error.errors[0], primary);
    assert.equal(error.errors.length, 2);
    return true;
  });
  assert.deepEqual(calls, ['close', 'request', 'response']);
});

test('only learner reads and three exact writes are admitted by the prospective facet', () => {
  for (const path of Object.values(POST_PATHS))
    assert.equal(learnerApiAllowed('POST', path), true);
  assert.equal(learnerApiAllowed('GET', '/api/ctf/status'), true);
  assert.equal(learnerApiAllowed('GET', `/api/ctf/operations/${id}`), true);
  for (const [method, path] of [['POST', '/api/ctf/stage/2/start'],
    ['POST', '/api/ctf/stage/1/attempt'], ['POST', '/api/ctf/stage/1/practice'],
    ['POST', '/api/ctf/heartbeat'], ['POST', '/api/ctf/admin/config'],
    ['GET', '/api/ctf/operations/not-a-uuid'], ['PUT', '/api/ctf/stage/1/hint']])
    assert.equal(learnerApiAllowed(method, path), false, `${method} ${path}`);
});

test('pre-bootstrap hint gate seed is one exact prerequisite and is read back without writing', async () => {
  const sql = [];
  await seedHintGateBeforeBootstrap({ query: async query => {
    sql.push(query); return { rows: [{ value: '0' }] };
  } });
  assert.equal(sql.length, 1);
  assert.equal(sql[0], "UPDATE ctf.ctf_config SET value='0' WHERE key='ctf_hint_gating_attempts' RETURNING value");
  await assertHintGate({ query: async query => {
    assert(query.startsWith('SELECT value FROM ctf.ctf_config'));
    return { rows: [{ value: '0' }] };
  } });
  await assert.rejects(assertHintGate({ query: async () => ({ rows: [{ value: '3' }] }) }));
  await assert.rejects(seedHintGateBeforeBootstrap({ query: async () => ({ rows: [] }) }));
});

test('learner prerequisite is staged before bootstrap, not rewritten after activation', () => {
  const source = fs.readFileSync(path.join(__dirname,
    'ctfAuthorityApplication.integration.test.js'), 'utf8');
  const seeded = source.indexOf('.seedHintGateBeforeBootstrap(c.migration)');
  const snapshot = source.indexOf('const before=Object.fromEntries(await Promise.all(TABLES.map');
  const prepared = source.indexOf('.prepare({operationId})');
  const activated = source.indexOf('let activated=await operator.activate');
  const rendered = source.indexOf('.runCtfLearnerEntryHintRenderedCases({');
  assert(seeded > 0 && seeded < snapshot && snapshot < prepared &&
    prepared < activated && activated < rendered);
  const helper = fs.readFileSync(path.join(__dirname,
    'support/ctfLearnerEntryHintRenderedCases.js'), 'utf8');
  const orchestrator = helper.slice(helper.indexOf('async function runCtfLearnerEntryHintRenderedCases'));
  assert(!orchestrator.includes('seedHintGateBeforeBootstrap('));
});

test('authority ABA reopens the real dashboard card because challenge stage lives in route state', () => {
  const helper = fs.readFileSync(path.join(__dirname,
    'support/ctfLearnerEntryHintRenderedCases.js'), 'utf8');
  const afterAba = helper.slice(helper.indexOf('const abaEventsObserved ='));
  assert(afterAba.includes("page.goto(origin + '/ctf'"));
  assert(afterAba.includes('pointer(await wait(stageOneCard))'));
  assert(!afterAba.includes('page.reload('));
});

test('fresh learner identity and session precede the physical CTF registration only', () => {
  const helper = fs.readFileSync(path.join(__dirname,
    'support/ctfLearnerEntryHintRenderedCases.js'), 'utf8');
  const section = helper.slice(helper.indexOf('async function runCtfLearnerEntryHintRenderedCases'));
  const identity = section.indexOf('INSERT INTO identity.users');
  const session = section.indexOf('const learner = await userRequest(learnerId)');
  const physical = section.indexOf('runCtfLearnerEntryHintFacet({');
  assert(identity > 0 && identity < session && session < physical);
  assert(!section.includes('INSERT INTO ctf.ctf_participants'));
});

test('canonical learner outbox joins actor/session, command hash and projection receipt', async () => {
  const command = JSON.stringify({ operationId: id, kind: 'start', actorId: '3012',
    scope: { ownerId: '3012', participantId: '3012', stageId: '1' } });
  const result = JSON.stringify({ message: 'started' });
  const hash = value => crypto.createHash('sha256').update(value).digest('hex');
  const row = { sequence: '5', operation_id: id, actor_id: '3012', session_id: '9',
    kind: 'start', state: 'applied', canonical_command: command,
    command_hash: hash(command), canonical_result: result, result_hash: hash(result) };
  const i = { migration: { query: async (sql, args) => {
    assert(sql.includes('kind=$2 AND actor_id=$3'));
    assert.deepEqual(args, ['4', 'start', '3012']);
    return { rows: [row] };
  } } };
  const c = { runtime: { query: async (sql, args) => {
    assert(sql.includes('ctf.projection_receipts'));
    assert.deepEqual(args, [id]);
    return { rows: [{ sequence: '5', operation_id: id, kind: 'start',
      command_hash: row.command_hash, canonical_result: result,
      result_hash: row.result_hash }] };
  } } };
  assert.equal(await outboxFor(i, c, '4', 'start', '3012', '9', '3012', 1), row);
  await assert.rejects(outboxFor(i, c, '4', 'start', '3012', '10', '3012', 1));
  const wrong = { ...c, runtime: { query: async () => ({ rows: [] }) } };
  await assert.rejects(outboxFor(i, wrong, '4', 'start', '3012', '9', '3012', 1));
});

test('peer and history require nonempty raw rows and exact equality', async () => {
  const pools = { migration: { query: async () => ({ rows: [{ row: '{"id":1}' }] }) },
    runtime: { query: async () => ({ rows: [{ row: '{"id":1}' }] }) } };
  const snapshot = await snapshotPeerAndHistory(pools, pools);
  assert.equal(assertPeerAndHistory(snapshot, structuredClone(snapshot)), true);
  const changed = structuredClone(snapshot);
  changed.siblingProgress[0] = '{"id":2}';
  assert.throws(() => assertPeerAndHistory(snapshot, changed));
  const empty = structuredClone(snapshot); empty.siblingSessions = [];
  assert.throws(() => assertPeerAndHistory(empty, empty));
});

test('physical selectors match exact Join, stage-one card and first-hint dialog labels', () => {
  const code = [joinButton, stageOneCard, hintButton, hintDialog].map(fn => fn.toString()).join('\n');
  assert(code.includes('Join CTF'));
  assert(code.includes('The Doorway'));
  assert(code.includes('Unlock Hint 1'));
  assert(code.includes('Unlock (-15 pts)'));
  const dashboard = fs.readFileSync(path.join(__dirname, '../../client/src/pages/CTFDashboard.js'), 'utf8');
  const challenge = fs.readFileSync(path.join(__dirname, '../../client/src/pages/CTFChallenge.js'), 'utf8');
  const defaults = require('../../server/data/ctfDefaults');
  assert(dashboard.includes('Join CTF'));
  assert.equal(defaults.stages[0].stage_name, 'The Doorway');
  assert(challenge.includes('Unlock Hint {hintsUsed + 1}'));
  assert(challenge.includes('Unlock (-${config?.[`ctf_hint_cost_${confirmHintIndex + 1}`]'));
  assert.equal(typeof vm.runInNewContext(`(${joinButton.toString()})`, { document: {
    querySelectorAll: () => [] } }), 'function');
});
