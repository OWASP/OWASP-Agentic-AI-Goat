'use strict';
// Separate, controlled rendered learner facet. This does not score an attempt,
// exercise the default attempt gate, call a model/Judge, or amend the original 55.
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const content = require('./ctfRecoveryRenderedCases');

const PROFILE = 'ctf-learner-entry-hint-q05';
const POST_PATHS = Object.freeze({ register: '/api/ctf/register',
  start: '/api/ctf/stage/1/start', hint: '/api/ctf/stage/1/hint' });
const FACTS = Object.freeze(['physicalJoin', 'physicalStageCard', 'automaticStart',
  'hintCancelNoPost', 'hintAbaNoPost', 'onePhysicalHintPurchase',
  'actorSessionOutboxBound', 'canonicalProjectionBound', 'durableProgressBound',
  'nonemptySiblingPreserved', 'noScoredAttemptOrCredit']);
const EXCLUDED = Object.freeze(['default-attempt-gate', 'scored-attempt',
  'fixed-practice', 'model-qualification', 'objective-judge', 'gameplay-credit']);
const LIMITS = Object.freeze({ browserActions: 400, apiRequests: 400, deadlineMs: 180000,
  sameIdGets: 32 });
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const DECIMAL = /^[1-9][0-9]*$/;
const exact = (value, keys) => {
  assert(value && typeof value === 'object' && !Array.isArray(value));
  assert.deepEqual(Object.keys(value).sort(), [...keys].sort());
};
const digest = value => createHash('sha256').update(value).digest('hex');
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));

function learnerApiAllowed(method, pathname) {
  if (method === 'POST') return Object.values(POST_PATHS).includes(pathname);
  return method === 'GET' && (['/api/ctf/config', '/api/ctf/stages',
    '/api/ctf/status', '/api/auth/status', '/api/auth/signup-config',
    '/api/changes/revisions'].includes(pathname) ||
    /^\/api\/ctf\/operations\/[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(pathname));
}

function assertLearnerDatabaseName(pathname, state, kind, nonce = null) {
  assert(['FRESH', 'POPULATED'].includes(state));
  assert(['IDENTITY', 'CTF'].includes(kind));
  const match = pathname.match(new RegExp(
    `^/owasp_ai_goat_test_ctf_learner_entry_hint_${state[0].toLowerCase()}_${kind[0].toLowerCase()}_([a-f0-9]{12})$`));
  assert(match, 'Exact disposable learner database name required');
  if (nonce !== null) assert.equal(match[1], nonce);
  return match[1];
}

function assertOperation(value, kind) {
  exact(value, ['originalStatus', 'resolvedStatus', 'sameIdGets', 'operationId', 'sequence']);
  assert([200, 202].includes(value.originalStatus));
  assert.equal(value.resolvedStatus, 200);
  assert(Number.isSafeInteger(value.sameIdGets) && value.sameIdGets >= 0 &&
    value.sameIdGets <= LIMITS.sameIdGets);
  assert.equal(value.originalStatus === 200, value.sameIdGets === 0);
  assert.match(value.operationId, UUID);
  assert.match(value.sequence, DECIMAL);
  assert(['register', 'start', 'hint'].includes(kind));
}

function assertLearnerEntryHintReceipt(r) {
  exact(r, ['version', 'profile', 'actorId', 'sessionId', 'participantId', 'stageId',
    'siblingOwnerId', 'prerequisite', 'browserPosts', 'serverPosts', 'operations',
    'startOperationIds',
    'hintDialog', 'facts', 'storeWitness', 'unexpectedApiPaths', 'browserActions',
    'apiRequests', 'modelCalls', 'judgeCalls', 'genuineCredit', 'excluded', 'stage']);
  assert.equal(r.version, 1); assert.equal(r.profile, PROFILE);
  for (const key of ['actorId', 'sessionId', 'participantId']) assert.match(r[key], DECIMAL);
  assert.equal(r.stageId, 1); assert.equal(r.siblingOwnerId, 1001);
  assert.deepEqual(r.prerequisite, { hintGate: '0', source: 'pre-bootstrap-config',
    defaultAttemptGateProven: false });
  exact(r.browserPosts, ['register', 'start', 'hint']);
  assert.equal(r.browserPosts.register, 1); assert.equal(r.browserPosts.hint, 1);
  assert(Number.isSafeInteger(r.browserPosts.start) && r.browserPosts.start >= 1 &&
    r.browserPosts.start <= 3);
  assert.deepEqual(r.serverPosts, r.browserPosts);
  assert(Array.isArray(r.startOperationIds) &&
    r.startOperationIds.length === r.browserPosts.start);
  assert.equal(new Set(r.startOperationIds).size, r.startOperationIds.length);
  for (const operationId of r.startOperationIds) assert.match(operationId, UUID);
  exact(r.operations, ['register', 'start', 'hint']);
  for (const kind of Object.keys(r.operations)) assertOperation(r.operations[kind], kind);
  assert(BigInt(r.operations.register.sequence) < BigInt(r.operations.start.sequence));
  assert(BigInt(r.operations.start.sequence) < BigInt(r.operations.hint.sequence));
  assert.equal(r.startOperationIds[0], r.operations.start.operationId);
  assert.equal(new Set([r.operations.register.operationId,
    ...r.startOperationIds, r.operations.hint.operationId]).size,
  r.startOperationIds.length + 2, 'Lifecycle operation IDs must be mutually distinct');
  exact(r.hintDialog, ['cancelPosts', 'abaPosts', 'abaEventsObserved', 'cancelStateUnchanged',
    'abaStateUnchanged']);
  assert.deepEqual(r.hintDialog, { cancelPosts: 0, abaPosts: 0,
    abaEventsObserved: 2, cancelStateUnchanged: true, abaStateUnchanged: true });
  exact(r.storeWitness, ['ownerRegistered', 'stageStarted', 'oneHintPurchased',
    'costApplied', 'siblingBeforeNonempty', 'siblingUnchanged', 'attemptsUnchanged',
    'judgmentsUnchanged', 'siblingLeaderboardUnchanged']);
  for (const value of Object.values(r.storeWitness)) assert.equal(value, true);
  exact(r.facts, FACTS); for (const value of Object.values(r.facts)) assert.equal(value, true);
  assert.deepEqual(r.excluded, [...EXCLUDED]); assert.deepEqual(r.unexpectedApiPaths, []);
  for (const [key, max] of [['browserActions', LIMITS.browserActions],
    ['apiRequests', LIMITS.apiRequests]])
    assert(Number.isSafeInteger(r[key]) && r[key] > 0 && r[key] <= max);
  assert.equal(r.modelCalls, 0); assert.equal(r.judgeCalls, 0);
  assert.equal(r.genuineCredit, 0); assert.equal(r.stage, 'complete');
  return true;
}

async function retireLearnerListeners(page, other, requestListener, responseListener, primary) {
  const cleanupErrors = [];
  try { if (other) await other.close(); } catch (error) { cleanupErrors.push(error); }
  try { page.off('request', requestListener); } catch (error) { cleanupErrors.push(error); }
  try { page.off('response', responseListener); } catch (error) { cleanupErrors.push(error); }
  if (cleanupErrors.length) throw new AggregateError(
    [...(primary ? [primary] : []), ...cleanupErrors],
    'Learner browser cleanup incomplete', { cause: primary });
}

// Called only in the FRESH source phase before bootstrap prepare/activation.
// Never synthesize a registration, start, hint, or attempted answer.
async function seedHintGateBeforeBootstrap(ctfMigration) {
  assert(ctfMigration && typeof ctfMigration.query === 'function');
  const result = await ctfMigration.query(
    "UPDATE ctf.ctf_config SET value='0' WHERE key='ctf_hint_gating_attempts' RETURNING value");
  assert.deepEqual(result.rows, [{ value: '0' }]);
}

async function assertHintGate(ctfRuntime) {
  const rows = (await ctfRuntime.query(
    "SELECT value FROM ctf.ctf_config WHERE key='ctf_hint_gating_attempts'")).rows;
  assert.deepEqual(rows, [{ value: '0' }]);
}

async function outboxFor(i, c, afterSequence, kind, actorId, sessionId,
  participantId = null, stageId = null) {
  const until = Date.now() + 10000;
  let rows;
  do {
    rows = (await i.migration.query(`SELECT sequence::text,operation_id::text,
      actor_id::text,session_id::text,kind,state,canonical_command,command_hash,
      canonical_result,result_hash FROM identity.ctf_outbox
      WHERE sequence>$1 AND kind=$2 AND actor_id=$3 ORDER BY sequence LIMIT 1`,
      [afterSequence, kind, actorId])).rows;
    if (rows.length === 1 && rows[0].state === 'applied') break;
    assert(rows.length <= 1, 'Exactly one canonical lifecycle operation expected');
    assert(Date.now() < until, 'Canonical lifecycle projection deadline');
    await pause(50);
  } while (true);
  const row = rows[0];
  assert.equal(row.kind, kind);
  assert.equal(row.actor_id, actorId); assert.equal(row.session_id, sessionId);
  assert.equal(digest(row.canonical_command), row.command_hash);
  assert.equal(digest(row.canonical_result), row.result_hash);
  const command = JSON.parse(row.canonical_command);
  assert.equal(command.operationId, row.operation_id);
  assert.equal(command.kind, kind); assert.equal(command.actorId, actorId);
  assert.equal(command.scope.ownerId, actorId);
  if (participantId !== null) assert.equal(command.scope.participantId, participantId);
  if (stageId !== null) assert.equal(command.scope.stageId, String(stageId));
  const projected = (await c.runtime.query(`SELECT sequence::text,operation_id::text,
    kind,command_hash,canonical_result,result_hash FROM ctf.projection_receipts
    WHERE operation_id=$1`, [row.operation_id])).rows;
  assert.deepEqual(projected, [{ sequence: row.sequence, operation_id: row.operation_id,
    kind, command_hash: row.command_hash, canonical_result: row.canonical_result,
    result_hash: row.result_hash }]);
  return row;
}

async function rawRows(pool, table, where = '', values = []) {
  return (await pool.query(`SELECT to_jsonb(t)::text AS row FROM ${table} t ${where}`, values))
    .rows.map(value => value.row).sort();
}

async function snapshotPeerAndHistory(i, c) {
  return {
    siblingProgress: await rawRows(c.runtime, 'ctf.ctf_progress', 'WHERE participant_id=1001'),
    siblingAttempts: await rawRows(c.runtime, 'ctf.ctf_attempts', 'WHERE participant_id=1001'),
    siblingSessions: await rawRows(c.runtime, 'ctf.ctf_sessions', 'WHERE participant_id=1001'),
    allAttempts: await rawRows(c.runtime, 'ctf.ctf_attempts'),
    judgments: await rawRows(c.runtime, 'ctf.ctf_judgments'),
    siblingLeaderboard: await rawRows(c.runtime, 'ctf.ctf_leaderboard',
      'WHERE participant_id=1001'),
    historicalBindings: await rawRows(i.migration, 'identity.ctf_progress_bindings',
      'WHERE owner_id=1001'),
  };
}

function assertPeerAndHistory(before, after) {
  assert(before.siblingProgress.length && before.siblingAttempts.length &&
    before.siblingSessions.length, 'Sibling fixture must be nonempty');
  assert.deepEqual(after, before);
  return true;
}

// Exact DOM predicates for the mounted production pages; callers perform real
// pointer clicks and capture physical requests before these may count as proof.
function joinButton() {
  const form = [...document.querySelectorAll('form')].find(x =>
    x.querySelector('label[for="displayName"]')?.textContent.trim() === 'Your CTF Name');
  const found = [...(form?.querySelectorAll('button[type="submit"]') || [])]
    .filter(x => x.textContent.trim() === 'Join CTF' && !x.disabled && x.getClientRects().length);
  return found.length === 1 ? found[0] : null;
}
function stageOneCard() {
  const found = [...document.querySelectorAll('[role="button"]')].filter(x =>
    x.querySelector('h3')?.textContent.trim() === 'The Doorway' &&
    x.getAttribute('tabindex') === '0' && x.getClientRects().length);
  return found.length === 1 ? found[0] : null;
}
function hintButton() {
  const found = [...document.querySelectorAll('button')].filter(x => {
    const own = [...x.childNodes].filter(n => n.nodeType === 3)
      .map(n => n.textContent).join('').replace(/\s+/g, ' ').trim();
    const spans = [...x.children].filter(n => n.tagName === 'SPAN');
    return own === 'Unlock Hint 1' && spans.length === 1 &&
      spans[0].textContent.trim() === '(-15 pts)' && !x.disabled && x.getClientRects().length;
  });
  return found.length === 1 ? found[0] : null;
}
function hintDialog() {
  const found = [...document.querySelectorAll('[role="dialog"]')].filter(x =>
    x.querySelector('h3')?.textContent.trim() === 'Unlock Hint 1?' &&
    [...x.querySelectorAll('button')].some(b => b.textContent.trim() === 'Cancel') &&
    [...x.querySelectorAll('button')].some(b => b.textContent.trim() === 'Unlock (-15 pts)'));
  return found.length === 1 ? found[0] : null;
}

async function runCtfLearnerEntryHintFacet({ page, origin, bearer, comparisonBearer,
  actorId, sessionId, i, c, serverCounts, apiRequests, ledger }) {
  assert(page && typeof page.waitForFunction === 'function');
  assert(new URL(origin).hostname === '127.0.0.1');
  assert(typeof bearer === 'string' && bearer.startsWith('Bearer '));
  assert(typeof comparisonBearer === 'string' && comparisonBearer.startsWith('Bearer '));
  assert.notEqual(bearer, comparisonBearer);
  for (const id of [actorId, sessionId]) assert.match(String(id), DECIMAL);
  assert(typeof serverCounts === 'function' && typeof apiRequests === 'function');
  assert(Array.isArray(ledger) && ledger.length === 0);
  await assertHintGate(c.runtime);
  const before = await snapshotPeerAndHistory(i, c);
  assert(before.siblingProgress.length && before.siblingAttempts.length &&
    before.siblingSessions.length);
  assert.deepEqual((await c.runtime.query('SELECT id FROM ctf.ctf_participants WHERE user_id=$1',
    [actorId])).rows, [], 'Learner must not be fixture-registered');
  const startServer = serverCounts(), startApi = apiRequests();
  assert.deepEqual(startServer, { register: 0, start: 0, hint: 0 });
  const seen = { register: [], start: [], hint: [] }, responses = [];
  let actions = 0;
  const startedAt = Date.now();
  const active = () => { assert(actions <= LIMITS.browserActions);
    assert(Date.now() - startedAt <= LIMITS.deadlineMs, 'Learner facet work deadline');
    assert.equal(ledger.length, 0, 'Learner lifecycle facet cannot call a provider'); };
  const action = fn => { actions++; active(); return fn(); };
  const pointer = async handle => {
    try { await content.contentPointerClick(page, handle, action); }
    finally { await handle.dispose(); }
  };
  const wait = async fn => {
    const handle = await action(() => page.waitForFunction(fn, { timeout: 15000,
      polling: 100 }));
    assert(handle.asElement()); return handle;
  };
  const clickText = async (selector, text) => {
    const handle = await action(() => page.waitForFunction(({ selector, text }) => {
      const found = [...document.querySelectorAll(selector)].filter(x =>
        x.textContent.trim() === text && !x.disabled && x.getClientRects().length);
      return found.length === 1 ? found[0] : null;
    }, { timeout: 15000, polling: 100 }, { selector, text }));
    await pointer(handle);
  };
  const maxSequence = async () => (await i.migration.query(
    'SELECT COALESCE(max(sequence),0)::text AS value FROM identity.ctf_outbox')).rows[0].value;
  const count = kind => seen[kind].length;
  const envelope = async (kind, response, row) => {
    assert([200, 202].includes(response.status()));
    const body = await response.json();
    let gets = 0;
    if (response.status() === 202) {
      assert.equal(body?.operationId, row.operation_id);
      const until = Date.now() + 30000;
      while (Date.now() < until && gets < LIMITS.sameIdGets) {
        const visible = await action(() => page.evaluate(() =>
          [...document.querySelectorAll('[role="status"] button')]
            .some(x => x.textContent.trim() === 'Check status' && !x.disabled)));
        if (visible) await clickText('[role="status"] button', 'Check status');
        const done = responses.find(x => x.path === `/api/ctf/operations/${row.operation_id}` &&
          x.status === 200);
        if (done) { gets = responses.filter(x => x.path === done.path).length; break; }
        await pause(100);
      }
      assert(gets > 0 && gets <= LIMITS.sameIdGets,
        `${kind} same-ID browser recovery deadline`);
    }
    return { originalStatus: response.status(), resolvedStatus: 200,
      sameIdGets: gets, operationId: row.operation_id, sequence: row.sequence };
  };
  const awaitPost = kind => action(() => page.waitForResponse(response => {
    const url = new URL(response.url());
    return url.origin === origin && url.pathname === POST_PATHS[kind] &&
      response.request().method() === 'POST';
  }, { timeout: 15000 }));
  const requestListener = req => {
    const url = new URL(req.url());
    for (const [kind, route] of Object.entries(POST_PATHS))
      if (url.origin === origin && req.method() === 'POST' && url.pathname === route)
        seen[kind].push({ path: url.pathname, bearer: req.headers().authorization || null,
          body: req.postData() || '' });
  };
  const responseListener = response => {
    const url = new URL(response.url());
    if (url.origin === origin && /^\/api\/ctf\/operations\//.test(url.pathname))
      responses.push({ path: url.pathname, status: response.status() });
  };
  page.on('request', requestListener); page.on('response', responseListener);
  const result = { version: 1, profile: PROFILE, actorId: String(actorId),
    sessionId: String(sessionId), participantId: null, stageId: 1,
    siblingOwnerId: 1001, prerequisite: { hintGate: '0', source: 'pre-bootstrap-config',
      defaultAttemptGateProven: false }, browserPosts: null, serverPosts: null,
    operations: {}, startOperationIds: [], hintDialog: null, facts: {}, storeWitness: null,
    unexpectedApiPaths: [], browserActions: 0, apiRequests: 0,
    modelCalls: 0, judgeCalls: 0, genuineCredit: 0,
    excluded: [...EXCLUDED], stage: 'incomplete' };
  let other, primary;
  try {
    await action(() => page.evaluateOnNewDocument(token =>
      localStorage.setItem('token', token), bearer.slice(7)));
    await action(() => page.goto(origin + '/ctf', { waitUntil: 'domcontentloaded' }));
    const join = await wait(joinButton), registerBefore = await maxSequence();
    const registerReply = awaitPost('register'); await pointer(join);
    const registerResponse = await registerReply;
    const register = await outboxFor(i, c, registerBefore, 'register',
      String(actorId), String(sessionId));
    assert.equal(count('register'), 1);
    assert.equal(seen.register[0].bearer, bearer);
    const registerBody = JSON.parse(seen.register[0].body);
    assert.deepEqual(Object.keys(registerBody), ['displayName']);
    result.operations.register = await envelope('register', registerResponse, register);
    const registered = (await c.runtime.query('SELECT id::text FROM ctf.ctf_participants WHERE user_id=$1 AND is_active=1',
      [actorId])).rows;
    assert.equal(registered.length, 1); result.participantId = registered[0].id;
    const ownerBinding = (await i.migration.query(`SELECT owner_id::text,participant_id::text,active
      FROM identity.ctf_participant_bindings WHERE owner_id=$1`, [actorId])).rows;
    assert.deepEqual(ownerBinding, [{ owner_id: String(actorId),
      participant_id: result.participantId, active: true }]);
    const teachingToken = JSON.parse(register.canonical_command).body.teachingSessionToken;
    assert(typeof teachingToken === 'string' && teachingToken.length > 0);
    const session = (await c.runtime.query(`SELECT participant_id::text FROM ctf.ctf_sessions
      WHERE participant_id=$1 AND session_token=$2 AND is_active=1`,
    [result.participantId, teachingToken])).rows;
    assert.equal(session.length, 1);
    assert.equal(session[0].participant_id, result.participantId);
    const stageCard = await wait(stageOneCard), startBefore = await maxSequence();
    const startReply = awaitPost('start'); await pointer(stageCard);
    const startResponse = await startReply;
    const started = await outboxFor(i, c, startBefore, 'start', String(actorId),
      String(sessionId), result.participantId, 1);
    assert.equal(count('start'), 1);
    assert.equal(seen.start[0].bearer, bearer);
    assert.deepEqual(JSON.parse(seen.start[0].body), {});
    result.operations.start = await envelope('start', startResponse, started);
    const progress = async () => (await c.runtime.query(`SELECT id::text,participant_id::text,
      stage_id,status,hints_used,hint_penalty_total,attempts_count FROM ctf.ctf_progress
      WHERE participant_id=$1 AND stage_id=1`, [result.participantId])).rows;
    const initialProgress = await progress();
    assert.equal(initialProgress.length, 1);
    assert.equal(initialProgress[0].status, 'in_progress');
    assert.equal(initialProgress[0].hints_used, 0);
    assert.equal(initialProgress[0].attempts_count, 0);
    const hintOpen = async () => pointer(await wait(hintButton));
    await hintOpen(); await (await wait(hintDialog)).dispose();
    await clickText('[role="dialog"] button', 'Cancel');
    assert.equal(count('hint'), 0); assert.deepEqual(await progress(), initialProgress);
    await hintOpen(); await (await wait(hintDialog)).dispose();
    other = await action(() => page.browserContext().newPage());
    await action(() => other.setRequestInterception(true));
    other.on('request', request => {
      const url = new URL(request.url());
      if (url.origin === origin && request.method() === 'GET' &&
        url.pathname === '/api/ctf/config') return request.continue();
      return request.abort();
    });
    await action(() => other.goto(origin + '/api/ctf/config', { waitUntil: 'domcontentloaded' }));
    await action(() => page.evaluate(() => { window.__ctfLearnerAba = 0;
      window.addEventListener('storage', event => {
        if (event.key === 'token') window.__ctfLearnerAba++;
      }); }));
    await action(() => other.evaluate(([b, a]) => {
      localStorage.setItem('token', b); localStorage.setItem('token', a);
    }, [comparisonBearer.slice(7), bearer.slice(7)]));
    const observed = await action(() => page.waitForFunction(() =>
      window.__ctfLearnerAba >= 2, { timeout: 15000 })); await observed.dispose();
    const abaEventsObserved = await action(() => page.evaluate(() => window.__ctfLearnerAba));
    assert.equal(abaEventsObserved, 2);
    assert.equal(count('hint'), 0); assert.deepEqual(await progress(), initialProgress);
    await action(() => other.close()); other = null;
    // The challenge route's stage is navigation state, not a reloadable URL.
    // Return through the mounted dashboard and physically reopen its card.
    await action(() => page.goto(origin + '/ctf', { waitUntil: 'domcontentloaded' }));
    await pointer(await wait(stageOneCard));
    await hintOpen(); await (await wait(hintDialog)).dispose();
    const hintBefore = await maxSequence(), hintReply = awaitPost('hint');
    await clickText('[role="dialog"] button', 'Unlock (-15 pts)');
    const hintResponse = await hintReply;
    const hint = await outboxFor(i, c, hintBefore, 'hint', String(actorId),
      String(sessionId), result.participantId, 1);
    assert.equal(count('hint'), 1);
    assert.equal(seen.hint[0].bearer, bearer);
    assert.deepEqual(JSON.parse(seen.hint[0].body), { hintIndex: 0 });
    result.operations.hint = await envelope('hint', hintResponse, hint);
    const finalProgress = await progress(); assert.equal(finalProgress.length, 1);
    assert.equal(finalProgress[0].status, 'in_progress');
    assert.equal(finalProgress[0].hints_used, 1);
    assert.equal(finalProgress[0].hint_penalty_total, 15);
    assert.equal(finalProgress[0].attempts_count, 0);
    const earned = (await c.runtime.query(`SELECT total_score,total_stages_completed
      FROM ctf.ctf_leaderboard WHERE participant_id=$1`, [result.participantId])).rows;
    assert(earned.length <= 1);
    if (earned.length) assert.deepEqual(earned[0],
      { total_score: 0, total_stages_completed: 0 });
    const binding = (await i.migration.query(`SELECT participant_id::text,progress_id::text,
      hints_used,hint_penalty_total,attempts_count FROM identity.ctf_progress_bindings
      WHERE owner_id=$1 AND stage_id=1`, [actorId])).rows;
    assert.deepEqual(binding, [{ participant_id: result.participantId,
      progress_id: finalProgress[0].id, hints_used: 1,
      hint_penalty_total: 15, attempts_count: 0 }]);
    const after = await snapshotPeerAndHistory(i, c);
    assertPeerAndHistory(before, after);
    assert(count('start') >= 1 && count('start') <= 3,
      'Bounded automatic start after authority refresh required');
    let startCursor = register.sequence;
    for (let n = 0; n < count('start'); n++) {
      const observed = await outboxFor(i, c, startCursor, 'start', String(actorId),
        String(sessionId), result.participantId, 1);
      assert(BigInt(observed.sequence) < BigInt(hint.sequence));
      result.startOperationIds.push(observed.operation_id);
      startCursor = observed.sequence;
    }
    const startRows = (await i.migration.query(`SELECT count(*)::integer AS n
      FROM identity.ctf_outbox WHERE sequence>$1 AND kind='start' AND actor_id=$2`,
    [register.sequence, actorId])).rows[0].n;
    assert.equal(startRows, count('start'));
    const endServer = serverCounts();
    result.browserPosts = Object.fromEntries(Object.keys(POST_PATHS).map(k => [k, count(k)]));
    result.serverPosts = Object.fromEntries(Object.keys(POST_PATHS)
      .map(k => [k, endServer[k] - startServer[k]]));
    assert.equal(result.browserPosts.register, 1);
    assert.equal(result.browserPosts.hint, 1);
    assert.deepEqual(result.serverPosts, result.browserPosts);
    result.hintDialog = { cancelPosts: 0, abaPosts: 0, abaEventsObserved,
      cancelStateUnchanged: true, abaStateUnchanged: true };
    result.storeWitness = { ownerRegistered: true, stageStarted: true,
      oneHintPurchased: true, costApplied: true, siblingBeforeNonempty: true,
      siblingUnchanged: true, attemptsUnchanged: true, judgmentsUnchanged: true,
      siblingLeaderboardUnchanged: true };
    result.facts = Object.fromEntries(FACTS.map(key => [key, true]));
    result.browserActions = actions; result.apiRequests = apiRequests() - startApi;
    result.stage = 'complete'; assertLearnerEntryHintReceipt(result);
    return result;
  } catch (error) { primary = error; throw error; } finally {
    await retireLearnerListeners(page, other, requestListener, responseListener, primary);
  }
}

function assertPrivateReceipt(file) {
  const stat = fs.lstatSync(file), parent = fs.lstatSync(path.dirname(file));
  assert(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1 &&
    stat.uid === process.getuid() && (stat.mode & 0o777) === 0o600 &&
    stat.size > 0 && stat.size <= 65536);
  assert(parent.isDirectory() && !parent.isSymbolicLink() &&
    parent.uid === process.getuid() && (parent.mode & 0o777) === 0o700);
}

const LEARNER_APP_READS = new Set(['/api/auth/status', '/api/auth/signup-config',
  '/api/changes/revisions', '/api/workshop/challenges', '/api/workshop/time/summary',
  '/api/workshop/config', '/api/workshop/config/snapshot',
  '/api/workshop/config/revision', '/api/ctf/config', '/api/ctf/stages',
  '/api/ctf/status', '/api/ctf/leaderboard']);
function learnerBrowserAllowed(method, pathname, auxiliary = false) {
  if (auxiliary) return method === 'GET' && pathname === '/api/ctf/config';
  return method === 'GET' && (LEARNER_APP_READS.has(pathname) ||
    /^\/api\/ctf\/operations\/[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(pathname)) ||
    method === 'POST' && Object.values(POST_PATHS).includes(pathname);
}

async function runCtfLearnerEntryHintRenderedCases({ state, i, c, ledger, web,
  origin, jwtSecret, contentHttp, learnerHttp, userRequest, admin }) {
  assert.equal(process.env.CTF_LEARNER_ENTRY_HINT_RENDERED_ISOLATED, '1');
  const runtime = fs.realpathSync(process.env.CTF_CONTENT_RUNTIME_DIRECTORY);
  const receiptPath = path.resolve(process.env.CTF_LEARNER_ENTRY_HINT_Q05_RECEIPT);
  assert.equal(receiptPath, path.join(runtime, 'ctf-learner-entry-hint-q05-result.json'));
  if (state === 'POPULATED') {
    assertPrivateReceipt(receiptPath);
    assertLearnerEntryHintReceipt(JSON.parse(fs.readFileSync(receiptPath, 'utf8')));
    assert.equal(ledger.length, 0, 'POPULATED migration cannot invoke provider');
    return;
  }
  assert.equal(state, 'FRESH'); assert.equal(fs.existsSync(receiptPath), false);
  const evidence = fs.realpathSync(process.env.CTF_RENDERED_EVIDENCE);
  const originalEnv = {};
  for (const [key, value] of Object.entries({
    IDENTITY_DATABASE_URL: process.env.PG_CTF_AUTHORITY_APPLICATION_FRESH_IDENTITY_RUNTIME_URL,
    IDENTITY_MIGRATION_DATABASE_URL: process.env.PG_CTF_AUTHORITY_APPLICATION_FRESH_IDENTITY_MIGRATION_URL,
    JWT_SECRET: jwtSecret,
  })) { originalEnv[key] = process.env[key]; process.env[key] = value; }
  let mounted, browser, pages, page, primary, receipt, started = Date.now();
  const unexpected = [];
  const countApi = () => contentHttp.apiRequests;
  const countServer = () => ({ ...learnerHttp });
  const trackRequest = (request, auxiliary = false) => {
    const url = new URL(request.url());
    if (['data:', 'blob:', 'about:'].includes(url.protocol)) return request.continue();
    if (url.origin !== origin || request.method() !== 'GET' &&
      (auxiliary || !url.pathname.startsWith('/api/ctf/'))) {
      unexpected.push(`${request.method()} ${url.pathname}`); return request.abort();
    }
    if (url.pathname.startsWith('/api/') &&
      !learnerBrowserAllowed(request.method(), url.pathname, auxiliary)) {
      unexpected.push(`${request.method()} ${url.pathname}`); return request.abort();
    }
    return request.continue();
  };
  try {
    await require('../../../server/database/postgres/workshopPlatformSeed')
      .seedWorkshopPlatform(i.migration);
    const adapter = require('../../../server/services/postgresIdentityAdapter')
      .getPostgresIdentityAdapter();
    const stores = require('../../../server/services/postgresPlatformStores')
      .getPostgresPlatformStores();
    mounted = await require('../../fixtures/legacyFileSsiFullAppParity')
      .mountLegacyParityRoutes({ app: web, adapter, pool: i.runtime,
        migration: i.migration, progress: stores.progress,
        config: stores.config, identity: adapter.repository });
    const learnerId = 2401;
    assert.deepEqual((await i.migration.query('SELECT id FROM identity.users WHERE id=$1',
      [learnerId])).rows, [], 'Learner fixture identity must be fresh');
    await i.migration.query(`INSERT INTO identity.users(id,username,email,password,role)
      VALUES($1,$2,$3,$4,'student')`, [learnerId, 'learner-entry-hint-2401',
      'learner-entry-hint-2401@fixture.invalid', '$2b$04$' + 'a'.repeat(53)]);
    const learner = await userRequest(learnerId);
    const authority = await adapter.validateSession(learner.headers.authorization.slice(7));
    assert.equal(authority?.user?.id, learnerId);
    assert.equal(String(authority?.session?.id), String(learner.identitySession.id));
    assert.notEqual(learner.headers.authorization, admin.headers.authorization);
    await assertHintGate(c.runtime);
    const sibling = await snapshotPeerAndHistory(i, c);
    assert(sibling.siblingProgress.length && sibling.siblingAttempts.length &&
      sibling.siblingSessions.length, 'Prebootstrap sibling evidence required');
    const report = JSON.parse(fs.readFileSync(process.env.CTF_CONTENT_BUILD_REPORT, 'utf8'));
    const root = path.resolve(__dirname, '../../..');
    const expectedBuild = report.inputMode === 'private-external-v1'
      ? fs.realpathSync(report.outputRoot) : path.join(root, 'client/build');
    const build = fs.realpathSync(process.env.CTF_CONTENT_BUILD_DIRECTORY);
    assert.equal(build, expectedBuild); assert(fs.existsSync(path.join(build, 'index.html')));
    web.use('/api', (_request, response) => response.status(404)
      .json({ error: 'Unmapped learner API' }));
    web.use(require('express').static(build));
    web.get('/{*path}', (_request, response) => response.sendFile(path.join(build, 'index.html')));
    browser = await require('../../fixtures/ctfTenContentBrowserAdmission')
      .launchCtfLearnerBrowser(evidence, 'learner');
    pages = content.contentActorPages(browser);
    page = await pages.newPage();
    await page.setViewport({ width: 1280, height: 900 });
    await page.setRequestInterception(true);
    page.on('request', request => trackRequest(request));
    receipt = await runCtfLearnerEntryHintFacet({ page, origin,
      bearer: learner.headers.authorization,
      comparisonBearer: admin.headers.authorization,
      actorId: learner.user.id, sessionId: learner.identitySession.id,
      i, c, serverCounts: countServer, apiRequests: countApi, ledger });
    assert.deepEqual(unexpected, []);
    assert(Date.now() - started <= LIMITS.deadlineMs);
  } catch (error) { primary = error; throw error; } finally {
    const failures = [];
    for (const close of [() => pages?.close(), () => browser?.close(),
      () => mounted?.close()]) {
      try { await close(); } catch (error) { failures.push(error); }
    }
    for (const [key, value] of Object.entries(originalEnv)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
    if (failures.length) throw new AggregateError(primary ? [primary, ...failures] : failures,
      'Learner rendered cleanup incomplete', { cause: primary });
  }
  assert(receipt && receipt.stage === 'complete');
  fs.writeFileSync(receiptPath, JSON.stringify(receipt, null, 2),
    { flag: 'wx', mode: 0o600 });
  assertPrivateReceipt(receiptPath);
  assertLearnerEntryHintReceipt(JSON.parse(fs.readFileSync(receiptPath, 'utf8')));
}

module.exports = { PROFILE, POST_PATHS, FACTS, EXCLUDED, LIMITS,
  learnerApiAllowed, learnerBrowserAllowed, assertLearnerDatabaseName,
  assertPrivateReceipt, assertLearnerEntryHintReceipt, seedHintGateBeforeBootstrap,
  assertHintGate, outboxFor, snapshotPeerAndHistory, assertPeerAndHistory,
  joinButton, stageOneCard, hintButton, hintDialog, retireLearnerListeners,
  runCtfLearnerEntryHintFacet, runCtfLearnerEntryHintRenderedCases };
