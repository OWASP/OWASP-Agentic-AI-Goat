'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { assertFullResetReceipt, createFullResetServerWitness,
  createFullResetResponseLoss, validServerBody, assertNonvacuousResetSeed,
  assertFullResetTerminal, CLEARED, RETAINED, IMMUTABLE_BOOTSTRAP, POST_PATH, TOKEN } =
  require('./support/ctfFullResetRenderedCases');

const operationId = '10000000-0000-0000-0000-000000000001';
const receipt = () => ({
  version: 2, profile: 'ctf-full-reset-q05', modelCalls: 0, judgeCalls: 0,
  actorId: '500', sessionId: '900', path: POST_PATH, dialogAbaEventsObserved: 2,
  requestCounts: { wrongToken: 0, cancel: 0, dialogAba: 0, browserPost: 1,
    serverPost: 1, browserFailed: 1, browserFinished: 0, serverFinished: 1 },
  responseStage: { paused: 1, failed: 1, continued: 0 },
  serverResponse: { status: 200, body: { message: 'CTF reset successfully' },
    lossPhase: 'after-real-http-response-before-browser-consumption' },
  operation: { operationId, sequence: '10', removedParticipants: 2, sameIdHarnessGets: 0 },
  pre: { clearedRows: Object.fromEntries(CLEARED.map(table => [table, table === 'ctf_participants' ? 2 : 1])),
    retainedRows: Object.fromEntries(RETAINED.map(table => [table, 1])),
    immutableBootstrapRows: Object.fromEntries(IMMUTABLE_BOOTSTRAP.map(table => [table, 1])),
    mutableIdentityMemoryRows: { technique: 1, payload: 1 } },
  facts: { wrongTokenNoPost: true, cancelNoPost: true, cancelNoEffect: true,
    dialogAbaNoPost: true, dialogAbaNoEffect: true, onePhysicalPost: true,
    capturedAuthorityAndBody: true, canonicalOperationApplied: true,
    removedCountMatches: true, mutableCtfCleared: true, mutableIdentityMemoryCleared: true,
    retainedCtfUnchanged: true,
    historicalIdentityEvidencePreserved: true, platformAndWorkshopSiblingPreserved: true,
    unknownUiNoReference: true, noAutomaticRetry: true },
  excluded: ['browser-acknowledged-success', 'browser-operation-id-recovery',
    'ctf-sibling-preservation', 'ban-deletion', 'judgment-deletion', 'immutable-evidence-deletion',
    'model-grading', 'full-Q05-denominator'],
  unexpectedApiPaths: [], stage: 'complete',
});
const changed = edit => { const r = structuredClone(receipt()); edit(r); return r; };

test('separate Full Reset receipt requires bounded actual effects and names exclusions', () => {
  assert.equal(assertFullResetReceipt(receipt()), true);
  assert.equal(POST_PATH, '/api/ctf/admin/reset');
  assert.equal(TOKEN, 'RESET_CTF_CONFIRM');
  assert(CLEARED.includes('ctf_participants') && CLEARED.includes('ctf_payload_blocklist'));
  assert(RETAINED.includes('ctf_bans') && RETAINED.includes('ctf_judgments'));
  const pending = changed(r => {
    r.serverResponse.status = 202;
    r.serverResponse.body = { success: false, pending: true, operationId,
      message: 'CTF operation is pending. No completion is being reported.' };
    r.operation.sameIdHarnessGets = 1;
  });
  assert.equal(assertFullResetReceipt(pending), true);
});

test('missing effects, fake browser recovery, duplicate requests, or invented scope fail closed', () => {
  for (const edit of [
    r => { r.facts.cancelNoEffect = false; }, r => { r.facts.dialogAbaNoPost = false; },
    r => { r.dialogAbaEventsObserved = 1; },
    r => { r.facts.mutableCtfCleared = false; }, r => { r.facts.retainedCtfUnchanged = false; },
    r => { r.facts.mutableIdentityMemoryCleared = false; },
    r => { r.facts.historicalIdentityEvidencePreserved = false; },
    r => { r.facts.platformAndWorkshopSiblingPreserved = false; },
    r => { r.facts.unknownUiNoReference = false; }, r => { r.facts.noAutomaticRetry = false; },
    r => { r.requestCounts.wrongToken = 1; }, r => { r.requestCounts.cancel = 1; },
    r => { r.requestCounts.dialogAba = 1; }, r => { r.requestCounts.browserPost = 2; },
    r => { r.requestCounts.serverPost = 2; }, r => { r.requestCounts.browserFinished = 1; },
    r => { r.responseStage.failed = 0; }, r => { r.responseStage.continued = 1; },
    r => { r.pre.clearedRows.ctf_attempts = 0; },
    r => { r.pre.retainedRows.ctf_bans = 0; },
    r => { r.pre.retainedRows.ctf_judgments = 0; },
    r => { r.pre.immutableBootstrapRows.pages = 0; },
    r => { r.pre.mutableIdentityMemoryRows.payload = 0; },
    r => { r.version = 1; },
    r => { r.operation.removedParticipants = 0; },
    r => { r.operation.removedParticipants = 1; },
    r => { r.operation.sameIdHarnessGets = 1; },
    r => { r.serverResponse.status = 202; },
    r => { r.serverResponse.body.message = 'Different outcome'; },
    r => { r.excluded = []; }, r => { r.unexpectedApiPaths.push('/api/other'); },
    r => { r.unexpectedField = true; },
  ]) assert.throws(() => assertFullResetReceipt(changed(edit)));
});

test('nonvacuous pre-reset witness requires every cleared table and retained ban/judgment rows', () => {
  const value = { cleared: Object.fromEntries(CLEARED.map(table => [table, [{ value: table }]])),
    retained: Object.fromEntries(RETAINED.map(table => [table, [{ value: table }]])),
    immutableBootstrap: Object.fromEntries(IMMUTABLE_BOOTSTRAP.map(table => [table, [{ value: table }]])),
    adaptiveMemory: { technique: [{ value: 'technique' }], payload: [{ value: 'payload' }] } };
  assert.deepEqual(assertNonvacuousResetSeed(value), {
    clearedRows: Object.fromEntries(CLEARED.map(table => [table, 1])),
    retainedRows: Object.fromEntries(RETAINED.map(table => [table, 1])),
    immutableBootstrapRows: Object.fromEntries(IMMUTABLE_BOOTSTRAP.map(table => [table, 1])),
    mutableIdentityMemoryRows: { technique: 1, payload: 1 },
  });
  for (const table of CLEARED) {
    const missing = structuredClone(value); missing.cleared[table] = [];
    assert.throws(() => assertNonvacuousResetSeed(missing), /populated/);
  }
  for (const table of ['ctf_bans', 'ctf_judgments']) {
    const missing = structuredClone(value); missing.retained[table] = [];
    assert.throws(() => assertNonvacuousResetSeed(missing), /populated/);
  }
  for (const table of IMMUTABLE_BOOTSTRAP) {
    const missing = structuredClone(value); missing.immutableBootstrap[table] = [];
    assert.throws(() => assertNonvacuousResetSeed(missing), /populated/);
  }
  for (const kind of ['technique', 'payload']) {
    const missing = structuredClone(value); missing.adaptiveMemory[kind] = [];
    assert.throws(() => assertNonvacuousResetSeed(missing), /populated/);
  }
});

test('terminal observer rejects late wrong-route mutation, retained-row drift, and provider use', async () => {
  const after = { retained: [{ table: 'ctf_bans', value: 'unchanged' }], outbox: ['original', 'reset'] };
  const outsideAfter = { platform: { user: 'retained' }, workshopSibling: { progress: 'retained' } };
  const seen = { posts: 1, paths: [POST_PATH], mutations: [`POST ${POST_PATH}`],
    body: [{ value: { confirm: TOKEN }, bearer: 'Bearer mounted-admin' }] };
  const ledger = [];
  let current = structuredClone(after);
  const input = { instructor: { isClosed: () => true }, seen,
    serverWitness: { snapshot: () => ({ requests: 1, responses: 1, finished: 1, status: 200,
      body: { message: 'CTF reset successfully' }, invalid: false }) },
    ledger, snapshot: async () => current, externalSnapshot: async () => outsideAfter,
    after, outsideAfter, unexpectedApiPaths: [], tokenA: 'mounted-admin' };
  assert.equal((await assertFullResetTerminal(input)).requests, 1);
  seen.mutations.push('PUT /api/ctf/admin/stages/2');
  await assert.rejects(assertFullResetTerminal(input), /Unexpected or replayed browser mutation/);
  seen.mutations.pop();
  current = { ...after, retained: [{ table: 'ctf_bans', value: 'late change' }] };
  await assert.rejects(assertFullResetTerminal(input), /Late CTF\/identity state drift/);
  current = after;
  ledger.push({ kind: 'provider call' });
  await assert.rejects(assertFullResetTerminal(input), /must not invoke a provider/);
  ledger.pop();
  await assert.rejects(assertFullResetTerminal({ ...input, instructor: { isClosed: () => false } }),
    /must retire before final proof/);
});

test('server witness observes original Express json response passively and rejects malformed outcomes', async () => {
  const witness = createFullResetServerWitness();
  const req = { method: 'POST', path: POST_PATH };
  const res = new EventEmitter();
  res.statusCode = 200;
  let returned = false, forwarded = null;
  res.json = function (body) { forwarded = body; return this; };
  witness.middleware(req, res, () => { returned = true; });
  assert.equal(returned, true);
  const body = { message: 'CTF reset successfully' };
  assert.equal(res.json(body), res);
  assert.equal(forwarded, body);
  res.emit('finish');
  assert.deepEqual(witness.snapshot(), {
    requests: 1, responses: 1, finished: 1, status: 200, body, invalid: false,
  });
  const bad = createFullResetServerWitness();
  const another = new EventEmitter(); another.statusCode = 200; another.json = value => value;
  bad.middleware(req, another, () => {});
  assert.deepEqual(another.json({ message: 'CTF reset successfully', invented: true }),
    { message: 'CTF reset successfully', invented: true });
  assert.equal(bad.snapshot().invalid, true);
  assert.equal(validServerBody(200, { message: 'CTF reset successfully' }), true);
  assert.equal(validServerBody(200, { message: 'CTF reset successfully', extra: 1 }), false);
});

test('response-stage loss matches one exact genuine endpoint and continues mismatches and repeats', async () => {
  class Session extends EventEmitter {
    sent = [];
    async send(method, args) { this.sent.push({ method, args }); }
    async detach() { this.detached = true; }
  }
  const session = new Session();
  const loss = createFullResetResponseLoss({ session, origin: 'http://127.0.0.1:1234' });
  await loss.start();
  const emit = (id, url, method, status) => session.emit('Fetch.requestPaused', {
    requestId: id, request: { url, method }, responseStatusCode: status,
  });
  emit('wrong-origin', 'http://127.0.0.1:1235' + POST_PATH, 'POST', 200);
  emit('wrong-method', 'http://127.0.0.1:1234' + POST_PATH, 'GET', 200);
  emit('wrong-path', 'http://127.0.0.1:1234/api/ctf/admin/participants/reset', 'POST', 200);
  emit('pre-response', 'http://127.0.0.1:1234' + POST_PATH, 'POST', undefined);
  emit('exact', 'http://127.0.0.1:1234' + POST_PATH, 'POST', 200);
  emit('duplicate', 'http://127.0.0.1:1234' + POST_PATH, 'POST', 200);
  await loss.stop();
  assert.deepEqual(loss.observations, { paused: 1, failed: 1, continued: 5 });
  assert.deepEqual(session.sent.filter(x => x.method === 'Fetch.failRequest').map(x => x.args.requestId), ['exact']);
  assert.equal(session.sent.filter(x => x.method === 'Fetch.continueRequest').length, 5);
  assert.equal(session.detached, true);
});

test('response-stage observer rejects a non-success response before claiming ACK loss', async () => {
  class Session extends EventEmitter {
    sent = [];
    async send(method, args) { this.sent.push({ method, args }); }
    async detach() { this.detached = true; }
  }
  const session = new Session();
  const loss = createFullResetResponseLoss({ session, origin: 'http://127.0.0.1:1234' });
  await loss.start();
  session.emit('Fetch.requestPaused', { requestId: 'rejected',
    request: { url: 'http://127.0.0.1:1234' + POST_PATH, method: 'POST' },
    responseStatusCode: 409 });
  await assert.rejects(loss.stop());
  assert.equal(loss.observations.failed, 0);
  assert.equal(session.detached, true);
});
