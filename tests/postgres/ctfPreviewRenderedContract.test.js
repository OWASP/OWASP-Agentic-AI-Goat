'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {
  FACTS, EXCLUDED, LIMITS, assertPreviewDatabaseName, assertPreviewProviderReservation,
  reservePreviewProvider,
  seedPreviewSiblingHistoryBeforeBootstrap, assertPreviewSiblingHistory,
  previewApiAllowed, previewReadinessSummary, waitPreviewRow, currentPreviewBearer,
  heldPreviewDoubleClick, snapshotPrivateStores,
  assertCtfPreviewReceipt,
  assertExactStoreTransition, immutableWitness, previewRow, previewButton, previewDialog,
} = require('./support/ctfPreviewRenderedCases');

test('Preview sibling history is seeded before canonical bootstrap and only read after activation', async () => {
  const source = fs.readFileSync(path.join(__dirname, 'ctfAuthorityApplication.integration.test.js'), 'utf8');
  const seeded = source.indexOf('.seedPreviewSiblingHistoryBeforeBootstrap(c.migration)');
  const prepared = source.indexOf("const lost=lostPreparationCommit(c.migration)");
  const activated = source.indexOf('let activated=await operator.activate(');
  const rendered = source.indexOf(".runCtfPreviewRenderedCases({t,state,i,c,request,admin,ledger,web,");
  assert(seeded > 0 && seeded < prepared && prepared < activated && activated < rendered);
  assert(source.includes("if(previewOnly&&state==='FRESH')await require('./support/ctfPreviewRenderedCases')"));
  const calls = [];
  const migration = { query: async sql => { calls.push(sql); return { rows: [] }; } };
  await seedPreviewSiblingHistoryBeforeBootstrap(migration);
  assert.deepEqual(calls.map(sql => sql.match(/^INSERT INTO (ctf\.[a-z_]+)/)?.[1]),
    ['ctf.ctf_progress', 'ctf.ctf_attempts', 'ctf.ctf_sessions']);
  const readbacks = [
    [{ participant_id: 1001, stage_id: 2, status: 'completed', completion_time: '60000', attempts_count: 1 }],
    [{ participant_id: 1001, stage_id: 2, attempt_number: 1, payload: 'owned sibling preview history', ai_response: 'owned sibling response' }],
    [{ participant_id: 1001, session_token: 'owned-preview-sibling', is_active: 1, total_active_time: 1000 }],
  ];
  calls.length = 0;
  await assertPreviewSiblingHistory({ query: async sql => {
    calls.push(sql); return { rows: readbacks.shift() };
  } });
  assert.equal(readbacks.length, 0);
  assert(calls.every(sql => sql.startsWith('SELECT ')));
  await assert.rejects(assertPreviewSiblingHistory({ query: async () => ({ rows: [] }) }));
  const activeHelper = fs.readFileSync(path.join(__dirname, 'support/ctfPreviewRenderedCases.js'), 'utf8')
    .split('async function runCtfPreviewRenderedCases(')[1];
  assert(activeHelper);
  assert(!/c\.migration\.query\(["'`]INSERT INTO ctf\.ctf_(?:progress|attempts|sessions)/.test(activeHelper));
});

function receipt() {
  return { version: 1, profile: 'ctf-preview-q05', targetStageId: 1, siblingStageId: 2,
    mountedActorId: '1002', mountedSessionId: '3002',
    cases: {
      cancel: { browserPosts: 0, serverPosts: 0, providerStarts: 0,
        uiPublished: false, stateInvariant: true },
      dialogAba: { browserPosts: 0, serverPosts: 0, providerStarts: 0,
        uiPublished: false, stateInvariant: true, eventsObserved: 2 },
      singleFlight: { browserPosts: 1, serverPosts: 1, providerStarts: 1,
        uiPublished: true, stateInvariant: true, status: 200 },
      postDispatchClose: { browserPosts: 1, serverPosts: 1, providerStarts: 1,
        uiPublished: false, stateInvariant: true, clientAborted: true },
    },
    providerDiagnostics: { kind: 'controlled-synthetic-transport',
      physicalStarted: 2, completed: 1, clientAborted: 1, maxPhysicalCalls: 2 },
    storeWitness: { targetStageUnchanged: true, siblingStageUnchanged: true,
      progressUnchanged: true, attemptsUnchanged: true, judgmentsUnchanged: true,
      historyUnchanged: true, outboxUnchanged: true },
    facts: Object.fromEntries(FACTS.map(key => [key, true])), excluded: [...EXCLUDED],
    unexpectedApiPaths: [], browserActions: 40, apiRequests: 60,
    stage: 'complete', judgeCalls: 0, genuineCredit: 0 };
}
const tamper = change => { const value = receipt(); change(value);
  assert.throws(() => assertCtfPreviewReceipt(value)); };

test('Preview receipt is distinct, bounded, and explicitly not model qualification', () => {
  assert.equal(assertCtfPreviewReceipt(receipt()), true);
  assert.equal(LIMITS.providerCalls, 2);
  assert.equal(LIMITS.browserActions, 1200);
  assert.equal(LIMITS.apiRequests, 1200);
  assert.equal(LIMITS.deadlineMs, 360000);
  assert(EXCLUDED.includes('model-qualification'));
  assert(EXCLUDED.includes('gameplay-credit'));
});

test('Preview synthetic provider reservation fails before a third physical dispatch', () => {
  assert.doesNotThrow(() => assertPreviewProviderReservation([]));
  assert.doesNotThrow(() => assertPreviewProviderReservation([{ settlement: 'completed' }]));
  assert.throws(() => assertPreviewProviderReservation([
    { settlement: 'completed' }, { settlement: 'client-aborted' }]));
  assert.throws(() => assertPreviewProviderReservation({ length: 0 }));
});

test('Preview three concurrent arrivals reserve at most two before asynchronous body reads', async () => {
  const ledger = [];
  const arrivals = Array.from({ length: 3 }, (_, index) => (async () => {
    const entry = reservePreviewProvider(ledger, { index, settlement: 'started' });
    await Promise.resolve(); // Body parsing yields only after the synchronous reservation.
    return entry;
  })());
  const result = await Promise.allSettled(arrivals);
  assert.deepEqual(result.map(row => row.status), ['fulfilled', 'fulfilled', 'rejected']);
  assert.deepEqual(ledger.map(row => row.index), [0, 1]);
});

test('Preview request admission allows only finite reads and the single stage-one Preview POST', () => {
  assert.equal(previewApiAllowed('GET', '/api/auth/status'), true);
  assert.equal(previewApiAllowed('GET', '/api/changes/revisions'), true);
  assert.equal(previewApiAllowed('GET', '/api/ctf/admin/stages'), true);
  const preload = ['/api/admin/pi-workshop/solutions',
    '/api/admin/xss-workshop/objective-solutions',
    '/api/admin/csrf-workshop/objective-solutions',
    '/api/admin/finflow-workshop/solutions',
    '/api/admin/supply-chain-workshop/solutions',
    '/api/admin/ea-workshop/solutions',
    '/api/admin/ipi-workshop/solutions',
    '/api/admin/mcp-workshop/solutions',
    '/api/admin/sql-injection-workshop/solutions',
    '/api/admin/nosql-injection-workshop/solutions'];
  assert.equal(preload.length, 10);
  for (const pathname of preload) {
    assert.equal(previewApiAllowed('GET', pathname), true);
    assert.equal(previewApiAllowed('POST', pathname), false);
    assert.equal(previewApiAllowed('GET', `${pathname}/preview/1`), false);
  }
  assert.equal(previewApiAllowed('POST', '/api/ctf/admin/stages/1/preview'), true);
  for (const [method, pathname] of [['POST', '/api/ctf/heartbeat'],
    ['POST', '/api/ctf/stage/1/start'], ['POST', '/api/ctf/stage/1/hint'],
    ['POST', '/api/ctf/admin/participants/3011/reset'],
    ['POST', '/api/ctf/admin/stages/2/preview'],
    ['PUT', '/api/ctf/admin/stages/2'], ['DELETE', '/api/ctf/admin/stages/2']]) {
    assert.equal(previewApiAllowed(method, pathname), false, `${method} ${pathname}`);
  }
  assert.equal(previewApiAllowed('GET', '/api/ctf/config', true), true);
  assert.equal(previewApiAllowed('POST', '/api/ctf/admin/stages/1/preview', true), false);
  assert.equal(previewApiAllowed('GET', '/api/ctf/admin/stages', true), false);
});

test('Preview roster timeout diagnostic contains only bounded tab, counts, and HTTP status', () => {
  assert.deepEqual(previewReadinessSummary({ activeTab: 'levels', rowCount: 0, token: 'private' },
    { requests: 2, statuses: [200, 403], failures: 1, payload: 'private' }),
  { activeTab: 'levels', rowCount: 0, rosterRequests: 2,
    rosterStatuses: [200, 403], rosterFailures: 1 });
  assert.deepEqual(previewReadinessSummary({ activeTab: 'secret', rowCount: 9000 },
    { requests: 9000, statuses: [200, 'secret', 700], failures: -4 }),
  { activeTab: 'unknown', rowCount: -1, rosterRequests: 1200,
    rosterStatuses: [200], rosterFailures: 0 });
});

test('Preview row timeout retains original failure and writes bounded readiness', async () => {
  const timeout = Error('original wait timeout');
  const receiptValue = {};
  let saves = 0;
  const page = { evaluate: async () => ({ activeTab: 'levels', rowCount: 0, token: 'private' }) };
  const wait = async () => { throw timeout; };
  await assert.rejects(waitPreviewRow(page, wait, fn => fn(), receiptValue,
    { requests: 1, statuses: [200], failures: 0 }, () => { saves++; }), error => error === timeout);
  assert.equal(saves, 1);
  assert.deepEqual(receiptValue.readiness, { activeTab: 'levels', rowCount: 0,
    rosterRequests: 1, rosterStatuses: [200], rosterFailures: 0 });
  page.evaluate = async () => { throw Error('page already retired'); };
  await assert.rejects(waitPreviewRow(page, wait, fn => fn(), receiptValue,
    { requests: 1, statuses: [], failures: 1 }, () => { saves++; }), error => error === timeout);
  assert.deepEqual(receiptValue.readiness, { activeTab: 'unavailable', rowCount: -1,
    rosterRequests: 1, rosterStatuses: [], rosterFailures: 1 });
});

test('Preview captures refreshed bearer only under the same mounted actor and session', async () => {
  let token = 'initial-token';
  const page = { evaluate: async () => token };
  const action = fn => fn();
  const adapter = { validateSession: async current => current === 'foreign-token'
    ? { user: { id: 3 }, session: { id: 9 } }
    : { user: { id: 2 }, session: { id: 9 } } };
  assert.deepEqual(await currentPreviewBearer(page, action, adapter, '2', '9'),
    { token, bearer: 'Bearer initial-token' });
  token = 'renewed-token';
  assert.deepEqual(await currentPreviewBearer(page, action, adapter, '2', '9'),
    { token, bearer: 'Bearer renewed-token' });
  token = 'foreign-token';
  await assert.rejects(currentPreviewBearer(page, action, adapter, '2', '9'));
  token = '';
  await assert.rejects(currentPreviewBearer(page, action, adapter, '2', '9'));
});

test('Preview second physical click occurs while the first provider response is held', async () => {
  const order = [];
  let start;
  const started = new Promise(resolve => { start = resolve; });
  await heldPreviewDoubleClick(async () => { order.push('first'); start(); }, started,
    async () => { order.push('second-before-release'); }, () => order.push('release'));
  assert.deepEqual(order, ['first', 'second-before-release', 'release']);
  const failure = [];
  await assert.rejects(heldPreviewDoubleClick(async () => { throw Error('first click failed'); },
    Promise.resolve(), async () => failure.push('second'), () => failure.push('release')));
  assert.deepEqual(failure, ['release']);
});

test('Preview raw snapshot includes graph events as well as runs and effects', async () => {
  const queries = [];
  const pool = { query: async sql => { queries.push(sql); return { rows: [] }; } };
  const result = await snapshotPrivateStores({ migration: pool }, { migration: pool });
  assert.deepEqual(result['graph_runtime.events'], []);
  assert(queries.some(sql => sql.includes('FROM graph_runtime.events t')));
});

test('Preview receipt rejects invented credit, provider overrun, false readback or mutable paths', () => {
  tamper(r => { r.providerDiagnostics.physicalStarted = 3; });
  tamper(r => { r.providerDiagnostics.completed = 2; });
  tamper(r => { r.providerDiagnostics.clientAborted = 0; });
  tamper(r => { r.providerDiagnostics.kind = 'actual-model'; });
  tamper(r => { r.cases.singleFlight.browserPosts = 2; });
  tamper(r => { r.cases.singleFlight.providerStarts = 0; });
  tamper(r => { r.cases.postDispatchClose.uiPublished = true; });
  tamper(r => { r.cases.postDispatchClose.clientAborted = false; });
  tamper(r => { r.cases.dialogAba.eventsObserved = 1; });
  tamper(r => { r.storeWitness.outboxUnchanged = false; });
  tamper(r => { r.facts.stage1NoLanguageOrOutputDefense = false; });
  tamper(r => { r.unexpectedApiPaths.push('/api/ctf/admin/config'); });
  tamper(r => { r.judgeCalls = 1; });
  tamper(r => { r.genuineCredit = 1; });
  tamper(r => { r.modelCalls = 0; });
  tamper(r => { r.targetStageId = 2; });
  tamper(r => { r.excluded.pop(); });
  tamper(r => { r.browserActions = 1201; });
  tamper(r => { r.apiRequests = 1201; });
  tamper(r => { r.stage = 'postflight'; });
});

test('Preview database names bind FRESH/POPULATED identity and CTF to one nonce', () => {
  const nonce = 'a1b2c3d4e5f6';
  for (const state of ['FRESH', 'POPULATED']) for (const kind of ['IDENTITY', 'CTF']) {
    const name = `/dvaia_test_ctf_preview_${state[0].toLowerCase()}_${kind[0].toLowerCase()}_${nonce}`;
    assert.equal(assertPreviewDatabaseName(name, state, kind, nonce), nonce);
    assert.throws(() => assertPreviewDatabaseName(name, state, kind, 'ffffffffffff'));
    assert.throws(() => assertPreviewDatabaseName(name, state === 'FRESH' ? 'POPULATED' : 'FRESH', kind, nonce));
    assert.throws(() => assertPreviewDatabaseName(name, state, kind === 'CTF' ? 'IDENTITY' : 'CTF', nonce));
    assert.throws(() => assertPreviewDatabaseName(name.replace('_preview_', '_config_'), state, kind, nonce));
    assert.throws(() => assertPreviewDatabaseName(name + 'x', state, kind, nonce));
  }
});

test('Preview store witness requires exact raw row equality, not matching counts', () => {
  const before = { 'ctf.ctf_stages': ['{"id":1,"name":"The Doorway"}'],
    'identity.ctf_outbox': [], 'ctf.ctf_progress': ['{"owner":1001,"score":1}'] };
  const equal = structuredClone(before);
  assert.equal(assertExactStoreTransition(before, equal), true);
  assert(Object.values(immutableWitness(before, equal)).every(Boolean));
  equal['ctf.ctf_progress'][0] = '{"owner":1001,"score":2}';
  assert.throws(() => assertExactStoreTransition(before, equal));
  assert.throws(() => immutableWitness(before, equal));
});

test('Preview physical DOM predicates identify only exact mounted stage, modal and controls', () => {
  const row = { cells: [{ textContent: '1' }, { textContent: 'The Doorway' }], getClientRects: () => [1] };
  const wrong = { cells: [{ textContent: '2' }, { textContent: 'Simple Guard' }], getClientRects: () => [1] };
  const button = { textContent: 'Preview', getClientRects: () => [1], disabled: false };
  const textarea = { getClientRects: () => [1] };
  const label = { textContent: 'Test Payload', parentElement: { querySelector: () => textarea } };
  const run = { textContent: 'Run Preview', getClientRects: () => [1],
    getAttribute: () => null, disabled: false };
  const close = { textContent: '', getAttribute: name => name === 'aria-label' ? 'Close' : null, disabled: false };
  const dialog = { getClientRects: () => [1], querySelector: () => ({ textContent: 'Disclosure Preview: The Doorway' }),
    querySelectorAll: name => name === 'label' ? [label] : name === 'button' ? [run, close] : [] };
  const context = { document: { querySelectorAll: name => name === 'table tbody tr' ? [wrong, row]
    : name === 'button' ? [button] : name === '[role="dialog"]' ? [dialog] : [] } };
  assert.equal(vm.runInNewContext(`(${previewRow.toString()})()`, context), row);
  assert.equal(vm.runInNewContext(`(${previewButton.toString()})()`, context), button);
  assert.equal(vm.runInNewContext(`(${previewDialog.toString()})()`, context), dialog);
  context.document.querySelectorAll = name => name === 'table tbody tr' ? [wrong]
    : name === 'button' ? [{ ...button, textContent: 'Save' }]
      : name === '[role="dialog"]' ? [{ ...dialog,
        querySelector: () => ({ textContent: 'Disclosure Preview: Simple Guard' }) }] : [];
  assert.equal(vm.runInNewContext(`(${previewRow.toString()})()`, context), null);
  assert.equal(vm.runInNewContext(`(${previewButton.toString()})()`, context), null);
  assert.equal(vm.runInNewContext(`(${previewDialog.toString()})()`, context), null);
});
