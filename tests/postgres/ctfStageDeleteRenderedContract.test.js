'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { JSDOM } = require('../../client/node_modules/jsdom');
const { assertStageDeleteReceipt, assertOwnedStageSelection, exactPhysicalStageDelete,
  recoverSameOperation, cleanupOwnedStage, validatedBearer, assessStageDeleteReadback,
  retireStageDeleteListeners, assertOwnedCreateResponse, assertOwnedStartResponse,
  recordStageDeleteConfirmation, openStageDeleteReview, FACTS } =
  require('./support/ctfStageDeleteRenderedCases');

const uuid = n => `${String(n).padStart(8, '0')}-0000-4000-8000-000000000001`;
const op = (n, seq, message) => ({ originalStatus: 200, resolvedStatus: 200,
  sameIdGets: 0, operationId: uuid(n), sequence: String(seq),
  browserAckOperationId: null, ackMessage: message });
const valid = () => ({ version: 1, profile: 'ctf-stage-delete-q05', stageNumber: 11,
  stageOrder: 0, targetStageId: 14, mountedActorId: '1002', mountedSessionId: '81',
  learnerActorId: '3011', learnerSessionId: '82',
  observedPath: '/api/ctf/admin/stages/14', browserDeletes: 1,
  setup: { create: op(1, 41, 'Stage created'),
    start: op(2, 43, 'Stage started successfully') },
  confirmed: op(3, 44, 'Stage deleted'),
  dialogTimeAba: { eventsObserved: 2, noDelete: true },
  preProgressRows: 1, preEventRows: 1,
  facts: Object.fromEntries(FACTS.map(name => [name, true])),
  excluded: ['attempts-nonvacuity', 'judgment-deletion', 'model-qualification',
    'byte-identical-database-undo'], unexpectedApiPaths: [], stage: 'complete',
  modelCalls: 0, judgeCalls: 0 });

test('receipt binds a distinct owned stage, real start, one delete, and nonvacuous cascade', () => {
  assert.equal(assertStageDeleteReceipt(valid()), true);
  for (const [index, change] of [
    r => { r.stageNumber = 10; }, r => { r.stageOrder = 1; },
    r => { r.targetStageId = 10; }, r => { r.browserDeletes = 2; },
    r => { r.observedPath = '/api/ctf/admin/stages/1'; },
    r => { r.dialogTimeAba.eventsObserved = 1; },
    r => { r.preProgressRows = 0; }, r => { r.preEventRows = 0; },
    r => { r.facts.progressAndEventCascaded = false; },
    r => { r.facts.identityBindingTombstoned = false; },
    r => { r.facts.canonicalTenAndSiblingPreserved = false; },
    r => { r.facts.historyPreserved = false; },
    r => { r.confirmed.operationId = r.setup.create.operationId; },
    r => { r.confirmed.sequence = r.setup.start.sequence; },
    r => { r.modelCalls = 1; }, r => { r.judgeCalls = 1; },
    r => { r.unexpectedApiPaths = [{ method: 'DELETE', path: '/api/ctf/admin/stages/1' }]; },
    r => { r.unknown = true; },
  ].entries()) { const changed = structuredClone(valid()); change(changed);
    assert.throws(() => assertStageDeleteReceipt(changed), `mutation ${index}`); }
});

test('pending operation requires bounded genuine same-ID GET, no second mutation', async () => {
  const receipt = valid();
  receipt.confirmed = { originalStatus: 202, resolvedStatus: 200, sameIdGets: 1,
    operationId: uuid(3), sequence: '44', browserAckOperationId: uuid(3), ackMessage: null };
  assert.equal(assertStageDeleteReceipt(receipt), true);
  receipt.confirmed.sameIdGets = 0;
  assert.throws(() => assertStageDeleteReceipt(receipt));
  receipt.confirmed.sameIdGets = 1;
  receipt.confirmed.browserAckOperationId = uuid(7);
  assert.throws(() => assertStageDeleteReceipt(receipt));
  const calls = [];
  assert.equal(await recoverSameOperation({ operationId: uuid(3), req: { owned: true },
    now: () => 1, sleep: async () => {}, request: async (method, route, req) => {
      calls.push([method, route, req.owned]);
      return calls.length < 32 ? { status: 202, body: { operationId: uuid(3) } }
        : { status: 200, body: { message: 'Stage deleted' } };
    }, message: 'Stage deleted' }), 32);
  assert.equal(calls.length, 32);
  assert(calls.every(call => call[0] === 'GET' && call[1] === `/operations/${uuid(3)}` && call[2]));
  await assert.rejects(recoverSameOperation({ operationId: uuid(3), req: {},
    now: () => 1, sleep: async () => {}, request: async () => ({ status: 202,
      body: { operationId: uuid(3) } }), message: 'Stage deleted' }), /exhausted/);
});

test('create/start readback uses real projected DTO shape, not only a message', async () => {
  assert.doesNotThrow(() => assertOwnedCreateResponse({ message: 'Stage created', id: 14 }, 14));
  assert.throws(() => assertOwnedCreateResponse({ message: 'Stage created', id: 1 }, 14));
  assert.throws(() => assertOwnedCreateResponse({ message: 'Stage created', id: 14,
    untrusted: true }, 14));
  const start = { message: 'Stage started successfully',
    stage: { id: 14, stage_number: 11 }, attemptsSoFar: 0, hintsUsed: 0 };
  assert.doesNotThrow(() => assertOwnedStartResponse(start, 14));
  for (const change of [
    v => { v.stage.id = 15; }, v => { v.stage.stage_number = 10; },
    v => { v.attemptsSoFar = 1; }, v => { v.hintsUsed = 1; },
    v => { v.alreadyCompleted = true; },
  ]) { const mutated = structuredClone(start); change(mutated);
    assert.throws(() => assertOwnedStartResponse(mutated, 14)); }
  const calls = [];
  await assert.rejects(recoverSameOperation({ operationId: uuid(5), req: {},
    now: () => 1, request: async (method, route) => {
      calls.push([method, route]);
      return { status: 200, body: { message: 'Stage created', id: 15 } };
    }, message: 'Stage created', validateBody: body => assertOwnedCreateResponse(body, 14) }));
  assert.deepEqual(calls, [['GET', `/operations/${uuid(5)}`]]);
});

test('owned stage number and order must be absent and prerequisite-free', () => {
  const stages = Array.from({ length: 10 }, (_, n) => ({ stage_number: n + 1,
    stage_order: n + 1 }));
  assert.equal(assertOwnedStageSelection(stages), true);
  assert.throws(() => assertOwnedStageSelection([...stages.slice(0, 9),
    { stage_number: 11, stage_order: 10 }]));
  assert.throws(() => assertOwnedStageSelection(stages.map((row, n) => n === 0
    ? { ...row, stage_order: 0 } : row)));
});

test('physical DELETE rejects wrong route, duplicate, body, and stale bearer', () => {
  const target = '/api/ctf/admin/stages/14';
  const good = { deletes: 1, paths: [`DELETE ${target}`], physical: [{ bearer: 'Bearer current', body: null }] };
  assert.equal(exactPhysicalStageDelete(good, target, 'Bearer current'), true);
  for (const bad of [
    { ...good, deletes: 2 }, { ...good, paths: [`DELETE ${target}`, 'DELETE /api/ctf/admin/stages/1'] },
    { ...good, paths: ['DELETE /api/ctf/admin/stages/1'] },
    { ...good, paths: [`POST ${target}`] },
    { ...good, physical: [{ bearer: 'Bearer stale', body: null }] },
    { ...good, physical: [{ bearer: 'Bearer current', body: '{}' }] },
  ]) assert.equal(exactPhysicalStageDelete(bad, target, 'Bearer current'), false);
});

test('actual confirmation recorder updates initial receipt before validation and catches late wrong path', () => {
  const target = '/api/ctf/admin/stages/14';
  const receipt = valid(); receipt.browserDeletes = 0; receipt.observedPath = null;
  receipt.facts.confirmedOnePhysicalDelete = false;
  const seen = { deletes: 1, paths: [`DELETE ${target}`], gets: [],
    physical: [{ bearer: 'Bearer current', body: null }] };
  recordStageDeleteConfirmation(receipt, seen, target, 'Bearer current');
  assert.equal(receipt.browserDeletes, 1);
  assert.equal(assertStageDeleteReceipt(receipt), true);
  seen.paths.push('PUT /api/ctf/admin/stages/1');
  recordStageDeleteConfirmation(receipt, seen, target, 'Bearer current');
  assert.equal(receipt.facts.confirmedOnePhysicalDelete, false);
  assert.throws(() => assertStageDeleteReceipt(receipt));
});

test('actual open-review flow leaves expanded editor open across Cancel and only clicks row when closed', async () => {
  const dom = new JSDOM('<table><tbody><tr id="owned"><td>11</td><td>Q05 controlled owned deletion stage</td></tr></tbody></table>');
  const prior = global.document; global.document = dom.window.document;
  const row = dom.window.document.getElementById('owned');
  row.getClientRects = () => [{ width: 1, height: 1 }];
  let pointerClicks = 0, deleteClicks = 0;
  const expand = () => {
    pointerClicks++;
    const priorEditor = dom.window.document.getElementById('editor');
    if (priorEditor) { priorEditor.remove(); return; }
    const editor = dom.window.document.createElement('tr'); editor.id = 'editor';
    const cell = dom.window.document.createElement('td'); cell.setAttribute('colspan', '7');
    const del = dom.window.document.createElement('button'); del.textContent = 'Delete';
    del.getClientRects = () => [{ width: 1, height: 1 }];
    cell.append(del); editor.append(cell); row.after(editor);
  };
  const page = { waitForFunction: async (fn, _opts, arg) => {
    const value = fn(arg); assert(value, 'DOM predicate did not become ready');
    return { evaluate: async evaluator => evaluator(value), dispose: async () => {} };
  } };
  const click = async (_page, selector, text) => {
    const matches = [...dom.window.document.querySelectorAll(selector)]
      .filter(item => item.textContent.trim() === text);
    assert.equal(matches.length, 1);
    if (text === 'Delete') {
      deleteClicks++;
      const dialog = dom.window.document.createElement('div');
      dialog.setAttribute('role', 'dialog');
      dialog.innerHTML = '<h3>Delete CTF stage</h3><p>Permanently delete "Q05 controlled owned deletion stage"?</p><button>Confirm Delete</button><button>Cancel</button>';
      dom.window.document.body.append(dialog);
    } else if (text === 'Cancel') {
      matches[0].closest('[role="dialog"]').remove();
    }
  };
  const args = { instructor: page, action: fn => fn(), pointer: async () => expand(),
    click, stageNumber: 11, stageName: 'Q05 controlled owned deletion stage' };
  try {
    await openStageDeleteReview(args);
    assert.equal(pointerClicks, 1); assert.equal(deleteClicks, 1);
    await click(page, '[role="dialog"] button', 'Cancel');
    assert(dom.window.document.getElementById('editor'));
    await openStageDeleteReview(args);
    assert.equal(pointerClicks, 1, 'second review must not collapse the open editor');
    assert.equal(deleteClicks, 2);
    dom.window.document.querySelector('[role="dialog"]').remove();
    dom.window.document.getElementById('editor').remove();
    await openStageDeleteReview(args);
    assert.equal(pointerClicks, 2, 'closed editor must be physically expanded');
  } finally { global.document = prior; dom.window.close(); }
});

test('same mounted actor/session may refresh token, but another session or actor is rejected', async () => {
  const adapter = { validateSession: async token => token === 'fresh'
    ? { user: { id: 1002 }, session: { id: 81 } }
    : token === 'other-session'
      ? { user: { id: 1002 }, session: { id: 82 } }
      : { user: { id: 1003 }, session: { id: 81 } } };
  assert.equal(await validatedBearer('fresh', adapter, '1002', '81'), 'Bearer fresh');
  await assert.rejects(validatedBearer('other-session', adapter, '1002', '81'));
  await assert.rejects(validatedBearer('other-actor', adapter, '1002', '81'));
});

test('partial setup makes one distinct canonical cleanup and records intent before dispatch', async () => {
  const events = [], requests = [];
  const result = await cleanupOwnedStage({ createdId: 14, browserDeletes: 0,
    exists: async id => id === 14, admin: { owned: true },
    request: async (method, route, req, body) => {
      requests.push([method, route, req.owned, body]);
      assert.equal(events[0].kind, 'distinct-setup-cleanup-intent');
      return { status: 200, body: { message: 'Stage deleted' } };
    }, verify: async id => { assert.equal(id, 14); },
    journal: event => events.push(event) });
  assert.deepEqual(result, { status: 'distinct-canonical-cleanup' });
  assert.deepEqual(requests, [['DELETE', '/admin/stages/14', true, {}]]);
  assert.deepEqual(events.map(x => x.kind), ['distinct-setup-cleanup-intent',
    'distinct-setup-cleanup']);
});

test('pending distinct setup cleanup only polls its acknowledged ID', async () => {
  const calls = [], journal = [];
  const result = await cleanupOwnedStage({ createdId: 14, browserDeletes: 0,
    exists: async () => true, admin: { owned: true },
    request: async (method, route) => {
      calls.push([method, route]);
      return method === 'DELETE'
        ? { status: 202, body: { pending: true, operationId: uuid(5) } }
        : { status: 200, body: { message: 'Stage deleted' } };
    }, verify: async id => assert.equal(id, 14), journal: event => journal.push(event) });
  assert.deepEqual(result, { status: 'distinct-canonical-cleanup' });
  assert.deepEqual(calls, [['DELETE', '/admin/stages/14'],
    ['GET', `/operations/${uuid(5)}`]]);
  assert.deepEqual(journal.map(x => x.kind), ['distinct-setup-cleanup-intent',
    'distinct-setup-cleanup']);
  assert.equal(journal[1].operationId, uuid(5));
});

test('uncertain browser deletion, absent stage, and uncertain cleanup never retry', async () => {
  let calls = 0; const journal = [];
  const common = { createdId: 14, admin: {}, exists: async () => true,
    request: async () => { calls++; throw Error('response lost'); },
    verify: async () => {}, journal: event => journal.push(event) };
  assert.deepEqual(await cleanupOwnedStage({ ...common, browserDeletes: 1 }),
    { status: 'browser-delete-uncertain-no-retry' });
  assert.deepEqual(await cleanupOwnedStage({ ...common, browserDeletes: 0,
    exists: async () => false }), { status: 'already-absent-no-retry' });
  assert.equal(calls, 0);
  await assert.rejects(cleanupOwnedStage({ ...common, browserDeletes: 0 }), /response lost/);
  assert.equal(calls, 1);
  assert.equal(journal.at(-1).kind, 'distinct-setup-cleanup-intent');
  assert.deepEqual(await cleanupOwnedStage({ ...common, createdId: null,
    createAttempted: true, browserDeletes: 0 }),
  { status: 'create-outcome-unresolved-no-cleanup' });
  assert.equal(calls, 1);
});

test('terminal readback requires real prestate, exact tombstone, history and sibling', () => {
  const input = { createdId: 14, baselineStages: ['ten canonical rows'],
    remainingStages: ['ten canonical rows'], targetStage: null,
    preProgressCount: 1, preEventCount: 1, postProgress: [], postEvents: [],
    siblingBefore: [{ row: 'sibling' }], siblingAfter: [{ row: 'sibling' }],
    binding: { active: false, applied_operation_id: uuid(3), applied_sequence: '44' },
    operationId: uuid(3), sequence: '44', retainedOperations: [uuid(1), uuid(2), uuid(3)] };
  assert.deepEqual(assessStageDeleteReadback(input), { nonvacuous: true,
    cascaded: true, tombstoned: true, canonicalTenAndSiblingPreserved: true,
    historyPreserved: true });
  for (const [change, failed] of [
    [v => { v.preProgressCount = 0; }, 'cascaded'],
    [v => { v.preEventCount = 0; }, 'cascaded'],
    [v => { v.postProgress = ['retained']; }, 'cascaded'],
    [v => { v.postEvents = ['retained']; }, 'cascaded'],
    [v => { v.binding.applied_operation_id = uuid(7); }, 'tombstoned'],
    [v => { v.binding.active = true; }, 'tombstoned'],
    [v => { v.targetStage = 'retained'; }, 'canonicalTenAndSiblingPreserved'],
    [v => { v.remainingStages = []; }, 'canonicalTenAndSiblingPreserved'],
    [v => { v.siblingAfter = []; }, 'canonicalTenAndSiblingPreserved'],
    [v => { v.retainedOperations = []; }, 'historyPreserved'],
  ]) { const changed = structuredClone(input); change(changed);
    assert.equal(assessStageDeleteReadback(changed)[failed], false); }
});

test('listener retirement clears captured bearer and preserves primary on either off failure', () => {
  const primary = Error('primary'); const removed = [];
  const request = () => {}, response = () => {};
  const seen = { physical: [{ bearer: 'Bearer private' }] };
  assert.throws(() => retireStageDeleteListeners({ instructor: {
    off: event => { removed.push(event); if (event === 'request') throw Error('off failed'); },
  }, onRequest: request, onResponse: response, seen, primary }),
  error => error instanceof AggregateError && error.cause === primary &&
    error.errors[0] === primary && error.errors.length === 2);
  assert.deepEqual(removed, ['request', 'response']);
  assert.deepEqual(seen.physical, []);
});
