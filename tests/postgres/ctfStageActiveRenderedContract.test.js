'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { JSDOM } = require('../../client/node_modules/jsdom');
const { assertStageActiveReceipt, exactPhysicalStageActivePut, findStageSwitch,
  validatedStageActiveBearer, finishStageActiveOwnedPhase, recoverStageActiveRestore,
  preserveStageActiveFailure, FACTS, PUT_PATH } = require('./support/ctfStageActiveRenderedCases');

const uuid = n => `${String(n).padStart(8, '0')}-0000-4000-8000-000000000001`;
const operation = (n, sequence) => ({ originalStatus: 200, resolvedStatus: 200, sameIdGets: 0,
  operationId: uuid(n), sequence: String(sequence), browserAckOperationId: null, ackMessage: 'Stage updated' });
const valid = () => ({ version: 1, profile: 'ctf-stage-active-q05', targetStageId: 2,
  siblingStageId: 3, mountedActorId: '1001', mountedSessionId: '1002',
  originalActive: 1, confirmedActive: 0, observedPath: PUT_PATH,
  browserPuts: 1, fixtureRestorePuts: 1, dialogTimeAba: { eventsObserved: 2, noPut: true },
  confirmed: operation(1, 11), restore: { ...operation(2, 12), scope: 'content-equivalence-only' },
  facts: Object.fromEntries(FACTS.map(name => [name, true])),
  excluded: ['byte-identical-undo', 'provenance-rollback', 'model-qualification'],
  unexpectedApiPaths: [], stage: 'complete', modelCalls: 0, judgeCalls: 0 });

test('stage-active receipt admits only one scoped physical PUT and a distinct restore', () => {
  assert.equal(assertStageActiveReceipt(valid()), true);
  for (const mutate of [
    r => { r.browserPuts = 2; }, r => { r.originalActive = 0; },
    r => { r.confirmedActive = 1; }, r => { r.observedPath = '/api/ctf/admin/stages/3'; },
    r => { r.dialogTimeAba.eventsObserved = 1; }, r => { r.dialogTimeAba.noPut = false; },
    r => { r.confirmed.operationId = r.restore.operationId; },
    r => { r.restore.sequence = r.confirmed.sequence; },
    r => { r.facts.cancelNoEffect = false; }, r => { r.facts.siblingPreserved = false; },
    r => { r.facts.nonAvailabilityFieldsUnchanged = false; },
    r => { r.facts.restoreContentEquivalent = false; },
    r => { r.modelCalls = 1; }, r => { r.judgeCalls = 1; },
    r => { r.unknown = true; },
  ]) { const changed = structuredClone(valid()); mutate(changed); assert.throws(() => assertStageActiveReceipt(changed)); }
});

test('202 needs genuine same-ID GET and cannot reuse the restore operation', () => {
  const receipt = valid();
  receipt.confirmed = { originalStatus: 202, resolvedStatus: 200, sameIdGets: 1,
    operationId: uuid(1), sequence: '11', browserAckOperationId: uuid(1), ackMessage: null };
  assert.equal(assertStageActiveReceipt(receipt), true);
  receipt.confirmed.sameIdGets = 0; assert.throws(() => assertStageActiveReceipt(receipt));
  receipt.confirmed.sameIdGets = 1; receipt.confirmed.browserAckOperationId = uuid(3);
  assert.throws(() => assertStageActiveReceipt(receipt));
});

test('request witness requires exact route, primitive active bit, captured bearer and no late PUT', () => {
  const good = { puts: 1, paths: [PUT_PATH], physical: [{ body: { is_active: 0 }, bearer: 'Bearer fresh' }] };
  assert.equal(exactPhysicalStageActivePut(good, 'Bearer fresh', 0), true);
  for (const bad of [
    { ...good, puts: 2 }, { ...good, paths: [PUT_PATH, '/api/ctf/admin/stages/3'] },
    { ...good, paths: ['/api/ctf/admin/stages/3'] },
    { ...good, physical: [{ body: { is_active: false }, bearer: 'Bearer fresh' }] },
    { ...good, physical: [{ body: { is_active: 0, stage_name: 'changed' }, bearer: 'Bearer fresh' }] },
    { ...good, physical: [{ body: { is_active: 0 }, bearer: 'Bearer stale' }] },
  ]) assert.equal(exactPhysicalStageActivePut(bad, 'Bearer fresh', 0), false);
});

test('stage switch binds exactly one target row and rejects duplicate or disabled controls', () => {
  const dom = new JSDOM('<table><tbody>' +
    '<tr><td>2</td><td>Target</td><td><button role="switch" aria-checked="true"></button></td></tr>' +
    '<tr><td>3</td><td>Sibling</td><td><button role="switch" aria-checked="true"></button></td></tr>' +
    '</tbody></table>');
  const doc = dom.window.document;
  assert.equal(findStageSwitch(2, doc)?.getAttribute('aria-checked'), 'true');
  doc.querySelector('tr button').disabled = true;
  assert.equal(findStageSwitch(2, doc), null);
  doc.querySelector('tr button').disabled = false;
  doc.querySelector('tbody').append(doc.querySelector('tr').cloneNode(true));
  assert.equal(findStageSwitch(2, doc), null);
  dom.window.close();
});

test('refreshed token is accepted only for the same mounted actor and session', async () => {
  const adapter = { validateSession: async token => token === 'fresh'
    ? { user: { id: 1001 }, session: { id: 1002 } }
    : token === 'other-session'
      ? { user: { id: 1001 }, session: { id: 1003 } }
      : { user: { id: 1003 }, session: { id: 1002 } } };
  assert.equal(await validatedStageActiveBearer('fresh', adapter, '1001', '1002'), 'Bearer fresh');
  await assert.rejects(validatedStageActiveBearer('other-session', adapter, '1001', '1002'));
  await assert.rejects(validatedStageActiveBearer('other-actor', adapter, '1001', '1002'));
});

test('auxiliary close failure preserves primary and still retires both listeners, bearer and receipt', async () => {
  const primary = new Error('primary phase failed');
  const close = new Error('owned auxiliary close failed');
  const removed = [], saved = [];
  const receipt = { stage: 'dialog-aba', browserPuts: 0, unexpectedApiPaths: [] };
  const seen = { puts: 1, physical: [{ bearer: 'Bearer sensitive' }] };
  const onRequest = () => {}, onResponse = () => {};
  await assert.rejects(finishStageActiveOwnedPhase({
    other: { close: async () => { throw close; } },
    instructor: { off: (event, handler) => { removed.push([event, handler]); } },
    onRequest, onResponse, seen, receipt, save: () => saved.push(structuredClone(receipt)),
    unexpectedApiPaths: [], completed: false, primary,
  }), error => error instanceof AggregateError && error.cause === primary &&
    error.errors[0] === primary && error.errors[1] === close);
  assert.deepEqual(removed, [['request', onRequest], ['response', onResponse]]);
  assert.deepEqual(seen.physical, []);
  assert.equal(saved.length, 1);
  assert.equal(saved[0].browserPuts, 1);
});

test('cleanup independently attempts response listener removal and save after request-listener failure', async () => {
  const removed = [], saved = [];
  const seen = { puts: 0, physical: [{ bearer: 'Bearer sensitive' }] };
  const receipt = { stage: 'cancel' };
  await assert.rejects(finishStageActiveOwnedPhase({
    other: null, instructor: { off: event => { removed.push(event); if (event === 'request') throw Error('off failed'); } },
    onRequest: () => {}, onResponse: () => {}, seen, receipt,
    save: () => saved.push(receipt.stage), unexpectedApiPaths: [], completed: false,
  }), error => error instanceof AggregateError && error.errors.length === 1);
  assert.deepEqual(removed, ['request', 'response']);
  assert.deepEqual(seen.physical, []);
  assert.deepEqual(saved, ['cancel']);
});

test('restore recovery allows exactly 32 same-ID GETs but never a thirty-third', async () => {
  const operationId = uuid(4);
  const paths = [];
  const request = async (method, path) => {
    paths.push([method, path]);
    return paths.length === 32 ? { status: 200, body: { message: 'Stage updated' } }
      : { status: 202, body: { pending: true, operationId } };
  };
  assert.equal(await recoverStageActiveRestore({ request, admin: {}, operationId,
    now: () => 1, pause: async () => {} }), 32);
  assert.equal(paths.length, 32);
  assert(paths.every(([method, path]) => method === 'GET' && path === `/operations/${operationId}`));
  let rejectedCalls = 0;
  await assert.rejects(recoverStageActiveRestore({
    request: async () => { rejectedCalls++; return { status: 202, body: { pending: true, operationId } }; },
    admin: {}, operationId, now: () => 1, pause: async () => {},
  }), /32 same-ID GETs/);
  assert.equal(rejectedCalls, 32);
});

test('restore recovery honors the original 30-second deadline before another GET', async () => {
  const operationId = uuid(5);
  let time = 0, calls = 0;
  await assert.rejects(recoverStageActiveRestore({
    request: async () => { calls++; time = 30000; return { status: 202, body: { pending: true, operationId } }; },
    admin: {}, operationId, now: () => time, pause: async () => {},
  }), /30-second deadline/);
  assert.equal(calls, 1);
});

test('terminal failure receipt write cannot replace the original assertion error', () => {
  const primary = new Error('terminal invariant failed');
  const saveError = new Error('private receipt write failed');
  const receipt = { stage: 'complete' };
  assert.throws(() => preserveStageActiveFailure(primary, receipt, () => { throw saveError; }),
    error => error instanceof AggregateError && error.cause === primary &&
      error.errors[0] === primary && error.errors[1] === saveError);
  assert.equal(receipt.stage, 'late-request-failed');
  assert.throws(() => preserveStageActiveFailure(primary, receipt, () => {}), error => error === primary);
});
