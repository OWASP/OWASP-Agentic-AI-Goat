'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createSecureShopConversationLifecycle } = require('../server/services/secureshopConversationLifecycle');
const { buildReceipt, digestSessionIds } = require('../server/database/postgres/secureshopConversationLifecycleRepository');
const { createSecureShopResetCleanupAuthorityRepository } = require('../server/database/postgres/secureshopResetCleanupAuthorityRepository');
const resetId = '10000000-0000-4000-8000-000000000001';
const sessionId = '20000000-0000-4000-8000-000000000002';
const binding = Object.freeze({ launchId: '30000000-0000-4000-8000-000000000003',
  scenarioId: '40000000-0000-4000-8000-000000000004', generation: 2,
  platformOwnerId: 11, platformSessionId: 22 });
const deferred = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; };
function fixture() {
  const events = [];
  const state = { status: 'pending', scope: binding, sessions: [{ sessionId, state: 'active' }],
    wait: null, corrupt: false, unauthorized: false };
  const receipt = buildReceipt({ resetId, ...binding }, { completedAt: '2026-09-13T12:00:00.000Z',
    sessionCount: 1, uncertainTurnCount: 1, sessionSetSha256: digestSessionIds([sessionId]) });
  const repository = {
    async beginRetirement(input) { assert.deepEqual(input, { resetId, binding }); events.push('begin'); return { resetId, status: state.status }; },
    async listRetirableSessions() { events.push('list'); return state.sessions; },
    async retireSession(input) { assert.deepEqual(input, { resetId, binding, sessionId }); events.push('retire'); },
    async completeRetirement() { events.push('complete'); state.status = 'completed'; },
    async readRetirementReceipt() { events.push('read'); return state.corrupt ? { ...receipt, platformOwnerId: 999 } : receipt; },
  };
  const cleanupAuthority = { async getOperation(value) {
    assert.equal(value, resetId);
    if (state.unauthorized) throw Object.assign(new Error('unavailable'), { code: 'RESET_CLEANUP_AUTHORITY_REQUIRED' });
    return { resetId, status: 'fenced', binding: state.scope };
  } };
  const turns = { async retire(value, callback) {
    assert.equal(value, sessionId); events.push('drain');
    if (state.wait) await state.wait;
    await callback(); events.push('drained');
  } };
  return { service: createSecureShopConversationLifecycle({ repository, turns, cleanupAuthority }), state, events, receipt };
}

test('generation retirement waits for admitted work and verifies persisted receipt before publication', async () => {
  const f = fixture(); const gate = deferred(); f.state.wait = gate.promise;
  const result = f.service.retireGeneration(resetId);
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(f.events, ['begin', 'list', 'drain']);
  gate.resolve();
  assert.deepEqual(await result, f.receipt);
  assert.deepEqual(f.events, ['begin', 'list', 'drain', 'retire', 'drained', 'complete', 'read']);
  assert.ok(Object.isFrozen(await f.service.readReceipt(resetId)));
  f.events.length = 0;
  assert.deepEqual(await f.service.retireGeneration(resetId), f.receipt);
  assert.deepEqual(f.events, ['begin', 'read']);
});

test('authority changes while a drain waits prevent retirement and completion', async () => {
  const f = fixture(); const gate = deferred(); f.state.wait = gate.promise;
  const pending = f.service.retireGeneration(resetId);
  const rejected = assert.rejects(pending, { code: 'RETIREMENT_SCOPE_MISMATCH' });
  await new Promise(resolve => setImmediate(resolve));
  f.state.scope = { ...binding, platformOwnerId: 12 };
  gate.resolve(); await rejected;
  assert.deepEqual(f.events, ['begin', 'list', 'drain']);
});

test('abort never detaches the pending drain or announces completed cleanup', async () => {
  const f = fixture(); const gate = deferred(); f.state.wait = gate.promise;
  const controller = new AbortController(); let settled = false;
  const pending = f.service.retireGeneration(resetId, { signal: controller.signal });
  pending.then(() => { settled = true; }, () => { settled = true; });
  const rejected = assert.rejects(pending, { name: 'AbortError' });
  await new Promise(resolve => setImmediate(resolve)); controller.abort();
  await new Promise(resolve => setImmediate(resolve)); assert.equal(settled, false);
  gate.resolve(); await rejected;
  assert.deepEqual(f.events, ['begin', 'list', 'drain']);
});

test('wrong-owner receipt and revoked cleanup authority cannot publish success', async () => {
  const f = fixture(); f.state.status = 'completed'; f.state.corrupt = true;
  await assert.rejects(f.service.retireGeneration(resetId), { code: 'INVALID_RETIREMENT_RECEIPT' });
  f.state.unauthorized = true;
  await assert.rejects(f.service.readReceipt(resetId), { code: 'RESET_CLEANUP_AUTHORITY_REQUIRED' });
});

test('duplicate or malformed session inventory is rejected before any drain', async () => {
  for (const sessions of [[{ sessionId, state: 'active' }, { sessionId, state: 'active' }],
    [{ sessionId, state: 'unknown' }], [{ sessionId: 'not-a-uuid', state: 'active' }]]) {
    const f = fixture(); f.state.sessions = sessions;
    await assert.rejects(f.service.retireGeneration(resetId));
    assert.deepEqual(f.events, ['begin', 'list']);
  }
});

test('cleanup operation derives immutable scope from durable reset and requires an advanced generation', async () => {
  let row = { status: 'fenced', from_generation: '2', to_generation: '3', current_generation: '3',
    launch_id: binding.launchId, scenario_id: binding.scenarioId,
    original_platform_owner_id: 11, original_platform_session_id: 22 };
  const authority = createSecureShopResetCleanupAuthorityRepository({ async query(sql, args) {
    assert.match(sql, /JOIN identity\.secureshop_launches/); assert.deepEqual(args, [resetId]);
    return { rows: row ? [row] : [] };
  } });
  const result = await authority.getOperation(resetId);
  assert.deepEqual(result, { resetId, status: 'fenced', toGeneration: 3, binding });
  assert.ok(Object.isFrozen(result.binding));
  row.current_generation = '2';
  await assert.rejects(authority.getOperation(resetId), { code: 'RESET_CLEANUP_AUTHORITY_REQUIRED' });
  row = null;
  await assert.rejects(authority.getOperation(resetId), { code: 'RESET_CLEANUP_AUTHORITY_REQUIRED' });
});
