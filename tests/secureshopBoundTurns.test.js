'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createBoundTurns } = require('../server/services/secureshopBoundTurns');
const { createRunCoordinator } = require('../server/agent-runtime/runCoordinator');
const scope = { launchId: '11111111-1111-4111-8111-111111111111', scenarioId: '22222222-2222-4222-8222-222222222222', generation: 1, platformOwnerId: 7, platformSessionId: 8 };
const persona = { id: 1, role: 'customer' };
const deferred = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; };

test('shared coordinator serializes turns and rechecks authority after waiting', async () => {
  const entered = deferred(), release = deferred(); let revoked = false, secondEffects = 0;
  const turns = createBoundTurns({ coordinator: createRunCoordinator({ family: 'BoundTurnsTest', ledger: null }), conversations: {
    async assertOwned() { if (revoked) throw new Error('launch revoked'); },
  } });
  const first = turns.run('owned', scope, persona, {}, async () => { entered.resolve(); await release.promise; });
  await entered.promise;
  const second = turns.run('owned', scope, persona, {}, async () => { secondEffects++; });
  // Let the second invocation pass pre-queue auth and join the existing queue.
  await new Promise(resolve => setImmediate(resolve));
  revoked = true; release.resolve();
  const results = await Promise.allSettled([first, second]);
  assert.ok(results.every(result => result.status === 'rejected'));
  assert.equal(secondEffects, 0);
});

test('effect admission rechecks launch after the ledger awaits and preserves raw results', async () => {
  let revoked = false, calls = 0, invalidateOnClaim = false;
  const turns = createBoundTurns({ conversations: { async assertOwned(_id, binding, actualPersona) {
    assert.equal(binding.platformOwnerId, 7); assert.deepEqual(actualPersona, persona);
    if (revoked) throw new Error('launch revoked');
  } }, coordinator: { async run(_id, _options, execute) { return execute({
    runId: 'run-fixture', ownerKey: '["BoundTurnsTest","owned"]', generation: 2, durableGeneration: '7',
    signal: new AbortController().signal, async check() {},
    async effect(key, callback) { assert.equal(key, 'tool-key'); if (invalidateOnClaim) revoked = true; return callback(); },
  }); } } });
  const payload = { raw: '<script>teaching payload</script>' };
  assert.equal(await turns.run('owned', scope, persona, {}, boundary => {
    assert.deepEqual(Object.keys(boundary), ['identity', 'signal', 'check', 'effect', 'effectWithReceipt']);
    assert.deepEqual(boundary.identity, { runId: 'run-fixture', ownerKey: '["BoundTurnsTest","owned"]', generation: 2, durableGeneration: '7' });
    assert.equal(Object.isFrozen(boundary.identity), true);
    return boundary.effect('tool-key', () => { calls++; return payload; });
  }), payload);
  invalidateOnClaim = true;
  await assert.rejects(turns.run('owned', scope, persona, {}, boundary => boundary.effect('tool-key', () => { calls++; })), /launch revoked/);
  assert.equal(calls, 1);
});

test('coordinator trace remains inside the same checked turn boundary', async () => {
  const order = [];
  const turns = createBoundTurns({ conversations: { async assertOwned() { order.push('owned'); } }, coordinator: {
    async run(_id, _options, execute) { return execute({ runId: 'run-trace', ownerKey: 'owner-trace', generation: 1,
      durableGeneration: '2', signal: new AbortController().signal, async check() { order.push('check'); },
      async effect(_key, callback) { return callback(); }, async trace(event) { order.push(['trace', event]); } }); },
  } });
  await turns.run('owned', scope, persona, {}, async boundary => {
    assert.equal(typeof boundary.trace, 'function');
    await boundary.trace({ type: 'decision' });
  });
  assert.deepEqual(order.find(value => Array.isArray(value)), ['trace', { type: 'decision' }]);
  const traceIndex = order.findIndex(value => Array.isArray(value));
  assert.equal(order[traceIndex - 1], 'check'); assert.equal(order[traceIndex + 1], 'check');
});

test('turn scope is snapshotted before queued work and lost lease suppresses effects', async () => {
  const supplied = { ...scope }; let effects = 0, lost = false;
  const turns = createBoundTurns({ conversations: { async assertOwned(_id, binding) { assert.equal(binding.platformOwnerId, 7); } },
    coordinator: { async run(_id, _options, execute) {
      supplied.platformOwnerId = 999;
      return execute({ runId: 'run-scope', ownerKey: 'server-owned-key', generation: 4, durableGeneration: '9',
        signal: new AbortController().signal, async check() { if (lost) throw new Error('lease lost'); }, async effect(_key, callback) { return callback(); } });
    } },
  });
  await assert.rejects(turns.run('owned', supplied, persona, {}, async boundary => {
    lost = true; return boundary.effect('tool', () => { effects++; });
  }), /lease lost/);
  assert.equal(effects, 0);
});

test('receipt-aware effects and retirement use the retained coordinator without claiming process-local completion', async () => {
  const resetCalls = [];
  const receipt = Object.freeze({ version: 1, runId: 'run-receipt', ownerKey: 'trusted-owner', generation: '3', effectKey: 'request:tool', status: 'completed' });
  const turns = createBoundTurns({ conversations: { async assertOwned() {} }, coordinator: {
    async run(_id, _options, execute) { return execute({ runId: 'run-receipt', ownerKey: 'trusted-owner', generation: 1, durableGeneration: '3',
      signal: new AbortController().signal, async check() {}, async effect(_key, callback) { return callback(); },
      async effectWithReceipt(key, callback) { assert.equal(key, 'tool'); return { value: await callback(), receipt }; } }); },
    async reset(id, cleanup) { resetCalls.push(id); return cleanup(); },
  } });
  const result = await turns.run('owned', scope, persona, {}, boundary => boundary.effectWithReceipt('tool', async () => ({ raw: true })));
  assert.deepEqual(result, { value: { raw: true }, receipt });
  let cleaned = 0;
  await turns.retire('owned', async () => { cleaned++; });
  assert.deepEqual(resetCalls, ['owned']); assert.equal(cleaned, 1);
  await assert.rejects(turns.retire('owned', null), /callback required/);
});

test('configured bound turns refuse a process-local fallback outside PostgreSQL', () => {
  const { createConfiguredBoundTurns } = require('../server/services/secureshopBoundTurns');
  const previous = process.env.PLATFORM_DATABASE_ENGINE;
  try {
    process.env.PLATFORM_DATABASE_ENGINE = 'sqlite';
    assert.throws(() => createConfiguredBoundTurns({ conversations: { async assertOwned() {} } }), /require PostgreSQL/);
  } finally {
    if (previous === undefined) delete process.env.PLATFORM_DATABASE_ENGINE;
    else process.env.PLATFORM_DATABASE_ENGINE = previous;
  }
});

test('pre-run admission is enclosed by launch ownership checks', async () => {
  const order = [];
  const turns = createBoundTurns({ conversations: { async assertOwned() { order.push('owned'); } }, coordinator: {
    async run(_id, options, execute) {
      order.push('coordinator');
      const decision = await options.admit();
      order.push('admitted');
      if (decision.skip) return decision.value;
      return execute({ runId: 'fresh', ownerKey: 'owner', generation: 1, durableGeneration: '1',
        signal: new AbortController().signal, async check() {}, async effect(_key, callback) { return callback(); } });
    },
  } });
  const result = await turns.run('owned', scope, persona, { admit: async () => {
    order.push('journal'); return { skip: true, value: 'retained' };
  } }, () => assert.fail('replay must not execute'));
  assert.equal(result, 'retained');
  assert.deepEqual(order, ['owned', 'coordinator', 'owned', 'journal', 'owned', 'admitted']);
});

test('turn authority rechecks retain the server-selected conversation purpose',async()=>{
  const purposes=[];
  const turns=createBoundTurns({conversations:{async assertOwned(_id,_binding,_persona,purpose){purposes.push(purpose);}},coordinator:{
    async run(_id,options,execute){assert.equal(options.idempotencyKey,'purpose-request');const admission=await options.admit();
      assert.equal(admission.skip,false);return execute({runId:'purpose-run',ownerKey:'purpose-owner',generation:1,durableGeneration:'1',
        signal:new AbortController().signal,async check(){},async effect(_key,callback){return callback();}});},
  }});
  await turns.run('owned',scope,persona,{conversationPurpose:'mcp_rug_pull',idempotencyKey:'purpose-request',
    admit:async()=>({skip:false})},async boundary=>{await boundary.check();return'ok';});
  assert.ok(purposes.length>=5);
  assert.ok(purposes.every(value=>value==='mcp_rug_pull'));
});
