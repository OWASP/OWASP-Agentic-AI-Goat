'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createSecureShopReviewResetCoordinator } = require('../server/services/secureshopReviewResetCoordinator');

test('unknown or unwired target kinds fail before any cleanup or reset commit', async () => {
  for (const targetKind of ['network', 'constructor', 'toString', '__proto__', 'controlled_ssrf']) {
    const calls = [];
    const coordinator = createSecureShopReviewResetCoordinator({
      launches: {
        async beginReset() { return { resetId: 'reset', toGeneration: 2 }; },
        async commitReset() { calls.push('commit'); },
      },
      cleanupAuthority: {
        async listTargets() { return { targets: [{ targetKind: 'reviews' }, { targetKind }] }; },
        async assertResolved() { calls.push('resolved'); },
        async finalizeReconciliation() { calls.push('finalize'); },
      },
      reviewRepository: { async cleanup() { calls.push('review'); } },
      fileCleanup: { async cleanup() { calls.push('file'); } },
      reconciler: { async reconcile() { calls.push('reconcile'); } },
    });
    await assert.rejects(coordinator.reset({}), { code: 'UNSUPPORTED_TARGET_CLEANUP' });
    assert.deepEqual(calls, [], targetKind);
  }
});

test('SSRF recovery reconciles the exact authorized target before finalizing without reactivating the launch', async () => {
  const target=Object.freeze({targetId:'ssrf-target',targetKind:'controlled_ssrf',launchId:'launch',
    scenarioId:'scenario',fromGeneration:7,platformOwnerId:11,platformSessionId:13});
  const calls=[],history={targetId:target.targetId};
  const coordinator=createSecureShopReviewResetCoordinator({
    launches:{async beginReset(){throw Error('recovery must not begin a new reset');},async commitReset(){throw Error('recovery must not reactivate');}},
    cleanupAuthority:{async listTargets(){return {resetId:'reset',targets:[target]};},
      async assertResolved(){calls.push('resolved');return {status:'aborted'};},
      async finalizeReconciliation(id,rows){assert.equal(id,'reset');assert.deepEqual(rows,[history]);calls.push('finalize');}},
    reviewRepository:{async cleanup(){throw Error('wrong target adapter');}},
    ssrfCleanup:{async cleanup(input,options){assert.equal(input,target);assert.deepEqual(options,{operationId:'reset'});calls.push('cleanup');}},
    reconciler:{async reconcile(input,options){assert.equal(input,target);assert.deepEqual(options,{operationId:'reset'});calls.push('reconcile');return {history};}},
  });
  assert.deepEqual(await coordinator.recover('reset'),{resetId:'reset',status:'aborted',resolved:true,activated:false,targets:1});
  assert.deepEqual(calls,['cleanup','reconcile','resolved','finalize']);
});

test('product cleanup receives the exact repository generation binding', async () => {
  const target = Object.freeze({ targetId: 'target', targetKind: 'products', launchId: 'launch',
    scenarioId: 'scenario', fromGeneration: 7, platformOwnerId: 11, platformSessionId: 13 });
  let cleanupInput;
  const coordinator = createSecureShopReviewResetCoordinator({
    launches: {
      async beginReset() { return { resetId: 'reset', fromGeneration: 7, toGeneration: 8 }; },
      async commitReset() { return { generation: 8 }; },
    },
    cleanupAuthority: {
      async listTargets() { return { targets: [target] }; },
      async assertResolved() { return { status: 'fenced' }; },
      async finalizeReconciliation() { return { resolved: true }; },
    },
    reviewRepository: { async cleanup() { throw new Error('wrong cleanup'); } },
    productCleanup: { async cleanup(input, options) { cleanupInput = { input, options }; } },
    reconciler: { async reconcile() { return { history: { targetId: 'target' } }; } },
  });
  assert.equal((await coordinator.reset({})).status, 'committed');
  assert.deepEqual(cleanupInput, { input: { targetId: 'target', launchId: 'launch',
    scenarioId: 'scenario', generation: 7, platformOwnerId: 11, platformSessionId: 13 },
  options: { operationId: 'reset' } });
});

test('persona inbox cleanup is optional and receives the exact repository generation binding', async () => {
  const target = Object.freeze({ targetId: 'target', targetKind: 'persona_inbox', launchId: 'launch',
    scenarioId: 'scenario', fromGeneration: 7, platformOwnerId: 11, platformSessionId: 13 });
  const base = {
    launches: {
      async beginReset() { return { resetId: 'reset', fromGeneration: 7, toGeneration: 8 }; },
      async commitReset() { return { generation: 8 }; },
    },
    cleanupAuthority: {
      async listTargets() { return { targets: [target] }; },
      async assertResolved() { return { status: 'fenced' }; },
      async finalizeReconciliation() { return { resolved: true }; },
    },
    reviewRepository: { async cleanup() { throw new Error('wrong cleanup'); } },
    reconciler: { async reconcile() { return { history: { targetId: 'target' } }; } },
  };
  await assert.rejects(createSecureShopReviewResetCoordinator(base).reset({}),
    { code: 'UNSUPPORTED_TARGET_CLEANUP' });
  let cleanupInput;
  const coordinator = createSecureShopReviewResetCoordinator({ ...base,
    personaInboxCleanup: { async cleanup(input, options) { cleanupInput = { input, options }; } },
  });
  assert.equal((await coordinator.reset({})).status, 'committed');
  assert.deepEqual(cleanupInput, { input: { targetId: 'target', launchId: 'launch',
    scenarioId: 'scenario', generation: 7, platformOwnerId: 11, platformSessionId: 13 },
  options: { operationId: 'reset' } });
});
