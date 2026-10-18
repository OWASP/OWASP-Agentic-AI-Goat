'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createSceneBinding, copySceneBinding, executionScope, assertSceneGrant, withSceneLease } = require('../server/services/secureshopSceneBinding');
const { createSecureShopScenes } = require('../server/services/secureshopScenes');
const birth = Object.freeze({ targetId: '11111111-1111-4111-8111-111111111111', launchId: '22222222-2222-4222-8222-222222222222',
  scenarioId: '33333333-3333-4333-8333-333333333333', generation: 1, platformOwnerId: 7, platformSessionId: 10 });
const current = Object.freeze({ launchId: '44444444-4444-4444-8444-444444444444',
  scenarioId: '55555555-5555-4555-8555-555555555555', generation: 2, platformOwnerId: 7, platformSessionId: 20 });
const ids = { sceneId: '66666666-6666-4666-8666-666666666666', sceneGeneration: 1, grantId: '77777777-7777-4777-8777-777777777777' };
test('scene binding keeps birth and current execution separate and retains private lease through normalization', async () => {
  let leased = false;
  const b = createSceneBinding(birth, { ...ids, execution: current, withLease: async work => { leased = true; try { return await work(); } finally { leased = false; } } });
  assert.equal(b.launchId, birth.launchId); assert.deepEqual(executionScope(b), current);
  const copy = copySceneBinding(b, { ...birth });
  assert.equal(await withSceneLease(copy, async () => { assert.equal(leased, true); return 42; }), 42);
  assert.equal(leased, false);
  assert.throws(() => executionScope({ ...b }), { code: 'SHOP_SCENE_STALE' });
  assert.throws(() => copySceneBinding(b, { ...birth, targetId: ids.sceneId }), { code: 'SHOP_SCENE_STALE' });
  assert.throws(() => createSceneBinding(birth, { ...ids, execution: { ...current, platformOwnerId: 8 }, withLease: work => work() }), { code: 'SHOP_SCENE_STALE' });
});
test('storage transaction grant uses current execution and denies an absent grant', async () => {
  const b = createSceneBinding(birth, { ...ids, execution: current, withLease: work => work() });
  let values;
  await assertSceneGrant({ query: async (_sql, params) => { values = params; return { rows: [{ allowed: true }] }; } }, b);
  assert.deepEqual(values, [ids.grantId, ids.sceneId, 1, birth.targetId, current.launchId, current.scenarioId, 2, 7, 20]);
  await assert.rejects(assertSceneGrant({ query: async () => ({ rows: [{ allowed: false }] }) }, b), { code: 'SHOP_SCENE_STALE' });
});
test('multiple retained practices require explicit selection and never silently merge', async () => {
  let grantCalls = 0;
  const scenes = [{ sceneId: ids.sceneId, isDefault: false }, { sceneId: ids.grantId, isDefault: false }];
  const repository = { candidates: async () => [], adopt: async () => scenes, list: async () => scenes,
    grant: async () => { grantCalls++; }, select: async () => {}, withLease: async () => {} };
  const service = createSecureShopScenes({ repository, reviewPool: { query: async () => { throw Error('Unexpected target write'); } }, launches: { assertCurrent: async () => {} } });
  await assert.rejects(service.resolve(current), { code: 'SHOP_SCENE_SELECTION_REQUIRED' });
  await assert.rejects(service.readExisting(current), { code: 'SHOP_SCENE_SELECTION_REQUIRED' });
  assert.equal(grantCalls, 0);
});
test('existing-only API resolution does not discover, adopt or provision a shop', async () => {
  const repository = { candidates: async () => { throw Error('Unexpected discovery'); }, adopt: async () => { throw Error('Unexpected adoption'); },
    list: async () => [], grant: async () => { throw Error('Unexpected grant'); }, select: async () => {}, withLease: async () => {} };
  const service = createSecureShopScenes({ repository, reviewPool: { query: async () => { throw Error('Unexpected database write'); } }, launches: { assertCurrent: async () => {} } });
  assert.equal(await service.readExisting(current), null);
});
