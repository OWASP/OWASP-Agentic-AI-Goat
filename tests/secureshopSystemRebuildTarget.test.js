'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createSystemRebuildTargetResolver } = require('../server/services/secureshopSystemRebuildTarget');
const { assertPersonaProductEffect } = require('../server/services/secureshopPersonaProductEffect');
const { createSceneBinding } = require('../server/services/secureshopSceneBinding');
const id = '11111111-1111-4111-8111-111111111111';
const scope = { launchId: id, scenarioId: id, generation: 1, platformOwnerId: 1, platformSessionId: 2 };
function fixture() {
  const state = { reads: 0, opens: 0, checks: 0 };
  const input = { scope, persona: { id: 3, role: 'admin' }, personaSession: { sessionId: id, authorityVersion: '1' } };
  const launches = {
    assertCurrent: async () => { if (state.retired) throw Error('retired'); },
    readExistingProductsTarget: async () => { state.reads++; return state.absent ? null : { ...scope, kind: 'products', targetId: id, ...(state.foreign ? { generation: 2 } : {}) }; },
    reserveProductsTarget: () => assert.fail('Read-only resolution must not allocate'),
  };
  const products = {
    open: async binding => { state.opens++; if (state.revokeOnOpen) state.revoked = true; return state.unprovisioned ? null : { ...binding }; },
    provision: () => assert.fail('Read-only resolution must not provision'),
  };
  const personaAuthority = { capture: async args => ({
    binding: { ...args.scope, personaId: args.personaId, role: args.role, sessionId: args.sessionId,
      authorityVersion: state.badFence ? '2' : args.authorityVersion },
    assertRemoteAdmission: async () => { state.checks++; if (state.revoked) throw Error('revoked'); },
    withCrossStoreEffect: async work => work(),
  }) };
  return { state, input, resolve: createSystemRebuildTargetResolver({ launches, products, personaAuthority }) };
}
test('admin resolution returns only existing target and captured effect authority', async () => {
  const f = fixture(), result = await f.resolve(f.input);
  assert.deepEqual(result.binding, { ...scope, targetId: id });
  assert.equal(assertPersonaProductEffect(result.personaEffect), result.personaEffect);
  assert.equal(f.state.reads, 1); assert.equal(f.state.opens, 1);
  assert.ok(Object.isFrozen(result) && Object.isFrozen(result.binding));
});
test('missing reservation, foreign reservation and unprovisioned target fail without allocation', async () => {
  for (const key of ['absent', 'foreign', 'unprovisioned']) {
    const f = fixture(); f.state[key] = true;
    await assert.rejects(f.resolve(f.input), { code: 'PRODUCT_TARGET_UNAVAILABLE' });
    assert.equal(f.state.opens, key === 'unprovisioned' ? 1 : 0);
  }
});
test('nonadmin, invalid session and substituted authority fail before reading target', async () => {
  for (const key of ['role', 'session', 'badFence']) {
    const f = fixture();
    if (key === 'role') f.input.persona.role = 'customer';
    if (key === 'session') f.input.personaSession.authorityVersion = '9007199254740992';
    if (key === 'badFence') f.state.badFence = true;
    await assert.rejects(f.resolve(f.input)); assert.equal(f.state.reads, 0);
  }
});
test('retirement, revoked session and abort prevent usable admission', async () => {
  for (const key of ['retired', 'revokeOnOpen', 'abort']) {
    const f = fixture(), controller = new AbortController();
    if (key === 'abort') controller.abort(); else f.state[key] = true;
    await assert.rejects(f.resolve(f.input, { signal: controller.signal }));
  }
});

test('admin rebuild resolves a retained birth target through an explicit current scene', async () => {
  const storage = { targetId: id,
    launchId: '22222222-2222-4222-8222-222222222222',
    scenarioId: '33333333-3333-4333-8333-333333333333', generation: 1,
    platformOwnerId: scope.platformOwnerId, platformSessionId: 9 };
  const scene = createSceneBinding(storage, {
    sceneId: '44444444-4444-4444-8444-444444444444', sceneGeneration: 1,
    grantId: '55555555-5555-4555-8555-555555555555', execution: scope,
    withLease: work => work(),
  });
  const f = fixture();
  const resolver = createSystemRebuildTargetResolver({
    launches: { assertCurrent: async () => {},
      readExistingProductsTarget: () => assert.fail('scene read must use existing-only resolver') },
    scenes: { readExisting: async () => scene },
    products: { open: async actual => { assert.equal(actual, scene); return { ...actual }; } },
    personaAuthority: { capture: async args => ({
      binding: { ...args.scope, personaId: args.personaId, role: args.role,
        sessionId: args.sessionId, authorityVersion: args.authorityVersion },
      assertRemoteAdmission: async () => {}, withCrossStoreEffect: work => work(),
    }) },
  });
  const result = await resolver(f.input);
  assert.equal(result.binding, scene);
  assert.equal(result.binding.launchId, storage.launchId);
  assert.equal(result.binding.scene.execution.launchId, scope.launchId);
});
