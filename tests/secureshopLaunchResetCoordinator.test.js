'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createSecureShopLaunchResetCoordinator } = require('../server/services/secureshopLaunchResetCoordinator');
const resetId = '10000000-0000-4000-8000-000000000001';
function fixture(failAt) {
  const events = [];
  const step = async name => { events.push(name); if (name === failAt) throw new Error(name); };
  const dependencies = {
    launches: {
      async beginReset() { await step('begin'); return { resetId, fromGeneration: 1, toGeneration: 2 }; },
      async commitReset(input) { assert.equal(input.expectedGeneration, 2); await step('commit'); return { launchId: input.launchId, generation: 2 }; },
    },
    cleanupAuthority: { async getOperation() { await step('authority'); return { resetId, status: 'fenced',
      binding: { platformOwnerId: 7 } }; } },
    conversationLifecycle: { async retireGeneration() { await step('drain'); } },
    conversationCheckpoint: { async finalize() { await step('conversation'); return { resetId }; } },
    targetCoordinator: { async recover() { await step('targets'); return { resetId, resolved: true, activated: false, targets: 2 }; } },
    progressCheckpoint: { async finalize() { await step('progress'); return { resetId }; } },
  };
  return { dependencies, events, build: () => createSecureShopLaunchResetCoordinator(dependencies) };
}
test('reset commits only after all independent cleanup checkpoints', async () => {
  const f = fixture(); const result = await f.build().reset({ expectedGeneration: 1 });
  assert.deepEqual(f.events, ['begin', 'authority', 'drain', 'conversation', 'targets', 'progress', 'commit']);
  assert.equal(result.status, 'committed'); assert.equal(result.targets, 2);
});
test('each cleanup failure leaves commit uncalled', async () => {
  for (const stage of ['authority', 'drain', 'conversation', 'targets', 'progress']) {
    const f = fixture(stage);
    await assert.rejects(f.build().reset({}), new RegExp(stage));
    assert.equal(f.events.at(-1), stage); assert.equal(f.events.includes('commit'), false);
  }
});
test('recovery repeats durable stages but never begins or commits a launch', async () => {
  const f = fixture(); const service = f.build();
  const first = await service.recover(resetId); const second = await service.recover(resetId);
  assert.deepEqual(first, second); assert.equal(first.activated, false);
  assert.equal(f.events.includes('begin'), false); assert.equal(f.events.includes('commit'), false);
});
test('abort waits for admitted retirement before rejecting and skips subsequent stages', async () => {
  const f = fixture(); const controller = new AbortController(); let release;
  const gate = new Promise(resolve => { release = resolve; });
  f.dependencies.conversationLifecycle.retireGeneration = async () => { f.events.push('drain'); await gate; };
  let settled = false;
  const pending = f.build().reset({ signal: controller.signal }).finally(() => { settled = true; });
  const rejection = assert.rejects(pending, { name: 'AbortError' });
  await new Promise(resolve => setImmediate(resolve)); controller.abort();
  await new Promise(resolve => setImmediate(resolve)); assert.equal(settled, false);
  release(); await rejection; assert.deepEqual(f.events, ['begin', 'authority', 'drain']);
});
test('misbound checkpoint and target activation cannot authorize reset commit', async () => {
  for (const stage of ['conversationCheckpoint', 'progressCheckpoint', 'targetCoordinator']) {
    const f = fixture();
    if (stage === 'targetCoordinator') f.dependencies[stage].recover = async () => ({ resetId, resolved: true, activated: true });
    else f.dependencies[stage].finalize = async () => ({ resetId: 'wrong' });
    await assert.rejects(f.build().reset({})); assert.equal(f.events.includes('commit'), false);
  }
});
test('Analytics cleanup must drain before reset commit and cannot be skipped on failure',async()=>{
 const f=fixture();f.dependencies.analyticsLifecycle={retireGeneration:async id=>{f.events.push('analytics');return{resetId:id,retired:true};}};await f.build().reset({expectedGeneration:1});assert.ok(f.events.indexOf('analytics')>f.events.indexOf('drain'));assert.ok(f.events.indexOf('analytics')<f.events.indexOf('commit'));
 const broken=fixture();broken.dependencies.analyticsLifecycle={retireGeneration:async()=>{throw Error('private analytics unavailable');}};await assert.rejects(broken.build().reset({}),/private analytics/);assert.equal(broken.events.includes('commit'),false);
});
test('protected admission runs the exact preflight and durable begin once before cleanup', async () => {
  const f = fixture();
  let admissions = 0;
  f.dependencies.sceneResetPreflight = {
    async withOwnerLease(owner, work) {
      assert.equal(owner, 7);
      f.events.push('owner-lease');
      return work({
        async readExactResetIntent(input) {
          assert.equal(input.sceneId, '30000000-0000-4000-8000-000000000007');
          return { exists: false };
        },
        async preflightLaunches(launches, options) {
          assert.deepEqual(launches, [{ launchId: '10000000-0000-4000-8000-000000000007', generation: 1 }]);
          assert.equal(options.expectedSceneId, '30000000-0000-4000-8000-000000000007');
          f.events.push('preflight');
        },
        async reconcileRetired() { f.events.push('retired-review-check'); },
      });
    },
  };
  const result = await f.build().reset({ launchId: '10000000-0000-4000-8000-000000000007',
    platformOwnerId: 7, expectedGeneration: 1, idempotencyKey: 'one' }, {
    expectedSceneId: '30000000-0000-4000-8000-000000000007',
    withAdmission: async begin => { admissions++; f.events.push('admin-lease'); await begin(); },
  });
  assert.equal(admissions, 1);
  assert.equal(result.status, 'committed');
  assert.deepEqual(f.events.slice(0, 5), ['admin-lease', 'owner-lease', 'preflight', 'begin', 'authority']);
});

test('admission cannot bypass durable begin or invoke it twice', async () => {
  const skipped = fixture();
  await assert.rejects(skipped.build().reset({}, { withAdmission: async () => {} }),
    { code: 'RESET_CLEANUP_AUTHORITY_REQUIRED' });
  assert.deepEqual(skipped.events, []);
  const repeated = fixture();
  await assert.rejects(repeated.build().reset({}, { withAdmission: async begin => {
    await begin(); await begin();
  } }), { code: 'RESET_CLEANUP_AUTHORITY_REQUIRED' });
  assert.equal(repeated.events.filter(event => event === 'begin').length, 1);
  assert.equal(repeated.events.includes('commit'), false);
});
test('committed idempotency replay rechecks cleanup without a second generation commit', async () => {
  const f = fixture();
  const launchId = '10000000-0000-4000-8000-000000000007';
  f.dependencies.launches.beginReset = async () => {
    f.events.push('begin-replay');
    return { resetId, fromGeneration: 1, toGeneration: 2, status: 'committed',
      binding: { launchId, generation: 2 } };
  };
  const result = await f.build().reset({ launchId, expectedGeneration: 1 });
  assert.equal(result.status, 'committed');
  assert.equal(result.binding.generation, 2);
  assert.deepEqual(f.events, ['begin-replay', 'authority', 'drain', 'conversation',
    'targets', 'progress']);
});
test('existing fenced reset resumes only the exact live execution under admission', async () => {
  const f = fixture();
  const launchId = '10000000-0000-4000-8000-000000000007';
  f.dependencies.cleanupAuthority.getOperation = async () => {
    f.events.push('authority');
    return { resetId, status:'fenced', toGeneration:2,
      binding:{ launchId, generation:1, platformOwnerId:7, platformSessionId:8 } };
  };
  const result = await f.build().resumeExisting(resetId, { launchId, platformOwnerId:7,
    platformSessionId:8, withAdmission: async admit => { f.events.push('admin-lease'); await admit(); } });
  assert.equal(result.activated, true);
  assert.equal(result.toGeneration, 2);
  assert.deepEqual(f.events.slice(0, 3), ['admin-lease','authority','authority']);
  assert.equal(f.events.includes('begin'), false);
  assert.equal(f.events.includes('commit'), true);
});

test('existing reset refuses a different execution before cleanup', async () => {
  const f = fixture();
  const launchId = '10000000-0000-4000-8000-000000000007';
  f.dependencies.cleanupAuthority.getOperation = async () => ({ resetId, status:'fenced',
    toGeneration:2, binding:{ launchId, generation:1, platformOwnerId:7,
      platformSessionId:8 } });
  await assert.rejects(f.build().resumeExisting(resetId, { launchId, platformOwnerId:7,
    platformSessionId:9 }), { code:'RESET_CLEANUP_AUTHORITY_REQUIRED' });
  assert.deepEqual(f.events, []);
});
