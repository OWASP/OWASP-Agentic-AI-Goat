'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { createSelectedSceneEffect } = require('../server/database/postgres/secureshopSelectedSceneEffect');

function fixture() {
  const scope = { launchId: randomUUID(), scenarioId: randomUUID(), generation: 2,
    platformOwnerId: 7, platformSessionId: 11 };
  const expectedTarget = { targetId: randomUUID(), sceneId: randomUUID(),
    sceneGeneration: 3, grantId: randomUUID() };
  const events = [], selects = [];
  let owner = true, current = true, commitFails = false, released = 0;
  const client = { async query(sql, values) {
    if (sql.startsWith('SELECT id FROM identity.secureshop_authority_owners')) {
      events.push('owner-lock'); assert.match(sql, /FOR SHARE/);
      assert.deepEqual(values, [scope.platformOwnerId]);
      return { rowCount: owner ? 1 : 0 };
    }
    if (sql.startsWith('SELECT l.launch_id')) {
      events.push('selected-lock'); selects.push({ sql, values });
      assert.ok(events.includes('owner-lock'));
      return { rowCount: current ? 1 : 0 };
    }
    events.push(sql);
    if (sql === 'COMMIT' && commitFails) throw Error('commit lost');
    return { rows: [] };
  }, release() { released++; } };
  const lease = createSelectedSceneEffect({ pool: { connect: async () => client },
    launches: { async assertCurrent(value) { assert.deepEqual(value, scope); events.push('launch-admission'); } } });
  return { scope, expectedTarget, lease, events, selects,
    get released() { return released; },
    set current(value) { current = value; }, set owner(value) { owner = value; },
    set commitFails(value) { commitFails = value; } };
}

test('owner and exact selected scene locks surround short work and a same-client post-check', async () => {
  const f = fixture();
  const result = await f.lease(f, async () => { f.events.push('review-commit'); return { saved: true }; });
  assert.deepEqual(result, { saved: true });
  assert.ok(f.events.indexOf('owner-lock') < f.events.indexOf('selected-lock'));
  assert.ok(f.events.indexOf('selected-lock') < f.events.indexOf('review-commit'));
  assert.ok(f.events.lastIndexOf('selected-lock') > f.events.indexOf('review-commit'));
  assert.ok(f.events.indexOf('COMMIT') > f.events.lastIndexOf('selected-lock'));
  assert.equal(f.released, 1);
  assert.equal(f.selects.length, 2);
  assert.deepEqual(f.selects[0], f.selects[1]);
  assert.deepEqual(f.selects[0].values, [f.scope.launchId, f.scope.scenarioId,
    2, 7, 11, f.expectedTarget.sceneId, f.expectedTarget.targetId, 3, f.expectedTarget.grantId]);
  assert.match(f.selects[0].sql, /x\.execution_session_id=e\.session_id/);
  assert.match(f.selects[0].sql, /g\.original_platform_session_id=\$5/);
  assert.match(f.selects[0].sql, /FOR SHARE OF l,x,s/);
  assert.equal(f.events.some(value => /^(INSERT|UPDATE|DELETE)/.test(value)), false);
});

test('missing owner or stale selection never enters work and releases rolled-back transaction', async () => {
  for (const key of ['owner', 'current']) {
    const f = fixture(); f[key] = false;
    let effects = 0;
    await assert.rejects(f.lease(f, async () => { effects++; }), { code: 'SHOP_SCENE_STALE' });
    assert.equal(effects, 0); assert.equal(f.released, 1);
    assert.equal(f.events.at(-1), 'ROLLBACK');
  }
});

test('input snapshot survives caller mutation; malformed target fails before admission', async () => {
  const f = fixture(), original = { ...f.expectedTarget };
  await f.lease(f, async () => { f.expectedTarget.sceneId = randomUUID(); });
  assert.equal(f.selects[1].values[5], original.sceneId);
  const denied = fixture();
  await assert.rejects(denied.lease({ scope: denied.scope,
    expectedTarget: { ...denied.expectedTarget, extra: true } }, async () => {}),
  { code: 'SHOP_SCENE_STALE' });
  assert.equal(denied.events.length, 0);
});

test('post-work stale authority and lost lease commit report uncertainty, never rollback of review effect', async () => {
  for (const failCommit of [false, true]) {
    const f = fixture(); let persisted = false;
    await assert.rejects(f.lease(f, async () => {
      persisted = true;
      if (failCommit) f.commitFails = true; else f.current = false;
    }), error => error.code === 'PERSONA_EFFECT_OUTCOME_UNCERTAIN'
      && error.executionBoundary === true && !!error.cause);
    assert.equal(persisted, true); assert.equal(f.released, 1);
    assert.equal(f.events.at(-1), 'ROLLBACK');
  }
});

test('nested lease is rejected without taking a second connection or silently releasing outer authority', async () => {
  const f = fixture();
  await f.lease(f, async () => {
    await assert.rejects(f.lease(f, async () => assert.fail('nested effect')),
      { code: 'SHOP_SCENE_STALE' });
  });
  assert.equal(f.events.filter(value => value === 'BEGIN').length, 1);
  assert.equal(f.released, 1);
});
