'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createSceneBinding } = require('../server/services/secureshopSceneBinding');
const { createSecureShopBoundCommerceRepository } = require(
  '../server/database/postgres/secureshopBoundCommerceRepository');
const { createSecureShopBoundAccountRepository } = require(
  '../server/database/postgres/secureshopBoundAccountRepository');

const birth = Object.freeze({ targetId: '30000000-0000-4000-8000-000000000091',
  launchId: '10000000-0000-4000-8000-000000000091',
  scenarioId: '20000000-0000-4000-8000-000000000091',
  generation: 2, platformOwnerId: 91, platformSessionId: 901 });
const current = Object.freeze({ launchId: '10000000-0000-4000-8000-000000000092',
  scenarioId: '20000000-0000-4000-8000-000000000092',
  generation: 3, platformOwnerId: 91, platformSessionId: 902 });

function fixture(kind, { revokeAtSecondGrant = false } = {}) {
  const calls = [], audits = [];
  let leased = false;
  const binding = createSceneBinding(birth, {
    sceneId: '40000000-0000-4000-8000-000000000091', sceneGeneration: 1,
    grantId: '50000000-0000-4000-8000-000000000091', execution: current,
    async withLease(work) {
      assert.equal(leased, false);
      leased = true; calls.push('lease-begin');
      try { return await work(); } finally { calls.push('lease-end'); leased = false; }
    },
  });
  let grants = 0;
  const client = { async query(sql, args) {
    calls.push(sql);
    if (sql === 'BEGIN' || sql === 'COMMIT' || sql === 'ROLLBACK') return { rows: [] };
    assert.equal(leased, true, 'every storage query stays inside the identity scene lease');
    if (sql.includes('assert_scene_execution_grant')) {
      grants++;
      assert.deepEqual(args, [binding.scene.grantId, binding.scene.sceneId, 1,
        birth.targetId, current.launchId, current.scenarioId, current.generation,
        current.platformOwnerId, current.platformSessionId]);
      return { rows: [{ allowed: !revokeAtSecondGrant || grants === 1 }] };
    }
    if (sql.includes('FROM secureshop_review.product_targets')) {
      assert.deepEqual(args, [birth.targetId, birth.launchId, birth.scenarioId,
        birth.generation, birth.platformOwnerId, birth.platformSessionId]);
      return { rows: [{ lifecycle: 'active' }] };
    }
    if (sql.includes('pg_advisory_xact_lock')) return { rows: [] };
    if (kind === 'account' && sql.includes('product_target_profile_overlays')) {
      assert.equal(args[0], birth.targetId);
      return { rows: [{ email: args[2], full_name: args[3], phone: args[4] }] };
    }
    if (kind === 'commerce' && sql.includes('SELECT cart_item_id,quantity')) {
      assert.equal(args[0], birth.targetId);
      return { rows: [] };
    }
    if (kind === 'commerce' && sql.includes('INSERT INTO secureshop_review.product_target_cart_items')) {
      assert.equal(args[0], birth.targetId);
      return { rows: [{ cart_item_id: 17 }] };
    }
    throw new Error(`unexpected query: ${sql}`);
  }, release() {} };
  const pool = { query() { throw new Error('transaction required'); },
    async connect() { return client; } };
  const deps = { async checkCurrent(actual) {
    calls.push('current-check');
    assert.deepEqual(actual, current, 'current execution, never birth launch, supplies authority');
  }, auditStore: { async append(transaction, event) {
    assert.equal(transaction, client);
    assert.equal(leased, true);
    audits.push(event);
  } } };
  const repository = kind === 'account'
    ? createSecureShopBoundAccountRepository(pool, deps)
    : createSecureShopBoundCommerceRepository(pool, deps);
  return { binding, repository, calls, audits, grants: () => grants };
}

for (const kind of ['account', 'commerce']) {
  const effect = f => kind === 'account'
    ? f.repository.updateProfile(f.binding, 41,
      { email: 'customer@example.test', fullName: 'Customer', phone: null },
      { id: 41, role: 'customer' })
    : f.repository.addCart(f.binding, { shopUserId: 41, productId: 7, quantity: 1 });

  test(`${kind} effect uses old storage only under current scene lease and audits current execution`, async () => {
    const f = fixture(kind);
    await effect(f);
    assert.equal(f.grants(), 2);
    assert(f.calls.indexOf('lease-begin') < f.calls.indexOf('BEGIN'));
    assert(f.calls.indexOf('COMMIT') < f.calls.indexOf('lease-end'));
    assert.equal(f.audits.length, 1);
    assert.deepEqual(f.audits[0].scope, current);
    const params = JSON.parse(f.audits[0].paramsJson);
    assert.equal(params.storageTargetId, birth.targetId);
    assert.equal(params.sceneId, f.binding.scene.sceneId);
    assert.equal(params.sceneGeneration, 1);
  });

  test(`${kind} effect rolls back if scene grant is lost before commit`, async () => {
    const f = fixture(kind, { revokeAtSecondGrant: true });
    await assert.rejects(effect(f), { code: 'SHOP_SCENE_STALE' });
    assert.equal(f.grants(), 2);
    assert(f.calls.includes('ROLLBACK'));
    assert(!f.calls.includes('COMMIT'));
    assert.equal(f.calls.at(-1), 'lease-end');
  });

  test(`${kind} rejects caller-supplied scene metadata before any storage access`, async () => {
    const f = fixture(kind);
    const forged = { ...birth, scene: f.binding.scene };
    await assert.rejects(effect({ ...f, binding: forged }), { code: 'SHOP_SCENE_STALE' });
    assert.deepEqual(f.calls, []);
  });
}
