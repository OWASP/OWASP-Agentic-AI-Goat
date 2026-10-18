'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createSceneBinding } = require('../server/services/secureshopSceneBinding');
const { createBoundCouponRepository } = require('../server/database/postgres/secureshopBoundCouponRepository');
const { createSecureShopBoundRefundRepository } = require('../server/database/postgres/secureshopBoundRefundRepository');

const birth = Object.freeze({ targetId: '30000000-0000-4000-8000-000000000093',
  launchId: '10000000-0000-4000-8000-000000000093',
  scenarioId: '20000000-0000-4000-8000-000000000093',
  generation: 2, platformOwnerId: 93, platformSessionId: 903 });
const current = Object.freeze({ launchId: '10000000-0000-4000-8000-000000000094',
  scenarioId: '20000000-0000-4000-8000-000000000094',
  generation: 3, platformOwnerId: 93, platformSessionId: 904 });
const personaSessionId = '70000000-0000-4000-8000-000000000093';
const operationId = '80000000-0000-4000-8000-000000000093';

function scene(withLease) {
  return createSceneBinding(birth, { sceneId: '40000000-0000-4000-8000-000000000093',
    sceneGeneration: 1, grantId: '50000000-0000-4000-8000-000000000093',
    execution: current, withLease });
}

test('coupon admission writes current execution receipt against immutable birth target under scene lease', async () => {
  const calls = [], checks = [], records = [];
  let leased = false, grants = 0;
  const target = scene(async work => { leased = true; try { return await work(); } finally { leased = false; } });
  const client = { release() {}, async query(sql, args = []) {
    calls.push(sql);
    if (['BEGIN', 'COMMIT', 'ROLLBACK'].includes(sql)) return { rows: [] };
    assert.equal(leased, true);
    if (sql.includes('assert_scene_execution_grant')) {
      grants++; return { rows: [{ allowed: true }] };
    }
    if (sql.includes('FROM secureshop_review.product_targets')) {
      assert.deepEqual(args, [birth.targetId, birth.launchId, birth.scenarioId,
        birth.generation, birth.platformOwnerId, birth.platformSessionId]);
      return { rows: [{ lifecycle: 'active' }] };
    }
    if (sql.startsWith('SELECT * FROM secureshop_review.bound_commerce_operations')) return { rows: [] };
    if (sql.startsWith('SELECT count(*)')) return { rows: [{ count: 0 }] };
    if (sql.startsWith('INSERT INTO secureshop_review.bound_commerce_operations')) {
      records.push(args); return { rows: [], rowCount: 1 };
    }
    return { rows: [] };
  } };
  const repository = createBoundCouponRepository({ pool: { connect: async () => client },
    checkCurrent: async scope => { checks.push(scope); assert.deepEqual(scope, current); } });
  const admitted = await repository.admitCoupon({ target, persona: { id: 41, role: 'customer' },
    personaSession: { sessionId: personaSessionId, authorityVersion: '1' },
    operationId, mode: 'vuln', code: 'WELCOME10',
    coupons: [{ id: 1, code: 'WELCOME10', discount_percent: 10, active: 1 }] });
  assert.equal(admitted.state, 'admitted');
  assert.equal(grants, 2);
  assert.equal(checks.length, 2);
  assert.equal(records[0][1], birth.targetId);
  assert.deepEqual(JSON.parse(records[0][8]).scope, current);
  assert(calls.includes('COMMIT'));
});

test('refund operation attributes current execution while ticket remains on birth target', async () => {
  const calls = [], events = [], checks = [];
  let leased = false, grants = 0;
  const target = scene(async work => { leased = true; try { return await work(); } finally { leased = false; } });
  const client = { release() {}, async query(sql, args = []) {
    calls.push(sql);
    if (['BEGIN', 'COMMIT', 'ROLLBACK'].includes(sql)) return { rows: [] };
    assert.equal(leased, true);
    if (sql.includes('assert_scene_execution_grant')) {
      grants++; return { rows: [{ allowed: true }] };
    }
    if (sql.includes('FROM secureshop_review.product_targets')) {
      assert.deepEqual(args, [birth.targetId, birth.launchId, birth.scenarioId,
        birth.generation, birth.platformOwnerId, birth.platformSessionId]);
      return { rows: [{ lifecycle: 'active' }] };
    }
    if (sql.includes('FROM secureshop_review.bound_audit_events')) return { rows: [] };
    if (sql.includes('FROM secureshop_review.product_target_orders')) {
      assert.equal(args[0], birth.targetId);
      return { rows: [{ order_id: 12, status: 'confirmed', payment_status: 'approved' }] };
    }
    if (sql.includes('INSERT INTO secureshop_review.product_target_refund_requests')) {
      assert.equal(args[0], birth.targetId);
      return { rows: [{ ticket_id: '77', order_id: '12' }], rowCount: 1 };
    }
    return { rows: [] };
  } };
  const repository = createSecureShopBoundRefundRepository({ query() {}, connect: async () => client }, {
    checkCurrent: async scope => { checks.push(scope); assert.deepEqual(scope, current); },
    auditStore: { async append(transaction, event) {
      assert.equal(transaction, client); assert.equal(leased, true); events.push(event);
    } },
  });
  const result = await repository.create(target, { shopUserId: 41, orderId: 12,
    requestId: '90000000-0000-4000-8000-000000000093',
    runId: 'a0000000-0000-4000-8000-000000000093', reason: 'duplicate charge',
    operation: { operationId, personaSessionId, authorityVersion: '1', toolInvocationId: 'tool-call-1' } });
  assert.equal(result.ticket_id, '77');
  assert.equal(grants, 2);
  assert.equal(checks.length, 2);
  assert.deepEqual(events.map(event => event.scope), [current, current]);
  const packet = JSON.parse(events[1].paramsJson);
  assert.deepEqual(packet.receipt.scope, { targetId: birth.targetId, ...current });
  assert.equal(packet.storageTargetId, birth.targetId);
  assert.equal(packet.sceneId, target.scene.sceneId);
  assert(calls.includes('COMMIT'));
});

test('coupon and refund deny forged scene metadata before any storage effect', async () => {
  const forged = { ...birth, scene: scene(work => work()).scene };
  let connections = 0;
  const coupon = createBoundCouponRepository({ pool: { async connect() { connections++; } }, checkCurrent: async () => {} });
  await assert.rejects(coupon.recover({ target: forged, persona: { id: 41, role: 'customer' },
    personaSession: { sessionId: personaSessionId, authorityVersion: '1' },
    operationId, mode: 'vuln' }), { code: 'SHOP_SCENE_STALE' });
  const refund = createSecureShopBoundRefundRepository({ query() {}, async connect() { connections++; } },
    { checkCurrent: async () => {} });
  await assert.rejects(refund.create(forged, { shopUserId: 41, orderId: 12,
    requestId: operationId, reason: 'duplicate charge' }), { code: 'SHOP_SCENE_STALE' });
  assert.equal(connections, 0);
});
