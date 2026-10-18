'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createSceneBinding } = require('../server/services/secureshopSceneBinding');
const { createSecureShopBoundIdorLessonRepository } =
  require('../server/database/postgres/secureshopBoundIdorLessonRepository');
const { createImmutableTemplateVictimReader } =
  require('../server/database/postgres/secureshopBoundIdorLessonRepository');

const SCOPE = Object.freeze({ launchId: '11111111-1111-4111-8111-111111111111',
  scenarioId: '22222222-2222-4222-8222-222222222222', generation: 3,
  platformOwnerId: 8, platformSessionId: 9 });
const STORAGE = Object.freeze({ ...SCOPE, targetId: '33333333-3333-4333-8333-333333333333' });
const SCENE = createSceneBinding(STORAGE, { sceneId: '44444444-4444-4444-8444-444444444444',
  sceneGeneration: 2, grantId: '55555555-5555-4555-8555-555555555555', execution: SCOPE,
  withLease: work => work() });
const ORIGIN = Object.freeze({ sessionId: '66666666-6666-4666-8666-666666666666',
  requestId: '77777777-7777-4777-8777-777777777777',
  runId: '88888888-8888-4888-8888-888888888888', step: 1,
  callId: 'call_1', toolKey: 'lesson.cart_remove' });
const PERSONA = Object.freeze({ id: 1000000001, role: 'customer' });
const SESSION = Object.freeze({ sessionId: '99999999-9999-4999-8999-999999999999', authorityVersion: '1' });

function fakeDatabase() {
  const state = { active: true, birth: null, operations: new Map(), cart: true,
    deleted: 0, orderReads: 0, birthInserts: 0, operationInserts: 0, queries: [], transaction: null };
  const query = async (sql, params = []) => {
    state.queries.push({ sql, params });
    if (sql === 'BEGIN') {
      state.transaction = { cart: state.cart, deleted: state.deleted,
        operationInserts: state.operationInserts, operations: new Map(state.operations) };
      return { rows: [], rowCount: 0 };
    }
    if (sql === 'ROLLBACK') {
      Object.assign(state, state.transaction);
      state.transaction = null;
      return { rows: [], rowCount: 0 };
    }
    if (sql === 'COMMIT') { state.transaction = null; return { rows: [], rowCount: 0 }; }
    if (sql.includes('set_config') || sql.includes('pg_advisory_xact_lock')) return { rows: [], rowCount: 0 };
    if (sql.includes('assert_scene_execution_grant')) return { rows: [{ allowed: state.active }], rowCount: 1 };
    if (sql.includes('FROM secureshop_review.product_targets')) {
      return { rows: [{ lifecycle: state.active ? 'active' : 'retired' }], rowCount: 1 };
    }
    if (sql.includes('FROM secureshop_review.owned_idor_lesson_births')) {
      return { rows: state.birth ? [state.birth] : [], rowCount: state.birth ? 1 : 0 };
    }
    if (sql.includes('FROM secureshop_review.product_target_products')) {
      return { rows: [{ product_id: 7 }], rowCount: 1 };
    }
    if (sql.includes('INSERT INTO secureshop_review.product_target_cart_items')) {
      return { rows: [{ cart_item_id: '1001', shop_user_id: 11, product_id: 7, quantity: 1,
        added_at_utc: '2026-10-12T00:00:00.000000Z' }], rowCount: 1 };
    }
    if (sql.includes('INSERT INTO secureshop_review.product_target_orders')) {
      return { rows: [{ order_id: '2001', shop_user_id: 11, total_amount: '1.00',
        subtotal_amount: '1.00', discount_amount: '0.00', coupon_code: null, coupon_percent: null,
        status: 'confirmed', payment_method: 'synthetic lesson', payment_status: 'approved',
        shipping_address: 'Synthetic lesson address',
        order_date_utc: '2026-10-12T00:00:00.000000Z',
        updated_at_utc: '2026-10-12T00:00:00.000000Z' }], rowCount: 1 };
    }
    if (sql.includes('INSERT INTO secureshop_review.product_target_order_items')) {
      return { rows: [{ order_item_id: '3001', product_id: 7, product_name: 'Synthetic lesson product',
        quantity: 1, price: '1.00', discount_amount: '0.00' }], rowCount: 1 };
    }
    if (sql.includes('INSERT INTO secureshop_review.owned_idor_lesson_births')) {
      state.birthInserts++;
      state.birth = { birth_id: params[0], target_id: params[1], scene_id: params[2],
        scene_generation: params[3], birth_grant_id: params[4], birth_launch_id: params[5],
        birth_scenario_id: params[6], birth_generation: params[7], platform_owner_id: params[8],
        attacker_shop_user_id: params[9], victim_shop_user_id: params[10],
        victim_identity_sha256: params[11], cart_item_id: String(params[12]),
        order_id: String(params[13]), cart_preimage: JSON.parse(params[14]),
        order_preimage: JSON.parse(params[15]), birth_sha256: params[16] };
      return { rows: [state.birth], rowCount: 1 };
    }
    if (sql.includes('FROM secureshop_review.owned_idor_lesson_operations')) {
      const row = state.operations.get(params[0]);
      return { rows: row ? [row] : [], rowCount: row ? 1 : 0 };
    }
    if (sql.includes('DELETE FROM secureshop_review.product_target_cart_items')) {
      if (sql.includes('AND shop_user_id=$3') || !state.cart) return { rows: [], rowCount: 0 };
      state.cart = false; state.deleted++;
      return { rows: [{ cart_item_id: '1001', shop_user_id: 11, product_id: 7, quantity: 1,
        added_at_utc: '2026-10-12T00:00:00.000000Z' }], rowCount: 1 };
    }
    if (sql.includes('SELECT order_id,shop_user_id,total_amount::text')) {
      state.orderReads++;
      if (sql.includes('AND shop_user_id=$3')) return { rows: [], rowCount: 0 };
      return { rows: [{ order_id: '2001', shop_user_id: 11, total_amount: '1.00',
        subtotal_amount: '1.00', discount_amount: '0.00', coupon_code: null, coupon_percent: null,
        status: 'confirmed', payment_method: 'synthetic lesson', payment_status: 'approved',
        shipping_address: 'Synthetic lesson address',
        order_date_utc: '2026-10-12T00:00:00.000000Z',
        updated_at_utc: '2026-10-12T00:00:00.000000Z' }], rowCount: 1 };
    }
    if (sql.includes('FROM secureshop_review.product_target_order_items')) {
      return { rows: [{ order_item_id: '3001', product_id: 7, product_name: 'Synthetic lesson product',
        quantity: 1, price: '1.00', discount_amount: '0.00' }], rowCount: 1 };
    }
    if (sql.includes('INSERT INTO secureshop_review.owned_idor_lesson_operations')) {
      state.operationInserts++;
      const row = { operation_id: params[0], birth_id: params[1], target_id: params[2],
        scene_id: params[3], scene_generation: params[4], grant_id: params[5],
        launch_id: params[6], scenario_id: params[7], generation: params[8],
        platform_owner_id: params[9], platform_session_id: params[10], actor_shop_user_id: params[11],
        persona_session_id: params[12], authority_version: params[13], action: params[14],
        numeric_id: String(params[15]), mode_snapshot: JSON.parse(params[16]),
        turn_origin: JSON.parse(params[17]), request_sha256: params[18],
        result_json: JSON.parse(params[19]), receipt_sha256: params[20] };
      state.operations.set(row.operation_id, row);
      return { rows: [row], rowCount: 1 };
    }
    throw new Error(`Unexpected SQL: ${sql}`);
  };
  return { state, pool: { query, async connect() { return { query, release() {} }; } } };
}
function fixture() {
  const { state, pool } = fakeDatabase(), tokens = new WeakSet();
  const modeAuthority = { assertToken(token) {
    if (!tokens.has(token)) throw new Error('Untrusted mode token');
    return token;
  } };
  const mode = (value, atEffect = async () => {}) => { const token = Object.freeze({ snapshot: Object.freeze({
    version: 1, featureId: 'customer_idor', policyVersion: 'reserved-synthetic-cart-and-order-ownership-v1',
    mode: value, generation: 1, modeStamp: 'stamp', scope: SCOPE }),
    assertCurrentAtEffect: atEffect }); tokens.add(token); return token; };
  const repository = createSecureShopBoundIdorLessonRepository(pool, { modeAuthority,
    readVictimIdentity: async () => ({ id: 11, role: 'customer',
      identityKind: 'teaching_persona', sourceSha256: 'a'.repeat(64) }) });
  const base = { scope: SCOPE, persona: PERSONA, personaSession: SESSION, retainedScene: SCENE };
  return { state, repository, base, mode };
}

test('birth is immutable and replay returns committed V10 effect before missing cart lookup', async () => {
  const x = fixture();
  const first = await x.repository.prepare(x.base), again = await x.repository.prepare(x.base);
  assert.deepEqual(again, first);
  assert.deepEqual(await x.repository.readBirth(x.base), first.birth);
  assert.equal(x.state.birthInserts, 1);
  assert.deepEqual(await x.repository.readCards(x.base), first.cards);
  const input = { ...x.base, modeToken: x.mode('vuln'), action: 'cart_remove',
    numericId: first.cards[0].numericId, turnOrigin: ORIGIN };
  const result = await x.repository.execute(input);
  assert.equal(result.result.status, 'deleted');
  assert.equal(result.result.preimage.shopUserId, 11);
  assert.deepEqual(await x.repository.execute(input), result);
  assert.deepEqual(await x.repository.readSaved({ ...input, operationId: result.operationId }), result);
  assert.deepEqual(await x.repository.prepare(x.base), first);
  assert.equal(x.state.deleted, 1);
  assert.equal(x.state.cart, false); // Preparation never recreates the deleted lesson row.
  assert.equal(x.state.birthInserts, 1);
  assert.equal(x.state.operationInserts, 1);
  assert.equal(x.state.cart, false);
});

test('victim reader accepts only the immutable student customer template actor', async () => {
  const reader = createImmutableTemplateVictimReader({ async query(sql, params) {
    assert.match(sql, /bound_persona_templates/);
    assert.deepEqual(params, [11]);
    return { rows: [{ id: 11, role: 'customer', source_sha256: Buffer.alloc(32, 0xaa),
      principal_id: null, original_platform_owner_id: null }] };
  } });
  assert.deepEqual(await reader(), { id: 11, role: 'customer', identityKind: 'teaching_persona',
    sourceSha256: 'aa'.repeat(32) });
  const foreign = createImmutableTemplateVictimReader({ async query() { return { rows: [{ id: 11,
    role: 'customer', source_sha256: Buffer.alloc(32), principal_id: 'foreign',
    original_platform_owner_id: 3 }] }; } });
  await assert.rejects(foreign(), { code: 'IDOR_LESSON_VICTIM_INVALID' });
});

test('fixed mode denies reserved foreign rows; V12 vuln read is durable and reset fences it', async () => {
  const x = fixture(), prepared = await x.repository.prepare(x.base);
  const fixed = x.mode('fixed'), vuln = x.mode('vuln');
  const cart = await x.repository.execute({ ...x.base, modeToken: fixed,
    action: 'cart_remove', numericId: prepared.cards[0].numericId, turnOrigin: ORIGIN });
  assert.deepEqual(cart.result, { status: 'denied', preimage: null });
  assert.equal(x.state.deleted, 0);
  const orderOrigin = { ...ORIGIN, callId: 'call_2', toolKey: 'lesson.order_status' };
  const denied = await x.repository.execute({ ...x.base, modeToken: fixed,
    action: 'order_status', numericId: prepared.cards[1].numericId, turnOrigin: orderOrigin });
  assert.deepEqual(denied.result, { status: 'denied', order: null });
  const disclosed = await x.repository.execute({ ...x.base, modeToken: vuln,
    action: 'order_status', numericId: prepared.cards[1].numericId,
    turnOrigin: { ...orderOrigin, callId: 'call_3' } });
  assert.equal(disclosed.result.status, 'disclosed');
  assert.equal(disclosed.result.order.shippingAddress, 'Synthetic lesson address');
  await assert.rejects(x.repository.readSaved({ ...x.base, modeToken: fixed,
    operationId: disclosed.operationId }), { code: 'IDOR_LESSON_SAVED_UNAVAILABLE' });
  x.state.active = false;
  await assert.rejects(x.repository.readSaved({ ...x.base, modeToken: vuln,
    operationId: disclosed.operationId }), { code: 'SHOP_SCENE_STALE' });
});

test('forged scene, actor, reserved ID and changed same-call request fail closed', async () => {
  const x = fixture(), prepared = await x.repository.prepare(x.base);
  await assert.rejects(x.repository.readCards({ ...x.base,
    retainedScene: { ...SCENE } }), { code: 'SHOP_SCENE_STALE' });
  await assert.rejects(x.repository.readCards({ ...x.base,
    persona: { id: 11, role: 'customer' } }), { code: 'IDOR_LESSON_ACTOR_INVALID' });
  await assert.rejects(x.repository.execute({ ...x.base, modeToken: x.mode('vuln'),
    action: 'cart_remove', numericId: prepared.cards[0].numericId + 1,
    turnOrigin: ORIGIN }), { code: 'IDOR_LESSON_ID_INVALID' });
  const token = x.mode('fixed');
  await x.repository.execute({ ...x.base, modeToken: token, action: 'cart_remove',
    numericId: prepared.cards[0].numericId, turnOrigin: ORIGIN });
  await assert.rejects(x.repository.execute({ ...x.base, modeToken: x.mode('vuln'),
    action: 'cart_remove', numericId: prepared.cards[0].numericId,
    turnOrigin: ORIGIN }), { code: 'IDOR_LESSON_OPERATION_CONFLICT' });
});

test('saved private result is bound to original persona session and immutable receipt digest', async () => {
  const x = fixture(), prepared = await x.repository.prepare(x.base), token = x.mode('vuln');
  const origin = { ...ORIGIN, toolKey: 'lesson.order_status' };
  const receipt = await x.repository.execute({ ...x.base, modeToken: token,
    action: 'order_status', numericId: prepared.cards[1].numericId, turnOrigin: origin });
  await assert.rejects(x.repository.readSaved({ ...x.base, modeToken: token,
    personaSession: { ...SESSION, sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' },
    operationId: receipt.operationId }), { code: 'IDOR_LESSON_SAVED_UNAVAILABLE' });
  const stored = x.state.operations.get(receipt.operationId);
  stored.result_json.order.shippingAddress = 'Tampered';
  await assert.rejects(x.repository.readSaved({ ...x.base, modeToken: token,
    operationId: receipt.operationId }), { code: 'IDOR_LESSON_RECEIPT_INVALID' });
});

test('mode drift after a V10 deletion aborts its transaction without an effect or receipt', async () => {
  const x = fixture(), prepared = await x.repository.prepare(x.base);
  let checks = 0;
  const token = x.mode('vuln', async () => {
    if (++checks === 2) throw Object.assign(new Error('mode changed'), { code: 'SECURESHOP_FEATURE_MODE_STALE' });
  });
  await assert.rejects(x.repository.execute({ ...x.base, modeToken: token,
    action: 'cart_remove', numericId: prepared.cards[0].numericId,
    turnOrigin: ORIGIN }), { code: 'SECURESHOP_FEATURE_MODE_STALE' });
  assert.equal(checks, 2);
  assert.equal(x.state.cart, true);
  assert.equal(x.state.deleted, 0);
  assert.equal(x.state.operationInserts, 0);
});
