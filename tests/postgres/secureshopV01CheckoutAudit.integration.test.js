'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');
const { createSceneBinding } = require('../../server/services/secureshopSceneBinding');
const { createLaunchScope } = require('../../server/services/secureshopConversationBinding');
const { createBoundCouponRepository } = require('../../server/database/postgres/secureshopBoundCouponRepository');
const { createSecureShopBoundCommerceRepository } = require('../../server/database/postgres/secureshopBoundCommerceRepository');
const { createCheckoutHistoryRepository } = require('../../server/database/postgres/secureshopCheckoutHistoryRepository');
const { createBoundAuditStore } = require('../../server/database/postgres/secureshopBoundAuditRepository');
const { createV01CheckoutAuditLesson } = require('../../server/services/secureshopV01CheckoutAuditLesson');

const PREFIX = 'PG_SECURESHOP_V01_CHECKOUT_AUDIT_';
const ROOT = path.resolve(__dirname, '../..');
const MIGRATIONS = path.join(ROOT, 'db/postgres/workshop-migrations/secureshop_review');
const ENABLED = process.env.SECURESHOP_V01_CHECKOUT_AUDIT_NATIVE === '1'
  && process.env.PG_TEST_DISPOSABLE === 'yes'
  && ['MIGRATION', 'RUNTIME'].every(role => process.env[`${PREFIX}REVIEW_${role}_URL`]);

function pool(role) {
  const parsed = new URL(process.env[`${PREFIX}REVIEW_${role}_URL`]);
  assert.equal(parsed.hostname, '127.0.0.1');
  assert.match(parsed.pathname, /^\/owasp_ai_goat_test_v01_checkout_audit_review_[a-z0-9]+$/);
  return new Pool({ connectionString: parsed.href, max: role === 'RUNTIME' ? 8 : 2,
    statement_timeout: 15000, lock_timeout: 3000,
    application_name: 'owasp-ai-goat-v01-checkout-audit-native' });
}
function scope(owner, generation = 1, session = owner + 1000) {
  return Object.freeze({ launchId: randomUUID(), scenarioId: randomUUID(), generation,
    platformOwnerId: owner, platformSessionId: session });
}
async function seedTarget(client, storage, execution, buyer) {
  const targetId = randomUUID(), scene = Object.freeze({ sceneId: randomUUID(),
    sceneGeneration: 2, grantId: randomUUID() });
  await client.query(`INSERT INTO secureshop_review.product_targets
    (target_id,launch_id,scenario_id,generation,original_platform_owner_id,
     original_platform_session_id,own_merchant_id,source_count,source_sha256)
    VALUES($1,$2,$3,$4,$5,$6,$7,1,$8)`, [targetId, storage.launchId,
    storage.scenarioId, storage.generation, storage.platformOwnerId,
    storage.platformSessionId, buyer + 5000, Buffer.alloc(32, 1)]);
  await client.query(`INSERT INTO secureshop_review.product_target_products
    (target_id,product_id,source_retailer_id,retailer_id,source_product_sha256,name,
     description,price,images,stock_quantity,status,template_source)
    VALUES($1,71,$2,$2,$3,'Native audit lamp','Owned synthetic product',17.25,'[]',3,'active','{{source}}')`,
  [targetId, buyer + 5000, Buffer.alloc(32, 2)]);
  await client.query(`INSERT INTO secureshop_review.product_target_cart_items
    (target_id,shop_user_id,product_id,quantity) VALUES($1,$2,71,1)`, [targetId, buyer]);
  await client.query(`INSERT INTO secureshop_review.scene_execution_grants
    (grant_id,scene_id,scene_generation,target_id,launch_id,scenario_id,generation,
     original_platform_owner_id,original_platform_session_id)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, [scene.grantId, scene.sceneId,
    scene.sceneGeneration, targetId, execution.launchId, execution.scenarioId,
    execution.generation, execution.platformOwnerId, execution.platformSessionId]);
  return createSceneBinding({ ...storage, targetId }, { ...scene, execution,
    withLease: work => work() });
}
function forgeNone(signed) {
  const payload = JSON.parse(Buffer.from(signed.split('.')[1], 'base64url').toString('utf8'));
  payload.role = 'admin';
  return `${Buffer.from(JSON.stringify({ typ: 'JWT', alg: 'none' })).toString('base64url')}.`
    + `${Buffer.from(JSON.stringify(payload)).toString('base64url')}.`;
}
function report(result) { return JSON.parse(result.content[0].text); }

function lessonAuthorities(executionScope, target, buyer, personaSession, state) {
  return {
    launches: { async assertCurrent(value) {
      assert.deepEqual(createLaunchScope(value), executionScope); if (state.stale) throw Error('reset');
    } },
    personaAuthority: { async capture(input) {
      return { binding: { ...input.scope, personaId: input.personaId, role: input.role,
        sessionId: input.sessionId, authorityVersion: input.authorityVersion },
      async assertRemoteAdmission() { if (state.stale) throw Error('persona reset'); } };
    } },
    modeAuthority: { async capture(binding, featureId) {
      assert.equal(featureId, 'checkout_audit_jwt');
      assert.equal(binding.shopUserId, buyer);
      const captured = state.mode;
      return { snapshot: { featureId, mode: captured, scope: executionScope },
        async assertCurrent() { if (state.stale || state.mode !== captured) throw Error('mode reset'); },
        async assertCurrentAtEffect() { if (state.stale || state.mode !== captured) throw Error('mode reset'); } };
    }, assertToken(value) { return value; } },
    async resolveExistingTarget(binding) {
      if (binding.shopUserId !== buyer || binding.platformOwnerId !== executionScope.platformOwnerId
          || binding.platformSessionId !== executionScope.platformSessionId) return null;
      return target;
    },
  };
}

test('native V01 lesson joins one real checkout audit and denies substituted lifecycle sources', {
  skip: !ENABLED, timeout: 120000,
}, async t => {
  const migration = pool('MIGRATION'), runtime = pool('RUNTIME');
  t.after(async () => Promise.all([migration.end(), runtime.end()]));
  const current = await migrate(migration, MIGRATIONS);
  assert.ok(current.length > 0);
  assert.deepEqual(await migrate(migration, MIGRATIONS), []);

  const buyer = 7301;
  const storage = scope(8301, 1, 9301);
  const executionScope = Object.freeze({ ...scope(storage.platformOwnerId, 4, 9304) });
  const target = await seedTarget(migration, storage, executionScope, buyer);
  const persona = Object.freeze({ id: buyer, role: 'customer' });
  const personaSession = Object.freeze({ sessionId: randomUUID(), authorityVersion: '2' });
  const operationId = randomUUID();
  const lifecycle = { stale: false, mode: 'vuln' };
  const checkCurrent = async value => {
    assert.deepEqual(value, executionScope);
    if (lifecycle.stale) throw Error('reset');
  };
  const auditStore = createBoundAuditStore({ store: 'review', pool: runtime, checkCurrent });
  const couponRepository = createBoundCouponRepository({ pool: runtime, checkCurrent });
  const checkoutInput = { shopUserId: buyer, shippingAddress: 'Owned synthetic address',
    paymentMethod: 'synthetic_card', operationId, persona, personaSession, mode: 'vuln' };

  const failing = createSecureShopBoundCommerceRepository(runtime, { checkCurrent,
    couponRepository, auditStore: { async append() { throw Error('owned audit outage'); } },
    effectTimeoutMs: 3000 });
  await assert.rejects(failing.checkout(target, checkoutInput), /owned audit outage/);
  assert.equal((await runtime.query(`SELECT count(*)::int AS n FROM secureshop_review.product_target_orders
    WHERE target_id=$1`, [target.targetId])).rows[0].n, 0);
  assert.equal((await runtime.query(`SELECT count(*)::int AS n FROM secureshop_review.bound_commerce_operations
    WHERE operation_id=$1`, [operationId])).rows[0].n, 0);
  assert.equal((await runtime.query(`SELECT count(*)::int AS n FROM secureshop_review.product_target_cart_items
    WHERE target_id=$1 AND shop_user_id=$2`, [target.targetId, buyer])).rows[0].n, 1);

  const commerce = createSecureShopBoundCommerceRepository(runtime, { checkCurrent,
    couponRepository, auditStore, effectTimeoutMs: 3000 });
  const created = await commerce.checkout(target, checkoutInput);
  assert.equal(created.total, 17.25);
  const checkoutHistory = createCheckoutHistoryRepository({ pool: runtime, checkCurrent });
  const checkout = await checkoutHistory.read(target, buyer, operationId);
  assert.equal(checkout.order.id, created.orderId);
  assert.deepEqual(checkout.order, { id: created.orderId, total: 17.25, subtotal: 17.25, discount: 0 });
  const original = await auditStore.checkoutForOrder(target, buyer, checkout);
  assert.equal(original.observation.orderId, created.orderId);
  assert.equal(original.observation.total, 17.25);

  let protectedReads = 0;
  const countedAudit = { async checkoutForOrder(...args) {
    protectedReads++; return auditStore.checkoutForOrder(...args);
  } };
  const authorities = lessonAuthorities(executionScope, target, buyer, personaSession, lifecycle);
  const lesson = createV01CheckoutAuditLesson({ secretMaterial: Buffer.alloc(32, 19),
    checkoutHistory, auditStore: countedAudit, ...authorities });
  const requestId = randomUUID();
  const input = { scope: executionScope, persona, personaSession, checkoutOperationId: operationId,
    requestId, execution: { runId: randomUUID(), ownerKey: '["SecureShop",8301]',
      durableGeneration: '4', async check() { if (lifecycle.stale) throw Error('reset'); } } };
  const customer = await lesson.presentCustomerToken(input);
  assert.equal(customer.orderId, created.orderId);
  const forged = forgeNone(customer.token);
  const disclosed = await lesson.readAudit({ ...input, teachingToken: forged });
  assert.deepEqual(report(disclosed), { status: 'disclosed', eventId: original.eventId,
    sourceSha256: original.sourceSha256, report: original.observation });
  assert.equal(protectedReads, 1);

  lifecycle.mode = 'fixed';
  await assert.rejects(lesson.readAudit({ ...input, teachingToken: forged }),
    { code: 'V01_TEACHING_TOKEN_DENIED' });
  assert.equal(protectedReads, 1, 'fixed mode rejects before protected audit SQL');
  lifecycle.mode = 'vuln';

  await assert.rejects(checkoutHistory.read(target, buyer + 1, operationId),
    { code: 'CHECKOUT_RECEIPT_NOT_FOUND' });
  await assert.rejects(auditStore.checkoutForOrder(target, buyer + 1, checkout),
    { code: 'INVALID_ARGUMENT' });
  await assert.rejects(auditStore.checkoutForOrder(target, buyer, checkout, randomUUID()),
    { code: 'INVALID_ARGUMENT' });
  const siblingInput = { ...input, scope: { ...executionScope,
    platformOwnerId: executionScope.platformOwnerId + 1 } };
  await assert.rejects(lesson.presentCustomerToken(siblingInput), { code: 'V01_MODE_UNAVAILABLE' });
  assert.equal(protectedReads, 1, 'sibling mode denial performs no protected audit SQL');

  lifecycle.stale = true;
  await assert.rejects(lesson.readAudit({ ...input, teachingToken: forged }), /reset/);
  assert.equal(protectedReads, 1, 'reset fences before protected audit SQL');
  lifecycle.stale = false;

  const duplicateId = randomUUID();
  const duplicate = await runtime.connect();
  try {
    await duplicate.query('BEGIN');
    await auditStore.append(duplicate, { eventId: duplicateId, scope: executionScope, persona,
      actor: 'customer', action: 'checkout', target: String(created.orderId),
      paramsJson: JSON.stringify({ total: 17.25, shippingAddress: checkoutInput.shippingAddress,
        paymentMethod: checkoutInput.paymentMethod, storageTargetId: target.targetId,
        sceneId: target.scene.sceneId, sceneGeneration: target.scene.sceneGeneration }),
      outcome: 'completed', sourceKind: 'order', sourceId: String(created.orderId) });
    await duplicate.query('COMMIT');
  } catch (error) { await duplicate.query('ROLLBACK').catch(() => {}); throw error; }
  finally { duplicate.release(); }
  await assert.rejects(auditStore.checkoutForOrder(target, buyer, checkout),
    { code: 'INVALID_ARGUMENT' });
  assert.equal((await migration.query(`SELECT count(*)::int AS n
    FROM secureshop_review.bound_audit_events WHERE event_id=ANY($1::uuid[])`,
  [[original.eventId, duplicateId]])).rows[0].n, 2);
});
