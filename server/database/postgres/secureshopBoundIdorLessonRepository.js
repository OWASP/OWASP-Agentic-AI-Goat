'use strict';

const { createHash, randomUUID } = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');
const { withTransaction } = require('./index');
const { createLaunchScope } = require('../../services/secureshopConversationBinding');
const { executionScope, assertSceneGrant, withSceneLease } = require('../../services/secureshopSceneBinding');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA = /^[0-9a-f]{64}$/;
const VICTIM_ID = Number(require('../../../db/postgres/seeds/secureshop.json').shop_users
  .find(row => row.username === 'student_customer' && row.role === 'customer')?.id);
const ACTION_TOOL = Object.freeze({ cart_remove: 'lesson.cart_remove', order_status: 'lesson.order_status' });

function failure(code) { return Object.assign(new Error('Owned IDOR lesson unavailable'), { code, executionBoundary: true }); }
function uuid(value) { if (typeof value !== 'string' || !UUID.test(value)) throw failure('IDOR_LESSON_INVALID'); return value.toLowerCase(); }
function positive(value, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) throw failure('IDOR_LESSON_INVALID');
  return value;
}
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(key =>
    `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
function digest(value) { return createHash('sha256').update(canonical(value)).digest('hex'); }
function hex(value) { if (!Buffer.isBuffer(value) || value.length !== 32) throw failure('IDOR_LESSON_RECEIPT_INVALID'); return value.toString('hex'); }
function buffer(value) { if (typeof value !== 'string' || !SHA.test(value)) throw failure('IDOR_LESSON_INVALID'); return Buffer.from(value, 'hex'); }
function safeBigint(value) { return positive(Number(value)); }
function sameScope(a, b) { return ['launchId','scenarioId','generation','platformOwnerId','platformSessionId'].every(key => a[key] === b[key]); }
function context(input) {
  if (!input || typeof input !== 'object' || !input.retainedScene?.scene) throw failure('IDOR_LESSON_SCENE_STALE');
  const scope = createLaunchScope(input.scope), scene = input.retainedScene;
  const execution = executionScope(scene); // Rejects an unbranded scene copy.
  if (!sameScope(scope, execution) || !UUID.test(scene.targetId || '')
      || !UUID.test(scene.scene.sceneId || '') || !UUID.test(scene.scene.grantId || '')
      || !Number.isSafeInteger(scene.scene.sceneGeneration) || scene.scene.sceneGeneration < 1
      || scene.platformOwnerId !== scope.platformOwnerId) throw failure('IDOR_LESSON_SCENE_STALE');
  const persona = input.persona;
  if (persona?.role !== 'customer' || positive(persona.id, 2147483647) < 1000000000
      || persona.id === VICTIM_ID) throw failure('IDOR_LESSON_ACTOR_INVALID');
  const session = input.personaSession;
  if (!session || typeof session.authorityVersion !== 'string'
      || !/^[1-9]\d*$/.test(session.authorityVersion)) throw failure('IDOR_LESSON_SESSION_STALE');
  return Object.freeze({ scope, scene, personaId: persona.id,
    personaSessionId: uuid(session.sessionId), authorityVersion: session.authorityVersion });
}
function origin(raw, action) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)
      || Object.keys(raw).sort().join(',') !== 'callId,requestId,runId,sessionId,step,toolKey'
      || raw.toolKey !== ACTION_TOOL[action] || !Number.isSafeInteger(raw.step) || raw.step < 0
      || typeof raw.callId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(raw.callId)) throw failure('IDOR_LESSON_ORIGIN_INVALID');
  return Object.freeze({ sessionId: uuid(raw.sessionId), requestId: uuid(raw.requestId),
    runId: uuid(raw.runId), step: raw.step, callId: raw.callId, toolKey: raw.toolKey });
}
function operationIdFor(source) {
  const bytes = createHash('sha256').update(`secureshop-owned-idor-v1:${canonical(source)}`).digest().subarray(0, 16);
  bytes[6] = (bytes[6] & 15) | 64; bytes[8] = (bytes[8] & 63) | 128;
  const h = bytes.toString('hex');
  return `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20)}`;
}
function snapshotMode(modeAuthority, raw, scope) {
  if (typeof modeAuthority?.assertToken !== 'function') throw failure('IDOR_LESSON_MODE_STALE');
  const token = modeAuthority.assertToken(raw);
  const value = token?.snapshot;
  if (value?.version !== 1 || value.featureId !== 'customer_idor'
      || typeof value.policyVersion !== 'string' || !value.policyVersion
      || !['vuln','fixed'].includes(value.mode) || !sameScope(value.scope || {}, scope)
      || !Number.isSafeInteger(value.generation) || value.generation < 0
      || typeof value.modeStamp !== 'string' || !value.modeStamp
      || typeof token.assertCurrentAtEffect !== 'function') throw failure('IDOR_LESSON_MODE_STALE');
  return Object.freeze({ version: 1, featureId: value.featureId, policyVersion: value.policyVersion,
    mode: value.mode, generation: value.generation, modeStamp: value.modeStamp, scope });
}
function birthReceipt(row) {
  if (!row) throw failure('IDOR_LESSON_UNAVAILABLE');
  return Object.freeze({ birthId: row.birth_id, targetId: row.target_id, sceneId: row.scene_id,
    sceneGeneration: safeBigint(row.scene_generation), birthGrantId: row.birth_grant_id,
    birthLaunchId: row.birth_launch_id, birthScenarioId: row.birth_scenario_id,
    birthGeneration: safeBigint(row.birth_generation), platformOwnerId: positive(Number(row.platform_owner_id)),
    attackerId: positive(Number(row.attacker_shop_user_id)), victimId: positive(Number(row.victim_shop_user_id)),
    victimIdentitySha256: hex(row.victim_identity_sha256), cartItemId: safeBigint(row.cart_item_id),
    orderId: safeBigint(row.order_id), cartPreimage: row.cart_preimage,
    orderPreimage: row.order_preimage, birthSha256: hex(row.birth_sha256) });
}
function cards(birth) {
  return Object.freeze([
    Object.freeze({ action: 'cart_remove', numericId: birth.cartItemId, label: 'Reserved lesson cart item' }),
    Object.freeze({ action: 'order_status', numericId: birth.orderId, label: 'Reserved lesson order' }),
  ]);
}
function operationReceipt(row) {
  if (!row || typeof row.result_json !== 'object' || !row.result_json) throw failure('IDOR_LESSON_RECEIPT_INVALID');
  const scope = { launchId: row.launch_id, scenarioId: row.scenario_id,
    generation: safeBigint(row.generation), platformOwnerId: positive(Number(row.platform_owner_id)),
    platformSessionId: positive(Number(row.platform_session_id)) };
  const request = { operationId: row.operation_id, birthId: row.birth_id,
    targetId: row.target_id, sceneId: row.scene_id,
    sceneGeneration: safeBigint(row.scene_generation), grantId: row.grant_id,
    scope, actorId: positive(Number(row.actor_shop_user_id)),
    personaSessionId: row.persona_session_id, authorityVersion: row.authority_version,
    action: row.action, numericId: safeBigint(row.numeric_id),
    mode: row.mode_snapshot, turnOrigin: row.turn_origin };
  if (digest(request) !== hex(row.request_sha256)
      || digest({ ...request, requestSha256: hex(row.request_sha256), result: row.result_json })
        !== hex(row.receipt_sha256)) throw failure('IDOR_LESSON_RECEIPT_INVALID');
  return Object.freeze({ operationId: row.operation_id, birthId: row.birth_id,
    targetId: row.target_id, sceneId: row.scene_id, sceneGeneration: safeBigint(row.scene_generation),
    grantId: row.grant_id, actorId: positive(Number(row.actor_shop_user_id)),
    personaSessionId: row.persona_session_id, authorityVersion: row.authority_version,
    action: row.action, numericId: safeBigint(row.numeric_id), mode: row.mode_snapshot,
    turnOrigin: row.turn_origin, requestSha256: hex(row.request_sha256),
    result: row.result_json, receiptSha256: hex(row.receipt_sha256) });
}
function exactBirth(row, ctx) {
  const b = birthReceipt(row);
  if (b.targetId !== ctx.scene.targetId || b.sceneId !== ctx.scene.scene.sceneId
      || b.sceneGeneration !== ctx.scene.scene.sceneGeneration
      || b.birthLaunchId !== ctx.scene.launchId || b.birthScenarioId !== ctx.scene.scenarioId
      || b.birthGeneration !== ctx.scene.generation
      || b.platformOwnerId !== ctx.scope.platformOwnerId || b.attackerId !== ctx.personaId
      || b.victimId !== VICTIM_ID || b.victimId === b.attackerId
      || digest({ birthId: b.birthId, targetId: b.targetId, sceneId: b.sceneId,
        sceneGeneration: b.sceneGeneration, birthGrantId: b.birthGrantId,
        birthLaunchId: b.birthLaunchId, birthScenarioId: b.birthScenarioId,
        birthGeneration: b.birthGeneration, platformOwnerId: b.platformOwnerId,
        attackerId: b.attackerId, victimId: b.victimId,
        victimIdentitySha256: b.victimIdentitySha256, cartItemId: b.cartItemId,
        orderId: b.orderId, cartPreimage: b.cartPreimage,
        orderPreimage: b.orderPreimage }) !== b.birthSha256) {
    throw failure('IDOR_LESSON_BIRTH_CONFLICT');
  }
  return b;
}
async function targetAndGrant(client, ctx) {
  await assertSceneGrant(client, ctx.scene);
  const s = ctx.scene;
  const result = await client.query(`SELECT lifecycle FROM secureshop_review.product_targets
    WHERE target_id=$1 AND launch_id=$2 AND scenario_id=$3 AND generation=$4
      AND original_platform_owner_id=$5 AND original_platform_session_id=$6 FOR SHARE`,
  [s.targetId,s.launchId,s.scenarioId,s.generation,s.platformOwnerId,s.platformSessionId]);
  if (result.rows[0]?.lifecycle !== 'active') throw failure('IDOR_LESSON_TARGET_STALE');
}
function createImmutableTemplateVictimReader(agentsPool) {
  if (typeof agentsPool?.query !== 'function') throw new TypeError('Agents identity pool required');
  return async () => {
    const row = (await agentsPool.query(`SELECT t.shop_user_id AS id,t.role,t.source_sha256,
      a.principal_id,a.original_platform_owner_id
      FROM secureshop_agents.bound_persona_templates t
      JOIN secureshop_agents.bound_actor_identities a
        ON a.shop_user_id=t.shop_user_id AND a.username=t.username
          AND a.email=t.email AND a.base_role=t.role
      WHERE t.username='student_customer' AND t.shop_user_id=$1`, [VICTIM_ID])).rows[0];
    if (!row || Number(row.id) !== VICTIM_ID || row.role !== 'customer'
        || row.principal_id !== null || row.original_platform_owner_id !== null) {
      throw failure('IDOR_LESSON_VICTIM_INVALID');
    }
    return Object.freeze({ id: VICTIM_ID, role: 'customer', identityKind: 'teaching_persona',
      sourceSha256: hex(row.source_sha256) });
  };
}
function createSecureShopBoundIdorLessonRepository(pool, { modeAuthority, readVictimIdentity } = {}) {
  if (typeof pool?.connect !== 'function' || typeof pool?.query !== 'function'
      || typeof readVictimIdentity !== 'function' || typeof modeAuthority?.assertToken !== 'function') {
    throw new TypeError('Owned IDOR lesson dependencies required');
  }
  async function withScene(ctx, work, modeToken = null) {
    return withSceneLease(ctx.scene, () => withTransaction(pool, async client => {
      await client.query("SELECT set_config('statement_timeout','3000',true),set_config('lock_timeout','3000',true)");
      await targetAndGrant(client, ctx);
      await modeToken?.assertCurrentAtEffect();
      const value = await work(client);
      await modeToken?.assertCurrentAtEffect();
      await targetAndGrant(client, ctx);
      return value;
    }));
  }
  async function loadBirth(client, ctx) {
    const row = (await client.query(`SELECT * FROM secureshop_review.owned_idor_lesson_births
      WHERE target_id=$1`, [ctx.scene.targetId])).rows[0];
    return row ? exactBirth(row, ctx) : null;
  }
  async function prepare(input) {
    const ctx = context(input);
    // This immutable identity is read before the review-store transaction;
    // a persona fence belongs outside this repository at the graph boundary.
    const victim = await readVictimIdentity();
    if (victim?.id !== VICTIM_ID || victim.role !== 'customer'
        || victim.identityKind !== 'teaching_persona' || !SHA.test(victim.sourceSha256 || '')) {
      throw failure('IDOR_LESSON_VICTIM_INVALID');
    }
    return withScene(ctx, async client => {
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1::text,0))',
        [`owned-idor-birth:${ctx.scene.targetId}`]);
      const prior = await loadBirth(client, ctx);
      if (prior) {
        if (prior.victimId !== victim.id || prior.victimIdentitySha256 !== victim.sourceSha256) {
          throw failure('IDOR_LESSON_BIRTH_CONFLICT');
        }
        return Object.freeze({ birth: prior, cards: cards(prior) });
      }
      const product = (await client.query(`SELECT p.product_id
        FROM secureshop_review.product_target_products p WHERE p.target_id=$1
          AND NOT EXISTS (SELECT 1 FROM secureshop_review.product_target_cart_items c
            WHERE c.target_id=p.target_id AND c.shop_user_id=$2 AND c.product_id=p.product_id)
        ORDER BY p.product_id LIMIT 1`,
      [ctx.scene.targetId,victim.id])).rows[0];
      if (!product) throw failure('IDOR_LESSON_PRODUCT_UNAVAILABLE');
      const cart = (await client.query(`INSERT INTO secureshop_review.product_target_cart_items
        (target_id,shop_user_id,product_id,quantity) VALUES($1,$2,$3,1)
        RETURNING cart_item_id,shop_user_id,product_id,quantity,
          to_char(added_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS added_at_utc`,
      [ctx.scene.targetId,victim.id,product.product_id])).rows[0];
      const order = (await client.query(`INSERT INTO secureshop_review.product_target_orders
        (target_id,shop_user_id,total_amount,status,payment_method,payment_status,shipping_address)
        VALUES($1,$2,$3,'confirmed','synthetic lesson','approved','Synthetic lesson address')
        RETURNING order_id,shop_user_id,total_amount::text AS total_amount,
          subtotal_amount::text AS subtotal_amount,discount_amount::text AS discount_amount,
          coupon_code,coupon_percent,status,payment_method,payment_status,shipping_address,
          to_char(order_date AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS order_date_utc,
          to_char(updated_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS updated_at_utc`,
      [ctx.scene.targetId,victim.id,'1.00'])).rows[0];
      const line = (await client.query(`INSERT INTO secureshop_review.product_target_order_items
        (target_id,order_id,product_id,product_name,quantity,price)
        VALUES($1,$2,$3,$4,1,$5) RETURNING order_item_id,product_id,product_name,quantity,
          price::text AS price,discount_amount::text AS discount_amount`,
      [ctx.scene.targetId,order.order_id,product.product_id,'Synthetic lesson product','1.00'])).rows[0];
      const cartPreimage = Object.freeze({ cartItemId: safeBigint(cart.cart_item_id),
        shopUserId: positive(Number(cart.shop_user_id)), productId: positive(Number(cart.product_id)),
        quantity: positive(Number(cart.quantity)), addedAt: cart.added_at_utc });
      const orderPreimage = Object.freeze({ orderId: safeBigint(order.order_id),
        shopUserId: positive(Number(order.shop_user_id)), totalAmount: order.total_amount,
        subtotalAmount: order.subtotal_amount, discountAmount: order.discount_amount,
        couponCode: order.coupon_code, couponPercent: order.coupon_percent,
        status: order.status, paymentMethod: order.payment_method,
        paymentStatus: order.payment_status, shippingAddress: order.shipping_address,
        orderDate: order.order_date_utc, updatedAt: order.updated_at_utc,
        item: Object.freeze({ orderItemId: safeBigint(line.order_item_id),
          productId: positive(Number(line.product_id)), productName: line.product_name,
          quantity: positive(Number(line.quantity)), price: line.price,
          discountAmount: line.discount_amount }) });
      const scene = ctx.scene.scene;
      const body = { birthId: randomUUID(), targetId: ctx.scene.targetId, sceneId: scene.sceneId,
        sceneGeneration: scene.sceneGeneration, birthGrantId: scene.grantId,
        birthLaunchId: ctx.scene.launchId, birthScenarioId: ctx.scene.scenarioId,
        birthGeneration: ctx.scene.generation, platformOwnerId: ctx.scope.platformOwnerId,
        attackerId: ctx.personaId, victimId: victim.id,
        victimIdentitySha256: victim.sourceSha256, cartItemId: cartPreimage.cartItemId,
        orderId: orderPreimage.orderId, cartPreimage, orderPreimage };
      const birthSha256 = digest(body);
      const row = (await client.query(`INSERT INTO secureshop_review.owned_idor_lesson_births
        (birth_id,target_id,scene_id,scene_generation,birth_grant_id,birth_launch_id,birth_scenario_id,
         birth_generation,platform_owner_id,attacker_shop_user_id,victim_shop_user_id,victim_identity_sha256,
         cart_item_id,order_id,cart_preimage,order_preimage,birth_sha256)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15::jsonb,$16::jsonb,$17)
        RETURNING *`, [body.birthId,body.targetId,body.sceneId,body.sceneGeneration,body.birthGrantId,
        body.birthLaunchId,body.birthScenarioId,body.birthGeneration,body.platformOwnerId,
        body.attackerId,body.victimId,buffer(body.victimIdentitySha256),body.cartItemId,body.orderId,
        JSON.stringify(cartPreimage),JSON.stringify(orderPreimage),buffer(birthSha256)])).rows[0];
      const birth = exactBirth(row, ctx);
      return Object.freeze({ birth, cards: cards(birth) });
    });
  }
  async function readCards(input) {
    const ctx = context(input);
    return withScene(ctx, async client => {
      const birth = await loadBirth(client, ctx);
      if (!birth) throw failure('IDOR_LESSON_UNAVAILABLE');
      return cards(birth);
    });
  }
  async function readBirth(input) {
    const ctx = context(input);
    return withScene(ctx, async client => {
      const birth = await loadBirth(client, ctx);
      if (!birth) throw failure('IDOR_LESSON_UNAVAILABLE');
      return birth;
    });
  }
  async function execute(input) {
    const ctx = context(input), action = input.action;
    if (!Object.hasOwn(ACTION_TOOL, action)) throw failure('IDOR_LESSON_INVALID');
    const numericId = positive(input.numericId), turnOrigin = origin(input.turnOrigin, action);
    const mode = snapshotMode(modeAuthority, input.modeToken, ctx.scope);
    if (input.requestId !== undefined && uuid(input.requestId) !== turnOrigin.requestId)
      throw failure('IDOR_LESSON_ORIGIN_INVALID');
    const operationId = operationIdFor(turnOrigin);
    return withScene(ctx, async client => {
      const birth = await loadBirth(client, ctx);
      if (!birth) throw failure('IDOR_LESSON_UNAVAILABLE');
      if (numericId !== (action === 'cart_remove' ? birth.cartItemId : birth.orderId))
        throw failure('IDOR_LESSON_ID_INVALID');
      const request = { operationId, birthId: birth.birthId, targetId: birth.targetId,
        sceneId: ctx.scene.scene.sceneId, sceneGeneration: ctx.scene.scene.sceneGeneration,
        grantId: ctx.scene.scene.grantId, scope: ctx.scope, actorId: ctx.personaId,
        personaSessionId: ctx.personaSessionId, authorityVersion: ctx.authorityVersion,
        action, numericId, mode, turnOrigin };
      const requestSha256 = digest(request);
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1::text,0))',
        [`owned-idor-operation:${operationId}`]);
      const prior = (await client.query(`SELECT * FROM secureshop_review.owned_idor_lesson_operations
        WHERE operation_id=$1`, [operationId])).rows[0];
      if (prior) {
        if (hex(prior.request_sha256) !== requestSha256) throw failure('IDOR_LESSON_OPERATION_CONFLICT');
        return operationReceipt(prior); // Before mutable cart-row lookup.
      }
      let result;
      if (action === 'cart_remove') {
        const returned = (await client.query(`DELETE FROM secureshop_review.product_target_cart_items
          WHERE target_id=$1 AND cart_item_id=$2
            ${mode.mode === 'fixed' ? 'AND shop_user_id=$3' : ''}
          RETURNING cart_item_id,shop_user_id,product_id,quantity,
            to_char(added_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS added_at_utc`,
        mode.mode === 'fixed' ? [birth.targetId,numericId,ctx.personaId] : [birth.targetId,numericId])).rows[0];
        if (returned && (Number(returned.shop_user_id) !== birth.victimId
            || safeBigint(returned.cart_item_id) !== birth.cartItemId
            || Number(returned.product_id) !== birth.cartPreimage.productId
            || Number(returned.quantity) !== birth.cartPreimage.quantity
            || returned.added_at_utc !== birth.cartPreimage.addedAt)) {
          throw failure('IDOR_LESSON_SOURCE_CONFLICT');
        }
        if (mode.mode === 'vuln' && !returned) throw failure('IDOR_LESSON_SOURCE_MISSING');
        result = returned ? { status: 'deleted', preimage: birth.cartPreimage }
          : { status: 'denied', preimage: null };
      } else {
        const returned = (await client.query(`SELECT order_id,shop_user_id,total_amount::text AS total_amount,
          subtotal_amount::text AS subtotal_amount,discount_amount::text AS discount_amount,
          coupon_code,coupon_percent,status,payment_method,payment_status,shipping_address,
          to_char(order_date AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS order_date_utc,
          to_char(updated_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS updated_at_utc
          FROM secureshop_review.product_target_orders
          WHERE target_id=$1 AND order_id=$2
            ${mode.mode === 'fixed' ? 'AND shop_user_id=$3' : ''} FOR SHARE`,
        mode.mode === 'fixed' ? [birth.targetId,numericId,ctx.personaId] : [birth.targetId,numericId])).rows[0];
        if (returned && (Number(returned.shop_user_id) !== birth.victimId
            || safeBigint(returned.order_id) !== birth.orderId
            || returned.total_amount !== birth.orderPreimage.totalAmount
            || returned.subtotal_amount !== birth.orderPreimage.subtotalAmount
            || returned.discount_amount !== birth.orderPreimage.discountAmount
            || returned.coupon_code !== birth.orderPreimage.couponCode
            || returned.coupon_percent !== birth.orderPreimage.couponPercent
            || returned.status !== birth.orderPreimage.status
            || returned.payment_method !== birth.orderPreimage.paymentMethod
            || returned.payment_status !== birth.orderPreimage.paymentStatus
            || returned.shipping_address !== birth.orderPreimage.shippingAddress
            || returned.order_date_utc !== birth.orderPreimage.orderDate
            || returned.updated_at_utc !== birth.orderPreimage.updatedAt)) {
          throw failure('IDOR_LESSON_SOURCE_CONFLICT');
        }
        if (mode.mode === 'vuln' && !returned) throw failure('IDOR_LESSON_SOURCE_MISSING');
        if (returned) {
          const line = (await client.query(`SELECT order_item_id,product_id,product_name,quantity,
            price::text AS price,discount_amount::text AS discount_amount
            FROM secureshop_review.product_target_order_items
            WHERE target_id=$1 AND order_id=$2 ORDER BY order_item_id FOR SHARE`,
          [birth.targetId,numericId])).rows;
          if (line.length !== 1 || safeBigint(line[0].order_item_id) !== birth.orderPreimage.item.orderItemId
              || Number(line[0].product_id) !== birth.orderPreimage.item.productId
              || line[0].product_name !== birth.orderPreimage.item.productName
              || Number(line[0].quantity) !== birth.orderPreimage.item.quantity
              || line[0].price !== birth.orderPreimage.item.price
              || line[0].discount_amount !== birth.orderPreimage.item.discountAmount) {
            throw failure('IDOR_LESSON_SOURCE_CONFLICT');
          }
        }
        result = returned ? { status: 'disclosed', order: birth.orderPreimage }
          : { status: 'denied', order: null };
      }
      const receiptSha256 = digest({ ...request, requestSha256, result });
      const row = (await client.query(`INSERT INTO secureshop_review.owned_idor_lesson_operations
        (operation_id,birth_id,target_id,scene_id,scene_generation,grant_id,launch_id,scenario_id,
         generation,platform_owner_id,platform_session_id,actor_shop_user_id,persona_session_id,
         authority_version,action,numeric_id,mode_snapshot,turn_origin,request_sha256,result_json,receipt_sha256)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17::jsonb,$18::jsonb,$19,$20::jsonb,$21)
        RETURNING *`, [operationId,birth.birthId,birth.targetId,request.sceneId,request.sceneGeneration,
        request.grantId,ctx.scope.launchId,ctx.scope.scenarioId,ctx.scope.generation,
        ctx.scope.platformOwnerId,ctx.scope.platformSessionId,ctx.personaId,ctx.personaSessionId,
        ctx.authorityVersion,action,numericId,JSON.stringify(mode),JSON.stringify(turnOrigin),
        buffer(requestSha256),JSON.stringify(result),buffer(receiptSha256)])).rows[0];
      return operationReceipt(row);
    }, input.modeToken);
  }
  async function readSaved(input) {
    const ctx = context(input), operationId = uuid(input.operationId);
    const mode = snapshotMode(modeAuthority, input.modeToken, ctx.scope);
    return withScene(ctx, async client => {
      const birth = await loadBirth(client, ctx);
      if (!birth) throw failure('IDOR_LESSON_UNAVAILABLE');
      const row = (await client.query(`SELECT * FROM secureshop_review.owned_idor_lesson_operations
        WHERE operation_id=$1`, [operationId])).rows[0];
      if (!row || row.birth_id !== birth.birthId || row.target_id !== birth.targetId
          || row.scene_id !== ctx.scene.scene.sceneId
          || Number(row.scene_generation) !== ctx.scene.scene.sceneGeneration
          || row.grant_id !== ctx.scene.scene.grantId
          || row.launch_id !== ctx.scope.launchId || row.scenario_id !== ctx.scope.scenarioId
          || Number(row.generation) !== ctx.scope.generation
          || Number(row.platform_owner_id) !== ctx.scope.platformOwnerId
          || Number(row.platform_session_id) !== ctx.scope.platformSessionId
          || row.actor_shop_user_id !== ctx.personaId
          || row.persona_session_id !== ctx.personaSessionId
          || row.authority_version !== ctx.authorityVersion
          || !isDeepStrictEqual(row.mode_snapshot, mode)) throw failure('IDOR_LESSON_SAVED_UNAVAILABLE');
      const receipt = operationReceipt(row);
      const expected = receipt.action === 'cart_remove'
        ? receipt.mode.mode === 'fixed'
          ? { status: 'denied', preimage: null }
          : { status: 'deleted', preimage: birth.cartPreimage }
        : receipt.action === 'order_status'
          ? receipt.mode.mode === 'fixed'
            ? { status: 'denied', order: null }
            : { status: 'disclosed', order: birth.orderPreimage }
          : null;
      if (!expected || !isDeepStrictEqual(receipt.result, expected)) throw failure('IDOR_LESSON_RECEIPT_INVALID');
      return receipt;
    }, input.modeToken);
  }
  return Object.freeze({ prepare, readBirth, readCards, execute, readSaved });
}

module.exports = { createSecureShopBoundIdorLessonRepository, createImmutableTemplateVictimReader };
