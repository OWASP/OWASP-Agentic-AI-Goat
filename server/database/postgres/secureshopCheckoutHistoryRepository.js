'use strict';

const { isDeepStrictEqual: equal } = require('node:util');
const { createLaunchScope } = require('../../services/secureshopConversationBinding');
const { executionScope, withSceneLease, assertSceneGrant } = require('../../services/secureshopSceneBinding');
const { UUID, hash } = require('../../services/secureshopCouponContract');
const missing = () => Object.assign(new Error('Checkout outcome is not confirmed'), { code: 'CHECKOUT_RECEIPT_NOT_FOUND' });
const corrupt = () => Object.assign(new Error('Checkout receipt unavailable'), { code: 'COMMERCE_INTEGRITY_UNAVAILABLE' });
function money(value) {
  if (!['number', 'string'].includes(typeof value) || !/^\d+(?:\.\d{1,2})?$/.test(String(value))) throw corrupt();
  const cents = Math.round(Number(value) * 100);
  if (!Number.isSafeInteger(cents) || cents < 0) throw corrupt();
  return cents;
}

// Historical reads deliberately do not use the mutation repository's exact-session
// replay method. The current scene grants access; the old receipt stays immutable.
function createCheckoutHistoryRepository({ pool, checkCurrent } = {}) {
  if (typeof pool?.connect !== 'function' || typeof checkCurrent !== 'function') throw TypeError('Checkout history dependencies required');
  async function guarded(target, actorId, work) {
    if (!target?.scene || !Number.isSafeInteger(actorId) || actorId < 1) throw missing();
    const scope = createLaunchScope(executionScope(target));
    await checkCurrent(scope);
    return withSceneLease(target, async () => {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        await client.query("SET LOCAL statement_timeout='3000ms'");
        await client.query("SET LOCAL lock_timeout='3000ms'");
        await assertSceneGrant(client, target);
        const active = await client.query(`SELECT 1 FROM secureshop_review.product_targets WHERE target_id=$1
          AND launch_id=$2 AND scenario_id=$3 AND generation=$4 AND original_platform_owner_id=$5
          AND original_platform_session_id=$6 AND lifecycle='active' FOR SHARE`,
        [target.targetId,target.launchId,target.scenarioId,target.generation,target.platformOwnerId,target.platformSessionId]);
        if (active.rowCount !== 1) throw missing();
        const scopeKey = hash({ version: 1, ownerId: scope.platformOwnerId, shopUserId: actorId, targetId: target.targetId });
        const result = await work(client, scopeKey);
        await checkCurrent(scope);
        await assertSceneGrant(client, target);
        await client.query('COMMIT');
        await checkCurrent(scope);
        return result;
      } catch (error) { await client.query('ROLLBACK').catch(() => {}); throw error; }
      finally { client.release(); }
    });
  }
  async function verify(client, row, target, actorId) {
    if (!row || row.state !== 'completed' || row.kind !== 'checkout' || row.target_id !== target.targetId
        || Number(row.shop_user_id) !== actorId) throw missing();
    if (typeof row.request_json !== 'string' || typeof row.result_json !== 'string'
        || hash(row.request_json) !== row.request_sha256 || hash(row.result_json) !== row.result_sha256) throw corrupt();
    let request, result, origin;
    try { request = JSON.parse(row.request_json); result = JSON.parse(row.result_json); origin = createLaunchScope(request.scope); }
    catch { throw corrupt(); }
    if (!equal(origin, request.scope) || origin.platformOwnerId !== target.platformOwnerId
        || request.targetId !== target.targetId || request.operationId !== row.operation_id
        || request.persona?.id !== actorId || request.persona?.role !== 'customer'
        || request.personaSession?.sessionId !== row.persona_session_id
        || request.personaSession?.authorityVersion !== String(row.authority_version)
        || !UUID.test(row.persona_session_id || '') || !/^[1-9][0-9]*$/.test(String(row.authority_version))
        || request.mode !== row.mode || !['fixed','vuln'].includes(row.mode)
        || !Number.isSafeInteger(result?.orderId) || result.orderId < 1) throw corrupt();
    // A pre-scene checkout can have the exact target birth. Later executions
    // require their retained grant, without resurrecting that execution's liveness.
    if (!equal(origin, createLaunchScope(target))) {
      const grant = await client.query(`SELECT 1 FROM secureshop_review.scene_execution_grants
        WHERE scene_id=$1 AND scene_generation=$2 AND target_id=$3 AND launch_id=$4 AND scenario_id=$5
          AND generation=$6 AND original_platform_owner_id=$7 AND original_platform_session_id=$8`,
      [target.scene.sceneId,target.scene.sceneGeneration,target.targetId,origin.launchId,origin.scenarioId,
        origin.generation,origin.platformOwnerId,origin.platformSessionId]);
      if (grant.rowCount !== 1) throw corrupt();
    }
    const order = (await client.query(`SELECT order_id,total_amount,subtotal_amount,discount_amount,shipping_address,payment_method
      FROM secureshop_review.product_target_orders WHERE target_id=$1 AND shop_user_id=$2 AND order_id=$3 FOR SHARE`,
    [target.targetId,actorId,result.orderId])).rows[0];
    if (!order || Number(order.order_id) !== result.orderId || order.shipping_address !== request.shippingAddress
        || order.payment_method !== request.paymentMethod || money(order.total_amount) !== money(result.total)
        || money(order.subtotal_amount) !== money(result.subtotal) || money(order.discount_amount) !== money(result.discount)
        || money(result.subtotal) - money(result.discount) !== money(result.total)) throw corrupt();
    const createdAt = new Date(row.created_at).toISOString();
    return { operationId: row.operation_id, status: 'completed', createdAt,
      order: { id: result.orderId, total: money(result.total)/100, subtotal: money(result.subtotal)/100, discount: money(result.discount)/100 } };
  }
  return Object.freeze({
    list(target, actorId) { return guarded(target, actorId, async (client, scopeKey) => {
      const rows = (await client.query(`SELECT * FROM secureshop_review.bound_commerce_operations
        WHERE target_id=$1 AND shop_user_id=$2 AND kind='checkout' AND state='completed'
        ORDER BY created_at DESC,operation_id DESC LIMIT 20`, [target.targetId,actorId])).rows;
      const operations = [];
      for (const row of rows) { const value = await verify(client,row,target,actorId);
        operations.push({ operationId:value.operationId,orderId:value.order.id,createdAt:value.createdAt }); }
      return { scopeKey, operations };
    }); },
    read(target, actorId, operationId) {
      if (!UUID.test(operationId || '')) throw Object.assign(new Error('Invalid checkout reference'), { code:'INVALID_ARGUMENT' });
      return guarded(target, actorId, async (client, scopeKey) => {
        const rows = (await client.query(`SELECT * FROM secureshop_review.bound_commerce_operations
          WHERE operation_id=$1 AND target_id=$2 AND shop_user_id=$3 AND kind='checkout'`,
        [operationId.toLowerCase(),target.targetId,actorId])).rows;
        if (rows.length !== 1) throw missing();
        const { createdAt, ...receipt } = await verify(client,rows[0],target,actorId);
        return { scopeKey, ...receipt };
      });
    },
  });
}
module.exports = { createCheckoutHistoryRepository };
