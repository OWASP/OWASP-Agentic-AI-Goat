'use strict';
const { withTransaction } = require('./index');
const receipts=require('./secureshopRefundOperationReceipt');
const { randomUUID } = require('node:crypto');
const { copySceneBinding, executionScope, assertSceneGrant, withSceneLease } =
  require('../../services/secureshopSceneBinding');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function fail(code, message) { throw Object.assign(new Error(message), { code }); }
function integer(value, label) { if (!Number.isSafeInteger(value) || value < 1) fail('INVALID_ARGUMENT', `${label} is invalid`); return value; }
function uuid(value, label) { if (typeof value !== 'string' || !UUID.test(value)) fail('INVALID_ARGUMENT', `${label} is invalid`); return value.toLowerCase(); }
function scope(input) {
  if (!input || typeof input !== 'object') fail('INVALID_ARGUMENT', 'scope is invalid');
  return copySceneBinding(input, Object.freeze({ targetId: uuid(input.targetId, 'targetId'), launchId: uuid(input.launchId, 'launchId'),
    scenarioId: uuid(input.scenarioId, 'scenarioId'), generation: integer(input.generation, 'generation'),
    platformOwnerId: integer(input.platformOwnerId, 'platformOwnerId'), platformSessionId: integer(input.platformSessionId, 'platformSessionId') }));
}
function values(value) { return [value.targetId,value.launchId,value.scenarioId,value.generation,value.platformOwnerId,value.platformSessionId]; }
function reason(value) { if (typeof value !== 'string' || !value.trim() || Buffer.byteLength(value, 'utf8') > 4096) fail('INVALID_ARGUMENT', 'reason is invalid'); return value; }
function currentTarget(client, value) { return client.query(`SELECT lifecycle FROM secureshop_review.product_targets
  WHERE target_id=$1 AND launch_id=$2 AND scenario_id=$3 AND generation=$4
    AND original_platform_owner_id=$5 AND original_platform_session_id=$6 FOR SHARE`, values(value)).then(({rows}) => {
    if (!rows[0] || rows[0].lifecycle !== 'active') fail('PRODUCT_TARGET_UNAVAILABLE', 'product target is unavailable');
  }); }
function ticket(row, replayed = false) { return Object.freeze({ ticket_id: String(row.ticket_id), order_id: String(row.order_id), ok: true, replayed }); }
function createSecureShopBoundRefundRepository(pool, { checkCurrent, auditStore } = {}) {
  if (typeof pool?.query !== 'function' || typeof pool?.connect !== 'function' || typeof checkCurrent !== 'function') fail('INVALID_CONFIGURATION', 'refund repository dependencies are invalid');
  if (auditStore && typeof auditStore.append !== 'function') fail('INVALID_CONFIGURATION', 'audit dependency invalid');
  async function guarded(binding, effectTimeoutMs, work) {
    const execution = executionScope(binding);
    await checkCurrent(execution);
    return withSceneLease(binding, () => withTransaction(pool, async client => {
      if (effectTimeoutMs !== undefined) await client.query("SELECT set_config('statement_timeout',$1,true),set_config('lock_timeout',$1,true)", [String(effectTimeoutMs)]);
      await assertSceneGrant(client, binding);
      await currentTarget(client, binding);
      const result = await work(client, execution);
      await checkCurrent(execution);
      await assertSceneGrant(client, binding);
      return result;
    }));
  }
  async function create(input, { shopUserId, orderId, requestId, runId = null, reason: body, operation, effectTimeoutMs }) {
    const binding = scope(input); const owner = integer(shopUserId, 'shopUserId'); const order = integer(orderId, 'orderId');
    const request = uuid(requestId, 'requestId'); const run = runId == null ? null : uuid(runId, 'runId'); const text = reason(body);
    const requested=operation?receipts.request(binding,{shopUserId:owner,orderId:order,requestId:request,runId:run,reason:text},operation):null;
    if(requested&&!auditStore)fail('INVALID_CONFIGURATION','Refund audit required');
    if(effectTimeoutMs!==undefined&&(!Number.isSafeInteger(effectTimeoutMs)||effectTimeoutMs<100||effectTimeoutMs>10000))fail('INVALID_ARGUMENT','Invalid effect timeout');
    return guarded(binding, effectTimeoutMs, async (client, execution) => {
      if(requested){await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',['refund-operation:'+requested.operationId]);const prior=await receipts.find(client,binding,requested.operationId,owner);if(prior){if(prior.digest!==requested.digest)receipts.fail();return {...prior.result,receipt:prior.receipt,replayed:true};}}
      const provenance = binding.scene ? { storageTargetId: binding.targetId,
        sceneId: binding.scene.sceneId, sceneGeneration: binding.scene.sceneGeneration } : {};
      const complete=async(result,applied)=>{if(!requested)return result;const exactResult={...result,replayed:false,applied};const receipt={operationId:requested.operationId,...requested.exact,applied,ticketId:result.ticket_id};await auditStore.append(client,{eventId:requested.operationId,scope:execution,persona:{id:owner,role:'customer'},actor:'customer',action:'refund_operation',target:result.ticket_id,paramsJson:JSON.stringify({digest:requested.digest,receipt,result:exactResult,...provenance}),outcome:'completed',sourceKind:'refund_operation',sourceId:requested.operationId});return {...exactResult,receipt};};
      const row = (await client.query(`SELECT order_id,status,payment_status FROM secureshop_review.product_target_orders
        WHERE target_id=$1 AND shop_user_id=$2 AND order_id=$3 FOR UPDATE`, [binding.targetId,owner,order])).rows[0];
      if (!row) fail('ORDER_NOT_FOUND', 'order is unavailable');
      if (row.payment_status !== 'approved' || row.status === 'cancelled') fail('REFUND_NOT_ELIGIBLE', 'order is not eligible');
      const inserted = await client.query(`INSERT INTO secureshop_review.product_target_refund_requests
        (target_id,shop_user_id,order_id,request_id,run_id,reason)
        VALUES($1,$2,$3,$4,$5,$6)
        ON CONFLICT(target_id,shop_user_id,order_id,operation_kind) DO NOTHING
        RETURNING ticket_id,order_id`, [binding.targetId,owner,order,request,run,text]);
      if (inserted.rowCount === 1) {
        if (auditStore) await auditStore.append(client, {
          eventId: randomUUID(), scope: execution, persona: { id: owner, role: 'customer' },
          actor: 'customer', action: 'refund_request', target: String(inserted.rows[0].ticket_id),
          paramsJson: JSON.stringify({ orderId: order, reason: text, requestId: request, runId: run, ...provenance }),
          outcome: 'completed', sourceKind: 'refund_request', sourceId: String(inserted.rows[0].ticket_id),
        });
        return complete(ticket(inserted.rows[0], false),true);
      }
      const existing = (await client.query(`SELECT ticket_id,order_id,status FROM secureshop_review.product_target_refund_requests
        WHERE target_id=$1 AND shop_user_id=$2 AND order_id=$3 AND operation_kind='refund_request'`, [binding.targetId,owner,order])).rows[0];
      if (!existing || existing.status === 'rejected') fail('REFUND_REQUEST_UNAVAILABLE', 'refund request is unavailable');
      return complete(ticket(existing, true),false);
    });
  }
  async function readReceipt(input,{operationId,shopUserId,personaSessionId,authorityVersion,effectTimeoutMs=3000}){const binding=scope(input);const id=uuid(operationId,'operationId');if(!Number.isSafeInteger(effectTimeoutMs)||effectTimeoutMs<100||effectTimeoutMs>10000)fail('INVALID_ARGUMENT','Invalid effect timeout');return guarded(binding,effectTimeoutMs,async client=>{const packet=await receipts.find(client,binding,id,integer(shopUserId,'shopUserId'));if(packet&&(packet.receipt.personaSessionId!==personaSessionId||packet.receipt.authorityVersion!==authorityVersion))receipts.fail();return packet?.receipt??null;});}
  async function readRequest(input,{requestId,shopUserId,personaSessionId,authorityVersion,effectTimeoutMs=3000}) {
    const binding=scope(input), request=uuid(requestId,'requestId'), actor=integer(shopUserId,'shopUserId');
    if(!Number.isSafeInteger(effectTimeoutMs)||effectTimeoutMs<100||effectTimeoutMs>10000)fail('INVALID_ARGUMENT','Invalid effect timeout');
    return guarded(binding,effectTimeoutMs,async client=>{
      const execution=executionScope(binding);
      const rows=(await client.query(`SELECT event_id FROM secureshop_review.bound_audit_events
        WHERE source_kind='refund_operation' AND launch_id=$1 AND scenario_id=$2 AND generation=$3
          AND original_platform_owner_id=$4 AND original_platform_session_id=$5
          AND shop_user_id=$6 AND shop_role='customer'
          AND params_json::jsonb->'receipt'->>'requestId'=$7 LIMIT 2`,
      [execution.launchId,execution.scenarioId,execution.generation,execution.platformOwnerId,
        execution.platformSessionId,actor,request])).rows;
      if(rows.length>1)receipts.fail();
      if(!rows.length)return null;
      const packet=await receipts.find(client,binding,rows[0].event_id,actor);
      const r=packet?.receipt, result=packet?.result;
      if(!r||r.requestId!==request||r.shopUserId!==actor||r.personaSessionId!==personaSessionId
        ||r.authorityVersion!==authorityVersion||!Number.isSafeInteger(r.orderId)||r.orderId<1
        ||typeof r.ticketId!=='string'||!/^\d+$/.test(r.ticketId)
        ||result?.ok!==true||result.ticket_id!==r.ticketId||result.order_id!==String(r.orderId)
        ||result.applied!==r.applied||!['boolean'].includes(typeof r.applied))receipts.fail();
      const original=receipts.request(binding,{shopUserId:actor,orderId:r.orderId,requestId:request,
        runId:r.runId,reason:r.reason},{operationId:r.operationId,personaSessionId:r.personaSessionId,
        authorityVersion:r.authorityVersion,toolInvocationId:r.toolInvocationId});
      if(original.digest!==packet.digest)receipts.fail();
      const ticketRow=(await client.query(`SELECT ticket_id,order_id FROM secureshop_review.product_target_refund_requests
        WHERE target_id=$1 AND shop_user_id=$2 AND order_id=$3 AND ticket_id=$4`,
      [binding.targetId,actor,r.orderId,r.ticketId])).rows;
      if(ticketRow.length!==1||String(ticketRow[0].ticket_id)!==r.ticketId
        ||String(ticketRow[0].order_id)!==String(r.orderId))receipts.fail();
      return Object.freeze({ticketId:r.ticketId,orderId:r.orderId});
    });
  }
  return Object.freeze({ create,readReceipt,readRequest });
}
module.exports = { createSecureShopBoundRefundRepository };
