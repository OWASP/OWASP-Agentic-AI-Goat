'use strict';
const {createHmac,createHash}=require('node:crypto');
const {prepareListingRewriteSave}=require('../../services/secureshopListingRewriteSaveContract');
const {resolveListingTarget,withListingTarget,assertListingTarget,assertListingOperation}=require('../../services/secureshopListingsTargetBinding');
const fail=code=>Object.assign(new Error('Owned rewrite save unavailable'),{code});
function createListingRewriteSaveRepository({pool,personaAuthority,capabilityKey,resolveTarget,resolveRetainedTarget}={}){
 if(resolveTarget!==undefined&&typeof resolveTarget!=='function')throw TypeError('Canonical target resolver required');
 if(resolveRetainedTarget!==undefined&&typeof resolveRetainedTarget!=='function')throw TypeError('Retained target resolver required');
 if(typeof pool?.connect!=='function'||typeof personaAuthority?.capture!=='function'||!Buffer.isBuffer(capabilityKey)||capabilityKey.length!==32)throw TypeError('Private rewrite save dependencies required');
 const key=Buffer.from(capabilityKey);
 return Object.freeze({async read({admission:raw,saveOperationId}){
  const {prepareListingAdmission,UUID}=require('../../services/secureshopListingJournalContract');
  const {executionScope}=require('../../services/secureshopSceneBinding');
  const a=prepareListingAdmission({...raw?.binding,request:raw?.request}),b=a.binding;
  if(a.request.action!=='rewrite'||typeof saveOperationId!=='string'||!UUID.test(saveOperationId)||typeof resolveRetainedTarget!=='function')throw fail('LISTING_SAVE_UNAVAILABLE');
  const expected={...b.scope,personaId:b.persona.id,role:'merchant',...b.personaSession};
  const fence=await personaAuthority.capture({scope:b.scope,personaId:b.persona.id,role:'merchant',...b.personaSession});
  if(!fence?.binding||Object.keys(expected).some(k=>expected[k]!==fence.binding[k])||typeof fence.assertRemoteAdmission!=='function')throw fail('SHOP_AUTH_INVALID');
  await fence.assertRemoteAdmission();
  const target=await resolveRetainedTarget(b);
  if(!target||target.targetId!==b.targetId||Object.keys(b.scope).some(k=>executionScope(target)[k]!==b.scope[k]))throw fail('LISTING_TARGET_UNAVAILABLE');
  return withListingTarget(target,async()=>{
   const client=await pool.connect();let damaged=false;
   try{
    // The scene-authority assertion takes FOR SHARE locks on its grant and
    // product-target rows. PostgreSQL rejects those locks in a READ ONLY
    // transaction, so retain the repeatable snapshot without that modifier.
    await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ');
    await client.query("SET LOCAL statement_timeout='3000ms'");await client.query("SET LOCAL lock_timeout='3000ms'");
    await assertListingTarget(client,target);await assertListingOperation(client,target,a.request.operationId,a.bindingSha256);
    const rows=(await client.query(`SELECT s.receipt_json,s.receipt_sha256,s.request_sha256,s.product_id
     FROM secureshop_review.owned_listing_rewrite_saves s
     JOIN secureshop_review.product_targets t ON t.target_id=s.target_id
     WHERE s.save_operation_id=$1 AND s.rewrite_operation_id=$2 AND s.target_id=$3 AND s.binding_sha256=$4
      AND t.lifecycle='active' AND t.launch_id=$5 AND t.scenario_id=$6 AND t.generation=$7
      AND t.original_platform_owner_id=$8 AND t.original_platform_session_id=$9
      AND NOT EXISTS(SELECT 1 FROM secureshop_review.bound_audit_owner_deletion_receipts d WHERE d.original_platform_owner_id=t.original_platform_owner_id)`,
     // A scene packet is admitted against its current execution scope, while
     // product_targets remains keyed to the immutable retained storage birth.
     // validateListingTarget and assertListingTarget above fence the execution
     // scope; this lookup must use the target's birth tuple.
     [saveOperationId,a.request.operationId,b.targetId,a.bindingSha256,target.launchId,target.scenarioId,target.generation,
      target.platformOwnerId,target.platformSessionId])).rows;
    if(rows.length!==1||typeof rows[0].receipt_json!=='string'||createHash('sha256').update(rows[0].receipt_json).digest('hex')!==rows[0].receipt_sha256)throw fail('LISTING_NOT_FOUND');
    const receipt=JSON.parse(rows[0].receipt_json);
    const keys=['version','saveOperationId','rewriteOperationId','targetId','requestedProductId','productId','bindingSha256','requestSha256','sourceSha256','htmlSha256'];
    if(!receipt||Object.keys(receipt).sort().join(',')!==keys.sort().join(',')||receipt.version!==1
     ||receipt.saveOperationId!==saveOperationId||receipt.rewriteOperationId!==a.request.operationId||receipt.targetId!==b.targetId
     ||receipt.bindingSha256!==a.bindingSha256||receipt.requestSha256!==rows[0].request_sha256||receipt.productId!==rows[0].product_id
     ||!['sourceSha256','htmlSha256','requestSha256'].every(k=>/^[a-f0-9]{64}$/.test(receipt[k])))throw fail('LISTING_SAVE_RECEIPT_INVALID');
    await assertListingTarget(client,target);await client.query('COMMIT');await fence.assertRemoteAdmission();return Object.freeze(receipt);
   }catch(error){try{await client.query('ROLLBACK');}catch{damaged=true;}throw error;}finally{client.release(damaged);}
  });
 },async save(raw){
  const x=prepareListingRewriteSave(raw),a=x.admission,b=a.binding,target=await resolveListingTarget(resolveTarget,b);
  const expected={...b.scope,personaId:b.persona.id,role:'merchant',...b.personaSession};
  const fence=await personaAuthority.capture({scope:b.scope,personaId:b.persona.id,role:'merchant',...b.personaSession});
  if(!fence?.binding||Object.keys(expected).some(k=>expected[k]!==fence.binding[k])||typeof fence.assertRemoteAdmission!=='function'||typeof fence.withCrossStoreEffect!=='function')throw fail('SHOP_AUTH_INVALID');
  await fence.assertRemoteAdmission();let commitAttempted=false;
  try{
   const result=await fence.withCrossStoreEffect(async()=>withListingTarget(target,async()=>{
    const client=await pool.connect();let damaged=false;
    try{
     await client.query('BEGIN');await client.query("SET LOCAL statement_timeout='3000ms'");await client.query("SET LOCAL lock_timeout='3000ms'");
     await client.query("SELECT pg_advisory_xact_lock(hashtextextended('secureshop-bound-audit-owner:'||$1::text,0))",[b.scope.platformOwnerId]);
     await assertListingTarget(client,target);await assertListingOperation(client,target,a.request.operationId,a.bindingSha256);
     const capability=createHmac('sha256',key).update(JSON.stringify([a.request.operationId,a.bindingSha256,a.requestSha256])).digest('hex');
     const row=(await client.query('SELECT secureshop_review.consume_owned_listing_rewrite($1::uuid,$2::uuid,$3::text,$4::integer,$5::text,$6::text,$7::text) AS receipt',
      [x.saveOperationId,a.request.operationId,a.bindingJson,x.productId,x.itemJson,x.itemSha256,capability])).rows[0];
     const receipt=JSON.parse(row?.receipt);
     const keys=['version','saveOperationId','rewriteOperationId','targetId','requestedProductId','productId','bindingSha256','requestSha256','sourceSha256','htmlSha256'];
     if(!receipt||Object.keys(receipt).sort().join(',')!==keys.sort().join(',')||receipt.version!==1||receipt.saveOperationId!==x.saveOperationId||receipt.rewriteOperationId!==a.request.operationId||receipt.targetId!==b.targetId||receipt.requestedProductId!==x.productId||receipt.bindingSha256!==a.bindingSha256||receipt.requestSha256!==x.itemSha256||receipt.sourceSha256!==x.sourceSha256||!/^[a-f0-9]{64}$/.test(receipt.htmlSha256)||!Number.isInteger(receipt.productId)||receipt.productId<1||receipt.productId>2147483647)throw fail('LISTING_SAVE_RECEIPT_INVALID');
     // withCrossStoreEffect retains the authority transaction and checks its
     // current session before/after this callback. Reacquiring it here deadlocks.
     await assertListingTarget(client,target);
     commitAttempted=true;await client.query('COMMIT');return Object.freeze(receipt);
    }catch(error){try{await client.query('ROLLBACK');}catch{damaged=true;}throw error;}finally{client.release(damaged);}
   }));
   await fence.assertRemoteAdmission();return result;
  }catch(error){if(commitAttempted)throw fail('LISTING_OUTCOME_UNCERTAIN');throw error;}
 }});
}
module.exports={createListingRewriteSaveRepository};
