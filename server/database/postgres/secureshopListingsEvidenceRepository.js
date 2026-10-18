'use strict';
const {prepareListingAdmission,rewriteReceipt,hash,UUID}=require('../../services/secureshopListingJournalContract');
const {createConversationBinding}=require('../../services/secureshopConversationBinding');
const {createTurnRequest}=require('../../services/secureshopTurnRequest');
const {SECURESHOP_CONVERSATION_PURPOSES}=require('../../services/secureshopConversationPurpose');
const {resolveListingTarget,withListingTarget,assertListingTarget,assertListingOperation}=require('../../services/secureshopListingsTargetBinding');
const {createLaunchScope}=require('../../services/secureshopConversationBinding');
const fail=()=>Object.assign(Error('Saved Listings evidence unavailable'),{code:'LISTING_EVIDENCE_UNAVAILABLE'});
// Requires the existing 0024 candidate tables; unavailable schemas fail closed.
// Read-only: never replay a save or start inference to obtain grading evidence.
function createListingsEvidenceRepository({reviewPool,personaAuthority,listingJournal,resolveTarget}={}){
 if(typeof reviewPool?.connect!=='function'||typeof personaAuthority?.capture!=='function'||typeof listingJournal?.get!=='function')throw TypeError('Private Listings evidence dependencies required');
 return Object.freeze({async readSaved({admission:raw,saveOperationId}){
  const admission=prepareListingAdmission({...raw?.binding,request:raw?.request}),b=admission.binding,target=await resolveListingTarget(resolveTarget,b),storage=target?createLaunchScope(target):b.scope;
  if(admission.request.action!=='rewrite'||!UUID.test(saveOperationId||''))throw fail();
  const operation=await listingJournal.get({...b,request:admission.request});
  if(operation.state!=='completed')throw fail();
  const rewrite=rewriteReceipt(operation.receipt,admission);
  const expected={...b.scope,personaId:b.persona.id,role:'merchant',...b.personaSession};
  const fence=await personaAuthority.capture({scope:b.scope,personaId:b.persona.id,role:'merchant',...b.personaSession});
  if(!fence?.binding||Object.keys(expected).some(key=>fence.binding[key]!==expected[key])
   ||typeof fence.assertRemoteAdmission!=='function'||typeof fence.withPersonaEffect!=='function'||typeof fence.withCrossStoreEffect!=='function')throw fail();
  await fence.assertRemoteAdmission();
  const binding=createConversationBinding(b.scope,b.persona);
  const turn=await fence.withPersonaEffect(async client=>{
   await client.query("SET LOCAL statement_timeout='3000ms'");await client.query("SET LOCAL lock_timeout='3000ms'");
   const rows=(await client.query(`SELECT tr.session_id,tr.request_id,tr.request_hash,tr.request_version,tr.status,tr.result_json
    FROM secureshop_agents.turn_requests tr JOIN secureshop_agents.agent_sessions s ON s.id=tr.session_id
    WHERE tr.request_id=$1 AND s.conversation_purpose=$2 AND s.authority_mode='launch_bound' AND s.binding_state='active'
    AND s.platform_launch_id=$3 AND s.platform_scenario_id=$4 AND s.platform_launch_generation=$5
    AND s.original_platform_owner_id=$6 AND s.original_platform_session_id=$7 AND s.user_id=$8 AND s.role='merchant'`,
   [admission.request.operationId,SECURESHOP_CONVERSATION_PURPOSES.listingRewrite,b.scope.launchId,b.scope.scenarioId,b.scope.generation,
    b.scope.platformOwnerId,b.scope.platformSessionId,b.persona.id])).rows;
   if(rows.length!==1||rows[0].status!=='completed')throw fail();
   const row=rows[0],request=createTurnRequest({sessionId:row.session_id,requestId:row.request_id,binding,message:admission.requestJson,version:row.request_version});
   if(request.hash!==row.request_hash)throw fail();
   const result=row.result_json,metadata=result?.taskMetadata?.listings,model=metadata?.model;
   if(result?.stopReason!=='end_turn'||result.text!==rewrite.html||metadata?.action!=='rewrite'||metadata.decision!=='rewritten'
    ||metadata.operationId!==admission.request.operationId||model?.provider!==rewrite.provider||model.model!==rewrite.model
    ||model.callId!==rewrite.callId||model.mocked!==false||model.fallback!==false)throw fail();
   return Object.freeze({sessionId:row.session_id,requestId:row.request_id,requestHash:row.request_hash,status:row.status,
    binding,requestVersion:row.request_version,result:structuredClone(row.result_json)});
  });
  await fence.assertRemoteAdmission();
  const saved=await fence.withCrossStoreEffect(async()=>withListingTarget(target,async()=>{
   const client=await reviewPool.connect();let damaged=false;
   try{
    await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ');
    await client.query("SET LOCAL statement_timeout='3000ms'");await client.query("SET LOCAL lock_timeout='3000ms'");
    await client.query("SELECT pg_advisory_xact_lock(hashtextextended('secureshop-bound-audit-owner:'||$1::text,0))",[b.scope.platformOwnerId]);
    await assertListingTarget(client,target);await assertListingOperation(client,target,admission.request.operationId,admission.bindingSha256);
    const rows=(await client.query(`SELECT s.*,g.rewrite_operation_id AS current_rewrite_operation_id,g.source_name,g.source_description,
     g.source_sha256,g.html_sha256,
     CASE WHEN o.product_id IS NULL THEN p.name ELSE o.name END AS current_name,
     CASE WHEN o.product_id IS NULL THEN p.description ELSE o.description END AS current_description,
     CASE WHEN o.product_id IS NULL THEN p.description_html ELSE o.description_html END AS current_html
     FROM secureshop_review.owned_listing_rewrite_saves s
     JOIN secureshop_review.owned_listing_generated_products g ON g.target_id=s.target_id AND g.product_id=s.product_id
     JOIN secureshop_review.product_targets t ON t.target_id=s.target_id
     JOIN secureshop_review.product_target_products p ON p.target_id=s.target_id AND p.product_id=s.product_id
     LEFT JOIN secureshop_review.product_target_listing_overlays o ON o.target_id=s.target_id AND o.product_id=s.product_id
     WHERE s.save_operation_id=$1 AND s.rewrite_operation_id=$2 AND s.target_id=$3 AND s.binding_sha256=$4
      AND t.lifecycle='active' AND t.launch_id=$5 AND t.scenario_id=$6 AND t.generation=$7
      AND t.original_platform_owner_id=$8 AND t.original_platform_session_id=$9 AND ($11::boolean OR t.own_merchant_id=$10)
      AND p.retailer_id=$10 AND (o.product_id IS NULL OR (o.shop_user_id=$10 AND o.archived_at IS NULL))
      AND NOT EXISTS(SELECT 1 FROM secureshop_review.bound_audit_owner_deletion_receipts d WHERE d.original_platform_owner_id=t.original_platform_owner_id)`,
    [saveOperationId,admission.request.operationId,b.targetId,admission.bindingSha256,storage.launchId,storage.scenarioId,storage.generation,
     storage.platformOwnerId,storage.platformSessionId,b.persona.id,!!target?.scene])).rows;
    if(rows.length!==1)throw fail();
    const row=rows[0];
    if(typeof row.receipt_json!=='string'||hash(row.receipt_json)!==row.receipt_sha256
     ||row.current_rewrite_operation_id!==admission.request.operationId||row.source_name!==admission.request.title
     ||row.source_description!==admission.request.description||row.current_name!==row.source_name||row.current_description!==row.source_description
     ||typeof row.current_html!=='string'||hash(row.current_html)!==row.html_sha256
     ||hash(JSON.stringify([row.source_name,row.source_description]))!==row.source_sha256)throw fail();
    const save=JSON.parse(row.receipt_json);
    if(save.saveOperationId!==saveOperationId||save.rewriteOperationId!==admission.request.operationId||save.targetId!==b.targetId
     ||save.productId!==row.product_id||save.bindingSha256!==admission.bindingSha256||save.requestSha256!==row.request_sha256
     ||save.htmlSha256!==row.html_sha256||save.sourceSha256!==row.source_sha256)throw fail();
    await assertListingTarget(client,target);
    await client.query('COMMIT');
    return {save,source:{admission,saveOperationId,productId:row.product_id,html:row.current_html,htmlSha256:row.html_sha256}};
   }catch(error){try{await client.query('ROLLBACK');}catch{damaged=true;}throw error;}finally{client.release(damaged);}
  }));
  await fence.assertRemoteAdmission();
  return Object.freeze({admission,operation,turn,...saved});
 }});
}
module.exports={createListingsEvidenceRepository};
