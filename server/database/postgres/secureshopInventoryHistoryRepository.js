'use strict';
const {isDeepStrictEqual:equal}=require('node:util');
const {createLaunchScope,createConversationBinding}=require('../../services/secureshopConversationBinding');
const {createTurnRequest}=require('../../services/secureshopTurnRequest');
const {assertSceneGrant,withSceneLease}=require('../../services/secureshopSceneBinding');
const {executionScope}=require('../../services/secureshopSceneBinding');
const {UUID,hash}=require('../../services/secureshopCouponContract');
const {fail,request:normalizeOperation}=require('../../services/secureshopInventoryContract');

const {assertInventoryMetadata,inventoryTaskEnvelope}=require('../../services/secureshopInventoryTaskContract');
const unavailable=()=>fail('INVENTORY_HISTORY_NOT_FOUND');
const oldScope=row=>createLaunchScope({launchId:row.platform_launch_id,scenarioId:row.platform_scenario_id,
 generation:Number(row.platform_launch_generation),platformOwnerId:Number(row.original_platform_owner_id),
 platformSessionId:Number(row.original_platform_session_id)});
function createInventoryHistoryRepository({agentsPool,reviewPool,checkCurrent}={}){
 if(typeof agentsPool?.query!=='function'||typeof reviewPool?.connect!=='function'||typeof checkCurrent!=='function')throw TypeError('Inventory history dependencies required');
 async function guarded(target,scope,work){
  if(!target?.scene||!equal(executionScope(target),createLaunchScope(scope)))throw unavailable();
  await checkCurrent(scope);
  return withSceneLease(target,async()=>{
   const client=await reviewPool.connect();
   try{
    await client.query('BEGIN');
    await client.query("SET LOCAL statement_timeout='3000ms'");
    await client.query("SET LOCAL lock_timeout='3000ms'");
    await assertSceneGrant(client,target);
    const birth=await client.query(`SELECT 1 FROM secureshop_review.product_targets WHERE target_id=$1
      AND launch_id=$2 AND scenario_id=$3 AND generation=$4 AND original_platform_owner_id=$5
      AND original_platform_session_id=$6 AND lifecycle='active' FOR SHARE`,
      [target.targetId,target.launchId,target.scenarioId,target.generation,target.platformOwnerId,target.platformSessionId]);
    if(birth.rowCount!==1)throw unavailable();
    const result=await work(client);
    await checkCurrent(scope);
    await assertSceneGrant(client,target);
    await client.query('COMMIT');
    await checkCurrent(scope);
    return result;
   }catch(error){await client.query('ROLLBACK').catch(()=>{});throw error;}finally{client.release();}
  });
 }
 const base=`FROM secureshop_agents.turn_requests tr JOIN secureshop_agents.agent_sessions s ON s.id=tr.session_id
    WHERE s.conversation_purpose='secureshop_inventory' AND s.authority_mode='launch_bound'
      AND s.original_platform_owner_id=$1 AND s.user_id=$2 AND s.role='merchant'
      AND tr.status='completed' AND tr.result_json->>'stopReason'='end_turn'
      AND tr.result_json #>> '{taskMetadata,inventory,targetId}'=$3`;
 async function row(requestId,ownerId,actorId,targetId){
  const result=await agentsPool.query(`SELECT tr.*,s.platform_launch_id,s.platform_scenario_id,
    s.platform_launch_generation,s.original_platform_owner_id,s.original_platform_session_id,s.user_id,s.role
    ${base} AND tr.request_id=$4`,[ownerId,actorId,targetId,requestId]);
  if(result.rows.length!==1)throw unavailable();return result.rows[0];
 }
 async function verify(client,turn,{target,ownerId,actorId,requestId}){
  const outcome=turn.result_json,meta=outcome?.taskMetadata?.inventory;
  try{assertInventoryMetadata(meta);}catch{throw unavailable();}
  if(meta.targetId!==target.targetId||meta.requestId!==requestId
    ||!['vuln','fixed'].includes(meta.mode)||typeof meta.message!=='string'||!meta.message.trim()
    ||!Array.isArray(meta.receipts)||meta.receipts.length>5||!Array.isArray(meta.effects)
    ||meta.effects.length!==meta.receipts.length||typeof outcome.text!=='string')throw unavailable();
  const origin=oldScope(turn);
  if(origin.platformOwnerId!==ownerId||Number(turn.user_id)!==actorId||turn.role!=='merchant')throw unavailable();
  const personaSession=meta.personaSession;
  if(!UUID.test(personaSession?.sessionId||'')||!/^[1-9][0-9]*$/.test(personaSession?.authorityVersion||''))throw unavailable();
  const originalPersonaSession={sessionId:personaSession.sessionId,authorityVersion:personaSession.authorityVersion};
  const priorSession=await agentsPool.query(`SELECT 1 FROM secureshop_agents.bound_persona_sessions WHERE session_id=$1
    AND shop_user_id=$2 AND role='merchant' AND platform_launch_id=$3 AND platform_scenario_id=$4
    AND platform_launch_generation=$5 AND original_platform_owner_id=$6 AND original_platform_session_id=$7`,
    [personaSession.sessionId,actorId,origin.launchId,origin.scenarioId,origin.generation,origin.platformOwnerId,origin.platformSessionId]);
  if(priorSession.rowCount!==1)throw unavailable();
  const encoded=inventoryTaskEnvelope(meta,meta.mode,originalPersonaSession);
  if(createTurnRequest({sessionId:turn.session_id,requestId,binding:createConversationBinding(origin,{id:actorId,role:'merchant'}),
    version:Number(turn.request_version),message:encoded}).hash!==turn.request_hash)throw unavailable();
  const operations=(await client.query(`SELECT * FROM secureshop_review.owned_inventory_operations
    WHERE target_id=$1 AND request_id=$2 AND shop_user_id=$3 ORDER BY operation_id`,[target.targetId,requestId,actorId])).rows;
  if(operations.length!==meta.receipts.length)throw unavailable();
  const byId=new Map(operations.map(value=>[value.operation_id,value]));
  if(byId.size!==operations.length)throw unavailable();
  const visible=[];
  for(const entry of meta.receipts){
   const receipt=entry?.receipt,b=receipt?.binding,stored=byId.get(receipt?.operationId);
   let canonical;
   try{canonical=normalizeOperation({target:{...origin,targetId:target.targetId},
     persona:{id:b?.persona?.id,role:b?.persona?.role},
     personaSession:{sessionId:b?.personaSession?.sessionId,authorityVersion:b?.personaSession?.authorityVersion},
     mode:b?.mode,operationId:b?.operationId,action:b?.action,
     args:b?.action==='set_stock'?{productId:b?.args?.productId,quantity:b?.args?.quantity}
       :b?.action==='reorder_suggestion'?{productId:b?.args?.productId}:{},
     execution:b?.execution?{runId:b.execution.runId,requestId:b.execution.requestId,callId:b.execution.callId}:null});}catch{throw unavailable();}
   if(receipt?.version!==1||!stored||!b||receipt.operationId!==b.operationId||b.targetId!==target.targetId
     ||!equal(b,canonical)||b.persona?.id!==actorId||b.persona?.role!=='merchant'
     ||!equal(b.personaSession,personaSession)||b.mode!==meta.mode||b.execution?.requestId!==requestId
     ||stored.state!=='completed'||Number(stored.shop_user_id)!==actorId
     ||stored.persona_session_id!==personaSession.sessionId
     ||String(stored.authority_version)!==personaSession.authorityVersion
     ||stored.mode!==meta.mode||stored.action!==b.action||stored.run_id!==b.execution.runId
     ||stored.call_id!==b.execution.callId
     ||stored.request_sha256!==receipt.requestSha256||stored.request_json===null
     ||hash(stored.request_json)!==stored.request_sha256||stored.result_json===null
     ||hash(stored.result_json)!==stored.result_sha256)throw unavailable();
   let request,verified;
   try{request=JSON.parse(stored.request_json);verified=JSON.parse(stored.result_json);}catch{throw unavailable();}
   if(!equal(request,b)||!equal(verified,receipt))throw unavailable();
   visible.push({action:b.action,result:receipt.result});byId.delete(receipt.operationId);
  }
  if(byId.size)throw unavailable();
  return Object.freeze({ok:true,status:'completed',historical:true,requestId,mode:meta.mode,
    answer:outcome.text,operations:visible});
 }
 return Object.freeze({
  async list({scope,target,persona}){
   const actorId=persona.id,ownerId=scope.platformOwnerId;
   return guarded(target,scope,async()=>{
    const result=await agentsPool.query(`SELECT tr.request_id,tr.finished_at,
      tr.result_json #>> '{taskMetadata,inventory,mode}' AS mode ${base}
      ORDER BY tr.finished_at DESC,tr.request_id DESC LIMIT 20`,[ownerId,actorId,target.targetId]);
    return {ok:true,operations:result.rows.filter(value=>['vuln','fixed'].includes(value.mode))
      .map(value=>({requestId:value.request_id,recordedAt:value.finished_at,mode:value.mode,status:'completed'}))};
   });
  },
  async read({scope,target,persona,requestId}){
   if(!UUID.test(requestId||''))throw fail('INVENTORY_INVALID');
   const actorId=persona.id,ownerId=scope.platformOwnerId;
   return guarded(target,scope,async client=>verify(client,await row(requestId,ownerId,actorId,target.targetId),
     {target,ownerId,actorId,requestId}));
  },
 });
}
module.exports={createInventoryHistoryRepository};
