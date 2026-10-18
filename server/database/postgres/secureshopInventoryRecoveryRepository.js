'use strict';
const {isDeepStrictEqual:equal}=require('node:util');
const {createLaunchScope,createConversationBinding}=require('../../services/secureshopConversationBinding');
const {createTurnRequest}=require('../../services/secureshopTurnRequest');
const {UUID}=require('../../services/secureshopCouponContract');
const {fail}=require('../../services/secureshopInventoryContract');
const {assertInventoryMetadata,inventoryTaskEnvelope}=require('../../services/secureshopInventoryTaskContract');
function createInventoryRecoveryRepository({personaAuthority,checkCurrent,mode}={}){
 if(typeof personaAuthority?.capture!=='function'||typeof checkCurrent!=='function'||!['vuln','fixed'].includes(mode))throw TypeError('Inventory recovery dependencies required');
 return Object.freeze({async read({scope:raw,persona,personaSession,requestId}){
  const scope=createLaunchScope(raw);if(persona?.role!=='merchant'||!UUID.test(requestId||''))throw fail('INVENTORY_INVALID');
  const fence=await personaAuthority.capture({scope,personaId:persona.id,role:persona.role,...personaSession}),expected={...scope,personaId:persona.id,role:persona.role,...personaSession};if(Object.keys(expected).some(k=>fence.binding?.[k]!==expected[k]))throw fail('SHOP_AUTH_INVALID');
  await checkCurrent(scope);const answer=await fence.withPersonaEffect(async client=>{
   await client.query("SET LOCAL statement_timeout='3000ms'");await client.query("SET LOCAL lock_timeout='3000ms'");
   const rows=(await client.query(`SELECT tr.session_id,tr.request_hash,tr.request_version,tr.status,tr.result_json FROM secureshop_agents.turn_requests tr JOIN secureshop_agents.agent_sessions s ON s.id=tr.session_id
   WHERE tr.request_id=$1 AND s.conversation_purpose='secureshop_inventory' AND s.authority_mode='launch_bound' AND s.binding_state='active'
   AND s.platform_launch_id=$2 AND s.platform_scenario_id=$3 AND s.platform_launch_generation=$4 AND s.original_platform_owner_id=$5 AND s.original_platform_session_id=$6 AND s.user_id=$7 AND s.role='merchant'`,[requestId,scope.launchId,scope.scenarioId,scope.generation,scope.platformOwnerId,scope.platformSessionId,persona.id])).rows;
   if(!rows.length)return{status:'not_found',requestId};if(rows.length!==1)throw fail('INVENTORY_RECOVERY_UNAVAILABLE');const row=rows[0];if(row.status!=='completed')return{status:row.status==='started'?'pending':'uncertain',requestId};
   const metadata=row.result_json?.taskMetadata?.inventory;try{assertInventoryMetadata(metadata);}catch{throw fail('INVENTORY_RECOVERY_UNAVAILABLE');}if(metadata.requestId!==requestId||metadata.mode!==mode||!equal(metadata.personaSession,personaSession)||row.result_json.stopReason!=='end_turn')throw fail('INVENTORY_RECOVERY_UNAVAILABLE');
   const request=createTurnRequest({sessionId:row.session_id,requestId,binding:createConversationBinding(scope,persona),version:row.request_version,message:inventoryTaskEnvelope(metadata,mode,personaSession)});if(request.hash!==row.request_hash)throw fail('INVENTORY_RECOVERY_UNAVAILABLE');return{status:'completed',requestId,outcome:row.result_json};
  });await checkCurrent(scope);await fence.assertRemoteAdmission();return answer;
 }});
}
module.exports={createInventoryRecoveryRepository};
