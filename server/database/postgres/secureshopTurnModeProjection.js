'use strict';
const {createConversationBinding}=require('../../services/secureshopConversationBinding');
const {createTurnRequest}=require('../../services/secureshopTurnRequest');
const {normalizeConversationPurpose,SECURESHOP_CONVERSATION_PURPOSES:purposes}=require('../../services/secureshopConversationPurpose');
const invalid=()=>Object.assign(Error('Original turn mode unavailable'),{code:'TURN_MODE_INTEGRITY_UNAVAILABLE'});
function projectSavedMode(value,featureId){
 if(value===undefined)return undefined;
 const exact=(v,keys)=>v&&Object.getPrototypeOf(v)===Object.prototype&&Reflect.ownKeys(v).length===keys.length&&keys.every(k=>Object.hasOwn(Object.getOwnPropertyDescriptor(v,k)||{},'value'));
 if(!exact(value,['version','featureId','policyVersion','effectiveMode','scope'])||value.version!==1||value.featureId!==featureId
  ||!['vuln','fixed'].includes(value.effectiveMode)||typeof value.policyVersion!=='string'||!/^[a-z0-9-]{1,128}$/.test(value.policyVersion)
  ||!exact(value.scope,['kind','id'])||value.scope.kind!=='launch_feature'||value.scope.id!==featureId)throw invalid();
 return Object.freeze({...value,scope:Object.freeze({...value.scope})});
}
// client must belong to the caller's existing authenticated persona transaction.
// An immutable effect may precede journal completion; absent old provenance stays absent.
async function readTurnModeProjection(client,{scope,persona,requestId,purpose,message,featureId,verifyResult,expectedStopReason='end_turn'}){
 const binding=createConversationBinding(scope,persona);purpose=normalizeConversationPurpose(purpose);
 if(typeof verifyResult!=='function'||typeof message!=='string')throw invalid();
 // Only validated Pricing denials opt into the distinct completed graph outcome.
 if(expectedStopReason!=='end_turn'&&(expectedStopReason!=='tool_denied'||featureId!=='pricing'
  ||![purposes.priceAdvisor,purposes.pricingStrategy].includes(purpose)))throw invalid();
 const rows=(await client.query(`SELECT tr.session_id,tr.request_hash,tr.request_version,tr.status,tr.result_json
  FROM secureshop_agents.turn_requests tr JOIN secureshop_agents.agent_sessions s ON s.id=tr.session_id
  WHERE tr.request_id=$1 AND s.conversation_purpose=$2 AND s.authority_mode='launch_bound' AND s.binding_state='active'
   AND s.platform_launch_id=$3 AND s.platform_scenario_id=$4 AND s.platform_launch_generation=$5
   AND s.original_platform_owner_id=$6 AND s.original_platform_session_id=$7 AND s.user_id=$8 AND s.role=$9`,
  [requestId,purpose,binding.launchId,binding.scenarioId,binding.generation,binding.platformOwnerId,binding.platformSessionId,binding.shopUserId,binding.role])).rows;
 if(!rows.length)return undefined;if(rows.length!==1)throw invalid();const row=rows[0];
 if(row.status!=='completed')return undefined;
 const request=createTurnRequest({sessionId:row.session_id,requestId,binding,message,version:row.request_version});
 if(request.hash!==row.request_hash||row.result_json?.stopReason!==expectedStopReason||verifyResult(row.result_json)!==true)throw invalid();
 return projectSavedMode(row.result_json.modeCapability,featureId);
}
module.exports={readTurnModeProjection,projectSavedMode};
