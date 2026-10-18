'use strict';
const moderationBinding=require('./secureshopReviewModerationBinding');
const {createPersonaReviewEffect}=require('./secureshopPersonaReviewEffect');
const BIRTH_KEYS=['targetId','launchId','scenarioId','generation','platformOwnerId','platformSessionId'];
function executionScopeKey(binding){return JSON.stringify([binding.launchId,binding.generation,binding.platformOwnerId,binding.platformSessionId,binding.personaId,binding.sessionId]);}
function verifiedReceipt(receipt,target,binding,operationId,expected){
 if(!receipt||receipt.kind!=='manual'||receipt.moderatorKind!=='manual'||receipt.operationId!==operationId.toLowerCase()
  ||BIRTH_KEYS.some(key=>receipt.scope?.[key]!==target[key])
  ||receipt.actor?.id!==binding.personaId||receipt.actor?.role!==binding.role
  ||receipt.actor?.personaSessionId!==binding.sessionId||receipt.actor?.authorityVersion!==binding.authorityVersion
  ||(expected&&(receipt.reviewId!==expected.reviewId||receipt.decision!==(expected.decision==='approve'?'approved':'rejected')||receipt.notes!==(expected.reason??null)||(expected.expectedSnapshotSha256!==undefined&&receipt.expectedSnapshotSha256!==expected.expectedSnapshotSha256))))
  throw Object.assign(Error('Review receipt unavailable'),{code:'SHOP_AUTH_INVALID'});
 return receipt;
}
function createManualReviewDecision({authority,repository,resolveTarget}={}){
 if(typeof authority?.capture!=='function'||typeof repository?.readDecisionReceipt!=='function'||typeof resolveTarget!=='function')throw new TypeError('Manual review recovery dependencies required');
 function captured({scope,persona,personaSession}){if(persona?.role!=='merchant')throw Object.assign(Error('Review authority unavailable'),{code:'SHOP_AUTH_INVALID'});return authority.capture({scope,personaId:persona.id,role:persona.role,sessionId:personaSession?.sessionId,authorityVersion:personaSession?.authorityVersion});}
 return Object.freeze({
  async capability(input){const fence=captured(input);await fence.assertRemoteAdmission();return{available:true,scopeKey:executionScopeKey(fence.binding)};},
  async decide(input){const fence=captured(input);await fence.assertRemoteAdmission();const target=await resolveTarget(input.scope);const result=await createPersonaReviewEffect({fence,repository}).decide(target,{moderation:moderationBinding.capture(target,input.persona,fence),reviewId:input.reviewId,decision:input.decision,notes:input.reason??null,moderatorKind:'manual',...(input.expectedSnapshotSha256===undefined?{}:{expectedSnapshotSha256:input.expectedSnapshotSha256}),auditPersona:{id:input.persona.id,role:input.persona.role},operation:{operationId:input.operationId,kind:'manual',personaSessionId:fence.binding.sessionId,authorityVersion:fence.binding.authorityVersion}});verifiedReceipt(result?.receipt,target,fence.binding,input.operationId,input);return Object.freeze({...result,executionScopeKey:executionScopeKey(fence.binding)});},
  async read(input){const fence=captured(input);await fence.assertRemoteAdmission();const target=await resolveTarget(input.scope);let receipt;try{receipt=await createPersonaReviewEffect({fence,repository}).readDecisionReceipt(target,{operationId:input.operationId,auditPersona:{id:input.persona.id,role:input.persona.role}});}catch(error){if(error?.code==='REVIEW_OPERATION_CONFLICT')return null;throw error;}return receipt?Object.freeze({receipt:verifiedReceipt(receipt,target,fence.binding,input.operationId),executionScopeKey:executionScopeKey(fence.binding)}):null;}
 });
}
module.exports={createManualReviewDecision};
