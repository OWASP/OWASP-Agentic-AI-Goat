'use strict';
const reviewScene = require('./secureshopReviewSceneBinding');
// Candidate-only store adapter. Target resolution/model/Judge work must happen
// before/after this call. Agents authority -> review target/row is the lock order.
// Never pass an agents client to the independent review store transaction.
function createPersonaReviewEffect({fence,repository,effectTimeoutMs=3000}={}) {
 if(typeof fence?.withCrossStoreEffect!=='function'||typeof repository?.decide!=='function'
  ||!Number.isSafeInteger(effectTimeoutMs)||effectTimeoutMs<100||effectTimeoutMs>10000)throw new TypeError('Bounded review effect dependencies required');
 return Object.freeze({...repository,async readDecisionReceipt(scope,input){
  if(['launchId','scenarioId','generation','platformOwnerId','platformSessionId'].some(k=>reviewScene.current(scope)[k]!==fence.binding[k])||input?.auditPersona?.id!==fence.binding.personaId||input.auditPersona.role!==fence.binding.role)throw Object.assign(Error('Review receipt authority mismatch'),{code:'SHOP_AUTH_INVALID'});
  return fence.withCrossStoreEffect(()=>repository.readDecisionReceipt(scope,input));
 },async decide(scope,input){
  if(!scope||['launchId','scenarioId','generation','platformOwnerId','platformSessionId'].some(k=>reviewScene.current(scope)[k]!==fence.binding[k])
   ||input?.auditPersona?.id!==fence.binding.personaId||input.auditPersona.role!==fence.binding.role)throw Object.assign(Error('Review effect authority mismatch'),{code:'SHOP_AUTH_INVALID',executionBoundary:true});
  if(input.operation && (input.operation.personaSessionId!==fence.binding.sessionId||input.operation.authorityVersion!==fence.binding.authorityVersion))throw Object.assign(Error('Decision session provenance mismatch'),{code:'SHOP_AUTH_INVALID'});
  // Scene moderation owns the same captured fence inside the repository.
  // Do not reacquire its agents lease around that call.
  return reviewScene.productScene(scope) ? repository.decide(scope,{...input,effectTimeoutMs})
   : fence.withCrossStoreEffect(()=>repository.decide(scope,{...input,effectTimeoutMs}));
 }});
}
module.exports={createPersonaReviewEffect};
