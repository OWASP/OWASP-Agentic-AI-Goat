'use strict';
const {createHash}=require('node:crypto');
const {executionScope}=require('./secureshopSceneBinding');
function createPersonaRefundEffect({fence,repository,effectTimeoutMs=3000}){
 if(typeof fence?.withCrossStoreEffect!=='function'||typeof repository?.create!=='function'||!Number.isSafeInteger(effectTimeoutMs)||effectTimeoutMs<100||effectTimeoutMs>10000)throw TypeError('Refund effect authority required');
 function check(scope,input){const current=executionScope(scope);if(!current||['launchId','scenarioId','generation','platformOwnerId','platformSessionId'].some(k=>current[k]!==fence.binding[k])||input.shopUserId!==fence.binding.personaId||fence.binding.role!=='customer')throw Object.assign(Error('Refund authority unavailable'),{code:'SHOP_AUTH_INVALID',executionBoundary:true});}
 return Object.freeze({
 async create(scope,input,invocation){check(scope,input);if(typeof invocation?.callId!=='string'||!invocation.callId||invocation.callId.length>128||!Number.isSafeInteger(invocation.step)||invocation.step<0||invocation.tool!=='support.refund_request')throw TypeError('Refund invocation provenance required');
 const hex=createHash('sha256').update(JSON.stringify([input.requestId,input.runId,invocation])).digest('hex');const operationId=`${hex.slice(0,8)}-${hex.slice(8,12)}-4${hex.slice(13,16)}-8${hex.slice(17,20)}-${hex.slice(20,32)}`;
 const operation={operationId,personaSessionId:fence.binding.sessionId,authorityVersion:fence.binding.authorityVersion,toolInvocationId:JSON.stringify([invocation.step,invocation.callId,invocation.tool])};
 return fence.withCrossStoreEffect(()=>repository.create(scope,{...input,operation,effectTimeoutMs}));},
 async readReceipt(scope,input){check(scope,input);return fence.withCrossStoreEffect(()=>repository.readReceipt(scope,{...input,personaSessionId:fence.binding.sessionId,authorityVersion:fence.binding.authorityVersion,effectTimeoutMs}));}
 });
}
module.exports={createPersonaRefundEffect};
