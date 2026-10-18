'use strict';
// No claim, signing or dispatch dependency is retained in this service.
const C=require('./secureshopOwnedMcpInvocationContract');
function createInvocationRecovery({repository,manager}={}){
 if(!['prepare','identity','settle'].every(k=>typeof repository?.[k]==='function')||typeof manager?.status!=='function')throw TypeError('Private status recovery dependencies required');
 const status=manager.status.bind(manager);
 async function reconcile(raw,{signal}={}){const input=C.bounded(raw,2048);signal?.throwIfAborted();const handle=await repository.prepare(input),identity=repository.identity(handle);signal?.throwIfAborted();const receipt=await status(identity,{signal});signal?.throwIfAborted();
  // The manager client verifies signature, domain, request and receipt schema.
  if(Object.entries(identity).some(([k,v])=>receipt[k]!==v)||!['absent','running','completed','failed_before_effect','uncertain'].includes(receipt.state))throw Object.assign(Error('Recovery receipt mismatch'),{code:'MCP_INVOCATION_RECOVERY_DENIED'});
  if(['absent','running'].includes(receipt.state))return C.freeze({identity,state:receipt.state,settled:false,needsCanonicalRetirement:receipt.state==='absent',automaticRetry:false});
  const settled=await repository.settle(handle,receipt);return C.freeze({identity,state:settled.state,settled:true,needsCanonicalRetirement:receipt.state==='uncertain',automaticRetry:false});
 }
 return Object.freeze({reconcile});
}
module.exports={createInvocationRecovery};
