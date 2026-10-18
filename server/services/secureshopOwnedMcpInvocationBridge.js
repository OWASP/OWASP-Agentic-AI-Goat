'use strict';
// Purpose-specific private bridge. No API accepts a persisted row, grant, receipt
// or signing key from a caller. Failed identity COMMIT never reaches claim().
const C=require('./secureshopOwnedMcpInvocationContract');
const W=require('./secureshopOwnedMcpInvocationWire');
const {currentEffectAdmission}=require('../agent-runtime/effectAdmissionContext');
const fail=()=>Object.assign(Error('Invocation requires private recovery'),{code:'MCP_INVOCATION_OUTCOME_UNCERTAIN',automaticRetry:false});
function createInvocationBridge({journal,launches,client,resolveAsset}={}){
 if(!['prepare','settlePrepared'].every(k=>typeof journal?.[k]==='function')||typeof launches?.admitOwnedMcpInvocation!=='function'||!['claim','status'].every(k=>typeof client?.[k]==='function')||typeof resolveAsset!=='function')throw TypeError('Private invocation bridge dependencies required');
 const recoveries=new WeakMap();
 async function settle(record,value){if(['completed','failed_before_effect','uncertain'].includes(value.state))await journal.settlePrepared(record.prepared,value);return value;}
 function invoke(raw,execution){
  // Snapshot and protect effect identity synchronously, before any await.
  const input=C.bounded(raw,196608),effect=currentEffectAdmission(execution),snapshot=C.snapshot(input.snapshot),request=C.request({...input,snapshot});
  const assetId=resolveAsset(C.freeze({snapshot,request,policySha256:input.policySha256}));
  const claim=W.claim({invocationId:input.invocationId,snapshot,request,personaSession:input.personaSession,managerInstanceId:input.managerInstanceId,runtimeSha256:input.runtimeSha256,policySha256:input.policySha256,effectKey:effect.ledgerEffectKey,assetId});
  const prepared=journal.prepare(input,execution),recovery=Object.freeze({});
  const record={prepared,identity:{invocationId:claim.invocationId,requestSha256:C.digest(request),managerInstanceId:claim.managerInstanceId,runtimeSha256:claim.runtimeSha256},committed:false};
  recoveries.set(recovery,record);
  const completion=(async()=>{
   const grant=await launches.admitOwnedMcpInvocation(prepared);
   if(grant.invocationId!==claim.invocationId||grant.requestSha256!==record.identity.requestSha256||grant.managerInstanceId!==claim.managerInstanceId||grant.state!=='admitted')throw fail();
   record.committed=true;
   try{return await settle(record,await client.claim(claim,{signal:execution.signal}));}catch(cause){throw Object.assign(fail(),{cause});}
  })();return Object.freeze({recovery,completion});
 }
 async function reconcile(handle,{signal}={}){const record=recoveries.get(handle);if(!record?.committed)throw fail();return settle(record,await client.status(record.identity,{signal}));}
 return Object.freeze({invoke,reconcile});
}
module.exports={createInvocationBridge};
