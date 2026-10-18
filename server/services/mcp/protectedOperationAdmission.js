'use strict';
// Explicit candidate composition only. This module admits effects; it does not
// reconcile historical runs, reconstruct model witnesses, or grant credit.
const protocol=require('./protocolContext');
const {currentEffectAdmission}=require('../../agent-runtime/effectAdmissionContext');
const {originFor}=require('./protectedDecisionAdmission');
const {createMcpProtectedReceiptRepository}=require('../../database/postgres/mcpProtectedReceiptRepository');
const {createMcpResourceRepository}=require('../../database/postgres/mcpResourceRepository');
function createProtectedOperationAdmission({identityPool,resourceLeasePool}={}){
 if(!identityPool||!resourceLeasePool||identityPool===resourceLeasePool
  ||!Number.isInteger(resourceLeasePool.options?.max)||resourceLeasePool.options.max<1||resourceLeasePool.options.max>4
  ||!(resourceLeasePool.options.connectionTimeoutMillis>0&&resourceLeasePool.options.connectionTimeoutMillis<=5000))throw TypeError('Dedicated bounded protected resource lease pool required');
 const leases=createMcpResourceRepository(resourceLeasePool);
 return Object.freeze({
  forExecution(scope,boundExecution){
   return async(request,execution,perform)=>{
    const invocation=protocol.requireProtocolContext(`mcp_${scope.platformOwnerId}`);
    if(execution!==invocation.execution||Object.keys(scope).filter(k=>['targetId','platformOwnerId','platformSessionId','generation'].includes(k)).some(k=>scope[k]!==request.binding[k]))throw Error('Protected admission scope mismatch');
    const effect=currentEffectAdmission(execution);
    const origin=originFor(invocation);
    const check=async()=>{await boundExecution.check();await execution.check();};
    const repository=createMcpProtectedReceiptRepository({pool:identityPool,
      resolveOrigin:async()=>origin,
      withTargetAuthority:async(binding,work)=>{
       if(protocol.canonicalDigest(binding)!==protocol.canonicalDigest(request.binding))throw Error('Protected admission scope mismatch');
       await check();
       const active=await leases.readActiveRunnerTarget(binding);
       if(!active||protocol.canonicalDigest(active)!==protocol.canonicalDigest(binding))throw Error('Protected target is not current');
       const value=await work();await check();return value;
      },readReceipt:async()=>{throw Error('Recovery is not mounted');}});
     await repository.checkReadiness();
     await repository.begin({request,execution,ledgerEffectKey:effect.ledgerEffectKey,sdkEffectKey:invocation.effectKey});
     // Acquire the resource row only after central admission releases its
     // identity/owner row locks. Retirement cannot invert that lock order.
     return leases.withActiveRunnerTarget(scope,check,async()=>{
     await check();
     // SQL commit precedes dispatch. Transport failure does not roll back the
     // intent, and the ledger records uncertainty; no automatic network replay.
     return perform();
    });
   };
  }
 });
}
module.exports={createProtectedOperationAdmission};
