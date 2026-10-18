'use strict';
const {createPool}=require('../../database/postgres');
const {createMcpProtectedReceiptRepository}=require('../../database/postgres/mcpProtectedReceiptRepository');
const {createProtectedReconciliationService}=require('./protectedReconciliationService');
function selected(env){const value=env.MCP_PROTECTED_RECOVERY_ENABLED;if(value===undefined||value===''||value==='false')return false;if(value==='true')return true;throw Error('MCP_PROTECTED_RECOVERY_ENABLED must be true or false');}
function cleanupError(error,index){return{index,name:error?.name||'Error',message:String(error?.message||error),code:error?.code};}
function attachCleanupErrors(error,cleanupErrors){if(!error||!['object','function'].includes(typeof error))return error;try{Object.defineProperty(error,'cleanupErrors',{configurable:true,enumerable:true,writable:true,value:cleanupErrors});}catch{}return error;}
async function createProtectedRecoveryProduction({env=process.env,identityAdapter,targets,poolFactory=createPool}={}){
 if(!selected(env))return null;
 const owned=[];const close=async()=>{const settled=await Promise.allSettled(owned.map((pool)=>Promise.resolve().then(()=>pool.end())));const cleanupErrors=settled.flatMap((result,index)=>result.status==='rejected'?[cleanupError(result.reason,index)]:[]);if(cleanupErrors.length){const error=Object.assign(new AggregateError(settled.filter(result=>result.status==='rejected').map(result=>result.reason),'Protected recovery cleanup failed'),{cleanupErrors});throw error;}};
 try{
  const identityLeasePool=poolFactory(env,'IDENTITY_DATABASE_URL',{purpose:'protected'});owned.push(identityLeasePool);
  const resourceLeasePool=poolFactory(env,'MCP_WORKSHOP_DATABASE_URL',{purpose:'protected'});owned.push(resourceLeasePool);
  const schema=createMcpProtectedReceiptRepository({pool:identityAdapter.pool,resolveOrigin:async()=>{throw Error('Readiness only');},withTargetAuthority:async()=>{throw Error('Readiness only');},readReceipt:async()=>{throw Error('Readiness only');}});
  const readiness=async()=>{await schema.checkReadiness();const r=await targets.readiness();if(r?.ready!==true||r.runnerReady!==true||r.isolation!=='bwrap-seccomp-v1'||!/^dvaia-mcp-sandbox(?:-[a-f0-9]{12})? \(enforce\)$/.test(r.supervisorProfile||'')||r.protectedJournalCapability!=='mcp-owned-protected-operation-journal.v1'||r.protectedReadbackCapability!=='mcp-owned-protected-readback.v1')throw Object.assign(Error('Protected recovery is unavailable'),{code:'MCP_PROTECTED_RECOVERY_UNAVAILABLE'});return{ready:true};};
  await readiness();
  const service=createProtectedReconciliationService({validateSession:t=>identityAdapter.validateSession(t),identityLeasePool,resourceLeasePool,targets});
  return Object.freeze({resourceLeasePool,readiness,close,reconcile:async(request,operationId)=>{await readiness();return service.reconcile(request,operationId);}});
 }catch(error){try{await close();}catch(cleanup){attachCleanupErrors(error,cleanup.cleanupErrors||[cleanupError(cleanup,0)]);}throw error;}
}
module.exports={attachCleanupErrors,createProtectedRecoveryProduction,selected};
