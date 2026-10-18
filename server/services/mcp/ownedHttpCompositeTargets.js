'use strict';
const crypto=require('node:crypto');const {createOwnedHttpClient}=require('./ownedHttpClient');
const {createOwnedHttpToolAdapter}=require('./ownedHttpToolAdapter');
const {verifyHttpCleanupReceipt}=require('../../database/postgres/mcpHttpLeaseRepository');
function operationId(target){const h=crypto.createHash('sha256').update('mcp-http-retire:'+target).digest('hex');return `${h.slice(0,8)}-${h.slice(8,12)}-5${h.slice(13,16)}-8${h.slice(17,20)}-${h.slice(20,32)}`;}
const {HTTP_CAPABILITY,MANIFEST_SHA256}=require('./ownedHttpCapability');
const fail=()=>{throw Object.assign(Error('HTTP_CHILD_CLEANUP_REQUIRED'),{code:'HTTP_CHILD_CLEANUP_REQUIRED'});};
function createOwnedHttpCompositeTargets({cli,http=null,leases,receiptRepository,readMode,enabled=false}={}){
 if(!cli||!leases||typeof leases.read!=='function'||typeof cli.admit!=='function'||typeof cli.retire!=='function')throw TypeError('CLI and durable HTTP lease dependencies required');
 async function cleanup(scope){const row=await leases.read(scope);if(!row)return;
  const value={...scope,operationId:operationId(scope.targetId)};const prior=await leases.beginRetirement(value);if(prior)return;
  if(!http)fail();await http.retire(value);const receipt=verifyHttpCleanupReceipt(await http.readRetirement(value),value);await leases.completeRetirement(value,receipt);
 }
 return Object.freeze({
  ...(typeof cli.readProtectedOperationReceipt==='function'?{readProtectedOperationReceipt:input=>cli.readProtectedOperationReceipt(input)}:{}),
  async readiness(){const base=await cli.readiness();if(enabled){if(!http||!receiptRepository||typeof readMode!=='function')fail();await leases.checkReadiness();await receiptRepository.checkReadiness();const status=await http.readiness();if(status?.ready!==true||status.manifestSha256!==MANIFEST_SHA256)fail();return {...base,httpCapability:HTTP_CAPABILITY};}return base;},
  async admit({scope,execution,withProtectedOperation}){
   const admitted=await cli.admit({scope,execution,withProtectedOperation});if(!enabled)return admitted;
   if(!http||!receiptRepository)fail();await execution.check();await leases.reserve(scope);await execution.check();
   const owned=await http.admit(scope);if(!owned||owned.scope?.targetId!==scope.targetId||owned.scope?.platformOwnerId!==scope.platformOwnerId||owned.scope?.platformSessionId!==scope.platformSessionId||owned.scope?.generation!==scope.generation)fail();
   await execution.check();await leases.activate(scope);
   const client=createOwnedHttpClient({request:http.request,scope,capability:owned.capability,readMode,receiptRepository});
   const adapter=createOwnedHttpToolAdapter({client});
   return {...admitted,runner:Object.freeze({...admitted.runner,fetchOwnedUrl:adapter.fetch})};
  },
  async retire({scope,operationId:parentOperation}){await cleanup(scope);return cli.retire({scope,operationId:parentOperation});},
  async readRetirement({scope,operationId:parentOperation}){await leases.assertRetired(scope);return cli.readRetirement({scope,operationId:parentOperation});},
 });
}
module.exports={createOwnedHttpCompositeTargets};
