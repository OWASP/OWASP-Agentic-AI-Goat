'use strict';
const fs=require('node:fs/promises'),crypto=require('node:crypto'),assert=require('node:assert/strict'),path=require('node:path');
async function main(){
 const {createMcpTargetStore}=require('/app/mcpTargets');
 const {createOwnedHttpExecutor}=require('/app/owned-http/executor');
 const {createOwnedHttpOperationStore}=require('/app/owned-http/operationStore');
 const root=await fs.mkdtemp('/tmp/owned-http-packaged-');
 const expectedProfile=process.env.MCP_OWNED_TARGET_APPARMOR_PROFILE;
 const targetStore=createMcpTargetStore({root,fixtureRoot:'/opt/lab-template'});
 const executor=createOwnedHttpExecutor({expectedProfile});
 const operations=createOwnedHttpOperationStore({targetStore,executor:executor.execute,checkReadiness:executor.checkReadiness});
 const binding={targetId:crypto.randomUUID(),ownerId:1,platformSessionId:1,generation:1};const allow=async()=>true;
 try{
  await targetStore.checkReadiness();const baselineChildren=(await fs.readFile(`/proc/self/task/${process.pid}/children`,'utf8')).trim();const readiness=await executor.checkReadiness();
  const owned=await targetStore.provisionTarget(binding,{authorize:allow});
  const request={url:'http://169.254.169.254/latest/meta-data/?raw=%2f',mode:'vuln',runId:crypto.randomUUID(),operationId:crypto.randomUUID(),invocationId:crypto.randomUUID(),mcpSessionId:'mcp_1'};
  const receipt=await operations.execute(owned.capability,allow,request);assert.equal(receipt.result.status,'completed');assert.equal(receipt.result.hits[0].path,'/latest/meta-data/?raw=%2f');
  assert.deepEqual(await operations.execute(owned.capability,allow,request),receipt);
  const journal=path.join(root,'targets',binding.targetId,'http-operations',request.operationId+'.json');assert.ok((await fs.stat(journal)).isFile());
  const beforeChildren=(await fs.readFile(`/proc/self/task/${process.pid}/children`,'utf8')).trim();
  assert.equal(beforeChildren,baselineChildren);
  const cancellation=createOwnedHttpExecutor({expectedProfile,timeoutMs:1});
  await assert.rejects(cancellation.execute({input:{url:'http://benign.training/',mode:'vuln',canary:'a'.repeat(64)}}),{code:'HTTP_EXECUTION_TIMEOUT'});
  const aborted=new AbortController();aborted.abort();
  await assert.rejects(executor.execute({input:{url:'http://benign.training/',mode:'vuln',canary:'a'.repeat(64)},signal:aborted.signal}),{code:'HTTP_OPERATION_ABORTED'});
  const workerPath='/usr/local/libexec/dvaia-owned-http-worker.js';
  const workerBefore=await fs.readFile(workerPath);
  // Read-only mounts may deny the write before the file permission check.
  await assert.rejects(fs.writeFile(workerPath,'untrusted'),error=>['EACCES','EROFS'].includes(error.code));
  assert.deepEqual(await fs.readFile(workerPath),workerBefore);
  const children=(await fs.readFile(`/proc/self/task/${process.pid}/children`,'utf8')).trim();assert.equal(children,beforeChildren);
  const retired=await targetStore.retireTarget(binding,{operationId:crypto.randomUUID(),authorize:allow});assert.equal(retired.status,'completed');
  await assert.rejects(fs.lstat(path.dirname(path.dirname(journal))),{code:'ENOENT'});
  await assert.rejects(operations.execute(owned.capability,allow,request),{code:'TARGET_RETIRED'});
  return {productionQualified:false,readiness,receipt,exactReplay:true,timeoutJoined:true,preabortedRejected:true,immutableWorkerWriteDenied:true,noHttpChildrenAdded:true,baselineChildren,canonicalRetirementRemovedJournal:true,retiredReplayRejected:true};
 }finally{await fs.rm(root,{recursive:true,force:true});}
}
if(require.main===module)main().then(value=>console.log(JSON.stringify(value))).catch(error=>{console.error(error.stack, error.cause);process.exitCode=1;});
module.exports={main};
