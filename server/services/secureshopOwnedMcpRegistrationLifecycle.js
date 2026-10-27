'use strict';
const {isDeepStrictEqual}=require('node:util');
const {createLaunchScope}=require('./secureshopConversationBinding');
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const fail=()=>Object.assign(Error('Owned registration drain required'),{code:'MCP_REGISTRATION_DRAIN_REQUIRED'});
function createOwnedMcpRegistrationLifecycle({journal,client,cleanupAuthority}={}){
 if(typeof journal?.existing!=='function'||typeof journal?.recordFence!=='function')throw TypeError('Registration journal required');
 async function drainRows(rows,{signal}={}){
  for(const row of rows){
   signal?.throwIfAborted();if(row.drained===true)continue;
   if(typeof client?.registrationHealth!=='function'||typeof client?.registrationState!=='function')throw fail();
   const health=await client.registrationHealth({signal});
   if(health.instanceId!==row.instance_id||health.runtimeDigest!==row.runtime_digest)throw fail();
   const id={instanceId:row.instance_id,operationId:row.operation_id,requestSha256:row.request_sha256};
   const state=await client.registrationState(id,{drain:true,signal});
   if(state?.version!==1||Object.entries(id).some(([k,v])=>state[k]!==v)||state.drained!==true||!['completed','retired'].includes(state.state))throw fail();
   if(typeof journal.recordDrain==='function')await journal.recordDrain(state);
  }
 }
 async function drain(scope,fenceId,kind,check,signal){
  if(!UUID.test(fenceId)||typeof check!=='function')throw fail();
  await check();const rows=await journal.existing(scope,{ownerOnly:kind==='owner_deletion'});
  await drainRows(rows,{signal});await check();
  const groups=new Map();
  for(const row of rows){
   if(!UUID.test(row.instance_id)||!UUID.test(row.operation_id))throw fail();
   const list=groups.get(row.instance_id)||[];list.push(row.operation_id);groups.set(row.instance_id,list);
  }
  for(const [instanceId,operationIds]of groups){
   signal?.throwIfAborted();await check();
   await journal.recordFence({version:1,kind,fenceId,...scope,instanceId,operationIds:operationIds.sort(),retired:true,drained:true});
  }
  await check();
 }
 async function beforeRetirement(resetId,{signal}={}){
  if(typeof cleanupAuthority?.getOperation!=='function')throw fail();
  const original=await cleanupAuthority.getOperation(resetId);
  if(original?.resetId!==resetId||!['fenced','committed','aborted'].includes(original.status))throw fail();
  const scope=createLaunchScope(original.binding);
  const check=async()=>{const current=await cleanupAuthority.getOperation(resetId);if(current?.resetId!==resetId||!['fenced','committed','aborted'].includes(current.status)||!isDeepStrictEqual(current.binding,original.binding))throw fail();};
  await drain(scope,resetId,'retirement',check,signal);
 }
 async function beforeDeletion({jobId,subjectId,check,signal}){
  if(!Number.isSafeInteger(subjectId)||subjectId<1)throw fail();
  await drain({platformOwnerId:subjectId},jobId,'owner_deletion',check,signal);
 }
 async function shutdown(){
  if(typeof journal.unsettled!=='function'||typeof journal.recordDrain!=='function')throw fail();
  await drainRows(await journal.unsettled());
  if((await journal.unsettled()).length)throw fail();
 }
 return Object.freeze({beforeRetirement,beforeDeletion,drainRows,shutdown});
}
module.exports={createOwnedMcpRegistrationLifecycle};
