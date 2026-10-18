'use strict';
const C=require('./secureshopOwnedMcpInvocationContract');
const {isOwnedMcpRegistryNotDispatched}=require('./secureshopOwnedMcpRegistryClient');
const P=require('../../sidecars/sandbox-runner/owned-mcp-registry/invoke-protocol');
const {currentEffectAdmission}=require('../agent-runtime/effectAdmissionContext');
const fail=()=>Object.assign(Error('Registered invocation requires recovery'),{code:'MCP_INVOCATION_OUTCOME_UNCERTAIN',automaticRetry:false,executionBoundary:true});
function createRegistryInvocationBridge({journal,launches,client,executorIdentity,personaSession,policy}={}){
 if(!['prepare','identity','settlePrepared','settleNotDispatched'].every(k=>typeof journal?.[k]==='function')
  ||typeof launches?.admitOwnedMcpInvocation!=='function'||typeof client?.invoke!=='function'
  ||typeof client?.invocationState!=='function'||!policy||typeof policy!=='object')throw TypeError('Registry invocation bridge dependencies required');
 const identity=C.freeze(C.bounded(executorIdentity,1024)),session=C.freeze(C.bounded(personaSession,1024));
 if(identity.version!==1||! /^[a-f0-9]{64}$/.test(identity.runtimeDigest||''))throw TypeError('Verified executor identity required');
 const policySha256=C.digest(C.bounded(policy,16384));
 async function dispatch(packet){
  const q=C.freeze(P.request(packet.request)),effect=currentEffectAdmission(packet.execution);
  if(q.instanceId!==identity.instanceId||effect.ledgerEffectKey!==packet.effect?.ledgerEffectKey
   ||typeof packet.snapshots?.withCurrentEntry!=='function')throw fail();
  const snapshot=C.snapshot({binding:packet.binding,entryId:q.entry.entryId,registryVersion:q.entry.registryVersion,
   schemaSha256:q.entry.schemaSha256,tools:q.entry.tools});
  const request=C.request({snapshot,runId:packet.execution.runId,requestId:packet.requestId,callId:packet.callId,
   toolIndex:snapshot.tools.findIndex(t=>t.name===q.toolName),args:q.args,mode:packet.mode});
  const prepared=journal.prepare({invocationId:q.operationId,snapshot,request,requestSha256:C.digest(request),
   managerInstanceId:identity.instanceId,runtimeSha256:identity.runtimeDigest,policySha256,personaSession:session,
   executorMapping:{version:1,request:q,requestSha256:P.digest(q),instanceId:identity.instanceId,runtimeSha256:identity.runtimeDigest}},packet.execution);
  let receipt,clientEntered=false,clientFailure;
  try{
  const grant=await launches.admitOwnedMcpInvocation(prepared);
  if(grant?.invocationId!==q.operationId||grant.requestSha256!==C.digest(request)
   ||grant.managerInstanceId!==identity.instanceId||grant.state!=='admitted')throw fail();
  // Identity/agents admission has committed before entering the held entry lock.
  // Settle only after that lock releases, avoiding recursive persona acquisition.

   await packet.execution.check();
   receipt=await packet.snapshots.withCurrentEntry(packet.entry,async()=>{clientEntered=true;try{return await client.invoke(q,{signal:packet.execution.signal});}catch(error){clientFailure=error;throw error;}});
   receipt=P.receipt(receipt,q);
  }catch(cause){
   if(!clientEntered||isOwnedMcpRegistryNotDispatched(clientFailure,q)){
    try{await journal.settleNotDispatched(prepared);}catch(settlementError){throw Object.assign(fail(),{cause,settlementError});}
    throw cause;
   }
   let status={version:1,...journal.identity(prepared),state:'unknown',drained:false};
   try{status=await client.invocationState(journal.identity(prepared),{drain:true});}catch{}
   try{await journal.settlePrepared(prepared,{status});}catch{}
   throw Object.assign(fail(),{cause});
  }
  await journal.settlePrepared(prepared,{receipt});
  await packet.execution.check();
  return C.freeze(receipt);
 }
 return Object.freeze({dispatch});
}

// Adapter for the existing lifecycle. There is deliberately no invoke/replay
// operation here. A restarted executor's unknown response cannot clear a fence.
function createRegistryInvocationRetirer({journal,client}={}){
 if(typeof journal?.mappings!=='function'||typeof client?.invocationState!=='function'
  ||typeof client?.invocationHealth!=='function')throw TypeError('Registry drain dependencies required');
 async function retire(raw,{signal}={}){
  const request=C.freeze(C.bounded(raw,65536));
  if(request.version!=='owned-mcp-invocation-fence-v1'||!['retirement','owner_deletion'].includes(request.kind)
   ||!Array.isArray(request.invocationIds))throw fail();
  const scope=request.kind==='owner_deletion'?{platformOwnerId:request.platformOwnerId}:
   require('./secureshopConversationBinding').createLaunchScope(request);
  const rows=(await journal.mappings(scope,{ownerOnly:request.kind==='owner_deletion'}))
   .filter(row=>row.manager_instance_id===request.managerInstanceId);
  if(C.digest(rows.map(row=>row.invocation_id).sort())!==C.digest(request.invocationIds)
   ||rows.some(row=>row.runtime_sha256!==request.runtimeSha256))throw fail();
  for(const row of rows){
   signal?.throwIfAborted();
   if(row.drained===true)continue;
   const m=row.mapping,ready=await client.invocationHealth({signal});
   if(!m||ready.instanceId!==m.instanceId||ready.runtimeDigest!==m.runtimeSha256)throw fail();
   const q={instanceId:m.instanceId,operationId:row.invocation_id,requestSha256:m.requestSha256};
   const status=await client.invocationState(q,{drain:true,signal});
   if(status?.version!==1||Object.entries(q).some(([key,value])=>status[key]!==value)
    ||status.drained!==true||!['completed','retired'].includes(status.state))throw fail();
  }
  return C.freeze({...request,retired:true,drained:true});
 }
 return Object.freeze({retire});
}
module.exports={createRegistryInvocationBridge,createRegistryInvocationRetirer};
