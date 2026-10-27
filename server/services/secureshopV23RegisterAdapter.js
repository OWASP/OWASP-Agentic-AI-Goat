'use strict';

// The graph's original mcp-registry.register call reaches this adapter only
// through the trusted local-tool binding. Model arguments never contain an
// owner, run, effect key, executor instance, or registration capability.
const {randomUUID}=require('node:crypto');
const {canonicalDigest}=require('./mcp/protocolContext');
const {registryRequestDigest}=require('./secureshopMcpRegistryContract');
const {createOwnerScopedRegisterCapability}=require('./secureshopV23RegisterCapability');
const {isOwnedMcpRegistryRegistrationNotDispatched}=require('./secureshopOwnedMcpRegistryClient');
const originalRegister=require('../../agent-host/agents/mcp-registry/tools').register;

const fail=code=>Object.assign(new Error(code),{code,executionBoundary:true});
function causeContains(error,predicate){const seen=new Set();while(error&&typeof error==='object'&&!seen.has(error)){if(predicate(error))return true;seen.add(error);error=error.cause;}return false;}

function createV23RegisterAdapter({mode,scope,persona,personaSession,execution,readRegistryVersion,
 assertRunCurrent,registrationJournal,launches,ownedMcpRegistry,client}={}){
 if(!['vuln','fixed'].includes(mode)||typeof execution?.check!=='function'||typeof readRegistryVersion!=='function'
  ||typeof assertRunCurrent!=='function'||typeof registrationJournal?.prepare!=='function'
  ||typeof registrationJournal?.admitPrepared!=='function'||typeof registrationJournal?.settlePrepared!=='function'
  ||typeof launches?.admitOwnedMcpRegistration!=='function'||typeof ownedMcpRegistry?.mutate!=='function'
  ||typeof client?.registrationHealth!=='function'||typeof client?.registrationState!=='function')
  throw new TypeError('Trusted V23 registration dependencies required');
 let closing=false;const controllers=new Set(),pending=new Set(),provenance=[],obligations=new Map();
 async function assertCurrent(signal){if(closing||signal?.aborted)throw fail('V23_REGISTER_RETIRED');await assertRunCurrent();await execution.check();if(closing||signal?.aborted)throw fail('V23_REGISTER_RETIRED');}
 async function submit(original,selection,signal){
  await assertCurrent(signal);
  const expectedVersion=await readRegistryVersion();
  if(typeof expectedVersion!=='string'||!/^(0|[1-9][0-9]{0,18})$/.test(expectedVersion)
   ||BigInt(expectedVersion)>9223372036854775807n)throw fail('V23_REGISTRY_VERSION_INVALID');
  const health=await client.registrationHealth({signal});await assertCurrent(signal);
  const operationId=randomUUID(),request=Object.freeze({version:1,action:'register',operationId,expectedVersion,
   name:original.name,transport:'stdio',url:'',stdio_cmd:original.stdio_cmd});
  const requestSha256=registryRequestDigest(request),argsSha256=canonicalDigest(original);
  const envelope={version:1,scope,persona,personaSession,runId:execution.runId,
   callId:selection?.callId,step:selection?.step,tool:selection?.tool,args:original,argsSha256,
   request,requestSha256,instanceId:health.instanceId,runtimeDigest:health.runtimeDigest,mode};
  // prepare consumes the current durable effect admission, not any field in
  // the model-selected command. The pre-effect row is committed before HTTP.
  const handle=registrationJournal.prepare(envelope,execution),identity=registrationJournal.identity(handle);
  if(identity.instanceId!==health.instanceId||identity.operationId!==operationId
   ||identity.requestSha256!==requestSha256)throw fail('V23_REGISTRATION_IDENTITY_INVALID');
  const obligation={handle,identity,drained:false};obligations.set(operationId,obligation);
  provenance.push(Object.freeze({operationId,argsSha256,requestSha256,instanceId:health.instanceId,
   runId:execution.runId,callId:selection.callId,step:selection.step}));
  // A lost reply from the pre-effect identity transaction may mean its row
  // committed. Retain the obligation *before* awaiting that transaction;
  // neither a thrown admission nor shutdown may infer non-dispatch from it.
  await launches.admitOwnedMcpRegistration(handle);
  let settled=false,serviceEntered=false,serviceNoDispatch=false;
  try{
   await assertCurrent(signal);
   serviceEntered=true;
   const operation=await ownedMcpRegistry.mutate({scope,persona,personaSession,request},{signal,
    registrationIdentity:identity,expectedRegistrationMode:mode,assertRunCurrent:()=>assertCurrent(signal),
    onRegistrationNotDispatched:async()=>{
     serviceNoDispatch=true;
     const settlement=await registrationJournal.settlePrepared(handle,{notDispatched:true});
     settled=true;obligation.drained=settlement.drained===true;
    },
    onRegistrationReceipt:async receipt=>{
     if(settled)throw fail('V23_REGISTRATION_RECEIPT_REPEATED');
     const settlement=await registrationJournal.settlePrepared(handle,{receipt});
     settled=true;obligation.drained=settlement.drained===true;
    }});
   await assertCurrent(signal);
   if(!settled||operation?.state!=='completed'||operation.operationId!==operationId
    ||operation.requestSha256!==requestSha256)throw fail('V23_REGISTRATION_PUBLICATION_INVALID');
   return Object.freeze({ok:true,name:original.name,transport:'stdio',stdio_cmd:original.stdio_cmd,
    command:original.stdio_cmd,isolation:'owned-mcp-registry-v1',operationId,requestSha256,
    registryVersion:operation.registryVersion,receipt:operation});
  }catch(error){
   if(!settled){
    try{
     if(!serviceEntered||serviceNoDispatch
      ||causeContains(error,item=>isOwnedMcpRegistryRegistrationNotDispatched(item,requestSha256))){
      const settlement=await registrationJournal.settlePrepared(handle,{notDispatched:true});
      obligation.drained=settlement.drained===true;
     }
     else{
      // A missing/altered ACK is not proof that no command ran. The exact
      // instance and operation must be queried and drained; query failure
      // deliberately leaves the admitted row unresolved for reset/shutdown.
      const status=await client.registrationState(identity,{drain:true});
      const settlement=await registrationJournal.settlePrepared(handle,{status});
      obligation.drained=settlement.drained===true;
     }
    }catch{} // Preserve the original boundary failure, never invent cleanup.
   }
   throw error;
  }
 }
 async function invoke(args,selection){
  if(closing)throw fail('V23_REGISTER_RETIRED');
  const controller=new AbortController();controllers.add(controller);
  const abort=()=>controller.abort();execution.signal?.addEventListener('abort',abort,{once:true});
  if(execution.signal?.aborted)abort();
  const capability=createOwnerScopedRegisterCapability({mode,
   assertCurrent:()=>assertCurrent(controller.signal),
   dispatch:original=>submit(original,selection,controller.signal)});
  const work=originalRegister(args,capability);pending.add(work);
  try{return await work;}finally{pending.delete(work);controllers.delete(controller);
   execution.signal?.removeEventListener('abort',abort);}
 }
 return Object.freeze({invoke,readProvenance:()=>Object.freeze([...provenance]),
  async close(){closing=true;for(const controller of controllers)controller.abort();await Promise.allSettled([...pending]);
   for(const obligation of obligations.values())if(!obligation.drained){
    try{const status=await client.registrationState(obligation.identity,{drain:true});
     const settlement=await registrationJournal.settlePrepared(obligation.handle,{status});
     obligation.drained=settlement.drained===true;}catch{}
   }
   if([...obligations.values()].some(value=>!value.drained))throw fail('V23_REGISTRATION_DRAIN_REQUIRED');}});
}

module.exports={createV23RegisterAdapter};
