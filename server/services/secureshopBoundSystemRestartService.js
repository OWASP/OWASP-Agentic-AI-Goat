'use strict';
const {normalizeRestartRequest,restartRequestDigest}=require('./secureshopSystemRestartContract');
const {validateRestartReceipt}=require('../../sidecars/sandbox-runner/owned-system/restart-wire');
const {isSystemRestartOutcomeUncertain,CAPABILITY}=require('./secureshopSystemRestartClient');
const {captureFeatureMode}=require('./secureshopFeatureModeAuthority');
const fail=code=>Object.assign(new Error('Bound System restart unavailable'),{code});
function createBoundSystemRestartService({repository,client,resolveTarget,modeAuthority}={}){
 if(['ensureTarget','begin','assertCurrent','complete','fail','operation'].some(k=>typeof repository?.[k]!=='function')
  ||typeof client?.health!=='function'||typeof client?.inspect!=='function'||typeof client?.execute!=='function'||typeof resolveTarget!=='function'
  ||typeof modeAuthority?.capture!=='function'||typeof modeAuthority?.assertToken!=='function')throw new TypeError('Bound restart dependencies and mode authority required');
 const busyTargets=new Set();
 async function capture(input){const token=await captureFeatureMode(modeAuthority,input.scope,'system_restart');await token.assertCurrent();return token;}
 function allowed(token,name){
  if(token.snapshot.mode==='fixed'&&!/^[A-Za-z0-9_][A-Za-z0-9_.@-]{0,127}$/.test(name))throw fail('SYSTEM_RESTART_FIXED_DENIED');
 }
 return Object.freeze({
  async administration(raw,{signal}={}){
   signal?.throwIfAborted();const input=structuredClone(raw),token=await capture(input),target=await resolveTarget(input,{signal});
   await token.assertCurrent();await client.health({signal});await token.assertCurrent();
   const state=await client.inspect(target.targetId,{signal});await token.assertCurrent();
   await repository.ensureTarget({...input,operationId:'00000000-0000-4000-8000-000000000001'},
    {targetId:target.targetId,instanceId:state.instanceId,generation:state.generation,binding:target.binding});
   await token.assertCurrent();return Object.freeze({restartCapability:CAPABILITY,targetId:target.targetId});
  },
  async execute(raw,{signal,beforeEffect}={}){
   if(beforeEffect!==undefined&&typeof beforeEffect!=='function')throw new TypeError('Trusted restart authority check required');
   signal?.throwIfAborted();const input=structuredClone(raw),request=normalizeRestartRequest({version:1,operationId:input.operationId,name:input.name}),token=await capture(input);
   const current=async()=>{signal?.throwIfAborted();await token.assertCurrent();allowed(token,request.name);signal?.throwIfAborted();};
   // Shared by direct form and protected chat confirmation: reject before allocation/admission.
   await current();
   const target=await resolveTarget(input,{signal});await current();
   if(busyTargets.has(target.targetId))throw fail('SYSTEM_RESTART_BUSY');busyTargets.add(target.targetId);
   let admitted,remoteFinished=false;
   try{
    await client.health({signal});await current();const state=await client.inspect(target.targetId,{signal});await current();
    await repository.ensureTarget(input,{targetId:target.targetId,instanceId:state.instanceId,generation:state.generation,binding:target.binding});await current();
    admitted=await repository.begin(input,{targetId:target.targetId,binding:target.binding});await current();
    if(admitted.state!=='running')return admitted;
    const remote=await client.execute({targetId:target.targetId,request},{signal,assertCurrent:async()=>{
     await current();await repository.assertCurrent(input,target.targetId,admitted.workerToken,target.binding);
     await beforeEffect?.();await current();
    }});
    remoteFinished=true;await current();
    const receipt=validateRestartReceipt({targetId:target.targetId,request},remote);
    const completed=await repository.complete(input,{targetId:target.targetId,workerToken:admitted.workerToken,receipt,binding:target.binding});
    await current();return completed;
   }catch(error){
    if(admitted?.state==='running'){
     const code=remoteFinished||isSystemRestartOutcomeUncertain(error)?'OUTCOME_UNCERTAIN':signal?.aborted?'ABORTED':'EXECUTION_FAILED';
     try{await repository.fail(input,{workerToken:admitted.workerToken,code,binding:target.binding});}catch{}
     if(code==='OUTCOME_UNCERTAIN'){const e=fail('SYSTEM_RESTART_OUTCOME_UNCERTAIN');e.automaticRetry=false;e.outcome='unknown';throw e;}
    }
    throw error;
   }finally{busyTargets.delete(target.targetId);}
  },
  operation:async raw=>{const input=structuredClone(raw),token=await capture(input),target=await resolveTarget(input);await token.assertCurrent();
   const result=await repository.operation(input,target.binding);await token.assertCurrent();return result;},
  async readEvidenceReceipt(raw){
   if(typeof repository.readEvidenceReceipt!=='function')throw fail('SYSTEM_RESTART_EVIDENCE_UNAVAILABLE');
   const input=structuredClone(raw),token=await capture(input),target=await resolveTarget(input);await token.assertCurrent();
   const result=await repository.readEvidenceReceipt(input,target.binding);await token.assertCurrent();return result;
  },
  requestDigest:raw=>restartRequestDigest(raw),
 });
}
module.exports={createBoundSystemRestartService};
