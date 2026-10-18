'use strict';
const {createHash}=require('node:crypto');
const {runCtfGuardianGraph}=require('../agent-runtime/ctfGuardianGraph');
const {requireCtfGuardianResult}=require('../agent-runtime/ctfGuardianResult');
const {runOutputDefenses,normalizedContains}=require('./ctfDefenseLayers');
function executionOwner(execution){
 let tuple;try{tuple=JSON.parse(execution?.ownerKey);}catch{throw TypeError('Owned CTF execution required');}
 if(!Array.isArray(tuple)||tuple.length!==2||tuple[0]!=='CTF'||typeof tuple[1]!=='string'||!/^([1-9][0-9]*)$/.test(tuple[1])||BigInt(tuple[1])>2147483647n||JSON.stringify(tuple)!==execution.ownerKey||execution.ownerId!==undefined&&String(execution.ownerId)!==tuple[1])throw TypeError('Owned CTF execution required');
 return tuple[1];
}
// No Judge here: createCtfDecisionService owns the canonical Judge workflow.
function createCtfProductionGuardian({model,outputModel=model,now=Date.now}={}){
 const provider=model||require('./multiProviderAIService'),reviewer=outputModel||provider;
 if(typeof provider.generateResponse!=='function'||typeof reviewer.generateResponse!=='function')throw TypeError('Configured CTF provider required');
 return async function runGuardian({stage,payload,execution,signal}){
  if(typeof execution?.check!=='function'||!execution.signal)throw TypeError('Owned CTF execution required');
  const ownerId=executionOwner(execution),captured=structuredClone(stage),input=payload;
  const owned=signal?AbortSignal.any([execution.signal,signal]):execution.signal;
  const check=async()=>{owned.throwIfAborted();await execution.check();owned.throwIfAborted();};
  const guarded={...execution,ownerId,signal:owned,check,...(typeof execution.trace==='function'?{trace:execution.trace.bind(execution)}:{})};
  let providerResult,responseTimeMs=null,reviewerObserved=false;
  const lessonReceipt=Object.freeze({observeReviewer(){reviewerObserved=true;}});
  await check();const start=now();
  const elapsed=()=>{const n=now()-start;return Number.isSafeInteger(n)&&n>=0&&n<=300000?n:null;};
  const finish=(processedResponse,guardianUnavailable)=>Object.freeze({processedResponse,providerResult:guardianUnavailable?null:providerResult,diagnostics:Object.freeze({version:1,responseTimeMs,timingScope:guardianUnavailable?'guardian_failure_elapsed':'guardian_generation',guardianUnavailable,reviewerObserved,visibleResponseSha256:createHash('sha256').update(processedResponse).digest('hex')})});
  try{
   const result=await runCtfGuardianGraph(captured,input,{execution:guarded,outputModel:reviewer,runOutputDefenses,normalizedContains,lessonReceipt,
    generate:async()=>{await check();providerResult=await provider.generateResponse(`${captured.system_prompt}\n\nUser: ${input}\nAssistant:`,{temperature:0.7,max_tokens:1000,timeout:120000,signal:owned,ownerId});await check();const valid=requireCtfGuardianResult(providerResult);responseTimeMs=elapsed();return valid.text;}});
   await check();return finish(result.processedResponse,false);
  }catch(error){
   // Reviewers may wrap cancellation; canonical execution is checked before
   // recognizing unavailable errors. Never turn revocation into a response.
   await check();
   if(!['CTF_GUARDIAN_UNAVAILABLE','CTF_DEFENSE_UNAVAILABLE'].includes(error?.code))throw error;
   responseTimeMs=elapsed();return finish('AI system temporarily unavailable. Please try again.',true);
  }
 };
}
module.exports={createCtfProductionGuardian};
