'use strict';
// Unmounted. No model, claim/outcome writer, coordinator or decision evaluator dependency.
const {validateCtfPredefenseRecoveryState:validateState}=require('../database/postgres/ctfPredefenseRecoveryRepository');
const uncertain=e=>e?.code==='CTF_TRANSACTION_UNCERTAIN'||/^08[A-Z0-9]{3}$/.test(e?.code||'')||['ECONNRESET','EPIPE','ETIMEDOUT','57P01','57P02','57P03'].includes(e?.code);
// Service union: repository seven-key current state OR this four-key non-credit
// pending envelope. Pending is not a publication and contains no guessed refs.
function validateCtfPredefenseRecoveryResult(value,runId){
 if(value?.state!=='recovery_pending')return validateState(value,runId);
 if(Object.keys(value).sort().join(',')!=='currentCompletion,runId,state,version'||value.version!==1||value.runId!==runId||!/^([a-f0-9]{8}-)([a-f0-9]{4}-){3}[a-f0-9]{12}$/.test(runId)||value.currentCompletion!==false)throw TypeError('Invalid CTF recovery pending envelope');
 return Object.freeze({...value});
}
function createCtfPredefenseRecoveryService(dependencies,{maxSteps=6,timeoutMs=5000}={}){
 if(!dependencies||Object.keys(dependencies).some(k=>!['repository','worker'].includes(k)))throw TypeError('Closed recovery dependencies required');
 const {repository,worker}=dependencies;
 for(const name of ['read','consume','enqueueBlocked'])if(typeof repository?.[name]!=='function')throw TypeError('Canonical recovery repository required');
 if(typeof worker?.pump!=='function'||!Number.isInteger(maxSteps)||maxSteps<1||maxSteps>8||!Number.isInteger(timeoutMs)||timeoutMs<1||timeoutMs>10000)throw TypeError('Bounded recovery worker required');
 const read=repository.read.bind(repository),consume=repository.consume.bind(repository),enqueue=repository.enqueueBlocked.bind(repository),pump=worker.pump.bind(worker);
 const snapshot=input=>{if(!input||Object.keys(input).some(k=>!['runId','session'].includes(k)))throw TypeError('Closed CTF recovery request required');return structuredClone(input);};
 return Object.freeze({read(input,options){const bound=snapshot(input);return read(bound,options).then(value=>validateState(value,bound.runId));},async resume(input,{signal}={}){
  const bound=snapshot(input),controller=new AbortController(),abort=()=>controller.abort(signal?.reason);
  if(signal?.aborted)signal.throwIfAborted();signal?.addEventListener('abort',abort,{once:true});
  const timer=setTimeout(()=>controller.abort(),timeoutMs),pending=()=>validateCtfPredefenseRecoveryResult({version:1,state:'recovery_pending',runId:bound.runId,currentCompletion:false},bound.runId);
  let abortListener;
  const cancelled=new Promise((_,reject)=>{abortListener=()=>reject(Object.assign(Error('CTF recovery interrupted'),{name:'AbortError'}));controller.signal.addEventListener('abort',abortListener,{once:true});});
  const work=async()=>{
   for(let step=0;step<maxSteps;step++){
    controller.signal.throwIfAborted();
    const value=validateState(await read(bound,{signal:controller.signal}),bound.runId);controller.signal.throwIfAborted();
    if(value.state==='outcome_stored')await consume(bound,{signal:controller.signal});
    else if(value.state==='blocked_ready_to_enqueue')await enqueue(bound,{signal:controller.signal});
    else if(['admission_pending','blocked_pending'].includes(value.state))await pump({maxEvents:1,signal:controller.signal});
    else return value; // Missing outcome, running, continue, or historical reference never starts inference.
   }
   return pending();
  };
  try{return await Promise.race([work(),cancelled]);}catch(error){if(signal?.aborted)throw error;if(controller.signal.aborted||uncertain(error))return pending();throw error;}
  finally{clearTimeout(timer);signal?.removeEventListener('abort',abort);controller.signal.removeEventListener('abort',abortListener);}
 }});
}
module.exports={createCtfPredefenseRecoveryService,validateCtfPredefenseRecoveryResult};
