'use strict';
// Source-reviewed public entry. Every invocation still requires the exact
// source/plan binding and produces its own live, non-serializable capability.
const fs=require('node:fs/promises'),native=require('node:fs'),crypto=require('node:crypto');
const adapter=require('./ownedSystemConfigBuildAdapter');
const {createOwnedSystemDriver}=require('./ownedSystemConfigPhaseDriver');
const consumer=require('./ownedSystemPrivateHttpConsumer');
const LIVE_ENABLED=true,owners=new WeakMap();
// Reviewed paired composition still requires exact original-browser/MAIN,
// source and fresh plan admission. Image receipts cannot supply authority.
const PAIRED_LIVE_ENABLED=true,pairedOwners=new WeakMap();
const pairedRuntimeOwners=new WeakMap();
const PHASES=Object.freeze(['inventory','preflight','prepare','namespace','relayStart','daemonStart','inspect',
 'metadataFetch','startArtifacts','closureEvidence','inspect','build','image','retireArtifacts','closureEvidence','inspect','handoff']);
const fail=code=>Object.assign(Error(code),{code});
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const exact=(v,names)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(',')===names.split(',').sort().join(',');
function retiredQualificationFailure(error){
 const r=error?.receipt;
 return adapter._internals.isPairRelayQualificationFailure(error)&&error.retirementUnproven===false
  &&exact(r,'localCleanupVerified,remoteCleanupVerified,guestResourcesAbsent,sharedStateUnchanged,debts')
  &&r.localCleanupVerified===true&&r.remoteCleanupVerified===true&&r.guestResourcesAbsent===true
  &&r.sharedStateUnchanged===true&&Array.isArray(r.debts)&&r.debts.length===0;
}
async function checkSelf(expected){
 if(typeof expected!=='string'||!/^[a-f0-9]{64}$/.test(expected)||await fs.realpath(__filename)!==__filename)throw fail('SYSTEM_PRODUCER_SOURCE');
 const fd=await fs.open(__filename,native.constants.O_RDONLY|native.constants.O_NOFOLLOW);
 try{const s=await fd.stat();if(!s.isFile()||s.nlink!==1||s.size>131072)throw fail('SYSTEM_PRODUCER_SOURCE');
  const bytes=await fd.readFile(),after=await fd.stat();
  if(after.size!==s.size||after.mtimeMs!==s.mtimeMs||after.ctimeMs!==s.ctimeMs||sha(bytes)!==expected)throw fail('SYSTEM_PRODUCER_SOURCE');
 }finally{await fd.close();}
}
function assertSystemImageCapability(capability){
 const row=capability&&owners.get(capability);
 if(!row||row.revoked)throw fail('SYSTEM_IMAGE_NOT_LIVE');
 row.proxy.assertActive();return row.proxy;
}
function assertPairedRuntimeCapability(capability){
 const row=capability&&pairedRuntimeOwners.get(capability);
 if(!row||row.revoked)throw fail('SYSTEM_PAIR_RUNTIME_NOT_LIVE');row.proxy.assertActive();return row.proxy;
}
async function within(work,end){
 const observed=Promise.resolve(work);void observed.catch(()=>{});
 const left=end-performance.now();if(!(left>0))throw fail('SYSTEM_PRODUCER_DEADLINE');
 let timer;try{return await Promise.race([observed,new Promise((_,reject)=>{timer=setTimeout(()=>reject(fail('SYSTEM_PRODUCER_DEADLINE')),left);})]);}
 finally{clearTimeout(timer);}
}
async function settled(work,end){
 if(!work)return true;
 try{await within(work.then(()=>{},()=>{}),end);return true;}catch{return false;}
}
// This implementation has no caller-supplied driver, runner, commands, source,
// image, proof or environment. Controlled tests replace module dependencies in
// a VM; no test-supplied driver is accepted by the public entry.
async function runProducer(options,callback,mode='system'){
 if(!['system','pair'].includes(mode))throw fail('SYSTEM_PRODUCER_MODE');
 const pair=mode==='pair';
 if(!exact(options,'root,runId,recipe,signal,buildDeadline,expectedPlanSha256,expectedProducerSha256,expectedDriverSha256,expectedPythonSha256')
  ||typeof callback!=='function'||!(options.signal instanceof AbortSignal)||!Number.isFinite(options.buildDeadline)
  ||options.buildDeadline<=performance.now()||options.buildDeadline-performance.now()>1800000)throw fail('SYSTEM_PRODUCER_OPTIONS');
 options.signal.throwIfAborted();await checkSelf(options.expectedProducerSha256);
 const plan=await (pair?adapter.systemPolicyBuildPlan:adapter.systemBuildPlan)(options.root,options.runId,options.recipe);
 if(adapter.planDigest(plan)!==options.expectedPlanSha256)throw fail('SYSTEM_PRODUCER_PLAN');
 await adapter.verifyPlan(plan);options.signal.throwIfAborted();
 const controller=new AbortController();
 const abort=()=>controller.abort(options.signal.reason||fail('SYSTEM_PRODUCER_INTERRUPTED'));
 options.signal.addEventListener('abort',abort,{once:true});if(options.signal.aborted)abort();
 let driver,owner,entry,capability,result,primary,driverReceipt,consumerWork,consumerFailure,callbackWork,callbackCalled=false,runtimeAttempted=false;
 let cleanupEnd=null,cohortTimer,interruptionReject,buildTimer,retirementClosed=false;
 const attemptedSlots=new Set(),confirmedSlots=new Set();
 const interrupted=new Promise((_,reject)=>{interruptionReject=reject;});void interrupted.catch(()=>{});
 const interruptedListener=()=>interruptionReject(controller.signal.reason||fail('SYSTEM_PRODUCER_INTERRUPTED'));
 controller.signal.addEventListener('abort',interruptedListener,{once:true});
 const debt=[],qualificationErrors=[],activeWork=new Set(),retirementWork=new Map();
 const trackActive=work=>{const p=Promise.resolve(work);activeWork.add(p);void p.then(()=>activeWork.delete(p),()=>activeWork.delete(p));return p;};
 const beginRetirement=()=>{
  if(retirementClosed)throw fail('SYSTEM_PRODUCER_RETIREMENT_CLOSED');
  const end=owner.beginRetirement(),now=performance.now();
  if(!Number.isFinite(end)||end<=now||cleanupEnd===null&&end-now>600000||cleanupEnd!==null&&end!==cleanupEnd)throw fail('SYSTEM_PRODUCER_CLEANUP_DEADLINE');
  cleanupEnd=end;return end;
 };
 try{
  controller.signal.throwIfAborted();
  if(pair)buildTimer=setTimeout(()=>controller.abort(fail('SYSTEM_PRODUCER_DEADLINE')),Math.max(0,options.buildDeadline-performance.now()));
  driver=await createOwnedSystemDriver({plan,signal:controller.signal,deadline:options.buildDeadline,
   expectedPlanSha256:options.expectedPlanSha256,expectedDriverSha256:options.expectedDriverSha256,expectedPythonSha256:options.expectedPythonSha256});
  for(const phase of pair?adapter._internals.PAIR_PHASES:PHASES){controller.signal.throwIfAborted();await driver.run(phase);}
  owner=await (pair?driver.claimPairedRuntime():driver.claimRuntime());
  clearTimeout(buildTimer);controller.signal.throwIfAborted();
  entry={revoked:false,retired:false,proxy:null};
  const active=()=>{if(entry.revoked)throw fail('SYSTEM_IMAGE_REVOKED');controller.signal.throwIfAborted();owner.assertActive();};
  const effect=(name,slot)=>(...args)=>{active();if(name==='startRuntime'){runtimeAttempted=true;if(pair)attemptedSlots.add(slot);}
   return trackActive((pair?owner.slots[slot]:owner)[name](...args));};
  const retire=(name,slot)=>(...args)=>{
   if(args.length)throw fail('SYSTEM_PRODUCER_CLEANUP_ARGUMENTS');beginRetirement();
   const key=pair?slot+':'+name:name;
   if(!retirementWork.has(key)){
    const work=Promise.resolve().then(()=>{beginRetirement();return (pair?owner.slots[slot]:owner)[name]();}).then(value=>{
     beginRetirement();if(name==='confirmRetired'){
      if(value!==true)throw fail('SYSTEM_PRODUCER_RETIREMENT');
      if(pair){confirmedSlots.add(slot);entry.retired=[...attemptedSlots].every(s=>confirmedSlots.has(s));}else entry.retired=true;
     }return value;
    });
    // Cache rejection as well as success: fallback cannot retry a mutation or
    // duplicate a cleanup phase already owned by the consumer.
    retirementWork.set(key,work);void work.catch(()=>{});
   }
   return retirementWork.get(key);
  };
  const slotProxy=slot=>Object.freeze({binding:(pair?owner.slots[slot]:owner).binding,assertActive:active,beginRetirement,
   startRuntime:effect('startRuntime',slot),inspectRuntime:effect('inspectRuntime',slot),openBridge:effect('openBridge',slot),
   closeBridge:retire('closeBridge',slot),stopRuntime:retire('stopRuntime',slot),confirmRetired:retire('confirmRetired',slot)});
  entry.proxy=pair?Object.freeze({binding:owner.binding,assertActive:active,beginRetirement,
   slots:Object.freeze({system:slotProxy('system'),policy:slotProxy('policy')})}):slotProxy('system');
  capability=Object.freeze({});(pair?pairedRuntimeOwners:owners).set(capability,entry);
  const cohortEnd=performance.now()+900000;
  cohortTimer=setTimeout(()=>controller.abort(fail('SYSTEM_PRODUCER_COHORT_DEADLINE')),Math.max(0,cohortEnd-performance.now()));
  const wrapped=(...args)=>{
   active();if(callbackCalled)throw fail('SYSTEM_PRODUCER_CALLBACK_REPLAY');callbackCalled=true;
   callbackWork=trackActive(Promise.resolve().then(()=>{active();return callback(...args);}));return callbackWork;
  };
  consumerWork=Promise.resolve().then(()=>{active();return (pair?consumer.withSystemAndPolicyPrivateHttp:consumer.withSystemPrivateHttp)(capability,{signal:controller.signal,deadline:cohortEnd},wrapped);});
  void consumerWork.catch(()=>{});
  result=await Promise.race([consumerWork,interrupted]);
  if(!callbackCalled)throw fail('SYSTEM_PRODUCER_NO_CALLBACK');
  await adapter.verifyPlan(plan);await checkSelf(options.expectedProducerSha256);
 }catch(e){primary=e;}
 finally{
  clearTimeout(cohortTimer);clearTimeout(buildTimer);
  // Revoke cached owner operations as well as the WeakMap lookup. Cleanup
  // methods remain usable only to settle this producer's actual live owner.
  if(entry)entry.revoked=true;if(capability)(pair?pairedRuntimeOwners:owners).delete(capability);
  if(owner){
   try{
    beginRetirement();
    const joinEnd=Math.min(cleanupEnd,performance.now()+5000);
    // Only actual application/actor operations have the short quiescence
    // bound. consumerWork includes legitimate channel/runtime retirement.
    const outstanding=Promise.allSettled([callbackWork,...activeWork].filter(Boolean));
    if(!await settled(outstanding,joinEnd))throw fail('SYSTEM_PRODUCER_CALLBACK_UNSETTLED');
    beginRetirement();
    if(consumerWork){
     const outcome=await within(consumerWork.then(value=>({value}),error=>({error})),cleanupEnd);
     if('error' in outcome){consumerFailure=outcome.error;primary ||= consumerFailure;}
     beginRetirement();
    }
    // A consumer's unresolved-retirement conclusion is not erased by fallback.
    if(consumerFailure?.retirementUnproven&&!entry.retired)throw consumerFailure;
    // The consumer has now settled. Reuse its exact phase promises, including
    // failures, and only perform phases it never started. No parallel cleanup.
    // Refusal before our start invocation owns no runtime/container obligation.
    // The builder still retires under the same deadline and actual driver proof.
    if(runtimeAttempted)for(const name of ['closeBridge','stopRuntime','confirmRetired']){
     for(const slot of pair?attemptedSlots:['system']){
      beginRetirement();await within((pair?entry.proxy.slots[slot]:entry.proxy)[name](),cleanupEnd);beginRetirement();
     }}
   }catch(e){debt.push(e);}
  }
  // Never close the builder beneath unresolved callback/channel work. A failed
  // consumer outcome is not itself cleanup debt if actual retirement succeeds.
  if(driver&&!debt.length)try{
   if(owner)beginRetirement();
   driverReceipt=owner?await within(driver.close(),cleanupEnd):await driver.close();
   if(driverReceipt.localCleanupVerified!==true||driverReceipt.remoteCleanupVerified!==true
    ||driverReceipt.guestResourcesAbsent!==true||driverReceipt.sharedStateUnchanged!==true)throw fail('SYSTEM_PRODUCER_RETIREMENT');
  }catch(e){if(e.receipt)driverReceipt=e.receipt;
   if(pair&&retiredQualificationFailure(e)){qualificationErrors.push(e);primary ||= e;}else debt.push(e);}
  // In-flight OS work may still settle under retained debt, but a late
  // consumer continuation cannot dispatch another cleanup phase after return.
  retirementClosed=true;
  controller.signal.removeEventListener('abort',interruptedListener);options.signal.removeEventListener('abort',abort);
 }
 if(primary||debt.length)throw Object.assign(new AggregateError([primary,...qualificationErrors.filter(e=>e!==primary),...debt].filter(Boolean),'System producer failed'),
  {code:'SYSTEM_PRODUCER_FAILED',primary,consumerFailure,retirementUnproven:debt.length>0,cleanupErrors:debt,driverReceipt});
 return Object.freeze({result,driverReceipt});
}
async function withPrivateSystemImage(options,callback){
 // Literal source policy, never an environment, receipt or caller option.
 if(!LIVE_ENABLED)throw fail('V24_PRIVATE_RUNTIME_NOT_ADMITTED');
 return runProducer(options,callback);
}
function assertPairedImageCapability(capability){
 const owner=capability&&pairedOwners.get(capability);
 if(!owner||owner.revoked)throw fail('SYSTEM_PAIR_NOT_LIVE');owner.assertActive();return owner.binding;
}
async function runPairedProducer(options,callback){
 if(!exact(options,'root,runId,recipe,signal,buildDeadline,expectedPlanSha256,expectedProducerSha256,expectedDriverSha256,expectedPythonSha256')
  ||typeof callback!=='function'||!(options.signal instanceof AbortSignal)||!Number.isFinite(options.buildDeadline)
  ||options.buildDeadline<=performance.now()||options.buildDeadline-performance.now()>1800000)throw fail('SYSTEM_PRODUCER_OPTIONS');
 options.signal.throwIfAborted();await checkSelf(options.expectedProducerSha256);
 const plan=await adapter.systemPolicyBuildPlan(options.root,options.runId,options.recipe);
 if(adapter.planDigest(plan)!==options.expectedPlanSha256)throw fail('SYSTEM_PRODUCER_PLAN');
 await adapter.verifyPlan(plan);options.signal.throwIfAborted();
 const controller=new AbortController(),abort=()=>controller.abort(options.signal.reason||fail('SYSTEM_PRODUCER_INTERRUPTED'));
 options.signal.addEventListener('abort',abort,{once:true});if(options.signal.aborted)abort();
 const timer=setTimeout(()=>controller.abort(fail('SYSTEM_PRODUCER_DEADLINE')),Math.max(0,options.buildDeadline-performance.now()));
 let interruptedReject;
 const interrupted=new Promise((_,reject)=>{interruptedReject=reject;});void interrupted.catch(()=>{});
 const onAbort=()=>interruptedReject(controller.signal.reason||fail('SYSTEM_PRODUCER_INTERRUPTED'));
 controller.signal.addEventListener('abort',onAbort,{once:true});if(controller.signal.aborted)onAbort();
 let driver,entry,capability,work,result,primary,driverReceipt;const debt=[],qualificationErrors=[];
 try{
  driver=await createOwnedSystemDriver({plan,signal:controller.signal,deadline:options.buildDeadline,
   expectedPlanSha256:options.expectedPlanSha256,expectedDriverSha256:options.expectedDriverSha256,expectedPythonSha256:options.expectedPythonSha256});
  for(const name of adapter._internals.PAIR_PHASES){controller.signal.throwIfAborted();await driver.run(name);}
  const owner=await driver.claimImages();
  const active=()=>{controller.signal.throwIfAborted();if(entry.revoked)throw fail('SYSTEM_PAIR_REVOKED');owner.assertActive();};
  entry={revoked:false,binding:owner.binding,assertActive:active};capability=Object.freeze({});pairedOwners.set(capability,entry);
  work=Promise.resolve().then(()=>{active();return callback(capability,{signal:controller.signal,deadline:options.buildDeadline});});
  void work.catch(()=>{});result=await within(Promise.race([work,interrupted]),options.buildDeadline);
  active();await adapter.verifyPlan(plan);await checkSelf(options.expectedProducerSha256);active();
 }catch(error){primary=error;}
 finally{
  clearTimeout(timer);controller.abort();if(entry)entry.revoked=true;if(capability)pairedOwners.delete(capability);
  // The callback cannot turn an unjoined operation into permission to remove
  // either image's daemon/disk. No fresh build or cohort budget is created.
  if(work&&!await settled(work,performance.now()+5000))debt.push(fail('SYSTEM_PRODUCER_CALLBACK_UNSETTLED'));
  if(driver&&!debt.length)try{
   driverReceipt=await driver.close();
   if(driverReceipt.localCleanupVerified!==true||driverReceipt.remoteCleanupVerified!==true
    ||driverReceipt.guestResourcesAbsent!==true||driverReceipt.sharedStateUnchanged!==true)throw fail('SYSTEM_PRODUCER_RETIREMENT');
  }catch(error){if(error.receipt)driverReceipt=error.receipt;
   if(retiredQualificationFailure(error)){qualificationErrors.push(error);primary ||= error;}else debt.push(error);}
  options.signal.removeEventListener('abort',abort);
  controller.signal.removeEventListener('abort',onAbort);
 }
 if(primary||debt.length)throw Object.assign(new AggregateError([primary,...qualificationErrors.filter(e=>e!==primary),...debt].filter(Boolean),'Paired System build failed'),
  {code:'SYSTEM_PAIR_FAILED',primary,retirementUnproven:debt.length>0,cleanupErrors:debt,driverReceipt});
 return Object.freeze({result,driverReceipt,runtimeAvailable:false,qualificationComplete:false});
}
async function withPrivateSystemAndPolicyImages(options,callback){
 if(!PAIRED_LIVE_ENABLED)throw fail('V24_PAIRED_RUNTIME_NOT_ADMITTED');
 return runProducer(options,callback,'pair');
}
module.exports={LIVE_ENABLED,PAIRED_LIVE_ENABLED,withPrivateSystemImage,withPrivateSystemAndPolicyImages,
 assertSystemImageCapability,assertPairedImageCapability,assertPairedRuntimeCapability,_internals:{runProducer,runPairedProducer,
  runPairedRuntimeProducer:(options,callback)=>runProducer(options,callback,'pair'),PHASES}};
