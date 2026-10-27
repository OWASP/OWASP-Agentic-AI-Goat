'use strict';
// Reviewed original cohort composition; exact plan and runtime admission remain mandatory.
const assert=require('node:assert/strict');
const path=require('node:path');
const {performance}=require('node:perf_hooks');
const LIVE_ENABLED=true; // Reviewed owner path; MAIN admission and exact producer plan remain independent.
const ROOT=path.resolve(__dirname,'../..');
const scopes=new WeakMap();
const failedTerminals=new WeakMap();
function claimFailedTerminal(error,{runId,expectedPlanSha256,outerDeadline}){
 const row=failedTerminals.get(error);
 if(!row||row.runId!==runId||row.planSha256!==expectedPlanSha256||row.deadline!==outerDeadline
  ||performance.now()>=outerDeadline)throw failure('ORIGINAL_COHORT_FAILED_TERMINAL_REQUIRED');
 failedTerminals.delete(error);
 return JSON.parse(row.bytes);
}
function failure(code){return Object.assign(new Error(code),{code});}
async function settlePublication(finalize,args,outerDeadline){
 assert(Number.isFinite(outerDeadline));
 const deadline=Math.min(performance.now()+5000,outerDeadline),pending=new Set();let open=true,timer;
 const check=()=>{if(!open||performance.now()>=deadline)throw failure('ORIGINAL_COHORT_PUBLICATION_DEADLINE');};
 const track=(fn,cleanup=false)=>{if(!cleanup)check();const operation=Promise.resolve().then(()=>{if(!cleanup)check();return fn();});
  pending.add(operation);operation.then(()=>pending.delete(operation),()=>pending.delete(operation));return operation;};
 const authority=Object.freeze({check,io:fn=>track(fn),close:fn=>track(fn,true)});
 let work;
 try{check();work=Promise.resolve().then(()=>{check();return finalize({...args,publication:authority});});
  const value=await Promise.race([work,new Promise((_,reject)=>{timer=setTimeout(()=>reject(failure('ORIGINAL_COHORT_PUBLICATION_DEADLINE')),Math.max(0,deadline-performance.now()));})]);check();
  if(pending.size)throw failure('ORIGINAL_COHORT_PUBLICATION_UNJOINED');
  return value;
 }catch(error){error.publicationDebt={sealed:false,pendingOperations:pending.size,lateWritesNotCancelled:true};throw error;}
 finally{open=false;clearTimeout(timer);work?.catch(()=>{});}
}
function assertScope(scope){
 const state=scopes.get(scope);
 if(!state||state.controlled||!state.active)throw failure('ORIGINAL_COHORT_SCOPE_REQUIRED');
 state.check();return state;
}
function validateWindow(value){
 const w=value?.cohortWindow;
 assert(w&&w.version===1&&w.clock==='producer-performance-now-ms');
 assert.equal(w.budgetMs,1200000);assert.equal(w.admissionIncluded,true);assert.equal(w.renewable,false);
 for(const k of ['startedAtMs','callbackEnteredAtMs','deadlineMs','remainingMs'])assert(Number.isFinite(w[k]));
 assert.equal(w.deadlineMs-w.startedAtMs,1200000);
 assert(w.callbackEnteredAtMs>=w.startedAtMs&&w.remainingMs>0&&w.remainingMs<=1200000);
 assert.equal(w.remainingMs,w.deadlineMs-w.callbackEnteredAtMs);assert.equal(value.deadline,w.deadlineMs);
 assert(value.signal&&typeof value.signal.throwIfAborted==='function');
 return w;
}
function producerProof(output,options){
 const r=output?.receipt,s=output?.result;
 assert(r&&r.version===1&&r.controlled===false&&r.buildCompleted===true&&r.cleanupVerified===true);
 assert.equal(r.runId,options.runId);assert.equal(r.planSha256,options.expectedPlanSha256);
 assert.equal(r.qualificationComplete,false);assert.equal(r.error,null);
 assert.deepEqual(r.cleanupErrors,[]);assert.deepEqual(r.interruptions,[]);
 assert(r.consumerJournal?.sealed===true);
 assert(s&&s.controlled===false&&s.cleanupVerified===true&&s.qualificationComplete===false);
 assert.equal(output.artifact,path.join(ROOT,'tasks/tmp','v23-build-'+options.runId));
 return Object.freeze({version:1,runId:r.runId,planSha256:r.planSha256,artifact:output.artifact,
  cleanupVerified:true,consumerCleanupVerified:true,sharedStatePreserved:true});
}
function originalContract(){
 const fixture=require('./secureshopV23Original.integration.test');
 return Object.freeze({runNative:fixture.runNative,candidateBytes:fixture.candidateBytes,assertReceipt:fixture.assertReceipt,
  file:'v23-original-result.json',successKind:'original-v23-owner-terminal',
  failureKind:'original-v23-failed-owner-terminal'});
}
function renderedContract(){
 const fixture=require('./secureshopV23PublicRendered.integration.test');
 return Object.freeze({runNative:fixture.runNative,candidateBytes:fixture.candidateBytes,assertReceipt:fixture.assertReceipt,
  file:'v23-public-admin-rendered-result.json',successKind:'original-v23-public-admin-rendered-owner-terminal',
  failureKind:'original-v23-public-admin-rendered-failed-owner-terminal'});
}
async function compose(options,producer,fixture,controlled,contract=originalContract()){
 let state,output,primary,called=false,callbackFailure;
 try{
  assert(Number.isFinite(options.outerDeadline));if(performance.now()>=options.outerDeadline)throw failure('ORIGINAL_COHORT_OUTER_DEADLINE');
  output=await producer({root:options.root,runId:options.runId,expectedPlanSha256:options.expectedPlanSha256,outerDeadline:options.outerDeadline,consumer:async value=>{
   assert(!called,'One original cohort callback required');called=true;
   validateWindow(value);
   if(options.judgeChannel)assert(require('../../tasks/qualification/v23-independent-judge-channel').isChannel(options.judgeChannel));
   const scope=Object.freeze({});
   state={controlled,active:true,settled:false,outcome:null,configuration:value.configuration,
    signal:value.signal,cohortWindow:value.cohortWindow,
    ...(options.judgeChannel?{acquireJudge:()=>options.judgeChannel.acquire(Math.min(value.deadline,options.outerDeadline))}:{}),
    check(){value.signal.throwIfAborted();if(performance.now()>=Math.min(value.deadline,options.outerDeadline))throw failure('ORIGINAL_COHORT_DEADLINE');},
    retain(outcome){assert(!this.outcome);assert(outcome&&typeof outcome.finalize==='function');this.outcome=outcome;}};
   scopes.set(scope,state);
   try{state.check();return await fixture(options.env,scope);}
   catch(error){callbackFailure=error;throw error;}
   finally{options.judgeChannel?.close();state.active=false;state.settled=true;scopes.delete(scope);}
  }});
  assert(called&&state.settled&&state.outcome,'Completed original cohort evidence required');
 }catch(error){primary=error;}
 // Never finalize while an expired producer callback still owns writes or stores.
 if(state&&!state.settled){const debt=failure('ORIGINAL_COHORT_UNJOINED');debt.primary=primary;debt.retirementUnproven=true;throw debt;}
 let proof,publication,failedProof;
 if(!primary)try{proof=producerProof(output,options);assert.equal(output.result.value,state.outcome.result);}catch(error){primary=error;}
 if(state?.outcome)try{publication=await settlePublication(async args=>{
  // Only the actual adapter's private error provenance can establish failed
  // retirement; a controlled producer or an error property cannot supply it.
  if(primary&&callbackFailure&&!controlled){
   try{failedProof=await args.publication.io(()=>require('./ownedMcpOriginalBuildAdapter').claimFailedRetirement(primary,callbackFailure,options));}
   catch(error){if(error.code!=='ORIGINAL_BUILD_FAILED_RETIREMENT_REQUIRED')throw error;}
   args.publication.check();
  }
  return state.outcome.finalize(args);
 },{proof:primary?null:proof,error:primary},options.outerDeadline);}
 catch(error){if(primary)primary.finalizationError=error;else primary=error;}
 if(primary){
  if(failedProof&&!primary.finalizationError&&state.outcome.result.passed===false){
   const bytes=contract.candidateBytes(state.outcome.result);
   const expected={version:1,file:contract.file,sha256:require('node:crypto').createHash('sha256').update(bytes).digest('hex'),
    bytes:Buffer.byteLength(bytes),unsealed:true,requiresOwnerTerminal:true};
   // Do not replace the original failure if publication was malformed.
   try{assert.deepEqual(publication,expected);assert(performance.now()<options.outerDeadline);
    failedTerminals.set(primary,Object.freeze({runId:options.runId,planSha256:options.expectedPlanSha256,deadline:options.outerDeadline,
     bytes:JSON.stringify({version:1,kind:contract.failureKind,passed:false,canonicalCredit:false,qualificationComplete:false,
      runId:options.runId,planSha256:options.expectedPlanSha256,retirement:failedProof,cohort:state.outcome.result,publication})}));
   }catch(error){primary.finalizationError=error;}
  }
  throw primary;
 }
 assert.equal(state.outcome.result.passed,true);
 if(!controlled)contract.assertReceipt(state.outcome.result);
 const bytes=contract.candidateBytes(state.outcome.result);
 assert.deepEqual(publication,{version:1,file:contract.file,sha256:require('node:crypto').createHash('sha256').update(bytes).digest('hex'),
  bytes:Buffer.byteLength(bytes),unsealed:true,requiresOwnerTerminal:true});
 return {version:1,kind:contract.successKind,passed:true,canonicalCredit:false,qualificationComplete:false,
  runId:options.runId,planSha256:options.expectedPlanSha256,cohort:state.outcome.result,publication};
}
async function runOriginalCohort(options={}){
 if(!LIVE_ENABLED)throw failure('ORIGINAL_COHORT_NOT_ADMITTED');
 assert.deepEqual(Object.keys(options).sort(),(options.judgeChannel?['env','expectedPlanSha256','judgeChannel','outerDeadline','root','runId']:['env','expectedPlanSha256','outerDeadline','root','runId']));
 if(options.judgeChannel)assert(require('../../tasks/qualification/v23-independent-judge-channel').isChannel(options.judgeChannel));
 assert.equal(options.root,ROOT);assert.match(options.runId,/^[a-f0-9]{32}$/);assert.match(options.expectedPlanSha256,/^[a-f0-9]{64}$/);
 return compose(options,require('./ownedMcpOriginalBuildAdapter').withOriginalRegistryService,
  require('./secureshopV23Original.integration.test').runNative,false);
}
async function runRenderedOriginalCohort(options={}){
 if(!LIVE_ENABLED)throw failure('ORIGINAL_COHORT_NOT_ADMITTED');
 assert.deepEqual(Object.keys(options).sort(),(options.judgeChannel?['env','expectedPlanSha256','judgeChannel','outerDeadline','root','runId']:['env','expectedPlanSha256','outerDeadline','root','runId']));
 if(options.judgeChannel)assert(require('../../tasks/qualification/v23-independent-judge-channel').isChannel(options.judgeChannel));
 assert.equal(options.root,ROOT);assert.match(options.runId,/^[a-f0-9]{32}$/);assert.match(options.expectedPlanSha256,/^[a-f0-9]{64}$/);
 const contract=renderedContract();
 return compose(options,require('./ownedMcpOriginalBuildAdapter').withOriginalRegistryService,contract.runNative,false,contract);
}
module.exports={runOriginalCohort,runRenderedOriginalCohort,assertScope,claimFailedTerminal,_internals:{validateWindow,producerProof,settlePublication,
 controlledScope:scope=>{const state=scopes.get(scope);assert(state?.controlled===true&&state.active);
  return Object.freeze({cohortWindow:state.cohortWindow,retain:outcome=>state.retain(outcome)});},
 runControlled:(options,producer,fixture)=>compose(options,producer,fixture,true)}};
