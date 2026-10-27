'use strict';
// The public entry remains closed until both concrete producer paths and the
// inherited-FD controller have received composed review. Timing JSON never
// supplies ownership. Only this module can mint its private owner identity.
const {performance}=require('node:perf_hooks');
const {createHash}=require('node:crypto');
const timing=require('./ownedV03CombinedLease');
const owners=new WeakMap();
const controllers=new WeakMap();
const LIVE_ENABLED=true;
const fail=code=>Object.assign(new Error(code),{code});
function assertCombinedOwner(owner){
 const state=owners.get(owner);
 if(!state)throw fail('V03_COMBINED_OWNER_REQUIRED');
 return owner;
}
function assertPrivateExecutors(controller){
 if(!controllers.has(controller))throw fail('V03_PRIVATE_EXECUTORS_REQUIRED');return controller;
}
function mintOwner(runId,planSha256,clock=()=>Math.floor(performance.now())){
 if(!/^[a-f0-9]{32}$/.test(runId||'')||! /^[a-f0-9]{64}$/.test(planSha256||''))throw fail('V03_COMBINED_BINDING');
 const model=timing.createControlledOwner({runId,startedAtMs:clock()});
 const state={model,clock,window:null,wrapper:null,phaseAbort:null,pending:new Set(),cohort:null,guestClock:null,revoked:false,last:model.record.startedAtMs};
 function now(){
  const value=clock();
  if(!Number.isSafeInteger(value)||value<state.last)throw fail('V03_CLOCK_REGRESSION');
  state.last=value;return value;
 }
 const binding=Object.freeze({runId,planSha256,expiresAtMs:model.record.expiresAtMs});
 const producerBindings=Object.freeze(Object.fromEntries(['diagnostic','listings'].map(kind=>[kind,Object.freeze({
  parentRunId:runId,runId:createHash('sha256').update(runId+':v03-'+kind).digest('hex').slice(0,32),
  planSha256,expiresAtMs:model.record.expiresAtMs})])));
 const owner=Object.freeze({
  binding:()=>binding,
  producerBinding(kind){
   if(!Object.hasOwn(producerBindings,kind))throw fail('V03_PRODUCER_KIND');
   return producerBindings[kind];
  },
  nowMs:()=>now(),
  wrapperWindow(){
   if(state.revoked||!state.wrapper||now()>=state.wrapper.graceDeadlineMs)throw fail('V03_WRAPPER_NOT_ACTIVE');
   return state.wrapper;
  },
  clockMapping(){
   if(!state.guestClock)throw fail('V03_CLOCK_NOT_ADMITTED');
   return require('./ownedV03GuestClock').assertGuestClockMapping(state.guestClock,owner);
  },
  remainingMs(){const left=binding.expiresAtMs-now();if(left<=0)throw fail('V03_LEASE_EXPIRED');return left;},
  phaseWindow(kind){
   const at=now();
   if(!state.window||state.window.kind!==kind||at>=state.window.deadlineMs)throw fail('V03_PHASE_NOT_ACTIVE');
   return state.window;
  },
  phaseSignal(kind){
   if(!state.window||state.window.kind!==kind||!state.phaseAbort||now()>=state.window.deadlineMs
     ||state.phaseAbort.signal.aborted)throw fail('V03_PHASE_NOT_ACTIVE');
   return state.phaseAbort.signal;
  },
  cohortDeadlineMs(){
   if(state.revoked||!state.cohort||now()>=state.cohort.deadlineMs)throw fail('V03_COHORT_NOT_ACTIVE');
   return state.cohort.deadlineMs;
  },
  isRevoked:()=>state.revoked
 });
 owners.set(owner,state);
 return {owner,state,now};
}

function registerGuestClock(binding,mapping){
 const {owner,state}=binding;
 if(state.guestClock||state.revoked||state.window?.kind!=='diagnosticBuildMs')
  throw fail('V03_CLOCK_REGISTRATION_PHASE');
 owner.phaseSignal('diagnosticBuildMs').throwIfAborted();
 const verified=require('./ownedV03GuestClock').assertGuestClockMapping(mapping,owner);
 // Only the fixed sampler's private identity is accepted. No packet, copied
 // mapping methods or producer-supplied timestamps can mint this authority.
 state.guestClock=verified;
}

// This controller accepts producers only from the fixed imported factories in
// the closed public entry below. No caller runner/factory/receipt option exists.
function controllerFor(binding,diagnostic,listings,waitUntil=async deadline=>{
 while(binding.now()<deadline)await new Promise(resolve=>setTimeout(resolve,Math.min(1000,deadline-binding.now())));
},schedule=setTimeout,cancel=clearTimeout,clockOptions=null){
 const {owner,state,now}=binding;
 let stage='new',retirement=null,claim=null;
 const debts=[];
 const retainParentDebt=error=>{
  if(error?.cleanupDebt===true||error?.remoteUncertain===true)
   debts.push({producer:'combined',phase:state.window?.kind||stage,code:error.code||'V03_PARENT_RESOURCE_UNPROVEN'});
 };
 async function boundedOperation(operation){
  const window=state.window,remaining=window.deadlineMs-now();
  if(remaining<=0)throw fail('V03_PHASE_EXPIRED');
  const abort=new AbortController();state.phaseAbort=abort;
  let timer;
  const deadline=new Promise((resolve,reject)=>{
   timer=schedule(()=>{
    debts.push({producer:'combined',phase:window.kind,code:'V03_PHASE_UNJOINED'});
    reject(fail('V03_PHASE_UNJOINED'));abort.abort();
   },remaining);
  });
  const work=Promise.resolve().then(operation);
  state.pending.add(work);
  work.then(()=>state.pending.delete(work),()=>state.pending.delete(work));
  let onAbort;
  const interrupted=new Promise((resolve,reject)=>{
   onAbort=()=>reject(fail('V03_OWNER_REVOKED'));
   abort.signal.addEventListener('abort',onAbort,{once:true});
  });
  // A timeout is debt even if work later settles. No absence is inferred from
  // the race; concrete producers still must join their owned commands.
  try{return await Promise.race([work,deadline,interrupted]);}
  finally{cancel(timer);abort.signal.removeEventListener('abort',onAbort);if(state.phaseAbort===abort)state.phaseAbort=null;}
 }
 async function phase(kind,operation){
  if(state.revoked)throw fail('V03_OWNER_REVOKED');
  state.window=state.model.beginPreparation(kind,now());
  const result=await boundedOperation(operation);
  if(state.revoked)throw fail('V03_OWNER_REVOKED');
  state.model.completePreparation(kind,now());state.window=null;return result;
 }
 async function retireBoth(reason){
  if(retirement)return retirement;
  state.revoked=true;stage='retiring';
  const priorWork=[...state.pending];
  const noOverlap=priorWork.length===0;
  state.phaseAbort?.abort();
  // Install the promise before invoking either producer: EOF, expiry, RPC
  // failure and normal close converge on one retirement, never a second lease.
  retirement=Promise.resolve().then(async()=>{
   const results={};
   const phases=[['diagnostic','diagnosticControllerJoinMs',async()=>{
    const window=state.window,signal=state.phaseAbort.signal;
    await Promise.allSettled(priorWork);
    if(signal.aborted||state.window!==window||now()>=window.deadlineMs)throw fail('V03_PHASE_EXPIRED');
    return diagnostic.join();
   }],
    ['diagnostic','diagnosticLostReplyMs',()=>diagnostic.settle()],
    ['diagnostic','diagnosticCleanupMs',()=>diagnostic.retire()],
    ['listings','listingsRetirementMs',()=>listings.join()],
    ['listings','listingsCleanupMs',()=>listings.retire()]];
   for(const [name,kind,operation] of phases){
    let claimed=false;
    try{
     state.window=state.model.beginRetirement(kind,now());claimed=true;
     const receipt=await boundedOperation(operation);
     const unstarted=kind==='diagnosticLostReplyMs'&&noOverlap&&debts.length===0
      &&state.pending.size===0&&claim===null
      &&require('./ownedSystemDiagnosticProducer').consumeUnstartedDiagnostic(diagnostic,owner,state.window);
     if(unstarted)state.model.completeUnstartedDiagnostic(now());
     else{
      if(kind==='diagnosticLostReplyMs')await waitUntil(state.window.deadlineMs);
      state.model.completeRetirement(kind,now());
     }
     claimed=false;
     if(kind.endsWith('CleanupMs')){
      if(!receipt||receipt.cleanupVerified!==true||receipt.resourceAbsenceProven!==true)
       throw fail('V03_PRODUCER_RETIREMENT_UNPROVEN');
      results[name]=receipt;
     }
    }catch(error){
     debts.push({producer:name,phase:kind,code:error.code||'V03_RETIREMENT_ERROR'});
     if(claimed)try{
      if(kind==='diagnosticLostReplyMs')await waitUntil(state.window.deadlineMs);
      state.model.recordRetirementDebt(kind,now());
     }catch(failure){debts.push({producer:name,phase:kind,code:failure.code||'V03_RETIREMENT_RESERVE'});}
    }finally{state.window=null;}
   }
   stage='closed';
   return Object.freeze({version:1,runId:owner.binding().runId,closed:true,
    cleanupVerified:debts.length===0&&state.pending.size===0,diagnosticAbsent:!!results.diagnostic,
    listingsAbsent:!!results.listings,reason,errors:Object.freeze(debts.slice())});
  });
  return retirement;
 }
 const controller=Object.freeze({
  owner,
  async start(){
   if(stage!=='new')throw fail('V03_START_ONCE');stage='preparing';
   const parentRemainingMsAtAdmission=owner.remainingMs();
   try{
    await phase('diagnosticBuildMs',async()=>{
     if(clockOptions){
      const window=state.window,signal=state.phaseAbort.signal;
      const mapping=await require('./ownedV03GuestClock').sampleGuestClock({...clockOptions,owner});
      if(signal.aborted||state.window!==window||now()>=window.deadlineMs)throw fail('V03_PHASE_EXPIRED');
      registerGuestClock(binding,mapping);
     }
     return diagnostic.prepare();
    });
    await phase('listingsBuildMs',()=>listings.prepare());
    await phase('listingsSettlementMs',()=>listings.settle());
    const diagnosticEndpoint=await phase('diagnosticStartupMs',()=>diagnostic.start());
    const listingsEndpoint=await phase('listingsStartupMs',()=>listings.start());
    if(diagnosticEndpoint?.ready!==true||listingsEndpoint?.ready!==true)throw fail('V03_BOTH_READY_REQUIRED');
    state.wrapper=state.model.beginWrapper(now());stage='ready';
    return {ready:true,parentRemainingMsAtAdmission};
   }catch(error){retainParentDebt(error);await retireBoth('preparation-failure');throw error;}
  },
  async claimCohort(){
   if(stage!=='ready'||claim)throw fail('V03_COHORT_ONCE');stage='claiming';
   state.cohort=state.model.claimCohort(now());
   claim=state.cohort;
   try{
    state.window=Object.freeze({kind:'cohortClaim',deadlineMs:claim.startedAtMs+timing.ACTIVATION_MS});
    let diagnosticEndpoint,listingsEndpoint;
    await boundedOperation(async()=>{
     const window=state.window,signal=state.phaseAbort.signal;
     diagnosticEndpoint=await diagnostic.claimCohort();
     if(signal.aborted||state.window!==window||now()>=window.deadlineMs)throw fail('V03_PHASE_EXPIRED');
     listingsEndpoint=await listings.claimCohort();
    });
    state.window=null;
    if(owner.cohortDeadlineMs()!==claim.deadlineMs)throw fail('V03_COHORT_CHANGED');
    const additional=listingsEndpoint?.additionalClockUncertaintyMs??0;
    if(!Number.isSafeInteger(additional)||additional<0||additional>2000)throw fail('V03_CLOCK_UNCERTAINTY');
    const uncertaintyMs=(state.guestClock?state.guestClock.uncertaintyMs():0)+additional;
    if(!Number.isSafeInteger(uncertaintyMs)||uncertaintyMs<0||uncertaintyMs>2000)throw fail('V03_CLOCK_UNCERTAINTY');
    const at=now(),activationRemainingMs=claim.startedAtMs+timing.ACTIVATION_MS-uncertaintyMs-at;
    if(activationRemainingMs<=0||claim.deadlineMs-uncertaintyMs-at<timing.COHORT_MS)throw fail('V03_ACTIVATION_EXPIRED');
    if(!diagnosticEndpoint||Object.keys(diagnosticEndpoint).sort().join(',')!=='token,url'
      ||typeof diagnosticEndpoint.url!=='string'||typeof diagnosticEndpoint.token!=='string'
      ||!listingsEndpoint||typeof listingsEndpoint.environment!=='object'||Array.isArray(listingsEndpoint.environment))
     throw fail('V03_PRIVATE_ENDPOINTS');
    const environment=Object.freeze({...listingsEndpoint.environment,
     SECURESHOP_LISTING_IMAGE_OPTIMIZE_V03_BROWSER_SYSTEM_URL:diagnosticEndpoint.url,
     SECURESHOP_LISTING_IMAGE_OPTIMIZE_V03_BROWSER_SYSTEM_TOKEN:diagnosticEndpoint.token});
    stage='claimed';return Object.freeze({activationMsAtClaim:timing.ACTIVATION_MS,
     infrastructureMsAtClaim:timing.INFRASTRUCTURE_MS,clockUncertaintyMs:uncertaintyMs,originalChildMs:timing.COHORT_MS,environment});
   }catch(error){retainParentDebt(error);await retireBoth('cohort-failure');throw error;}
  },
  retire:retireBoth,
  status:()=>Object.freeze({stage,revoked:state.revoked,cleanupVerified:stage==='closed'&&debts.length===0&&state.pending.size===0})
 });controllers.set(controller,owner);return controller;
}

function watchOwnerChannel(controller,channel,clock=()=>Math.floor(performance.now()),
 schedule=setTimeout,cancel=clearTimeout){
 assertCombinedOwner(controller.owner);
 let totalTimer=null,cohortTimer=null,retiring=null,cohortArmed=false;
 const detach=()=>{
  if(totalTimer!==null)cancel(totalTimer);if(cohortTimer!==null)cancel(cohortTimer);
  channel.removeListener('end',eof);channel.removeListener('close',eof);channel.removeListener('error',error);
 };
 const retire=reason=>{
  if(retiring)return retiring;
  retiring=Promise.resolve().then(()=>controller.retire(reason));
  // Retirement failure is retained for the owner to await. Event callbacks
  // must not turn it into an unhandled rejection or silently claim success.
  retiring.then(detach,detach);return retiring;
 };
 const arm=(deadline,reason)=>{
  const remaining=deadline-clock();
  if(!Number.isSafeInteger(remaining)||remaining<=0){retire(reason);return null;}
  return schedule(()=>{retire(reason);},remaining);
 };
 const eof=()=>{retire('inherited-fd-eof');},error=()=>{retire('inherited-fd-error');};
 channel.once('end',eof);channel.once('close',eof);channel.once('error',error);
 totalTimer=arm(controller.owner.binding().expiresAtMs,'absolute-owner-expiry');
 return Object.freeze({
  armCohort(){
   if(cohortArmed||retiring)throw fail('V03_WATCHDOG_COHORT_ONCE');
   cohortArmed=true;
   cohortTimer=arm(controller.owner.cohortDeadlineMs(),'absolute-cohort-expiry');
  },
  async close(reason='normal-close'){
   try{return await retire(reason);}
   finally{detach();}
  }
 });
}

async function createPrivateExecutors(options){
 if(!LIVE_ENABLED)throw fail('V03_COMPOSED_PRODUCERS_NOT_ADMITTED');
 // No generic runner or callable-shaped capability is accepted here.
 if(!options||Object.keys(options).sort().join(',')!=='clock,diagnostic,listings,planSha256,root,runId')
  throw fail('V03_PARENT_OPTIONS');
 const binding=mintOwner(options.runId,options.planSha256);
 const diagnosticModule=require('./ownedSystemDiagnosticProducer');
 const listingsModule=require('./ownedV03ListingsProducer');
 const diagnostic=diagnosticModule.createDiagnosticProducer({...options.diagnostic,
  root:options.root,parentRunId:options.runId,runId:binding.owner.producerBinding('diagnostic').runId,combinedOwner:binding.owner});
 const listings=listingsModule.createListingsProducer({...options.listings,
  root:options.root,parentRunId:options.runId,runId:binding.owner.producerBinding('listings').runId,combinedOwner:binding.owner});
 diagnosticModule.assertDiagnosticProducer(diagnostic);
 listingsModule.assertListingsProducer(listings);
 if(!options.clock||Object.keys(options.clock).sort().join(',')!=='expectedClockSha256,expectedDriverSha256,expectedPythonSha256')
  throw fail('V03_CLOCK_OPTIONS');
 return controllerFor(binding,diagnostic,listings,undefined,undefined,undefined,
  {...options.clock,root:options.root});
}
module.exports={createPrivateExecutors,assertCombinedOwner,assertPrivateExecutors,watchOwnerChannel};
if(require.main===module){
 // One fixed entry; importing this module never dispatches it. The entry and
 // all concrete factories remain independently closed until composed review.
 require('./ownedV03ParentEntry').runParent().then(terminal=>{
  const success=terminal.terminalPublicationVerified===true&&terminal.cleanupVerified===true&&terminal.finalization?.publicationVerified===true
   &&terminal.finalization?.candidate?.work?.workTerminalSucceeded===true;
  process.exitCode=success?0:1;
 }).catch(error=>{
  process.exitCode=1;
  process.stderr.write(JSON.stringify({version:1,qualificationComplete:false,
   failure:error.code||'V03_PARENT_ENTRY_FAILURE',cleanupDebt:error.cleanupDebt===true,
   sourceCheckPending:error.sourceCheckPending===true,terminalWritePending:error.terminalWritePending===true})+'\n');
 });
}
