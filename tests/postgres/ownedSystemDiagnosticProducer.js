'use strict';
// Concrete diagnostic lifecycle, callable only by the closed combined owner.
// No caller factories, commands, images, URLs, tokens or serialized authority.
const fs=require('node:fs/promises'),native=require('node:fs'),crypto=require('node:crypto');
const adapter=require('./ownedSystemDiagnosticBuildAdapter');
const {createOwnedSystemDriver,_internals:{NORMAL}}=require('./ownedSystemConfigPhaseDriver');
const producers=new WeakMap();
const fail=code=>Object.assign(new Error(code),{code});
const sha=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
const exact=(value,names)=>value&&typeof value==='object'&&!Array.isArray(value)
 &&Object.keys(value).sort().join(',')===names.split(',').sort().join(',');
async function checkSource(expected){
 if(await fs.realpath(__filename)!==__filename)throw fail('DIAGNOSTIC_PRODUCER_SOURCE');
 const fd=await fs.open(__filename,native.constants.O_RDONLY|native.constants.O_NOFOLLOW|native.constants.O_NONBLOCK);
 let primary;
 try{
  const before=await fd.stat();
  if(!before.isFile()||before.nlink!==1||before.size>131072)throw fail('DIAGNOSTIC_PRODUCER_SOURCE');
  const bytes=Buffer.alloc(before.size);let offset=0;
  while(offset<bytes.length){const row=await fd.read(bytes,offset,bytes.length-offset,offset);
   if(!row.bytesRead)throw fail('DIAGNOSTIC_PRODUCER_SOURCE');offset+=row.bytesRead;}
  const after=await fd.stat();
  if(['dev','ino','size','mtimeMs','ctimeMs'].some(key=>before[key]!==after[key])||sha(bytes)!==expected)
   throw fail('DIAGNOSTIC_PRODUCER_SOURCE');
 }catch(error){primary=error;}
 finally{try{await fd.close();}catch(error){primary ||= error;primary.cleanupDebt=true;primary.producerSourceCloseUnproven=true;}}
 if(primary)throw primary;
}
function assertDiagnosticProducer(value){
 if(!producers.has(value))throw fail('DIAGNOSTIC_PRODUCER_REQUIRED');return value;
}
function createDiagnosticProducer(options){
 if(!exact(options,'root,runId,parentRunId,combinedOwner,expectedPlanSha256,expectedProducerSha256,expectedDriverSha256,expectedPythonSha256'))
  throw fail('DIAGNOSTIC_PRODUCER_OPTIONS');
 const owner=require('./ownedV03PrivateExecutors').assertCombinedOwner(options.combinedOwner);
 const binding=owner.producerBinding('diagnostic');
 if(options.runId!==binding.runId||options.parentRunId!==binding.parentRunId||owner.isRevoked())throw fail('DIAGNOSTIC_PRODUCER_BINDING');
 for(const key of ['expectedPlanSha256','expectedProducerSha256','expectedDriverSha256','expectedPythonSha256'])
  if(! /^[a-f0-9]{64}$/.test(options[key]||''))throw fail('DIAGNOSTIC_PRODUCER_PIN');
 let consumerAttempted=false;
 let stage='new',driver=null,runtime=null,token=null,primary=null,retirement=null,joined=false,runtimeStarted=false;
 const active=()=>{if(owner.isRevoked()||primary)throw fail('DIAGNOSTIC_PRODUCER_INACTIVE');};
 async function attempt(operation){try{return await operation();}catch(error){primary ||= error;stage='failed';throw error;}}
 const producer=Object.freeze({
  async prepare(){
   active();if(stage!=='new')throw fail('DIAGNOSTIC_PREPARE_ONCE');stage='preparing';
   return attempt(async()=>{
    const window=owner.phaseWindow('diagnosticBuildMs'),signal=owner.phaseSignal('diagnosticBuildMs');
    try{
    await checkSource(options.expectedProducerSha256);signal.throwIfAborted();
    const plan=await adapter.diagnosticBuildPlan(options.root,options.runId);
    if(adapter.planDigest(plan)!==options.expectedPlanSha256)throw fail('DIAGNOSTIC_PRODUCER_PLAN');
    await adapter.verifyDiagnosticBuildPlan(plan);signal.throwIfAborted();
    driver=await createOwnedSystemDriver({plan,combinedOwner:owner,signal,deadline:window.deadlineMs,
     expectedPlanSha256:options.expectedPlanSha256,expectedDriverSha256:options.expectedDriverSha256,
     expectedPythonSha256:options.expectedPythonSha256});
    }catch(error){
     // Read-only capture/derivation may own descriptors before a driver handle
     // exists. Absence of that handle is not proof those descriptors closed.
     // Preserve the primary and conservatively retain pre-driver closure debt.
     error.cleanupDebt=true;error.preDriverClosureUnproven=true;throw error;
    }
    for(const name of NORMAL){active();signal.throwIfAborted();await driver.run(name);}
    await driver.claimDiagnosticImage();runtime=driver.claimDiagnosticRuntime();stage='prepared';
    return Object.freeze({prepared:true});
   });
  },
  async start(){
   consumerAttempted=true;
   active();if(stage!=='prepared')throw fail('DIAGNOSTIC_START_ORDER');stage='starting';
   return attempt(async()=>{
    owner.phaseWindow('diagnosticStartupMs');token=crypto.randomBytes(32).toString('base64url');
    runtimeStarted=true;const result=await runtime.startRuntime(token);
    if(!exact(result,'ready')||result.ready!==true)throw fail('DIAGNOSTIC_READINESS');
    active();stage='ready';return Object.freeze({ready:true});
   });
  },
  async claimCohort(){
   consumerAttempted=true;
   active();if(stage!=='ready')throw fail('DIAGNOSTIC_COHORT_ORDER');stage='claiming';
   return attempt(async()=>{
    owner.phaseWindow('cohortClaim');const value=await runtime.claimCohort();
    if(!exact(value,'port')||!Number.isSafeInteger(value.port)||value.port<1||value.port>65535)
     throw fail('DIAGNOSTIC_PRIVATE_ENDPOINT');
    active();stage='claimed';return Object.freeze({url:'http://127.0.0.1:'+value.port,token});
   });
  },
  async join(){
   if(!owner.isRevoked())throw fail('DIAGNOSTIC_RETIREMENT_ORDER');
   owner.phaseWindow('diagnosticControllerJoinMs');
   if(joined)throw fail('DIAGNOSTIC_JOIN_ONCE');joined=true;
   return runtime?runtime.join():Object.freeze({joinRequested:true});
  },
  async settle(){
   if(!owner.isRevoked()||!joined)throw fail('DIAGNOSTIC_SETTLEMENT_ORDER');
   // The combined parent enforces the complete fixed330s wait. This method
   // cannot start a timer or renew that phase, nor claim resource absence.
   owner.phaseWindow('diagnosticLostReplyMs');if(runtime)await runtime.settle();
   return Object.freeze({settlementRequested:true});
  },
  retire(){
   if(retirement)return retirement;
   if(!owner.isRevoked()||!joined)throw fail('DIAGNOSTIC_RETIREMENT_ORDER');
   owner.phaseWindow('diagnosticCleanupMs');stage='retiring';
   retirement=(async()=>{
    if(runtimeStarted)await runtime.stopRuntime();
    const receipt=driver?await driver.close():null;
    const verified=driver?receipt?.localCleanupVerified===true&&receipt.remoteCleanupVerified===true
     &&receipt.guestResourcesAbsent===true&&receipt.sharedStateUnchanged===true
     &&Array.isArray(receipt.debts)&&receipt.debts.length===0:!primary?.cleanupDebt;
    if(!verified)throw Object.assign(fail('DIAGNOSTIC_RETIREMENT_UNPROVEN'),{receipt,retirementUnproven:true});
    token=null;stage='closed';return Object.freeze({cleanupVerified:true,resourceAbsenceProven:true});
   })();return retirement;
  },
  publicStatus:()=>Object.freeze({stage,ready:stage==='ready'||stage==='claimed',closed:stage==='closed'})
 });
 producers.set(producer,{owner,consume:(window)=>{
  if(consumerAttempted||stage!=='prepared'||primary||!joined||!runtime||runtimeStarted||retirement)return false;
  return require('./ownedSystemConfigPhaseDriver').consumeUnstartedSettlement(runtime,owner,window);
 }});return producer;
}
function consumeUnstartedDiagnostic(producer,owner,window){
 const entry=producers.get(producer);return !!entry&&entry.owner===owner&&entry.consume(window);
}
module.exports={createDiagnosticProducer,assertDiagnosticProducer,consumeUnstartedDiagnostic};
