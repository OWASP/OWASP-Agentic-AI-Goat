'use strict';
// Post-work ownership only. This module cannot execute Docker or qualify work.
// A fixed PG owner must additionally consume the private capability and retain
// its own exact identity/command proofs before any cleanup or final receipt.
const timing=require('./ownedV03CombinedLease');
const owners=new WeakMap();
const RETIREMENT_MS=timing.BUDGET.diagnosticControllerJoinMs+timing.BUDGET.diagnosticLostReplyMs
 +timing.BUDGET.diagnosticCleanupMs+timing.BUDGET.listingsRetirementMs+timing.BUDGET.listingsCleanupMs;
const PG_COMMAND_MS=Object.freeze([30000,30000,30000,30000,10000,10000]);
// Actual fixed PG transport uses one <=10s identity/group inspector after
// each original Docker command; its initial birth read is inside command time.
const PG_JOIN_MS=10000;
const PG_RESERVE_MS=PG_COMMAND_MS.reduce((sum,n)=>sum+n+PG_JOIN_MS,0);
const fail=code=>Object.assign(new Error(code),{code});
function assertPostWork(value,owner){if(!owners.has(value)||owners.get(value)!==owner)throw fail('V03_POST_WORK_REQUIRED');return value;}
function coordinator(controller,main,schedule=setTimeout,cancel=clearTimeout,postgres){
 const owner=controller.owner,wrapper=owner.wrapperWindow(),expiry=owner.binding().expiresAtMs;
 let work=null,mainProof=null,producerProof=null,postgresProof=null,deadline=null,retirement=null,failure=null,handoff=null;
 async function terminalWithin(deadlineMs){
  const remaining=deadlineMs-owner.nowMs();if(remaining<=0)throw fail('V03_MAIN_WORK_EXPIRED');
  let timer;
  try{return await Promise.race([main.terminal(),new Promise((resolve,reject)=>{
   timer=schedule(()=>reject(fail('V03_MAIN_WORK_EXPIRED')),remaining);
  })]);}finally{cancel(timer);}
 }
 const value=Object.freeze({
  noteWorkHandoff(primaryFailed){
   if(handoff||retirement||typeof primaryFailed!=='boolean'||owner.nowMs()>=wrapper.deadlineMs)
    throw fail('V03_POST_WORK_HANDOFF');
   handoff=Object.freeze({primaryFailed,acceptedAtMs:owner.nowMs(),qualificationComplete:false,cleanupPending:true});
   return handoff;
  },
  retireAfterMain(){
   if(retirement)return retirement;
   retirement=(async()=>{
    try{work=await terminalWithin(wrapper.deadlineMs);}catch(error){
     failure=error.code||'V03_MAIN_TERMINAL';
     if(error.code==='V03_MAIN_WORK_EXPIRED'){
      const shutdown=await main.shutdownTimedOutWork();work=shutdown.terminal;
     }
    }
    const successfulTerminal=work?.closed===true&&work.code===0&&work.signal===null&&work.spawnFailure===null
     &&Number.isSafeInteger(work.observedAtMs)&&work.observedAtMs>=wrapper.startedAtMs&&work.observedAtMs<wrapper.deadlineMs;
    // Freeze before any asynchronous join/retirement. Joining consumes this
    // reservation, never creates a new 300 seconds after producer cleanup.
    deadline=successfulTerminal?Math.min(expiry,work.observedAtMs+RETIREMENT_MS+timing.BUDGET.originalWrapperGraceMs):expiry;
    try{mainProof=await main.retire();}catch(error){
     throw Object.assign(fail('V03_POST_WORK_MAIN_UNJOINED'),{cleanupDebt:true,cause:error});
    }
    if(mainProof?.groupAbsent!==true)throw Object.assign(fail('V03_POST_WORK_MAIN_UNJOINED'),{cleanupDebt:true});
    // Only the joined MAIN subtree held the host PG connection. Its exact
    // owned PG must leave the shared bridge before builders compare it.
    // pgDeadline reserves the entire original producer-retirement budget.
    postgresProof=await postgres.retire(value);
    if(postgresProof?.absent!==true)throw Object.assign(fail('V03_POST_WORK_PG_UNPROVEN'),{cleanupDebt:true});
    producerProof=await controller.retire('main-terminal');
    return Object.freeze({workTerminalSucceeded:successfulTerminal&&!failure&&handoff?.primaryFailed===false,qualificationComplete:false,
     cleanupPending:true,main:work,mainProof,producerProof,postgresProof,deadlineMs:deadline,failure,handoff});
   })();return retirement;
  },
  pgDeadline(){
   if(mainProof?.groupAbsent!==true)throw fail('V03_POST_WORK_QUIESCENCE_REQUIRED');
   // Before builder retirement reserve every original producer phase, including
   // lost-reply settlement. Time consumed by PG cannot renew any lease.
   const end=producerProof===null?deadline-RETIREMENT_MS:deadline;
   if(!Number.isSafeInteger(deadline)||deadline>expiry||end-owner.nowMs()<=PG_RESERVE_MS)
    throw fail('V03_POST_WORK_PG_RESERVE');
   return end;
  },
  publicationDeadline(){
   if(mainProof?.groupAbsent!==true||postgresProof?.absent!==true||producerProof?.cleanupVerified!==true
    ||producerProof.diagnosticAbsent!==true||producerProof.listingsAbsent!==true
    ||!Number.isSafeInteger(deadline)||owner.nowMs()>=deadline)throw fail('V03_POST_WORK_PUBLICATION_DEADLINE');
   return deadline;
  },
  status:()=>Object.freeze({qualificationComplete:false,cleanupPending:true,deadlineMs:deadline,
   handoff,mainAbsent:mainProof?.groupAbsent===true,producerCleanupVerified:producerProof?.cleanupVerified===true})
 });owners.set(value,owner);return value;
}
function createPostWork(controller,main,postgres){
 require('./ownedV03PrivateExecutors').assertPrivateExecutors(controller);
 require('./ownedV03MainProcess').assertMainProcess(main,controller.owner);
 require('./ownedV03PostgresOwner').assertPostgresOwner(postgres,controller.owner);
 return coordinator(controller,main,undefined,undefined,postgres);
}
module.exports={createPostWork,assertPostWork};
