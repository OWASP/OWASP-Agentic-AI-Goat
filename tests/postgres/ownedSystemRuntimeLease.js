'use strict';
// Prospective budget contract only. No process/file/namespace operation and no
// runtime admission. The shared V23 holder remains /usr/bin/sleep 900.
const {isDeepStrictEqual:equal}=require('node:util');
const BUDGET=Object.freeze({
 buildOwnerMs:1800000,       // Existing fixed System driver's aggregate work cap.
 originalCohortMs:900000,    // Original policy-instruction-browser outer timeout.
 localControllerJoinMs:6000,// TERM(4s), then at most 2s to close; no reaped signal.
 remoteLostReplyMs:330000,  // Longest remote timeout310s + kill/scheduling20s.
 cleanupMs:600000,          // Separate fixed driver's aggregate cleanup window.
});
const TOTAL_MS=Object.values(BUDGET).reduce((n,v)=>n+v,0); // 3,636,000ms.
const TARGET='original-v24-system-total-lease-v1';
const fail=code=>Object.assign(new Error(code),{code});
const exact=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)
 &&Object.keys(v).sort().join(',')===keys.split(',').sort().join(',');
const time=n=>Number.isSafeInteger(n)&&n>=0&&n<=Number.MAX_SAFE_INTEGER-TOTAL_MS;
const sha=s=>typeof s==='string'&&/^[a-f0-9]{64}$/.test(s);
function proposal({runId,planSha256,guestMonotonicMs}){
 if(!/^[a-f0-9]{32}$/.test(runId||'')||!sha(planSha256)||!time(guestMonotonicMs))throw fail('SYSTEM_LEASE_INPUT');
 return Object.freeze({version:1,target:TARGET,runId,planSha256,clock:'linux-monotonic-ms',
  startedAtMs:guestMonotonicMs,expiresAtMs:guestMonotonicMs+TOTAL_MS,
  budget:BUDGET,executionApproved:false});
}
function validate(record,{runId,planSha256,guestMonotonicMs}){
 if(typeof runId!=='string'||!/^[a-f0-9]{32}$/.test(runId)||!sha(planSha256)
  ||!exact(record,'version,target,runId,planSha256,clock,startedAtMs,expiresAtMs,budget,executionApproved')
  ||record.version!==1||record.target!==TARGET||record.runId!==runId||record.planSha256!==planSha256
  ||record.clock!=='linux-monotonic-ms'||record.executionApproved!==false||!time(record.startedAtMs)
  ||record.expiresAtMs!==record.startedAtMs+TOTAL_MS||!equal(record.budget,BUDGET)
  ||!time(guestMonotonicMs)||guestMonotonicMs<record.startedAtMs)throw fail('SYSTEM_LEASE_RECORD');
 if(guestMonotonicMs>=record.expiresAtMs)throw fail('SYSTEM_LEASE_EXPIRED');
 return record;
}
// Only this stateful owner computes subsequent windows. Repeated calls do not
// refresh any deadline. Durable integration must exclusively save the initial
// lease before namespace creation and save the cohort claim before its dispatch.
// A deserialized record alone must never reconstruct live execution authority.
function createControlledOwner(binding){
 const record=proposal(binding);
 let observed=record.startedAtMs,build=false,cohort=null,cleanup=null,notBefore=0;
 const current=now=>{
  validate(record,{...binding,guestMonotonicMs:now});
  if(now<observed)throw fail('SYSTEM_LEASE_CLOCK_REGRESSION');observed=now;
 };
 const result=(kind,deadlineMs)=>Object.freeze({kind,clock:record.clock,deadlineMs,
  leaseExpiresAtMs:record.expiresAtMs,executionApproved:false,resourceAbsenceProven:false});
 return Object.freeze({
  record,
  beginBuild(now){
   current(now);if(build||cohort!==null||cleanup!==null)throw fail('SYSTEM_BUILD_ALREADY_CLAIMED');
   const deadline=record.startedAtMs+BUDGET.buildOwnerMs;
   if(now>=deadline)throw fail('SYSTEM_BUILD_WINDOW_EXPIRED');build=true;return result('build',deadline);
  },
  beginCohort(now){
   current(now);
   if(!build||cohort!==null||cleanup!==null||now<notBefore)throw fail('SYSTEM_COHORT_NOT_ADMITTED');
   // Full unchanged900s must fit, with all termination/recovery reservations.
   const reserve=BUDGET.localControllerJoinMs+BUDGET.remoteLostReplyMs+BUDGET.cleanupMs;
   if(now+BUDGET.originalCohortMs+reserve>record.expiresAtMs)throw fail('SYSTEM_COHORT_RESERVE');
   cohort=now+BUDGET.originalCohortMs;return result('original-policy-instruction-browser',cohort);
  },
  recordLostReply(now,remoteSeconds){
   current(now);if(![150,310].includes(remoteSeconds)||cleanup!==null)throw fail('SYSTEM_REPLY_BOUND');
   const until=now+(remoteSeconds+20)*1000;
   if(until+BUDGET.cleanupMs>record.expiresAtMs)throw fail('SYSTEM_RECOVERY_RESERVE');
   notBefore=Math.max(notBefore,until);return result('uncertain-remote-wait',notBefore);
  },
  beginCleanup(now){
   current(now);if(now<notBefore)throw fail('SYSTEM_REMOTE_WAIT_PENDING');
   if(cleanup===null)cleanup=Math.min(now+BUDGET.cleanupMs,record.expiresAtMs);
   if(now>=cleanup)throw fail('SYSTEM_CLEANUP_WINDOW_EXPIRED');
   return result('cleanup',cleanup);
  },
  holderRemainingSeconds(now){
   current(now);return Math.ceil((record.expiresAtMs-now)/1000);
  },
 });
}
module.exports={BUDGET,TOTAL_MS,TARGET,proposal,validate,createControlledOwner};

