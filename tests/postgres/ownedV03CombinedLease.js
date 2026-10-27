'use strict';
// Timing contract only: no resource authority, process, guest lease or live export.
// Sequential reservations intentionally take no credit for overlapping cleanup.
const TARGET='original-v03-combined-preparation-lease-v1';
const BUDGET=Object.freeze({diagnosticBuildMs:1800000,listingsBuildMs:1800000,
 listingsSettlementMs:680000,diagnosticStartupMs:120000,listingsStartupMs:60000,
 originalWrapperMs:1800000,originalWrapperGraceMs:300000,
 diagnosticControllerJoinMs:6000,diagnosticLostReplyMs:330000,
 diagnosticCleanupMs:600000,listingsRetirementMs:1080000,listingsCleanupMs:2520000});
const COHORT_MS=1200000;
const ACTIVATION_MS=10000,INFRASTRUCTURE_MS=COHORT_MS+ACTIVATION_MS;
const TOTAL_MS=Object.values(BUDGET).reduce((a,b)=>a+b,0);
const PREPARE=['diagnosticBuildMs','listingsBuildMs','listingsSettlementMs','diagnosticStartupMs','listingsStartupMs'];
const RETIRE=['diagnosticControllerJoinMs','diagnosticLostReplyMs','diagnosticCleanupMs','listingsRetirementMs','listingsCleanupMs'];
const reserve=keys=>keys.reduce((n,k)=>n+BUDGET[k],0);
const fail=code=>Object.assign(new Error(code),{code});
const safe=n=>Number.isSafeInteger(n)&&n>=0&&n<=Number.MAX_SAFE_INTEGER-TOTAL_MS;
function createControlledOwner({runId,startedAtMs}){
 if(!/^[a-f0-9]{32}$/.test(runId||'')||!safe(startedAtMs))throw fail('V03_LEASE_INPUT');
 const expiresAtMs=startedAtMs+TOTAL_MS;
 const record=Object.freeze({version:1,target:TARGET,runId,clock:'owner-monotonic-ms',
  startedAtMs,expiresAtMs,budget:BUDGET,executionApproved:false});
 let observed=startedAtMs,index=0,active=null,wrapper=null,cohort=null,retirement=false,retireIndex=0;
 const ready=new Set(),claims=new Map();
 function current(now){
  if(!safe(now)||now<observed)throw fail('V03_CLOCK_REGRESSION');
  if(now>=expiresAtMs)throw fail('V03_LEASE_EXPIRED');observed=now;
 }
 function window(kind,now,deadlineMs){
  if(deadlineMs<=now)throw fail('V03_WINDOW_EXPIRED');
  return Object.freeze({kind,startedAtMs:now,deadlineMs,leaseExpiresAtMs:expiresAtMs,
   executionApproved:false,resourceAbsenceProven:false});
 }
 return Object.freeze({record,
  beginPreparation(kind,now){
   current(now);
   if(retirement||wrapper||active||PREPARE[index]!==kind)throw fail('V03_PREPARATION_ORDER');
   const remaining=reserve(PREPARE.slice(index+1))+BUDGET.originalWrapperMs+BUDGET.originalWrapperGraceMs+reserve(RETIRE);
   const end=Math.min(now+BUDGET[kind],expiresAtMs-remaining);
   active=window(kind,now,end);claims.set(kind,active);return active;
  },
  completePreparation(kind,now){
   current(now);
   if(retirement||!active||active.kind!==kind||now>=active.deadlineMs)throw fail('V03_PREPARATION_UNPROVEN');
   // Caller still must independently prove real readiness; this is a control model.
   if(kind==='diagnosticStartupMs')ready.add('diagnostic');
   if(kind==='listingsStartupMs')ready.add('listings');
   active=null;index++;
  },
  beginWrapper(now){
   current(now);
   if(retirement||wrapper||active||index!==PREPARE.length||ready.size!==2)throw fail('V03_BOTH_READY_REQUIRED');
   const end=now+BUDGET.originalWrapperMs,graceEnd=end+BUDGET.originalWrapperGraceMs;
   if(graceEnd+reserve(RETIRE)>expiresAtMs)throw fail('V03_WRAPPER_RESERVE');
   wrapper=Object.freeze({...window('original-wrapper',now,end),graceDeadlineMs:graceEnd});return wrapper;
  },
  claimCohort(now){
   current(now);
   if(retirement||!wrapper||cohort)throw fail('V03_COHORT_ONCE');
   const end=now+INFRASTRUCTURE_MS;
   if(end>wrapper.deadlineMs)throw fail('V03_FULL_COHORT_REQUIRED');
   cohort=window('original-v03-cohort',now,end);return cohort;
  },
  facadeDeadline(producer,now){
   current(now);
   if(!['diagnostic','listings'].includes(producer)||retirement||!cohort||now>=cohort.deadlineMs)throw fail('V03_COHORT_NOT_ACTIVE');
   return cohort.deadlineMs;
  },
  beginRetirement(kind,now){
   current(now);
   if(RETIRE[retireIndex]!==kind)throw fail('V03_RETIREMENT_ORDER');
   retirement=true;
   if(claims.has(kind))return claims.get(kind); // Never renew a claimed window.
   const end=Math.min(now+BUDGET[kind],expiresAtMs-reserve(RETIRE.slice(retireIndex+1)));
   if(kind==='diagnosticLostReplyMs'&&end-now!==BUDGET[kind])throw fail('V03_LOST_REPLY_RESERVE');
   const result=window(kind,now,end);claims.set(kind,result);return result;
  },
  completeRetirement(kind,now){
   current(now);const prior=claims.get(kind);
   if(!retirement||RETIRE[retireIndex]!==kind||!prior)throw fail('V03_RETIREMENT_UNPROVEN');
   if(kind==='diagnosticLostReplyMs' ? now<prior.deadlineMs : now>=prior.deadlineMs)
    throw fail('V03_RETIREMENT_UNPROVEN');
   retireIndex++;
  },
  // Timing-only transition: actual authority is the parent's synchronous,
  // private producer/driver consumption. This model never mints resource proof.
  completeUnstartedDiagnostic(now){
   current(now);const kind='diagnosticLostReplyMs',prior=claims.get(kind);
   if(!retirement||RETIRE[retireIndex]!==kind||!prior||now>=prior.deadlineMs)
    throw fail('V03_RETIREMENT_UNPROVEN');
   retireIndex++;
  },
  recordRetirementDebt(kind,now){
   current(now);
   if(!retirement||RETIRE[retireIndex]!==kind||!claims.has(kind))throw fail('V03_RETIREMENT_ORDER');
   if(kind==='diagnosticLostReplyMs'&&now<claims.get(kind).deadlineMs)throw fail('V03_RETIREMENT_UNPROVEN');
   // Moving to a later exact cleanup reservation does not prove that the
   // failed phase completed or that its resources/commands are absent.
   retireIndex++;
   return Object.freeze({kind,resourceAbsenceProven:false,retirementDebt:true});
  }
 });
}
module.exports={TARGET,BUDGET,COHORT_MS,ACTIVATION_MS,INFRASTRUCTURE_MS,TOTAL_MS,createControlledOwner};
