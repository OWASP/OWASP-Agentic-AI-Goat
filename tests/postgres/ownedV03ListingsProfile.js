'use strict';
// Fixed V03-only views of the real combined owner's current reservations.
// These views neither mint ownership nor create a fresh timer. Existing
// listings-manager-browser 540/600/6680 specifications are not modified.
const {assertCombinedOwner}=require('./ownedV03PrivateExecutors');
const {BUDGET,COHORT_MS,INFRASTRUCTURE_MS,TOTAL_MS}=require('./ownedV03CombinedLease');
const fail=code=>Object.assign(new Error(code),{code});
const TARGET='original-v03-listings-combined-owner-v1';
const PHASES=Object.freeze({build:'listingsBuildMs',settlement:'listingsSettlementMs',
 startup:'listingsStartupMs',retirement:'listingsRetirementMs',cleanup:'listingsCleanupMs'});
const SPECIFICATION=Object.freeze({version:1,target:TARGET,cohortMs:COHORT_MS,
 infrastructureMs:INFRASTRUCTURE_MS,
 parentMs:TOTAL_MS,buildMs:BUDGET.listingsBuildMs,settlementMs:BUDGET.listingsSettlementMs,
 startupMs:BUDGET.listingsStartupMs,retirementMs:BUDGET.listingsRetirementMs,
 cleanupMs:BUDGET.listingsCleanupMs,channelMs:120000,executionApproved:false});
function forOwner(owner){
 assertCombinedOwner(owner);
 const initial=owner.producerBinding('listings');
 return Object.freeze({
  binding(){
   assertCombinedOwner(owner);
   if(owner.producerBinding('listings')!==initial)throw fail('V03_LISTINGS_OWNER_CHANGED');
   return initial;
  },
  phase(name){
   assertCombinedOwner(owner);
   if(!Object.hasOwn(PHASES,name)||owner.isRevoked()&&!['retirement','cleanup'].includes(name))
    throw fail('V03_LISTINGS_PHASE');
   const kind=PHASES[name],window=owner.phaseWindow(kind);
   if(window.deadlineMs>initial.expiresAtMs||window.deadlineMs-window.startedAtMs>BUDGET[kind])
    throw fail('V03_LISTINGS_WINDOW');
   return Object.freeze({deadlineMs:window.deadlineMs,signal:owner.phaseSignal(kind)});
  },
  cohortDeadlineMs(){assertCombinedOwner(owner);return owner.cohortDeadlineMs();},
  // Per-request cap is retained; the actual channel must also check the
  // immutable common cohort end immediately before dispatch and while pumping.
  channelDeadlineMs(){
   const now=owner.nowMs();
   const end=owner.cohortDeadlineMs();
   if(now>=end)throw fail('V03_LISTINGS_COHORT_EXPIRED');
   return Math.min(end,now+SPECIFICATION.channelMs);
  }
 });
}
module.exports={TARGET,SPECIFICATION,forOwner};
