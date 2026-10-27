'use strict';
// Prospective Pricing-only lease. A validated DTO is not execution authority.
const {isDeepStrictEqual:equal}=require('node:util');
const BUDGET=Object.freeze({setup:180000,metadata:300000,artifacts:300000,build:300000,cohort:600000,localJoin:6000,remoteUncertainty:330000,retirement:600000});
const TOTAL_MS=Object.values(BUDGET).reduce((a,b)=>a+b,0),TARGET='original-v33-pricing-total-lease-v1';
const fail=code=>Object.assign(new Error(code),{code});
const PROFILES=Object.freeze({
 v33:Object.freeze({target:TARGET,totalMs:TOTAL_MS,budget:BUDGET}),
 'v34-browser':Object.freeze({target:'original-v34-pricing-total-lease-v1',totalMs:3016000,budget:Object.freeze({...BUDGET,cohort:1000000})}),
 'v25-manual':Object.freeze({target:'original-v25-pricing-total-lease-v1',totalMs:2856000,budget:Object.freeze({...BUDGET,cohort:840000})}),
});
function profile(name='v33'){
 if(typeof name!=='string'||!Object.hasOwn(PROFILES,name))throw fail('PRICING_LEASE_PROFILE');
 return PROFILES[name];
}
const time=(n,total=TOTAL_MS)=>Number.isSafeInteger(n)&&n>=0&&n<=Number.MAX_SAFE_INTEGER-total;
function proposal(runId,start,name='v33'){
 const p=profile(name);
 if(typeof runId!=='string'||!/^[a-f0-9]{32}$/.test(runId)||!time(start,p.totalMs))throw fail('PRICING_LEASE_INPUT');
 return Object.freeze({version:1,target:p.target,runId,clock:'linux-monotonic-ms',startedAtMs:start,expiresAtMs:start+p.totalMs,budget:p.budget,executionApproved:false});
}
function validate(record,runId,now,name='v33'){
 const p=profile(name);
 if(!record||!equal(record,proposal(runId,record.startedAtMs,name))||!time(now,p.totalMs)||now<record.startedAtMs)throw fail('PRICING_LEASE_RECORD');
 if(now>=record.expiresAtMs)throw fail('PRICING_LEASE_EXPIRED');return record;
}
function createControlledOwner(runId,start,name='v33'){
 const record=proposal(runId,start,name),BUDGET=profile(name).budget,steps=['setup','metadata','artifacts','build','cohort'];let index=0,last=start,current=null,retirement=null,uncertainUntil=0,uncertain=false;
 const check=now=>{validate(record,runId,now,name);if(now<last)throw fail('PRICING_CLOCK_REGRESSION');last=now;};
 return Object.freeze({record,
  claim(name,now){check(now);if(retirement!==null||uncertain||name!==steps[index]||current)throw fail('PRICING_PHASE_ORDER');
   const reserve=steps.slice(index+1).reduce((n,key)=>n+BUDGET[key],0)+BUDGET.localJoin+BUDGET.remoteUncertainty+BUDGET.retirement;
   const deadline=index===0?record.startedAtMs+BUDGET.setup:now+BUDGET[name];
   if(now>=deadline||deadline+reserve>record.expiresAtMs)throw fail('PRICING_PHASE_RESERVE');
   current={name,deadline};index++;return Object.freeze({...current});},
  complete(name,now){check(now);if(!current||current.name!==name||now>=current.deadline||retirement!==null||uncertain)throw fail('PRICING_PHASE_COMPLETION');current=null;},
  lostReply(now,remoteSeconds){check(now);if(retirement!==null||uncertain||![150,310].includes(remoteSeconds))throw fail('PRICING_REMOTE_UNCERTAINTY');
   uncertain=true;uncertainUntil=now+(remoteSeconds+20)*1000;
   if(uncertainUntil+BUDGET.localJoin+BUDGET.retirement>record.expiresAtMs)throw fail('PRICING_RETIREMENT_RESERVE');return uncertainUntil;},
  retire(now){check(now);if(now<uncertainUntil)throw fail('PRICING_REMOTE_WAIT');if(retirement===null){if(now+BUDGET.retirement>record.expiresAtMs)throw fail('PRICING_RETIREMENT_RESERVE');retirement=now+BUDGET.retirement;}
   if(now>=retirement)throw fail('PRICING_RETIREMENT_EXPIRED');return Object.freeze({deadline:retirement,absenceProven:false});},
 });
}
module.exports={BUDGET,TOTAL_MS,TARGET,profile,proposal,validate,createControlledOwner};
