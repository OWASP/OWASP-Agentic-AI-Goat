'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),lease=require('./postgres/ownedPricingRuntimeLease');
const run='a'.repeat(32);
test('V25 manual uses its original840s child and unchanged600s retirement, never V33/V34 authority',()=>{
 const p=lease.profile('v25-manual'),r=lease.proposal(run,0,'v25-manual');
 assert.equal(p.totalMs,2856000);assert.equal(p.budget.cohort,840000);
 assert.deepEqual({...p.budget,cohort:600000},lease.BUDGET);
 assert.equal(lease.validate(r,run,1,'v25-manual'),r);
 for(const other of ['v33','v34-browser'])assert.throws(()=>lease.validate(r,run,1,other),/RECORD/);
 const o=lease.createControlledOwner(run,0,'v25-manual');let n=0;
 for(const name of ['setup','metadata','artifacts','build']){o.claim(name,n);o.complete(name,++n);}
 const child=o.claim('cohort',n);assert.equal(child.deadline,n+840000);
 assert.throws(()=>o.claim('cohort',n+1),/ORDER/);
 assert.throws(()=>o.complete('cohort',child.deadline),/COMPLETION/);
 const retired=o.retire(child.deadline);assert.equal(retired.deadline,child.deadline+600000);
 assert.equal(o.retire(child.deadline+1).deadline,retired.deadline);
 assert.throws(()=>o.retire(retired.deadline),/EXPIRED/);
});
test('V34 is a closed 1416+1000+600 profile and never enlarges V33',()=>{
 const p=lease.profile('v34-browser'),r=lease.proposal(run,100,'v34-browser');
 assert.equal(p.totalMs,3016000);assert.equal(p.budget.cohort,1000000);
 assert.deepEqual({...p.budget,cohort:600000},lease.BUDGET);
 assert.equal(lease.profile().totalMs,2616000);assert.equal(lease.profile().budget.cohort,600000);
 assert.equal(lease.validate(r,run,101,'v34-browser'),r);
 assert.throws(()=>lease.validate(r,run,101),/RECORD/);
 assert.throws(()=>lease.validate(lease.proposal(run,100),run,101,'v34-browser'),/RECORD/);
 for(const name of [null,'v34',3016000,{},'toString'])assert.throws(()=>lease.profile(name),/PROFILE/);
 const o=lease.createControlledOwner(run,0,'v34-browser');let n=0;
 for(const name of ['setup','metadata','artifacts','build']){o.claim(name,n);o.complete(name,++n);}
 const child=o.claim('cohort',n);assert.equal(child.deadline,n+1000000);
 // Startup consumes this window; neither readiness nor a retry reclaims it.
 assert.throws(()=>o.claim('cohort',n+100),/ORDER/);
 assert.throws(()=>o.complete('cohort',child.deadline),/COMPLETION/);
 const end=o.retire(child.deadline);assert.equal(end.deadline,child.deadline+600000);
 assert.equal(o.retire(child.deadline+1).deadline,end.deadline);
 assert.throws(()=>o.retire(end.deadline),/EXPIRED/);
});
test('Pricing original windows total2616s; no generic build/runtime authority',()=>{
 assert.equal(lease.TOTAL_MS,2616000);const r=lease.proposal(run,100);assert.equal(r.executionApproved,false);
 assert.equal(lease.validate(r,run,101),r);assert.throws(()=>lease.validate({...r,expiresAtMs:r.expiresAtMs+1},run,101));
 assert.throws(()=>lease.validate(r,'b'.repeat(32),101));assert.throws(()=>lease.validate(r,run,r.expiresAtMs));
});
test('phases are ordered single use and preserve full future cohort/retirement reservations',()=>{
 const o=lease.createControlledOwner(run,0);assert.throws(()=>o.claim('cohort',0));
 let n=0;for(const name of ['setup','metadata','artifacts','build','cohort']){o.claim(name,n);assert.throws(()=>o.claim(name,n));n+=1;o.complete(name,n);}
 assert.throws(()=>o.claim('cohort',n));const first=o.retire(n);assert.equal(o.retire(n+10).deadline,first.deadline);
 assert.throws(()=>o.retire(first.deadline));assert.throws(()=>o.claim('setup',n));
});
test('uncertain reply terminalizes work and waiting does not establish remote absence',()=>{
 const o=lease.createControlledOwner(run,0);o.claim('setup',0);const until=o.lostReply(1,310);
 assert.throws(()=>o.complete('setup',2));assert.throws(()=>o.claim('metadata',2));assert.throws(()=>o.retire(until-1));
 assert.equal(o.retire(until).absenceProven,false);assert.throws(()=>o.lostReply(until,310));
});
test('late admission and clock regression fail closed without renewing lease',()=>{
 const o=lease.createControlledOwner(run,0);assert.throws(()=>o.claim('setup',180000),/RESERVE/);
 const p=lease.createControlledOwner(run,0);p.claim('setup',0);p.complete('setup',1);assert.throws(()=>p.claim('metadata',0),/REGRESSION/);
});
