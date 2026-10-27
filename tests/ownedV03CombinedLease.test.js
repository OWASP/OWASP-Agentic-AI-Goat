'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const v=require('./postgres/ownedV03CombinedLease');
const old=require('./postgres/ownedMcpOriginalServiceLease');
const make=()=>v.createControlledOwner({runId:'a'.repeat(32),startedAtMs:1000});
const phases=['diagnosticBuildMs','listingsBuildMs','listingsSettlementMs','diagnosticStartupMs','listingsStartupMs'];
function ready(owner){let now=1000;for(const p of phases){owner.beginPreparation(p,now);owner.completePreparation(p,++now);}return now;}
test('source-derived conservative ledger contains wrapper rather than adding child again',()=>{
 assert.equal(v.TOTAL_MS,11096000);assert.equal(v.COHORT_MS,1200000);
 assert.equal(v.BUDGET.originalWrapperMs,1800000);assert.equal(v.BUDGET.originalWrapperGraceMs,300000);
 assert.equal(old.specification('listings-manager-browser').totalMs,6680000);
 assert.equal(old.specification('listings-manager-browser').phases.cohort,540000);
 assert.equal(make().record.executionApproved,false);
});
test('both preparations required and fixed order cannot be skipped or replayed',()=>{
 const o=make();assert.throws(()=>o.beginWrapper(1000),/BOTH_READY/);
 assert.throws(()=>o.beginPreparation('listingsBuildMs',1000),/ORDER/);
 o.beginPreparation(phases[0],1000);assert.throws(()=>o.beginPreparation(phases[0],1000),/ORDER/);
});
test('both facades share exactly one immutable full cohort deadline',()=>{
 const o=make(),now=ready(o);o.beginWrapper(now);const c=o.claimCohort(now+1);
 assert.equal(c.deadlineMs-(now+1),1210000);
 assert.equal(o.facadeDeadline('diagnostic',now+2),o.facadeDeadline('listings',now+3));
 assert.throws(()=>o.claimCohort(now+4),/ONCE/);
 assert.throws(()=>o.beginWrapper(now+4),/BOTH_READY/);
});
test('startup does not start a renewed 1200 second runtime timer',()=>{
 const o=make(),now=ready(o);assert.throws(()=>o.facadeDeadline('diagnostic',now),/NOT_ACTIVE/);
 const w=o.beginWrapper(now);assert.throws(()=>o.claimCohort(w.deadlineMs-1199999),/FULL_COHORT/);
});
test('late preparation cannot borrow terminal reservations',()=>{
 const o=make();assert.throws(()=>o.beginPreparation(phases[0],1000+1800000),/WINDOW_EXPIRED/);
});
test('failed preparation can retire but revokes cohort authority',()=>{
 const o=make();o.beginPreparation(phases[0],1000);
 o.beginRetirement('diagnosticControllerJoinMs',1001);
 assert.throws(()=>o.completePreparation(phases[0],1002),/UNPROVEN/);
 assert.throws(()=>o.beginWrapper(1002),/BOTH_READY/);
});
test('retirement claim is immutable and ordered; no cleanup success claim',()=>{
 const o=make(),a=o.beginRetirement('diagnosticControllerJoinMs',1000);
 assert.equal(o.beginRetirement('diagnosticControllerJoinMs',1001),a);
 assert.equal(a.resourceAbsenceProven,false);
 assert.throws(()=>o.beginRetirement('listingsCleanupMs',1002),/ORDER/);
 o.completeRetirement('diagnosticControllerJoinMs',1003);
 const lost=o.beginRetirement('diagnosticLostReplyMs',1003);
 assert.equal(lost.deadlineMs,331003);
 assert.throws(()=>o.completeRetirement('diagnosticLostReplyMs',1004),/UNPROVEN/);
 o.completeRetirement('diagnosticLostReplyMs',331003);
});
test('expiry, unsafe clock and backward time deny',()=>{
 assert.throws(()=>v.createControlledOwner({runId:'x',startedAtMs:0}),/INPUT/);
 const o=make();o.beginPreparation(phases[0],1001);
 assert.throws(()=>o.completePreparation(phases[0],1000),/CLOCK/);
 assert.throws(()=>o.beginWrapper(11097000),/EXPIRED/);
});
test('late retirement cannot shorten mandatory lost-reply wait',()=>{
 const o=make();o.beginRetirement('diagnosticControllerJoinMs',1000);
 o.completeRetirement('diagnosticControllerJoinMs',1001);
 const latest=o.record.expiresAtMs-v.BUDGET.diagnosticCleanupMs-v.BUDGET.listingsRetirementMs-v.BUDGET.listingsCleanupMs-v.BUDGET.diagnosticLostReplyMs;
 assert.throws(()=>o.beginRetirement('diagnosticLostReplyMs',latest+1),/LOST_REPLY_RESERVE/);
});
test('retirement revokes both facades immediately',()=>{
 const o=make(),now=ready(o);o.beginWrapper(now);o.claimCohort(now);
 o.beginRetirement('diagnosticControllerJoinMs',now+1);
 for(const p of ['diagnostic','listings'])assert.throws(()=>o.facadeDeadline(p,now+2),/NOT_ACTIVE/);
});
test('serialized timing record cannot reconstruct live authority',()=>{
 const o=make(),copy=JSON.parse(JSON.stringify(o.record));
 assert.equal(copy.executionApproved,false);assert.equal(copy.facadeDeadline,undefined);
 assert.equal(v.activate,undefined);assert.equal(v.guestSource,undefined);
});
