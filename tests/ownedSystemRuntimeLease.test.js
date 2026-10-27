'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path');
const lease=require('./postgres/ownedSystemRuntimeLease');
const binding=()=>({runId:'a'.repeat(32),planSha256:'b'.repeat(64),guestMonotonicMs:100000});
test('System budget arithmetic is explicit and retains original workload/cleanup caps',()=>{
 assert.deepEqual(lease.BUDGET,{buildOwnerMs:1800000,originalCohortMs:900000,localControllerJoinMs:6000,remoteLostReplyMs:330000,cleanupMs:600000});
 assert.equal(lease.TOTAL_MS,3636000);assert.equal(lease.proposal(binding()).executionApproved,false);
});
test('absolute guest windows are claimed once and never reset by cleanup polling',()=>{
 const owner=lease.createControlledOwner(binding()),start=binding().guestMonotonicMs;
 assert.equal(owner.beginBuild(start+1000).deadlineMs,start+1800000);
 assert.throws(()=>owner.beginBuild(start+2000),/ALREADY_CLAIMED/);
 const cohort=owner.beginCohort(start+1800000);assert.equal(cohort.deadlineMs,start+2700000);
 assert.throws(()=>owner.beginCohort(start+1800001),/NOT_ADMITTED/);
 const uncertain=owner.recordLostReply(cohort.deadlineMs+6000,310);
 assert.equal(uncertain.deadlineMs,start+3036000);assert.equal(uncertain.resourceAbsenceProven,false);
 assert.throws(()=>owner.beginCleanup(uncertain.deadlineMs-1),/WAIT_PENDING/);
 const cleanup=owner.beginCleanup(uncertain.deadlineMs);assert.equal(cleanup.deadlineMs,start+3636000);
 assert.equal(owner.beginCleanup(uncertain.deadlineMs+1000).deadlineMs,cleanup.deadlineMs);
 assert.throws(()=>owner.beginCleanup(cleanup.deadlineMs),/LEASE_EXPIRED/);
});
test('no original cohort may start without full900s plus unchanged recovery reserves',()=>{
 const owner=lease.createControlledOwner(binding());owner.beginBuild(100000);
 assert.throws(()=>owner.beginCohort(1900001),/COHORT_RESERVE/);
});
test('wrong target, clock, binding, budget, reset and extra fields reject',()=>{
 const base=lease.proposal(binding());
 for(const change of [
  r=>r.clock='host-performance',r=>r.target='v23',r=>r.startedAtMs++,r=>r.expiresAtMs++,
  r=>r.budget={...r.budget,originalCohortMs:120000},r=>r.executionApproved=true,r=>r.extra=true,
  r=>r.runId='c'.repeat(32),r=>r.planSha256='d'.repeat(64)
 ]){const r=structuredClone(base);change(r);assert.throws(()=>lease.validate(r,binding()));}
 assert.throws(()=>lease.proposal({...binding(),guestMonotonicMs:NaN}));
 assert.throws(()=>lease.proposal({...binding(),guestMonotonicMs:true}));
 for(const changed of [{runId:'wrong'},{planSha256:'wrong'}]){
  assert.throws(()=>lease.validate({...base,...changed},{...binding(),...changed}));
 }
});
test('same guest monotonic clock cannot move backwards or silently refresh holder',()=>{
 const owner=lease.createControlledOwner(binding());
 const initial=owner.holderRemainingSeconds(100000),later=owner.holderRemainingSeconds(101001);
 assert.equal(initial,3636);assert.equal(later,3635);assert.throws(()=>owner.holderRemainingSeconds(100500),/CLOCK_REGRESSION/);
 assert.equal(owner.record.expiresAtMs,3736000);assert(Object.isFrozen(owner.record.budget));
});
test('source anchors preserve shared V23 holder900 and original policy-instruction cohort limits',async()=>{
 const root=path.resolve(__dirname,'..'),read=p=>fs.readFile(path.join(root,p),'utf8');
 const [bounded,driver,main,scenario,owner]=await Promise.all([
  read('tests/postgres/ownedMcpBoundedBuild.js'),read('tests/postgres/ownedSystemConfigPhaseDriver.js'),
  read('tests/postgres/run-secureshop-agent-host-transport-main.py'),
  read('tests/postgres/secureshopStandaloneRoleChoicesRendered.integration.test.js'),
  read('tests/postgres/ownedSystemOriginalBrowserOwner.js')]);
 assert(bounded.includes('setsid /usr/bin/unshare --net -- /usr/bin/sleep 900'));
 assert(driver.includes('deadline-performance.now()>1800000'));assert(driver.includes('cleanupEnd ||= performance.now()+600000'));
 assert(driver.includes("['metadataFetch','startArtifacts','build'].includes(name)?310:150"));
 assert(driver.includes('remoteSeconds||310)+20'));assert(driver.includes('remoteUncertain:true})),6000)'));
 assert(main.includes('V24_OWNER_TOTAL_SECONDS = 3636'));
 assert(main.includes("[args.node, str(source / V24_OWNER), '--owned-main-input', str(grant_path)]"));
 assert(owner.includes('cohort:900000'));assert(owner.includes('endpoint.deadline-performance.now()>900000'));
 assert(scenario.includes('ADMIN_POLICY_BROWSER ? 840000 : 600000'));
 assert(scenario.includes('POLICY_INSTRUCTION_BROWSER ? 24'));assert(scenario.includes('status.roleTurns = 4'));
});

