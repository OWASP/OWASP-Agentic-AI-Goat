'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),Module=require('node:module');
const file=path.join(__dirname,'postgres/ownedV03PrivateExecutors.js');
// Offline-only exact-source extraction. The production module never exports a
// mint function and this extracted instance has a separate private WeakMap.
function controls(transform=source=>source){
 const extracted=new Module(file,module);extracted.filename=file;
 extracted.paths=Module._nodeModulePaths(path.dirname(file));
 extracted._compile(transform(fs.readFileSync(file,'utf8'))+'\nmodule.exports.control={mintOwner,controllerFor,watchOwnerChannel,registerGuestClock};',file);
 return extracted.exports;
}
function setup(){
 const api=controls(),events=[];let now=100;
 const binding=api.control.mintOwner('a'.repeat(32),'b'.repeat(64),()=>now);
 const producer=name=>Object.fromEntries(['prepare','settle','start','claimCohort','join','retire'].map(method=>[method,async()=>{
  events.push(name+':'+method);now++;
  if(method==='claimCohort'){
   binding.owner.cohortDeadlineMs();
   return name==='diagnostic'?{url:'http://127.0.0.1:23456',token:'t'.repeat(48)}:{environment:{}};
  }
  if(method==='retire')return {cleanupVerified:true,resourceAbsenceProven:true};
  return {ready:true};
 }]));
 const diagnostic=producer('diagnostic'),listings=producer('listings');
 return {api,binding,events,diagnostic,listings,waitUntil:async deadline=>{now=deadline;},make:()=>api.control.controllerFor(binding,diagnostic,listings,async deadline=>{now=deadline;})};
}
test('enabled production entry rejects invalid options and JSON/callable owners cannot mint authority',async()=>{
 const api=require('./postgres/ownedV03PrivateExecutors');
 await assert.rejects(api.createPrivateExecutors({}),{code:'V03_PARENT_OPTIONS'});
 assert.throws(()=>api.assertCombinedOwner({remainingMs:()=>11096000}),{code:'V03_COMBINED_OWNER_REQUIRED'});
 assert.equal(api.mintOwner,undefined);
});
test('explicitly closed gate rejects before owner or producer admission',async()=>{
 const api=controls(source=>{
  assert.equal(source.split('const LIVE_ENABLED=true;').length,2);
  return source.replace('const LIVE_ENABLED=true;','const LIVE_ENABLED=false;');
 });
 await assert.rejects(api.createPrivateExecutors({}),{code:'V03_COMPOSED_PRODUCERS_NOT_ADMITTED'});
});
test('clock registration rejects missing, out-of-phase and callable-shaped mapping authority',()=>{
 const s=setup(),owner=s.binding.owner;
 assert.throws(()=>owner.clockMapping(),{code:'V03_CLOCK_NOT_ADMITTED'});
 assert.throws(()=>s.api.control.registerGuestClock(s.binding,{}),{code:'V03_CLOCK_REGISTRATION_PHASE'});
 s.binding.state.window=s.binding.state.model.beginPreparation('diagnosticBuildMs',s.binding.now());
 s.binding.state.phaseAbort=new AbortController();
 assert.throws(()=>s.api.control.registerGuestClock(s.binding,{mapDeadline:x=>x,binding:()=>owner.binding()}),
  {code:'V03_CLOCK_MAPPING_REQUIRED'});
 assert.throws(()=>owner.clockMapping(),{code:'V03_CLOCK_NOT_ADMITTED'});
 s.binding.state.phaseAbort.abort();
 assert.throws(()=>s.api.control.registerGuestClock(s.binding,{}),{code:'V03_PHASE_NOT_ACTIVE'});
});
test('actual controller builds both before either startup and claims one full immutable cohort',async()=>{
 const s=setup(),c=s.make();await c.start();
 assert.deepEqual(s.events,['diagnostic:prepare','listings:prepare','listings:settle','diagnostic:start','listings:start']);
 const claim=await c.claimCohort();assert.equal(claim.originalChildMs,1200000);
 assert.equal(claim.infrastructureMsAtClaim-claim.activationMsAtClaim,1200000);
 const end=c.owner.cohortDeadlineMs();
 await assert.rejects(c.claimCohort(),{code:'V03_COHORT_ONCE'});
 assert.equal(c.owner.cohortDeadlineMs(),end);
});
test('retirement revokes before either producer and attempts both despite first failure',async()=>{
 const s=setup();s.diagnostic.retire=async()=>{assert.equal(s.binding.owner.isRevoked(),true);s.events.push('diagnostic:failed');throw Error('unknown');};
 const c=s.make();await c.start();const receipt=await c.retire('eof');
 assert.equal(receipt.cleanupVerified,false);assert.equal(receipt.diagnosticAbsent,false);assert.equal(receipt.listingsAbsent,true);
 assert.equal(s.events.filter(x=>x==='listings:retire').length,1);
 assert.strictEqual(await c.retire('again'),receipt);
});
test('preparation failure retains original error and retires both',async()=>{
 const s=setup(),original=Error('build');s.diagnostic.prepare=async()=>{throw original;};
 const c=s.make();await assert.rejects(c.start(),e=>e===original);
 assert.deepEqual(s.events,['diagnostic:join','diagnostic:settle','diagnostic:retire','listings:join','listings:retire']);
});
test('parent-only preparation debt survives otherwise successful producer cleanup',async()=>{
 const s=setup(),original=Object.assign(Error('owned parent file remains'),{code:'V03_CLOCK_FILE_CLOSE',cleanupDebt:true});
 s.diagnostic.prepare=async()=>{throw original;};
 const c=s.make();await assert.rejects(c.start(),e=>e===original);
 const receipt=await c.retire('again');
 assert.equal(receipt.cleanupVerified,false);
 assert.equal(receipt.diagnosticAbsent,true);assert.equal(receipt.listingsAbsent,true);
 assert.ok(receipt.errors.some(row=>row.producer==='combined'&&row.code==='V03_CLOCK_FILE_CLOSE'));
 assert.equal(c.status().cleanupVerified,false);
});
test('revocation during pending preparation cannot resurrect readiness',async()=>{
 const s=setup();let resolve;s.diagnostic.prepare=()=>new Promise(r=>resolve=r);
 const c=s.make(),starting=c.start();await Promise.resolve();
 const signal=s.binding.owner.phaseSignal('diagnosticBuildMs');
 const retiring=c.retire('eof');assert.equal(signal.aborted,true);
 let closed=false;retiring.then(()=>{closed=true;});await Promise.resolve();assert.equal(closed,false);
 resolve();await retiring;
 await assert.rejects(starting,{code:'V03_OWNER_REVOKED'});
 assert.equal(c.status().stage,'closed');
});
test('inherited channel EOF autonomously retires both once without child close RPC',async()=>{
 const s=setup(),c=s.make(),wire=new(require('node:events').EventEmitter)(),timers=[];
 const guard=s.api.control.watchOwnerChannel(c,wire,()=>100,(fn,ms)=>{timers.push({fn,ms});return timers.length;},()=>{});
 await c.start();wire.emit('end');wire.emit('close');await Promise.resolve();
 const result=await guard.close();assert.equal(result.cleanupVerified,true);
 assert.equal(s.events.filter(x=>x==='diagnostic:retire').length,1);
 assert.equal(s.events.filter(x=>x==='listings:retire').length,1);
 assert.equal(wire.listenerCount('end'),0);
});
test('absolute owner and cohort watchdogs use existing deadlines without renewal',async()=>{
 const s=setup(),c=s.make(),wire=new(require('node:events').EventEmitter)(),timers=[];
 const guard=s.api.control.watchOwnerChannel(c,wire,()=>100,(fn,ms)=>{timers.push({fn,ms});return timers.length;},()=>{});
 assert.equal(timers[0].ms,11096000);
 await c.start();const claim=await c.claimCohort();guard.armCohort();
 assert.equal(timers[1].ms,c.owner.cohortDeadlineMs()-100);
 assert.throws(()=>guard.armCohort(),{code:'V03_WATCHDOG_COHORT_ONCE'});
 timers[1].fn();await guard.close();assert.equal(c.owner.isRevoked(),true);
});
test('unjoined phase deadline aborts capability and cannot become cleanup success',async()=>{
 const s=setup(),timers=[];let signal;
 s.diagnostic.prepare=()=>{signal=s.binding.owner.phaseSignal('diagnosticBuildMs');return new Promise((resolve,reject)=>signal.addEventListener('abort',()=>reject(Error('aborted'))));};
 const c=s.api.control.controllerFor(s.binding,s.diagnostic,s.listings,async()=>{},
  fn=>{timers.push(fn);return timers.length;},()=>{});
 const starting=c.start();await Promise.resolve();timers[0]();
 await assert.rejects(starting,{code:'V03_PHASE_UNJOINED'});
 assert.equal(signal.aborted,true);
 assert.equal((await c.retire('again')).cleanupVerified,false);
});
test('never-resolving cohort claim is bounded and unresolved work remains debt',async()=>{
 const s=setup(),timers=new Map();let id=0;
 const c=s.api.control.controllerFor(s.binding,s.diagnostic,s.listings,s.waitUntil,
  fn=>{timers.set(++id,fn);return id;},key=>timers.delete(key));
 await c.start();s.diagnostic.claimCohort=()=>new Promise(()=>{});
 const claiming=c.claimCohort();const observed=assert.rejects(claiming,{code:'V03_PHASE_UNJOINED'});
 await new Promise(setImmediate);
 assert.equal(timers.size,1);[...timers.values()][0]();
 await new Promise(setImmediate);
 // The abandoned claim must also be bounded by the controller-join reserve.
 assert.equal(timers.size,1);[...timers.values()][0]();
 await observed;
 const receipt=await c.retire('again');assert.equal(receipt.cleanupVerified,false);
 assert.ok(receipt.errors.some(row=>row.code==='V03_PHASE_UNJOINED'));
});
test('V03 Listings profile consumes branded windows and preserves old profile literals',async()=>{
 const s=setup(),profileFile=path.join(__dirname,'postgres/ownedV03ListingsProfile.js');
 const extracted=new Module(profileFile,module);extracted.filename=profileFile;
 extracted.paths=Module._nodeModulePaths(path.dirname(profileFile));
 const originalRequire=extracted.require.bind(extracted);
 extracted.require=name=>name==='./ownedV03PrivateExecutors'?s.api:originalRequire(name);
 extracted._compile(fs.readFileSync(profileFile,'utf8'),profileFile);
 const profile=extracted.exports.forOwner(s.binding.owner);
 assert.throws(()=>profile.phase('build'),{code:'V03_PHASE_NOT_ACTIVE'});
 s.listings.prepare=async()=>{
  const window=profile.phase('build');assert.equal(window.signal.aborted,false);
  assert.equal(window.deadlineMs-s.binding.owner.nowMs(),1800000);
 };
 const c=s.make();await c.start();await c.claimCohort();
 assert.equal(profile.channelDeadlineMs()-s.binding.owner.nowMs(),120000);
 assert.equal(profile.cohortDeadlineMs(),c.owner.cohortDeadlineMs());
 const old=require('./postgres/ownedMcpOriginalServiceLease').specification('listings-manager-browser');
 assert.equal(old.totalMs,6680000);assert.equal(old.phases.cohort,540000);
 assert.throws(()=>extracted.exports.forOwner(JSON.parse(JSON.stringify(s.binding.owner))),{code:'V03_COMBINED_OWNER_REQUIRED'});
});
test('producer runs are fixed domain-separated children of one parent expiry',()=>{
 const s=setup(),owner=s.binding.owner,a=owner.producerBinding('diagnostic'),b=owner.producerBinding('listings');
 assert.notEqual(a.runId,b.runId);assert.notEqual(a.runId,a.parentRunId);
 assert.equal(a.parentRunId,owner.binding().runId);assert.equal(b.parentRunId,a.parentRunId);
 assert.equal(a.expiresAtMs,b.expiresAtMs);assert.equal(a.expiresAtMs,owner.binding().expiresAtMs);
 assert.strictEqual(owner.producerBinding('diagnostic'),a);
 assert.throws(()=>owner.producerBinding('caller-selected'),{code:'V03_PRODUCER_KIND'});
});
test('late preparation settlement cannot invoke join after join window was abandoned',async()=>{
 const s=setup(),timers=new Map();let id=0,resolve;
 s.diagnostic.prepare=()=>new Promise(r=>resolve=r);
 const c=s.api.control.controllerFor(s.binding,s.diagnostic,s.listings,s.waitUntil,
  fn=>{timers.set(++id,fn);return id;},key=>timers.delete(key));
 const starting=c.start(),observed=assert.rejects(starting,{code:'V03_OWNER_REVOKED'});
 await new Promise(setImmediate);const retirement=c.retire('eof');
 await new Promise(setImmediate);assert.equal(timers.size,1);[...timers.values()][0]();
 const receipt=await retirement;assert.equal(receipt.cleanupVerified,false);
 resolve();await observed;await new Promise(setImmediate);
 assert.equal(s.events.includes('diagnostic:join'),false);
 assert.equal(c.status().cleanupVerified,false);
});
test('claim completion after activation allowance cannot admit browser workload',async()=>{
 const s=setup(),c=s.make();await c.start();
 s.diagnostic.claimCohort=async()=>{await s.waitUntil(s.binding.owner.nowMs()+10000);};
 await assert.rejects(c.claimCohort(),{code:'V03_PHASE_EXPIRED'});
 assert.equal(s.events.includes('listings:claimCohort'),false);
 assert.equal(c.owner.isRevoked(),true);
});
test('slow preparation preserves admission sample rather than subtracting work twice',async()=>{
 const s=setup(),advance=kind=>async()=>{await s.waitUntil(s.binding.owner.phaseWindow(kind).deadlineMs-1);return {ready:true};};
 s.diagnostic.prepare=advance('diagnosticBuildMs');s.listings.prepare=advance('listingsBuildMs');
 s.listings.settle=advance('listingsSettlementMs');s.diagnostic.start=advance('diagnosticStartupMs');
 s.listings.start=advance('listingsStartupMs');
 const c=s.make(),response=await c.start();
 assert.equal(response.parentRemainingMsAtAdmission,11096000);
 assert.equal(c.owner.remainingMs(),6636005);
});
test('both guest and local pipe clock uncertainty consume the same activation allowance',async()=>{
 const s=setup(),c=s.make();await c.start();
 // Offline internal-state injection only; production registration stays branded.
 s.binding.state.guestClock={uncertaintyMs:()=>700};
 s.listings.claimCohort=async()=>({environment:{},additionalClockUncertaintyMs:600});
 const result=await c.claimCohort();assert.equal(result.clockUncertaintyMs,1300);
 assert.equal(result.originalChildMs,1200000);assert.equal(result.infrastructureMsAtClaim,1210000);
});
test('combined uncertainty above bound or too-late mapped claim cannot dispatch shortened work',async()=>{
 for(const late of [false,true]){
  const s=setup(),c=s.make();await c.start();s.binding.state.guestClock={uncertaintyMs:()=>1200};
  s.listings.claimCohort=async()=>{
   if(late)await s.waitUntil(s.binding.owner.nowMs()+9000);
   return {environment:{},additionalClockUncertaintyMs:late?200:1000};
  };
  await assert.rejects(c.claimCohort(),{code:late?'V03_ACTIVATION_EXPIRED':'V03_CLOCK_UNCERTAINTY'});
  assert.equal(c.owner.isRevoked(),true);
 }
});
