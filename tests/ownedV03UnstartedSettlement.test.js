'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),vm=require('node:vm');
const fs=require('node:fs');
// Read current production modules; no ignored proposal or preimage dependency.
const sources=Object.fromEntries(['ownedSystemConfigPhaseDriver','ownedSystemDiagnosticProducer',
 'ownedV03PrivateExecutors','ownedV03CombinedLease'].map(name=>[name,
 fs.readFileSync(require('node:path').join(__dirname,'postgres',name+'.js'),'utf8')]));
const Module=require('node:module'),path=require('node:path');
function fixture(){
 let revoked=false,window={kind:'diagnosticControllerJoinMs',deadlineMs:1000};
 const signal=new AbortController();
 const owner={isRevoked:()=>revoked,phaseWindow:kind=>{assert.equal(kind,window.kind);return window;},phaseSignal:()=>signal.signal,clockMapping:()=>({})};
 const code=sources.ownedSystemConfigPhaseDriver;
 const start=code.indexOf(' const claimDiagnosticRuntime=()=>{'),end=code.indexOf('\n return Object.freeze({directory,run:name=>phase(name)',start);
 const context={plan:{runId:'a'.repeat(32)},diagnostic:true,diagnosticImage:{target:'original-v03-diagnostic'},runtime:null,
  sequence:{busy:false,closed:false,failed:false,index:17},NORMAL:Array(17),debts:[],combinedOwner:owner,
  ordinal:17,cleanupEnd:null,notBefore:0,performance:{now:()=>100},Object,WeakMap,AbortController,
  error:code=>Object.assign(Error(code),{code}),freeze:Object.freeze,
  require:name=>name==='./ownedV03GuestClock'?{assertGuestClockMapping:()=>({binding:()=>({})})}:{}};
 vm.createContext(context);
 vm.runInContext(code.slice(code.indexOf('const unstartedSettlements='),code.indexOf('const PYTHON='))+code.slice(start,end)+'\nthis.handle=claimDiagnosticRuntime();this.consume=consumeUnstartedSettlement;',context);
 return {context,owner,signal,get window(){return window;},set window(v){window=v;},
  async settle(){revoked=true;context.handle.join();window={kind:'diagnosticLostReplyMs',deadlineMs:1000};await context.handle.settle();},
  consume:()=>context.consume(context.handle,owner,window)};
}
test('actual private runtime handle issues no serializable authority; same-owner settled epoch consumes once',async()=>{
 const f=fixture();await f.settle();
 assert.equal(f.context.consume({},f.owner,f.window),false);
 assert.equal(f.consume(),true);assert.equal(f.consume(),false);
});
test('cross-owner and stale-window proof fail closed and burn one-use eligibility',async()=>{
 for(const mode of ['owner','window']){
  const f=fixture();await f.settle();
  assert.equal(f.context.consume(f.context.handle,mode==='owner'?{}:f.owner,mode==='window'?{...f.window}:f.window),false);
  assert.equal(f.consume(),false);
 }
});
test('actual state changes, uncertainty, debt, late work and attempts deny early settlement',async()=>{
 const changes=[f=>f.context.ordinal++,f=>f.context.sequence.busy=true,f=>f.context.sequence.failed=true,
  f=>f.context.sequence.closed=true,f=>f.context.sequence.index--,f=>f.context.debts.push('FD_CLOSE'),
  f=>f.context.notBefore=1,f=>f.context.cleanupEnd=900,f=>f.context.runtime.failed=true,
  f=>f.context.runtime.bridgeAttempted=true,f=>f.context.runtime.claimAttempted=true,
  f=>f.context.runtime.started=true,f=>f.context.runtime.stopAttempted=true,f=>f.signal.abort(),
  f=>f.context.performance.now=()=>1000,
  async f=>{await assert.rejects(f.context.handle.startRuntime('ignored'));},
  async f=>{await assert.rejects(f.context.handle.claimCohort());}];
 for(const change of changes){const f=fixture();await f.settle();await change(f);assert.equal(f.consume(),false);}
});
test('actual timing model retains default 330s and all budgets, early transition is exact-phase one-shot',()=>{
 const box={module:{exports:{}},Object,Set,Map,Number,Error};vm.runInNewContext(sources.ownedV03CombinedLease,box);
 const api=box.module.exports;
 assert.equal(api.TOTAL_MS,11096000);assert.equal(api.COHORT_MS,1200000);assert.equal(api.BUDGET.diagnosticLostReplyMs,330000);
 const m=api.createControlledOwner({runId:'a'.repeat(32),startedAtMs:0});
 assert.throws(()=>m.completeUnstartedDiagnostic(1));
 m.beginRetirement('diagnosticControllerJoinMs',1);m.completeRetirement('diagnosticControllerJoinMs',2);
 const w=m.beginRetirement('diagnosticLostReplyMs',3);
 assert.equal(w.deadlineMs,330003);assert.throws(()=>m.completeRetirement('diagnosticLostReplyMs',4));
 assert.throws(()=>m.recordRetirementDebt('diagnosticLostReplyMs',4));
 m.completeUnstartedDiagnostic(4);assert.throws(()=>m.completeUnstartedDiagnostic(5));
 const c=m.beginRetirement('diagnosticCleanupMs',5);assert.equal(c.deadlineMs,600005);
 assert.equal(m.record.expiresAtMs,11096000);
});
test('actual parent failure orchestration skips only proven idle branch; overlap and debt retain full wait',async()=>{
 for(const scenario of ['idle','overlap','debt','unproven']){
  const timingBox={module:{exports:{}}};vm.runInNewContext(sources.ownedV03CombinedLease,timingBox);
  const filename=path.resolve('tests/postgres/ownedV03PrivateExecutors.js'),m=new Module(filename,module);
  m.filename=filename;m.paths=Module._nodeModulePaths(path.dirname(filename));
  const original=m.require.bind(m);let consumed=0;
  m.require=name=>name==='./ownedV03CombinedLease'?timingBox.module.exports:
   name==='./ownedSystemDiagnosticProducer'?{consumeUnstartedDiagnostic:()=>{consumed++;return scenario!=='unproven';}}:original(name);
  m._compile(sources.ownedV03PrivateExecutors+'\nmodule.exports.seam={mintOwner,controllerFor};',filename);
  let now=100,waited=0;
  const binding=m.exports.seam.mintOwner('a'.repeat(32),'b'.repeat(64),()=>now);
  const cleanup=async()=>({cleanupVerified:true,resourceAbsenceProven:true});
  const diagnostic={prepare:async()=>{},start:async()=>{throw Error('must not start');},join:async()=>{},settle:async()=>{},retire:cleanup};
  const failure=Object.assign(Error('listings settlement'),scenario==='debt'?{cleanupDebt:true}:{});
  const listings={prepare:async()=>{},settle:async()=>{
   if(scenario==='overlap'){const p=Promise.resolve();binding.state.pending.add(p);p.then(()=>queueMicrotask(()=>binding.state.pending.delete(p)));}
   throw failure;
  },join:async()=>{},retire:cleanup};
  // Explicit externally pending work at retirement entry is retained even if
  // already resolved; the private parent may not infer no overlap from join.
  if(scenario==='overlap'){
   const p=Promise.resolve();binding.state.pending.add(p);
   diagnostic.join=async()=>{binding.state.pending.delete(p);};
  }
  const controller=m.exports.seam.controllerFor(binding,diagnostic,listings,async end=>{waited++;now=end;});
  await assert.rejects(controller.start(),e=>e===failure);
  assert.equal(waited,scenario==='idle'?0:1);
  assert.equal(consumed,['idle','unproven'].includes(scenario)?1:0);
  assert.equal(binding.state.model.record.expiresAtMs,11096100);
 }
});
