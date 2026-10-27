'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs');
const path=require('node:path'),vm=require('node:vm'),crypto=require('node:crypto');
const file=path.join(__dirname,'postgres/ownedSystemDiagnosticProducer.js'),source=fs.readFileSync(file,'utf8');
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
function fixture(fault={}){
 const calls=[],signal=new AbortController().signal;let revoked=false;
 const owner={producerBinding:()=>({parentRunId:'a'.repeat(32),runId:'b'.repeat(32)}),isRevoked:()=>revoked,
  phaseWindow:kind=>{calls.push('phase:'+kind);return {deadlineMs:1800000};},phaseSignal:()=>signal};
 const runtime={async startRuntime(token){calls.push('start');assert.match(token,/^[A-Za-z0-9_-]{43}$/);
   if(fault.start)throw fault.start;return {ready:true};},
  async claimCohort(){calls.push('claim');return {port:fault.port??18090};},
  async join(){calls.push('join');if(fault.join)throw fault.join;return {localRetired:true};},
  async settle(){calls.push('settle');return {localRetired:true};},
  async stopRuntime(){calls.push('stop');if(fault.stop)throw fault.stop;return {};}};
 const driver={async run(name){calls.push(name);if(fault.build)throw fault.build;},
  async claimDiagnosticImage(){calls.push('image');},claimDiagnosticRuntime(){return runtime;},
  async close(){calls.push('close');return {localCleanupVerified:true,remoteCleanupVerified:true,guestResourcesAbsent:true,
   sharedStateUnchanged:!fault.changed,debts:[]};}};
 const module={exports:{}};
 vm.runInNewContext(source,{module,Buffer,__filename:file,
  require(name){if(name==='./ownedV03PrivateExecutors')return {assertCombinedOwner:value=>{if(value!==owner)throw Error('brand');return value;}};
   if(name==='node:fs/promises'&&fault.sourceClose){const real=require(name);return {...real,async open(...args){
    const handle=await real.open(...args);return {stat:()=>handle.stat(),read:(...values)=>handle.read(...values),
     async close(){await handle.close();throw fault.sourceClose;}};}};}
   if(name==='./ownedSystemDiagnosticBuildAdapter')return {diagnosticBuildPlan:async()=>{if(fault.plan)throw fault.plan;return {};},planDigest:()=> 'c'.repeat(64),verifyDiagnosticBuildPlan:async()=>{}};
   if(name==='./ownedSystemConfigPhaseDriver')return {createOwnedSystemDriver:async options=>{
    assert.equal(options.combinedOwner,owner);assert.equal(options.signal,signal);calls.push('driver');
    if(fault.construction)throw fault.construction;return driver;},_internals:{NORMAL:['first','last']}};
   return require(name);}
 },{filename:file});
 const options={root:path.resolve(__dirname,'..'),runId:'b'.repeat(32),parentRunId:'a'.repeat(32),combinedOwner:owner,
  expectedPlanSha256:'c'.repeat(64),expectedProducerSha256:sha(source),expectedDriverSha256:'d'.repeat(64),expectedPythonSha256:'e'.repeat(64)};
 return {api:module.exports,options,calls,revoke:()=>{revoked=true;}};
}
async function ready(f){const producer=f.api.createDiagnosticProducer(f.options);await producer.prepare();await producer.start();return producer;}
test('concrete producer uses fixed phases and publishes endpoint only after cohort claim',async()=>{
 const f=fixture(),p=f.api.createDiagnosticProducer(f.options);
 assert.equal(f.api.assertDiagnosticProducer(p),p);assert.throws(()=>f.api.assertDiagnosticProducer({...p}),/REQUIRED/);
 assert.equal((await p.prepare()).prepared,true);await assert.rejects(p.prepare(),/ONCE/);
 assert.deepEqual({...await p.start()},{ready:true});
 assert(!JSON.stringify(p.publicStatus()).includes('token'));
 const endpoint=await p.claimCohort();assert.equal(endpoint.url,'http://127.0.0.1:18090');assert.match(endpoint.token,/^[A-Za-z0-9_-]{43}$/);
 await assert.rejects(p.claimCohort(),/ORDER/);f.revoke();await p.join();await p.settle();
 const first=p.retire(),second=p.retire();assert.equal(first,second);assert.equal((await first).cleanupVerified,true);
 assert.equal(f.calls.filter(x=>x==='close').length,1);assert(f.calls.indexOf('last')<f.calls.indexOf('start'));
 assert(f.calls.indexOf('join')<f.calls.indexOf('stop'));assert(f.calls.indexOf('stop')<f.calls.indexOf('close'));
});
test('forged owner, foreign run and caller execution options cannot allocate a driver',()=>{
 const f=fixture();
 for(const delta of [{combinedOwner:{}},{runId:'f'.repeat(32)},{parentRunId:'f'.repeat(32)},
  {runner(){}},{token:'caller'},{url:'http://outside'},{expectedDriverSha256:'bad'}])
  assert.throws(()=>f.api.createDiagnosticProducer({...f.options,...delta}));
 assert(!f.calls.includes('driver'));
});
test('failed build retains primary and still closes owned builder without fabricating runtime work',async()=>{
 const primary=Error('build failed'),f=fixture({build:primary}),p=f.api.createDiagnosticProducer(f.options);
 await assert.rejects(p.prepare(),error=>error===primary);f.revoke();await p.join();await p.settle();
 assert.equal((await p.retire()).resourceAbsenceProven,true);assert(!f.calls.includes('start'));assert(!f.calls.includes('stop'));
});
test('prepared but never-started runtime does not invent a remote runtime intent',async()=>{
 const f=fixture(),p=f.api.createDiagnosticProducer(f.options);await p.prepare();f.revoke();await p.join();await p.settle();
 assert.equal((await p.retire()).cleanupVerified,true);assert(!f.calls.includes('stop'));assert(f.calls.includes('close'));
});
test('failed start remains failure and unresolved stop prevents builder deletion',async()=>{
 const primary=Error('start failed'),stop=Error('stop unproven'),f=fixture({start:primary,stop}),p=f.api.createDiagnosticProducer(f.options);
 await p.prepare();await assert.rejects(p.start(),error=>error===primary);f.revoke();await p.join();await p.settle();
 await assert.rejects(p.retire(),error=>error===stop);assert(!f.calls.includes('close'));assert.equal(p.publicStatus().closed,false);
});
test('retirement requires revocation and unchanged shared state proof',async()=>{
 const f=fixture({changed:true}),p=await ready(f);await assert.rejects(p.join(),/ORDER/);
 f.revoke();await assert.rejects(p.claimCohort(),/INACTIVE/);await p.join();await p.settle();
 await assert.rejects(p.retire(),/UNPROVEN/);assert.equal(p.publicStatus().closed,false);
});
test('source descriptor and early driver construction close debt veto no-driver clean retirement',async()=>{
 for(const fault of [{sourceClose:Error('source close unproven')},{plan:Error('capture descriptor close unproven')},
  {construction:Object.assign(Error('construction primary'),{cleanupDebt:true,driverSetupCleanupErrors:['JOURNAL_CLOSE_UNPROVEN']})}]){
  const f=fixture(fault),p=f.api.createDiagnosticProducer(f.options);
  await assert.rejects(p.prepare(),error=>error===(fault.sourceClose||fault.plan||fault.construction)&&error.cleanupDebt===true);
  f.revoke();await p.join();await p.settle();await assert.rejects(p.retire(),/RETIREMENT_UNPROVEN/);
  assert.equal(p.publicStatus().closed,false);assert(!f.calls.includes('close'));
 }
 const f=fixture({sourceClose:Error('secondary close')}),p=f.api.createDiagnosticProducer({...f.options,expectedProducerSha256:'f'.repeat(64)});
 await assert.rejects(p.prepare(),error=>error.code==='DIAGNOSTIC_PRODUCER_SOURCE'&&error.cleanupDebt===true);
});
