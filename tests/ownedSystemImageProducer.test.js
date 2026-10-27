'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path'),vm=require('node:vm'),crypto=require('node:crypto');
const producer=require('./postgres/ownedSystemImageProducer');
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
async function fixture(fault=''){
 const filename=path.join(__dirname,'postgres/ownedSystemImageProducer.js'),source=await fs.readFile(filename,'utf8');
 const module={exports:{}},events=[],controller=new AbortController(),timers=[],deadlines=[];
 let closed=false,cleanupEnd=null,cachedOwner,capability,releaseBridge,releaseStop,releaseActive;
 let qualificationError;
 if(fault.startsWith('qualified-')){
  const file=path.join(__dirname,'ownedSystemConfigBuildAdapter.test.js'),mod={exports:{}},local=require('node:module').createRequire(file);
  new Function('require','module','exports','__dirname','__filename',await fs.readFile(file,'utf8')+'\nmodule.exports=pairRelayFixture;')(
   id=>id==='node:test'?()=>{}:local(id),mod,mod.exports,__dirname,file);
  const f=await mod.exports(),rows=f.packet.files['relay.adapter.log'].trim().split('\n').map(JSON.parse);
  const start=JSON.parse(f.observations.find(r=>r.name==='systemReserve').value).before.rows.adapter.pairBudget.connections;
  rows[0].records[start]={host:'deb.debian.org',status:'denied'};f.packet.files['relay.adapter.log']=rows.map(JSON.stringify).join('\n');
  try{require('./postgres/ownedSystemConfigBuildAdapter')._internals.validatePairRelayTerminal(f.plan,f.observations,JSON.stringify(f.packet));}
  catch(e){qualificationError=e;}
  assert(qualificationError);
 }
 const bridgeWait=new Promise(resolve=>{releaseBridge=resolve;}),stopWait=new Promise(resolve=>{releaseStop=resolve;}),activeWait=new Promise(resolve=>{releaseActive=resolve;});
 const plan={fixed:true},clock={now:1000};
 const receipt=()=>({localCleanupVerified:true,remoteCleanupVerified:true,guestResourcesAbsent:true,sharedStateUnchanged:fault!=='shared-change'});
 const owner={binding:Object.freeze({runId:'a'.repeat(32)}),assertActive(){events.push('active');},
  beginRetirement(){events.push('begin');cleanupEnd??=clock.now+600000;const count=events.filter(v=>v==='begin').length;
   if(fault==='cleanup-microtask-expiry'&&count===2)queueMicrotask(()=>{clock.now=cleanupEnd+1;});
   const end=fault==='renewal'?cleanupEnd+count:cleanupEnd;deadlines.push(end);return end;},
  async startRuntime(){events.push('runtime-start');if(fault==='active-unsettled')await activeWait;},async inspectRuntime(){events.push('runtime-inspect');},async openBridge(){events.push('bridge-open');},
  async closeBridge(){events.push('bridge-close');if(fault==='bridge-debt')throw Error('bridge unproven');if(fault.startsWith('delayed-retirement'))await bridgeWait;},
  async stopRuntime(){events.push('runtime-stop');if(fault.startsWith('delayed-retirement'))await stopWait;},
  async confirmRetired(){events.push('confirmed');return true;}};
 const pairOwner={binding:{runId:'a'.repeat(32)},assertActive:owner.assertActive,beginRetirement:owner.beginRetirement,slots:{}};
 for(const slot of ['system','policy']){
  pairOwner.slots[slot]={binding:{runId:'a'.repeat(32),target:'original-v24-'+slot},assertActive:owner.assertActive};
  for(const method of ['startRuntime','inspectRuntime','openBridge','closeBridge','stopRuntime','confirmRetired'])
   pairOwner.slots[slot][method]=async(...args)=>{
    events.push(slot+':'+method);
    if(slot==='policy'&&method==='startRuntime'&&fault==='pair-runtime-start')throw Error('renderer start failed');
    if(slot==='policy'&&method==='closeBridge'&&fault==='pair-channel-debt')throw Object.assign(Error('renderer channel debt'),{retirementUnproven:true});
    if(slot==='policy'&&method==='closeBridge'&&fault==='pair-channel-held')await bridgeWait;
    return method==='confirmRetired'?true:undefined;
   };
 }
 const adapter={systemBuildPlan:async()=>plan,systemPolicyBuildPlan:async()=>plan,
  _internals:{PAIR_PHASES:require('./postgres/ownedSystemConfigBuildAdapter')._internals.PAIR_PHASES,
   isPairRelayQualificationFailure:require('./postgres/ownedSystemConfigBuildAdapter')._internals.isPairRelayQualificationFailure},
  planDigest:()=> 'a'.repeat(64),verifyPlan:async p=>assert.equal(p,plan)};
 const driver={async createOwnedSystemDriver(options){events.push('driver');assert.deepEqual(Object.keys(options).sort(),
  ['deadline','expectedDriverSha256','expectedPlanSha256','expectedPythonSha256','plan','signal'].sort());
  return {async run(name){events.push(name);if(fault==='build-failure'&&name==='build')throw Error('build failed');
    if(fault==='pair-second-failure'&&name==='policyBuild')throw Error('second build failed');},
   async claimImages(){events.push('claim-pair');if(fault==='pair-proof')throw Error('second replay unproven');return owner;},
   async claimRuntime(){events.push('claim');return owner;},async claimPairedRuntime(){events.push('claim-runtime-pair');return pairOwner;},async close(){events.push('driver-close');
    if(qualificationError){closed=true;
     const failure=Object.assign(qualificationError,{retirementUnproven:false,receipt:{...receipt(),debts:[]}});
     if(fault==='qualified-unclean')failure.receipt.guestResourcesAbsent=false;
     if(fault==='qualified-forged')throw Object.assign(Error(failure.message),failure);
     throw failure;
    }
    if(fault==='close-expiry-rejection'){clock.now=cleanupEnd+1;throw Error('late driver rejection');}
    if(fault==='pair-second-failure')throw Object.assign(Error('partial renderer retirement unproven'),{retirementUnproven:true,
     receipt:{localCleanupVerified:true,remoteCleanupVerified:false,guestResourcesAbsent:false,sharedStateUnchanged:true,debts:['controlled-export-fault']}});
    closed=true;return receipt();}};}};
 const consumer={async withSystemPrivateHttp(cap,lifecycle,callback){
  events.push('consumer-entry');
  if(fault==='consumer-refusal')throw Error('consumer refused');
  if(fault==='consumer-no-callback')return 'no callback';
  capability=cap;cachedOwner=module.exports.assertSystemImageCapability(cap);
  assert.throws(()=>module.exports.assertSystemImageCapability(JSON.parse(JSON.stringify(cap))),/SYSTEM_IMAGE_NOT_LIVE/);
  await cachedOwner.startRuntime({token:'private'});await cachedOwner.inspectRuntime();await cachedOwner.openBridge();
  if(fault==='consumer-early-return'){void callback({origin:'controlled'});return 'early';}
  try{return await callback({origin:'controlled'});}
  finally{
   cachedOwner.beginRetirement();await cachedOwner.closeBridge();await cachedOwner.stopRuntime();await cachedOwner.confirmRetired();
  }
 },async withSystemAndPolicyPrivateHttp(cap,lifecycle,callback){
  capability=cap;cachedOwner=module.exports.assertPairedRuntimeCapability(cap);events.push('pair-consumer-entry');
  assert.throws(()=>module.exports.assertSystemImageCapability(cap),/SYSTEM_IMAGE_NOT_LIVE/);
  assert.throws(()=>module.exports.assertPairedRuntimeCapability(JSON.parse(JSON.stringify(cap))),/SYSTEM_PAIR_RUNTIME_NOT_LIVE/);
  const attempted=[];
  try{
   for(const slot of ['system','policy']){attempted.push(slot);await cachedOwner.slots[slot].startRuntime(slot==='system'?{token:'private'}:{});
    await cachedOwner.slots[slot].inspectRuntime();await cachedOwner.slots[slot].openBridge();}
   return await callback({system:{origin:'controlled-system'},policy:{origin:'controlled-policy'},deadline:lifecycle.deadline});
  }finally{
   cachedOwner.beginRetirement();
   for(const method of ['closeBridge','stopRuntime','confirmRetired'])for(const slot of attempted)await cachedOwner.slots[slot][method]();
  }
 }};
 const load=id=>id==='./ownedSystemConfigBuildAdapter'?adapter:id==='./ownedSystemConfigPhaseDriver'?driver:
  id==='./ownedSystemPrivateHttpConsumer'?consumer:require(id);
 vm.runInNewContext('(function(require,module,exports,__filename){'+source+'\n})',{
  Buffer,AbortController,AbortSignal,AggregateError,performance:{now:()=>clock.now},
  setTimeout:(fn,ms)=>{const row={fn,due:clock.now+ms,cleared:false};row.handle=setTimeout(fn,ms<=5000?Math.min(ms,5):ms);timers.push(row);
   if(fault==='abort-before-consumer'&&ms===900000)controller.abort(Error('cancel before consumer'));return row;},
  clearTimeout:row=>{if(row){row.cleared=true;clearTimeout(row.handle);}}
 })(load,module,module.exports,filename);
 const options={root:path.resolve(__dirname,'..'),runId:'a'.repeat(32),recipe:{fixed:true},signal:controller.signal,
  buildDeadline:1801000,expectedPlanSha256:'a'.repeat(64),expectedProducerSha256:sha(source),expectedDriverSha256:'b'.repeat(64),expectedPythonSha256:'c'.repeat(64)};
 return {api:module.exports,options,events,controller,deadlines,releaseBridge,releaseStop,releaseActive,
  advance(ms){clock.now+=ms;},fireExpired(){for(const row of timers)if(!row.cleared&&row.due<=clock.now){row.cleared=true;clearTimeout(row.handle);row.fn();}},
  get closed(){return closed;},get cachedOwner(){return cachedOwner;},get capability(){return capability;}};
}
async function until(predicate){for(let n=0;n<500;n++){if(predicate())return;await new Promise(resolve=>setTimeout(resolve,1));}assert.fail('controlled checkpoint not reached');}
test('both producer entries retain the driver error receipt alongside original failure',async()=>{
 for(const entry of ['runtime','image-only']){
  const f=await fixture('pair-second-failure');
  const run=entry==='runtime'?f.api.withPrivateSystemAndPolicyImages:f.api._internals.runPairedProducer;
  await assert.rejects(run(f.options,()=>assert.fail('unexpected cohort')),e=>{
   assert.equal(e.primary.message,'second build failed');assert.equal(e.driverReceipt,e.cleanupErrors[0].receipt);
   assert.equal(e.driverReceipt.remoteCleanupVerified,false);assert.equal(e.retirementUnproven,true);return true;
  });
  assert.equal(f.events.filter(x=>x==='driver-close').length,1);
 }
});
test('both actual paired producer routes reject branded qualification after clean retirement, preserving an earlier primary',async()=>{
 for(const entry of ['runtime','image-only'])for(const earlier of [false,true]){
  const f=await fixture('qualified-clean'),primary=Error('original callback failure');
  const run=entry==='runtime'?f.api.withPrivateSystemAndPolicyImages:f.api._internals.runPairedProducer;
  await assert.rejects(run(f.options,()=>{if(earlier)throw primary;return 'not qualification';}),e=>{
   assert.equal(e.retirementUnproven,false);assert.equal(e.cleanupErrors.length,0);
   const qualification=e.errors.find(x=>require('./postgres/ownedSystemConfigBuildAdapter')._internals.isPairRelayQualificationFailure(x));
   assert(qualification);assert.equal(qualification.code,'SYSTEM_PAIR_RELAY_TERMINAL');
   assert.equal(e.primary,earlier?primary:qualification);assert.equal(e.driverReceipt,qualification.receipt);
   return true;
  });
  assert(f.closed);assert.equal(f.events.filter(x=>x==='driver-close').length,1);
 }
});
test('same-code copies and branded errors with incomplete retirement remain cleanup debt',async()=>{
 for(const fault of ['qualified-forged','qualified-unclean']){
  const f=await fixture(fault);
  await assert.rejects(f.api.withPrivateSystemAndPolicyImages(f.options,()=>{}),e=>e.retirementUnproven===true&&e.cleanupErrors.length===1);
 }
});
test('reviewed producer rejects invalid invocation and dictionaries cannot mint authority',async()=>{
 assert.equal(producer.LIVE_ENABLED,true);
 await assert.rejects(producer.withPrivateSystemImage({}),/SYSTEM_PRODUCER_OPTIONS/);
 for(const cap of [{},Object.freeze({imageId:'sha256:'+'a'.repeat(64)}),null])assert.throws(()=>producer.assertSystemImageCapability(cap),/SYSTEM_IMAGE_NOT_LIVE/);
 const f=await fixture();
 await assert.rejects(f.api.withPrivateSystemImage({...f.options,expectedProducerSha256:'0'.repeat(64)},()=>{}),/SYSTEM_PRODUCER_SOURCE/);
 await assert.rejects(f.api.withPrivateSystemImage({...f.options,expectedPlanSha256:'0'.repeat(64)},()=>{}),/SYSTEM_PRODUCER_PLAN/);
 assert.deepEqual(f.events,[]);
});
test('reviewed paired entry rejects malformed input and a forced closed gate precedes all effects',async()=>{
 assert.equal(producer.PAIRED_LIVE_ENABLED,true);assert.equal(producer.LIVE_ENABLED,true);
 await assert.rejects(producer.withPrivateSystemAndPolicyImages({},()=>{}),/SYSTEM_PRODUCER_OPTIONS/);
 assert.throws(()=>producer.assertPairedImageCapability({images:{system:{},policy:{}}}),/SYSTEM_PAIR_NOT_LIVE/);
 const filename=path.join(__dirname,'postgres/ownedSystemImageProducer.js'),original=await fs.readFile(filename,'utf8');
 assert.equal(original.split('const PAIRED_LIVE_ENABLED=true,pairedOwners=new WeakMap();').length,2);
 const source=original.replace('const PAIRED_LIVE_ENABLED=true,pairedOwners=new WeakMap();','const PAIRED_LIVE_ENABLED=false,pairedOwners=new WeakMap();');
 const module={exports:{}},local=require('node:module').createRequire(filename);let reads=0,calls=0;
 vm.runInNewContext('(function(require,module,exports,__filename){'+source+'\n})',
  {Buffer,AbortController,AbortSignal,performance,setTimeout,clearTimeout,AggregateError})(local,module,module.exports,filename);
 const poison=new Proxy({}, {get(){reads++;throw Error('unexpected option read');},ownKeys(){reads++;throw Error('unexpected option enumeration');}});
 module.exports.PAIRED_LIVE_ENABLED=true;
 await assert.rejects(module.exports.withPrivateSystemAndPolicyImages(poison,()=>{calls++;}),/V24_PAIRED_RUNTIME_NOT_ADMITTED/);
 assert.equal(reads,0);assert.equal(calls,0);
});
test('paired runtime producer joins both image proofs and one callback before shared actual retirement',async()=>{
 const f=await fixture();let calls=0;
 const result=await f.api._internals.runPairedRuntimeProducer(f.options,endpoints=>{
  calls++;assert.equal(endpoints.system.origin,'controlled-system');assert.equal(endpoints.policy.origin,'controlled-policy');
  assert.equal(endpoints.deadline,901000);return 'cohort';
 });
 assert.equal(calls,1);assert.equal(result.result,'cohort');assert(f.closed);
 assert(f.events.indexOf('policyReplayRetire')<f.events.indexOf('claim-runtime-pair'));
 assert(f.events.indexOf('policy:closeBridge')<f.events.indexOf('system:stopRuntime'));
 assert(f.events.indexOf('policy:confirmRetired')<f.events.indexOf('driver-close'));
 for(const slot of ['system','policy'])for(const method of ['closeBridge','stopRuntime','confirmRetired'])assert.equal(f.events.filter(x=>x===slot+':'+method).length,1);
 assert.equal(new Set(f.deadlines).size,1);assert.throws(()=>f.api.assertPairedRuntimeCapability(f.capability),/SYSTEM_PAIR_RUNTIME_NOT_LIVE/);
 assert.throws(()=>f.cachedOwner.slots.policy.startRuntime({}),/SYSTEM_IMAGE_REVOKED/);
});
test('paired failed second startup preserves primary and actual channel debt prevents builder deletion',async()=>{
 const start=await fixture('pair-runtime-start');let calls=0;
 await assert.rejects(start.api._internals.runPairedRuntimeProducer(start.options,()=>{calls++;}),error=>{
  assert.equal(error.primary.message,'renderer start failed');assert.equal(error.retirementUnproven,false);return true;
 });
 assert.equal(calls,0);assert(start.closed);assert(start.events.includes('policy:confirmRetired'));
 const debt=await fixture('pair-channel-debt');
 await assert.rejects(debt.api._internals.runPairedRuntimeProducer(debt.options,()=>true),error=>error.retirementUnproven===true);
 assert(!debt.closed);assert(!debt.events.some(x=>x.endsWith(':stopRuntime')));assert(!debt.events.includes('driver-close'));
});
test('paired actual cleanup promise is joined once; timer does not grant builder deletion underneath it',async()=>{
 const f=await fixture('pair-channel-held');let done=false;
 const work=f.api._internals.runPairedRuntimeProducer(f.options,()=>true).then(v=>{done=true;return v;});
 await until(()=>f.events.includes('policy:closeBridge'));await new Promise(resolve=>setTimeout(resolve,20));
 assert.equal(done,false);assert(!f.closed);assert(!f.events.includes('system:stopRuntime'));
 f.releaseBridge();await work;assert(f.closed);assert.equal(f.events.filter(x=>x==='policy:closeBridge').length,1);
});
test('paired unjoined callback retains both targets and late settlement cannot dispatch cleanup after return',async()=>{
 const f=await fixture();let release;
 const callback=new Promise(resolve=>{release=resolve;});
 await assert.rejects(f.api._internals.runPairedRuntimeProducer(f.options,()=>{
  f.controller.abort(Error('paired cohort canceled'));return callback;
 }),error=>error.retirementUnproven===true&&error.cleanupErrors.some(e=>e.code==='SYSTEM_PRODUCER_CALLBACK_UNSETTLED'));
 assert(!f.closed);assert(!f.events.some(e=>e.endsWith(':closeBridge')));
 const count=f.events.length;release();await new Promise(resolve=>setImmediate(resolve));
 assert.equal(f.events.length,count);assert(!f.closed);
});
test('deadline crossed by actual driver close still observes its rejecting promise and retains debt',async()=>{
 const f=await fixture('close-expiry-rejection');
 await assert.rejects(f.api._internals.runPairedRuntimeProducer(f.options,()=>true),error=>
  error.retirementUnproven===true&&error.cleanupErrors.some(e=>e.code==='SYSTEM_PRODUCER_DEADLINE'));
 await new Promise(resolve=>setImmediate(resolve));await new Promise(resolve=>setImmediate(resolve));
 assert(!f.closed);assert.equal(f.events.filter(e=>e==='driver-close').length,1);
});
test('paired producer joins both builds and replays before callback then revokes paired-only authority',async()=>{
 const f=await fixture();let capability;
 const result=await f.api._internals.runPairedProducer(f.options,(cap,lifecycle)=>{
  capability=cap;assert.equal(lifecycle.deadline,f.options.buildDeadline);
  assert.equal(f.api.assertPairedImageCapability(cap).runId,'a'.repeat(32));
  assert.throws(()=>f.api.assertSystemImageCapability(cap),/SYSTEM_IMAGE_NOT_LIVE/);
  assert.throws(()=>f.api.assertPairedImageCapability(JSON.parse(JSON.stringify(cap))),/SYSTEM_PAIR_NOT_LIVE/);
  assert(f.events.indexOf('systemReplayRetire')<f.events.indexOf('claim-pair'));
  assert(f.events.indexOf('policyReplayRetire')<f.events.indexOf('claim-pair'));return 'pair';
 });
 assert.equal(result.result,'pair');assert.equal(result.runtimeAvailable,false);assert.equal(result.qualificationComplete,false);
 assert(f.closed);assert.throws(()=>f.api.assertPairedImageCapability(capability),/SYSTEM_PAIR_NOT_LIVE/);
 assert(!f.events.includes('consumer-entry'));assert(!f.events.includes('runtime-start'));
});
test('partial second build failure and invalid joined replay proof never reach paired callback',async()=>{
 for(const fault of ['pair-second-failure','pair-proof']){
  const f=await fixture(fault);let calls=0;
  await assert.rejects(f.api._internals.runPairedProducer(f.options,()=>{calls++;}),e=>{
   assert.equal(e.primary.message,fault==='pair-proof'?'second replay unproven':'second build failed');
   assert.equal(e.retirementUnproven,fault==='pair-second-failure');return true;
  });
  assert.equal(calls,0);assert.equal(f.closed,fault==='pair-proof');
  if(fault==='pair-second-failure')assert(!f.events.includes('claim-pair'));
 }
});
test('paired aborted unjoined callback retains daemon debt and late settlement never starts cleanup',async()=>{
 const f=await fixture();let release,cap;
 const work=new Promise(resolve=>{release=resolve;});
 await assert.rejects(f.api._internals.runPairedProducer(f.options,c=>{
  cap=c;f.controller.abort(Error('pair cancelled'));return work;
 }),e=>e.primary.message==='pair cancelled'&&e.retirementUnproven===true);
 assert(!f.closed);assert(!f.events.includes('driver-close'));assert.throws(()=>f.api.assertPairedImageCapability(cap),/SYSTEM_PAIR_NOT_LIVE/);
 release();await new Promise(resolve=>setImmediate(resolve));assert(!f.events.includes('driver-close'));
});
test('fixed producer performs full phase sequence and revokes cached operation authority before final builder retirement',async()=>{
 const f=await fixture();const result=await f.api._internals.runProducer(f.options,async client=>{assert.equal(client.origin,'controlled');return 'original result';});
 assert.equal(result.result,'original result');assert.equal(result.driverReceipt.sharedStateUnchanged,true);
 const phases=f.events.filter(v=>producer._internals.PHASES.includes(v));assert.deepEqual(phases,Array.from(producer._internals.PHASES));
 assert(f.events.indexOf('confirmed')<f.events.indexOf('driver-close'));assert(f.closed);
 assert.throws(()=>f.api.assertSystemImageCapability(f.capability),/SYSTEM_IMAGE_NOT_LIVE/);
 assert.throws(()=>f.cachedOwner.startRuntime({token:'late'}),/SYSTEM_IMAGE_REVOKED/);
 assert.equal(f.events.filter(v=>v==='runtime-start').length,1);
});
test('callback failure remains primary after actual owned retirement; it is not relabeled cleanup debt',async()=>{
 const f=await fixture();await assert.rejects(f.api._internals.runProducer(f.options,async()=>{throw Error('original failure');}),
  e=>e.primary.message==='original failure'&&e.retirementUnproven===false&&e.cleanupErrors.length===0);
 assert(f.closed);assert(f.events.includes('confirmed'));
});
test('unsettled actual callback on abort prevents bridge/container/builder teardown and revokes late operations',async()=>{
 const f=await fixture();let release;
 const callback=new Promise(resolve=>{release=resolve;});
 await assert.rejects(f.api._internals.runProducer(f.options,()=>{
  f.controller.abort(Error('cancel'));return callback;
 }),e=>e.retirementUnproven===true&&e.cleanupErrors.some(v=>v.code==='SYSTEM_PRODUCER_CALLBACK_UNSETTLED'));
 assert.equal(f.closed,false);assert(!f.events.includes('bridge-close'));assert(!f.events.includes('runtime-stop'));
 assert.throws(()=>f.cachedOwner.openBridge(),/SYSTEM_IMAGE_REVOKED/);
 release('late');await new Promise(resolve=>setImmediate(resolve));assert.equal(f.closed,false);
});
test('early consumer return cannot substitute for actual callback settlement',async()=>{
 const f=await fixture('consumer-early-return');let release;const callback=new Promise(resolve=>{release=resolve;});
 await assert.rejects(f.api._internals.runProducer(f.options,()=>callback),e=>e.retirementUnproven===true);
 assert.equal(f.closed,false);assert(!f.events.includes('runtime-stop'));release();
});
test('renewed cleanup deadline, transport debt and changed shared inventory all fail closed',async()=>{
 for(const fault of ['renewal','bridge-debt','shared-change']){
  const f=await fixture(fault);await assert.rejects(f.api._internals.runProducer(f.options,async()=> 'result'),e=>e.retirementUnproven===true);
  if(fault!=='shared-change')assert.equal(f.closed,false);
  if(fault==='bridge-debt'){assert.equal(f.events.filter(v=>v==='bridge-close').length,1);assert(!f.events.includes('runtime-stop'));}
 }
});
test('abort waits legitimate26s bridge and150s remote retirement within the same600s deadline, without duplicate fallback',async()=>{
 const f=await fixture('delayed-retirement');let finished=false;
 const outcome=f.api._internals.runProducer(f.options,()=>{f.controller.abort(Error('cancel'));return 'settled';})
  .then(v=>({value:v}),error=>({error})).finally(()=>{finished=true;});
 await until(()=>f.events.includes('bridge-close'));
 await new Promise(resolve=>setTimeout(resolve,15));assert.equal(finished,false);
 assert.equal(f.closed,false);assert(!f.events.includes('runtime-stop'));
 assert.throws(()=>f.cachedOwner.openBridge(),/SYSTEM_IMAGE_REVOKED/);
 f.advance(26000);f.releaseBridge();await until(()=>f.events.includes('runtime-stop'));
 assert.equal(finished,false);f.advance(150000);f.releaseStop();
 const {error}=await outcome;assert.equal(error.primary.message,'cancel');assert.equal(error.retirementUnproven,false);
 assert.equal(error.cleanupErrors.length,0);assert(f.closed);assert.equal(new Set(f.deadlines).size,1);assert.equal(f.deadlines[0],601000);
 for(const phase of ['bridge-close','runtime-stop','confirmed','driver-close'])assert.equal(f.events.filter(v=>v===phase).length,1);
});
test('consumer retirement expiry retains debt and never starts parallel fallback or permits late deletion',async()=>{
 const f=await fixture('delayed-retirement-expired');
 const outcome=f.api._internals.runProducer(f.options,()=>{f.controller.abort(Error('cancel'));return 'settled';}).then(()=>null,e=>e);
 await until(()=>f.events.includes('bridge-close'));await new Promise(resolve=>setTimeout(resolve,10));
 f.advance(600001);f.fireExpired();const error=await outcome;
 assert.equal(error.primary.message,'cancel');assert.equal(error.retirementUnproven,true);assert.equal(f.closed,false);
 assert.equal(f.events.filter(v=>v==='bridge-close').length,1);assert(!f.events.includes('runtime-stop'));
 f.releaseBridge();f.releaseStop();await new Promise(resolve=>setImmediate(resolve));
 assert.equal(f.closed,false);assert(!f.events.includes('runtime-stop'));assert.equal(new Set(f.deadlines).size,1);
});
test('actual active operation still has short quiescence bound and cannot be mistaken for consumer retirement',async()=>{
 const f=await fixture('active-unsettled');
 const outcome=f.api._internals.runProducer(f.options,async()=> 'unreached').then(()=>null,e=>e);
 await until(()=>f.events.includes('runtime-start'));f.controller.abort(Error('cancel active'));
 const error=await outcome;assert.equal(error.retirementUnproven,true);
 assert(error.cleanupErrors.some(v=>v.code==='SYSTEM_PRODUCER_CALLBACK_UNSETTLED'));
 assert.equal(f.closed,false);assert(!f.events.includes('bridge-close'));assert(!f.events.includes('runtime-inspect'));
 f.releaseActive();await new Promise(resolve=>setImmediate(resolve));assert(!f.events.includes('runtime-inspect'));assert.equal(f.closed,false);
});
test('abort before consumer dispatch and refusal/no-callback remain failures without admitting runtime work',async()=>{
 for(const [fault,message]of [['abort-before-consumer','cancel before consumer'],['consumer-refusal','consumer refused'],['consumer-no-callback','SYSTEM_PRODUCER_NO_CALLBACK']]){
  const f=await fixture(fault);let calls=0;
  await assert.rejects(f.api._internals.runProducer(f.options,async()=>{calls++;}),e=>e.primary.message===message);
  assert.equal(calls,0);assert(!f.events.includes('runtime-start'));
  for(const phase of ['bridge-close','runtime-stop','confirmed'])assert(!f.events.includes(phase));
  if(fault==='abort-before-consumer')assert(!f.events.includes('consumer-entry'));
  assert.equal(f.events.filter(v=>v==='driver-close').length,1);
 }
});
test('cleanup microtask rechecks the immutable deadline before dispatching owner cleanup',async()=>{
 const f=await fixture('cleanup-microtask-expiry');
 await assert.rejects(f.api._internals.runProducer(f.options,async()=> 'complete'),e=>e.retirementUnproven===true);
 assert.equal(f.events.filter(v=>v==='bridge-close').length,0);
 assert(!f.events.includes('runtime-stop'));assert.equal(f.closed,false);assert.equal(new Set(f.deadlines).size,1);
});
test('predispatch source/admission failure creates no driver; build failure still retires owned builder',async()=>{
 for(const change of [v=>v.runner=()=>{},v=>v.expectedProducerSha256='0'.repeat(64),v=>v.expectedPlanSha256='0'.repeat(64)]){
  const f=await fixture();change(f.options);await assert.rejects(f.api._internals.runProducer(f.options,async()=>{}));assert(!f.events.includes('driver'));
 }
 const f=await fixture('build-failure');await assert.rejects(f.api._internals.runProducer(f.options,async()=>{}),e=>e.primary.message==='build failed');
 assert(f.closed);assert(!f.events.includes('claim'));
});

// Load all three actual modules in one CommonJS-shaped VM graph. Only the
// fixed driver, immutable-plan preparation, and HTTP response are controlled;
// adapter delegation, WeakMap mint/revocation and consumer orchestration are
// the real source, not independently agreeable admission stubs.
async function linkedFixture(order,openGate=false,fault='',pair=false){
 const {createRequire}=require('node:module');
 const names=['ownedSystemConfigBuildAdapter','ownedSystemImageProducer','ownedSystemPrivateHttpConsumer'];
 const files=new Map(await Promise.all(names.map(async name=>{
  const filename=path.join(__dirname,'postgres',name+'.js');return [name,{filename,source:await fs.readFile(filename,'utf8')}];
 })));
 const events=[],requests=[],cache=new Map(),control=new AbortController();let cleanupEnd,capability,cachedOwner;
 const binding={version:1,target:'original-v24-system',runId:'a'.repeat(32),imageId:'sha256:'+'b'.repeat(64),
  inputSha256:'c'.repeat(64),daemonId:'d'.repeat(36),physical:{privateDockerHost:'unix:///var/tmp/dvaia-v23-build-'+'a'.repeat(32)+'/fs/docker.sock',
   namespaceInode:'net:[12345]',filesystemIdentity:{device:1,inode:2},daemonProcess:{pid:101,startTicks:'100',exe:'/usr/bin/dockerd'},
   namespaceHolder:{pid:102,startTicks:'101',exe:'/usr/bin/sleep'}}};
 const runtimeReceipt={version:1,runId:binding.runId,containerId:'e'.repeat(64),imageId:binding.imageId,running:true,namespaceInode:12345};
 const local={version:1,runId:binding.runId,channelIds:[],localRetired:true,retirementUnproven:false,remoteRetired:false,builderReleaseAllowed:false,failures:[]};
 const remote={version:1,runId:binding.runId,containerAbsent:true,profileAbsent:true,remoteChannelsAbsent:true,channelFailures:[],builderReleaseAllowed:false};
 const owner={binding,assertActive(){events.push('active');},beginRetirement(){return cleanupEnd??=performance.now()+600000;},
  async startRuntime({token}){assert.match(token,/^[A-Za-z0-9_-]{43}$/);events.push('runtime-start');return runtimeReceipt;},
  async inspectRuntime(){events.push('runtime-inspect');return runtimeReceipt;},async openBridge(){events.push('bridge-open');return {port:18090};},
  async closeBridge(){events.push('bridge-close');return local;},async stopRuntime(){events.push('runtime-stop');return remote;},
  async confirmRetired(){events.push('confirmed');return true;}};
 const policyBinding={...binding,target:'original-v24-policy',imageId:'sha256:'+'f'.repeat(64)};
 const policyRow={...runtimeReceipt,target:policyBinding.target,imageId:policyBinding.imageId,containerId:'f'.repeat(64),namespaceInode:23456};
 const policyOwner={binding:policyBinding,assertActive:owner.assertActive,beginRetirement:owner.beginRetirement,
  async startRuntime(input){assert.deepEqual(Object.keys(input),[]);events.push('policy-start');
   if(fault==='policy-start')throw Error('renderer start failed');return policyRow;},
  async inspectRuntime(){events.push('policy-inspect');return policyRow;},async openBridge(){events.push('policy-bridge');return {port:18091};},
  async closeBridge(){events.push('policy-close');if(fault==='policy-close')throw Error('renderer channel debt');return {...local,target:policyBinding.target};},
  async stopRuntime(){events.push('policy-stop');return {...remote,target:policyBinding.target};},async confirmRetired(){events.push('policy-confirm');return true;}};
 const pairOwner={binding:{runId:binding.runId},slots:{system:owner,policy:policyOwner},assertActive:owner.assertActive,beginRetirement:owner.beginRetirement};
 const driver={async createOwnedSystemDriver(){events.push('driver');return {
  async run(phase){events.push(phase);},async claimRuntime(){events.push('claim');return owner;},
  async claimPairedRuntime(){events.push('claim-pair');return pairOwner;},async close(){events.push('driver-close');
   return {localCleanupVerified:true,remoteCleanupVerified:true,guestResourcesAbsent:true,sharedStateUnchanged:true};}};}};
 const context=vm.createContext({Buffer,URL,AbortController,AbortSignal,Error,AggregateError,performance,setTimeout,clearTimeout,
  process:{env:{LIVE_ENABLED:'1',V24_PRIVATE_RUNTIME_NOT_ADMITTED:'false',SYSTEM_PRIVATE_HTTP_NOT_ADMITTED:'false'}},
  fetch:async(url,init)=>{const parsed=new URL(url);requests.push([parsed.href,init.method]);
   if(parsed.port==='18091')return new Response(JSON.stringify(fault==='policy-health'?{}:
    {policyRenderer:{enabled:true,available:true,isolation:require('../server/services/secureshopPromptPolicyContract').ISOLATION}}));
   return new Response(JSON.stringify({version:'secureshop-owned-system-http.v1',
   ready:true,isolation:'bwrap-system-config-v1',configReadCapability:'secureshop-owned-system-config-read.v1'}));}});
 function load(name){
  if(cache.has(name))return cache.get(name).exports;
  const {filename,source:original}=files.get(name),module={exports:{}};cache.set(name,module);
  let source=original;
  if(!openGate&&name==='ownedSystemImageProducer'){
   // VM-only forced-closed policy verifies that env/exported flags never
   // override a source gate. Open controls use actual admitted source bytes;
   // all driver and HTTP work remains controlled inside this VM.
   assert.equal(source.split('const LIVE_ENABLED=true,owners=new WeakMap();').length,2);
   source=source.replace('const LIVE_ENABLED=true,owners=new WeakMap();','const LIVE_ENABLED=false,owners=new WeakMap();');
  }
  const localRequire=createRequire(filename);
  vm.runInContext('(function(require,module,exports,__filename,__dirname){'+source+'\n})',context)(id=>{
   const dependency=id.startsWith('./')?id.slice(2):null;
   if(dependency==='ownedSystemConfigPhaseDriver')return driver;
   return files.has(dependency)?load(dependency):localRequire(id);
  },module,module.exports,filename,path.dirname(filename));
  return module.exports;
 }
 for(const name of order)load(name);
 const adapter=load(names[0]),api=load(names[1]),consumer=load(names[2]),plan=Object.freeze({controlled:true});
 adapter.systemBuildPlan=adapter.systemPolicyBuildPlan=async()=>plan;adapter.planDigest=()=> 'a'.repeat(64);adapter.verifyPlan=async value=>assert.equal(value,plan);
 const assertion=pair?'assertPairedRuntimeCapability':'assertSystemImageCapability',realAssert=api[assertion];
 api[assertion]=value=>{const live=realAssert(value);capability=value;cachedOwner=live;return live;};
 if(fault==='consumer-refusal')consumer.withSystemPrivateHttp=async()=>{throw Error('controlled refusal');};
 const options={root:path.resolve(__dirname,'..'),runId:binding.runId,recipe:{controlled:true},signal:control.signal,
  buildDeadline:performance.now()+1800000,expectedPlanSha256:'a'.repeat(64),expectedProducerSha256:sha(files.get(names[1]).source),
  expectedDriverSha256:'b'.repeat(64),expectedPythonSha256:'c'.repeat(64)};
 return {adapter,api,consumer,options,events,requests,control,get capability(){return capability;},get cachedOwner(){return cachedOwner;}};
}
const importOrders=[
 ['ownedSystemConfigBuildAdapter','ownedSystemImageProducer','ownedSystemPrivateHttpConsumer'],
 ['ownedSystemImageProducer','ownedSystemPrivateHttpConsumer','ownedSystemConfigBuildAdapter'],
 ['ownedSystemPrivateHttpConsumer','ownedSystemConfigBuildAdapter','ownedSystemImageProducer']];
test('VM-forced closed gate survives all import orders and env/exported claims, with zero driver or HTTP work',async()=>{
 for(const order of importOrders){
  const f=await linkedFixture(order);let calls=0;
  f.api.LIVE_ENABLED=true;f.consumer.LIVE_ENABLED=true;
  await assert.rejects(f.adapter.withPrivateSystemImage(f.options,()=>{calls++;}),{code:'V24_PRIVATE_RUNTIME_NOT_ADMITTED'});
  await assert.rejects(f.api.withPrivateSystemImage(f.options,()=>{calls++;}),{code:'V24_PRIVATE_RUNTIME_NOT_ADMITTED'});
  await assert.rejects(f.consumer.withSystemPrivateHttp({executionApproved:true}, {},()=>{calls++;}),{code:'SYSTEM_IMAGE_NOT_LIVE'});
  assert.equal(calls,0);assert.deepEqual(f.events,[]);assert.deepEqual(f.requests,[]);
 }
});
test('VM-only public entry runs real lazy delegation and branded consumer in every import order, then revokes every authority view',async()=>{
 for(const order of importOrders){
  const f=await linkedFixture(order,true);let calls=0;
  const result=await f.adapter.withPrivateSystemImage(f.options,async endpoint=>{
   calls++;assert.equal(endpoint.baseURL,'http://127.0.0.1:18090');assert.equal(typeof endpoint.client.read,'function');
   assert.match(endpoint.token,/^[A-Za-z0-9_-]{43}$/);assert(endpoint.deadline<=performance.now()+900000);
   const before=f.events.length;
   for(const fake of [structuredClone(f.capability),{binding:f.cachedOwner.binding},f.cachedOwner]){
    assert.throws(()=>f.adapter.assertSystemImageCapability(fake),{code:'SYSTEM_IMAGE_NOT_LIVE'});
    await assert.rejects(f.consumer.withSystemPrivateHttp(fake,{},()=>{throw Error('must not call');}),{code:'SYSTEM_IMAGE_NOT_LIVE'});
   }
   assert.equal(f.events.length,before);return 'original callback';
  });
  assert.equal(calls,1);assert.equal(result.result.value,'original callback');assert.equal(result.result.qualificationAccepted,false);
  assert.equal(result.driverReceipt.sharedStateUnchanged,true);
  assert.deepEqual(f.events.filter(value=>producer._internals.PHASES.includes(value)),Array.from(producer._internals.PHASES));
  assert.deepEqual(f.requests,[['http://127.0.0.1:18090/secureshop/system/health','GET']]);
  for(const phase of ['bridge-close','runtime-stop','confirmed','driver-close'])assert.equal(f.events.filter(value=>value===phase).length,1);
  assert(f.events.indexOf('confirmed')<f.events.indexOf('driver-close'));
  assert.throws(()=>f.adapter.assertSystemImageCapability(f.capability),{code:'SYSTEM_IMAGE_NOT_LIVE'});
  await assert.rejects(f.consumer.withSystemPrivateHttp(f.capability,{},()=>{calls++;}),{code:'SYSTEM_IMAGE_NOT_LIVE'});
  assert.throws(()=>f.cachedOwner.startRuntime({token:'late'}),{code:'SYSTEM_IMAGE_REVOKED'});assert.equal(calls,1);
 }
});
test('VM-only delegated public entry preserves original callback failure and genuine cleanup without native credit',async()=>{
 const f=await linkedFixture(importOrders[0],true);
 await assert.rejects(f.adapter.withPrivateSystemImage(f.options,async()=>{throw Error('original callback failed');}),
  error=>error.primary.message==='original callback failed'&&error.retirementUnproven===false&&error.driverReceipt.remoteCleanupVerified===true);
 for(const phase of ['bridge-close','runtime-stop','confirmed','driver-close'])assert.equal(f.events.filter(value=>value===phase).length,1);
 assert.throws(()=>f.adapter.assertSystemImageCapability(f.capability),{code:'SYSTEM_IMAGE_NOT_LIVE'});
});
test('actual paired producer and consumer modules compose in every import order with original health protocols',async()=>{
 for(const order of importOrders){
  const f=await linkedFixture(order,true,'',true);let calls=0,endpoints;
  const result=await f.api._internals.runPairedRuntimeProducer(f.options,value=>{
   endpoints=value;calls++;assert.equal(typeof value.system.client.read,'function');assert.equal(typeof value.policy.client.render,'function');
   assert.equal(f.requests.length,2);assert(f.events.indexOf('policyReplayRetire')<f.events.indexOf('claim-pair'));return 'original pair';
  });
  assert.equal(calls,1);assert.equal(result.result.value,'original pair');assert.equal(result.result.qualificationAccepted,false);
  assert.deepEqual(f.requests,[['http://127.0.0.1:18090/secureshop/system/health','GET'],['http://127.0.0.1:18091/health',undefined]]);
  assert(f.events.indexOf('policy-close')<f.events.indexOf('runtime-stop'));assert(f.events.indexOf('policy-confirm')<f.events.indexOf('driver-close'));
  assert.throws(()=>f.api.assertPairedRuntimeCapability(f.capability),{code:'SYSTEM_PAIR_RUNTIME_NOT_LIVE'});
  assert.throws(()=>f.cachedOwner.slots.policy.startRuntime({}),{code:'SYSTEM_IMAGE_REVOKED'});
  await assert.rejects(endpoints.policy.client.checkReadiness());await assert.rejects(endpoints.system.client.assertReady());assert.equal(f.requests.length,2);
 }
});
test('composed pair never exposes cohort after renderer failure and never deletes builder with actual bridge debt',async()=>{
 for(const fault of ['policy-start','policy-health','policy-close']){
  const f=await linkedFixture(importOrders[0],true,fault,true);let calls=0;
  await assert.rejects(f.api._internals.runPairedRuntimeProducer(f.options,()=>{calls++;return true;}),error=>{
   assert.equal(error.retirementUnproven,fault==='policy-close');return true;
  });
  assert.equal(calls,fault==='policy-close'?1:0);assert.equal(f.events.includes('driver-close'),fault!=='policy-close');
  if(fault==='policy-close'){assert(!f.events.includes('runtime-stop'));assert(!f.events.includes('policy-stop'));}
 }
});
