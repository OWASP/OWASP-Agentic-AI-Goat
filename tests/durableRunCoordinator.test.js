'use strict';
const Module=require('node:module'),load=Module._load;Module._load=function(r,p,m){if(/(?:^|\/)authDb(?:\.js)?$/.test(r))throw Error('authDb forbidden');return load.call(this,r,p,m);};
const {test}=require('node:test'),assert=require('node:assert/strict');const {createRunCoordinator}=require('../server/agent-runtime/runCoordinator');
function durableFixture(){let generation=0;const effects=new Map();return {begin:async()=>({durableGeneration:generation}),assertCurrent:async c=>{if(c.durableGeneration!==generation){const e=Error('stale');e.name='AbortError';throw e;}},finish:async()=>{},invalidate:async()=>{generation++;return {};},effect:async(c,key,fn)=>{const id=c.ownerKey+':'+c.durableGeneration+':'+key;if(effects.has(id)){const e=Error('replay blocked');e.code='GRAPH_EFFECT_REPLAY_BLOCKED';throw e;}effects.set(id,{status:'started',context:c,key});try{const value=await fn();effects.get(id).status='completed';return value;}catch(error){effects.get(id).status='uncertain';throw error;}},readCompletedEffect:async(c,key)=>{const row=effects.get(c.ownerKey+':'+c.durableGeneration+':'+key);return row?.status==='completed'?{ownerKey:c.ownerKey,generation:String(c.durableGeneration),runId:c.runId,effectKey:key,status:'completed',untrustedExtra:'omit'}:null;}};}
test('New coordinator after restart reads durable generation and refuses an uncertain effect replay',async()=>{
 const ledger=durableFixture();const first=createRunCoordinator({family:'ARIA',ledger});let effects=0;
 await first.reset(1);await assert.rejects(first.run(1,{idempotencyKey:'request-a'},e=>e.effect('tool',async()=>{effects++;throw Error('lost reply');})),/lost reply/);
 const restarted=createRunCoordinator({family:'ARIA',ledger});await assert.rejects(restarted.run(1,{idempotencyKey:'request-a'},e=>e.effect('tool',async()=>effects++)),{code:'GRAPH_EFFECT_REPLAY_BLOCKED'});assert.equal(effects,1);
 await restarted.reset(1);await restarted.run(1,{idempotencyKey:'request-a'},e=>e.effect('tool',async()=>effects++));assert.equal(effects,2);
});
test('receipt-aware effect exposes only an exact completed ledger reread',async()=>{
 const ledger=durableFixture(),coordinator=createRunCoordinator({family:'Receipt',ledger});let boundaryIdentity;
 const result=await coordinator.run('owner',{idempotencyKey:'request-one'},async execution=>{boundaryIdentity={runId:execution.runId,ownerKey:execution.ownerKey,generation:execution.durableGeneration};return execution.effectWithReceipt('tool',async()=>({raw:'value'}));});
 assert.deepEqual(result.value,{raw:'value'});assert.deepEqual(result.receipt,{version:1,ownerKey:boundaryIdentity.ownerKey,generation:String(boundaryIdentity.generation),runId:boundaryIdentity.runId,effectKey:'request-one:tool',status:'completed'});
 assert.equal(Object.hasOwn(result.receipt,'untrustedExtra'),false);
 const bad={...durableFixture(),async readCompletedEffect(){return null;}};
 await assert.rejects(createRunCoordinator({family:'ReceiptBad',ledger:bad}).run('owner',{},e=>e.effectWithReceipt('tool',async()=>true)),{code:'EFFECT_RECEIPT_INVALID'});
});
test('generation invalidated while the receipt read awaits cannot publish stale completion proof',async()=>{
 const ledger=durableFixture();let entered,release;const reading=new Promise(resolve=>{entered=resolve;});const held=new Promise(resolve=>{release=resolve;});
 const read=ledger.readCompletedEffect.bind(ledger);ledger.readCompletedEffect=async(...args)=>{entered();await held;return read(...args);};
 const coordinator=createRunCoordinator({family:'ReceiptRace',ledger});
 const pending=coordinator.run('owner',{},execution=>execution.effectWithReceipt('tool',async()=>true));
 await reading;const reset=coordinator.reset('owner');release();
 await assert.rejects(pending,{name:'AbortError'});await reset;
});
test('Remote generation reset fences late completion from another coordinator',async()=>{
 const ledger=durableFixture(),a=createRunCoordinator({family:'ARIA',ledger}),b=createRunCoordinator({family:'ARIA',ledger});let ready,release;const entered=new Promise(r=>ready=r),slow=new Promise(r=>release=r);let writes=0;
 const pending=a.run(1,{},async e=>{ready();await slow;await e.check();writes++;});const rejected=assert.rejects(pending,{name:'AbortError'});await entered;await b.reset(1);release();await rejected;assert.equal(writes,0);
});
test('durable pre-run admission skips replay before run creation and does not serialize different owners',async()=>{
 const releases=new Map(),tails=new Map(),runs=[];let active=0,maxActive=0;
 const ledger={supportsPreRunAdmission:true,
  async begin(context,{admit}){const previous=tails.get(context.ownerKey)||Promise.resolve();let release;const tail=new Promise(resolve=>release=resolve);tails.set(context.ownerKey,tail);await previous;
   const decision=await admit();if(decision.skip){release();return {skipped:true,value:decision.value};}
   releases.set(context.runId,release);runs.push(context.runId);return {durableGeneration:'0'};},
  async assertCurrent(){},async finish(context){releases.get(context.runId)?.();releases.delete(context.runId);}};
 const a=createRunCoordinator({family:'Admission',ledger}),b=createRunCoordinator({family:'Admission',ledger});
 const skipped=await a.run('same',{admit:async()=>({skip:true,value:'retained'})},()=>assert.fail('replay created a run'));
 assert.equal(skipped,'retained');assert.equal(runs.length,0);
 let releaseBoth;const both=new Promise(resolve=>releaseBoth=resolve);let entered=0;
 const execute=async()=>{active++;maxActive=Math.max(maxActive,active);if(++entered===2)releaseBoth();await both;active--;return 'fresh';};
 const values=await Promise.all([a.run('owner-a',{admit:async()=>({skip:false})},execute),b.run('owner-b',{admit:async()=>({skip:false})},execute)]);
 assert.deepEqual(values,['fresh','fresh']);assert.equal(maxActive,2);assert.equal(runs.length,2);
});
test('pre-run admission rejects an unsupported durable ledger before begin',async()=>{
 let begins=0,admissions=0;
 const ledger={async begin(){begins++;return {durableGeneration:'0'};},async finish(){}};
 await assert.rejects(createRunCoordinator({family:'UnsupportedAdmission',ledger}).run('owner',{
  admit:async()=>{admissions++;return {skip:true,value:'unsafe'};},
 },()=>assert.fail()),/does not support pre-run admission/);
 assert.equal(begins,0);assert.equal(admissions,0);
});
test('a replay decision is not published after cancellation during admission',async()=>{
 const controller=new AbortController();let runs=0;
 const ledger={supportsPreRunAdmission:true,async begin(_context,{admit}){const decision=await admit();return {skipped:true,value:decision.value};}};
 await assert.rejects(createRunCoordinator({family:'CancelledReplay',ledger}).run('owner',{signal:controller.signal,
  admit:async()=>{controller.abort(new DOMException('revoked','AbortError'));return {skip:true,value:'stale result'};},
 },()=>{runs++;}),{name:'AbortError'});
 assert.equal(runs,0);
});

test('reset callback receives frozen current authority and cannot report success after lease loss',async()=>{
 let current=true,released=0,checks=0,captured,mutations=0;
 const ledger={async invalidate(){return{durableGeneration:'9',async acquire(){},
  async assertCurrent(){checks++;if(!current){const error=Error('reset lease lost');error.name='AbortError';throw error;}},
  async release(){released++;current=false;}};}};
 const coordinator=createRunCoordinator({family:'ResetAuthority',ledger});
 await assert.rejects(coordinator.reset('owner',async execution=>{
  captured=execution;assert.equal(Object.isFrozen(execution),true);await execution.check();
  current=false;await execution.check();mutations++;
 }),{name:'AbortError'});
 assert.equal(mutations,0);assert.equal(released,1);assert.ok(checks>=3);
 assert.equal(captured.ownerKey,JSON.stringify(['ResetAuthority','owner']));
 assert.equal(captured.generation,1);assert.equal(captured.durableGeneration,'9');
 await assert.rejects(captured.check(),{name:'AbortError'});
});

test('superseded local reset authority never enters its cleanup callback',async()=>{
 let releaseFirst;const firstInvalidated=new Promise(resolve=>{releaseFirst=resolve;});
 let invalidations=0,firstCallbacks=0,secondCallbacks=0;
 const ledger={async invalidate(){invalidations++;if(invalidations===1)await firstInvalidated;return{};}};
 const coordinator=createRunCoordinator({family:'ResetSupersession',ledger});
 const first=coordinator.reset('owner',async()=>{firstCallbacks++;});
 await new Promise(resolve=>setImmediate(resolve));
 const second=coordinator.reset('owner',async()=>{secondCallbacks++;});releaseFirst();
 await assert.rejects(first,{name:'AbortError'});await second;
 assert.equal(firstCallbacks,0);assert.equal(secondCallbacks,1);
});

test('local reset authority expires after callback completion without a durable ledger',async()=>{
 let captured;
 const coordinator=createRunCoordinator({family:'LocalResetExpiry',ledger:null});
 await coordinator.reset('owner',async execution=>{captured=execution;await execution.check();});
 assert.equal(captured.durableGeneration,null);
 await assert.rejects(captured.check(),{name:'AbortError'});
});

test('an in-flight retained reset check cannot become valid after callback completion',async()=>{
 let calls=0,releaseHeartbeat,lateOutcome;
 const heartbeat=new Promise(resolve=>{releaseHeartbeat=resolve;});
 const ledger={async invalidate(){return{async acquire(){},async release(){},async assertCurrent(){
  calls++;if(calls===2)await heartbeat;
 }};}};
 const coordinator=createRunCoordinator({family:'RetainedResetCheck',ledger});
 await coordinator.reset('owner',async execution=>{
  lateOutcome=execution.check().then(()=>({status:'fulfilled'}),error=>({status:'rejected',error}));
  await new Promise(resolve=>setImmediate(resolve));
 });
 releaseHeartbeat();const result=await lateOutcome;
 assert.equal(result.status,'rejected');assert.equal(result.error.name,'AbortError');
});
