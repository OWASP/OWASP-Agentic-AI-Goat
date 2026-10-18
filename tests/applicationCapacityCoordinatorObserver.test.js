'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),crypto=require('node:crypto'),Module=require('node:module');
const {instrument,createRecorder,SYMBOL}=require('./fixtures/applicationCapacityCoordinatorObserver.cjs');
const filename=require.resolve('../server/agent-runtime/runCoordinator'),source=fs.readFileSync(filename,'utf8'),sha=crypto.createHash('sha256').update(source).digest('hex');
function load(){const m=new Module(filename,module);m.filename=filename;m.paths=module.paths;m._compile(instrument(source,sha),filename);return m.exports;}
test('exact source and unique sites required before boot',()=>{assert.throws(()=>instrument(source,'0'.repeat(64)),/identity/);const drift=source+'\nretained[lane]++; owner[field]++;';assert.throws(()=>instrument(drift,crypto.createHash('sha256').update(drift).digest('hex')),/anchor/);});
test('ordinary tombstones retain physical counter after caller abort; lifecycle also observed',async()=>{
 const ids=Array.from({length:200},(_,i)=>String(i+1)),r=createRecorder(ids);globalThis[Symbol.for(SYMBOL)]=r.record;
 let release,entered;const held=new Promise(x=>release=x),started=new Promise(x=>entered=x);
 try{const c=load().createRunCoordinator({family:'capacity',ledger:null});const a=c.run(ids[0],{},async()=>{entered();await held;});await started;
 const stop=new AbortController(),b=c.run(ids[0],{signal:stop.signal},async()=>assert.fail('cancelled dispatch'));stop.abort();await assert.rejects(b,{name:'AbortError'});assert.equal(r.snapshot().current.runs,2);
 release();await a;await new Promise(x=>setImmediate(x));assert.equal(r.snapshot().current.runs,0);
 await c.reset(ids[0],async()=>{});assert.equal(r.snapshot().peak.lifecycle,1);assert.equal(r.snapshot().current.lifecycle,0);assert(r.snapshot().valid);
 }finally{release?.();delete globalThis[Symbol.for(SYMBOL)];}
});
test('observer failure never throws into runtime and invalid observations fail external claim',async()=>{
 globalThis[Symbol.for(SYMBOL)]=()=>{throw Error('observer unavailable');};try{await load().createRunCoordinator({family:'capacity',ledger:null}).run(crypto.randomUUID(),{},async()=>42);}finally{delete globalThis[Symbol.for(SYMBOL)];}
 const r=createRecorder(Array.from({length:200},(_,i)=>String(i+1)));assert.doesNotThrow(()=>r.record({ownerKey:'bad'}));assert.equal(r.snapshot().valid,false);
});
test('passive lease observations bind active and queued owners without changing admission results',async()=>{
 const {observeLeaseAdmission}=require('./fixtures/applicationCapacityCoordinatorObserver.cjs'),{admissionFor}=require('../server/agent-runtime/graphLeaseAdmission');
 const original=admissionFor({options:{max:1}}),wrapped=observeLeaseAdmission(original,new Set(['1','2']));const first=await wrapped.acquire('["ARIA","1"]');const abort=new AbortController(),second=wrapped.acquire('["NOVA","2"]',abort.signal);assert.deepEqual(wrapped.snapshot().owners,[{ownerKey:'["ARIA","1"]',kind:'run',state:'active'},{ownerKey:'["NOVA","2"]',kind:'run',state:'queued'}]);abort.abort();await assert.rejects(second,{name:'AbortError'});assert.equal(wrapped.snapshot().owners.length,1);first();assert.deepEqual(wrapped.snapshot().owners,[]);assert.equal(original.snapshot().active,0);
});
test('held cohort selection includes active and queued work in each invalidation kind despite late owners winning admission',()=>{
 const {selectInvalidationCohorts}=require('./fixtures/applicationCapacityCoordinatorObserver.cjs');
 const users=Array.from({length:200},(_,index)=>({id:index+1,index}));
 const observations=users.map(u=>({ownerKey:JSON.stringify([u.index<100?'ARIA':'NOVA',String(u.id)]),kind:'run',state:[130,150,170,190].includes(u.index)?'active':'queued'}));
 const c=selectInvalidationCohorts(users,observations.reverse());
 assert.deepEqual(['cancel','revoke','reset','siblings'].map(k=>c[k].length),[40,20,20,120]);assert.equal(new Set(c.ordered.map(u=>u.id)).size,200);
 for(const kind of ['cancel','revoke','reset']){const states=c[kind].map(u=>observations.find(o=>JSON.parse(o.ownerKey)[1]===String(u.id)).state);assert(states.includes('active'));assert(states.includes('queued'));}
 assert(c.siblings.every(u=>observations.find(o=>JSON.parse(o.ownerKey)[1]===String(u.id)).state==='queued'));
 assert.deepEqual(selectInvalidationCohorts(users,observations.reverse()),c);
 const positions=new Map(users.map((u,i)=>[u.id,i]));const originalResults=users.map(u=>({id:u.id}));assert.deepEqual(c.ordered.map(u=>originalResults[positions.get(u.id)].id),c.ordered.map(u=>u.id));
 for(const bad of [observations.slice(1),[observations[0],...observations.slice(1,-1),observations[0]],observations.map((o,i)=>i===0?{...o,ownerKey:'["ARIA","999"]'}:o),observations.map(o=>({...o,state:'queued'}))])assert.throws(()=>selectInvalidationCohorts(users,bad));
});

test('physical sampler failures retain bounded nonsecret cause and failed snapshot rather than later success',()=>{
 const {physicalSampleFailure}=require('./fixtures/applicationCapacityCoordinatorObserver.cjs');
 const query=physicalSampleFailure(Object.assign(Error('secret connection URL'),{code:'57014'}),undefined,3,'read-mix',42);
 assert.equal(query.reason,'PG_QUERY_FAILURE');assert.equal(query.code,'57014');assert.equal(query.snapshot,null);assert(!JSON.stringify(query).includes('secret'));
 for(const [code,total,transactions] of [['PG_TOTAL_LIMIT',96,0],['PG_IDLE_TRANSACTION',30,1]]){
  const failed=physicalSampleFailure(Object.assign(Error('private'),{code}),[{total,transactions,datname:'private-db'}],4,'normal-runs',44);
  assert.equal(failed.reason,code);assert.deepEqual(failed.snapshot,{total,idleTransactions:transactions});assert(!JSON.stringify(failed).includes('private'));
 }
});
test('every concurrent reset outcome must be200 or409; ignored500 and transport failures reject',()=>{
 const {assertResetOutcomes}=require('./fixtures/applicationCapacityCoordinatorObserver.cjs');
 assertResetOutcomes([{status:200},{status:409},{status:409},{status:200}]);
 for(const bad of [{status:500},{status:401},{error:'AbortError'}])assert.throws(()=>assertResetOutcomes([{status:200},{status:409},{status:200},bad]));
 assert.throws(()=>assertResetOutcomes([]));
});

test('phase failure waits for pending physical sample and saves its late failure before closing database',async()=>{
 const {settlePhysicalSampler}=require('./fixtures/applicationCapacityCoordinatorObserver.cjs');
 const report={failure:{message:'original phase failure'}},events=[];let complete;
 const pending=new Promise(resolve=>complete=()=>{report.sampleFailure='57014';events.push('sample');resolve();});
 const timer=setInterval(()=>assert.fail('timer was not cleared'),1000);
 const finish=(async()=>{await settlePhysicalSampler(timer,pending,()=>events.push(JSON.stringify(report)));events.push('db.end');})();
 await new Promise(resolve=>setImmediate(resolve));assert.deepEqual(events,[]);
 complete();await finish;assert.equal(events[0],'sample');assert.deepEqual(JSON.parse(events[1]),{failure:{message:'original phase failure'},sampleFailure:'57014'});assert.equal(events[2],'db.end');
});
test('passive owner lifecycle counters retain exact owner binding and disappear only at zero',()=>{
 const r=createRecorder(Array.from({length:200},(_,i)=>String(i+1)));
 r.record({ownerKey:'["ARIA","1"]',lane:'lifecycle',event:'reserve',global:4,owner:4});
 assert.deepEqual(r.snapshot().owners,[{ownerKey:'["ARIA","1"]',runs:0,lifecycle:4}]);
 r.record({ownerKey:'["ARIA","2"]',lane:'lifecycle',event:'reserve',global:5,owner:1});
 assert.equal(r.snapshot().owners.find(x=>x.ownerKey==='["ARIA","1"]').lifecycle,4);
 r.record({ownerKey:'["ARIA","1"]',lane:'lifecycle',event:'release',global:1,owner:0});
 assert.deepEqual(r.snapshot().owners,[{ownerKey:'["ARIA","2"]',runs:0,lifecycle:1}]);
});
