'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const {createRunCoordinator}=require('../server/agent-runtime/runCoordinator');
const gate=()=>{let resolve;const promise=new Promise(r=>resolve=r);return{promise,resolve};};
const turn=()=>new Promise(r=>setImmediate(r));
const opts={timeoutMs:5000};
const handled=p=>p.then(value=>({value}),error=>({error}));

test('queued deadline settles before predecessor, but run and reset barriers cannot overtake it',async()=>{
 const c=createRunCoordinator({family:'deadline',ledger:null}),held=gate(),started=gate(),order=[];
 const first=handled(c.run(1,opts,async()=>{started.resolve();await held.promise;order.push('first');}));await started.promise;
 let body=0,admit=0;const queued=handled(c.run(1,{timeoutMs:20,admit:()=>{admit++;return{skip:false};}},()=>body++));
 const outcome=await Promise.race([queued,new Promise((_,reject)=>setTimeout(()=>reject(Error('queued deadline did not settle')),250))]);
 assert.equal(outcome.error.name,'AbortError');assert.equal(body,0);assert.equal(admit,0);
 const reset=handled(c.reset(1,async()=>order.push('reset')));const arrival=handled(c.run(1,opts,async()=>order.push('arrival')));
 await turn();assert.deepEqual(order,[]);held.resolve();await Promise.all([first,reset,arrival]);assert.deepEqual(order,['first','reset','arrival']);
});

test('explicit queued cancellation retains capacity tombstones until predecessor settles',async()=>{
 const c=createRunCoordinator({family:'retention',ledger:null}),held=gate(),started=gate();
 const first=handled(c.run(1,opts,async()=>{started.resolve();await held.promise;}));await started.promise;
 const pending=[];for(let i=0;i<15;i++){const ac=new AbortController();pending.push(handled(c.run(1,{...opts,signal:ac.signal},()=>assert.fail('cancelled body'))));ac.abort();}
 for(const p of pending)assert.equal((await p).error.name,'AbortError');
 for(let i=0;i<20;i++)await assert.rejects(c.run(1,opts,()=>{}),{code:'GRAPH_RUN_CAPACITY_EXCEEDED',statusCode:503});
 assert.equal(await c.run(2,opts,()=>42),42);
 // Saturated ordinary lane still permits reset; reset does not release the held effect.
 const reset=handled(c.reset(1));await turn();held.resolve();await first;await reset;
 assert.equal(await c.run(1,opts,()=>43),43);
});

test('process ceiling spans coordinator instances and includes active work',async()=>{
 const held=gate(),pending=[];const a=createRunCoordinator({family:'global-a',ledger:null}),b=createRunCoordinator({family:'global-b',ledger:null});
 try{for(let i=0;i<1024;i++)pending.push(handled((i%2?a:b).run(i,opts,()=>held.promise)));
 await assert.rejects(createRunCoordinator({family:'global-c',ledger:null}).run(99999,opts,()=>{}),{code:'GRAPH_RUN_CAPACITY_EXCEEDED'});
 }finally{held.resolve();await Promise.all(pending);}
 assert.equal(await a.run(99999,opts,()=>7),7);
});

test('lifecycle limits reject before invalidation/generation mutation and reserve separate process capacity',async()=>{
 let invalidations=0;const c=createRunCoordinator({family:'lifecycle',ledger:{invalidate:async()=>{invalidations++;return{};}}});
 const held=gate(),entered=gate();const jobs=[handled(c.withScopesQuiesced(1,['email'],async()=>{entered.resolve();await held.promise;}))];await entered.promise;
 for(let i=0;i<3;i++)jobs.push(handled(c.withScopesQuiesced(1,['email'],()=>{})));
 await assert.rejects(c.reset(1),{code:'GRAPH_RUN_CAPACITY_EXCEEDED'});assert.equal(invalidations,0);
 held.resolve();await Promise.all(jobs);let generation;await c.reset(1,e=>{generation=e.generation;});assert.equal(generation,1);
 const all=gate(),many=[];try{for(let i=0;i<256;i++)many.push(handled(c.withScopesQuiesced(i+10,['email'],()=>all.promise)));
 await assert.rejects(c.withScopesQuiesced(900,['email'],()=>{}),{code:'GRAPH_RUN_CAPACITY_EXCEEDED'});
 }finally{all.resolve();await Promise.all(many);}
 await c.withScopesQuiesced(900,['email'],()=>{});
});

test('validation and already-aborted signal allocate no controllers or ledger work',async()=>{
 const c=createRunCoordinator({family:'validation',ledger:{begin:()=>assert.fail('begin')}});const ac=new AbortController();ac.abort();
 const Original=global.AbortController;let allocations=0;global.AbortController=class extends Original{constructor(){super();allocations++;}};
 try{await assert.rejects(c.run(1,{signal:ac.signal},()=>{}),{name:'AbortError'});
 for(const [options,fn] of [[{timeoutMs:0},()=>{}],[{admit:3},()=>{}],[{},null],[{signal:{}},()=>{}]])await assert.rejects(c.run(1,options,fn));
 assert.equal(allocations,0);
 }finally{global.AbortController=Original;}
});

test('active cancellation does not settle caller or release tail before effect drains',async()=>{
 const c=createRunCoordinator({family:'active',ledger:null}),held=gate(),started=gate(),ac=new AbortController();let settled=false,next=false;
 const active=handled(c.run(1,{...opts,signal:ac.signal},async()=>{started.resolve();await held.promise;})).then(r=>{settled=true;return r;});await started.promise;
 ac.abort();const later=c.run(1,opts,()=>{next=true;});await turn();assert.equal(settled,false);assert.equal(next,false);
 held.resolve();assert.equal((await active).error.name,'AbortError');await later;
});

test('failed reset invalidation still retains predecessor barrier',async()=>{
 const held=gate(),started=gate();const c=createRunCoordinator({family:'invalidate-fail',ledger:{begin:async()=>({}),invalidate:async()=>{throw Error('invalidation failed');}}});
 const active=handled(c.run(1,opts,async()=>{started.resolve();await held.promise;}));await started.promise;
 const reset=handled(c.reset(1));let entered=false;const next=handled(c.run(1,opts,()=>{entered=true;}));await turn();assert.equal(entered,false);
 held.resolve();await active;assert.match((await reset).error.message,/invalidation failed/);await next;
});

test('synchronous allocation failure frees reservation and listener failure keeps predecessor ordering',async()=>{
 const c=createRunCoordinator({family:'setup-fail',ledger:null}),Original=global.AbortController;
 global.AbortController=class{constructor(){throw Error('allocation failed');}};
 try{for(let i=0;i<20;i++)await assert.rejects(c.run(1,opts,()=>{}),/allocation failed/);}finally{global.AbortController=Original;}
 const held=gate(),started=gate();const active=handled(c.run(1,opts,async()=>{started.resolve();await held.promise;}));await started.promise;
 let removed=0;const signal={aborted:false,addEventListener(){throw Error('listener failed');},removeEventListener(){removed++;}};
 await assert.rejects(c.run(1,{...opts,signal},()=>assert.fail('failed setup body')),/listener failed/);
 let next=false;const following=c.run(1,opts,()=>{next=true;});await turn();assert.equal(next,false);assert.equal(removed,1);
 held.resolve();await active;await following;assert.equal(next,true);
});

test('cancelled queued caller cleans listeners immediately while begun failure finishes once',async()=>{
 let begins=0,finishes=0;const c=createRunCoordinator({family:'cleanup',ledger:{begin:async()=>{begins++;return{};},finish:async()=>{finishes++;}}});
 const held=gate(),started=gate(),ac=new AbortController();const active=handled(c.run(1,opts,async()=>{started.resolve();await held.promise;throw Error('body failure');}));await started.promise;
 let adds=0,removes=0;const add=ac.signal.addEventListener.bind(ac.signal),remove=ac.signal.removeEventListener.bind(ac.signal);
 ac.signal.addEventListener=(...a)=>{adds++;return add(...a);};ac.signal.removeEventListener=(...a)=>{removes++;return remove(...a);};
 const queued=handled(c.run(1,{...opts,signal:ac.signal},()=>assert.fail('queued body')));ac.abort();assert.equal((await queued).error.name,'AbortError');assert.equal(adds,1);assert.equal(removes,1);assert.equal(begins,1);
 held.resolve();assert.match((await active).error.message,/body failure/);await turn();assert.equal(begins,1);assert.equal(finishes,1);
});

test('throwing signal cleanup reports failure and cannot strand tail or counters after success',async()=>{
 const c=createRunCoordinator({family:'cleanup-throw-success',ledger:null});
 const signal={aborted:false,addEventListener(){},removeEventListener(){throw Error('private cleanup detail');}};
 for(let i=0;i<20;i++)await assert.rejects(c.run(1,{...opts,signal},()=>1),{code:'GRAPH_RUN_CLEANUP_FAILED'});
 assert.equal(await c.run(1,opts,()=>2),2);
});

test('queued throwing removal never escapes abort event and retains predecessor until actual drain',async()=>{
 const c=createRunCoordinator({family:'cleanup-throw-queued',ledger:null}),held=gate(),started=gate(),ac=new AbortController();
 const active=handled(c.run(1,opts,async()=>{started.resolve();await held.promise;}));await started.promise;
 ac.signal.removeEventListener=()=>{throw Error('private removal');};
 const queued=handled(c.run(1,{...opts,signal:ac.signal},()=>assert.fail('cancelled callback')));
 assert.doesNotThrow(()=>ac.abort());const outcome=await queued;assert.equal(outcome.error.name,'AbortError');assert.equal(outcome.error.cleanupError.code,'GRAPH_RUN_CLEANUP_FAILED');
 let next=false;const later=c.run(1,opts,()=>{next=true;});await turn();assert.equal(next,false);held.resolve();await active;await later;
 assert.equal(await c.run(1,opts,()=>3),3);
});

test('setup and primary body errors survive throwing removal with explicit cleanup code',async()=>{
 const c=createRunCoordinator({family:'cleanup-throw-primary',ledger:null});
 const signal={aborted:false,addEventListener(){throw Error('registration failed');},removeEventListener(){throw Error('secret cleanup text');}};
 await assert.rejects(c.run(1,{...opts,signal},()=>{}),e=>e.message==='registration failed'&&e.cleanupError.code==='GRAPH_RUN_CLEANUP_FAILED'&&!e.cleanupError.message.includes('secret'));
 const normal={...signal,addEventListener(){}};
 await assert.rejects(c.run(1,{...opts,signal:normal},()=>{throw Error('body failed');}),e=>e.message==='body failed'&&e.cleanupError.code==='GRAPH_RUN_CLEANUP_FAILED');
 assert.equal(await c.run(1,opts,()=>4),4);
});
