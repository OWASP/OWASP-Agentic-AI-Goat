'use strict';
const Module=require('node:module'),load=Module._load;Module._load=function(r,p,m){if(/(?:^|\/)authDb(?:\.js)?$/.test(r))throw Error('authDb forbidden');return load.call(this,r,p,m);};
const {test}=require('node:test'),assert=require('node:assert/strict');
const {createRunCoordinator}=require('../server/agent-runtime/runCoordinator');
const {ownerWorkflowRoute,checkOwnerRun}=require('../server/agent-runtime/ownerWorkflowRoutes');
const response=()=>({statusCode:200,status(n){this.statusCode=n;return this;},json(p){this.payload=p;this.headersSent=true;return this;}});
test('Reset fences late model continuation and waits for callback persistence before clearing',{timeout:2000},async()=>{
 const runs=createRunCoordinator({family:'fixture',ledger:null});let enter,release;const started=new Promise(r=>enter=r),slow=new Promise(r=>release=r);let effects=0;
 const chat=ownerWorkflowRoute(runs,r=>r.owner,async(req,res)=>{enter();await slow;await checkOwnerRun();effects++;res.json({ok:true});});
 const reset=ownerWorkflowRoute(runs,r=>r.owner,async(req,res)=>{effects=0;res.json({reset:true});},{reset:true});
 const chatRes=response(),resetRes=response();const pending=chat({owner:'a'},chatRes);await started;const resetting=reset({owner:'a'},resetRes);release();await Promise.all([pending,resetting]);assert.equal(effects,0);assert.equal(chatRes.statusCode,409);assert.equal(resetRes.payload.reset,true);
});
test('Response buffering retains callback lifetime and serializes owner requests',{timeout:2000},async()=>{
 const runs=createRunCoordinator({family:'fixture',ledger:null});const events=[];
 const handler=ownerWorkflowRoute(runs,r=>r.owner,(req,res)=>{events.push(req.id+'start');setTimeout(()=>{events.push(req.id+'end');res.json({id:req.id});},5);});
 await Promise.all([handler({owner:'a',id:1},response()),handler({owner:'a',id:2},response())]);assert.deepEqual(events,['1start','1end','2start','2end']);
});
test('Buffered response preserves chained content-type and raw send method',{timeout:2000},async()=>{
 const runs=createRunCoordinator({family:'fixture',ledger:null});const res=response();res.type=function(t){this.contentType=t;return this;};res.send=function(p){this.raw=p;this.headersSent=true;return this;};
 const route=ownerWorkflowRoute(runs,()=>1,(req,out)=>out.type('text/html').send('<img onerror=fixture()>'));
 await route({},res);assert.equal(res.raw,'<img onerror=fixture()>');assert.equal(res.contentType,'text/html');assert.equal(res.payload,undefined);
});


test('disconnected caller cancels its run, blocks later effects and releases listeners', async () => {
 const {EventEmitter}=require('node:events');
 const runs=createRunCoordinator({family:'disconnect-fixture',ledger:null});
 const req=Object.assign(new EventEmitter(),{owner:'a'});
 const res=Object.assign(new EventEmitter(),response());
 let enter,release;const started=new Promise(r=>enter=r),slow=new Promise(r=>release=r);
 let effects=0,aborted=false;
 const route=ownerWorkflowRoute(runs,r=>r.owner,async(_req,out)=>{
  const execution=require('../server/agent-runtime/ownerWorkflowRoutes').getOwnerExecution();
  execution.signal.addEventListener('abort',()=>{aborted=true;},{once:true});
  enter();await slow;await checkOwnerRun();effects++;out.json({ok:true});
 });
 const pending=route(req,res);await started;
 res.destroyed=true;res.emit('close');release();await pending;
 assert.equal(aborted,true);assert.equal(effects,0);assert.equal(res.payload,undefined);
 assert.equal(req.listenerCount('aborted'),0);assert.equal(res.listenerCount('close'),0);
 const next=response();await ownerWorkflowRoute(runs,()=> 'a',(_req,out)=>out.json({ok:true}))({},next);
 assert.equal(next.payload.ok,true,'owner lock is released');
});

test('finished response close does not cancel execution and normal cleanup removes listeners',async()=>{
 const {EventEmitter}=require('node:events');
 const req=new EventEmitter(),res=Object.assign(new EventEmitter(),response());
 const runs=createRunCoordinator({family:'finished-fixture',ledger:null});
 let signal;
 await ownerWorkflowRoute(runs,()=> 'a',async(_req,out)=>{
  signal=require('../server/agent-runtime/ownerWorkflowRoutes').getOwnerExecution().signal;
  res.writableEnded=true;res.emit('close');await checkOwnerRun();out.json({ok:true});
 })(req,res);
 assert.equal(signal.aborted,false);assert.equal(req.listenerCount('aborted'),0);assert.equal(res.listenerCount('close'),0);
});

test('real HTTP disconnect aborts owner execution before subsequent mutation', {timeout:5000}, async t => {
 const express=require('express'),http=require('node:http');
 const app=express(),runs=createRunCoordinator({family:'http-disconnect-fixture',ledger:null});
 let started,finished;const entered=new Promise(r=>started=r),done=new Promise(r=>finished=r);
 let effects=0;
 app.get('/slow',ownerWorkflowRoute(runs,()=> 'owned-http-fixture',async(_req,out)=>{
  const execution=require('../server/agent-runtime/ownerWorkflowRoutes').getOwnerExecution();
  started();
  await new Promise(resolve=>execution.signal.addEventListener('abort',resolve,{once:true}));
  try{await checkOwnerRun();effects++;out.json({ok:true});}finally{finished();}
 }));
 const server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});
 t.after(()=>new Promise(resolve=>{server.closeAllConnections();server.close(resolve);}));
 const request=http.get(`http://127.0.0.1:${server.address().port}/slow`);
 request.on('error',()=>{});
 await entered;request.destroy();
 await done;
 assert.equal(effects,0);
});


test('deadline releases callback response wait and permits the next owner run', {timeout:2000}, async () => {
 const runs=createRunCoordinator({family:'callback-deadline-fixture',ledger:null,defaultTimeoutMs:30});
 let lateReply,published=0;
 const route=ownerWorkflowRoute(runs,()=> 'a',(_req,out)=>{lateReply=()=>out.json({late:true});},
  {beforePublish:()=>{published++;}});
 const first=response();await route({},first);
 assert.equal(first.statusCode,409);assert.equal(published,0);
 const next=response();await ownerWorkflowRoute(runs,()=> 'a',(_req,out)=>out.json({ok:true}))({},next);
 assert.equal(next.payload.ok,true);
 lateReply();assert.equal(first.payload.late,undefined,'expired buffered response is not published');
});

test('reset cancels a missing callback response before clearing owner state', {timeout:2000}, async () => {
 const runs=createRunCoordinator({family:'callback-reset-fixture',ledger:null});
 let entered;const started=new Promise(resolve=>entered=resolve);
 const first=response();const pending=ownerWorkflowRoute(runs,()=> 'a',()=>{entered();})({},first);
 await started;
 let reset=false;await runs.reset('a',async()=>{reset=true;});await pending;
 assert.equal(reset,true);assert.equal(first.statusCode,409);
});

test('reset route async context rejects a lost durable lease before its next mutation',async()=>{
 let current=true,released=0,mutations=0,entered,continueReset;
 const started=new Promise(resolve=>{entered=resolve;}),gate=new Promise(resolve=>{continueReset=resolve;});
 const ledger={async invalidate(){return{durableGeneration:'12',async acquire(){},
  async assertCurrent(){if(!current){const error=Error('lease lost');error.name='AbortError';throw error;}},
  async release(){released++;}};}};
 const runs=createRunCoordinator({family:'reset-route-lease',ledger});
 const route=ownerWorkflowRoute(runs,()=> 'a',async(_req,out)=>{
  entered();await gate;await checkOwnerRun();mutations++;out.json({ok:true});
 },{reset:true});
 const res=response(),pending=route({},res);await started;current=false;continueReset();await pending;
 assert.equal(mutations,0);assert.equal(released,1);assert.equal(res.statusCode,409);
 assert.equal(res.payload.error,'Request invalidated by reset');
});

test('reset route never publishes buffered success when its lease is lost after handler work',async()=>{
 let current=true;
 const ledger={async invalidate(){return{durableGeneration:'13',async acquire(){},
  async assertCurrent(){if(!current){const error=Error('lease lost');error.name='AbortError';throw error;}},
  async release(){}};}};
 const runs=createRunCoordinator({family:'reset-route-publish',ledger});
 const route=ownerWorkflowRoute(runs,()=> 'a',async(_req,out)=>{
  out.json({ok:true});current=false;
 },{reset:true});
 const res=response();await route({},res);
 assert.equal(res.statusCode,409);assert.deepEqual(res.payload,{error:'Request invalidated by reset'});
});

test('optional server scope is captured before coordinator async work and forwarded exactly once',async()=>{
 let release,scopeCalls=0;const gate=new Promise(resolve=>{release=resolve;});
 const seen=[];const coordinator={async run(owner,options,execute){
  seen.push({owner,scope:options.scope});await gate;
  return execute({signal:options.signal,check:async()=>{}});
 }};
 const req={auth:{userId:7},tab:'profile',body:{scope:{userId:999,scopeKey:'email'}}};
 const route=ownerWorkflowRoute(coordinator,r=>r.auth.userId,
  async(_req,out)=>out.json({ok:true}),{scopeFor:r=>{
   scopeCalls++;return{userId:r.auth.userId,scopeKey:r.tab==='profile'?'stored_user':'stored_llm'};
  }});
 const res=response(),pending=route(req,res);
 req.auth.userId=99;req.tab='model';req.body.scope.scopeKey='reflected';
 release();await pending;
 assert.equal(scopeCalls,1);
 assert.deepEqual(seen,[{owner:7,scope:{userId:7,scopeKey:'stored_user'}}]);
 assert.deepEqual(res.payload,{ok:true});
});

test('scope omission preserves legacy run options and request body is never authority',async()=>{
 const calls=[];const coordinator={async run(owner,options,execute){
  calls.push({owner,options});return execute({signal:options.signal,check:async()=>{}});
 }};
 const route=ownerWorkflowRoute(coordinator,r=>r.owner,(_req,out)=>out.json({ok:true}));
 await route({owner:4,body:{userId:4,scopeKey:'stored_llm',scope:{userId:4,scopeKey:'email'}}},response());
 assert.equal(calls[0].owner,4);assert.equal(Object.hasOwn(calls[0].options,'scope'),false);
});

test('scope mapping remains caller-owned and reset routes reject scope mappers',async()=>{
 const calls=[];const coordinator={async run(owner,options,execute){
  calls.push(options.scope);return execute({signal:options.signal,check:async()=>{}});
 }};
 const siblingScopes=Object.freeze({user:'stored_user',model:'stored_llm'});
 const route=ownerWorkflowRoute(coordinator,r=>r.userId,(_req,out)=>out.json({ok:true}),{
  scopeFor:r=>({userId:r.userId,scopeKey:siblingScopes[r.profileKind]})
 });
 await route({userId:8,profileKind:'user'},response());
 await route({userId:8,profileKind:'model'},response());
 assert.deepEqual(calls,[{userId:8,scopeKey:'stored_user'},{userId:8,scopeKey:'stored_llm'}]);
 assert.throws(()=>ownerWorkflowRoute({reset(){}},r=>r.owner,()=>{},
  {reset:true,scopeFor:r=>r.scope}),/Reset routes cannot use/);
 assert.throws(()=>ownerWorkflowRoute(coordinator,r=>r.owner,()=>{},
  {scopeFor:{}}),/scope mapper must be a function/i);
});

test('outer admission precedes coordinator and remains held through callback persistence',async()=>{
 const events=[];let active=false;
 const runs=createRunCoordinator({family:'admission-callback',ledger:null});
 const route=ownerWorkflowRoute(runs,()=>7,(_req,out)=>{
  setImmediate(async()=>{await checkOwnerRun();events.push('persist');assert.equal(active,true);out.json({ok:true});});
 },{withAdmission:async(owner,work)=>{
  assert.equal(owner,7);events.push('admit');active=true;
  try{return await work({check:async()=>{assert.equal(active,true);}});}finally{active=false;events.push('release');}
 }});
 const out=response();await route({},out);assert.equal(out.payload.ok,true);
 assert.deepEqual(events,['admit','persist','release']);
});
test('admission rejection prevents coordinator entry and response success',async()=>{
 let entered=false;const out=response();
 const route=ownerWorkflowRoute({run:async()=>{entered=true;}},()=>7,()=>{},
 {withAdmission:async()=>{throw new Error('pending reset');}});
 await route({},out);assert.equal(entered,false);assert.equal(out.statusCode,500);
 assert.equal(out.payload.error,'pending reset');
});
test('lost outer admission blocks subsequent handler effects',async()=>{
 let live=true,effects=0;const out=response();
 const route=ownerWorkflowRoute(createRunCoordinator({family:'admission-lost',ledger:null}),()=>7,async(_req,res)=>{
  live=false;await checkOwnerRun();effects++;res.json({ok:true});
 },{withAdmission:async(_,work)=>work({check:async()=>{if(!live)throw new Error('lifecycle lost');}})});
 await route({},out);assert.equal(effects,0);assert.equal(out.statusCode,500);
});
test('direct execution effects cannot bypass lost outer admission',async()=>{
 let live=true,effects=0;const out=response();
 const route=ownerWorkflowRoute({run:async(_owner,_options,work)=>work({check:async()=>{},effect:async()=>{effects++;}})},()=>7,async(_req,res)=>{
  live=false;await require('../server/agent-runtime/ownerWorkflowRoutes').getOwnerExecution().effect('write',()=>{});
  res.json({ok:true});
 },{withAdmission:async(_,work)=>work({check:async()=>{if(!live)throw new Error('lifecycle lost');}})});
 await route({},out);assert.equal(effects,0);assert.equal(out.statusCode,500);
});

test('optional admission wrap preserves checks and release while fencing callback admission and publication',async()=>{
 const {createAdmittedPlatformSessionFence}=require('../server/agent-runtime/admittedPlatformSession');
 const {getOwnerExecution}=require('../server/agent-runtime/ownerWorkflowRoutes');
 for(const phase of ['normal','provider','admission','publication']){
  let live=true,checks=0,released=false,effects=0,entered,release;
  const waiting=new Promise(resolve=>entered=resolve),pause=()=>{entered();return new Promise(resolve=>release=resolve);};
  const signal=new AbortController().signal;
  const execution={signal,check:async()=>{},effect:async function(key,work){assert.equal(this,execution);if(phase==='admission')await pause();return work.call({callback:true},'argument');}};
  const coordinator={run:async(_owner,_options,work)=>work(execution)};
  const req={user:{id:7},identitySession:{id:11},headers:{authorization:'Bearer private'}};
  const route=ownerWorkflowRoute(coordinator,()=>7,async(_req,out)=>{
   const run=getOwnerExecution();assert.equal(run.signal,signal);if(phase==='provider')await pause();
   await run.effect('tool',function(arg){assert.equal(this.callback,true);assert.equal(arg,'argument');effects++;});
   if(phase==='publication')await pause();out.json({private:'held'});
  },{withAdmission:async(owner,work,request)=>{
   assert.equal(request,req);assert.equal(owner,7);
   const fence=createAdmittedPlatformSessionFence(request,{validateSession:async()=>live?{user:{id:7},session:{id:11,user_id:7}}:null});
   const guard={check:async()=>{checks++;await fence.check();},wrap:fence.wrap};
   try{return await work(guard);}finally{released=true;}
  }});
  const res=response(),pending=route(req,res);if(phase!=='normal'){await waiting;live=false;release();}await pending;
  assert.equal(released,true);assert.ok(checks>0);assert.equal(effects,['normal','publication'].includes(phase)?1:0);
  if(phase==='normal')assert.equal(res.payload.private,'held');else{assert.equal(res.statusCode,401);assert.equal(res.payload.code,'SESSION_REVOKED');assert.equal(res.payload.private,undefined);}
 }
});

test('session publication authority survives coordinator finalization without calling released lifecycle checks',async()=>{
 let live=true,active=true,entered,release;const waiting=new Promise(resolve=>entered=resolve);
 const execution={check:async()=>{},signal:new AbortController().signal};
 const coordinator={run:async(_owner,_options,work)=>{await work(execution);entered();await new Promise(resolve=>release=resolve);}};
 const route=ownerWorkflowRoute(coordinator,()=>7,(_req,res)=>res.json({held:true}),{withAdmission:async(_owner,work)=>{
  try{return await work({check:async()=>{assert.equal(active,true);},checkPublication:async()=>{assert.equal(active,false);if(!live)throw Object.assign(Error('revoked'),{code:'SESSION_REVOKED'});}});}finally{active=false;}
 }});
 const res=response(),pending=route({},res);await waiting;live=false;release();await pending;assert.equal(res.statusCode,401);assert.equal(res.payload.held,undefined);
 const releaseFailure=ownerWorkflowRoute({run:async(_o,_p,work)=>work(execution)},()=>7,(_q,r)=>r.json({held:true}),{withAdmission:async(_o,work)=>{await work({check:async()=>{}});throw Error('lease release failed');}});
 const failed=response();await releaseFailure({},failed);assert.equal(failed.statusCode,500);assert.equal(failed.payload.held,undefined);
});

 test('publication callback is captured once and rejects invalid callback types',async()=>{
  let originalChecks=0;const guard={check:async()=>{},checkPublication:async()=>{originalChecks++;}};
  const coordinator={run:async(_o,_p,work)=>{await work({check:async()=>{}});guard.checkPublication=()=>{throw Error('replacement must not run');};}};
  const out=response();await ownerWorkflowRoute(coordinator,()=>1,(_q,r)=>r.json({ok:true}),{withAdmission:(_o,work)=>work(guard)})({},out);assert.equal(out.statusCode,200);assert.equal(originalChecks,1);
  const invalid=response();await ownerWorkflowRoute(coordinator,()=>1,(_q,r)=>r.json({ok:true}),{withAdmission:(_o,work)=>work({check:async()=>{},checkPublication:true})})({},invalid);assert.equal(invalid.statusCode,500);assert.equal(invalid.payload.ok,undefined);
 });

test('complete admission wrapper rejects malformed opt-in and lost run identity/methods before handler',async()=>{
 const signal=new AbortController().signal;const execution={runId:'owned',ownerKey:'owner',generation:1,durableGeneration:2,signal,check:async()=>{},effect:async()=>{},effectWithReceipt:async()=>{},checkpoint:async()=>{},trace:async()=>{}};
 const variants=[{wrapOwnsAdmission:'true'}, {wrapOwnsAdmission:true}, ...['runId','ownerKey','generation','durableGeneration','signal'].map(key=>({wrapOwnsAdmission:true,wrap:e=>({...e,[key]:null})})),...['check','effect','effectWithReceipt','checkpoint','trace'].map(key=>({wrapOwnsAdmission:true,wrap:e=>({...e,[key]:null})}))];
 for(const malformed of variants){let entered=false;const res=response();await ownerWorkflowRoute({run:async(_o,_p,work)=>work(execution)},()=>7,(_q,r)=>{entered=true;r.json({ok:true});},{withAdmission:(_o,work)=>work({check:async()=>{},...malformed})})({},res);assert.equal(entered,false);assert.equal(res.statusCode,500);}
});
test('complete session wrapper retains entry, callback and post-finalization revocation fences',async()=>{
 const {createAdmittedPlatformSessionFence:create}=require('../server/agent-runtime/admittedPlatformSession');
 const {getOwnerExecution}=require('../server/agent-runtime/ownerWorkflowRoutes');
 for(const phase of ['entry','provider','admission','callback','finalization','normal']){
  let live=true,effects=0,wraps=0;
  const req={headers:{authorization:'Bearer controlled'},user:{id:7},identitySession:{id:11}};
  const execution={runId:'run',ownerKey:'owner',generation:1,durableGeneration:1,signal:new AbortController().signal,check:async()=>{},effect:async function(key,work){assert.equal(this,execution);if(phase==='admission')live=false;return work.call({receiver:true},42);}};
  const coordinator={run:async(_o,_p,work)=>{if(phase==='entry')live=false;await work(execution);if(phase==='finalization')live=false;}};
  const res=response();await ownerWorkflowRoute(coordinator,()=>7,async(_q,r)=>{if(phase==='provider')live=false;await getOwnerExecution().effect('tool',function(value){assert.equal(this.receiver,true);assert.equal(value,42);effects++;if(phase==='callback')live=false;});r.json({private:'held'});},{withAdmission:async(_o,work)=>{const f=create(req,{validateSession:async()=>live?{user:{id:7},session:{id:11,user_id:7}}:null});await f.check();return work({...f,wrapOwnsAdmission:true,wrap:e=>{wraps++;assert.equal(e,execution);return f.wrap(e);},checkPublication:f.check});}})(req,res);
  assert.equal(wraps,1);assert.equal(effects,['callback','finalization','normal'].includes(phase)?1:0);assert.equal(res.statusCode,phase==='normal'?200:401);assert.equal(res.payload.private,phase==='normal'?'held':undefined);
 }
});

test('server timeout mapper is captured once, defaults stay absent, body timeout is ignored and resets reject it',async()=>{
 let options,calls=0;const coordinator={run:async(owner,opts,fn)=>{options=opts;await fn({check:async()=>{}});}};
 const route=ownerWorkflowRoute(coordinator,()=>1,(req,res)=>res.json({ok:true}),{timeoutFor:()=>{calls++;return 300000;}});
 await route({body:{timeoutMs:1}},response());assert.equal(options.timeoutMs,300000);assert.equal(calls,1);
 await ownerWorkflowRoute(coordinator,()=>1,(req,res)=>res.json({ok:true}))({body:{timeoutMs:300000}},response());assert.equal(Object.hasOwn(options,'timeoutMs'),false);
 assert.throws(()=>ownerWorkflowRoute(coordinator,()=>1,()=>{},{reset:true,timeoutFor:()=>1}),/Reset/);
 assert.throws(()=>ownerWorkflowRoute(coordinator,()=>1,()=>{},{timeoutFor:1}),/mapper/);
 for(const value of [null,0,-1,NaN,Infinity,300001,1.5,'300000']){let admitted=false;const out=response();await ownerWorkflowRoute({run:()=>{admitted=true;}},()=>1,()=>{},{timeoutFor:()=>value})({},out);assert.equal(admitted,false);assert.equal(out.statusCode,500);}
});
test('mapped aggregate deadline aborts actual coordinator and prevents publication',async()=>{
 const runs=createRunCoordinator({family:'mapped-timeout',ledger:null,defaultTimeoutMs:240000});let signal;
 const out=response();await ownerWorkflowRoute(runs,()=>1,async(req,res)=>{signal=require('../server/agent-runtime/ownerWorkflowRoutes').getOwnerExecution().signal;await new Promise(resolve=>signal.addEventListener('abort',resolve,{once:true}));await checkOwnerRun();res.json({late:true});},{timeoutFor:()=>15})({},out);
 assert.equal(signal.aborted,true);assert.equal(out.statusCode,409);assert.equal(out.payload.late,undefined);
});
