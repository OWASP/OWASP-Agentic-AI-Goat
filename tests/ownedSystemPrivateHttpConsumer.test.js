'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const runtime = require('./postgres/ownedSystemPrivateHttpConsumer');
const {validateBinding,operationProgram,validateRetirement} = runtime._internals;
function binding() { return {version:1,target:'original-v24-system',runId:'a'.repeat(32),imageId:'sha256:'+'b'.repeat(64),
  inputSha256:'c'.repeat(64),daemonId:'d'.repeat(36),physical:{privateDockerHost:'unix:///var/tmp/dvaia-v23-build-'+'a'.repeat(32)+'/fs/docker.sock',
    namespaceInode:'net:[12345]',filesystemIdentity:{device:1,inode:2},daemonProcess:{pid:101,startTicks:'100',exe:'/usr/bin/dockerd'},
    namespaceHolder:{pid:102,startTicks:'101',exe:'/usr/bin/sleep'}}}; }
test('public entry remains closed for serialized or cloned image receipts before consumer effects', async()=>{
  assert.equal(runtime.LIVE_ENABLED,false);let calls=0;
  for(const cap of [null,{},binding(),JSON.parse(JSON.stringify(binding()))])
    await assert.rejects(runtime.withSystemPrivateHttp(cap,{},()=>{calls++;}),{code:'SYSTEM_IMAGE_NOT_LIVE'});
  assert.equal(calls,0);
});
test('consumer brand rejection precedes lifecycle/receipt getters and cannot be enabled by claimed admission fields',async()=>{
 let reads=0,calls=0;
 const poison=new Proxy({}, {get(){reads++;throw Error('must not inspect caller authority');}});
 for(const cap of [poison,{LIVE_ENABLED:true,executionApproved:true,runtimeAvailable:true,owner:ownerFixture().owner},
   Object.freeze({version:1,qualificationAccepted:true,binding:binding()})]){
  await assert.rejects(runtime.withSystemPrivateHttp(cap,poison,()=>{calls++;}),{code:'SYSTEM_IMAGE_NOT_LIVE'});
 }
 assert.equal(reads,0);assert.equal(calls,0);
});
test('closed System binding cannot target shared Docker, another target, PID alias or path',()=>{
  assert.deepEqual(validateBinding(binding()),binding());
  for(const mutate of [b=>b.target='original-v23-registry',b=>b.physical.privateDockerHost='unix:///var/run/docker.sock',
    b=>b.physical.namespaceHolder.pid=101,b=>b.physical.namespaceInode='net:[0]',b=>b.physical.daemonProcess.exe='/bin/sh',
    b=>b.extra=true,b=>b.physical.filesystemIdentity.inode=-1]) {const b=binding();mutate(b);assert.throws(()=>validateBinding(b));}
});
test('fixed operation source retains original profile and no host publish or caller command',()=>{
  for(const op of ['start','inspect','stop']) {const p=operationProgram(binding(),op);assert.match(p.sourceSha256,/^[a-f0-9]{64}$/);
    assert.match(p.source,/SECURESHOP_SYSTEM_CONFIG_PORT=8090/);assert.match(p.source,/system-runtime\.deadline/);
    assert.match(p.source,/--network', 'none' if self.policy else 'host'/);assert.doesNotMatch(p.source,/'-p',|'--publish',/);}
  assert.throws(()=>operationProgram(binding(),'shell'));assert.throws(()=>operationProgram(binding(),'start',['a'.repeat(32)]));
  assert.throws(()=>operationProgram(binding(),'stop',['a'.repeat(32),'a'.repeat(32)]));
});
test('retirement keeps local and remote observations distinct and never mints release authority',()=>{
  const b=binding(),local={version:1,runId:b.runId,channelIds:[],localRetired:true,retirementUnproven:false,remoteRetired:false,builderReleaseAllowed:false,failures:[]};
  const remote={version:1,runId:b.runId,containerAbsent:true,profileAbsent:true,remoteChannelsAbsent:true,channelFailures:[],builderReleaseAllowed:false};
  assert.deepEqual(validateRetirement(b,local,remote),{retirementObserved:true,transportSucceeded:true,builderReleaseAllowed:false,failures:[]});
  assert.equal(validateRetirement(b,{...local,failures:['LostTransport']},remote).transportSucceeded,false);
  for(const [l,r] of [[{...local,localRetired:false},remote],[local,{...remote,remoteChannelsAbsent:false}],
    [local,{...remote,runId:'f'.repeat(32)}],[{...local,builderReleaseAllowed:true},remote]])
    assert.throws(()=>validateRetirement(b,l,r),{code:'SYSTEM_RETIREMENT_UNPROVEN'});
});
test('unchanged original client readiness validates exact health without config-read substitute or retry',async()=>{
  const requests=[];const controller=new AbortController();
  const options={port:18090,token:'a'.repeat(43),signal:controller.signal,deadline:performance.now()+1000};
  const health={version:'secureshop-owned-system-http.v1',ready:true,isolation:'bwrap-system-config-v1',configReadCapability:'secureshop-owned-system-config-read.v1'};
  const client=await runtime._internals.originalReadiness(options,async(url,init)=>{
    requests.push({url:url.href,method:init.method});return new Response(JSON.stringify(health));
  });
  assert.equal(typeof client.read,'function');assert.equal(typeof client.metrics,'function');
  assert.deepEqual(requests,[{url:'http://127.0.0.1:18090/secureshop/system/health',method:'GET'}]);
  let calls=0;
  await assert.rejects(runtime._internals.originalReadiness(options,async()=>{calls++;return new Response(JSON.stringify({...health,extra:true}));}),{code:'SYSTEM_CONFIG_UNAVAILABLE'});
  assert.equal(calls,1);
  controller.abort();await assert.rejects(runtime._internals.originalReadiness(options,()=>{calls++;}));assert.equal(calls,1);
});
test('fixed bridge template requires exact binding and preserves source pin and stop-pipe protocol',()=>{
  const program=runtime._internals.bridgeProgram(binding(),{masterBirth:[1,2]});
  assert.match(program.source,/SYSTEM_CHANNEL_SOURCE/);assert.match(program.source,/bridge_controller\(/);
  assert.match(program.source,/len\(sys.argv\)==2/);assert.match(program.source,/b'S'/);
  assert.throws(()=>runtime._internals.bridgeProgram(binding(),null));
});
test('startup-only health polling never retries a tool POST and is bounded by inherited deadline',async()=>{
  const controller=new AbortController(),calls=[];
  const health={version:'secureshop-owned-system-http.v1',ready:true,isolation:'bwrap-system-config-v1',configReadCapability:'secureshop-owned-system-config-read.v1'};
  const client=await runtime._internals.waitForOriginalReadiness({port:18090,token:'a'.repeat(43),signal:controller.signal,deadline:performance.now()+1500},async(url,init)=>{
    calls.push([url.pathname,init.method]);return calls.length===1?new Response('',{status:503}):new Response(JSON.stringify(health));
  });
  assert.equal(typeof client.metrics,'function');assert.deepEqual(calls,[['/secureshop/system/health','GET'],['/secureshop/system/health','GET']]);
  await assert.rejects(runtime._internals.waitForOriginalReadiness({port:18090,token:'a'.repeat(43),signal:controller.signal,deadline:performance.now()-1},()=>{throw Error('must not fetch');}),{code:'SYSTEM_READINESS_DEADLINE'});
});

function ownerFixture() {
  const b=binding(),events=[];
  let cleanupEnd;
  const runtimeReceipt={version:1,runId:b.runId,containerId:'e'.repeat(64),imageId:b.imageId,running:true,namespaceInode:12345};
  const local={version:1,runId:b.runId,channelIds:[],localRetired:true,retirementUnproven:false,remoteRetired:false,builderReleaseAllowed:false,failures:[]};
  const remote={version:1,runId:b.runId,containerAbsent:true,profileAbsent:true,remoteChannelsAbsent:true,channelFailures:[],builderReleaseAllowed:false};
  const owner={binding:b,beginRetirement(){return cleanupEnd ??= performance.now()+600000;},assertActive(){events.push('active');},async startRuntime({token}){assert.match(token,/^[A-Za-z0-9_-]{43}$/);events.push('start');return runtimeReceipt;},
    async inspectRuntime(){events.push('inspect');return {...runtimeReceipt};},async openBridge(){events.push('bridge');return {port:18090};},
    async closeBridge(){events.push('close');return local;},async stopRuntime(){events.push('stop');return remote;},
    async confirmRetired(...args){assert.deepEqual(args,[]);events.push('confirm');return true;}};
  const health=async()=>new Response(JSON.stringify({version:'secureshop-owned-system-http.v1',ready:true,isolation:'bwrap-system-config-v1',configReadCapability:'secureshop-owned-system-config-read.v1'}));
  return {owner,events,local,remote,runtimeReceipt,health};
}
const life=signal=>({signal:signal||new AbortController().signal,deadline:performance.now()+10000});
function pairFixture(){
 const system=ownerFixture(),policy=ownerFixture(),events=[];let end,claims=0;
 policy.owner.binding.target='original-v24-policy';policy.owner.binding.imageId='sha256:'+'f'.repeat(64);
 Object.assign(policy.runtimeReceipt,{target:'original-v24-policy',namespaceInode:23456,imageId:policy.owner.binding.imageId,containerId:'f'.repeat(64)});
 policy.local.target=policy.remote.target='original-v24-policy';
 policy.owner.startRuntime=async input=>{assert.deepEqual(input,{});return policy.runtimeReceipt;};
 policy.owner.openBridge=async()=>({port:18091});
 for(const [slot,f]of Object.entries({system,policy}))for(const name of ['startRuntime','inspectRuntime','openBridge','closeBridge','stopRuntime','confirmRetired']){
  const original=f.owner[name];f.owner[name]=(...args)=>{events.push(slot+':'+name);return original(...args);};
 }
 const owner={slots:{system:system.owner,policy:policy.owner},assertActive(){},beginRetirement(){claims++;return end??=performance.now()+600000;}};
 const fetch=async(url,init)=>{const u=new URL(url);events.push(u.port+':'+u.pathname);
  if(u.port==='18090')return system.health(url,init);
  assert.equal(u.port,'18091');assert.equal(init.headers,undefined);
  return new Response(JSON.stringify({policyRenderer:{enabled:true,available:true,isolation:require('../server/services/secureshopPromptPolicyContract').ISOLATION}}));};
 return {owner,system,policy,events,fetch,get claims(){return claims;}};
}
test('paired consumer gates callback on both actual original readiness clients and retires all channels first',async()=>{
 const f=pairFixture();let calls=0;
 const result=await runtime._internals.runControlledPairConsumer(f.owner,life(),endpoints=>{
  calls++;assert.equal(typeof endpoints.system.client.read,'function');assert.equal(typeof endpoints.policy.client.render,'function');
  assert.equal(endpoints.system.baseURL,'http://127.0.0.1:18090');assert.equal(endpoints.policy.baseURL,'http://127.0.0.1:18091');
  assert(!('token' in endpoints.policy));assert(f.events.includes('18090:/secureshop/system/health'));assert(f.events.includes('18091:/health'));
  f.events.push('callback');return 'original-cohort';
 },f.fetch);
 assert.equal(calls,1);assert.equal(result.value,'original-cohort');assert.equal(result.qualificationAccepted,false);
 assert(f.events.indexOf('callback')<f.events.indexOf('system:closeBridge'));
 assert(f.events.indexOf('policy:closeBridge')<f.events.indexOf('system:stopRuntime'));
 assert(f.events.indexOf('policy:stopRuntime')<f.events.indexOf('system:confirmRetired'));
 assert(f.claims>1);
});
test('paired missing/false renderer readiness or second start failure cannot invoke cohort and joins both obligations',async()=>{
 for(const fault of ['start','health']){
  const f=pairFixture();let callbacks=0;
  if(fault==='start')f.policy.owner.startRuntime=async()=>{f.events.push('policy:startRuntime');throw Error('renderer start lost');};
  const fetch=(url,init)=>new URL(url).port==='18091'?Promise.resolve(new Response('{}')):f.fetch(url,init);
  await assert.rejects(runtime._internals.runControlledPairConsumer(f.owner,life(),()=>{callbacks++;},fetch));
  assert.equal(callbacks,0);assert(f.events.includes('system:confirmRetired'));assert(f.events.includes('policy:confirmRetired'));
  assert(f.events.indexOf('policy:closeBridge')<f.events.indexOf('system:stopRuntime'));
 }
});
test('retained original clients cannot dispatch after paired callback retirement even without caller signals',async()=>{
 const f=pairFixture();let endpoints;
 await runtime._internals.runControlledPairConsumer(f.owner,life(),value=>{endpoints=value;},f.fetch);
 const count=f.events.length;
 await assert.rejects(endpoints.system.client.assertReady());await assert.rejects(endpoints.policy.client.checkReadiness());
 assert.equal(f.events.length,count);
});
test('paired channel debt prevents every remote deletion and preserves the original failure',async()=>{
 const f=pairFixture();f.policy.owner.closeBridge=async()=>{throw Error('renderer still active');};
 await assert.rejects(runtime._internals.runControlledPairConsumer(f.owner,life(),()=>{throw Error('original cohort failed');},f.fetch),error=>{
  assert.equal(error.message,'original cohort failed');assert.equal(error.cleanupError.message,'renderer still active');assert.equal(error.retirementUnproven,true);return true;
 });
 assert(!f.events.some(e=>e.endsWith(':stopRuntime')));assert(!f.events.some(e=>e.endsWith(':confirmRetired')));
});
test('paired abort after first readiness prevents second dispatch and joins only attempted target',async()=>{
 const f=pairFixture(),controller=new AbortController();
 await assert.rejects(runtime._internals.runControlledPairConsumer(f.owner,life(controller.signal),()=>assert.fail('no cohort'),async(url,init)=>{
  const response=await f.fetch(url,init);controller.abort(Error('stop between endpoints'));return response;
 }),/stop between endpoints/);
 assert(!f.events.includes('policy:startRuntime'));assert(f.events.includes('system:confirmRetired'));assert(!f.events.includes('policy:stopRuntime'));
});
test('paired namespace or endpoint alias fails before callback without accepting cross-target receipts',async()=>{
 for(const fault of ['namespace','port']){
  const f=pairFixture();if(fault==='namespace')f.policy.runtimeReceipt.namespaceInode=12345;
  else f.policy.owner.openBridge=async()=>({port:18090});
  await assert.rejects(runtime._internals.runControlledPairConsumer(f.owner,life(),()=>assert.fail('no cohort'),f.fetch));
  assert(f.events.includes('policy:confirmRetired'));
 }
 let calls=0;await assert.rejects(runtime.withSystemAndPolicyPrivateHttp({},life(),()=>{calls++;}),/SYSTEM_PAIR_RUNTIME_NOT_LIVE/);assert.equal(calls,0);
});
test('renderer original readiness uses real protocol, bounded lifecycle, and no System credential',async()=>{
 const c=new AbortController(),calls=[],end=performance.now()+10000;
 const runtimeClient=await runtime._internals.policyReadiness({port:18091,signal:c.signal,deadline:end},async(url,request)=>{
  calls.push({url,method:request.method,headers:request.headers,signal:request.signal,redirect:request.redirect});
  return new Response(JSON.stringify({policyRenderer:{enabled:true,available:true,isolation:require('../server/services/secureshopPromptPolicyContract').ISOLATION}}));
 });
 assert.equal(typeof runtimeClient.render,'function');assert.equal(calls.length,1);
 assert.equal(calls[0].url,'http://127.0.0.1:18091/health');assert.equal(calls[0].headers,undefined);
 assert.equal(calls[0].redirect,'error');c.abort();
 await assert.rejects(runtimeClient.checkReadiness());assert.equal(calls.length,1);
 await assert.rejects(runtime._internals.policyReadiness({port:18091,signal:new AbortController().signal,deadline:end},async()=>
  new Response(JSON.stringify({policyRenderer:{enabled:true,available:true,isolation:'fake'}}))),{code:'POLICY_RENDER_UNAVAILABLE'});
});
test('renderer binding and runtime/retirement are literal target-specific and never admit System receipt swaps',()=>{
 const b={...binding(),target:'original-v24-policy'};assert.deepEqual(validateBinding(b),b);
 const f=ownerFixture(),row={...f.runtimeReceipt,target:b.target,namespaceInode:23456};
 assert.deepEqual(runtime._internals.validateRuntime(b,row),row);
 for(const changed of [{...row,namespaceInode:12345},{...row,target:'original-v24-system'},f.runtimeReceipt])
  assert.throws(()=>runtime._internals.validateRuntime(b,changed));
 assert.throws(()=>validateRetirement(b,f.local,f.remote));
 assert.equal(validateRetirement(b,{...f.local,target:b.target},{...f.remote,target:b.target}).retirementObserved,true);
});
test('renderer consumer preserves original protocol and retains failed second startup without fake confirmation',async()=>{
 const f=ownerFixture();f.owner.binding.target='original-v24-policy';
 f.owner.startRuntime=async input=>{assert.deepEqual(input,{});f.events.push('policy-start');throw Error('second-start-failed');};
 f.local.target=f.remote.target='original-v24-policy';
 await assert.rejects(runtime._internals.runControlledConsumer(f.owner,life(),()=>assert.fail('no callback'),f.health),/second-start-failed/);
 assert.deepEqual(f.events.filter(x=>['policy-start','close','stop','confirm'].includes(x)),['policy-start','close','stop','confirm']);
 const pending=ownerFixture();pending.owner.binding.target='original-v24-policy';
 pending.owner.startRuntime=async()=>{throw Error('start failed');};
 pending.owner.closeBridge=async()=>{throw Object.assign(Error('unjoined channel'),{retirementUnproven:true});};
 await assert.rejects(runtime._internals.runControlledConsumer(pending.owner,life(),()=>assert.fail(),pending.health),
  error=>error.message==='start failed'&&error.retirementUnproven===true);
 assert.equal(pending.events.includes('stop'),false);assert.equal(pending.events.includes('confirm'),false);
});
test('renderer abort between stage admission and deferred invocation cannot start a container',async()=>{
 const f=ownerFixture(),c=new AbortController();f.owner.binding.target='original-v24-policy';
 f.local.target=f.remote.target='original-v24-policy';let checks=0,starts=0;
 f.owner.assertActive=()=>{if(++checks===2)queueMicrotask(()=>c.abort(Error('before actual dispatch')));};
 f.owner.startRuntime=async()=>{starts++;throw Error('must not start');};
 await assert.rejects(runtime._internals.runControlledConsumer(f.owner,life(c.signal),()=>assert.fail(),f.health),/before actual dispatch/);
 assert.equal(starts,0);
});
test('actual serialized renderer operation consumes no token and preserves supplied nonrenewing deadline',()=>{
 const b={...binding(),target:'original-v24-policy'},program=operationProgram(b,'start');
 const suffix=program.source.slice(program.source.indexOf('\nimport base64, signal\nstopping'));
 const input={deadline:100,runtimeDeadline:120};
 const code=`import json,os,select,types\nclass GuestRuntime:\n def __init__(self,b,end,stopped):\n  assert b['target']=='original-v24-policy' and end==100\n def start(self,token,profile,end):\n  assert token is None and end==120 and len(profile)>100\n  return {'observed':True}\nos.read=lambda *args:${JSON.stringify(Buffer.from(JSON.stringify(input)).toString('base64'))}\nimport base64\nos.read=lambda *args:base64.b64decode(${JSON.stringify(Buffer.from(JSON.stringify(input)).toString('base64'))})\nselect.select=lambda *args:([0],[],[])\ndef require(value,code):\n if not value:raise RuntimeError(code)\n`+suffix;
 const run=require('node:child_process').spawnSync('/opt/homebrew/bin/python3',['-I','-S','-B','-c',code],{encoding:'utf8',timeout:5000,maxBuffer:8192});
 assert.equal(run.status,0,run.stderr);assert.deepEqual(JSON.parse(run.stdout),{observed:true});
});
test('retirement deadline is finite bounded and cannot renew between phases',async()=>{
  for (const value of [NaN,Infinity,performance.now()-1,performance.now()+700000,Promise.resolve(42)]) {
    const f=ownerFixture();f.owner.beginRetirement=()=>value;
    await assert.rejects(runtime._internals.runControlledConsumer(f.owner,life(),async()=>1,f.health),
      error=>error.code==='SYSTEM_RETIREMENT_DEADLINE'&&error.retirementUnproven===true);
    assert.equal(f.events.includes('close'),false);assert.equal(f.events.includes('stop'),false);
  }
  const f=ownerFixture();let end;
  f.owner.beginRetirement=()=>end===undefined?(end=performance.now()+1000):++end;
  await assert.rejects(runtime._internals.runControlledConsumer(f.owner,life(),async()=>1,f.health),
    error=>error.code==='SYSTEM_RETIREMENT_DEADLINE'&&error.retirementUnproven===true);
  assert.equal(f.events.includes('close'),false);
});
test('one short owner cleanup budget expires without starting later teardown',async()=>{
  const f=ownerFixture();let end,finish;
  f.owner.beginRetirement=()=>end??=performance.now()+15;
  f.owner.closeBridge=()=>new Promise(resolve=>{finish=()=>resolve(f.local);});
  await assert.rejects(runtime._internals.runControlledConsumer(f.owner,life(),async()=>1,f.health),
    error=>error.code==='SYSTEM_CLEANUP_DEADLINE'&&error.retirementUnproven===true);
  assert.equal(f.events.includes('stop'),false);assert.equal(f.events.includes('confirm'),false);
  finish();await new Promise(resolve=>setImmediate(resolve));
});
test('controlled owning lifecycle joins real-shaped runtime and teardown without minting qualification',async()=>{
  const f=ownerFixture();
  const result=await runtime._internals.runControlledConsumer(f.owner,life(),async context=>{
    f.events.push('consumer');assert.equal(context.baseURL,'http://127.0.0.1:18090');assert.equal(typeof context.client.metrics,'function');return 'finished';
  },f.health);
  assert.equal(result.value,'finished');assert.equal(result.controlled,true);assert.equal(result.qualificationAccepted,false);
  assert.deepEqual(f.events.filter(x=>x!=='active'),['start','inspect','bridge','consumer','close','stop','confirm']);
});
test('runtime identity disagreement prevents bridge and consumer but attempts owned cleanup',async()=>{
  const f=ownerFixture();f.owner.inspectRuntime=async()=>({...f.runtimeReceipt,containerId:'f'.repeat(64)});
  await assert.rejects(runtime._internals.runControlledConsumer(f.owner,life(),()=>{throw Error('unexpected consumer');},f.health),{code:'SYSTEM_RUNTIME_CHANGED'});
  assert.equal(f.events.includes('bridge'),false);assert.equal(f.events.includes('confirm'),true);
});
test('local retirement debt stops remote teardown; failed owner confirmation never permits release',async()=>{
  const f=ownerFixture();f.local.localRetired=false;f.local.retirementUnproven=true;
  await assert.rejects(runtime._internals.runControlledConsumer(f.owner,life(),async()=>1,f.health),error=>error.retirementUnproven===true);
  assert.equal(f.events.includes('stop'),false);assert.equal(f.events.includes('confirm'),false);
  const g=ownerFixture();g.owner.confirmRetired=async()=>false;
  await assert.rejects(runtime._internals.runControlledConsumer(g.owner,life(),async()=>1,g.health),error=>error.code==='SYSTEM_OWNER_RETIREMENT_UNPROVEN'&&error.retirementUnproven===true);
});
test('transport failure stays failure after proven retirement and preserves a prior primary',async()=>{
  const f=ownerFixture();f.local.failures.push('RemoteFailed');
  await assert.rejects(runtime._internals.runControlledConsumer(f.owner,life(),async()=>1,f.health),error=>error.code==='SYSTEM_TRANSPORT_FAILED'&&error.retirement?.retirementObserved===true);
  assert.equal(f.events.includes('confirm'),true);
  const g=ownerFixture();g.local.failures.push('RemoteFailed');const primary=Error('original');
  await assert.rejects(runtime._internals.runControlledConsumer(g.owner,life(),async()=>{throw primary;},g.health),error=>error===primary&&error.cleanupError.code==='SYSTEM_TRANSPORT_FAILED');
});
test('cancelled owner operation must settle before any runtime teardown',async()=>{
  const f=ownerFixture(),controller=new AbortController();let complete;
  f.owner.startRuntime=()=>new Promise(resolve=>{complete=()=>{f.events.push('settled');resolve(f.runtimeReceipt);};});
  const promise=runtime._internals.runControlledConsumer(f.owner,life(controller.signal),async()=>1,f.health);
  await new Promise(resolve=>setImmediate(resolve));controller.abort(Error('cancelled'));
  await new Promise(resolve=>setImmediate(resolve));assert.equal(f.events.includes('close'),false);
  complete();await assert.rejects(promise,/cancelled/);
  assert.ok(f.events.indexOf('settled')<f.events.indexOf('close'));
});
