'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),vm=require('node:vm');
const fs=require('node:fs'),path=require('node:path'),{createRequire}=require('node:module');
const service=require('./postgres/ownedMcpOriginalService');
const original=require('./postgres/ownedMcpRegistryService')._internals;
const TOKEN='x'.repeat(43),PREFIX='/secureshop/mcp-registry';
const identity={instanceId:'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  operationId:'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',requestSha256:'c'.repeat(64)};
const reply=q=>JSON.stringify({status:200,body:{version:1,...q,state:'completed',drained:true}});
function setup(){
  const records=[],calls=[];let end;
  const owner={assertActive(){},record(row){records.push(row);},
    execRegistration:async packet=>{const q=JSON.parse(packet);calls.push(q.path);return reply(identity);},
    beginRetirement(){return end??=performance.now()+1000;},
    async closeEndpoint(){calls.push('endpoint-close');},async stopListener(){calls.push('listener-stop');},
    async confirmRetired(){calls.push('confirm');return true;}};
  const open=()=>service._internals.createControlledService(owner,
    {token:TOKEN,signal:new AbortController().signal,deadline:performance.now()+1000});
  return{owner,open,calls,records};
}
test('public fence and separate prospective budget preserve original cohort/default fixture',async()=>{
  assert.equal(service.LIVE_ENABLED,false);await assert.rejects(service.withOriginalService({}),{code:'ORIGINAL_SERVICE_NOT_ADMITTED'});
  assert.equal(service.TOTAL_LEASE_SECONDS,7400);assert.equal(service.BUDGET.originalCohortSeconds,1200);
  assert.equal(service.BUDGET.serviceStartupSeconds,120);assert.equal(service.LIMITS.registrationEffects,2);
});
async function emittedProxy(packet,respond){
 let output='',diagnostic='';
 const code=await new Promise(resolve=>vm.runInNewContext(service.fixedProxy('v39-atomic-pair').source,
  {Buffer,JSON,Error,AbortSignal,setTimeout:()=>0,clearTimeout:()=>{},
   fetch:async(url,options)=>{assert.equal(url,'http://127.0.0.1:8094'+PREFIX+JSON.parse(packet).path);
    assert.equal(options.redirect,'error');assert.equal(options.headers.authorization,'Bearer '+TOKEN);
    const row=await respond(JSON.parse(packet));return{status:row.status,body:(async function*(){yield Buffer.from(JSON.stringify(row.body));})()};},
   process:{stdin:(async function*(){yield Buffer.from(packet);})(),exit:resolve,
    stdout:{write(bytes,callback){output+=bytes;callback();}},stderr:{write(bytes,callback){diagnostic+=bytes;callback();}}}}));
 if(code!==0)throw Object.assign(Error('controlled proxy failed'),{code:'CONTROLLED_PROXY_FAILED'});
 assert.equal(diagnostic,'');return output;
}
function invocation(){
 const tools=[{name:'echo',description:'controlled tool',inputSchema:{type:'object'}}];
 return{version:1,instanceId:identity.instanceId,operationId:identity.operationId,
  entry:{entryId:'dddddddd-dddd-4ddd-8ddd-dddddddddddd',registryVersion:'1',transport:'stdio',endpoint:'node packaged.js',
   tools,schemaSha256:require('../server/services/secureshopMcpSchemaDigest').mcpSchemaDigest(tools)},toolName:'echo',args:{}};
}
for(const profile of ['v39-atomic-pair','q05-registered-pair'])test(profile+' actual relay to serialized proxy preserves production execute/invoke and exact status/drain',async()=>{
 const protocol=require('../sidecars/sandbox-runner/owned-mcp-registry/invoke-protocol');
 const q=invocation(),id={instanceId:q.instanceId,operationId:q.operationId,requestSha256:protocol.digest(q)},calls=[];
 const result={content:[{type:'text',text:'controlled'}]};
 const receipt={version:1,...id,entryId:q.entry.entryId,registryVersion:q.entry.registryVersion,
  schemaSha256:q.entry.schemaSha256,endpointSha256:protocol.digest(q.entry.endpoint),argumentsSha256:protocol.digest(q.args),
  resultSha256:protocol.digest(result),result,isolation:'owned-mcp-registry-v1'};
 const f=setup();f.owner.execRegistration=packet=>emittedProxy(packet,async request=>{
  calls.push(request.path);
  if(request.path==='/health')return{status:200,body:{version:1,ready:true,isolation:'owned-mcp-registry-v1',registryCapability:'secureshop-owned-mcp-registry.v1',runtimeDigest:'a'.repeat(64)}};
  if(request.path==='/invoke/health')return{status:200,body:{version:1,instanceId:q.instanceId,runtimeDigest:'a'.repeat(64)}};
  if(request.path==='/execute'){assert.deepEqual(Object.keys(request.body).sort(),['activeEntries','mode','request']);return{status:200,body:{version:1,changes:[]}};}
  if(request.path==='/invoke')return{status:200,body:{version:1,receipt}};
  assert.ok(['/invoke/status','/invoke/drain'].includes(request.path));assert.deepEqual(request.body,id);
  return{status:200,body:{version:1,...id,state:'completed',drained:true}};
 });
 const s=service._internals.createControlledService(f.owner,{token:TOKEN,profile,signal:new AbortController().signal,deadline:performance.now()+10000});
 const relay=original.createRelay({token:TOKEN,profile,dispatch:(...args)=>s.dispatch(...args)});
 try{
  const address=await relay.listen(),client=require('../server/services/secureshopOwnedMcpRegistryClient').createOwnedMcpRegistryClient({
   baseURL:'http://127.0.0.1:'+address.port,token:TOKEN,expectedRuntimeDigest:'a'.repeat(64)});
  const registration={version:1,action:'retire',operationId:'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',expectedVersion:'1',name:'controlled'};
  assert.deepEqual(await client.execute(registration,{activeEntries:[],mode:'vuln',assertCurrent:async()=>{}}),[]);
  assert.deepEqual(await client.invoke(q),receipt);
  assert.equal((await client.invocationState(id)).drained,true);
  assert.equal((await client.invocationState(id,{drain:true})).drained,true);
  assert.throws(()=>s.dispatch('POST',PREFIX+'/invoke',q),/NO_INVOKE_RETRY/);
  assert.throws(()=>s.dispatch('POST',PREFIX+'/invoke/drain',{...id,requestSha256:'f'.repeat(64)}),/FOREIGN_RECOVERY/);
  for(const route of ['/execute/status','/execute/drain','/invoke?x=1']){
   const response=await fetch('http://127.0.0.1:'+address.port+PREFIX+route,{method:'POST',headers:{authorization:'Bearer '+TOKEN},body:'{}'});
   assert.equal(response.status,404);await response.arrayBuffer();
  }
  assert.deepEqual(calls,['/health','/execute','/invoke/health','/invoke','/invoke/status','/invoke/drain']);
 }finally{await relay.close();await s.close();}
});
test('V39 uncertain execute has no invented drain and survives until actual owner retirement',async()=>{
 for(const failStop of [false,true]){
  const f=setup(),primary=Object.assign(Error('lost execute'),{code:'LOST_EXECUTE'});
  f.owner.execRegistration=async()=>{throw primary;};
  f.owner.stopListener=async()=>{f.calls.push('listener-stop');if(failStop)throw Error('unknown container');};
  const s=service._internals.createControlledService(f.owner,{token:TOKEN,profile:'v39-atomic-pair',signal:new AbortController().signal,deadline:performance.now()+1000});
  const body={request:{version:1,action:'retire',operationId:identity.operationId,expectedVersion:'1',name:'controlled'},mode:'vuln',activeEntries:[]};
  await assert.rejects(s.dispatch('POST',PREFIX+'/execute',body),e=>e===primary);
  assert.equal(s.snapshot().unresolved,1);
  assert.throws(()=>s.dispatch('POST',PREFIX+'/execute',body),/NO_EXECUTE_RETRY/);
  await assert.rejects(s.close(),e=>e===primary&&e.retirementUnproven===failStop&&e.serviceReceipt.unresolved===(failStop?1:0));
  assert.equal(f.calls.includes('confirm'),!failStop);
 }
});
test('V39 production invocation failure drains the exact captured identity without retry',async()=>{
 const protocol=require('../sidecars/sandbox-runner/owned-mcp-registry/invoke-protocol'),q=invocation();
 const id={instanceId:q.instanceId,operationId:q.operationId,requestSha256:protocol.digest(q)},paths=[],f=setup();
 f.owner.execRegistration=packet=>emittedProxy(packet,async request=>{
  paths.push(request.path);
  if(request.path==='/invoke/health')return{status:200,body:{version:1,instanceId:q.instanceId,runtimeDigest:'a'.repeat(64)}};
  if(request.path==='/invoke')return{status:200,body:{version:1,receipt:{wrong:true}}};
  assert.equal(request.path,'/invoke/drain');assert.deepEqual(request.body,id);
  return{status:200,body:{version:1,...id,state:'retired',drained:true}};
 });
 const s=service._internals.createControlledService(f.owner,{token:TOKEN,profile:'v39-atomic-pair',signal:new AbortController().signal,deadline:performance.now()+1000});
 const client=require('../server/services/secureshopOwnedMcpRegistryClient').createOwnedMcpRegistryClient({
  baseURL:'http://127.0.0.1:8094',token:TOKEN,expectedRuntimeDigest:'a'.repeat(64),
  fetchImpl:async(url,options)=>{const row=await s.dispatch(options.method,url.pathname,options.body?JSON.parse(options.body):null);
   return new Response(JSON.stringify(row.body),{status:row.status});}});
 await assert.rejects(client.invoke(q),e=>e.code==='MCP_REGISTRY_INVOCATION_UNCERTAIN'&&e.drained===true);
 assert.deepEqual(paths,['/invoke/health','/invoke','/invoke/drain']);assert.equal(s.snapshot().unresolved,0);
 await assert.rejects(s.close(),e=>e.retirementUnproven===false&&e.serviceReceipt.retired===true);
});
test('actual fixed proxy source and serialized packet retain exact original protocol',async()=>{
  const fixed=service.fixedProxy();assert.equal(fixed.source,original.PROXY);
  assert.equal(fixed.network,'none');assert.equal(fixed.port,8094);assert.equal(fixed.executionApproved,false);
  const packet=service._internals.serializeRequest('POST',PREFIX+'/registration',identity,TOKEN);
  let observed,output='';
  const done=new Promise(resolve=>{
    vm.runInNewContext(fixed.source,{Buffer,JSON,Error,AbortSignal,
      setTimeout:()=>0,clearTimeout:()=>{},
      fetch:async(url,options)=>{observed={url,options};return{status:200,body:(async function*(){yield Buffer.from('{"ok":true}');})()};},
      process:{stdin:(async function*(){yield Buffer.from(packet);})(),exit:resolve,
        stdout:{write(bytes,callback){output+=bytes;callback();}},stderr:{write(bytes,callback){output+=bytes;callback();}}}});
  });
  assert.equal(await done,0);assert.equal(observed.url,'http://127.0.0.1:8094'+PREFIX+'/registration');
  assert.equal(observed.options.redirect,'error');assert.equal(observed.options.headers.authorization,'Bearer '+TOKEN);
  assert.equal(observed.options.body,JSON.stringify(identity));assert.deepEqual(JSON.parse(output),{status:200,body:{ok:true}});
  for(const url of ['https://example.test/',PREFIX+'/registration/other',PREFIX+'/registration?x=1'])
    assert.throws(()=>service._internals.serializeRequest('POST',url,identity,TOKEN));
  assert.throws(()=>service._internals.serializeRequest('POST',PREFIX+'/registration',{text:'x'.repeat(196608)},TOKEN));
});
test('durable intent precedes one dispatch; same identity status allowed, registration never resent',async()=>{
  const f=setup(),s=f.open();f.owner.execRegistration=async packet=>{
    assert.equal(f.records.at(-1).stage,'request-intent');f.calls.push(JSON.parse(packet).path);return reply(identity);
  };
  await s.dispatch('POST',PREFIX+'/registration',identity);
  assert.throws(()=>s.dispatch('POST',PREFIX+'/registration',identity),{code:'ORIGINAL_SERVICE_NO_REGISTRATION_RETRY'});
  await s.dispatch('POST',PREFIX+'/registration/status',identity);
  assert.throws(()=>s.dispatch('POST',PREFIX+'/registration/status',{...identity,requestSha256:'d'.repeat(64)}),{code:'ORIGINAL_SERVICE_FOREIGN_RECOVERY'});
  const a=s.close(),b=s.close();assert.equal(a,b);assert.equal((await a).retired,true);
  assert.equal(f.calls.filter(x=>x==='/registration').length,1);
  assert.throws(()=>s.dispatch('GET',PREFIX+'/health',null),{code:'ORIGINAL_SERVICE_REVOKED'});
});
test('committed lost ACK is recovered using same-ID drain only and original failure retained',async()=>{
  const f=setup(),s=f.open(),originalError=Error('lost response');let committed;
  f.owner.execRegistration=async packet=>{
    const q=JSON.parse(packet);f.calls.push(q.path);
    if(q.path==='/registration'){committed=structuredClone(q.body);throw originalError;}
    assert.equal(q.path,'/registration/drain');assert.deepEqual(q.body,committed);return reply(committed);
  };
  await assert.rejects(s.dispatch('POST',PREFIX+'/registration',identity),error=>error===originalError);
  await assert.rejects(s.close(),error=>error===originalError&&error.retirementUnproven===false&&error.serviceReceipt.unresolved===0);
  assert.deepEqual(f.calls,['/registration','endpoint-close','/registration/drain','listener-stop','confirm']);
});
test('uncertain drain or foreign proof prevents container/profile retirement',async()=>{
  const f=setup(),s=f.open();
  f.owner.execRegistration=async packet=>{
    const q=JSON.parse(packet);f.calls.push(q.path);
    return q.path==='/registration'?JSON.stringify({status:503,body:{uncertain:true}}):reply({...identity,instanceId:'dddddddd-dddd-4ddd-8ddd-dddddddddddd'});
  };
  await s.dispatch('POST',PREFIX+'/registration',identity);
  await assert.rejects(s.close(),error=>error.retirementUnproven===true&&error.serviceReceipt.unresolved===1);
  assert.equal(f.calls.includes('listener-stop'),false);
});
test('journal thenable rejects before dispatch and caps exactly two registration attempts',async()=>{
  const f=setup(),s=f.open();f.owner.record=()=>Promise.resolve();
  assert.throws(()=>s.dispatch('POST',PREFIX+'/registration',identity),{code:'ORIGINAL_SERVICE_ASYNC_JOURNAL'});
  assert.deepEqual(f.calls,[]);
  const g=setup(),other=g.open();
  await other.dispatch('POST',PREFIX+'/registration',identity);
  await other.dispatch('POST',PREFIX+'/registration',{...identity,operationId:'dddddddd-dddd-4ddd-8ddd-dddddddddddd'});
  assert.throws(()=>other.dispatch('POST',PREFIX+'/registration',{...identity,operationId:'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'}),{code:'ORIGINAL_SERVICE_NO_REGISTRATION_RETRY'});
});
test('pending execution outlives cleanup deadline and retains runtime without late stop',async()=>{
  const f=setup(),s=f.open();let release,end;
  f.owner.beginRetirement=()=>end??=performance.now()+15;
  f.owner.execRegistration=()=>new Promise(resolve=>{release=()=>resolve(reply(identity));});
  const call=s.dispatch('POST',PREFIX+'/registration',identity);
  await new Promise(resolve=>setImmediate(resolve));
  await assert.rejects(s.close(),error=>error.retirementUnproven===true&&error.serviceReceipt.pending===1);
  assert.equal(f.calls.includes('listener-stop'),false);
  release();await call;assert.equal(f.calls.includes('listener-stop'),false);
});
test('retirement deadline renewal cannot authorize later teardown',async()=>{
  const f=setup(),s=f.open();let end;
  f.owner.beginRetirement=()=>end===undefined?(end=performance.now()+1000):++end;
  await assert.rejects(s.close(),error=>error.code==='ORIGINAL_SERVICE_RETIREMENT_WINDOW'&&error.retirementUnproven===true);
  assert.equal(f.calls.includes('listener-stop'),false);
});
test('constructor uses original health validator before cohort claim and returns original configuration',async()=>{
  const f=setup();let startup,cohort,relayClosed=false;
  Object.assign(f.owner,{workspace:'a'.repeat(12),runtimeDigest:'e'.repeat(64),
    beginStartup:()=>startup??=performance.now()+1000,beginCohort(){f.calls.push('cohort');return cohort??=performance.now()+1200000;},
    async startListener({token,proxySha256}){assert.match(token,/^[A-Za-z0-9_-]{43}$/);assert.equal(proxySha256,service.fixedProxy().sourceSha256);f.calls.push('start');},
    async inspectListener(){f.calls.push('inspect');return true;},
    async execRegistration(packet){const q=JSON.parse(packet);assert.equal(q.path,'/registration/health');f.calls.push('health');
      return JSON.stringify({status:200,body:{version:1,instanceId:identity.instanceId,runtimeDigest:f.owner.runtimeDigest,registrationCapability:'owned-mcp-registration-v1'}});}});
  const handle=await service._internals.startControlledService(f.owner,{signal:new AbortController().signal,
    relayFactory:()=>({async listen(){f.calls.push('listen');return{address:'127.0.0.1',port:18094};},async close(){relayClosed=true;}})});
  assert.deepEqual(f.calls.slice(0,5),['start','inspect','health','listen','cohort']);
  assert.equal(handle.configuration.baseURL,'http://127.0.0.1:18094');assert.equal(handle.executionApproved,false);
  await handle.close();assert.equal(relayClosed,true);assert.equal(f.calls.at(-1),'confirm');
});
test('invalid original health never claims cohort and still joins owned cleanup',async()=>{
  const f=setup();let startup;
  Object.assign(f.owner,{workspace:'a'.repeat(12),runtimeDigest:'e'.repeat(64),
    beginStartup:()=>startup??=performance.now()+1000,beginCohort(){throw Error('must not claim');},
    async startListener(){},async inspectListener(){return true;},
    async execRegistration(){return JSON.stringify({status:200,body:{ready:true}});}});
  await assert.rejects(service._internals.startControlledService(f.owner,{signal:new AbortController().signal,
    relayFactory:()=>{throw Error('must not listen');}}),{code:'MCP_REGISTRY_EXECUTOR_UNAVAILABLE'});
  assert.deepEqual(f.calls,['endpoint-close','listener-stop','confirm']);
});
test('first request timeout survives a late valid ACK and proven retirement',async()=>{
  const f=setup();let release;
  f.owner.execRegistration=()=>new Promise(resolve=>{release=()=>resolve(reply(identity));});
  const s=service._internals.createControlledService(f.owner,{token:TOKEN,
    signal:new AbortController().signal,deadline:performance.now()+15});
  let first;
  await assert.rejects(s.dispatch('POST',PREFIX+'/registration',identity),error=>{
    first=error;return error.code==='ORIGINAL_SERVICE_DEADLINE';
  });
  assert.equal(s.snapshot().pending,1);
  const closing=s.close();release();
  await assert.rejects(closing,error=>error===first&&error.retirementUnproven===false
    &&error.serviceReceipt.retired===true&&error.serviceReceipt.error==='ORIGINAL_SERVICE_DEADLINE');
  assert.equal(f.records.at(-1).error,'ORIGINAL_SERVICE_DEADLINE');
});
function clockedService(clock) {
  const filename=path.join(__dirname,'postgres/ownedMcpOriginalService.js');
  const module={exports:{}};
  const factory=vm.runInNewContext('(function(require,module,exports){'+fs.readFileSync(filename,'utf8')+'\n})',
    {performance:{now:()=>clock.now},Buffer,AbortSignal,Response,setTimeout,clearTimeout});
  factory(createRequire(filename),module,module.exports);return module.exports;
}
test('clock crosses retirement deadline in queued microtask: no late stop effect',async()=>{
  const clock={now:0},subject=clockedService(clock),f=setup();let calls=0;
  f.owner.beginRetirement=()=>{if(++calls===3)queueMicrotask(()=>{clock.now=2000;});return 1000;};
  f.owner.stopListener=async()=>{f.calls.push(['stop',clock.now]);};
  const s=subject._internals.createControlledService(f.owner,{token:TOKEN,
    signal:new AbortController().signal,deadline:10000});
  await assert.rejects(s.close(),error=>error.retirementUnproven===true);
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal(f.calls.some(x=>Array.isArray(x)&&x[0]==='stop'),false);
});
test('startup failure cleanup rechecks deadline inside scheduled effect',async()=>{
  const clock={now:0},subject=clockedService(clock),f=setup(),primary=Error('start failed');let calls=0;
  Object.assign(f.owner,{workspace:'a'.repeat(12),runtimeDigest:'e'.repeat(64),
    beginStartup:()=>10000,beginCohort:()=>20000,async startListener(){throw primary;},async inspectListener(){return true;},
    beginRetirement(){if(++calls===2)queueMicrotask(()=>{clock.now=2000;});return 1000;}});
  await assert.rejects(subject._internals.startControlledService(f.owner,{signal:new AbortController().signal}),
    error=>error===primary&&error.retirementUnproven===true);
  await new Promise(resolve=>setImmediate(resolve));
  assert.deepEqual(f.calls,[]);
});
test('expiry at within admission observes queued guard rejection without late effects',async()=>{
  let reads=0;
  const clock={get now(){return ++reads>=9?2000:0;}};
  const subject=clockedService(clock),f=setup();
  f.owner.beginRetirement=()=>1000;
  const s=subject._internals.createControlledService(f.owner,{token:TOKEN,
    signal:new AbortController().signal,deadline:10000});
  await assert.rejects(s.close(),error=>error.code==='ORIGINAL_SERVICE_DEADLINE'
    &&error.retirementUnproven===true);
  // Let the deferred guard reject and the unhandled-rejection turn pass.
  // node:test fails this test if that rejection has no observer.
  await new Promise(resolve=>setImmediate(resolve));
  await new Promise(resolve=>setImmediate(resolve));
  assert.ok(reads>=9);
  assert.deepEqual(f.calls,[]);
  assert.equal(f.records.at(-1).error,'ORIGINAL_SERVICE_DEADLINE');
});
