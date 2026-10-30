'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto');
const {Readable}=require('node:stream'),{EventEmitter}=require('node:events');
const {startService,_internals:i}=require('./postgres/ownedMcpRegistryService');
const {RUNTIME_IMAGE,RUNTIME_DIGEST,_internals:runtime}=require('./postgres/ownedMcpRuntimeQualification');
const {PINS}=require('./postgres/ownedMcpBoundedBuild');
const actualRoot=path.resolve(__dirname,'..'),instanceId='11111111-1111-4111-8111-111111111111';
const operation={instanceId,operationId:'22222222-2222-4222-8222-222222222222',requestSha256:'a'.repeat(64)};
test('V39 route profile is closed and never widens historical registration defaults',()=>{
 for(const route of ['/execute','/invoke','/invoke/status','/invoke/drain']){
  assert.equal(i.allowed('POST',i.PREFIX+route),false);
  assert.equal(i.allowed('POST',i.PREFIX+route,'v39-atomic-pair'),true);
  for(const suffix of ['?x=1','/extra'])assert.equal(i.allowed('POST',i.PREFIX+route+suffix,'v39-atomic-pair'),false);
  assert.equal(i.allowed('GET',i.PREFIX+route,'v39-atomic-pair'),false);
 }
 assert.throws(()=>i.createRelay({profile:'unknown'}),/PROFILE/);
 assert.equal(i.proxySource(),i.PROXY);assert.notEqual(i.proxySource('v39-atomic-pair'),i.PROXY);
});
test('Q05 private profile admits owned invoke while ordinary registration and V39 identities remain separate',()=>{
 for(const route of ['/execute','/invoke','/invoke/status','/invoke/drain']){
  assert.equal(i.allowed('POST',i.PREFIX+route,'q05-registered-pair'),true);
  assert.equal(i.allowed('POST',i.PREFIX+route),false);
  assert.equal(i.allowed('POST',i.PREFIX+route+'?foreign=1','q05-registered-pair'),false);
 }
 assert.notEqual(i.proxySource('q05-registered-pair'),i.proxySource('v39-atomic-pair'));
 assert.throws(()=>i.routeProfile('q05-registered-pair-extra'),/PROFILE/);
});
async function fixture(t,fault={}){
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'registry-service-control-'));await fs.mkdir(path.join(root,'tasks/tmp'),{recursive:true});t.after(()=>fs.rm(root,{recursive:true,force:true}));
  const nonce=crypto.randomBytes(6).toString('hex'),name='owasp-ai-goat-owned-mcp-registry-'+nonce,directory=path.join(root,'tasks/tmp/v23-service-'+nonce),id='c'.repeat(64),calls=[];
  let exists=false,running=false,profile=false,token,dispatch,closed=false,bodySeen=[];
  const read=async name=>JSON.parse(await fs.readFile(path.join(directory,name+'.json')));
  const row=()=>({Id:id,Name:'/'+name,Image:RUNTIME_IMAGE,Config:{User:'10001:10001',Entrypoint:['node','sidecars/sandbox-runner/owned-mcp-registry/http-listener.js'],Labels:{'owasp-ai-goat.runtime':nonce},Env:['SECURESHOP_MCP_REGISTRY_ENABLED=true','SECURESHOP_MCP_REGISTRY_TOKEN='+token,'SECURESHOP_MCP_REGISTRY_PROFILE='+name,'SECURESHOP_MCP_REGISTRY_HOST=127.0.0.1','SECURESHOP_MCP_REGISTRY_PORT=8094']},HostConfig:{NetworkMode:'none',ReadonlyRootfs:true,Privileged:false,CapDrop:['ALL'],Memory:536870912,NanoCpus:1000000000,PidsLimit:128,LogConfig:{Type:'none'},RestartPolicy:{Name:'no'},SecurityOpt:['apparmor='+name,'seccomp=unconfined'],Tmpfs:{'/tmp':'rw,nosuid,nodev,noexec,size=16m'}},Mounts:[],State:{Running:running}});
  const docker=async(spec,args,options={})=>{
    calls.push(args);assert.equal(spec.root,root);assert.equal(options.timeoutMs,40000,'every Docker phase is bounded');
    if(args[0]==='info')return JSON.stringify(fault.daemon||PINS.daemon);
    if(args[0]==='image'&&args[1]==='ls'){assert(args.includes('--all'));return PINS.postgres+' postgres:18\n'+(fault.missingImage?'':RUNTIME_IMAGE+' <none>:<none>\n');}
    if(args[0]==='volume')return '';
    if(args[0]==='ps')return exists?id:'';
    if(args[0]==='network')return fault.changedNetwork&&closed?'changed':args[1]==='ls'?'bridge default none':'{"bridge":"preserved"}';
    if(args[0]==='create'){
      assert(profile);const intent=await read('intent');assert.deepEqual(intent.argv,args);assert.equal(intent.runtimeImageId,RUNTIME_IMAGE);
      token=intent.token;const env=await fs.readFile(args[args.indexOf('--env-file')+1],'utf8');assert(env.includes('SECURESHOP_MCP_REGISTRY_TOKEN='+token));
      assert.equal((await fs.stat(path.join(directory,'intent.json'))).mode&0o777,0o600);exists=true;
      if(fault.lostCreate)throw Error('lost create reply');return id;
    }
    if(args[0]==='container'){
      await fault.inspect?.();
      const r=row();if(fault.foreign)r.Config.Labels['owasp-ai-goat.runtime']='foreign';if(fault.publish)r.HostConfig.PortBindings={'8094/tcp':[{}]};if(fault.mount)r.Mounts=[{Type:'bind',Destination:'/app'}];return JSON.stringify([r]);
    }
    if(args[0]==='start'){assert.equal((await read('created')).id,id);running=true;return id;}
    if(args[0]==='exec'){
      assert.deepEqual(args,['exec','-i',id,'node','-e',i.PROXY]);assert.equal(options.timeoutMs,40000);
      let input='';for await(const b of options.input)input+=b;const q=JSON.parse(input);assert.equal(q.token,token);bodySeen.push(q);
      if(q.path.endsWith('/health')){if(fault.healthFailures>0){fault.healthFailures--;throw Error('listener not ready');}return JSON.stringify({status:200,body:{version:1,instanceId,registrationCapability:'owned-mcp-registration-v1',runtimeDigest:fault.badHealth?'0'.repeat(64):RUNTIME_DIGEST}});}
      await fault.exec?.(q);
      if(q.path==='/registration'&&fault.lostExec)throw Object.assign(Error('lost reply'),{code:'ADMISSION_COMMAND_TIMEOUT'});
      if(q.path==='/registration')return JSON.stringify({status:200,body:{version:1,...operation,state:'completed',drained:true,changes:[]}});
      if(q.path==='/registration/drain')return JSON.stringify({status:200,body:{version:1,...q.body,state:fault.unknownDrain?'unknown':'completed',drained:!fault.unknownDrain}});
      assert.fail('unexpected proxy path '+q.path);
    }
    if(args[0]==='stop'){if(!fault.unjoined)running=false;return id;}
    if(args[0]==='rm'){assert.equal(args[1],id);assert(!running);if(fault.removeFailure)throw Error('remove failed');exists=false;return id;}
    assert.fail('unexpected docker operation '+args.join(' '));
  };
  const remote=async(spec,op,policy)=>{calls.push(['guest',op]);assert(policy.includes(name));await read('intent');if(op==='install'){profile=true;if(fault.profileFailure)throw Error('lost install reply');}else{assert(!exists);if(fault.cleanupFailure)throw Error('profile retained');profile=false;closed=true;}};
  const relayFactory=options=>{dispatch=options.dispatch;return{async listen(){return{address:'127.0.0.1',port:12345};},async close(){calls.push(['relay','close']);}};};
  return {root,nonce,directory,calls,read,bodySeen,run:()=>startService({root,nonce,docker,remote,relayFactory,verifyHost:false,readTemplate:()=>fs.readFile(path.join(actualRoot,runtime.TEMPLATE),'utf8')}),dispatch:(...args)=>dispatch(...args),state:()=>({exists,running,profile})};
}
test('service uses admitted image with network none, exact private environment and bounded real protocol relay',async t=>{
  const f=await fixture(t),service=await f.run();assert.equal(service.configuration.runtimeDigest,RUNTIME_DIGEST);assert.equal(service.configuration.baseURL,'http://127.0.0.1:12345');
  const response=await f.dispatch('POST',i.PREFIX+'/registration',operation);assert.equal(response.body.state,'completed');
  await service.close();await service.close();assert.deepEqual(f.state(),{exists:false,running:false,profile:false});
  assert.equal((await f.read('cleanup')).cleanupVerified,true);assert.equal(f.calls.filter(x=>x[0]==='rm').length,1);
  assert(!f.calls.some(x=>['load','build','pull','tag'].includes(x[1])||x[0]==='network'&&['create','rm'].includes(x[1])));
  assert(!f.bodySeen.some(x=>x.path==='/registration/drain'),'durable completed/drained ACK needs no expiring-cache requery');
  assert(!f.calls.flat().includes(service.configuration.token),'token travels private file/stdin, never command arguments');
});
test('failed guest install retains private phase diagnostic even after cleanup',async t=>{
 const f=await fixture(t,{profileFailure:true});await assert.rejects(f.run(),{code:'REGISTRY_SERVICE_STARTUP_FAILED'});
 const diagnostic=await f.read('failure');assert.equal(diagnostic.phase,'guest-install');assert.equal(diagnostic.automaticRetry,false);
 assert.equal(diagnostic.error.errors[0].message,'lost install reply');assert.equal((await fs.stat(path.join(f.directory,'failure.json'))).mode&0o777,0o600);
 assert(!f.calls.some(x=>x[0]==='create'));assert.equal((await f.read('cleanup')).cleanupVerified,true);
});
test('diagnostics are bounded and redact exact secrets and bearer values through nested errors',()=>{
 const secret='sensitive-value',cause=Object.assign(Error(secret),{code:'RUNTIME_GUEST_FAILED',diagnostic:{code:2,stderr:'Bearer hidden '+secret+'x'.repeat(9000)}});
 const value=i.diagnostic(new AggregateError([cause],'startup failed'),secret),serialized=JSON.stringify(value);
 assert(!serialized.includes(secret));assert(!serialized.includes('Bearer hidden'));assert(value.errors[0].stderr.length<=4096);assert.equal(value.errors[0].exitCode,2);
});
test('lost mutating reply is not retried; exact operation drains before container stop',async t=>{
  const f=await fixture(t,{lostExec:true}),service=await f.run();await assert.rejects(f.dispatch('POST',i.PREFIX+'/registration',operation));await service.close();
  assert.equal(f.bodySeen.filter(x=>x.path==='/registration').length,1);assert.equal(f.bodySeen.filter(x=>x.path==='/registration/drain').length,1);
  assert.deepEqual((await f.read('cleanup')).unresolved,[]);
});
test('unknown operation fails close even after verified physical resource cleanup',async t=>{
  const f=await fixture(t,{lostExec:true,unknownDrain:true}),service=await f.run();await assert.rejects(f.dispatch('POST',i.PREFIX+'/registration',operation));await assert.rejects(service.close());
  const receipt=await f.read('cleanup');assert.equal(receipt.cleanupVerified,true);assert.equal(receipt.unresolved.length,1);assert.deepEqual(f.state(),{exists:false,running:false,profile:false});
});
test('conflicting operation identity cannot replace retained drain authority',async t=>{
  const f=await fixture(t,{lostExec:true}),service=await f.run();await assert.rejects(f.dispatch('POST',i.PREFIX+'/registration',operation));
  await assert.rejects(f.dispatch('POST',i.PREFIX+'/registration',{...operation,requestSha256:'b'.repeat(64)}),{code:'REGISTRY_SERVICE_OPERATION_CONFLICT'});
  await service.close();assert.deepEqual(f.bodySeen.find(x=>x.path.endsWith('/drain')).body,operation);
});
test('lost create reply leaves durable intent and never removes by name',async t=>{
  const f=await fixture(t,{lostCreate:true});await assert.rejects(f.run());const receipt=await f.read('cleanup');assert.equal(receipt.cleanupVerified,false);assert.equal(receipt.containerAbsent,false);
  assert(!f.calls.some(x=>x[0]==='rm'||x[0]==='guest'&&x[1]==='cleanup'));await f.read('intent');
});
for(const fault of ['foreign','publish','mount','badHealth','profileFailure'])test('startup identity or boundary failure cannot serve: '+fault,async t=>{
  const f=await fixture(t,{[fault]:true});await assert.rejects(f.run());
  if(fault==='foreign')assert(!f.calls.some(x=>x[0]==='rm'));
  assert.equal((await f.read('cleanup')).cleanupVerified,!['foreign','publish','mount'].includes(fault));
});
for(const fault of ['unjoined','removeFailure','cleanupFailure','changedNetwork'])test('failed join/cleanup/network preservation rejects close: '+fault,async t=>{
  const f=await fixture(t,{[fault]:true}),service=await f.run();await assert.rejects(service.close());assert.equal((await f.read('cleanup')).cleanupVerified,false);
  if(['unjoined','removeFailure'].includes(fault))assert(!f.calls.some(x=>x[0]==='guest'&&x[1]==='cleanup'));
});
test('exclusive namespace and invalid source identity cause no resource mutation',async t=>{
  const f=await fixture(t);await fs.mkdir(f.directory);await assert.rejects(f.run());assert(!f.calls.some(x=>['guest','create'].includes(x[0])));
  await assert.rejects(startService({root:f.root,nonce:'../foreign'}));
});
function fakeServer(){const server=new EventEmitter();server.listen=()=>queueMicrotask(()=>server.emit('listening'));server.address=()=>({address:'127.0.0.1',port:12345});server.close=cb=>cb();return server;}
function request(method,url,body,token='x'.repeat(43)){
  const req=Readable.from(body===undefined?[]:[Buffer.from(typeof body==='string'?body:JSON.stringify(body))]);Object.assign(req,{method,url,headers:{authorization:'Bearer '+token},aborted:false});
  const res=Object.assign(new EventEmitter(),{destroyed:false,writeHead(status){this.status=status;},end(value){this.body=JSON.parse(value);}});return{req,res};
}
test('HTTP relay preserves real status/body and rejects auth, traversal, unsupported operations and oversized input',async()=>{
  const seen=[],relay=i.createRelay({token:'x'.repeat(43),createServer:fakeServer,dispatch:async(...args)=>{seen.push(args);return{status:409,body:{error:'REAL_CONFLICT'}};}});
  for(const [method,url,body,token,status]of [['POST',i.PREFIX+'/registration',operation,undefined,409],['GET',i.PREFIX+'/health',undefined,'wrong',401],['POST',i.PREFIX+'/../execute',{},undefined,404],['POST',i.PREFIX+'/execute',{},undefined,404],['POST',i.PREFIX+'/registration','x'.repeat(i.LIMITS.request+1),undefined,413]]){
    const {req,res}=request(method,url,body,token);await relay.handle(req,res);assert.equal(res.status,status);
  }
  assert.equal(seen.length,1);assert.deepEqual(seen[0].slice(0,3),['POST',i.PREFIX+'/registration',operation]);assert(seen[0][3].signal instanceof AbortSignal);await relay.close();
});
test('HTTP capacity is bounded and close waits pending dispatch without retry',async()=>{
  let release,calls=0;const gate=new Promise(resolve=>{release=resolve;}),relay=i.createRelay({token:'x'.repeat(43),createServer:fakeServer,dispatch:async()=>{calls++;await gate;return{status:200,body:{}};}});
  const a=request('GET',i.PREFIX+'/health'),b=request('GET',i.PREFIX+'/health'),c=request('GET',i.PREFIX+'/health');
  const pa=relay.handle(a.req,a.res),pb=relay.handle(b.req,b.res);await relay.handle(c.req,c.res);assert.equal(c.res.status,429);
  let done=false;const closing=relay.close().then(()=>{done=true;});await new Promise(resolve=>setImmediate(resolve));assert.equal(done,false);release();await Promise.all([pa,pb,closing]);assert.equal(calls,2);
  const d=request('GET',i.PREFIX+'/health');await relay.handle(d.req,d.res);assert.equal(d.res.status,503);
});
function barrier(){let release,entered;const waiting=new Promise(resolve=>{entered=resolve;}),gate=new Promise(resolve=>{release=resolve;});return{waiting,release,async hold(){entered();await gate;}};}
test('request 256 reserves synchronously before inspect; concurrent 257 never executes',async t=>{
  const fault={},f=await fixture(t,fault),service=await f.run();
  for(let n=0;n<254;n++)await f.dispatch('GET',i.PREFIX+'/registration/health',null);
  const gate=barrier();fault.inspect=()=>gate.hold();
  const last=f.dispatch('GET',i.PREFIX+'/registration/health',null);await gate.waiting;
  await assert.rejects(f.dispatch('GET',i.PREFIX+'/registration/health',null),{code:'REGISTRY_SERVICE_REQUEST_BUDGET'});
  gate.release();await last;delete fault.inspect;await service.close();assert.equal(f.bodySeen.length,256);
});
for(const phase of ['inspect','journal'])test('disconnect during '+phase+' cannot dispatch fresh registration',async t=>{
  const fault={},f=await fixture(t,fault),service=await f.run(),gate=barrier();
  const original=runtime.journal;
  if(phase==='inspect')fault.inspect=()=>gate.hold();
  else{runtime.journal=async(...args)=>{await original(...args);if(args[1]==='request-000002')await gate.hold();};t.after(()=>{runtime.journal=original;});}
  const relay=i.createRelay({token:'x'.repeat(43),createServer:fakeServer,dispatch:f.dispatch});
  const {req,res}=request('POST',i.PREFIX+'/registration',operation),work=relay.handle(req,res);await gate.waiting;res.destroyed=true;res.emit('close');gate.release();await work;
  delete fault.inspect;runtime.journal=original;await relay.close();await service.close();
  assert.equal(f.bodySeen.filter(q=>q.path==='/registration').length,0);assert.deepEqual((await f.read('cleanup')).unresolved,[]);
});
test('close cancels a pending pre-effect inspection before registration executes',async t=>{
  const fault={},f=await fixture(t,fault),service=await f.run(),gate=barrier();fault.inspect=()=>gate.hold();
  const work=f.dispatch('POST',i.PREFIX+'/registration',operation);const rejected=assert.rejects(work,{code:'REGISTRY_SERVICE_NOT_DISPATCHED'});await gate.waiting;
  const closing=service.close();gate.release();await rejected;delete fault.inspect;await closing;assert(!f.bodySeen.some(q=>q.path==='/registration'));
});
test('disconnect after possible dispatch retains uncertain obligation and exact drain',async t=>{
  const fault={lostExec:true},f=await fixture(t,fault),service=await f.run(),gate=barrier();fault.exec=q=>q.path==='/registration'?gate.hold():undefined;
  const relay=i.createRelay({token:'x'.repeat(43),createServer:fakeServer,dispatch:f.dispatch}),{req,res}=request('POST',i.PREFIX+'/registration',operation);
  const work=relay.handle(req,res);await gate.waiting;res.destroyed=true;res.emit('close');gate.release();await work;await relay.close();await service.close();
  assert.equal(f.bodySeen.filter(q=>q.path==='/registration').length,1);assert.deepEqual(f.bodySeen.find(q=>q.path==='/registration/drain').body,operation);
});
test('startup polls only bounded read-only health until listener ready',async t=>{
  const f=await fixture(t,{healthFailures:2}),service=await f.run();assert.equal(f.bodySeen.length,3);assert(f.bodySeen.every(q=>q.method==='GET'));await service.close();
});
test('startup health polling stops after five failures and cleans exact resources',async t=>{
  const f=await fixture(t,{healthFailures:20});await assert.rejects(f.run());assert.equal(f.bodySeen.length,5);assert.equal((await f.read('cleanup')).cleanupVerified,true);
});
async function proxy(packet,{response='{"state":"real-response"}',status=409,rejectFetch=false}={}){
  const calls=[],outputs=[],errors=[],timers=[];let resolve;const ended=new Promise(done=>{resolve=done;});
  const process={stdin:Readable.from([Buffer.from(typeof packet==='string'?packet:JSON.stringify(packet))]),stdout:{write(text,done){outputs.push(text);done();}},stderr:{write(text,done){errors.push(text);done();}},exit(code){resolve(code);}};
  require('node:vm').runInNewContext(i.PROXY,{process,Buffer,AbortSignal,setTimeout(callback,ms){timers.push({callback,ms});return 1;},fetch:async(url,options)=>{calls.push({url,options});if(rejectFetch)throw Error('controlled lost response');return{status,body:Readable.from([Buffer.from(response)])};}});
  return {code:await ended,calls,outputs,errors,timers};
}
test('actual proxy code forwards exact JSON only to namespace loopback and preserves error response',async()=>{
  const body={...operation,command:'literal; $(not executed)'},result=await proxy({method:'POST',path:'/registration',body,token:'x'.repeat(43)});
  assert.equal(result.code,0);assert.equal(result.calls.length,1);assert.equal(result.calls[0].url,'http://127.0.0.1:8094/secureshop/mcp-registry/registration');
  assert.deepEqual(JSON.parse(result.calls[0].options.body),body);assert.equal(result.calls[0].options.redirect,'error');assert.equal(result.timers[0].ms,30000);
  assert.deepEqual(JSON.parse(result.outputs[0]),{status:409,body:{state:'real-response'}});
});
test('actual proxy refuses URL escape and unsupported mutation before fetch',async()=>{
  for(const route of ['http://foreign/','/registration/../execute','/execute','/invoke']){
    const result=await proxy({method:'POST',path:route,body:{},token:'x'.repeat(43)});assert.equal(result.code,70);assert.equal(result.calls.length,0);
  }
});
test('actual proxy bounds input/output and never retries lost response',async()=>{
  const oversized=await proxy('x'.repeat(200705));assert.equal(oversized.code,70);assert.equal(oversized.calls.length,0);
  const packet={method:'GET',path:'/health',body:null,token:'x'.repeat(43)};
  const lost=await proxy(packet,{rejectFetch:true});assert.equal(lost.code,70);assert.equal(lost.calls.length,1);assert.equal(lost.outputs.length,0);
  const large=await proxy(packet,{response:'x'.repeat(524289)});assert.equal(large.code,70);assert.equal(large.outputs.length,0);
});
