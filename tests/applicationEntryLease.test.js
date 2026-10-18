'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
const {createApplicationLifecycle}=require('../server/services/applicationLifecycle');
const tick=()=>new Promise(setImmediate);
function fixture({acquire,start}={}){
 const calls=[],exits=[],listeners={},middleware=[];const app=Object.assign(()=>{},{locals:{},use:fn=>middleware.push(fn)});
 const abort=new AbortController();const lease={signal:abort.signal,async assertClean(){calls.push("clean");},assertHeld(){if(abort.signal.aborted)throw Error('lost');},async close(){calls.push('lease-close');abort.abort();}};
 const lifecycle=createApplicationLifecycle({timeoutMs:100,exit:x=>exits.push(x)});
 const modules={'../scripts/application-node-runtime':{assertSupportedApplicationNodeVersion(){}},dotenv:{config(){}},'./services/applicationDatabaseEngine':{assertApplicationDatabaseEngine(){}},'./services/platformSigningConfiguration':{assertPlatformSigningConfiguration(){}},express:()=>app,'./services/applicationLifecycle':{createApplicationLifecycle:()=>lifecycle},'./services/applicationStartupDiagnostic':require('../server/services/applicationStartupDiagnostic'),'./services/applicationMaintenanceLease':{acquireApplicationMaintenanceLease:acquire||(async()=>lease)},'./applicationServer':{startApplicationServer:start||(async()=>{calls.push('constructed');})}};
 const context={module:{exports:{}},require(name){calls.push('require:'+name);assert(Object.hasOwn(modules,name));return modules[name];},process:{versions:{node:'26.10.0'},env:{},once:(e,f)=>listeners[e]=f,on:(e,f)=>listeners[e]=f},console:{error(){}},AbortController};
 vm.runInNewContext(fs.readFileSync(path.resolve(__dirname,'../server/index.js'),'utf8'),context);
 return {app,exported:context.module.exports,calls,exits,listeners,lifecycle,abort,lease,middleware};
}
test('callable export stable and stateful module deferred until lease acquisition',async()=>{
 let resolve;const f=fixture({acquire:()=>new Promise(r=>resolve=r)});assert.equal(f.exported,f.app);assert.equal(typeof f.exported,'function');assert(!f.calls.includes('require:./applicationServer'));
 let status;f.middleware[0]({}, {status:n=>{status=n;return{json(){}};}},()=>assert.fail());assert.equal(status,503);
 resolve(f.lease);await f.app.locals.applicationReady;let next=false;f.middleware[0]({},null,()=>next=true);assert(next);await f.lifecycle.shutdown();assert.equal(f.calls.at(-1),'lease-close');
});
test('busy acquisition cannot import construction',async()=>{const f=fixture({acquire:async()=>{throw Error('busy');}});await assert.rejects(f.app.locals.applicationReady);assert(!f.calls.includes('require:./applicationServer'));assert.deepEqual(f.exits,[1]);});
test('signal while acquisition pending closes late lease without constructing',async()=>{let resolve;const f=fixture({acquire:()=>new Promise(r=>resolve=r)});f.listeners.SIGTERM();await tick();resolve(f.lease);await f.app.locals.applicationReady;assert(!f.calls.includes('require:./applicationServer'));assert.equal(f.calls.filter(x=>x==='lease-close').length,1);});
test('loss during readiness denies readiness and releases only after ordinary drain',async()=>{
 let finish,drain;const f=fixture({start:async({lifecycle,signal})=>{lifecycle.register(()=>new Promise(r=>drain=r));await new Promise(r=>finish=r);signal.throwIfAborted();}});
 await tick();f.abort.abort();await tick();assert(!f.calls.includes('lease-close'));finish();await tick();drain();await assert.rejects(f.app.locals.applicationReady);assert.equal(f.calls.filter(x=>x==='lease-close').length,1);assert.deepEqual(f.exits,[1]);
});
test('partial construction failure drains allocated owner before lease finalizer',async()=>{const order=[];const f=fixture({start:async({lifecycle})=>{lifecycle.register(async()=>order.push('owner'));throw Error('partial');}});await assert.rejects(f.app.locals.applicationReady);assert.deepEqual(order,['owner']);assert.equal(f.calls.at(-1),'lease-close');});
test('failed owner drain retains lease until process termination',async()=>{const f=fixture({start:async({lifecycle})=>{lifecycle.register(()=>{throw Error('undrained');});throw Error('partial');}});await assert.rejects(f.app.locals.applicationReady);assert(!f.calls.includes('lease-close'));assert.deepEqual(f.exits,[1]);});
test('construction registers partial cleanup before stateful imports and only closes cached modules',()=>{
 const s=fs.readFileSync(path.resolve(__dirname,'../server/applicationServer.js'),'utf8');assert(s.indexOf('lifecycle.register(async')<s.indexOf("sessionManager = require"));assert(s.includes('require.cache[require.resolve(name)]?.exports'));assert(s.includes('track(startup)'));assert(s.includes('assertActive();\n  await checked(new Promise'));assert(!s.includes('module.exports = app'));
});
test('SecureShop terminal host failure revokes every mounted shop router before using the owned shutdown lifecycle',()=>{
 const source=fs.readFileSync(path.resolve(__dirname,'../server/applicationServer.js'),'utf8');
 const begin=source.indexOf('const revokeSecureShopRuntime = error => {');
 const end=source.indexOf('secureShopReady = secureshopV2.boot',begin);
 assert(begin>0&&end>begin);
 const block=source.slice(begin,end);
 for(const name of ['secureshopBoundGateway','secureshopBoundLaunchRouter','secureshopBoundReadiness','secureshopStandaloneAuthRouter','secureshopPublicCatalog','secureshopV2Router','secureshopV2MerchantRouter','secureshopV2AdminRouter','secureshopV2UploadsRouter','secureshopV2EmailRouter','secureshopV2AuthRouter'])assert.match(block,new RegExp(`app\\.locals\\.${name} = null`));
 assert.match(block,/void lifecycle\.shutdown\(1\)/);
 assert.match(source,/host\.setTerminalFailureHandler\(revokeSecureShopRuntime\)/);
});
test('partial module failure attempts cached children cleanup but conservatively forbids lease release',async()=>{
 const source=fs.readFileSync(path.resolve(__dirname,'../server/applicationServer.js'),'utf8');
 const calls=[],callbacks=[];const exports={};
 const fakeRequire=name=>{if(name==='./services/applicationLifecycle')return require('../server/services/applicationLifecycle');throw Error('import failed');};
 fakeRequire.resolve=name=>name;fakeRequire.cache={'./database/postgres':{exports:{closePostgresPools:async()=>calls.push('pools')}}};
 const context={module:{exports},require:fakeRequire};vm.runInNewContext(source,context);
 await assert.rejects(context.module.exports.startApplicationServer({app:{locals:{}},lifecycle:{register:f=>callbacks.push(f),stopping:false},signal:new AbortController().signal,assertHeld(){}}),/import failed/);
 await assert.rejects(callbacks[0](),error=>error instanceof AggregateError&&error.errors.some(e=>e.message==='APPLICATION_PARTIAL_IMPORT_UNDRAINED'));
 assert.deepEqual(calls,['pools']);
});
test('actual SecureShop awaited continuation stops before next factory after lease loss',async()=>{
 const source=fs.readFileSync(path.resolve(__dirname,'../server/applicationServer.js'),'utf8');
 const begin=source.indexOf('const systemRestartClient ='),end=source.indexOf('getStartupObjectiveGradingCore(gradingBootstrap.gradingCore)',begin);
 assert(begin>0&&end>begin);const calls=[];let release;const controller=new AbortController();
 const context={process:{env:{}},systemRestartActivation:{prepareSystemRestartClient:()=>new Promise(r=>release=r)},mcpTrustFeature:false,ssrfFeature:false,
 require(){calls.push('downstream-factory');return {prepareSecureShopStartupGrading:async()=>({})};},assertActive:()=>controller.signal.throwIfAborted()};
 vm.runInNewContext(source.match(/const checked=async promise=>[^\n]+/)[0]+'\nthis.run=async()=>{'+source.slice(begin,end)+'};',context);
 const pending=context.run();controller.abort();release({owned:true});await assert.rejects(pending);assert.deepEqual(calls,[]);
});
test('actual cleanup waits pending startup then closes only its HTTP listener',async()=>{
 const source=fs.readFileSync(path.resolve(__dirname,'../server/applicationServer.js'),'utf8');const a=source.indexOf('lifecycle.register(async'),b=source.indexOf('\nassertActive();',a);
 let close,resolveStartup;const calls=[],server={listening:false,close(done){calls.push('http-close');this.listening=false;done();},closeIdleConnections(){}};
 const pending=new Promise(r=>resolveStartup=r);
 vm.runInNewContext(source.slice(a,b),{lifecycle:{register:fn=>close=fn},server,settleApplicationCleanup:require('../server/services/applicationLifecycle').settleApplicationCleanup,closeApplicationOwnedResources:require('../server/services/applicationLifecycle').closeApplicationOwnedResources,
 sessionManager:null,startupTasks:[pending],authRoutes:null,teachingSessionProduction:null,evidenceMaintenance:null,secureShopReady:Promise.resolve(),constructionComplete:true,app:{locals:{}},loaded:()=>({}),process:{env:{}}});
 const stopping=close();await tick();assert.deepEqual(calls,[]);server.listening=true;resolveStartup();await stopping;assert.deepEqual(calls,['http-close']);assert.equal(server.listening,false);
});
test('real lease lifetime survives SIGTERM drain; real connection loss still exits nonzero',async()=>{
 const {EventEmitter}=require('node:events');
 const {acquireApplicationMaintenanceLease}=require('../server/services/applicationMaintenanceLease');
 for(const lost of [false,true]){
  const order=[];let release;
  const client=new EventEmitter();Object.assign(client,{connect:async()=>{},query:async sql=>({rows:sql.startsWith('SELECT name,checksum')?[{name:'0001_maintenance_fence.sql',checksum:require('../server/database/postgres/applicationMaintenanceControl').MAINTENANCE_BOOTSTRAP_SHA256}]:sql.startsWith('SELECT *,database_oid')?[{version:1,installation_id:'11111111-1111-4111-8111-111111111111',operation_id:'22222222-2222-4222-8222-222222222222',epoch:'1',state:'clean',target_matches:true}]:[{acquired:true}]}),end:async()=>{order.push('session-end');client.emit('end');}});
  const f=fixture({acquire:options=>acquireApplicationMaintenanceLease({...options,env:{IDENTITY_DATABASE_URL:'postgres://fixture:fixture@localhost/identity'},probeMs:30000,clientFactory:()=>client}),start:async({lifecycle})=>lifecycle.register(()=>new Promise(resolve=>{order.push('drain-start');release=()=>{order.push('drain-end');resolve();};}))});
  await f.app.locals.applicationReady;
  if(lost)client.emit('error',Error('connection lost'));else f.listeners.SIGTERM();
  await tick();assert(order.includes('drain-start'));
  if(!lost)assert(!order.includes('session-end'),'held lease must survive ordinary drain');
  release();await f.lifecycle.shutdown();
  assert.deepEqual(f.exits,[lost?1:0]);assert.equal(order.filter(x=>x==='session-end').length,1);
  if(!lost)assert(order.indexOf('session-end')>order.indexOf('drain-end'));
 }
});
test('dirty or missing durable control denies entry before construction',async()=>{for(const code of ['APPLICATION_MAINTENANCE_DIRTY','APPLICATION_MAINTENANCE_CONTROL_UNAVAILABLE']){const controller=new AbortController();let constructed=false;const f=fixture({acquire:async()=>({signal:controller.signal,assertHeld(){},async assertClean(){throw Object.assign(Error(code),{code});},async close(){}}),start:async()=>{constructed=true;}});await assert.rejects(f.app.locals.applicationReady,{code});assert.equal(constructed,false);assert.deepEqual(f.exits,[1]);}});
