'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const { runWindowsStartup } = require('../scripts/start-application');
function fixture({ retained = true, failAt, environment = {}, enabled = true } = {}) {
  const events = [], requests = [], rejectors = [];
  let callback;
  const ownChild = async () => ({ stopAndJoin: async () => {}, failurePromise: new Promise((_, reject) => rejectors.push(reject)) });
  const session = { async openLoopbackForwards(ports, options) {
    if (callback) assert.equal(options.ownChild, callback);
    callback = options.ownChild; requests.push(ports);
    return options.ownChild({executable:'controlled',args:[]});
  }};
  const stage = name => async options => {
    events.push(name);
    assert.equal(options.ownedLabSession, session);
    if (name === 'postgres') assert.equal(options.existingOnly, true);
    await session.openLoopbackForwards([{local: name==='postgres'?5432:8025,guest:name==='postgres'?5432:8025}],{ownChild:options.ownLabChild});
    if (failAt === name) throw Object.assign(Error(name),{code:'CONTROLLED_FAILURE'});
  };
  const options = { retryDelay:async()=>{}, workspace:require('node:path').resolve(__dirname,'..'),home:'C:\\Users\\Student',environment,
    fileSystem:{lstatSync(file){if(file.endsWith('audit-sql-target.json'))throw Object.assign(Error('absent'),{code:'ENOENT'});assert.ok(file.endsWith('local-postgres.json'));if(!retained)throw Object.assign(Error('absent'),{code:'ENOENT'});return {}; }},
    async prepareLab(input){events.push('lab');assert.equal(input.mode,'existing');return {session,ownLabChild:ownChild,async close(){events.push('close');if(failAt==='close')throw Object.assign(Error('cleanup'),{code:'CLEANUP_UNPROVED'});}};},
    localPostgres:stage('postgres'),
    async baseServices(input){events.push('base');assert.equal(input.mode,'start');assert.equal(input.session,session); await session.openLoopbackForwards([{local:9099,guest:9099}],{ownChild:input.ownLabChild});if(failAt==='base')throw Object.assign(Error('base'),{code:'CONTROLLED_FAILURE'});},
    mailpitReady:stage('mailpit'),loadMcp:()=>({'MCP_OWNED_RESOURCES_ENABLED':enabled?'true':'false'}),startMcp:stage('mcp'),mcpReady:async()=>({ready:true}),
    protectedServices:[8093,8094].map(port=>({load:()=>({enabled,url:`http://127.0.0.1:${port}`}),start:stage(`protected${port}`),ready:async()=>({ready:true})})),
    async prepareApplication(){events.push('prepare');if(failAt==='prepare')throw Object.assign(Error('prepare'),{code:'CONTROLLED_FAILURE'});},
    createSupervisor(){events.push('supervisor');return {async stop(){events.push('stop');}};},
    async runApplication(){events.push('run');}
  };
  return {options,events,requests,rejectors};
}
test('Windows startup uses existing lab, retained PostgreSQL, base start and exact protected loopback groups',async()=>{
 const f=fixture({environment:{IPI_EMAIL_PROVIDER:'mailpit',MAILPIT_STATE_PATH:'private'}});await runWindowsStartup(f.options);
 assert.deepEqual(f.events,['lab','postgres','base','mailpit','mcp','protected8093','protected8094','prepare','supervisor','run','close']);
 assert.ok(f.requests.some(p=>p[0].local===8092));assert.ok(f.requests.some(p=>p[0].local===8093));assert.ok(f.requests.some(p=>p[0].local===8094));
});
test('exact missing local state permits external PostgreSQL and disabled protected services are not provisioned',async()=>{
 const f=fixture({retained:false,enabled:false});await runWindowsStartup(f.options);
 assert.deepEqual(f.events,['lab','base','prepare','supervisor','run','close']);
});
test('inaccessible named PostgreSQL state denies before guest admission instead of treating it as missing',async()=>{
 const f=fixture();f.options.fileSystem.lstatSync=()=>{throw Object.assign(Error('denied'),{code:'EACCES'});};
 await assert.rejects(runWindowsStartup(f.options),{code:'EACCES'});assert.deepEqual(f.events,[]);
});
test('preparation failures retain primary error and drain the facade on every path',async()=>{
 for(const failAt of ['postgres','base','prepare']) {const f=fixture({failAt});await assert.rejects(runWindowsStartup(f.options),{code:'CONTROLLED_FAILURE'});assert.equal(f.events.at(-1),'close');assert.ok(!f.events.includes('run'));}
 const f=fixture();f.options.prepareApplication=async()=>{throw Object.assign(Error('primary'),{code:'PRIMARY'});};f.options.prepareLab=async()=>({session:{},ownLabChild:()=>{},close:async()=>{throw Object.assign(Error('cleanup'),{code:'CLEANUP_UNPROVED'});}});f.options.fileSystem.lstatSync=()=>{throw Object.assign(Error('absent'),{code:'ENOENT'});};f.options.baseServices=async()=>{};f.options.loadMcp=()=>({});f.options.protectedServices=[];
 await assert.rejects(runWindowsStartup(f.options),e=>e.code==='PRIMARY'&&e.cleanupError.code==='CLEANUP_UNPROVED');
});
test('forward failure during readiness prevents supervisor launch without exposing native diagnostics',async()=>{
 const f=fixture();f.options.prepareApplication=async()=>{f.rejectors[0](Error('PRIVATE_NATIVE_OUTPUT'));await Promise.resolve();};
 await assert.rejects(runWindowsStartup(f.options),e=>e.code==='WINDOWS_LAB_FORWARD_FAILED'&&!e.message.includes('PRIVATE_NATIVE_OUTPUT'));assert.ok(!f.events.includes('supervisor'));assert.equal(f.events.at(-1),'close');
});
test('forward failure during foreground supervision stops and joins application before tunnels close',async()=>{
 const f=fixture();let done;const stopped=new Promise(resolve=>{done=resolve;});
 f.options.createSupervisor=()=>({async stop(){f.events.push('stop');done();}});
 f.options.runApplication=async()=>{f.events.push('run');f.rejectors[0](Error('PRIVATE_NATIVE_OUTPUT'));await stopped;f.events.push('joined');};
 await assert.rejects(runWindowsStartup(f.options),{code:'WINDOWS_LAB_FORWARD_FAILED'});
 assert.deepEqual(f.events.slice(-4),['run','stop','joined','close']);
});
test('a failed application stop never skips forwarding cleanup',async()=>{
 const f=fixture();let release;const ended=new Promise(resolve=>release=resolve);
 f.options.createSupervisor=()=>({async stop(){f.events.push('stop');release();throw Object.assign(Error('join'),{code:'JOIN_UNPROVED'});}});
 f.options.runApplication=async()=>{f.rejectors[0](Error('native'));await ended;};
 await assert.rejects(runWindowsStartup(f.options),e=>e.code==='JOIN_UNPROVED');assert.equal(f.events.at(-1),'close');
});
test('canonical main dispatches Windows existing lifecycle only after read-only plan/config/port guards',async()=>{
 const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),{createRequire}=require('node:module');
 const filename=path.join(__dirname,'../scripts/start-application.js'),realRequire=createRequire(filename),module={exports:{}},events=[];
 const runtime={...process,env:{PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres'},exitCode:0};
 const overrides={
  dotenv:{config(){events.push('dotenv');}},
  '../server/services/applicationDatabaseEngine':{assertApplicationDatabaseEngine(){
   return realRequire('../server/services/applicationDatabaseEngine').assertApplicationDatabaseEngine({env:runtime.env});
  }},
  './lib/windows-host-preflight':{validateWindowsHostPreflight:x=>x,assertWindowsHostSupported(){events.push('host');}},
  '../server/services/secureshopSystemManagedEnvironment':{loadWithQualified(){return {};},async assertReady(){events.push('system');}},
  '../server/services/secureshopPricingManagedConfiguration':{environment(){return {};}},
  '../server/services/secureshopPricingActivation':{async preparePricingClient(){events.push('pricing');}},
  '../server/services/secureshopPolicyRendererManagedEnvironment':{load(){return {};}},
  './lib/start-managed-listings':{async startManagedListings(){events.push('listings');}},
  '../db/postgres/initialize-application':{configurationPlan(){return [{configured:true,schema:'identity'}];}},
  '../server/services/platformSigningConfiguration':{assertPlatformSigningConfiguration(){events.push('signing');}},
  './application-data-root':{ensureApplicationDataRoot(){events.push('data-root');return 'admitted';}},
  'node:net':{createServer(){return {once(){},listen(_,callback){events.push('port');callback();},close(callback){callback();}};}},
 };
 const wrapped=vm.runInThisContext(`(function(require,module,exports,__filename,__dirname,process,console){${fs.readFileSync(filename,'utf8')}\n})`);
 wrapped(name=>Object.hasOwn(overrides,name)?overrides[name]:realRequire(name),module,module.exports,filename,path.dirname(filename),runtime,{log(){},error(){}});
 let calls=0;
 const options={platform:'win32',observeWindowsHost:()=>({hostSupported:true}),async windowsStartup(input){calls++;events.push('existing-lifecycle');await input.prepareApplication();}};
 await module.exports.main(['--plan'],options);assert.equal(calls,0);assert.ok(!events.includes('signing'));
 events.length=0;await module.exports.main([],options);
 assert.deepEqual(events,['host','dotenv','signing','port','port','listings','existing-lifecycle','data-root','system','pricing']);assert.equal(calls,1);
 runtime.env.PLATFORM_DATABASE_ENGINE='sqlite';await assert.rejects(module.exports.main([],options),{code:'ERR_POSTGRES_REQUIRED'});assert.equal(calls,1);
});

test('protected readiness denial after forwarding prevents application start and drains retained session',async()=>{
 const f=fixture();f.options.protectedServices[0].ready=async()=>({ready:false});
 await assert.rejects(runWindowsStartup(f.options),{code:'WINDOWS_LAB_SERVICE_NOT_READY'});assert.ok(!f.events.includes('prepare'));assert.equal(f.events.at(-1),'close');
});

test('bounded readiness retries admit a real ready receipt and redact permanent transport errors',async()=>{
 const f=fixture();let attempts=0;f.options.mcpReady=async()=>{if(++attempts<3)throw Error('PRIVATE_TRANSPORT');return {ready:true};};
 await runWindowsStartup(f.options);assert.equal(attempts,3);
 const denied=fixture();attempts=0;denied.options.mcpReady=async()=>{attempts++;throw Object.assign(Error('PRIVATE_TRANSPORT'),{code:'PRIVATE_SECRET'});};
 await assert.rejects(runWindowsStartup(denied.options),e=>e.code==='WINDOWS_LAB_SERVICE_NOT_READY'&&!e.message.includes('PRIVATE_TRANSPORT'));assert.equal(attempts,10);assert.equal(denied.events.at(-1),'close');
});

test('protected service start diagnostics stay private and failed start closes the facade',async()=>{
 const f=fixture();f.options.protectedServices[0].start=async()=>{throw Error('PRIVATE_DOCKER_ENV');};
 await assert.rejects(runWindowsStartup(f.options),e=>e.code==='WINDOWS_LAB_SERVICE_START_FAILED'&&!e.message.includes('PRIVATE_DOCKER_ENV'));assert.equal(f.events.at(-1),'close');
});

test('retained Audit SQL forwards through the same monitored owner before application readiness',async()=>{
 const f=fixture();f.options.fileSystem.lstatSync=()=>({});f.options.startAudit=async options=>{f.events.push('audit');await options.ownedLabSession.openLoopbackForwards([{local:16432,guest:16432}],{ownChild:options.ownLabChild});};
 await runWindowsStartup(f.options);assert.ok(f.events.indexOf('audit')<f.events.indexOf('prepare'));assert.ok(f.requests.some(p=>p[0].local===16432));
});

test('external PostgreSQL with Gmail and explicit sidecar opt-out starts without an owned guest',async()=>{
 const f=fixture({retained:false,enabled:false,environment:{PG_ADMIN_DATABASE_URL:'private-external',IPI_EMAIL_PROVIDER:'gmail',MCP_SIDECARS_AUTOSTART:'false'}});
 await runWindowsStartup(f.options);assert.deepEqual(f.events,['prepare','supervisor','run']);
});
test('retained PostgreSQL still requires the guest when ordinary sidecars are disabled',async()=>{
 const f=fixture({enabled:false,environment:{MCP_SIDECARS_AUTOSTART:'false'}});await runWindowsStartup(f.options);
 assert.deepEqual(f.events,['lab','postgres','prepare','supervisor','run','close']);
});
