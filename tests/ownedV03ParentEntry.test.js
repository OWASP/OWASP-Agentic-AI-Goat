'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const source=fs.readFileSync(require.resolve('./postgres/ownedV03ParentEntry'),'utf8');
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const validate=new Function('require','fail','sha',source.slice(source.indexOf('function validatePlan('),source.indexOf('async function readParentPlan('))+';return validatePlan;')(
 name=>{assert.equal(name,'./ownedV03MainAdmission');return require('./postgres/ownedV03MainAdmission');},
 code=>Object.assign(Error(code),{code}),sha);
function fixture(){
 const root=path.resolve(__dirname,'..'),runId='a'.repeat(32);
 const plan={version:1,target:'original-v03-combined-parent-admission-v1',root,runId,sourcePins:{},
  mainArgvTemplate:[root+'/tests/postgres/run-secureshop-agent-host-transport-main.py','--v03-private-run-id',runId,
   '--v03-private-plan-sha256','@V03_PLAN_SHA256@','--v03-private-channel-fd','3','--v03-private-admission-fd','4'],
  expectedPythonSha256:'b'.repeat(64),expectedHostPythonSha256:'a'.repeat(64),diagnosticPlanSha256:'c'.repeat(64),listingsPlanSha256:'d'.repeat(64),postgresSpec:{}};
 return {root,runId,plan};
}
test('parent plan digest binds template without self-reference',()=>{
 const {root,runId,plan}=fixture(),raw=Buffer.from(JSON.stringify(plan)+'\n'),digest=sha(raw);
 const result=validate(raw,root,runId,digest);assert.equal(result.bound.mainArgv[4],digest);
 assert.equal(result.plan.mainArgvTemplate[4],'@V03_PLAN_SHA256@');
});
test('parent plan denies changed digest, foreign run and noncanonical duplicate keys',()=>{
 const {root,runId,plan}=fixture(),raw=Buffer.from(JSON.stringify(plan)+'\n');
 assert.throws(()=>validate(raw,root,runId,'e'.repeat(64)),{code:'V03_PARENT_PLAN_DIGEST'});
 assert.throws(()=>validate(raw,root,'f'.repeat(32),sha(raw)),{code:'V03_PARENT_PLAN_BINDING'});
 const duplicate=Buffer.from(raw.toString().replace('{','{"version":1,'));
 assert.throws(()=>validate(duplicate,root,runId,sha(duplicate)),{code:'V03_PARENT_PLAN_BINDING'});
});
test('parent entry stays closed before filesystem or resource work',async()=>{
 await assert.rejects(require('./postgres/ownedV03ParentEntry').runParent(),{code:'V03_PARENT_ENTRY_NOT_ADMITTED'});
});
test('actual CLI hookup preserves closed gate and cannot print a qualifying terminal',async()=>{
 const executors=fs.readFileSync(require.resolve('./postgres/ownedV03PrivateExecutors'),'utf8');
 const snippet=executors.slice(executors.indexOf('if(require.main===module){'));
 const module={},output=[],process={exitCode:null,stdout:{write:()=>{throw Error('unexpected success');}},stderr:{write:text=>output.push(JSON.parse(text))}};
 const load=name=>{assert.equal(name,'./ownedV03ParentEntry');return require('./postgres/ownedV03ParentEntry');};load.main=module;
 new Function('require','module','process','fail',snippet)(load,module,process,code=>Error(code));
 await new Promise(resolve=>setImmediate(resolve));
 assert.equal(process.exitCode,1);assert.equal(output.length,1);
 assert.equal(output[0].failure,'V03_PARENT_ENTRY_NOT_ADMITTED');assert.equal(output[0].qualificationComplete,false);
});
function orchestration(failure){
 const events=[],{plan,root}=fixture();
 for(const name of ['ownedV03GuestClock.js','ownedSystemConfigPhaseDriver.js','ownedSystemDiagnosticProducer.js',
  'ownedV03ListingsProducer.js','ownedV03ListingsDriver.js'])plan.sourcePins['tests/postgres/'+name]='e'.repeat(64);
 const owner={binding:()=>({expiresAtMs:10000}),nowMs:()=>0},controller={owner,start:async()=>{events.push('prepare');if(failure==='prepare')throw Error('prepare');},
  retire:async()=>{events.push('producers-retire');return {cleanupVerified:true};}};
 const main={channel:()=>({}),retire:async()=>{events.push('main-retire');}};
 const modules={
  './ownedV03PrivateExecutors':{createPrivateExecutors:async options=>{
   assert.equal(options.listings.expectedTransportSha256,plan.sourcePins['tests/postgres/ownedSystemConfigPhaseDriver.js']);
   assert.equal(options.diagnostic.expectedPythonSha256,plan.expectedPythonSha256);
   assert.equal(options.clock.expectedPythonSha256,plan.expectedPythonSha256);
   assert.equal(options.listings.expectedHostPythonSha256,plan.expectedHostPythonSha256);return controller;}},
  './ownedV03PostgresOwner':{createPostgresOwner:async options=>{assert.equal(options.expectedPythonSha256,plan.expectedHostPythonSha256);events.push('pg-owner');return {};}},
  './ownedV03MainProcess':{createMainProcess:async options=>{assert.equal(options.expectedPythonSha256,plan.expectedHostPythonSha256);events.push('main');if(failure==='main')throw Error('main');return main;}},
  './ownedV03ParentProtocol':{serveParent:()=>{events.push('server');return {done:Promise.resolve({qualificationComplete:false,finalization:{candidate:{work:{deadlineMs:5000}}}})};}},
  './ownedV03MainAdmission':{verifySources:async()=>{events.push('source-after');}}
 };
 const run=new Function('LIVE_ENABLED','readParentPlan','require','sha','fail','process',
  source.slice(source.indexOf('async function verifyFinalSources('),source.indexOf('module.exports='))+';return runParent;')(
  true,async()=>({root,directory:root+'/tasks/tmp/synthetic',plan,planSha256:'f'.repeat(64),bound:{}}),
  name=>{assert.ok(Object.hasOwn(modules,name));return modules[name];},sha,code=>Error(code),{argv:[],stdout:{write:(raw,callback)=>{events.push('publish');callback();}}});
 return {run,events};
}
test('fixed parent composition prepares both owners before MAIN and uses one finalizer',async()=>{
 const f=orchestration();assert.equal((await f.run()).qualificationComplete,false);
 assert.deepEqual(f.events,['prepare','pg-owner','main','server','source-after','publish']);
});
test('attempted MAIN without a handle cannot authorize producer deletion',async()=>{
 const f=orchestration('main');await assert.rejects(f.run(),e=>e.cleanupDebt&&e.producerRetirementUnproven);
 assert.deepEqual(f.events,['prepare','pg-owner','main']);
});
test('pre-MAIN preparation failure retains primary and attempts owned retirement',async()=>{
 const f=orchestration('prepare');await assert.rejects(f.run(),e=>e.message==='prepare'&&e.cleanupDebt);
 assert.deepEqual(f.events,['prepare','producers-retire']);
});
test('late final source verification retains pending debt and cannot return a terminal',async()=>{
 let complete;
 const verify=new Function('require','fail',source.slice(source.indexOf('async function verifyFinalSources('),source.indexOf('async function runParent('))+';return verifyFinalSources;')(
  ()=>({verifySources:()=>new Promise(resolve=>{complete=resolve;})}),code=>Object.assign(Error(code),{code}));
 const owner={binding:()=>({expiresAtMs:1000}),nowMs:()=>0};
 await assert.rejects(verify(owner,'/synthetic',{}, {finalization:{candidate:{work:{deadlineMs:1}}}}),
  error=>error.code==='V03_PARENT_FINAL_SOURCE_DEADLINE'&&error.cleanupDebt&&error.sourceCheckPending);
 complete();await Promise.resolve();
});
test('backpressured terminal publication times out with debt and late callback cannot succeed',async()=>{
 let callback,now=0;
 const publish=new Function('process','fail',source.slice(source.indexOf('async function publishParentTerminal('),source.indexOf('async function runParent('))+';return publishParentTerminal;')(
  {stdout:{write:(raw,cb)=>{callback=cb;}}},code=>Object.assign(Error(code),{code}));
 const owner={binding:()=>({expiresAtMs:1000}),nowMs:()=>now};
 await assert.rejects(publish(owner,{finalization:{candidate:{work:{deadlineMs:1}}}}),
  error=>error.code==='V03_PARENT_TERMINAL_DEADLINE'&&error.cleanupDebt&&error.terminalWritePending);
 now=2;callback();await Promise.resolve();
});
test('actual host observer hash gate rejects a crossed runtime-executable pin',async()=>{
 const mainSource=fs.readFileSync(require.resolve('./postgres/ownedV03MainProcess'),'utf8');
 const root=path.resolve(__dirname,'..'),hostBytes=Buffer.from('synthetic physical app'),runtimeBytes=Buffer.from('synthetic runtime launcher');
 const modules={
  './ownedV03PrivateExecutors':{assertCombinedOwner:value=>value},
  './ownedV03MainAdmission':{verifySources:async()=>{}},
  './ownedSystemConfigPhaseDriver':{_internals:{regular:async file=>{
   assert.match(file,/Resources\/Python\.app\/Contents\/MacOS\/Python$/);return hostBytes;}}}
 };
 const create=new Function('require','path','crypto','__dirname','inspector','fail',
  mainSource.slice(mainSource.indexOf('async function createLocalObserver('),mainSource.indexOf('module.exports='))+';return createLocalObserver;')(
  name=>modules[name],path,crypto,path.join(root,'tests/postgres'),()=>({observe:()=>{},pending:new Set(),debts:[]}),code=>Object.assign(Error(code),{code}));
 const options={owner:{isRevoked:()=>false},root,sourcePins:Object.fromEntries(['v03_private_process.py','ownedV03MainProcess.js']
  .map(name=>['tests/postgres/'+name,'a'.repeat(64)])),expectedPythonSha256:sha(runtimeBytes)};
 await assert.rejects(create(options),{code:'V03_MAIN_PYTHON'});
 assert.equal((await create({...options,expectedPythonSha256:sha(hostBytes)})).status().debts,0);
});
