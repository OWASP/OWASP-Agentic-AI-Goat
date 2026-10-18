'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
function setup({fail,drainFailure,busy,loss,importFailure,closeFailure,seedFailure,standaloneSeedFailure,assessmentSeedFailure,lossAfterStandaloneSeed,lossAfterWorkshopSeed}={}){
 const calls=[],module={exports:{}},env={};const source=fs.readFileSync(require.resolve('../db/postgres/initialize-application'),'utf8');
 const lease={async beginMaintenance(){return Object.freeze({epoch:"1"});},async finishMaintenance(){},assertHeld(){calls.push('held');if((loss&&calls.includes('identity'))||(lossAfterWorkshopSeed&&calls.includes('seed'))||(lossAfterStandaloneSeed&&calls.includes('standalone-seed')))throw Object.assign(Error('lost'),{code:'APPLICATION_LEASE_NOT_HELD'});},async close(){calls.push('lease-close');if(closeFailure)throw Object.assign(Error('private'),{code:'APPLICATION_LEASE_CLOSE_TIMEOUT'});}};
 const pg={createPool(){return{async end(){calls.push('pool-end');if(drainFailure)throw Error('postgres://secret');}};},async closePostgresPools(){calls.push('all-pools');}};
 function load(name){if(name.endsWith('applicationMaintenanceLease'))return{async acquireApplicationMaintenanceLease({mode}){assert.equal(mode,'maintenance');calls.push('lease');if(busy)throw Object.assign(Error('busy'),{code:'APPLICATION_MAINTENANCE_BUSY'});return lease;}};if(name.endsWith('/postgres')){if(importFailure)throw Error('private import');return pg;}if(name.endsWith('identityRepository'))return{async initializeIdentityRepository(){calls.push('identity');if(fail)throw Object.assign(Error('postgres://secret'),{code:'42601',migration:'0001_initial.sql'});}};if(name.endsWith('workshopPlatformSeed'))return{async seedWorkshopPlatform(){calls.push('seed');if(seedFailure)throw new TypeError('private credential URL');}};if(name.endsWith('secureshopStandaloneSeed'))return{async seedSecureShopStandaloneDefaults(){calls.push('standalone-seed');if(standaloneSeedFailure)throw new Error('private seed credential');}};if(name.endsWith('secureshopAssessmentSeed'))return{async seedSecureShopAssessmentDefaults(){calls.push('assessment-seed');if(assessmentSeedFailure)throw new Error('private assessment credential');}};return new Proxy({}, {get:()=>async()=>calls.push('workshop')});}
 vm.runInNewContext(source,{module,require:load,process:{env},console:{log(){}},setTimeout,clearTimeout,AggregateError});
 for(const row of module.exports.requiredStoreManifest){env[row.runtimeVariable]='owned';env[row.migrationVariable]='owned';}
 return{...module.exports,calls};
}
test('canonical initializer acquires before writes and closes exclusive lease after every pool',async()=>{const x=setup();await x.initializeApplication();assert.equal(x.calls[0],'lease');assert(x.calls.indexOf('identity')>x.calls.indexOf('held'));assert.equal(x.calls.at(-1),'lease-close');assert.equal(x.calls.at(-2),'held');assert(x.calls.indexOf('all-pools')<x.calls.indexOf('lease-close'));});
test('busy maintenance performs no initialization',async()=>{const x=setup({busy:true});await assert.rejects(x.initializeApplication(),{code:'APPLICATION_MAINTENANCE_BUSY'});assert.deepEqual(x.calls,['lease']);});
test('primary plus drain failures sanitized and retained lease prevents unsafe unlock',async()=>{const x=setup({fail:true,drainFailure:true});await assert.rejects(x.initializeApplication(),e=>e.code==='APPLICATION_INITIALIZATION_REQUIRES_EXIT'&&e.migration==='0001_initial.sql'&&e.errors.some(v=>v.code==='42601')&&!JSON.stringify(e).includes('secret'));assert(x.calls.includes('all-pools'));assert(!x.calls.includes('lease-close'));});
test('lease loss between identity initialization and seed prevents seed and later stores',async()=>{const x=setup({loss:true});await assert.rejects(x.initializeApplication(),{code:'APPLICATION_INITIALIZATION_REQUIRES_EXIT'});assert(!x.calls.includes('seed'));assert(!x.calls.includes('workshop'));});
test('plan reads only manifest without acquiring lease',()=>{const x=setup();assert.equal(x.configurationPlan({}).length,16);assert.deepEqual(x.calls,[]);});
test('compatibility library preserves explicit fatal lease contract rather than swallowing it',async()=>{
 const failure=Object.assign(Error('retained lease'),{code:'APPLICATION_INITIALIZATION_REQUIRES_EXIT'});
 await assert.rejects(require('../scripts/deploy-fresh').main(['init'],{initialize:async()=>{throw failure;},error(){}}),e=>e===failure);
});
test('CLI fatal boundaries terminate their own process despite retained active resources',()=>{
 const {spawnSync}=require('node:child_process');
 for(const file of ['../scripts/start-application.js','../scripts/deploy-fresh.js']){
  const source=fs.readFileSync(require.resolve(file),'utf8');const start=source.indexOf('if (require.main === module)');const exportAfter=source.indexOf('module.exports',start);const end=exportAfter<0?source.length:exportAfter;assert(start>=0&&end>start);
  const child=`const vm=require('node:vm');setInterval(()=>{},10000);const module={};vm.runInNewContext(${JSON.stringify(source.slice(start,end))},{require:{main:module},module,process,console:{error(){}},main:()=>Promise.reject(Object.assign(Error('retained'),{code:'APPLICATION_INITIALIZATION_REQUIRES_EXIT'}))});`;
  const result=spawnSync(process.execPath,['-e',child],{timeout:2000,encoding:'utf8'});assert.equal(result.error,undefined);assert.equal(result.status,1,file);assert.equal(result.signal,null);
 }
});

test('post-acquisition import and final close failures retain explicit fatal contract',async()=>{for(const options of [{importFailure:true},{closeFailure:true}]){const x=setup(options);await assert.rejects(x.initializeApplication(),e=>e.code==='APPLICATION_INITIALIZATION_REQUIRES_EXIT'&&!JSON.stringify(e).includes('private'));}});

test('initializer failure diagnostics retain bounded safe cause codes without private error fields',()=>{
 const {initializationFailureSummary:summary}=require('../db/postgres/initialize-application');
 const error=Object.assign(new AggregateError([Object.assign(Error('postgres://private'),{code:'42601',migration:'0001_initial.sql',sql:'private'}),Object.assign(Error('private'),{code:'MODULE_NOT_FOUND'}),Object.assign(Error('private'),{code:'PRIVATE_SECRET',migration:'/private/credentials.sql'})],'private'),{code:'APPLICATION_INITIALIZATION_REQUIRES_EXIT'});
 assert.deepEqual(summary(error),{code:'APPLICATION_INITIALIZATION_REQUIRES_EXIT',causes:[{code:'42601',migration:'0001_initial.sql'},{code:'MODULE_NOT_FOUND'},{code:'APPLICATION_INITIALIZATION_FAILED'}]});
 assert.equal(summary({errors:Array(30).fill(error)}).causes.length,8);
 assert(!JSON.stringify(summary(error)).includes('private'));
});

test('uncoded initialization failures retain only exact phase store and safe class',async()=>{
 for(const [options,phase,store,errorClass] of [[{importFailure:true},'postgres_import',undefined,'Error'],[{seedFailure:true},'catalog_seed','identity','TypeError']]){
  const x=setup(options);await assert.rejects(x.initializeApplication(),e=>{const report=x.initializationFailureSummary(e),cause=report.causes[0];assert.equal(cause.phase,phase);assert.equal(cause.store,store);assert.equal(cause.errorClass,errorClass);assert(!JSON.stringify(report).includes('private'));return true;});
 }
 const {initializationFailureSummary}=setup();const report=initializationFailureSummary({code:'APPLICATION_INITIALIZATION_FAILED',phase:'private phase',store:'postgres://secret',errorClass:'private name'});assert.deepEqual(Object.keys(report).sort(),['causes','code']);
});


test('standalone default seed runs under lease after identity catalog and before pool drain',async()=>{
 const x=setup();await x.initializeApplication();const at=x.calls.indexOf('standalone-seed');
 assert(at>x.calls.indexOf('seed'));assert.equal(x.calls[at-1],'held');
 assert(at<x.calls.indexOf('pool-end'));
});
test('lease loss after workshop seed prevents standalone default writes',async()=>{
 const x=setup({lossAfterWorkshopSeed:true});await assert.rejects(x.initializeApplication(),{code:'APPLICATION_INITIALIZATION_REQUIRES_EXIT'});
 assert(x.calls.includes('seed'));assert(!x.calls.includes('standalone-seed'));
});
test('standalone seed failure cannot advance to later stores or expose credentials',async()=>{
 const x=setup({standaloneSeedFailure:true});
 await assert.rejects(x.initializeApplication(),e=>e.code==='APPLICATION_INITIALIZATION_REQUIRES_EXIT'&&!JSON.stringify(x.initializationFailureSummary(e)).includes('private'));
 assert(x.calls.includes('standalone-seed'));assert(!x.calls.includes('workshop'));
});

test('shop assessment defaults run within the identity maintenance lease before drain',async()=>{
 const x=setup();await x.initializeApplication();const at=x.calls.indexOf('assessment-seed');
 assert(at>x.calls.indexOf('standalone-seed'));assert.equal(x.calls[at-1],'held');
 assert.equal(x.calls[at+1],'held');assert(at<x.calls.indexOf('pool-end'));
});
test('lease loss before assessment seed prevents its writes and all later stores',async()=>{
 const x=setup({lossAfterStandaloneSeed:true});await assert.rejects(x.initializeApplication(),{code:'APPLICATION_INITIALIZATION_REQUIRES_EXIT'});
 assert(!x.calls.includes('assessment-seed'));assert(!x.calls.includes('workshop'));
});
test('assessment seed failure preserves fatal maintenance contract without private diagnostics',async()=>{
 const x=setup({assessmentSeedFailure:true});await assert.rejects(x.initializeApplication(),e=>e.code==='APPLICATION_INITIALIZATION_REQUIRES_EXIT'&&!JSON.stringify(x.initializationFailureSummary(e)).includes('private'));
 assert(x.calls.includes('assessment-seed'));assert(!x.calls.includes('workshop'));
});
