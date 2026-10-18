'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),{EventEmitter}=require('node:events');
const scopes=require('../scripts/lib/application-maintenance-scope');
function sourceModule(file,load,env){const module={exports:{}};vm.runInNewContext(fs.readFileSync(require.resolve(file),'utf8'),{module,require:load,process:{env},URL,console:{log(){}},setTimeout,clearTimeout,AggregateError,AbortController});return module.exports;}
function harness(){
 const env={PG_TLS:'disable'},events=[];class Pool extends EventEmitter{constructor(options){super();this.options=options;events.push('allocate');}async end(){events.push('end');}}
 const pg=sourceModule('../server/database/postgres',name=>name==='./poolBudget'?require('../server/database/postgres/poolBudget'):{Pool},env);
 let initializer;initializer=sourceModule('../db/postgres/initialize-application',name=>{
  if(name.endsWith('application-maintenance-scope'))return scopes;if(name.endsWith('/postgres'))return pg;
  if(name.endsWith('identityRepository'))return{initializeIdentityRepository:async()=>events.push('identity')};
  if(name.endsWith('workshopPlatformSeed'))return{seedWorkshopPlatform:async()=>events.push('seed')};
  if(name.endsWith('applicationMaintenanceLease'))throw Error('Nested lease acquisition forbidden');
  return new Proxy({}, {get:()=>async()=>{const p=pg.createPool(env,'SQL_WORKSHOP_DATABASE_URL');await p.end();}});
 },env);
 for(const row of initializer.requiredStoreManifest){env[row.runtimeVariable]=`postgres://runtime@127.0.0.1/${row.schema}`;env[row.migrationVariable]=`postgres://migration@127.0.0.1/${row.schema}`;}
 const options={environment:env,acquire:async()=>({async beginMaintenance(){return Object.freeze({epoch:"1"});},async finishMaintenance(){},assertHeld(){},async close(){events.push('lease-close');}}),drain:()=>pg.closePostgresPools()};
 const additions=sourceModule('../scripts/initialize-application-additions',name=>name.includes('initialize-application')?initializer:name.includes('application-maintenance-scope')?scopes:{closePostgresPools:()=>pg.closePostgresPools()},env);
 return{env,events,pg,initializer,options,additions};
}
test('real managed registry remains usable for admin allocation after scoped initialization until outer drain',async()=>{
 const h=harness();await scopes.withApplicationMaintenanceScope(h.options,async scope=>{await h.initializer.initializeApplication({maintenanceScope:scope});const admin=h.pg.createPool(h.env,'IDENTITY_MIGRATION_DATABASE_URL');h.events.push('admin-ready');await admin.end();});assert(h.events.indexOf('admin-ready')<h.events.indexOf('lease-close'));assert.equal(h.pg.getPoolBudgetSnapshot().reserved,0);assert.throws(()=>h.pg.createPool(h.env,'IDENTITY_DATABASE_URL'),/shutting down/);
});
for(const mutation of ['second-store','tls'])test(`additions rejects ${mutation} effective environment mismatch before first import or write`,async()=>{
 const h=harness();let imports=0,writes=0;
 await scopes.withApplicationMaintenanceScope(h.options,async scope=>{
  const selected={...h.env,...(mutation==='second-store'?{NOSQL_WORKSHOP_MIGRATION_DATABASE_URL:'postgres://migration@127.0.0.1/foreign'}:{PG_TLS:'require'})};
  await assert.rejects(h.additions.initializeAdditions(['aria','nova'],{environment:selected,maintenanceScope:scope,load:()=>{imports++;return new Proxy({}, {get:()=>async()=>{writes++;}});}}),{code:'ADDITIVE_ENVIRONMENT_MISMATCH'});
  assert.equal(imports,0);assert.equal(writes,0);
 });
});
