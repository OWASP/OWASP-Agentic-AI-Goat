'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const path=require('node:path');
const {execFile}=require('node:child_process');
const {promisify}=require('node:util');
const {readMigrations}=require('../db/postgres/migrate');
const {STORES,assertStudentDeletionReadiness}=require('../server/services/studentDeletionProduction');

async function fixture(overrides={}){
 const expected={};for(const [name,store] of Object.entries(STORES))expected[name]=await readMigrations(store.directory);
 const calls=[];
 const runtimePools={};const migrationPools={};
 for(const [name,store] of Object.entries(STORES)){
  runtimePools[name]={async query(sql,values){calls.push(['runtime',name,sql]);
   if(sql.startsWith('SELECT current_user'))return{rows:[{role:store.runtimeRole,database:overrides.duplicate?'owned_shared':`owned_${name}`}]};
   if(sql.includes('to_regprocedure'))return{rows:[{present:overrides.missing===name||overrides.missingCapability===values?.[0]?false:true,
    executable:true,public_revoked:overrides.public===name?false:true}]};
   if(name==='identity'&&sql.includes("to_regclass('identity.ipi_email_artifacts')"))return{rows:[{
    table_ready:overrides.emailArtifact!=='missing-table',run_table_ready:true,
    privileges_ready:overrides.emailArtifact!=='missing-privileges',
    immutable_ready:overrides.emailArtifact!=='missing-triggers'}]};
   throw Error('unexpected runtime query');}};
  migrationPools[name]={async query(sql){calls.push(['migration',name,sql]);
   if(sql.startsWith('SELECT current_user'))return{rows:[{role:store.migrationRole,database:overrides.duplicate?'owned_shared':`owned_${name}`}]};
   if(sql.includes('dvaia_migrations.ledger'))return{rows:overrides.ledger===name?expected[name].slice(0,-1):expected[name]};
   throw Error('unexpected migration query');}};
 }
 return{runtimePools,migrationPools,calls};
}
test('production deletion readiness requires every exact ledger and runtime finalizer capability',async()=>{
 const ready=await fixture();assert.equal(await assertStudentDeletionReadiness(ready),true);
 for(const name of Object.keys(STORES))assert.equal(ready.calls.some(call=>call[1]===name&&call[2].includes('to_regprocedure')),true);
 assert.equal(ready.calls.some(call=>call[0]==='runtime'&&call[1]==='identity'
  &&call[2].includes("to_regclass('identity.ipi_email_artifacts')")),true);
});
test('partial finalizer or partial migration manifest fails the whole deletion boundary',async()=>{
 for(const [kind,name] of [['missing','xss'],['public','identity'],['ledger','finflow']]){
  const value=await fixture({[kind]:name});
  await assert.rejects(assertStudentDeletionReadiness(value),{code:'DELETION_UNAVAILABLE',statusCode:503});
 }
});
test('missing IPI email artifact table rejects the complete deletion readiness boundary',async()=>{
 for(const emailArtifact of ['missing-table','missing-privileges','missing-triggers']){
  const value=await fixture({emailArtifact});
  await assert.rejects(assertStudentDeletionReadiness(value),{
   code:'EMAIL_ARTIFACT_STORAGE_NOT_READY',statusCode:503,
  });
  assert.equal(value.calls.some(call=>call[0]==='runtime'&&call[1]==='identity'
   &&call[2].includes("to_regclass('identity.ipi_email_artifacts')")),true);
 }
});
test('partial runtime-pool allocation closes every pool already owned by the deletion composition',async()=>{
 const script=String.raw`
  const assert=require('node:assert/strict'),Module=require('node:module');
  const target=${JSON.stringify(path.join(__dirname,'../server/services/studentDeletionProduction.js'))};
  const original=Module._load;let ended=0;
  Module._load=function(request,parent,isMain){
   if(parent?.filename===target&&request==='../database/postgres')return{createPool(_env,key){
    if(key==='XSS_WORKSHOP_DATABASE_URL')return{async end(){ended+=1;}};
    if(key==='FINFLOW_WORKSHOP_DATABASE_URL')throw Error('owned allocation failure');
    throw Error('unexpected pool');}};
   if(parent?.filename===target&&request==='./ctfAuthorityProduction')return{getProductionCtfAuthority:()=>({runtime:{deleteStudent(){}}})};
   if(parent?.filename===target&&request==='./postgresIdentityAdapter')return{getPostgresIdentityAdapter:()=>({pool:{}})};
   return original.call(this,request,parent,isMain);
  };
  process.env.PLATFORM_DATABASE_ENGINE='postgres';process.env.LEGACY_PLATFORM_LIFECYCLE_ENABLED='true';
  for(const key of ['IDENTITY_DATABASE_URL','IDENTITY_MIGRATION_DATABASE_URL','XSS_WORKSHOP_DATABASE_URL',
   'XSS_WORKSHOP_MIGRATION_DATABASE_URL','FINFLOW_WORKSHOP_DATABASE_URL','FINFLOW_WORKSHOP_MIGRATION_DATABASE_URL',
   'LEGACY_CHALLENGE_DATABASE_URL','LEGACY_CHALLENGE_MIGRATION_DATABASE_URL',
   'SENSITIVE_LOOKUP_DATABASE_URL','SENSITIVE_LOOKUP_MIGRATION_DATABASE_URL'])process.env[key]='postgresql://owned.invalid/test';
  require(target).getProductionStudentDeletionComposition().then(()=>{throw Error('unexpected success')},error=>{
   assert.match(error.message,/allocation failure/);assert.equal(ended,1);
  }).catch(error=>{console.error(error);process.exitCode=1});`;
 await promisify(execFile)(process.execPath,['-e',script],{timeout:10000});
});

test('owned readiness holds only one migration reservation and closes it before the next store',async()=>{
 const {assertOwnedStudentDeletionReadiness}=require('../server/services/studentDeletionProduction');
 const ready=await fixture();let active=0,peak=0,index=0;
 const migrations=Object.values(ready.migrationPools);
 const createMigrationPool=()=>{
  const pool=migrations[index++],end=pool.end;
  active+=1;peak=Math.max(peak,active);
  return{...pool,async end(){await end?.call(pool);active-=1;}};
 };
 assert.equal(await assertOwnedStudentDeletionReadiness({runtimePools:ready.runtimePools,
   createMigrationPool,env:{}}),true);
 assert.equal(index,Object.keys(STORES).length);assert.equal(peak,1);assert.equal(active,0);
});

test('owned readiness stops after a failed store and closes the failing migration pool',async()=>{
 const {assertOwnedStudentDeletionReadiness}=require('../server/services/studentDeletionProduction');
 const ready=await fixture({ledger:'xss'});let allocated=0,closed=0;
 const migrations=Object.values(ready.migrationPools);
 await assert.rejects(assertOwnedStudentDeletionReadiness({runtimePools:ready.runtimePools,env:{},
  createMigrationPool(){const pool=migrations[allocated++];return{...pool,async end(){closed+=1;}};}}),
 {code:'DELETION_UNAVAILABLE'});
 assert.equal(allocated,2);assert.equal(closed,2);
});
test('owned readiness closes identity migration pool and stops when IPI email artifacts are unavailable',async()=>{
 const {assertOwnedStudentDeletionReadiness}=require('../server/services/studentDeletionProduction');
 const ready=await fixture({emailArtifact:'missing-table'});let allocated=0,closed=0;
 const migrations=Object.values(ready.migrationPools);
 await assert.rejects(assertOwnedStudentDeletionReadiness({runtimePools:ready.runtimePools,env:{},
  createMigrationPool(){const pool=migrations[allocated++];return{...pool,async end(){closed+=1;}};}}),
 {code:'EMAIL_ARTIFACT_STORAGE_NOT_READY',statusCode:503});
 assert.equal(allocated,1);assert.equal(closed,1);
});

test('migration cleanup failure prevents later allocation and leaves borrowed runtime pools open',async()=>{
 const {assertOwnedStudentDeletionReadiness}=require('../server/services/studentDeletionProduction');
 const ready=await fixture();let allocated=0,runtimeEnds=0;
 for(const pool of Object.values(ready.runtimePools))pool.end=async()=>{runtimeEnds+=1;};
 await assert.rejects(assertOwnedStudentDeletionReadiness({runtimePools:ready.runtimePools,env:{},
  createMigrationPool(){allocated+=1;return{...Object.values(ready.migrationPools)[0],
   async end(){throw Error('owned migration close failed');}};}}),/owned migration close failed/);
 assert.equal(allocated,1);assert.equal(runtimeEnds,0);
});

test('duplicate store identity rejects only after every sequential migration pool closes',async()=>{
 const {assertOwnedStudentDeletionReadiness}=require('../server/services/studentDeletionProduction');
 const ready=await fixture({duplicate:true});let allocated=0,closed=0;
 const migrations=Object.values(ready.migrationPools);
 await assert.rejects(assertOwnedStudentDeletionReadiness({runtimePools:ready.runtimePools,env:{},
  createMigrationPool(){const pool=migrations[allocated++];return{...pool,async end(){closed+=1;}};}}),
 /stores are not isolated/);
 assert.equal(allocated,Object.keys(STORES).length);assert.equal(closed,allocated);
});

test('private history cleanup is mandatory for production student deletion readiness',async()=>{
 const signature='legacy_ai_private.cleanup_history_for_student_deletion(uuid,uuid,integer)';
 assert.ok(STORES.identity.capabilities.includes(signature));
 await assert.rejects(assertStudentDeletionReadiness(await fixture({missingCapability:signature})),{code:'DELETION_UNAVAILABLE',statusCode:503});
});

test('production deletion refuses before pool allocation when CTF singleton is unavailable',async()=>{
 const script=String.raw`
 const assert=require('node:assert/strict'),Module=require('node:module');
 const target=${JSON.stringify(require.resolve('../server/services/studentDeletionProduction'))};
 const original=Module._load;let allocations=0;
 Module._load=function(request,parent,isMain){
  if(parent?.filename===target&&request==='../database/postgres')return{createPool(){allocations++;throw Error('must not allocate');}};
  if(parent?.filename===target&&request==='./ctfAuthorityProduction')return{getProductionCtfAuthority(){throw Object.assign(Error('unavailable'),{code:'CTF_RUNTIME_UNAVAILABLE'});}};
  return original.call(this,request,parent,isMain);
 };
 process.env.PLATFORM_DATABASE_ENGINE='postgres';process.env.LEGACY_PLATFORM_LIFECYCLE_ENABLED='true';
 for(const prefix of ['IDENTITY','XSS_WORKSHOP','FINFLOW_WORKSHOP','LEGACY_CHALLENGE','SENSITIVE_LOOKUP'])for(const suffix of ['_DATABASE_URL','_MIGRATION_DATABASE_URL'])process.env[prefix+suffix]='postgresql://owned.invalid/test';
 require(target).getProductionStudentDeletionComposition().then(()=>{throw Error('unexpected success')},error=>{assert.equal(error.code,'CTF_RUNTIME_UNAVAILABLE');assert.equal(allocations,0);}).catch(e=>{console.error(e);process.exitCode=1});`;
 await require('node:util').promisify(require('node:child_process').execFile)(process.execPath,['-e',script]);
});
