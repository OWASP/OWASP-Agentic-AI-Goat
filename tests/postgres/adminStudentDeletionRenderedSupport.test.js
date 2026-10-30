'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const s=require('./adminStudentDeletionRenderedSupport');
function env(){const e={PG_TEST_DISPOSABLE:'yes',PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres',PG_POOL_BUDGET:'78'};
 for(const row of s.STORES){for(const [key,role]of [[row.runtimeVariable,row.runtimeRole],[row.migrationVariable,row.migrationRole]])e[key]=`postgresql://${role}@127.0.0.1:54321/owasp_ai_goat_test_student_deletion_123456abcdef_${row.schema}`;}return e;}
test('production opener rejects injectable environment before importing allocation modules',async()=>{
 const Module=require('node:module'),original=Module._load;let sideEffects=0;
 Module._load=function(name,...args){if(name==='../../server/database/postgres'||name==='../../server/services/studentDeletionProduction'){
  sideEffects++;throw Error('Allocation import forbidden');}return original.call(this,name,...args);};
 try{await assert.rejects(s.openProductionDeletionSupport(env()),/requires process.env identity/);
  await assert.rejects(s.openProductionDeletionSupport({...process.env}),/requires process.env identity/);
  assert.equal(sideEffects,0);
 }finally{Module._load=original;}
});
test('canonical sixteen store admission returns no credentials and rejects alias/role/host drift',()=>{
 const e=env();assert.equal(s.admitStores(e).length,16);assert.equal(JSON.stringify(s.admitStores(e)).includes('postgresql'),false);
 for(const mutate of [e=>e.IDENTITY_DATABASE_URL=e.CTF_DATABASE_URL,e=>e.IDENTITY_DATABASE_URL=e.IDENTITY_DATABASE_URL.replace('127.0.0.1','localhost'),
  e=>e.PG_POOL_BUDGET='100',e=>e.LEGACY_PLATFORM_LIFECYCLE_ENABLED='true',e=>e.IDENTITY_DATABASE_URL+='?options=unsafe',
  e=>e.IDENTITY_MIGRATION_DATABASE_URL=e.IDENTITY_DATABASE_URL,
  e=>e.IDENTITY_DATABASE_URL=e.IDENTITY_DATABASE_URL.replace('_identity','_extra_identity'),
  e=>e.IDENTITY_DATABASE_URL=e.IDENTITY_DATABASE_URL.replace('_identity','_'+ 'x'.repeat(64)+'_identity')]){const v={...e};mutate(v);assert.throws(()=>s.admitStores(v));}
});
test('duplicate lifecycle pools count against aggregate budget, never deduplicated by URL',()=>{
 const e=env(),a=Array.from({length:9},(_,i)=>({id:`pool-${i}`,key:'IDENTITY_DATABASE_URL'}));
 assert.equal(s.planPools(e,a).reserved,72);assert.throws(()=>s.planPools(e,[...a,{id:'extra',key:'IDENTITY_DATABASE_URL'}]));
 assert.throws(()=>s.planPools(e,[a[0],a[0]]));
 assert.equal(s.assertPoolSnapshot({reserved:9,allocations:[{purpose:'control',max:8},{purpose:'lease',max:1}]}).reserved,9);
 for(const p of [{reserved:1,allocations:[]},{reserved:79,allocations:[{purpose:'workshop',max:79}]},{reserved:1,allocations:[{purpose:'unknown',max:1}]}])assert.throws(()=>s.assertPoolSnapshot(p));
});
test('identity oracle requires all exact ordered real steps, tombstone, no sessions and unchanged sibling',()=>{
 const jobId='12345678-1234-4234-8234-123456789abc';const state={jobs:[{job_id:jobId,state:'completed'}],
  user:[{id:19,username:`deleted-${jobId}`,email:`deleted-${jobId}@invalid.local`,is_active:0}],sessions:[],
  steps:s.STUDENT_DELETION_STEPS.map(step_key=>({step_key,state:'completed'}))};
 const options={subjectId:19,jobId,siblingBefore:{id:20,active:true},siblingAfter:{id:20,active:true}};
 assert.equal(s.assertIdentityDeletionComplete(state,options).canonicalCredit,false);
 for(const mutate of [v=>v.steps.pop(),v=>v.steps.reverse(),v=>v.steps[0].state='pending',v=>v.user=[],v=>v.user[0].is_active=1,v=>v.sessions.push({id:1}),v=>v.jobs[0].state='running']){
  const v=structuredClone(state);mutate(v);assert.throws(()=>s.assertIdentityDeletionComplete(v,options));}
 assert.throws(()=>s.assertIdentityDeletionComplete(state,{...options,siblingAfter:{id:20,active:false}}));
});
