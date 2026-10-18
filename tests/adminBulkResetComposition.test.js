'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createAdminBulkResetComposition,assertAdminBulkResetReadiness}=require('../server/services/adminBulkResetComposition');
const request={user:{id:2},identitySession:{id:9},headers:{authorization:'Bearer current'}};
test('bulk composition refreshes exact canonical bearer binding and does not allocate lease before use',async()=>{
 let calls=0,pools=0;const composition=createAdminBulkResetComposition({pool:{query:async()=>({rows:[]})},identityAdapter:{validateSession:async token=>{assert.equal(token,'current');calls++;return{user:{id:2},session:{id:9}};}},createLeasePool:()=>{pools++;}});
 assert.deepEqual(await composition.resolveBulkActor(request),{actorId:2,sessionId:'9'});await composition.resolveBulkActor(request);assert.equal(calls,2);assert.equal(pools,0);
 await assert.rejects(composition.resolveBulkActor({...request,user:{id:3}}),{code:'BULK_RESET_AUTHORITY_REJECTED'});
 await assert.rejects(composition.resolveBulkActor({...request,headers:{}}),{code:'BULK_RESET_AUTHORITY_REJECTED'});
 await assert.rejects(composition.bulkJournal.listPending({actorId:2,sessionId:'9'}),{code:'RESET_STORAGE_NOT_READY'});assert.equal(pools,0);
});
test('readiness fails closed for missing schema and database errors',async()=>{
 await assert.rejects(assertAdminBulkResetReadiness({query:async()=>({rows:[]})}),{code:'RESET_STORAGE_NOT_READY'});
 await assert.rejects(assertAdminBulkResetReadiness({query:async()=>{throw new Error('private database detail');}}),error=>error.code==='RESET_STORAGE_NOT_READY'&&!error.message.includes('private'));
});
test('default factory composes durable bulk readiness without eagerly allocating a lease pool',async()=>{
 const Module=require('node:module'),original=Module._load;const servicePath=require.resolve('../server/services/postgresWorkshopResetService');delete require.cache[servicePath];let allocated=0;
 const pool={query:async()=>({rows:[]})};
 Module._load=function(name,parent,...rest){
  if(parent?.filename===servicePath){
   if(name==='./postgresPlatformStores')return{getPostgresPlatformStores:()=>({pool,progress:{}})};
   if(name==='./postgresIdentityAdapter')return{getPostgresIdentityAdapter:()=>({pool,validateSession:async()=>({user:{id:2},session:{id:9}})})};
   if(name==='../database/postgres')return{createPool:()=>{allocated++;return{};}};
  }
  return original.call(this,name,parent,...rest);
 };
 try{const service=require(servicePath).getPostgresWorkshopResetService();assert.equal(allocated,0);await assert.rejects(service.listPendingBulkResets({actorRequest:request}),{code:'RESET_STORAGE_NOT_READY'});assert.equal(allocated,0);}finally{Module._load=original;delete require.cache[servicePath];}
});
