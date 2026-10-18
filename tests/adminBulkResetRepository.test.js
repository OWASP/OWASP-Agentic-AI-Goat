'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createAdminBulkResetRepository}=require('../server/database/postgres/adminBulkResetRepository');
const operationId='cccccccc-cccc-4ccc-accc-cccccccccccc';
test('bulk reset requires a separate lease pool and discards failed unlock connections',async()=>{
 const pool={query:async()=>({rows:[]})};await assert.rejects(createAdminBulkResetRepository(pool).withOperation(operationId,async()=>{}),/Dedicated/);
 const unlockFailure=new Error('connection lost');let released;
 const client={query:async sql=>{if(sql.includes('try_advisory'))return{rows:[{locked:true}]};throw unlockFailure;},release:error=>{released=error;}};
 const repo=createAdminBulkResetRepository(pool,{leasePool:{connect:async()=>client}});
 await assert.rejects(repo.withOperation(operationId,async()=>{}),error=>error===unlockFailure);assert.equal(released,unlockFailure);
});
test('failed operation unlocks and returns a healthy lease connection',async()=>{
 let released='not released',unlocked=false;
 const client={query:async sql=>{if(sql.includes('try_advisory'))return{rows:[{locked:true}]};unlocked=true;return{rows:[{unlocked:true}]};},release:error=>{released=error;}};
 const repo=createAdminBulkResetRepository({query:async()=>{}},{leasePool:{connect:async()=>client}});
 await assert.rejects(repo.withOperation(operationId,async()=>{throw new Error('child failed');}),/child failed/);assert.equal(unlocked,true);assert.equal(released,undefined);
});
