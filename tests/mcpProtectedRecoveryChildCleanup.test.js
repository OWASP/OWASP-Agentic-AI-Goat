'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {closeChildResources}=require('./fixtures/mcpProtectedRecoveryChild');
const {reserveDedicatedConnection}=require('../server/database/postgres');

test('protected recovery child attempts every teardown and retains each cleanup failure',async()=>{
 const calls=[];
 const errors=await closeChildResources({
  production:{async close(){calls.push('production.close');throw Object.assign(new Error('production close failed'),{code:'PRODUCTION_CLOSE'});}},
  server:{closeAllConnections(){calls.push('server.closeAllConnections');throw new Error('server connection close failed');},close(callback){calls.push('server.close');callback(Object.assign(new Error('server close failed'),{code:'SERVER_CLOSE'}));}},
  pools:[{end:()=>{calls.push('pool.one');throw Object.assign(new Error('pool one failed'),{code:'POOL_ONE'});}},
   {end:async()=>{calls.push('pool.two');throw Object.assign(new Error('pool two failed'),{code:'POOL_TWO'});}}],
 });
 assert.deepEqual(calls,['production.close','server.closeAllConnections','server.close','pool.one','pool.two']);
 assert.deepEqual(errors.map(error=>[error.phase,error.code]),[
  ['production.close','PRODUCTION_CLOSE'],['server.closeAllConnections',null],['server.close','SERVER_CLOSE'],
  ['pool.end','POOL_ONE'],['pool.end','POOL_TWO']
 ]);
});

test('protected recovery child retains a nonzero budget failure after teardown attempts',async()=>{
 const release=reserveDedicatedConnection({PG_POOL_BUDGET:'1'});
 try{
  const errors=await closeChildResources({production:null,server:null,pools:[]});
  assert.equal(errors.length,1);assert.equal(errors[0].phase,'pool-budget');assert.match(errors[0].message,/1 !== 0/);
 }finally{release();}
});
