'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const {attachCleanupErrors,createProtectedRecoveryProduction}=require('../server/services/mcp/protectedRecoveryProduction');
const {getPoolBudgetSnapshot}=require('../server/database/postgres');
const env={MCP_PROTECTED_RECOVERY_ENABLED:'true',IDENTITY_DATABASE_URL:'postgresql://fixture@localhost/dvaia_fixture',MCP_WORKSHOP_DATABASE_URL:'postgresql://fixture@localhost/dvaia_mcp_fixture'};
const identityAdapter={validateSession:async()=>null,pool:{query:async sql=>({rows:[sql.includes('has_table_privilege')?{read:true,write:false}:{admit:true,append:true,internal:false}]})}};
const targets={readProtectedOperationReceipt:async()=>{},readiness:async()=>({ready:true,runnerReady:true,isolation:'bwrap-seccomp-v1',supervisorProfile:'dvaia-mcp-sandbox (enforce)',protectedJournalCapability:'mcp-owned-protected-operation-journal.v1',protectedReadbackCapability:'mcp-owned-protected-readback.v1'})};
test('managed recovery registers four connections within76/78 modeled budget and closes them',async()=>{
 const before=getPoolBudgetSnapshot().reserved;const result=await createProtectedRecoveryProduction({env,identityAdapter,targets});assert.equal(getPoolBudgetSnapshot().reserved,before+4);assert.equal(72+4,76);assert.equal(result.resourceLeasePool.options.max,2);await result.close();assert.equal(getPoolBudgetSnapshot().reserved,before);
});
test('old capability, schema drift and partial pool allocation failures close all newly owned pools',async()=>{
 for(const selected of [
  {env,identityAdapter,targets:{...targets,readiness:async()=>({ready:true})}},
  {env,targets,identityAdapter:{...identityAdapter,pool:{query:async()=>({rows:[{read:true,write:true}]})}}},
  {env:{...env,PG_POOL_BUDGET:'3'},identityAdapter,targets},
 ]){const before=getPoolBudgetSnapshot().reserved;await assert.rejects(createProtectedRecoveryProduction(selected));assert.equal(getPoolBudgetSnapshot().reserved,before);}
});

test('close attempts every owned pool and reports synchronous and asynchronous cleanup failures',async()=>{
 const calls=[];
 const poolFactory=(_env,key)=>({options:{max:1,connectionTimeoutMillis:5000},end:()=>{calls.push(key);if(key==='IDENTITY_DATABASE_URL')throw Object.assign(Error('identity close failed'),{code:'IDENTITY_CLOSE'});return Promise.reject(Object.assign(Error('mcp close failed'),{code:'MCP_CLOSE'}));}});
 const result=await createProtectedRecoveryProduction({env:{...env,PG_POOL_BUDGET:'2'},identityAdapter,targets,poolFactory});
 await assert.rejects(result.close(),error=>{assert.equal(error.name,'AggregateError');assert.deepEqual(calls,['IDENTITY_DATABASE_URL','MCP_WORKSHOP_DATABASE_URL']);assert.deepEqual(error.cleanupErrors.map(item=>item.code),['IDENTITY_CLOSE','MCP_CLOSE']);return true;});
});

test('close waits for a delayed pool after another pool rejects',async()=>{
 let release;const calls=[];
 const poolFactory=(_env,key)=>({options:{max:1,connectionTimeoutMillis:5000},end:()=>{calls.push(key);if(key==='IDENTITY_DATABASE_URL')return Promise.reject(Object.assign(Error('identity close failed'),{code:'IDENTITY_CLOSE'}));return new Promise((_,reject)=>{release=()=>reject(Object.assign(Error('delayed mcp close failed'),{code:'MCP_CLOSE_DELAYED'}));});}});
 const result=await createProtectedRecoveryProduction({env:{...env,PG_POOL_BUDGET:'2'},identityAdapter,targets,poolFactory});
 const closing=result.close();await new Promise(resolve=>setImmediate(resolve));assert.deepEqual(calls,['IDENTITY_DATABASE_URL','MCP_WORKSHOP_DATABASE_URL']);release();await assert.rejects(closing,error=>{assert.deepEqual(error.cleanupErrors.map(item=>item.code),['IDENTITY_CLOSE','MCP_CLOSE_DELAYED']);return true;});
});

test('initialization preserves the readiness error while reporting cleanup failures',async()=>{
 const poolFactory=(_env,key)=>({options:{max:1},end:()=>{throw Object.assign(Error(`${key} close failed`),{code:`${key}_CLOSE`});}});
 await assert.rejects(createProtectedRecoveryProduction({env:{...env,PG_POOL_BUDGET:'2'},identityAdapter,targets:{...targets,readiness:async()=>{throw Object.assign(Error('readiness failed'),{code:'READINESS'});}},poolFactory}),error=>{assert.equal(error.code,'READINESS');assert.deepEqual(error.cleanupErrors.map(item=>item.code),['IDENTITY_DATABASE_URL_CLOSE','MCP_WORKSHOP_DATABASE_URL_CLOSE']);return true;});
});

test('cleanup diagnostics never replace a frozen primary error',()=>{
 const primary=Object.freeze(Error('primary'));
 assert.strictEqual(attachCleanupErrors(primary,[{code:'CLEANUP'}]),primary);
 assert.equal(primary.message,'primary');
});
