'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {poolBudget}=require('../../server/database/postgres/poolBudget');
const {createPool,getPoolBudgetSnapshot}=require('../../server/database/postgres');
test('pool categories fit laptop reserve and aggregate allocation rejects oversubscription',async()=>{
 assert.equal(poolBudget({},'IDENTITY_DATABASE_URL').max,8);assert.equal(poolBudget({},'WORKSHOP_DATABASE_URL').max,2);assert.equal(poolBudget({},'IDENTITY_MIGRATION_DATABASE_URL').max,1);assert.equal(poolBudget({},'IDENTITY_DATABASE_URL','lease').max,4);assert.equal(poolBudget({},'IDENTITY_DATABASE_URL','provision').max,1);
 assert.throws(()=>poolBudget({PG_POOL_MAX_LEASE:'1000'},'IDENTITY_DATABASE_URL','lease'),/integer/);
 assert.throws(()=>poolBudget({PG_POOL_MAX_PROVISION:'2'},'IDENTITY_DATABASE_URL','provision'),/integer/);
 const env={IDENTITY_DATABASE_URL:'postgresql://fixture@localhost/fixture',PG_POOL_BUDGET:'10'};
 const control=createPool(env,'IDENTITY_DATABASE_URL');try{assert.equal(getPoolBudgetSnapshot().reserved,8);assert.throws(()=>createPool(env,'IDENTITY_DATABASE_URL',{purpose:'lease'}),/budget exhausted/);}finally{await control.end();}
 const lease=createPool(env,'IDENTITY_DATABASE_URL',{purpose:'lease'});assert.equal(getPoolBudgetSnapshot().reserved,4);await lease.end();assert.equal(getPoolBudgetSnapshot().reserved,0);
});

test('teaching effect leases reserve a separate bounded allocation', async () => {
 const env={IDENTITY_DATABASE_URL:'postgresql://fixture@localhost/fixture',PG_POOL_BUDGET:'10'};
 assert.equal(poolBudget(env,'IDENTITY_DATABASE_URL','teaching').max,2);
 const control=createPool(env,'IDENTITY_DATABASE_URL');
 const teaching=createPool(env,'IDENTITY_DATABASE_URL',{purpose:'teaching'});
 try {
  assert.equal(getPoolBudgetSnapshot().reserved,10);
  assert.throws(()=>createPool(env,'IDENTITY_DATABASE_URL',{purpose:'teaching'}),/budget exhausted/);
 } finally {await teaching.end();await control.end();}
});

test('protected identity and resource lease purposes reserve four managed slots',async()=>{
 const env={IDENTITY_DATABASE_URL:'postgresql://fixture@localhost/fixture',MCP_WORKSHOP_DATABASE_URL:'postgresql://fixture@localhost/mcp_fixture'};
 assert.equal(poolBudget(env,'IDENTITY_DATABASE_URL','protected').max,2);
 const a=createPool(env,'IDENTITY_DATABASE_URL',{purpose:'protected'}),b=createPool(env,'MCP_WORKSHOP_DATABASE_URL',{purpose:'protected'});
 try{assert.equal(getPoolBudgetSnapshot().reserved,4);assert.equal(72+getPoolBudgetSnapshot().reserved,76);assert.ok(76<=poolBudget(env,'IDENTITY_DATABASE_URL').budget);}finally{await a.end();await b.end();}
});
