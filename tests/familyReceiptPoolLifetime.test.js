'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const pg=require('../server/database/postgres');
test('family receipt projections share canonical lazy pools and retain registry shutdown ownership',async()=>{
 const keys=['CTF_DATABASE_URL','FINFLOW_WORKSHOP_DATABASE_URL','XSS_WORKSHOP_DATABASE_URL'];const prior=Object.fromEntries(keys.map(key=>[key,process.env[key]]));
 for(const key of keys)process.env[key]='postgresql://fixture@127.0.0.1/unused_fixture';
 const pools=[];let queries=0,closed=0;
 try {
  const getters=[require('../server/database/postgres/ctfDb').getCtfPool,require('../server/database/postgres/sensitiveInfoWorkshopDb').getFinflowPool,require('../server/database/postgres/xssWorkshopDb').getXssWorkshopPool];
  assert.equal(pg.getPoolBudgetSnapshot().reserved,0,'module imports remain allocation-free');
  for(const get of getters){const pool=get();pools.push(pool);assert.equal(get(),pool);pool.query=async()=>{queries++;return {rows:[]};};const end=pool.end.bind(pool);pool.end=()=>{closed++;return end();};}
  assert.equal(pg.getPoolBudgetSnapshot().reserved,6);
  const factory=require('../server/database/postgres/agentRunReadRepository').createLazyFamilyReceiptAdapters;
  for(const adapters of [factory(),factory()])for(const key of ['CTF','LegacySensitiveInfo','XSS_EMAIL'])assert.deepEqual(await adapters[key]({runId:randomUUID(),ownerId:17}),[]);
  assert.equal(queries,6);assert.equal(pg.getPoolBudgetSnapshot().reserved,6,'independent projection factories allocate no duplicate pool');assert.equal(closed,0,'read adapter does not close canonical pool');
  await pg.closePostgresPools();assert.equal(closed,3);assert.equal(pg.getPoolBudgetSnapshot().reserved,0);
 } finally {for(const p of pools)if(!p.ended)await p.end();for(const key of keys)if(prior[key]===undefined)delete process.env[key];else process.env[key]=prior[key];}
});
