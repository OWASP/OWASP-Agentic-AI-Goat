'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {requiredStoreManifest}=require('../db/postgres/initialize-application');
const {poolBudget}=require('../server/database/postgres/poolBudget');
const pg=require('../server/database/postgres');
const deletion=require('../server/services/studentDeletionProduction');
const reset=require('../server/services/sensitiveInfoResetComposition');
test('fully warmed supported backend plus readiness and agent-host stays within explicit single-instance budget',async()=>{
 const allocations=[];const add=(caller,key,purpose,count=1)=>{for(let i=0;i<count;i++)allocations.push({caller,key,...poolBudget({},key,purpose)});};
 for(const store of requiredStoreManifest)add('canonical_runtime',store.runtimeVariable);
 add('configured_run_ledger','IDENTITY_DATABASE_URL','lease');
 add('secureshop_cleanup','IDENTITY_DATABASE_URL','lease');
 add('secureshop_scene_provision','IDENTITY_DATABASE_URL','provision');
 add('sensitive_info_reset',reset.STORES.finflow.runtimeEnv);
 for(const store of Object.values(deletion.STORES))if(store.runtimeEnv!=='IDENTITY_DATABASE_URL')add('student_deletion_runtime',store.runtimeEnv);
 add('legacy_file_cleanup','FINFLOW_WORKSHOP_DATABASE_URL');
 add('teaching_effect','IDENTITY_DATABASE_URL','teaching');
 add('xss_mutation','IDENTITY_DATABASE_URL','lease');
 add('workshop_reset_admission','IDENTITY_DATABASE_URL','lease');
 add('bulk_reset','IDENTITY_DATABASE_URL','lease');
 // Family receipt projections reuse the canonical CTF/FinFlow/XSS pools.
 const total=allocations.reduce((sum,row)=>sum+row.max,0);assert.equal(total,73);
 const budget=poolBudget({},'IDENTITY_DATABASE_URL').budget;assert.equal(budget,78);
 const pools=[];
 try{
  for(const row of allocations)pools.push(pg.createPool({[row.key]:'postgresql://fixture@127.0.0.1/unused_fixture'},row.key,{purpose:row.purpose}));
  assert.equal(pg.getPoolBudgetSnapshot().reserved,73);
  for(let i=0;i<3;i++)pools.push(pg.createPool({IDENTITY_MIGRATION_DATABASE_URL:'postgresql://fixture@127.0.0.1/unused_fixture'},'IDENTITY_MIGRATION_DATABASE_URL'));
  assert.equal(pg.getPoolBudgetSnapshot().reserved,76);assert.ok(76<=budget);
  const agentHost=2*poolBudget({},'SECURESHOP_DATABASE_URL').max;assert.equal(agentHost,4);
  assert.equal(100-3-budget-agentHost,15,'default PG100 leaves15 usable slots beyond backend ceiling+agenthost');
 }finally{await Promise.all(pools.map(pool=>pool.end()));}
 assert.equal(pg.getPoolBudgetSnapshot().reserved,0);
});
