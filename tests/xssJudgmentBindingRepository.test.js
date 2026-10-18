'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {createXssJudgmentBindingRepository}=require('../server/database/postgres/xssJudgmentBindingRepository');

const value=Object.freeze({runId:'123e4567-e89b-42d3-a456-426614174000',ownerId:7,
 ownerKey:'["XSS","7"]',scopeKey:'stored_user',parentGeneration:'3',childGeneration:'4'});
const row=()=>({runId:value.runId,ownerId:7,ownerKey:value.ownerKey,scopeKey:value.scopeKey,
 parentGeneration:'3',childGeneration:'4'});

test('uses ordered authority functions and preserves exact bigint coordinates',async()=>{
 const calls=[];const client={query:async(sql,args)=>{calls.push({sql,args});return{rowCount:1,rows:[row()]};}};
 const repo=createXssJudgmentBindingRepository();
 assert.deepEqual(await repo.lockRunPrefix(client,value),value);
 assert.deepEqual(await repo.lockEvaluationPrefix(client,{userId:7,evaluationId:value.runId}),value);
 assert.deepEqual(await repo.bindEvaluationAfterWorkshopLock(client,{userId:7,evaluationId:value.runId,
  workshopGeneration:9,value}),value);
 assert.deepEqual(await repo.assertChildAfterWorkshopLock(client,{userId:7,evaluationId:value.runId,
  workshopGeneration:9,value}),value);
 assert.deepEqual(calls.map(call=>call.sql.match(/identity\.([a-z_]+)/)[1]),[
  'lock_xss_judgment_run_prefix','lock_xss_judgment_prefix',
  'bind_xss_judgment_scope','assert_xss_judgment_child_current']);
 assert.deepEqual(calls[2].args.slice(-2),['4',9]);
});

test('unbound history returns null while stale or conflicting authority fails closed',async()=>{
 const repo=createXssJudgmentBindingRepository();
 assert.equal(await repo.lockEvaluationPrefix({query:async()=>({rowCount:0,rows:[]})},
  {userId:7,evaluationId:value.runId}),null);
 await assert.rejects(repo.lockRunPrefix({query:async()=>({rowCount:1,rows:[{...row(),childGeneration:'5'}]})},value),
  {code:'STALE_GENERATION'});
 await assert.rejects(repo.lockRunPrefix({query:async()=>{const error=new Error('stale');error.code='55000';throw error;}},value),
  error=>error.code==='STALE_GENERATION'&&error.cause?.code==='55000');
});

test('scoped-run omission is rejected while a legacy unscoped run remains compatible',async()=>{
 const repo=createXssJudgmentBindingRepository();let unscoped=true;
 const client={query:async()=>({rows:[{unscoped}],rowCount:1})};
 await repo.assertRunIsUnscoped(client,{runId:value.runId});
 unscoped=false;
 await assert.rejects(repo.assertRunIsUnscoped(client,{runId:value.runId}),{code:'JUDGMENT_SCOPE_MISMATCH'});
});
