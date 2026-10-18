'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const {createSecureShopRealmProgressCleanupCheckpointRepository:createRepository}
  =require('../server/database/postgres/secureshopRealmProgressCleanupCheckpointRepository');

test('shop checkpoint uses only retained shop authority and returns the same immutable receipt on replay',async()=>{
  const resetId=randomUUID(),saved={reset_id:resetId,launch_id:randomUUID(),tenant_id:randomUUID(),
    principal_id:randomUUID(),retired_contribution_count:2,projected_completion_count:1},calls=[];
  const pool={connect:async()=>{throw Error('Platform checkpoint must not run');},async query(sql,args){
    calls.push(sql);assert.deepEqual(args,[resetId]);
    if(sql.includes('SELECT o.realm'))return{rows:[{realm:'shop'}]};
    assert.equal(sql,'SELECT * FROM secureshop_auth.finalize_assessment_cleanup($1)');
    return{rows:[{...saved}]};
  }};
  const repository=createRepository(pool),first=await repository.finalize(resetId);
  assert.deepEqual(first,await repository.finalize(resetId));
  assert.equal(first.realm,'shop');assert.deepEqual(first.checkpoint,saved);
  assert.equal(calls.some(sql=>sql.includes('workshop_platform')||sql.includes('identity.users')),false);
});

test('missing or unknown reset realm fails before either cleanup writer',async()=>{
  for(const rows of [[],[{realm:'unknown'}],[{realm:null}]]){
    let calls=0;
    const pool={connect:async()=>{throw Error('Unexpected platform transaction');},query:async()=>{calls++;return{rows};}};
    await assert.rejects(createRepository(pool).finalize(randomUUID()),{code:'PROGRESS_CHECKPOINT_MISMATCH'});
    assert.equal(calls,1);
  }
});

test('shop checkpoint failure never falls back to platform cleanup or accepts another receipt',async()=>{
  const resetId=randomUUID();let outcome;
  const pool={connect:async()=>{throw Error('Platform fallback forbidden');},async query(sql){
    if(sql.includes('SELECT o.realm'))return{rows:[{realm:'shop'}]};
    if(outcome instanceof Error)throw outcome;
    return{rows:outcome};
  }};
  const repository=createRepository(pool);
  for(outcome of [[],[{reset_id:randomUUID()}]]){
    await assert.rejects(repository.finalize(resetId),{code:'PROGRESS_CHECKPOINT_MISMATCH'});
  }
  outcome=Object.assign(Error('Expected guarded rollback'),{code:'55000'});
  await assert.rejects(repository.finalize(resetId),{code:'55000'});
});

test('explicit platform realm retains the original platform transaction path',async()=>{
  let connected=0;
  const sentinel=Object.assign(Error('Platform transaction selected'),{code:'EXPECTED_PLATFORM_PATH'});
  const pool={query:async()=>({rows:[{realm:'platform'}]}),connect:async()=>{connected++;throw sentinel;}};
  await assert.rejects(createRepository(pool).finalize(randomUUID()),{code:'EXPECTED_PLATFORM_PATH'});
  assert.equal(connected,1);
});

test('shop progress reads surviving contributions, not an immutable retired first-completion row',async()=>{
  const {createSecureShopAssessmentSubjects}=require('../server/services/secureshopAssessmentSubject');
  const {createSecureShopAssessmentStore}=require('../server/database/postgres/secureshopAssessmentStore');
  const tenant=randomUUID(),principal=randomUUID(),scope={launchId:randomUUID(),scenarioId:randomUUID(),
    generation:2,platformOwnerId:501,platformSessionId:502};
  let active=false;
  const answer=rows=>({rows,rowCount:rows.length});
  const query=async sql=>{
    if(['BEGIN','COMMIT','ROLLBACK'].includes(sql)||sql.includes('pg_advisory_xact_lock'))return answer([]);
    if(sql.includes('SELECT realm'))return answer([{realm:'shop',shop_tenant_id:tenant}]);
    if(sql.includes('SELECT e.tenant_id'))return answer([{tenant_id:tenant,principal_id:principal,shop_user_id:1000000001,membership_version:'1'}]);
    if(sql.includes('SELECT s.id'))return answer([{id:502}]);
    if(sql.includes('SELECT l.launch_id'))return answer([{launch_id:scope.launchId}]);
    if(sql.includes('lock_assessment_mode'))return answer([{mode:'vuln',generation:0,revision:'1'}]);
    if(sql.includes('SELECT o.*'))return answer([{catalog_active:true,effective_enabled:true,qualification:'native-model'}]);
    if(sql.includes('FROM secureshop_auth.assessment_completions'))return answer([{objective_id:'ss_loop_observation'}]);
    if(sql.includes('FROM secureshop_auth.active_assessment_contributions'))return answer(active?[{objective_id:'ss_loop_observation'}]:[]);
    throw Error('Unexpected progress query');
  };
  const pool={query,connect:async()=>({query,release(){}})};
  const subjects=createSecureShopAssessmentSubjects({identityPool:pool,launches:{assertCurrent:async()=>{}},
    personaAuthority:{capture:()=>({assertRemoteAdmission:async()=>{},withCrossStoreEffect:work=>work()})}});
  const subject=await subjects.capture({scope,personaId:1000000001,role:'customer',sessionId:randomUUID(),authorityVersion:'1'},
    {runId:randomUUID(),ownerKey:'shop-reset-test',durableGeneration:'0',check:async()=>{}});
  const {progress}=createSecureShopAssessmentStore({pool,subject});
  const state=()=>progress.getObjectiveCompletionState(501,'secureshop_agent_security','ss_loop_observation',{expectedGeneration:0});
  assert.deepEqual(await state(),{generation:0,completed:false});
  assert.deepEqual(await progress.getCanonicalWorkshopCompletions(501,'secureshop_agent_security',{expectedGeneration:0}),
    {generation:0,objectiveIds:[]});
  active=true;
  assert.deepEqual(await state(),{generation:0,completed:true});
  assert.deepEqual(await progress.getCanonicalWorkshopCompletions(501,'secureshop_agent_security',{expectedGeneration:0}),
    {generation:0,objectiveIds:['ss_loop_observation']});
});
