'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {randomUUID,createHash}=require('node:crypto');
const fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path');
const {migrate}=require('../../db/postgres/migrate');
const {createPool}=require('../../server/database/postgres');
const {initializeIdentityRepository}=require('../../server/database/postgres/identityRepository');
const {seedWorkshopPlatform}=require('../../server/database/postgres/workshopPlatformSeed');
const {createObjectiveJudgmentRepository}=require('../../server/database/postgres/objectiveJudgmentRepository');

const RUNTIME='PG_XSS_JUDGMENT_TEST_RUNTIME_URL',MIGRATION='PG_XSS_JUDGMENT_TEST_MIGRATION_URL';
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&Boolean(process.env[RUNTIME])&&Boolean(process.env[MIGRATION]);
const password='$2b$12$000000000000000000000uG3W0Jp6IPhhD1TRqN8Yc2zJQG3vVnSA';
function owned(value,role){const url=new URL(value);assert.equal(url.hostname,'127.0.0.1');
 assert.match(url.pathname,/^\/owasp_ai_goat_test_xss_judgment_test_[a-z0-9]+$/);assert.equal(decodeURIComponent(url.username),role);}
function result(input,overrides={}){return{family:input.family,scenario:input.scenario,objectiveId:input.objectiveId,
 rubricVersion:input.rubricVersion,evidenceDigest:input.evidenceDigest,runId:input.runId,mode:input.mode,
 verdict:'pass',criteria:[{id:'observed',satisfied:true,evidenceRefs:['receipt']}],explanation:'Observed.',
 provider:'controlled',model:'controlled',judgeVersion:'xss-child-v1',judgePolicyDigest:'d'.repeat(64),
 durationMs:1,attempts:1,errorCode:null,contextTokens:8192,usage:{outputTokens:1},...overrides};}
async function waitForAdvisoryWait(pool,pid){
 const deadline=Date.now()+5000;
 while(Date.now()<deadline){
  const row=(await pool.query(`SELECT wait_event_type,wait_event FROM pg_stat_activity WHERE pid=$1`,[pid])).rows[0];
  if(row?.wait_event_type==='Lock'&&row?.wait_event==='advisory')return;
  await new Promise(resolve=>setImmediate(resolve));
 }
 throw new Error(`Backend ${pid} did not enter the expected advisory wait`);
}

test('native 0073 binds XSS Judge begin, award and retry to exact current child authority',
 {skip:!enabled},async()=>{
  owned(process.env[RUNTIME],'dvaia_identity_runtime');owned(process.env[MIGRATION],'dvaia_identity_migration');
  const runtime=createPool(process.env,RUNTIME),migration=createPool(process.env,MIGRATION),observer=createPool(process.env,RUNTIME);
  const prefix=await fs.mkdtemp(path.join(os.tmpdir(),'owasp-ai-goat-xss-judgment-0072-'));
  try{
   const source=path.join(__dirname,'../../db/postgres/identity-migrations');
   const names=(await fs.readdir(source)).filter(name=>/^\d{4}_.*\.sql$/.test(name)&&Number(name.slice(0,4))<=72).sort();
   assert.equal(names.at(-1),'0072_xss_profile_reset_journal.sql');
   for(const name of names)await fs.copyFile(path.join(source,name),path.join(prefix,name));
   assert.equal((await migrate(migration,prefix)).at(-1),'0072_xss_profile_reset_journal.sql');
   await seedWorkshopPlatform(migration);
   const owner=(await migration.query(`INSERT INTO identity.users(username,email,password)
     VALUES('xss-judgment-owner','xss-judgment-owner@fixture.invalid',$1) RETURNING id`,[password])).rows[0];
   const ownerKey=JSON.stringify(['XSS',String(owner.id)]);
   await migration.query('INSERT INTO graph_runtime.owners(owner_key,generation) VALUES($1,0)',[ownerKey]);
   assert.deepEqual(await initializeIdentityRepository(runtime,migration),['0073_xss_judgment_child_binding.sql']);
   assert.deepEqual(await initializeIdentityRepository(runtime,migration),[],'0073 replays as a no-op');

   // Deterministic absent-row race, ordering A: the unbound judgment admission
   // owns the run key first, so a later scope bind waits and then rejects.
   const raceA=randomUUID(),raceAEvaluation=randomUUID();
   await migration.query(`INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status)
     VALUES($1,$2,0,'running')`,[raceA,ownerKey]);
   const judgmentClient=await runtime.connect(),bindingClient=await runtime.connect();
   try{
    await judgmentClient.query('BEGIN');await bindingClient.query('BEGIN');
    assert.equal((await judgmentClient.query(
      'SELECT identity.assert_xss_run_unscoped_for_judgment($1) admitted',[raceA])).rows[0].admitted,true);
    await judgmentClient.query(`INSERT INTO workshop_platform.objective_judgments
      (user_id,evaluation_id,workshop_key,objective_id,family,scenario,rubric_version,evidence_digest,
       run_id,generation,mode,canonical_mode)
      VALUES($1,$2,'xss_workshop','xss_r1','XSS','race-a','xss-child-v1',$3,$4,0,NULL,NULL)`,
    [owner.id,raceAEvaluation,'a'.repeat(64),raceA]);
    const bindingOutcome=bindingClient.query('SELECT * FROM identity.bind_xss_run_scope($1,$2,$3,$4,0)',
      [raceA,owner.id,ownerKey,'reflected']).then(value=>({value}),error=>({error}));
    await waitForAdvisoryWait(observer,bindingClient.processID);
    await judgmentClient.query('COMMIT');
    assert.equal((await bindingOutcome).error?.code,'55000');await bindingClient.query('ROLLBACK');
    assert.equal((await migration.query('SELECT count(*)::int n FROM identity.xss_run_bindings WHERE run_id=$1',[raceA])).rows[0].n,0);
    assert.equal((await migration.query('SELECT count(*)::int n FROM workshop_platform.objective_judgments WHERE evaluation_id=$1',[raceAEvaluation])).rows[0].n,1);
   }finally{try{await judgmentClient.query('ROLLBACK');}catch{}try{await bindingClient.query('ROLLBACK');}catch{}
    judgmentClient.release();bindingClient.release();}

   // Ordering B: a scope bind owns the same run key first, so unbound admission
   // waits and then rejects after the binding commits.
   const raceB=randomUUID();await migration.query(`INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status)
     VALUES($1,$2,0,'running')`,[raceB,ownerKey]);
   const bindingFirst=await runtime.connect(),judgmentSecond=await runtime.connect();
   try{
    await bindingFirst.query('BEGIN');await judgmentSecond.query('BEGIN');
    await bindingFirst.query('SELECT * FROM identity.bind_xss_run_scope($1,$2,$3,$4,0)',
      [raceB,owner.id,ownerKey,'email']);
    const admissionOutcome=judgmentSecond.query(
      'SELECT identity.assert_xss_run_unscoped_for_judgment($1) admitted',[raceB])
      .then(value=>({value}),error=>({error}));
    await waitForAdvisoryWait(observer,judgmentSecond.processID);
    await bindingFirst.query('COMMIT');
    assert.equal((await admissionOutcome).error?.code,'55000');await judgmentSecond.query('ROLLBACK');
    assert.equal((await migration.query('SELECT count(*)::int n FROM identity.xss_run_bindings WHERE run_id=$1',[raceB])).rows[0].n,1);
    assert.equal((await migration.query('SELECT count(*)::int n FROM workshop_platform.objective_judgments WHERE run_id=$1',[raceB])).rows[0].n,0);
   }finally{try{await bindingFirst.query('ROLLBACK');}catch{}try{await judgmentSecond.query('ROLLBACK');}catch{}
    bindingFirst.release();judgmentSecond.release();}

   const repo=createObjectiveJudgmentRepository(runtime);
   async function admitted(scopeKey){
    const runId=randomUUID();
    await migration.query(`INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status)
      VALUES($1,$2,0,'running')`,[runId,ownerKey]);
    const binding=(await runtime.query(`SELECT run_id AS "runId",owner_id AS "ownerId",owner_key AS "ownerKey",
      scope_key AS "scopeKey",parent_generation::text AS "parentGeneration",
      child_generation::text AS "childGeneration"
      FROM identity.bind_xss_run_scope($1,$2,$3,$4,0)`,[runId,owner.id,ownerKey,scopeKey])).rows[0];
    return Object.freeze({...binding,ownerId:Number(binding.ownerId)});
   }
   const make=(objectiveId,xssScope,overrides={})=>({userId:owner.id,evaluationId:randomUUID(),
    workshopKey:'xss_workshop',objectiveId,family:'XSS',scenario:objectiveId,rubricVersion:'xss-child-v1',
    evidenceDigest:'a'.repeat(64),runId:xssScope.runId,mode:null,expectedGeneration:0,
    expectedMode:null,expectedModeStamp:'default',xssScope,...overrides});

   const awarded=make('xss_s1',await admitted('stored_user'));
   await repo.beginEvaluation(awarded);
   assert.equal((await repo.recordVerdict({userId:owner.id,evaluationId:awarded.evaluationId,
    result:result(awarded)})).disposition,'awarded');

   const staleAward=make('xss_s2',await admitted('stored_user'));
   await repo.beginEvaluation(staleAward);
   await migration.query(`UPDATE identity.xss_scope_state SET child_generation=child_generation+1,
     updated_at=clock_timestamp() WHERE owner_id=$1 AND scope_key='stored_user'`,[owner.id]);
   await assert.rejects(repo.recordVerdict({userId:owner.id,evaluationId:staleAward.evaluationId,
    result:result(staleAward)}),{code:'STALE_GENERATION'});
   assert.equal((await migration.query(`SELECT count(*)::int n FROM workshop_platform.completions
     WHERE user_id=$1 AND workshop_key='xss_workshop' AND objective_id='xss_s2'`,[owner.id])).rows[0].n,0);

   const packet='{}',digest=createHash('sha256').update(packet).digest('hex');
   const currentRetry=make('xss_g2',await admitted('stored_llm'),{evidenceDigest:digest,
    recovery:{packet,judgeVersion:'xss-child-v1',ownerKey,ownerGeneration:'0'}});
   await repo.beginEvaluation(currentRetry);
   await repo.recordVerdict({userId:owner.id,evaluationId:currentRetry.evaluationId,
    result:result(currentRetry,{verdict:'unavailable',criteria:[],errorCode:'JUDGE_TRANSPORT'})});
   const retry=await repo.beginRetry({userId:owner.id,evaluationId:currentRetry.evaluationId,
    judgeVersion:'xss-child-v1',ownerGeneration:'0'});
   assert.notEqual(retry.receipt.evaluationId,currentRetry.evaluationId);
   assert.equal((await repo.recordVerdict({userId:owner.id,evaluationId:retry.receipt.evaluationId,
    result:result(currentRetry)})).disposition,'awarded');
   await migration.query("UPDATE graph_runtime.runs SET status='completed',finished_at=clock_timestamp() WHERE run_id=$1",
    [currentRetry.runId]);
   assert.equal((await repo.beginEvaluation(currentRetry)).verdict,'unavailable',
    'persisted receipt replay does not require the original graph run to remain running');

   const omittedScope=make('xss_s3',await admitted('stored_user'));
   const {xssScope:omitted,...downgraded}=omittedScope;
   await assert.rejects(repo.beginEvaluation(downgraded),{code:'JUDGMENT_SCOPE_MISMATCH'});
   assert.equal(await repo.getEvaluation(downgraded),null,'scoped run cannot create an unbound judgment');

   const retryInput=make('xss_g1',await admitted('stored_llm'),{evidenceDigest:digest,
    recovery:{packet,judgeVersion:'xss-child-v1',ownerKey,ownerGeneration:'0'}});
   await repo.beginEvaluation(retryInput);
   await repo.recordVerdict({userId:owner.id,evaluationId:retryInput.evaluationId,
    result:result(retryInput,{verdict:'unavailable',criteria:[],errorCode:'JUDGE_TRANSPORT'})});
   assert.equal((await repo.listRecoverable({userId:owner.id,judgeVersion:'xss-child-v1'}))
    .find(row=>row.evaluationId===retryInput.evaluationId).canRetry,true);
   await migration.query(`UPDATE identity.xss_scope_state SET child_generation=child_generation+1,
     updated_at=clock_timestamp() WHERE owner_id=$1 AND scope_key='stored_llm'`,[owner.id]);
   assert.equal((await repo.getRecovery({userId:owner.id,evaluationId:retryInput.evaluationId})).xss_binding_current,false);
   assert.equal((await repo.listRecoverable({userId:owner.id,judgeVersion:'xss-child-v1'}))
    .find(row=>row.evaluationId===retryInput.evaluationId).canRetry,false);
   await assert.rejects(repo.beginRetry({userId:owner.id,evaluationId:retryInput.evaluationId,
    judgeVersion:'xss-child-v1',ownerGeneration:'0'}),{code:'STALE_GENERATION'});
   assert.equal((await migration.query(`SELECT child_generation::text generation FROM identity.xss_scope_state
     WHERE owner_id=$1 AND scope_key='stored_user'`,[owner.id])).rows[0].generation,'1','sibling bump is preserved');
   await assert.rejects(runtime.query('SELECT * FROM identity.xss_judgment_bindings'),{code:'42501'});
   assert.equal((await runtime.query('SELECT identity.xss_judgment_binding_is_current($1,$2) current',
    [owner.id,retryInput.evaluationId])).rows[0].current,false);
  }finally{
   const settled=await Promise.allSettled([runtime.end(),migration.end(),observer.end(),fs.rm(prefix,{recursive:true,force:true})]);
   const failures=settled.filter(value=>value.status==='rejected').map(value=>value.reason);
   if(failures.length)throw new AggregateError(failures,'XSS judgment child fixture cleanup failed');
  }
 });
