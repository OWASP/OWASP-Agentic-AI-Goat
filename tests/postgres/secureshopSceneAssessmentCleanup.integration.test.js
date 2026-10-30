'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const fsp=require('node:fs/promises');
const path=require('node:path');
const {randomUUID,createHash}=require('node:crypto');
const {Module,createRequire}=require('node:module');
const {Pool}=require('pg');
const {migrate}=require('../../db/postgres/migrate');

const PREFIX='PG_SECURESHOP_SCENE_ASSESSMENT_';
const KEYS=['IDENTITY_RUNTIME_URL','IDENTITY_MIGRATION_URL'];
const ENABLED=process.env.SECURESHOP_SCENE_ASSESSMENT_NATIVE==='1'
 &&process.env.PG_TEST_DISPOSABLE==='yes'&&KEYS.every(k=>process.env[PREFIX+k]);
const DIRECTORY=path.resolve(__dirname,'../../db/postgres/identity-migrations');
const V03='ss_listing_image_command_execution';
const V03_RUBRIC='secureshop-listings-optimize-v1';
async function waitFor(check,{timeoutMs=3000,intervalMs=20}={}){const deadline=Date.now()+timeoutMs;
 while(Date.now()<deadline){if(await check())return;await new Promise(resolve=>setTimeout(resolve,intervalMs));}
 throw new Error('Timed out waiting for bounded native concurrency state');}
function disposableUrl(key){const u=new URL(process.env[PREFIX+key]);assert.equal(u.protocol,'postgresql:');
 assert.equal(u.hostname,'127.0.0.1');assert.match(u.pathname,/^\/owasp_ai_goat_test_[a-z0-9_]+$/);
 assert.equal(u.password,'');assert.equal(u.search,'');assert.equal(u.hash,'');return u.href;}
function historicalMigrator(ceiling){const filename=require.resolve('../../db/postgres/migrate');
 const local=createRequire(filename),original=require('node:fs/promises');
 const virtual={...original,async readdir(target,...args){const names=await original.readdir(target,...args);
  return path.resolve(target)===DIRECTORY?names.filter(n=>!/^\d{4}_/.test(n)||Number(n.slice(0,4))<=ceiling):names;}};
 const loaded=new Module(filename,module);loaded.filename=filename;
 loaded.require=n=>n==='node:fs/promises'?virtual:local(n);loaded._compile(fs.readFileSync(filename,'utf8'),filename);
 return loaded.exports.migrate;}
const count=(pool,sql,args=[])=>pool.query(sql,args).then(r=>Number(r.rows[0].n));
function packet(binding,scene){const audit={id:'listing_optimize_audit',source:'server_observation',content:{
 version:V03_RUBRIC,raw:{binding:{scope:binding.scope,persona:{id:binding.shopUserId,role:'merchant'},
  targetId:scene.targetId,mode:'vuln'},request:{version:1,action:'optimize',sceneId:scene.sceneId,
   sceneGeneration:1,grantId:scene.grantId},sourceSetup:{version:1,kind:'listing_optimize_setup',action:'optimize',
   scene:{sceneId:scene.sceneId,sceneGeneration:1,grantId:scene.grantId,targetId:scene.targetId}}}}};
 return JSON.stringify({rubric:{family:'SecureShop',scenario:'bound_listings_image_optimize',objectiveId:V03,
  version:V03_RUBRIC,mode:'vuln'},evidence:[audit],facts:{}});}
function result(){return {verdict:'pass',provider:'controlled-native-fixture',model:'none',
 explanation:'Migration projection only; no model or credit qualification.'};}

test('scene reset retires exact V03 scene contributions and preserves immutable evidence and unrelated progress',
 {skip:!ENABLED,timeout:120000},async t=>{
  assert.equal(path.resolve(process.env.OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE||'/'),process.cwd());
  const migration=new Pool({connectionString:disposableUrl('IDENTITY_MIGRATION_URL'),max:2});
  const runtime=new Pool({connectionString:disposableUrl('IDENTITY_RUNTIME_URL'),max:8});
  t.after(async()=>{const ended=await Promise.allSettled([migration.end(),runtime.end()]);
   assert.equal(ended.filter(x=>x.status==='rejected').length,0);});
  assert.deepEqual((await historicalMigrator(151)(migration,DIRECTORY)).at(-1),'0151_secureshop_files_principal_admission.sql');
  const sql=await fsp.readFile(path.join(DIRECTORY,'0152_secureshop_scene_assessment_cleanup.sql'),'utf8');
  const fresh=await migration.connect();
  try{await fresh.query('BEGIN');await fresh.query(sql);
   assert.equal(await count(fresh,'SELECT count(*)::int n FROM secureshop_auth.assessment_scene_bindings'),0);
   assert.equal(await count(fresh,'SELECT count(*)::int n FROM secureshop_auth.assessment_scene_cleanup_history'),0);
   await fresh.query('ROLLBACK');}catch(error){await fresh.query('ROLLBACK').catch(()=>{});throw error;}finally{fresh.release();}

  await require('../../server/database/postgres/secureshopStandaloneSeed').seedSecureShopStandaloneDefaults(migration);
  await require('../../server/database/postgres/secureshopAssessmentSeed').seedSecureShopAssessmentDefaults(migration);
  const auth=require('../../server/services/secureshopStandaloneAuth').createSecureShopStandaloneAuthService({repository:
   require('../../server/database/postgres/secureshopStandaloneAuthRepository').createSecureShopStandaloneAuthRepository({pool:runtime})});
  const adminLogin=await auth.login({username:'student_admin',password:'student123'});
  const merchantLogin=await auth.login({username:'student_merchant',password:'student123'});
  const otherLogin=await auth.register({username:`merchant_${randomUUID().slice(0,8)}`,
   email:`${randomUUID()}@scene-assessment.invalid`,password:'disposable-scene-assessment',role:'merchant'});
  const admin=await auth.establishTenantContext(adminLogin.context);
  const merchant=await auth.establishTenantContext(merchantLogin.context);
  const other=await auth.establishTenantContext(otherLogin.context);
  assert.equal(admin.tenantId,merchant.tenantId);assert.equal(other.tenantId,merchant.tenantId);
  assert.notEqual(admin.principalId,merchant.principalId);assert.notEqual(other.principalId,merchant.principalId);
  const launches=require('../../server/database/postgres/secureshopLaunchRepository').createSecureShopLaunchRepository(runtime);
  async function execution(context){const issued=await launches.issueOrRenew({platformOwnerId:context.ownerId,
   platformSessionId:context.sessionId,expiresAt:new Date(Date.now()+1800000),shopPrincipal:context});
   return {context,scope:require('../../server/services/secureshopConversationBinding').createLaunchScope(issued.binding)};}
  const adminRun=await execution(admin),merchantRun=await execution(merchant),otherRun=await execution(other);
  async function makeScene(run){const reserved=await launches.reserveProductsTarget({...run.scope,
   expectedGeneration:run.scope.generation});const scene={sceneId:randomUUID(),grantId:randomUUID(),targetId:reserved.targetId};
   await migration.query(`INSERT INTO identity.secureshop_scenes
    (scene_id,original_platform_owner_id,product_target_id,birth_launch_id,birth_scenario_id,
     birth_generation,birth_platform_session_id)
    VALUES($1,$2,$3,$4,$5,$6,$7)`,[scene.sceneId,run.scope.platformOwnerId,scene.targetId,
     run.scope.launchId,run.scope.scenarioId,run.scope.generation,run.scope.platformSessionId]);
   await migration.query(`INSERT INTO identity.secureshop_scene_execution_grants
    (grant_id,scene_id,scene_generation,launch_id,scenario_id,generation,
     original_platform_owner_id,original_platform_session_id)
    VALUES($1,$2,1,$3,$4,$5,$6,$7)`,[scene.grantId,scene.sceneId,run.scope.launchId,
     run.scope.scenarioId,run.scope.generation,run.scope.platformOwnerId,run.scope.platformSessionId]);
   return scene;}
  async function grant(scene,run){const grantId=randomUUID();await migration.query(`INSERT INTO identity.secureshop_scene_execution_grants
    (grant_id,scene_id,scene_generation,launch_id,scenario_id,generation,
     original_platform_owner_id,original_platform_session_id)
    VALUES($1,$2,1,$3,$4,$5,$6,$7)`,[grantId,scene.sceneId,run.scope.launchId,run.scope.scenarioId,
     run.scope.generation,run.scope.platformOwnerId,run.scope.platformSessionId]);return grantId;}
  const shared=await makeScene(merchantRun);shared.adminGrantId=await grant(shared,adminRun);
  const unrelated=await makeScene(otherRun);
  function binding(run){return {scope:run.scope,shopUserId:run.context.shopUserId,runId:randomUUID(),
   ownerKey:`scene-assessment:${randomUUID()}`,ownerGeneration:'0'};}
  async function insertJudgment(run,scene,{objective=V03,rubric=V03_RUBRIC,withContribution=true,withCompletion=true}={}){
   const id=randomUUID(),b=binding(run),encoded=JSON.stringify(result()),document=objective===V03?packet(b,scene):null;
   await migration.query(`INSERT INTO secureshop_auth.assessment_judgments
    (tenant_id,principal_id,evaluation_id,shop_user_id,execution_json,objective_id,family,scenario,
     rubric_version,evidence_digest,run_id,generation,mode,mode_stamp,packet,judge_version,owner_key,
     owner_generation,verdict,disposition,result_json,result_digest,evaluated_at)
    VALUES($1,$2,$3,$4,$5::jsonb,$6,'SecureShop',$7,$8,$9,$10,0,'vuln',$11,$12,$13,$14,0,
     'pass','awarded',$15::jsonb,$16,clock_timestamp())`,[run.context.tenantId,run.context.principalId,id,
      run.context.shopUserId,JSON.stringify(b),objective,objective===V03?'bound_listings_image_optimize':'assessment_adapter',
      rubric,createHash('sha256').update(document||objective).digest('hex'),b.runId,
      createHash('sha256').update(`mode:${id}`).digest('hex'),document,'objective-judge-v5',b.ownerKey,encoded,
      createHash('sha256').update(encoded).digest('hex')]);
   if(withCompletion)await migration.query(`INSERT INTO secureshop_auth.assessment_completions
    (tenant_id,principal_id,objective_id,generation,evaluation_id) VALUES($1,$2,$3,0,$4) ON CONFLICT DO NOTHING`,
    [run.context.tenantId,run.context.principalId,objective,id]);
   if(withContribution)await migration.query(`INSERT INTO secureshop_auth.assessment_contributions
    (tenant_id,principal_id,evaluation_id) VALUES($1,$2,$3)`,[run.context.tenantId,run.context.principalId,id]);
   return {id,b,document};}
  async function insertUnavailable(source,badPacket){
   const id=randomUUID(),value={verdict:'unavailable',provider:null,model:null,errorCode:'MODEL_UNAVAILABLE',
    explanation:'Retained unavailable fixture; no positive contribution.'},encoded=JSON.stringify(value);
   await migration.query(`INSERT INTO secureshop_auth.assessment_judgments
    (tenant_id,principal_id,evaluation_id,shop_user_id,execution_json,objective_id,family,scenario,
     rubric_version,evidence_digest,run_id,generation,mode,mode_stamp,packet,judge_version,owner_key,
     owner_generation,verdict,disposition,result_json,result_digest,evaluated_at)
    SELECT tenant_id,principal_id,$2,shop_user_id,execution_json,objective_id,family,scenario,
     rubric_version,$3,$4,generation,mode,mode_stamp,$5,judge_version,$6,owner_generation,
     'unavailable','not_pass',$7::jsonb,$8,clock_timestamp()
    FROM secureshop_auth.assessment_judgments WHERE evaluation_id=$1`,[source.id,id,
     createHash('sha256').update(badPacket).digest('hex'),randomUUID(),badPacket,`unavailable:${id}`,
     encoded,createHash('sha256').update(encoded).digest('hex')]);return id;}
  const retired=await insertJudgment(merchantRun,shared);
  const late=await insertJudgment(merchantRun,shared,{withContribution:false,withCompletion:false});
  const survivor=await insertJudgment(otherRun,unrelated);
  const nonScene=await insertJudgment(merchantRun,null,{objective:'ss_loop_observation',rubric:'assessment-adapter-v1'});
  const malformed=late.document.replace(shared.grantId,unrelated.grantId);
  const historicalUnavailable=await insertUnavailable(late,malformed);
  const historicalNonArrays=await Promise.all([
   insertUnavailable(late,JSON.stringify({evidence:null})),
   insertUnavailable(late,JSON.stringify({evidence:{unexpected:true}})),
   insertUnavailable(late,JSON.stringify({evidence:'scalar'}))]);

  const populated=await migration.connect();
  try{await populated.query('BEGIN');await populated.query(sql);
   assert.equal(await count(populated,'SELECT count(*)::int n FROM secureshop_auth.assessment_scene_bindings'),3);
   assert.equal(await count(populated,'SELECT count(*)::int n FROM secureshop_auth.active_assessment_contributions'),3);
   await populated.query('ROLLBACK');}catch(error){await populated.query('ROLLBACK').catch(()=>{});throw error;}finally{populated.release();}
  assert.deepEqual(await migrate(migration,DIRECTORY),['0152_secureshop_scene_assessment_cleanup.sql']);
  assert.deepEqual(await migrate(migration,DIRECTORY),[]);
  assert.equal(await count(runtime,'SELECT count(*)::int n FROM secureshop_auth.assessment_scene_bindings'),3);
  assert.equal(await count(runtime,`SELECT count(*)::int n FROM secureshop_auth.assessment_scene_bindings
   WHERE authority_kind='v03-packet-scene-grant-v1'`),3);
  assert.equal(await count(runtime,`SELECT count(*)::int n FROM secureshop_auth.assessment_scene_bindings
   WHERE evaluation_id=$1`,[historicalUnavailable]),0);
  for(const evaluationId of historicalNonArrays)assert.equal(await count(runtime,`SELECT count(*)::int n
   FROM secureshop_auth.assessment_scene_bindings WHERE evaluation_id=$1`,[evaluationId]),0);
  const freshUnavailable=await insertUnavailable(late,malformed);
  assert.equal(await count(runtime,`SELECT count(*)::int n FROM secureshop_auth.assessment_scene_bindings
   WHERE evaluation_id=$1`,[freshUnavailable]),0);
  await assert.rejects(migration.query(`INSERT INTO secureshop_auth.assessment_contributions
    (tenant_id,principal_id,evaluation_id) VALUES($1,$2,$3)`,
   [merchant.tenantId,merchant.principalId,freshUnavailable]),{code:'55000'});

  const immutableBefore={judgments:(await runtime.query(`SELECT * FROM secureshop_auth.assessment_judgments ORDER BY evaluation_id`)).rows,
   completions:(await runtime.query(`SELECT * FROM secureshop_auth.assessment_completions ORDER BY evaluation_id`)).rows,
   contributions:(await runtime.query(`SELECT * FROM secureshop_auth.assessment_contributions ORDER BY evaluation_id`)).rows};
  const reset=await launches.beginReset({launchId:adminRun.scope.launchId,
   platformOwnerId:adminRun.scope.platformOwnerId,platformSessionId:adminRun.scope.platformSessionId,
   expectedGeneration:adminRun.scope.generation,idempotencyKey:`scene-assessment-${randomUUID()}`});
  assert.equal((await runtime.query('SELECT status FROM identity.secureshop_scenes WHERE scene_id=$1',[shared.sceneId])).rows[0].status,'retired');
  assert.equal((await runtime.query('SELECT status FROM identity.secureshop_scenes WHERE scene_id=$1',[unrelated.sceneId])).rows[0].status,'active');
  const checkpoint=require('../../server/database/postgres/secureshopRealmProgressCleanupCheckpointRepository')
   .createSecureShopRealmProgressCleanupCheckpointRepository(runtime);
  // Hold the cleanup transaction after its trigger has acquired the scene
  // advisory lock. A concurrent contribution must physically wait, then reject
  // after the authoritative retirement commits; it can never arrive late.
  const cleanupClient=await runtime.connect(),blockedClient=await runtime.connect();
  let first,blockedResult;
  try{
   await cleanupClient.query('BEGIN');
   await cleanupClient.query("SET LOCAL statement_timeout='10000ms'");
   first=await require('../../server/database/postgres/secureshopRealmProgressCleanupCheckpointRepository')
    .createSecureShopRealmProgressCleanupCheckpointRepository(cleanupClient).finalize(reset.resetId);
   await blockedClient.query('BEGIN');
   await blockedClient.query("SET LOCAL statement_timeout='10000ms'");
   const blockerPid=Number((await blockedClient.query('SELECT pg_backend_pid() AS pid')).rows[0].pid);
   const blocked=blockedClient.query(`INSERT INTO secureshop_auth.assessment_contributions
    (tenant_id,principal_id,evaluation_id) VALUES($1,$2,$3)`,
    [merchant.tenantId,merchant.principalId,late.id]).then(value=>({value}),error=>({error}));
   await waitFor(async()=>{const row=(await runtime.query(`SELECT wait_event_type,wait_event
     FROM pg_stat_activity WHERE pid=$1`,[blockerPid])).rows[0];
    return row?.wait_event_type==='Lock'&&row?.wait_event==='advisory';});
   await cleanupClient.query('COMMIT');
   blockedResult=await blocked;
   assert.equal(blockedResult.error?.code,'55000');
   await blockedClient.query('ROLLBACK');
  }finally{
   await cleanupClient.query('ROLLBACK').catch(()=>{});cleanupClient.release();
   await blockedClient.query('ROLLBACK').catch(()=>{});blockedClient.release();
  }
  const replayed=await checkpoint.finalize(reset.resetId);
  assert.deepEqual(replayed,first);
  assert.equal(first.realm,'shop');
  assert.deepEqual((await runtime.query(`SELECT scene_id,target_id,retiring_launch_id,from_generation::int,
    to_generation::int,retired_judgment_count,retired_contribution_count,projected_completion_count
    FROM secureshop_auth.assessment_scene_cleanup_history WHERE reset_id=$1`,[reset.resetId])).rows,[{
     scene_id:shared.sceneId,target_id:shared.targetId,retiring_launch_id:adminRun.scope.launchId,
     from_generation:1,to_generation:2,retired_judgment_count:2,retired_contribution_count:1,
     projected_completion_count:1}]);
  const active=id=>count(runtime,'SELECT count(*)::int n FROM secureshop_auth.active_assessment_contributions WHERE evaluation_id=$1',[id]);
  assert.equal(await active(retired.id),0);assert.equal(await active(survivor.id),1);assert.equal(await active(nonScene.id),1);
  assert.deepEqual((await runtime.query(`SELECT * FROM secureshop_auth.assessment_judgments ORDER BY evaluation_id`)).rows,immutableBefore.judgments);
  assert.deepEqual((await runtime.query(`SELECT * FROM secureshop_auth.assessment_completions ORDER BY evaluation_id`)).rows,immutableBefore.completions);
  assert.deepEqual((await runtime.query(`SELECT * FROM secureshop_auth.assessment_contributions ORDER BY evaluation_id`)).rows,immutableBefore.contributions);
  await assert.rejects(migration.query(`INSERT INTO secureshop_auth.assessment_contributions
    (tenant_id,principal_id,evaluation_id) VALUES($1,$2,$3)`,[merchant.tenantId,merchant.principalId,late.id]),{code:'55000'});
  assert.equal(await count(runtime,'SELECT count(*)::int n FROM secureshop_auth.assessment_contributions WHERE evaluation_id=$1',[late.id]),0);
 });
