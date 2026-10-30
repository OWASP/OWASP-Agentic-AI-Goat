'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const express=require('express');
const fs=require('node:fs/promises');
const path=require('node:path');
const {randomUUID}=require('node:crypto');
const {Pool}=require('pg');
const bcrypt=require('bcryptjs');
const {initializeIdentityRepository,createIdentityRepository}=require('../../server/database/postgres/identityRepository');
const {createSecureShopLaunchRepository}=require('../../server/database/postgres/secureshopLaunchRepository');
const {createObjectiveJudgmentRepository}=require('../../server/database/postgres/objectiveJudgmentRepository');
const {createSecureShopProgressCleanupCheckpointRepository,WORKSHOP_KEY}=require('../../server/database/postgres/secureshopProgressCleanupCheckpointRepository');
const {createWorkshopProgressRepository}=require('../../server/database/postgres/workshopProgressRepository');
const {createWorkshopConfigRepository}=require('../../server/database/postgres/workshopConfigRepository');
const {createPostgresAdminRepository}=require('../../server/database/postgres/adminRepository');
const {createPostgresIdentityAdapter}=require('../../server/services/postgresIdentityAdapter');
const {createPostgresAdminAuth}=require('../../server/middleware/postgresAdminAuth');
const {createPostgresAdminRouter}=require('../../server/routes/postgresAdmin');
const {createPostgresWorkshopRouter}=require('../../server/routes/postgresWorkshop');
const PREFIX='PG_SECURESHOP_PROGRESS_CHECKPOINT_TEST';
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&process.env[`${PREFIX}_MIGRATION_URL`]&&process.env[`${PREFIX}_RUNTIME_URL`];
async function apply(pool,relative){await pool.query(await fs.readFile(path.join(__dirname,relative),'utf8'));}
function evaluation(userId,binding,objectiveId){return {userId,evaluationId:randomUUID(),workshopKey:WORKSHOP_KEY,
 objectiveId,family:'SecureShop',scenario:'instance-progress',rubricVersion:'instance-progress-v1',
 evidenceDigest:'a'.repeat(64),runId:randomUUID(),mode:null,instanceScope:binding};}
function verdict(input){return {family:input.family,scenario:input.scenario,objectiveId:input.objectiveId,
 rubricVersion:input.rubricVersion,evidenceDigest:input.evidenceDigest,runId:input.runId,mode:null,
 verdict:'pass',criteria:[{id:'observed',satisfied:true,evidenceRefs:['effect']}],
 explanation:'Observed fixture effect.',provider:'fixture',model:'fixture',usage:null};}

test('native instance retirement preserves sibling objective, activity, time, and mounted HTTP parity',{skip:!enabled,timeout:30000},async()=>{
 const migrationUrl=new URL(process.env[`${PREFIX}_MIGRATION_URL`]);
 const runtimeUrl=new URL(process.env[`${PREFIX}_RUNTIME_URL`]);
 for(const url of [migrationUrl,runtimeUrl]){assert.ok(['127.0.0.1','localhost'].includes(url.hostname));assert.match(url.pathname,/^\/owasp_ai_goat_test_[a-z0-9_]+$/);}
 assert.equal(migrationUrl.pathname,runtimeUrl.pathname);
 const migration=new Pool({connectionString:migrationUrl.href,max:2});
 const runtime=new Pool({connectionString:runtimeUrl.href,max:8});
 let server;
 try{
  await initializeIdentityRepository(runtime,migration);
  await migration.query(`INSERT INTO workshop_platform.exercises
    (workshop_key,challenge_key,challenge_name,ordinal,catalog_active)
    VALUES($1,'secureshop-agent-security','SecureShop Agent Security',900,true)`,[WORKSHOP_KEY]);
  for(const [objectiveId,label,ordinal,visible] of [['shared','Shared',1,true],['only-a','Only A',2,true],
    ['only-b','Only B',3,true],['hidden-b','Hidden B',4,false]]){
   await migration.query(`INSERT INTO workshop_platform.objectives
    (workshop_key,objective_id,label,ordinal,catalog_active,is_enabled) VALUES($1,$2,$3,$4,true,$5)`,
   [WORKSHOP_KEY,objectiveId,label,ordinal,visible]);
  }
  await migration.query(`INSERT INTO workshop_platform.exercises
    (workshop_key,challenge_key,challenge_name,ordinal,catalog_active,is_visible)
    VALUES('secureshop-hidden-fixture','secureshop-hidden-fixture','Hidden SecureShop fixture',901,true,false)`);
  await migration.query(`INSERT INTO workshop_platform.objectives
    (workshop_key,objective_id,label,ordinal,catalog_active,is_enabled)
    VALUES('secureshop-hidden-fixture','hidden-workshop-objective','Hidden workshop objective',1,true,true)`);
  await apply(migration,'../../docs/modernization/drafts/secureshop-instance-objective-contributions.sql');
  await apply(migration,'../../docs/modernization/drafts/secureshop-progress-cleanup-checkpoint.sql');
  const identities=createIdentityRepository(runtime),launches=createSecureShopLaunchRepository(runtime);
  const receipts=createObjectiveJudgmentRepository(runtime),progress=createWorkshopProgressRepository(runtime);
  const config=createWorkshopConfigRepository(runtime);
  const checkpoint=createSecureShopProgressCleanupCheckpointRepository(runtime);
  const passwordHash=await bcrypt.hash('instance-progress-owned',4);
  const user=await identities.createUser({username:`progress-${randomUUID().slice(0,8)}`,
   email:`${randomUUID()}@progress.invalid`,passwordHash});
  const adminPasswordHash=await bcrypt.hash('instance-progress-admin',4);
  const admin=await identities.createUser({username:`progress-admin-${randomUUID().slice(0,8)}`,
   email:`${randomUUID()}@progress.invalid`,passwordHash:adminPasswordHash});
  await migration.query("UPDATE identity.users SET role='super_admin',admin_level=2,email_verified=1 WHERE id=$1",[admin.id]);
  await identities.grantPermission({userId:admin.id,permission:'manage_progress',grantedBy:admin.id});
  const adapter=createPostgresIdentityAdapter({repository:identities,progress,jwtSecret:'owned-progress-http-secret'});
  const userSession=await adapter.createSession(await identities.findCredentialById(user.id),{get:()=>null,ip:'127.0.0.1'});
  const adminSession=await adapter.createSession(await identities.findCredentialById(admin.id),{get:()=>null,ip:'127.0.0.1'});
  const auth=createPostgresAdminAuth(adapter),app=express();
  const unavailable=()=>((_req,res)=>res.status(503).json({error:'Not mounted in this focused qualification'}));
  const operational=new Proxy({},{get:unavailable});
  app.use(express.json());
  app.use('/api/workshop',createPostgresWorkshopRouter({stores:{pool:runtime,progress,config},
   authenticateToken:auth.authenticateToken,resetService:{}}));
  app.use('/api/admin',createPostgresAdminRouter({adapter,stores:{pool:runtime,progress,config},auth,
   repository:createPostgresAdminRepository(runtime),operational,resetService:{}}));
  app.use((error,_req,res,_next)=>res.status(error.statusCode||500).json({error:error.message,code:error.code}));
  server=await new Promise(resolve=>{const value=app.listen(0,'127.0.0.1',()=>resolve(value));});
  const base=`http://127.0.0.1:${server.address().port}`;
  async function request(url,{token=userSession.token}={}){
   const response=await fetch(base+url,{headers:{authorization:`Bearer ${token}`}});
   return {status:response.status,body:await response.json()};
  }
  async function assertHttpParity({completed,time}){
   const [stats,progressResponse,challenges,timeSummary,adminView,adminProgress,adminRows]=await Promise.all([
    request('/api/workshop/student/stats'),request('/api/workshop/progress'),request('/api/workshop/challenges'),
    request('/api/workshop/time/summary'),request(`/api/admin/student-workshop-view/${user.id}`,{token:adminSession.token}),
    request(`/api/admin/students/${user.id}/progress`,{token:adminSession.token}),
    request(`/api/admin/progress?studentId=${user.id}`,{token:adminSession.token})]);
   for(const response of [stats,progressResponse,challenges,timeSummary,adminView,adminProgress,adminRows])assert.equal(response.status,200);
   assert.deepEqual(progressResponse.body.challenges,challenges.body.challenges);
   const rows=challenges.body.challenges;
   assert.ok(!rows.some(row=>row.workshopKey==='secureshop-hidden-fixture'));
   const shop=rows.find(row=>row.workshopKey===WORKSHOP_KEY);assert.ok(shop);
   assert.deepEqual(shop.objectives.map(objective=>objective.id),['shared','only-a','only-b']);
   assert.equal(shop.completedObjectiveCount,completed);assert.equal(shop.timeSpentSeconds,time);
   assert.equal(stats.body.totalObjectives,rows.reduce((sum,row)=>sum+row.objectiveCount,0));
   assert.equal(stats.body.completedObjectives,rows.reduce((sum,row)=>sum+row.completedObjectiveCount,0));
   assert.equal(stats.body.totalTime,rows.reduce((sum,row)=>sum+row.timeSpentSeconds,0));
   assert.deepEqual(timeSummary.body.summary,Object.fromEntries(rows.map(row=>[row.workshopKey,row.timeSpentSeconds])));
   const canonical=row=>({workshopKey:row.workshopKey,objectiveCount:row.objectiveCount,
    completedObjectiveCount:row.completedObjectiveCount,timeSpentSeconds:row.timeSpentSeconds,
    objectives:row.objectives.map(objective=>({id:objective.id,completed:objective.completed}))});
   const expected=canonical(shop);
   for(const values of [adminView.body.challenges,adminView.body.workshops,
     adminProgress.body.progress,adminRows.body.progress]){
    const projected=values.find(row=>row.workshopKey===WORKSHOP_KEY);assert.ok(projected);
    assert.deepEqual(canonical(projected),expected);
    assert.ok(!values.some(row=>row.workshopKey==='secureshop-hidden-fixture'));
   }
   return shop;
  }
  const adminCatalog=await request('/api/admin/challenges',{token:adminSession.token});assert.equal(adminCatalog.status,200);
  assert.ok(adminCatalog.body.challenges.some(row=>row.workshop_key==='secureshop-hidden-fixture'&&row.enabled===false),
   'authorized admin catalog retains the hidden workshop');
  const adminObjectives=await request(`/api/admin/workshops/${WORKSHOP_KEY}/objectives`,{token:adminSession.token});
  assert.equal(adminObjectives.status,200);
  assert.ok(adminObjectives.body.objectives.some(row=>row.objective_id==='hidden-b'&&row.is_enabled===false),
   'authorized admin objective catalog retains the hidden objective');
  async function makeLaunch(){
   const session=await identities.createSession({userId:user.id,token:randomUUID(),
    expiresAt:new Date(Date.now()+3600000).toISOString(),expectedPasswordHash:passwordHash});
   const issued=await launches.issueOrRenew({platformOwnerId:user.id,platformSessionId:session.id,
    expiresAt:new Date(Date.now()+3600000).toISOString()});
   return {...issued.binding,platformOwnerId:user.id,platformSessionId:session.id};
  }
  const a=await makeLaunch(),b=await makeLaunch();
  async function award(binding,objectiveId){const input=evaluation(user.id,binding,objectiveId);
   await receipts.beginEvaluation(input);return receipts.recordVerdict({userId:user.id,evaluationId:input.evaluationId,result:verdict(input)});}
  await award(a,'shared');await award(a,'only-a');await award(b,'shared');await award(b,'only-b');
  const generation=await progress.getGeneration(user.id,WORKSHOP_KEY);
  await progress.recordSecureShopActivity({userId:user.id,activityKey:'agent_turn',activityDelta:2,
   contributionId:randomUUID(),expectedGeneration:generation,instanceScope:a});
  await progress.recordSecureShopActivity({userId:user.id,activityKey:'agent_turn',activityDelta:5,
   contributionId:randomUUID(),expectedGeneration:generation,instanceScope:b});
  await progress.recordHeartbeat({userId:user.id,workshopKey:WORKSHOP_KEY,expectedGeneration:generation,instanceScope:a});
  await migration.query(`UPDATE workshop_platform.time_tracking SET last_heartbeat=last_heartbeat-interval '30 seconds'
    WHERE user_id=$1 AND platform_launch_id=$2`,[user.id,a.launchId]);
  await progress.recordHeartbeat({userId:user.id,workshopKey:WORKSHOP_KEY,expectedGeneration:generation,instanceScope:a});
  await progress.recordHeartbeat({userId:user.id,workshopKey:WORKSHOP_KEY,expectedGeneration:generation,instanceScope:b});
  await migration.query(`UPDATE workshop_platform.time_tracking SET last_heartbeat=last_heartbeat-interval '40 seconds'
    WHERE user_id=$1 AND platform_launch_id=$2`,[user.id,b.launchId]);
  await progress.recordHeartbeat({userId:user.id,workshopKey:WORKSHOP_KEY,expectedGeneration:generation,instanceScope:b});
  await assert.rejects(runtime.query(`INSERT INTO workshop_platform.time_tracking
    (user_id,workshop_key,session_start,last_heartbeat,platform_launch_id,platform_scenario_id,
     platform_launch_generation,workshop_generation) VALUES($1,$2,now(),now(),$3,$4,$5,$6)`,
  [user.id,WORKSHOP_KEY,a.launchId,a.scenarioId,a.generation,generation]),{code:'42501'});
  const protectedTime=(await runtime.query(`SELECT id,duration_seconds FROM workshop_platform.time_tracking
    WHERE user_id=$1 AND workshop_key=$2 AND platform_launch_id=$3 ORDER BY id DESC LIMIT 1`,
  [user.id,WORKSHOP_KEY,a.launchId])).rows[0];
  assert.equal((await runtime.query('UPDATE workshop_platform.time_tracking SET duration_seconds=999 WHERE id=$1',
    [protectedTime.id])).rowCount,0);
  assert.equal((await runtime.query('DELETE FROM workshop_platform.time_tracking WHERE id=$1',
    [protectedTime.id])).rowCount,0);
  assert.equal((await runtime.query('SELECT duration_seconds FROM workshop_platform.time_tracking WHERE id=$1',
    [protectedTime.id])).rows[0].duration_seconds,30);
  await assert.rejects(runtime.query(`INSERT INTO workshop_platform.instance_activity_contributions
    (user_id,contribution_id,workshop_key,activity_key,activity_delta,platform_launch_id,
     platform_scenario_id,platform_launch_generation,workshop_generation)
    VALUES($1,$2,$3,'forged',1,$4,$5,$6,$7)`,
  [user.id,randomUUID(),WORKSHOP_KEY,a.launchId,a.scenarioId,a.generation,generation]),{code:'42501'});
  await assert.rejects(runtime.query(`INSERT INTO workshop_platform.activity_counters
    (user_id,workshop_key,activity_key,activity_count) VALUES($1,$2,'forged',1)`,
  [user.id,WORKSHOP_KEY]),{code:'42501'});
  await assert.rejects(runtime.query(`SELECT * FROM workshop_platform.record_secureshop_activity_contribution(
    $1,$2,'forged',1,$3,$4,$5,$6)`,
  [user.id,randomUUID(),a.launchId,randomUUID(),a.generation,generation]),/launch is stale/);
  await assert.rejects(runtime.query(`SELECT * FROM workshop_platform.record_secureshop_heartbeat(
    $1,$2,$3,$4,$5)`,[user.id,a.launchId,randomUUID(),a.generation,generation]),
  /launch is stale/);
  await Promise.all(Array.from({length:20},()=>runtime.query(`SELECT * FROM
    workshop_platform.record_secureshop_activity_contribution($1,$2,'race_activity',1,$3,$4,$5,$6)`,
  [user.id,randomUUID(),b.launchId,b.scenarioId,b.generation,generation])));
  assert.equal((await runtime.query(`SELECT activity_count FROM workshop_platform.activity_counters
    WHERE user_id=$1 AND workshop_key=$2 AND activity_key='race_activity'`,
  [user.id,WORKSHOP_KEY])).rows[0].activity_count,20);
  await assert.rejects(progress.recordHeartbeat({userId:user.id,workshopKey:WORKSHOP_KEY}),
   {code:'INSTANCE_SCOPE_REQUIRED'});
  await assert.rejects(progress.recordSecureShopActivity({userId:user.id,activityKey:'agent_turn'}),
   {code:'INSTANCE_SCOPE_REQUIRED'});
  await assert.rejects(progress.syncObjectiveComplete(user.id,WORKSHOP_KEY,'only-a'),
   {code:'INSTANCE_SCOPE_REQUIRED'});
  await assert.rejects(progress.resetWorkshopProgress(user.id,WORKSHOP_KEY),
   {code:'INSTANCE_SCOPE_REQUIRED'});

  const reset=await launches.beginReset({launchId:a.launchId,platformOwnerId:user.id,
   platformSessionId:a.platformSessionId,expectedGeneration:a.generation,idempotencyKey:'retire-instance-a'});
  const first=await checkpoint.finalize(reset.resetId);
  assert.equal(first.replayed,false);assert.equal(first.checkpoint.workshopGeneration,generation);
  assert.deepEqual({objectives:first.checkpoint.retiredObjectiveContributionCount,
   activity:first.checkpoint.retiredActivityContributionCount,time:first.checkpoint.retiredTimeSeconds},
  {objectives:2,activity:1,time:'30'});
  assert.equal(await progress.getGeneration(user.id,WORKSHOP_KEY),generation,'instance reset must preserve shared generation');
  assert.deepEqual((await progress.getCanonicalWorkshopCompletions(user.id,WORKSHOP_KEY,
   {expectedGeneration:generation})).objectiveIds,['only-b','shared']);
  const sharedTimes=(await runtime.query(`SELECT c.completed_at,min(s.accepted_at) AS expected
    FROM workshop_platform.completions c JOIN workshop_platform.objective_contributions s
      ON s.user_id=c.user_id AND s.workshop_key=c.workshop_key AND s.objective_id=c.objective_id
    WHERE c.user_id=$1 AND c.workshop_key=$2 AND c.objective_id='shared'
      AND s.platform_launch_id=$3 GROUP BY c.completed_at`,[user.id,WORKSHOP_KEY,b.launchId])).rows[0];
  assert.equal(sharedTimes.completed_at.toISOString(),sharedTimes.expected.toISOString(),
    'canonical completion time comes from the earliest surviving contribution');
  let row=(await runtime.query(`SELECT activity_count FROM workshop_platform.activity_counters
   WHERE user_id=$1 AND workshop_key=$2 AND activity_key='agent_turn'`,[user.id,WORKSHOP_KEY])).rows[0];
  assert.equal(row.activity_count,5);
  assert.equal((await progress.getWorkshopProgress(user.id,WORKSHOP_KEY)).timeSpentSeconds,40);
  const afterA=await assertHttpParity({completed:2,time:40});
  assert.deepEqual(afterA.objectives.filter(objective=>objective.completed).map(objective=>objective.id),['shared','only-b']);
  assert.equal((await runtime.query(`SELECT count(*)::integer AS count FROM workshop_platform.objective_contributions
   WHERE user_id=$1`,[user.id])).rows[0].count,4,'retirement preserves immutable objective history');
  await launches.commitReset({resetId:reset.resetId,launchId:a.launchId,platformOwnerId:user.id,
   platformSessionId:a.platformSessionId,expectedGeneration:reset.toGeneration});

  await progress.recordSecureShopActivity({userId:user.id,activityKey:'agent_turn',activityDelta:3,
   contributionId:randomUUID(),expectedGeneration:generation,instanceScope:b});
  await migration.query(`UPDATE workshop_platform.time_tracking SET last_heartbeat=last_heartbeat-interval '10 seconds'
    WHERE user_id=$1 AND platform_launch_id=$2`,[user.id,b.launchId]);
  await progress.recordHeartbeat({userId:user.id,workshopKey:WORKSHOP_KEY,
   expectedGeneration:generation,instanceScope:b});
  const replay=await checkpoint.finalize(reset.resetId);
  assert.equal(replay.replayed,true);
  row=(await runtime.query(`SELECT activity_count FROM workshop_platform.activity_counters
   WHERE user_id=$1 AND workshop_key=$2 AND activity_key='agent_turn'`,[user.id,WORKSHOP_KEY])).rows[0];
  assert.equal(row.activity_count,8,'replay validates the current sibling projection');
  assert.equal((await progress.getWorkshopProgress(user.id,WORKSHOP_KEY)).timeSpentSeconds,50);
  await assertHttpParity({completed:2,time:50});
  assert.equal((await runtime.query(`SELECT count(*)::integer AS count FROM identity.secureshop_progress_cleanup_history
   WHERE reset_id=$1`,[reset.resetId])).rows[0].count,1);
  await assert.rejects(runtime.query(`INSERT INTO identity.secureshop_progress_cleanup_history
    (reset_id,launch_id,scenario_id,from_launch_generation,original_platform_owner_id,
     original_platform_session_id,workshop_key,workshop_generation,
     retired_objective_contribution_count,retired_activity_contribution_count,
     retired_time_entry_count,retired_time_seconds,projected_completion_count,
     projected_activity_count,projected_time_entry_count,projected_time_seconds)
    SELECT reset_id,launch_id,scenario_id,from_launch_generation,original_platform_owner_id,
     original_platform_session_id,workshop_key,workshop_generation,
     retired_objective_contribution_count,retired_activity_contribution_count,
     retired_time_entry_count,retired_time_seconds,projected_completion_count,
     projected_activity_count,projected_time_entry_count,projected_time_seconds
    FROM identity.secureshop_progress_cleanup_history WHERE reset_id=$1`,[reset.resetId]),{code:'42501'});
  const beforeRejected=(await runtime.query(`SELECT
    (SELECT count(*)::integer FROM workshop_platform.instance_activity_contributions WHERE user_id=$1) AS activity,
    (SELECT count(*)::integer FROM workshop_platform.time_tracking WHERE user_id=$1 AND workshop_key=$2) AS time`,
  [user.id,WORKSHOP_KEY])).rows[0];
  await migration.query("UPDATE identity.users SET account_locked_until=clock_timestamp()+interval '1 hour' WHERE id=$1",[user.id]);
  await assert.rejects(progress.recordSecureShopActivity({userId:user.id,activityKey:'locked',
    contributionId:randomUUID(),expectedGeneration:generation,instanceScope:b}),{code:'STALE_GENERATION'});
  await migration.query('UPDATE identity.users SET account_locked_until=NULL WHERE id=$1',[user.id]);
  const expired=await makeLaunch();
  await migration.query("UPDATE identity.user_sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1",[expired.platformSessionId]);
  await assert.rejects(progress.recordHeartbeat({userId:user.id,workshopKey:WORKSHOP_KEY,
    expectedGeneration:generation,instanceScope:expired}),{code:'STALE_GENERATION'});
  const inactive=await makeLaunch();
  await migration.query('UPDATE identity.user_sessions SET is_active=0 WHERE id=$1',[inactive.platformSessionId]);
  await assert.rejects(progress.recordSecureShopActivity({userId:user.id,activityKey:'inactive-session',
    contributionId:randomUUID(),expectedGeneration:generation,instanceScope:inactive}),{code:'STALE_GENERATION'});
  await assert.rejects(progress.recordSecureShopActivity({userId:user.id,activityKey:'wrong-session',
    contributionId:randomUUID(),expectedGeneration:generation,
    instanceScope:{...b,platformSessionId:a.platformSessionId}}),{code:'STALE_GENERATION'});
  const inactiveHash=await bcrypt.hash('inactive-progress-owner',4);
  const inactiveOwner=await identities.createUser({username:`inactive-${randomUUID().slice(0,8)}`,
    email:`${randomUUID()}@progress.invalid`,passwordHash:inactiveHash});
  const inactiveSession=await identities.createSession({userId:inactiveOwner.id,token:randomUUID(),
    expiresAt:new Date(Date.now()+3600000).toISOString(),expectedPasswordHash:inactiveHash});
  const inactiveLaunch=await launches.issueOrRenew({platformOwnerId:inactiveOwner.id,
    platformSessionId:inactiveSession.id,expiresAt:new Date(Date.now()+3600000).toISOString()});
  await migration.query('UPDATE identity.users SET is_active=0 WHERE id=$1',[inactiveOwner.id]);
  await assert.rejects(progress.recordSecureShopActivity({userId:inactiveOwner.id,activityKey:'inactive-owner',
    contributionId:randomUUID(),expectedGeneration:0,instanceScope:{...inactiveLaunch.binding,
      platformOwnerId:inactiveOwner.id,platformSessionId:inactiveSession.id}}),{code:'STALE_GENERATION'});
  assert.deepEqual((await runtime.query(`SELECT
    (SELECT count(*)::integer FROM workshop_platform.instance_activity_contributions WHERE user_id=$1) AS activity,
    (SELECT count(*)::integer FROM workshop_platform.time_tracking WHERE user_id=$1 AND workshop_key=$2) AS time`,
  [user.id,WORKSHOP_KEY])).rows[0],beforeRejected,'rejected authority cannot create progress sources');

  const finalReset=await launches.beginReset({launchId:b.launchId,platformOwnerId:user.id,
    platformSessionId:b.platformSessionId,expectedGeneration:b.generation,idempotencyKey:'retire-instance-b'});
  await checkpoint.finalize(finalReset.resetId);
  assert.deepEqual((await progress.getCanonicalWorkshopCompletions(user.id,WORKSHOP_KEY,
    {expectedGeneration:generation})).objectiveIds,[]);
  assert.deepEqual((await runtime.query(`SELECT generation,started_at,
    (SELECT count(*)::integer FROM workshop_platform.activity_counters a
      WHERE a.user_id=s.user_id AND a.workshop_key=s.workshop_key) AS activity
    FROM workshop_platform.user_state s WHERE user_id=$1 AND workshop_key=$2`,
  [user.id,WORKSHOP_KEY])).rows[0],{generation,started_at:null,activity:0});
  assert.equal((await progress.getWorkshopProgress(user.id,WORKSHOP_KEY)).timeSpentSeconds,0);
  const afterB=await assertHttpParity({completed:0,time:0});
  assert.ok(afterB.objectives.every(objective=>objective.completed===false));

  // With the owner row held, finalize must wait before taking the launch lock.
  // The opposite order deadlocks against identity deletion's owner->launch path.
  const zeroHash=await bcrypt.hash('zero-progress-owner',4);
  const zero=await identities.createUser({username:`zero-${randomUUID().slice(0,8)}`,
    email:`${randomUUID()}@progress.invalid`,passwordHash:zeroHash});
  const zeroSession=await identities.createSession({userId:zero.id,token:randomUUID(),
    expiresAt:new Date(Date.now()+3600000).toISOString(),expectedPasswordHash:zeroHash});
  const zeroLaunch=await launches.issueOrRenew({platformOwnerId:zero.id,platformSessionId:zeroSession.id,
    expiresAt:new Date(Date.now()+3600000).toISOString()});
  const zeroReset=await launches.beginReset({launchId:zeroLaunch.binding.launchId,platformOwnerId:zero.id,
    platformSessionId:zeroSession.id,expectedGeneration:1,idempotencyKey:'zero-progress-lock-order'});
  const blocker=await runtime.connect();
  try{
    await blocker.query('BEGIN');
    await blocker.query('SELECT id FROM identity.users WHERE id=$1 FOR UPDATE',[zero.id]);
    const pending=checkpoint.finalize(zeroReset.resetId);
    await new Promise(resolve=>setTimeout(resolve,40));
    await blocker.query('SELECT launch_id FROM identity.secureshop_launches WHERE launch_id=$1 FOR UPDATE NOWAIT',
      [zeroLaunch.binding.launchId]);
    await blocker.query('ROLLBACK');
    assert.equal((await pending).replayed,false);
  }finally{await blocker.query('ROLLBACK').catch(()=>{});blocker.release();}
  await assert.rejects(runtime.query(`UPDATE identity.secureshop_progress_cleanup_history
    SET projected_completion_count=0 WHERE reset_id=$1`,[reset.resetId]),{code:'42501'});
 }finally{if(server)await new Promise(resolve=>server.close(resolve));await Promise.allSettled([runtime.end(),migration.end()]);}
});
