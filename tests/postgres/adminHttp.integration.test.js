'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const express=require('express');
const bcrypt=require('bcryptjs');
const {createPool}=require('../../server/database/postgres');
const {initializeIdentityRepository,createIdentityRepository}=require('../../server/database/postgres/identityRepository');
const {createWorkshopProgressRepository}=require('../../server/database/postgres/workshopProgressRepository');
const {createWorkshopConfigRepository}=require('../../server/database/postgres/workshopConfigRepository');
const {createPostgresAdminRepository}=require('../../server/database/postgres/adminRepository');
const {seedWorkshopPlatform}=require('../../server/database/postgres/workshopPlatformSeed');
const {createPostgresIdentityAdapter}=require('../../server/services/postgresIdentityAdapter');
const {createPostgresAdminAuth}=require('../../server/middleware/postgresAdminAuth');
const {createPostgresAuthRouter}=require('../../server/routes/postgresAuth');
const {createPostgresAdminRouter}=require('../../server/routes/postgresAdmin');
const {createPostgresWorkshopRouter}=require('../../server/routes/postgresWorkshop');
const {createPostgresHintsRouter,createPostgresSolutionsRouter}=require('../../server/routes/postgresWorkshopContent');
const {projectWorkshopChallenges}=require('../../server/services/workshopChallengeProjection');
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&Boolean(process.env.PG_ADMIN_TEST_MIGRATION_URL);
function sqlBarrierPool(basePool, predicate, {pauseAfterResolve=false}={}) {
 let issuedResolve,acquiredResolve,acquiredReject,releaseResolve,matched=false;
 const issued=new Promise(resolve=>{issuedResolve=resolve;}),acquired=new Promise((resolve,reject)=>{acquiredResolve=resolve;acquiredReject=reject;});
 const releasePromise=new Promise(resolve=>{releaseResolve=resolve;});
 return {
  issued,acquired,release:()=>releaseResolve(),
  pool:{
   query:(...args)=>basePool.query(...args),
   async connect(){
    const client=await basePool.connect();
    return new Proxy(client,{get(target,key){
     if(key==='query')return async(...args)=>{
      const sql=typeof args[0]==='string'?args[0]:args[0]?.text;
      if(!matched&&predicate(String(sql||'').replace(/\s+/g,' ').trim())){
       matched=true;issuedResolve();
       try{
        const result=await target.query(...args);acquiredResolve();
        if(pauseAfterResolve)await releasePromise;
        return result;
       }catch(error){acquiredReject(error);throw error;}
      }
      const value=target[key];return typeof value==='function'?value.apply(target,args):value;
     };
     const value=target[key];return typeof value==='function'?value.bind(target):value;
    }});
   },
  },
 };
}
async function waitForBarrier(promise,label) {
 let timer;
 try{return await Promise.race([promise,new Promise((_,reject)=>{
  timer=setTimeout(()=>reject(new Error(`Timed out waiting for ${label}`)),10000);timer.unref();
 })]);}finally{clearTimeout(timer);}
}
const observe=promise=>promise.then(value=>({status:'fulfilled',value}),reason=>({status:'rejected',reason}));
test('real PG18 admin HTTP preserves RBAC, identity, visibility parity, and reset truthfulness',{skip:!enabled},async()=>{
 for(const key of ['PG_ADMIN_TEST_MIGRATION_URL','PG_ADMIN_TEST_RUNTIME_URL'])assert.match(new URL(process.env[key]).pathname,/^\/dvaia_test_[a-z0-9_]+$/);
 const migration=createPool(process.env,'PG_ADMIN_TEST_MIGRATION_URL'),pool=createPool(process.env,'PG_ADMIN_TEST_RUNTIME_URL');let server,authRouter;
 try{
  await initializeIdentityRepository(pool,migration);await seedWorkshopPlatform(migration);
  const identity=createIdentityRepository(pool),progress=createWorkshopProgressRepository(pool),config=createWorkshopConfigRepository(pool),password='AdminFixture@123',studentPassword='StudentFixture@123';
  const admin=await identity.createUser({username:'admin-fixture',email:'admin@example.test',passwordHash:await bcrypt.hash(password,4)});
  const student=await identity.createUser({username:'student-fixture',email:'student@example.test',passwordHash:await bcrypt.hash(studentPassword,4)});
  const nonStudent=await identity.createUser({username:'zero-level-admin',email:'zero-admin@example.test',passwordHash:await bcrypt.hash('NonStudentFixture@123',4)});
  await migration.query("UPDATE identity.users SET role='admin',admin_level=0 WHERE id=$1",[nonStudent.id]);
  await migration.query("UPDATE identity.users SET role='super_admin',admin_level=2,email_verified=1 WHERE id=$1",[admin.id]);
  for(const permission of ['user_management','challenge_management','system_config','manage_progress','system_logs'])await identity.grantPermission({userId:admin.id,permission,grantedBy:admin.id});
  const credential=await identity.findCredentialById(admin.id),adapter=createPostgresIdentityAdapter({repository:identity,progress,jwtSecret:'isolated-admin-http-secret'});
  const session=await adapter.createSession(credential,{get:()=>null,ip:'127.0.0.1'}),studentSession=await adapter.createSession(await identity.findCredentialById(student.id),{get:()=>null,ip:'127.0.0.1'}),resetCalls=[];
  const resetService={resetAdministrativeStudent:async input=>{if(input.workshopKey==='xss_workshop')throw Object.assign(new Error('Challenge reset storage has not completed PostgreSQL migration'),{code:'RESET_STORAGE_NOT_READY',statusCode:503});resetCalls.push(['student',input]);return{generation:1};},resetWorkshop:async input=>{resetCalls.push(['workshop',input]);}};
  const auth=createPostgresAdminAuth(adapter),adminRepository=createPostgresAdminRepository(pool),app=express(),pass=(_req,_res,next)=>next();app.use(express.json());
  authRouter=createPostgresAuthRouter({adapter,limiters:{loginRateLimiter:pass,registerRateLimiter:pass,passwordResetRateLimiter:pass}});
  app.use('/api/auth',authRouter);app.use('/api/admin',createPostgresAdminRouter({adapter,stores:{pool,progress,config},auth,repository:adminRepository,resetService}));
  app.use('/api/workshop',createPostgresWorkshopRouter({stores:{pool,progress,config},authenticateToken:auth.authenticateToken,requirePermission:auth.requirePermission,accountRepository:adminRepository,resetService}));
  app.use('/api/hints',createPostgresHintsRouter(config));app.use('/api/solutions',createPostgresSolutionsRouter(config));
  server=await new Promise(resolve=>{const value=app.listen(0,'127.0.0.1',()=>resolve(value));});const base=`http://127.0.0.1:${server.address().port}`;
  async function request(path,{method='GET',body,token=session.token}={}){const response=await fetch(base+path,{method,headers:{...(token?{authorization:`Bearer ${token}`}:{}),...(body?{'content-type':'application/json'}:{})},body:body?JSON.stringify(body):undefined});return{status:response.status,body:await response.json()};}
  assert.equal((await request('/api/admin/students',{token:null})).status,401);
  const students=await request('/api/admin/students');assert.equal(students.status,200);assert.ok(students.body.students.some(row=>row.id===student.id));
  assert.ok(students.body.students.every(row=>row.role==='student'),'student rosters must use role, not administrative privilege level');
  assert.ok(!students.body.students.some(row=>row.id===nonStudent.id));
  assert.equal((await request(`/api/admin/student-workshop-view/${nonStudent.id}`)).status,404);
  const view=await request(`/api/admin/student-workshop-view/${student.id}`);assert.equal(view.status,200);
  const canonical=await progress.getVisibleUserProgress(student.id),projectedCanonical=projectWorkshopChallenges(canonical);assert.deepEqual(view.body.challenges,projectedCanonical);assert.deepEqual(view.body.workshops,projectedCanonical);
  assert.equal(view.body.overview.totalObjectives,canonical.reduce((sum,row)=>sum+row.objectiveCount,0));
  assert.equal(view.body.overview.completedObjectives,0);assert.equal(view.body.overview.totalTimeSeconds,0);assert.equal(view.body.overview.pointsAvailable,false);
  await identity.revokePermission(admin.id,'manage_progress');
  assert.equal((await request(`/api/admin/student-workshop-view/${student.id}`)).status,403,'revoked progress grant must fail closed');
  assert.equal((await request(`/api/admin/students/${student.id}/workshops/sql_injection_workshop/reset`,{method:'POST',body:{}})).status,403);
  assert.equal((await request(`/api/workshop/instructor/reset-progress/${student.id}`,{method:'POST',body:{}})).status,403,'instructor alias must enforce the current progress grant');
  assert.deepEqual(resetCalls,[]);
  await identity.grantPermission({userId:admin.id,permission:'manage_progress',grantedBy:admin.id,expiresAt:new Date(Date.now()-60000).toISOString()});
  assert.equal((await request(`/api/admin/student-workshop-view/${student.id}`)).status,403,'expired progress grant must fail closed');
  await identity.grantPermission({userId:admin.id,permission:'manage_progress',grantedBy:admin.id});
  for(const target of [nonStudent.id,999999]){
    assert.equal((await request(`/api/admin/students/${target}/workshops/sql_injection_workshop/reset`,{method:'POST',body:{}})).status,404);
    assert.equal((await request(`/api/workshop/instructor/reset-progress/${target}`,{method:'POST',body:{}})).status,404);
  }
  assert.deepEqual(resetCalls,[],'missing and non-student targets must not reach either reset service');
  const all=await request('/api/admin/all-students-workshop-view');assert.equal(all.status,200);
  assert.ok(!all.body.students.some(row=>row.id===nonStudent.id),'aggregate workshop view must also exclude non-student accounts');
  const listed=all.body.students.find(row=>row.id===student.id);assert.deepEqual(listed.challenges,view.body.challenges);assert.equal(listed.totalObjectives,view.body.overview.totalObjectives);
  assert.equal((await request(`/api/admin/students/${student.id}`,{method:'PUT',body:{full_name:'Updated fixture'}})).status,200);
  let updated=await identity.getUserById(student.id);assert.equal(updated.full_name,'Updated fixture');assert.equal(updated.is_active,1);assert.equal(updated.admin_level,0);
  assert.equal((await request(`/api/admin/users/${student.id}`,{method:'PUT',body:{role:'super_admin'}})).status,400);
  assert.equal((await identity.getUserById(student.id)).role,'student');
  const challenges=await request('/api/admin/challenges');assert.equal(challenges.status,200);assert.ok(challenges.body.challenges.some(row=>row.key==='sql_injection_workshop'));
  assert.equal(challenges.body.challenges.find(row=>row.key==='sql_injection_workshop').workshopKey,'sql_injection_workshop');
  await identity.revokePermission(admin.id,'challenge_management');
  assert.equal((await request('/api/admin/challenges/toggle',{method:'POST',body:{challengeKey:'excessive_agency',enabled:false}})).status,403,'revoked challenge grant must fail closed');
  assert.equal((await request('/api/workshop/instructor/challenges/excessive_agency/toggle',{method:'PUT',body:{enabled:false}})).status,403,'instructor alias must enforce the current challenge grant');
  await identity.grantPermission({userId:admin.id,permission:'challenge_management',grantedBy:admin.id,expiresAt:new Date(Date.now()-60000).toISOString()});
  assert.equal((await request('/api/admin/challenges/toggle',{method:'POST',body:{challengeKey:'excessive_agency',enabled:false}})).status,403,'expired challenge grant must fail closed');
  await identity.grantPermission({userId:admin.id,permission:'challenge_management',grantedBy:admin.id});
  const studentBeforeDeniedAdminActions=await identity.getUserById(student.id);
  await identity.revokePermission(admin.id,'user_management');
  assert.equal((await request(`/api/workshop/instructor/students/${student.id}/toggle`,{method:'PUT',body:{enabled:false}})).status,403,'instructor alias must enforce the current user-management grant');
  assert.equal((await request('/api/admin/students',{method:'POST',body:{username:'denied-student',email:'denied@example.test',password:'DeniedFixture@123'}})).status,403);
  assert.equal((await request(`/api/admin/students/${student.id}`,{method:'PUT',body:{fullName:'Denied update'}})).status,403);
  assert.equal((await request(`/api/admin/students/${student.id}/change-password`,{method:'POST',body:{password:'DeniedFixture@123'}})).status,403);
  assert.equal((await request(`/api/admin/users/${student.id}/lock`,{method:'POST',body:{}})).status,403);
  assert.equal((await identity.getUserById(student.id)).is_active,1);
  assert.equal((await identity.getUserById(student.id)).full_name,studentBeforeDeniedAdminActions.full_name);
  assert.equal(await identity.findActiveSession(studentSession.token,student.id)!==null,true,'permission denial must not revoke the target session');
  await identity.grantPermission({userId:admin.id,permission:'user_management',grantedBy:admin.id});
  const adminPasswordBefore=(await identity.findCredentialById(admin.id)).password;
  assert.equal((await request(`/api/admin/students/${admin.id}`,{method:'PUT',body:{fullName:'Must not change'}})).status,404);
  assert.equal((await request(`/api/admin/students/${admin.id}/change-password`,{method:'POST',body:{password:'MustNotChange@123'}})).status,404);
  assert.equal((await identity.findCredentialById(admin.id)).password,adminPasswordBefore,'student aliases must not mutate administrator credentials');
  const legacyXss=await request('/api/admin/xss-workshop/solutions');assert.equal(legacyXss.status,200);assert.deepEqual(legacyXss.body.challenges.map(row=>row.challengeId),['email','reflected','stored_llm','stored_user']);
  assert.equal((await request('/api/admin/xss-workshop/solutions/toggle',{method:'POST',body:{challengeId:'reflected',enabled:'truthy'}})).status,200);
  assert.equal((await pool.query("SELECT solutions_enabled FROM workshop_platform.xss_legacy_solution_visibility WHERE challenge_id='reflected'")).rows[0].solutions_enabled,true);
  let xssSnapshot=await config.getSnapshot();assert.equal(xssSnapshot.exercises.xss_workshop.showSolutions,false);assert.ok(Object.values(xssSnapshot.exercises.xss_workshop.objectives).every(item=>!item.solutionVisible),'legacy tab toggle must not publish canonical objectives');
  const legacyBulk=await request('/api/admin/xss-workshop/solutions/bulk',{method:'POST',body:{enabled:0}});assert.equal(legacyBulk.status,200);assert.equal(legacyBulk.body.updated,4);
  assert.equal((await request('/api/admin/xss-workshop/solutions/reflected',{method:'POST',body:{title:'Instructor edit',difficulty:'Custom',hints:['One'],examples:[{payload:'<b>x</b>'}],approach:'Edited',tips:['Two']}})).status,200);
  assert.deepEqual((await request('/api/admin/xss-workshop/solutions/preview/reflected')).body.solution,{title:'Instructor edit',difficulty:'Custom',hints:['One'],examples:[{payload:'<b>x</b>'}],approach:'Edited',tips:['Two']});
  await seedWorkshopPlatform(migration);assert.equal((await request('/api/admin/xss-workshop/solutions/preview/reflected')).body.solution.title,'Instructor edit','restart seed must preserve instructor edits');
  await migration.query(`CREATE FUNCTION workshop_platform.reject_xss_legacy_enable() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN IF NEW.solutions_enabled THEN RAISE EXCEPTION 'intentional atomicity fixture'; END IF; RETURN NEW; END $$`);
  await migration.query(`CREATE TRIGGER reject_xss_legacy_enable BEFORE UPDATE ON workshop_platform.xss_legacy_solution_visibility
    FOR EACH ROW EXECUTE FUNCTION workshop_platform.reject_xss_legacy_enable()`);
  assert.equal((await request('/api/admin/challenges/solutions/toggle',{method:'POST',body:{challengeKey:'reflected_xss_llm',showSolutions:true}})).status,500);
  xssSnapshot=await config.getSnapshot();assert.equal(xssSnapshot.exercises.xss_workshop.showSolutions,false);assert.ok(Object.values(xssSnapshot.exercises.xss_workshop.objectives).every(item=>!item.solutionVisible),'legacy write failure must roll back canonical master and objectives');
  assert.equal((await pool.query('SELECT count(*)::integer AS count FROM workshop_platform.xss_legacy_solution_visibility WHERE solutions_enabled=true')).rows[0].count,0);
  await migration.query('DROP TRIGGER reject_xss_legacy_enable ON workshop_platform.xss_legacy_solution_visibility');
  await migration.query('DROP FUNCTION workshop_platform.reject_xss_legacy_enable()');
  assert.equal((await request('/api/admin/challenges/solutions/toggle',{method:'POST',body:{challengeKey:'reflected_xss_llm',showSolutions:true}})).status,200);
  xssSnapshot=await config.getSnapshot();assert.equal(xssSnapshot.exercises.xss_workshop.showSolutions,true);assert.ok(Object.values(xssSnapshot.exercises.xss_workshop.objectives).every(item=>item.solutionVisible));
  assert.equal((await pool.query('SELECT count(*)::integer AS count FROM workshop_platform.xss_legacy_solution_visibility WHERE solutions_enabled=true')).rows[0].count,4,'generic XSS master toggle must update both namespaces');
  assert.equal((await request('/api/admin/challenges/solutions/toggle',{method:'POST',body:{challengeKey:'sql_injection_workshop',showSolutions:true}})).status,200);
  let snapshot=await config.getSnapshot();assert.equal(snapshot.exercises.sql_injection_workshop.showSolutions,true);assert.ok(Object.values(snapshot.exercises.sql_injection_workshop.objectives).every(item=>item.solutionVisible));
  assert.equal((await request('/api/admin/challenges/hints/toggle',{method:'POST',body:{challengeKey:'sql_injection_workshop',showHints:false}})).status,200);
  snapshot=await config.getSnapshot();assert.equal(snapshot.exercises.sql_injection_workshop.showSolutions,true,'hint and solution gates remain independent');
  const eaBeforeBulk=snapshot.exercises.excessive_agency;
  await migration.query(`CREATE FUNCTION workshop_platform.reject_partial_ea_objective_bulk() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN IF NEW.workshop_key='excessive_agency' AND NEW.objective_id='objective_9' AND NEW.is_enabled=false THEN RAISE EXCEPTION 'intentional objective bulk atomicity fixture'; END IF; RETURN NEW; END $$`);
  await migration.query(`CREATE TRIGGER reject_partial_ea_objective_bulk BEFORE UPDATE OF is_enabled ON workshop_platform.objectives
    FOR EACH ROW EXECUTE FUNCTION workshop_platform.reject_partial_ea_objective_bulk()`);
  try {
    assert.equal((await request('/api/admin/workshops/excessive_agency/objectives/bulk-toggle',{method:'POST',body:{enabled:false}})).status,500);
    const afterRejected=await config.getSnapshot();
    assert.ok(Object.values(afterRejected.exercises.excessive_agency.objectives).every(item=>item.isVisible),'one failed bulk action must not partially hide objectives');
    assert.equal(afterRejected.exercises.excessive_agency.showHints,eaBeforeBulk.showHints);
    assert.equal(afterRejected.exercises.excessive_agency.showSolutions,eaBeforeBulk.showSolutions);
  } finally {
    await migration.query('DROP TRIGGER reject_partial_ea_objective_bulk ON workshop_platform.objectives');
    await migration.query('DROP FUNCTION workshop_platform.reject_partial_ea_objective_bulk()');
  }
  const disabledEa=await request('/api/admin/workshops/excessive_agency/objectives/bulk-toggle',{method:'POST',body:{enabled:false}});
  assert.equal(disabledEa.status,200);assert.equal(disabledEa.body.affectedCount,9);assert.equal(disabledEa.body.changed,true);
  snapshot=await config.getSnapshot();assert.ok(Object.values(snapshot.exercises.excessive_agency.objectives).every(item=>!item.isVisible));
  assert.equal(snapshot.exercises.excessive_agency.showHints,eaBeforeBulk.showHints);assert.equal(snapshot.exercises.excessive_agency.showSolutions,eaBeforeBulk.showSolutions);
  const enabledEa=await request('/api/admin/workshops/excessive_agency/objectives/bulk-toggle',{method:'POST',body:{enabled:true}});
  assert.equal(enabledEa.status,200);assert.equal(enabledEa.body.affectedCount,9);assert.equal(enabledEa.body.changed,true);
  snapshot=await config.getSnapshot();assert.ok(Object.values(snapshot.exercises.excessive_agency.objectives).every(item=>item.isVisible));

  // Canonical completion writes are controlled parity fixtures here. XSS/EA route suites separately prove Judge-backed awards.
  for(const [workshopKey,objectiveIds] of [['xss_workshop',['xss_r1','xss_e1']],['excessive_agency',['objective_5','objective_8']]]){
    for(const objectiveId of objectiveIds)await progress.syncObjectiveComplete(student.id,workshopKey,objectiveId);
  }
  const heartbeatStart=Date.now();await progress.recordHeartbeat({userId:student.id,workshopKey:'xss_workshop',now:heartbeatStart});
  await progress.recordHeartbeat({userId:student.id,workshopKey:'xss_workshop',now:heartbeatStart+30000});
  async function studentPayloads(){
    const [stats,challenges,dashboard]=await Promise.all([
      request('/api/workshop/student/stats',{token:studentSession.token}),request('/api/workshop/challenges',{token:studentSession.token}),request('/api/workshop/progress',{token:studentSession.token})]);
    assert.equal(stats.status,200);assert.equal(challenges.status,200);assert.equal(dashboard.status,200);
    assert.deepEqual(challenges.body.challenges,dashboard.body.challenges);
    const rows=challenges.body.challenges;
    assert.equal(stats.body.totalObjectives,rows.reduce((sum,row)=>sum+row.objectiveCount,0));
    assert.equal(stats.body.completedObjectives,rows.reduce((sum,row)=>sum+row.completedObjectiveCount,0));
    assert.equal(stats.body.totalTime,rows.reduce((sum,row)=>sum+row.timeSpentSeconds,0));
    assert.equal(stats.body.completedChallenges,rows.filter(row=>row.status==='completed').length);
    return {stats:stats.body,rows};
  }
  let parity=await studentPayloads();
  assert.equal(parity.rows.find(row=>row.workshopKey==='xss_workshop').completedObjectiveCount,2);
  assert.equal(parity.rows.find(row=>row.workshopKey==='excessive_agency').completedObjectiveCount,2);
  const adminParity=await request(`/api/admin/student-workshop-view/${student.id}`);
  assert.deepEqual(adminParity.body.challenges,parity.rows);assert.deepEqual(adminParity.body.workshops,parity.rows);
  const detail = await request(`/api/admin/students/${student.id}/progress`);
  assert.equal(detail.status, 200);
  // Student Details retains its established display DTO; its facts must still
  // match the canonical workshop projection used by preview and dashboards.
  assert.equal(detail.body.progress.length, parity.rows.length);
  for (const canonical of parity.rows) {
    const row = detail.body.progress.find(value => value.id === canonical.id);
    assert.ok(row);
    assert.equal(row.challenge_name, canonical.name);
    assert.equal(row.status, canonical.status);
    assert.equal(row.time_spent_seconds, canonical.timeSpentSeconds);
    assert.deepEqual(detail.body.workshopObjectives[canonical.workshopKey]
      .map(value => [value.objective_id, value.completed]),
    canonical.objectives.map(value => [value.id, value.completed]));
  }
  assert.equal(detail.body.stats.totalObjectivesCompleted, parity.stats.completedObjectives);
  assert.equal(detail.body.stats.totalTimeSpent, parity.stats.totalTime);
  assert.equal(detail.body.stats.completedChallenges, parity.stats.completedChallenges);
  assert.equal(detail.body.pointsAvailable, false);


  await migration.query("UPDATE workshop_platform.objectives SET label='Instructor-edited XSS objective' WHERE workshop_key='xss_workshop' AND objective_id='xss_r1'");
  const objectiveDto=await request('/api/admin/workshops/xss_workshop/objectives');
  assert.equal(objectiveDto.body.workshopKey,'xss_workshop');
  assert.deepEqual(Object.fromEntries(objectiveDto.body.objectives.map(item=>[item.objective_id,[item.workshopKey,item.label]])).xss_r1,
    ['xss_workshop','Instructor-edited XSS objective']);
  const independentBefore=(await config.getSnapshot({includeRaw:true})).exercises.xss_workshop.objectives.xss_r1.raw;
  assert.equal((await request('/api/admin/workshops/xss_workshop/objectives/xss_r1/toggle',{method:'POST',body:{enabled:false}})).status,200);
  const independentAfter=(await config.getSnapshot({includeRaw:true})).exercises.xss_workshop.objectives.xss_r1.raw;
  assert.equal(independentAfter.hintEnabled,independentBefore.hintEnabled);
  assert.equal(independentAfter.solutionEnabled,independentBefore.solutionEnabled);
  parity=await studentPayloads();let xss=parity.rows.find(row=>row.workshopKey==='xss_workshop');
  assert.equal(xss.objectiveCount,11);assert.equal(xss.completedObjectiveCount,1);assert.ok(!xss.objectives.some(item=>item.id==='xss_r1'));
  assert.equal((await pool.query("SELECT count(*)::integer AS count FROM workshop_platform.completions WHERE user_id=$1 AND workshop_key='xss_workshop' AND objective_id='xss_r1'",[student.id])).rows[0].count,1,'hidden completion is retained');
  assert.equal((await request('/api/admin/workshops/xss_workshop/objectives/xss_r1/toggle',{method:'POST',body:{enabled:true}})).status,200);
  parity=await studentPayloads();xss=parity.rows.find(row=>row.workshopKey==='xss_workshop');assert.equal(xss.objectiveCount,12);assert.equal(xss.completedObjectiveCount,2);assert.equal(xss.objectives.find(item=>item.id==='xss_r1').completed,true);

  for(const objective of xss.objectives)await progress.syncObjectiveComplete(student.id,'xss_workshop',objective.id);
  await pool.query("INSERT INTO identity.activity_logs(user_id,action_type,action_details) VALUES($1,'admin_activity_dto_fixture','{}')",[student.id]);
  parity=await studentPayloads();
  let activityUsers=await request('/api/admin/users?limit=100');
  let activityUser=activityUsers.body.users.find(row=>row.id===student.id);
  assert.equal(activityUsers.status,200);assert.ok(activityUser.recent_activity_count>=1);
  assert.equal(activityUser.total_challenges,parity.rows.length);
  assert.equal(activityUser.completed_challenges,parity.rows.filter(row=>row.status==='completed').length);
  assert.equal(activityUser.progress_percentage,Math.round(100*activityUser.completed_challenges/activityUser.total_challenges));

  assert.equal((await request('/api/admin/challenges/toggle',{method:'POST',body:{challengeKey:'excessive_agency',enabled:false}})).status,200);
  parity=await studentPayloads();assert.ok(!parity.rows.some(row=>row.workshopKey==='excessive_agency'));
  activityUsers=await request('/api/admin/users?limit=100');activityUser=activityUsers.body.users.find(row=>row.id===student.id);
  assert.equal(activityUser.total_challenges,parity.rows.length,'active-user totals use the same visible exercise set as learner dashboards');
  assert.equal(activityUser.completed_challenges,parity.rows.filter(row=>row.status==='completed').length);
  assert.ok((await request('/api/admin/challenges')).body.challenges.some(row=>row.key==='excessive_agency'&&row.enabled===false));
  assert.ok(Object.values((await request('/api/hints/excessive_agency/status',{token:null})).body.objectives).every(value=>value===false));
  assert.equal((await request('/api/admin/challenges/toggle',{method:'POST',body:{challengeKey:'excessive_agency',enabled:true}})).status,200);
  parity=await studentPayloads();assert.equal(parity.rows.find(row=>row.workshopKey==='excessive_agency').completedObjectiveCount,2);

  for(const fixture of [
    {challengeKey:'reflected_xss_llm',workshopKey:'xss_workshop',objectiveId:'xss_r1',otherId:'xss_r2',solutionStatus:'/api/solutions/xss-workshop/status',solutionContent:'/api/solutions/xss-workshop/objective/',solutionAdmin:'/api/admin/xss-workshop/objective-solutions/xss_r1/toggle',solutionAdminList:'/api/admin/xss-workshop/objective-solutions'},
    {challengeKey:'excessive_agency',workshopKey:'excessive_agency',objectiveId:'objective_5',otherId:'objective_6',solutionStatus:'/api/solutions/excessive-agency/status',solutionContent:'/api/solutions/excessive-agency/',solutionAdmin:'/api/admin/ea-workshop/solutions/toggle',solutionAdminList:'/api/admin/ea-workshop/solutions'},
  ]){
    assert.equal((await request('/api/admin/challenges/solutions/toggle',{method:'POST',body:{challengeKey:fixture.challengeKey,showSolutions:false}})).status,200);
    assert.equal((await request('/api/admin/challenges/hints/toggle',{method:'POST',body:{challengeKey:fixture.challengeKey,showHints:true}})).status,200);
    let hints=(await request(`/api/hints/${fixture.challengeKey}/status`,{token:null})).body.objectives;
    let solutions=(await request(fixture.solutionStatus,{token:null})).body.objectives;
    assert.equal(hints[fixture.objectiveId],true);assert.equal(solutions[fixture.objectiveId],false);
    assert.equal((await request(`/api/hints/${fixture.challengeKey}/${fixture.objectiveId}`,{token:null})).status,200);
    assert.equal((await request(fixture.solutionContent+fixture.objectiveId,{token:null})).status,403);
    const solutionBody=fixture.workshopKey==='excessive_agency'?{objectiveId:fixture.objectiveId,enabled:true}:{enabled:true};
    assert.equal((await request(fixture.solutionAdmin,{method:'POST',body:solutionBody})).status,200);
    solutions=(await request(fixture.solutionStatus,{token:null})).body.objectives;
    assert.equal(solutions[fixture.objectiveId],true);assert.equal(solutions[fixture.otherId],false);
    assert.equal((await request(fixture.solutionContent+fixture.objectiveId,{token:null})).status,200);
    assert.equal((await request(fixture.solutionContent+fixture.otherId,{token:null})).status,403);
    assert.equal((await request(`/api/admin/workshops/${fixture.workshopKey}/hints/${fixture.objectiveId}/toggle`,{method:'POST',body:{enabled:false}})).status,200);
    hints=(await request(`/api/hints/${fixture.challengeKey}/status`,{token:null})).body.objectives;
    assert.equal(hints[fixture.objectiveId],false);assert.equal(solutions[fixture.objectiveId],true,'hint and solution gates stay independent');
    assert.equal((await request(`/api/hints/${fixture.challengeKey}/${fixture.objectiveId}`,{token:null})).status,403);
    assert.equal((await request('/api/admin/challenges/solutions/toggle',{method:'POST',body:{challengeKey:fixture.challengeKey,showSolutions:true}})).status,200);
    assert.equal((await request('/api/admin/challenges/hints/toggle',{method:'POST',body:{challengeKey:fixture.challengeKey,showHints:false}})).status,200);
    hints=(await request(`/api/hints/${fixture.challengeKey}/status`,{token:null})).body.objectives;
    solutions=(await request(fixture.solutionStatus,{token:null})).body.objectives;
    assert.ok(Object.values(hints).every(value=>value===false));assert.ok(Object.values(solutions).every(value=>value===true));
    assert.deepEqual((await request(`/api/admin/workshops/${fixture.workshopKey}/hints`)).body.hints,hints);
    assert.ok((await request(fixture.solutionAdminList)).body.objectives.every(item=>item.solutions_enabled===true));
    parity=await studentPayloads();const row=parity.rows.find(item=>item.workshopKey===fixture.workshopKey);
    assert.ok(row.objectives.every(item=>item.hintVisible===false&&item.solutionVisible===true));
    const adminObjectives=await request(`/api/admin/workshops/${fixture.workshopKey}/objectives`);
    assert.equal(adminObjectives.body.objectives.length,row.objectiveCount);assert.ok(adminObjectives.body.objectives.every(item=>item.is_enabled===true&&item.solutions_enabled===true));
  }
  assert.equal((await request(`/api/admin/users/${student.id}/lock`,{method:'POST',body:{}})).status,200);assert.equal((await identity.checkAccountLockout(student.id)).locked,true);
  assert.equal(await identity.findActiveSession(studentSession.token,student.id),null,'locking must deny the current bearer');
  assert.equal((await pool.query(`SELECT is_active,revoked_at,revoke_reason FROM identity.user_sessions
    WHERE session_token_hash=$1`,[require('node:crypto').createHash('sha256').update(studentSession.token).digest('hex')])).rows[0].revoke_reason,'account_locked');
  assert.ok(await identity.findActiveSession(session.token,admin.id),'locking a student must preserve the administrator sibling session');
  assert.ok((await request('/api/admin/users/locked')).body.lockedUsers.some(row=>row.id===student.id));
  assert.equal((await request(`/api/admin/users/${student.id}/unlock`,{method:'POST',body:{}})).status,200);assert.equal((await identity.checkAccountLockout(student.id)).locked,false);
  assert.equal(await identity.findActiveSession(studentSession.token,student.id),null,'unlock must not revive the old bearer');
  const afterUnlock=await request('/api/auth/login',{method:'POST',token:null,body:{username:student.username,password:studentPassword}});
  assert.equal(afterUnlock.status,200,'fresh login after unlock must work');
  assert.equal((await request('/api/workshop/student/stats',{token:afterUnlock.body.token})).status,200);
  assert.equal((await request(`/api/admin/students/${student.id}`,{method:'PUT',body:{isActive:false}})).status,200);
  assert.equal(await identity.findActiveSession(afterUnlock.body.token,student.id),null);
  assert.equal((await request(`/api/admin/students/${student.id}`,{method:'PUT',body:{isActive:true}})).status,200);
  assert.equal(await identity.findActiveSession(afterUnlock.body.token,student.id),null,'reactivation must not revive the old bearer');
  const afterReactivation=await request('/api/auth/login',{method:'POST',token:null,body:{username:student.username,password:studentPassword}});
  assert.equal(afterReactivation.status,200,'fresh login after reactivation must work');
  assert.equal((await request(`/api/workshop/instructor/students/${student.id}/toggle`,{method:'PUT',body:{enabled:false}})).status,200);
  assert.equal(await identity.findActiveSession(afterReactivation.body.token,student.id),null);
  assert.equal((await request(`/api/workshop/instructor/students/${student.id}/toggle`,{method:'PUT',body:{enabled:true}})).status,200);
  assert.equal(await identity.findActiveSession(afterReactivation.body.token,student.id),null,'instructor re-enable must not revive the old bearer');
  const afterInstructorEnable=await request('/api/auth/login',{method:'POST',token:null,body:{username:student.username,password:studentPassword}});
  assert.equal(afterInstructorEnable.status,200,'fresh login after instructor re-enable must work');
  const changedStudentPassword='StudentChanged@123';
  const changedPassword=await request(`/api/admin/students/${student.id}/change-password`,{method:'POST',body:{password:changedStudentPassword}});
  assert.equal(changedPassword.status,200);assert.ok(changedPassword.body.sessionsRevoked>=1);
  assert.equal(await identity.findActiveSession(afterInstructorEnable.body.token,student.id),null);
  assert.equal((await request('/api/auth/login',{method:'POST',token:null,body:{username:student.username,password:studentPassword}})).status,401);
  assert.equal((await request('/api/auth/login',{method:'POST',token:null,body:{username:student.username,password:changedStudentPassword}})).status,200,
    'student-scoped administrative password reset must permit a fresh login only with the replacement credential');

  await adminRepository.setUserLock({userId:student.id,locked:false,actorId:admin.id,actorUsername:admin.username,ipAddress:'127.0.0.1'});
  const issueOwnsLock=sqlBarrierPool(pool,sql=>sql.startsWith('SELECT * FROM identity.users WHERE id=$1 FOR UPDATE'),{pauseAfterResolve:true});
  const restrictionWaits=sqlBarrierPool(pool,sql=>sql.startsWith('SELECT id FROM identity.users WHERE id=$1 FOR UPDATE'));
  const issueFirstAdapter=createPostgresIdentityAdapter({repository:createIdentityRepository(issueOwnsLock.pool),progress,jwtSecret:'isolated-admin-http-secret'});
  const waitingRestriction=createPostgresAdminRepository(restrictionWaits.pool);
  let restrictionSettled=false,restrictedSecond;
  const issuedFirst=observe(issueFirstAdapter.createSession(await identity.findCredentialById(student.id),{get:()=>null,ip:'127.0.0.1'}));
  let issuedSession;
  try{
   await waitForBarrier(issueOwnsLock.acquired,'session-owned user-row lock');
   restrictedSecond=observe(waitingRestriction.setUserLock({userId:student.id,locked:true,actorId:admin.id,actorUsername:admin.username,ipAddress:'127.0.0.1'})).finally(()=>{restrictionSettled=true;});
   await waitForBarrier(restrictionWaits.issued,'waiting restriction SQL');await new Promise(setImmediate);
   assert.equal(restrictionSettled,false,'restriction must wait while session issuance owns the user-row lock');
  }finally{issueOwnsLock.release();}
  const issueFirstOutcome=await issuedFirst,restrictionSecondOutcome=await restrictedSecond;
  assert.equal(issueFirstOutcome.status,'fulfilled');assert.equal(restrictionSecondOutcome.status,'fulfilled');issuedSession=issueFirstOutcome.value;
  assert.equal(await identity.findActiveSession(issuedSession.token,student.id),null,'the waiting restriction must revoke the just-issued session');

  await adminRepository.setUserLock({userId:student.id,locked:false,actorId:admin.id,actorUsername:admin.username,ipAddress:'127.0.0.1'});
  const restrictionOwnsLock=sqlBarrierPool(pool,sql=>sql.startsWith('SELECT id FROM identity.users WHERE id=$1 FOR UPDATE'),{pauseAfterResolve:true});
  const issuanceWaits=sqlBarrierPool(pool,sql=>sql.startsWith('SELECT * FROM identity.users WHERE id=$1 FOR UPDATE'));
  const lockingRepository=createPostgresAdminRepository(restrictionOwnsLock.pool);
  const waitingIssueAdapter=createPostgresIdentityAdapter({repository:createIdentityRepository(issuanceWaits.pool),progress,jwtSecret:'isolated-admin-http-secret'});
  let issuanceSettled=false,issuedSecond;
  const restrictedFirst=observe(lockingRepository.setUserLock({userId:student.id,locked:true,actorId:admin.id,actorUsername:admin.username,ipAddress:'127.0.0.1'}));
  try{
   await waitForBarrier(restrictionOwnsLock.acquired,'restriction-owned user-row lock');
   issuedSecond=observe(waitingIssueAdapter.createSession(await identity.findCredentialById(student.id),{get:()=>null,ip:'127.0.0.1'})).finally(()=>{issuanceSettled=true;});
   await waitForBarrier(issuanceWaits.issued,'waiting session-issuance SQL');await new Promise(setImmediate);
   assert.equal(issuanceSettled,false,'session issuance must wait while restriction owns the user-row lock');
  }finally{restrictionOwnsLock.release();}
  const restrictionFirstOutcome=await restrictedFirst,rejectedIssue=await issuedSecond;
  assert.equal(restrictionFirstOutcome.status,'fulfilled');
  assert.equal(rejectedIssue.status,'rejected');assert.match(rejectedIssue.reason.message,/Account unavailable/);
  assert.equal((await pool.query('SELECT count(*)::integer AS count FROM identity.user_sessions WHERE user_id=$1 AND is_active=1',[student.id])).rows[0].count,0,
    'both serialized orderings must end with no active target session');
  await adminRepository.setUserLock({userId:student.id,locked:false,actorId:admin.id,actorUsername:admin.username,ipAddress:'127.0.0.1'});
  assert.equal((await request(`/api/admin/students/${student.id}/workshops/sql_injection_workshop/reset`,{method:'POST',body:{}})).status,200);
  assert.equal((await request(`/api/admin/students/${student.id}/workshops/xss_workshop/reset`,{method:'POST',body:{}})).status,503);
  assert.equal((await request('/api/admin/workshops/sql_injection_workshop/reset-all-students',{method:'POST',body:{}})).status,200);
  assert.deepEqual(resetCalls.map(([kind,{operationId,actorRequest,...input}])=>[kind,input]),[['student',{userId:String(student.id),workshopKey:'sql_injection_workshop'}],['workshop',{workshopKey:'sql_injection_workshop'}]]);
  for(const [,input] of resetCalls){assert.match(input.operationId,/^[0-9a-f-]{36}$/);assert.equal(input.actorRequest.user.id,admin.id);assert.ok(Object.isFrozen(input.actorRequest));assert.equal(input.actorRequest.headers.authorization,`Bearer ${session.token}`);} 
 }finally{authRouter?.close();if(server)await new Promise(resolve=>server.close(resolve));await Promise.all([pool.end(),migration.end()]);}
});
