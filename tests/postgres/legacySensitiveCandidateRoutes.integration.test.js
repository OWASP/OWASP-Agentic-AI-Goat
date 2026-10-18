'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os'),{randomUUID}=require('node:crypto');
const {Pool}=require('pg');
test('mounted canonical legacy file agent persists controlled Judge credit and fences native reset',{skip:process.env.LEGACY_CANDIDATE_ROUTES_NATIVE!=='1',timeout:120000},async()=>{
 assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');assert.equal(fs.realpathSync(process.env.DVAIA_ISOLATED_TEST_WORKSPACE),fs.realpathSync(process.cwd()));
 const url=(store,role)=>{const u=new URL(process.env[(store==='identity'?'WORKSHOP_RAG':'LEGACY_FINFLOW')+'_'+role.toUpperCase()+'_URL']);assert.equal(u.hostname,'127.0.0.1');assert.match(u.pathname,/^\/dvaia_test_workshop_rag_[a-f0-9]+(?:_finflow)?$/);assert.equal(u.username,`dvaia_${store==='identity'?'identity':'finflow'}_${role}`);return u.href;};
 Object.assign(process.env,{PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres',IDENTITY_DATABASE_URL:url('identity','runtime'),IDENTITY_MIGRATION_DATABASE_URL:url('identity','migration'),FINFLOW_WORKSHOP_DATABASE_URL:url('finflow','runtime'),FINFLOW_WORKSHOP_MIGRATION_DATABASE_URL:url('finflow','migration'),JWT_SECRET:randomUUID()+randomUUID()});
 const migration=new Pool({connectionString:url('identity','migration')}),finflowMigration=new Pool({connectionString:url('finflow','migration')}),finflow=new Pool({connectionString:url('finflow','runtime')});
 const freshUrl=new URL(process.env.LEGACY_FRESH_IDENTITY_MIGRATION_URL);assert.equal(freshUrl.hostname,'127.0.0.1');assert.match(freshUrl.pathname,/^\/dvaia_test_workshop_rag_[a-f0-9]+_fresh$/);assert.equal(freshUrl.username,'dvaia_identity_migration');const freshIdentity=new Pool({connectionString:freshUrl.href});
 let server,root,fullParity,renderedAuth;const evidence={status:'incomplete',scope:'Actual mounted candidate router, canonical bearer, graph/effects/Judge persistence and aggregate reset; controlled actor/Judge transports, no actual-model claim'};
 try{
  await require('../../db/postgres/migrate').migrate(freshIdentity,path.resolve('db/postgres/identity-migrations'));assert.deepEqual(await require('../../db/postgres/migrate').migrate(freshIdentity,path.resolve('db/postgres/identity-migrations')),[]);
  assert.equal((await freshIdentity.query('SELECT count(*)::int AS n FROM identity.legacy_file_ssi_resets')).rows[0].n,0);evidence.registeredFreshIdentityNoop=true;
  const migrationFs=require('node:fs/promises'),originalReaddir=migrationFs.readdir;
  const identityMigrations=path.resolve('db/postgres/identity-migrations');
  migrationFs.readdir=async function(directory,...args){
   const entries=await originalReaddir.call(this,directory,...args);
   return path.resolve(String(directory))===identityMigrations
    ? entries.filter(name=>typeof name==='string'&&(!name.endsWith('.sql')||name<'0091_')) : entries;
  };
  try{await require('../../db/postgres/migrate').migrate(migration,identityMigrations);}
  finally{migrationFs.readdir=originalReaddir;}
  await require('../../db/postgres/migrate').migrate(finflowMigration,path.resolve('db/postgres/workshop-migrations/finflow'));
  await require('../../server/database/postgres/sensitiveInfoWorkshopDb').createFinflowWorkshopDb(finflow).initialize(finflowMigration);
  await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(migration);
  const defaultRows=(await migration.query("SELECT is_enabled FROM workshop_platform.objectives WHERE workshop_key='legacy_sensitive_file_ssi'")).rows;assert.equal(defaultRows.length,5);assert.ok(defaultRows.every(row=>row.is_enabled===true));
  evidence.canonicalSeedReleasedDefaults=true;
  const adapter=require('../../server/services/postgresIdentityAdapter').getPostgresIdentityAdapter(),pool=adapter.pool;
  const preIdentity=require('../../server/database/postgres/identityRepository').createIdentityRepository(pool);
  const oldUser=await preIdentity.createUser({username:randomUUID(),email:randomUUID()+'@example.invalid',passwordHash:await require('bcryptjs').hash(randomUUID(),4)});
  const oldOperation=randomUUID();await pool.query('SELECT * FROM identity.begin_sensitive_info_reset($1,$2)',[oldUser.id,oldOperation]);
  const migrate=require('../../db/postgres/migrate').migrate;
  for(const [store,pool] of [['identity',migration],['finflow',finflowMigration]]){
   const source=store==='identity'?'db/postgres/identity-migrations':'db/postgres/workshop-migrations/finflow';
   await migrate(pool,path.resolve(source));assert.deepEqual(await migrate(pool,path.resolve(source)),[]);
  }
  await require('../../server/database/postgres/legacyFileSsiCatalogCandidate').seedLegacyFileSsiCandidate(migration);
  await require('../../server/database/postgres/legacyFileSsiCatalogCandidate').seedLegacyFileSsiCandidate(migration);
  const config=require('../../server/database/postgres/workshopConfigRepository').createWorkshopConfigRepository(pool);
  const {WORKSHOP_KEY,OBJECTIVES}=require('../../server/config/legacyFileSsiCurriculum');
  await config.setExerciseVisibility(WORKSHOP_KEY,false);await config.setObjectiveVisibility(WORKSHOP_KEY,OBJECTIVES[0].id,false);await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(migration);let preserved=(await config.getSnapshot({includeRaw:true})).exercises[WORKSHOP_KEY];assert.equal(preserved.isVisible,false);assert.equal(preserved.objectives[OBJECTIVES[0].id].raw.objectiveEnabled,false);evidence.instructorDisabledChoicesPreserved=true;
  await config.setExerciseVisibility(WORKSHOP_KEY,true);for(const o of OBJECTIVES)await config.setObjectiveVisibility(WORKSHOP_KEY,o.id,true);
  await require('../../server/services/legacySensitiveCandidateComposition').assertLegacySensitiveCandidateReadiness({pool});
  await config.setMasterHintVisibility(WORKSHOP_KEY,true);await config.setMasterSolutionVisibility(WORKSHOP_KEY,true);
  await config.setMasterHintVisibility(WORKSHOP_KEY,false);let gates=(await config.getSnapshot()).exercises[WORKSHOP_KEY];assert.equal(gates.showHints,false);assert.equal(gates.showSolutions,true);
  const seeded=JSON.stringify((await migration.query('SELECT * FROM workshop_platform.objectives WHERE workshop_key=$1 ORDER BY objective_id',[WORKSHOP_KEY])).rows);
  await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(migration);assert.equal(JSON.stringify((await migration.query('SELECT * FROM workshop_platform.objectives WHERE workshop_key=$1 ORDER BY objective_id',[WORKSHOP_KEY])).rows),seeded);
  assert.equal((await migration.query('SELECT count(*)::int AS n FROM workshop_platform.objectives WHERE workshop_key=$1 AND catalog_active AND is_enabled',[WORKSHOP_KEY])).rows[0].n,5);
  await assert.rejects(finflow.query('UPDATE finflow.legacy_file_ssi_cleanup_receipts SET owner_id=owner_id'),{code:'42501'});
  const identity=require('../../server/database/postgres/identityRepository').createIdentityRepository(pool),hash=await require('bcryptjs').hash(randomUUID(),4);
  const owner=async()=>{const user=await identity.createUser({username:randomUUID(),email:randomUUID()+'@example.invalid',passwordHash:hash});return{user,session:await adapter.createSession(await identity.findCredentialById(user.id),{})};};
  const a=await owner(),b=await owner();
  root=fs.mkdtempSync(path.join(os.tmpdir(),'legacy-candidate-files-'));process.env.LEGACY_SENSITIVE_FILES_ROOT=root;require('../../server/database/sensitiveInfoFiles').createSensitiveFiles();const flag=require('../../server/config/legacySensitiveFlags').FILE_FLAGS[0];
  const runs=require('../../server/agent-runtime/runCoordinator').createRunCoordinator({family:'LegacySensitiveInfo',ledger:require('../../server/agent-runtime/postgresRunLedger').createPostgresRunLedger(pool)});
  const finflowRuns=require('../../server/agent-runtime/runCoordinator').createRunCoordinator({family:'SensitiveInfo',ledger:require('../../server/agent-runtime/postgresRunLedger').createPostgresRunLedger(pool)});
  const aggregateJournal=require('../../server/database/postgres/sensitiveInfoResetRepository').createSensitiveInfoResetRepository(pool);
  const aggregateCleanup=require('../../server/database/postgres/sensitiveInfoCleanupRepository').createSensitiveInfoCleanupRepository(finflow);
  let legacyAggregateDrains=0;
  const aggregate=require('../../server/services/sensitiveInfoAggregateReset').createSensitiveInfoAggregateReset({legacyRuns:{reset:(id,work)=>{legacyAggregateDrains++;return runs.reset(id,work);}},finflowReset:(id,work)=>finflowRuns.reset(id,work),journal:aggregateJournal,cleanup:aggregateCleanup});
  assert.equal((await aggregateJournal.read(oldOperation)).planVersion,1);
  await assert.rejects(runs.run(String(oldUser.id),{},async()=>{}));
  await aggregate.recover(oldOperation);assert.equal(legacyAggregateDrains,1);await runs.run(String(oldUser.id),{},async execution=>execution.check());
  const progress=require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(pool);
  const dashboard=(await progress.getVisibleUserProgress(a.user.id)).find(r=>r.workshopKey===WORKSHOP_KEY);
  const detail=await progress.getWorkshopProgress(a.user.id,WORKSHOP_KEY);
  const adminProjection=(await progress.getUsersProgress([a.user.id])).get(a.user.id).find(r=>r.workshopKey===WORKSHOP_KEY);
  assert.equal(dashboard.route,'/workshop/file-ssi');assert.equal(dashboard.objectiveCount,5);
  for(const row of [detail,adminProjection]){assert.equal(row.objectiveCount,dashboard.objectiveCount);assert.deepEqual(row.objectives,dashboard.objectives.map(({text,hintVisible,solutionVisible,...o})=>o));}
  assert.deepEqual(dashboard.objectives.map(o=>o.label),OBJECTIVES.map(o=>o.text));
  evidence.canonicalAdminDashboardCountsAndLabelsAgree=true;
  const judge=require('../../server/agent-runtime/objectiveJudge').createObjectiveJudge({model:{generate:async()=>({response:JSON.stringify({verdict:'pass',explanation:'Controlled fixture observed outcome',criteria:[{id:'observed_outcome',satisfied:true,evidenceRefs:['tool_result']}]}),provider:'fixture',model:'controlled-judge',metadata:{eval_count:3}})}});
  const completion=require('../../server/services/objectiveCompletionService').createObjectiveCompletionService({receipts:require('../../server/database/postgres/objectiveJudgmentRepository').createObjectiveJudgmentRepository(pool),progress,judge});
  const tools=require('../../server/services/legacySensitiveTools').createLegacySensitiveTools({sensitiveFilesDir:root,publicDir:path.join(root,'public')});
  let calls=0,hold=false,release,entered;
  const production=require('../../server/services/legacySensitiveAgentProduction').createLegacySensitiveAgentProduction({env:{AI_PROVIDER:'ollama',OLLAMA_MODEL:'controlled-actor'},tools,observeModelCall:()=>{},providerFactory:()=>({chat:async(messages,_tools,opts)=>{
   calls++;let response;
   if(opts.format==='json'&&messages.some(m=>m.content==='read then failed SSI')){const count=messages.filter(m=>m.role==='assistant').length;response=JSON.stringify(count===0?{action:'read_teaching_file',params:{path:'../secret/database_credentials.txt'}}:count===1?{action:'render_ssi_template',params:{template:'ordinary text'}}:{action:'finish',params:{}});}
   else if(opts.format==='json'){response=JSON.stringify(messages.some(m=>m.role==='assistant')?{action:'finish',params:{}}:messages.some(m=>m.content.includes('render exact SSI'))?{action:'render_ssi_template',params:{template:'<!--#include file="../secret/database_credentials.txt" -->'}}:{action:'read_teaching_file',params:{path:messages.some(m=>m.content.includes('denied path'))?'../../outside.txt':'../secret/database_credentials.txt'}});}
   else{if(hold){entered();await new Promise(resolve=>{release=resolve;});}response=flag;}
   return{response,provider:'ollama',model:'controlled-actor'};
  }})});
  const finflowStore=require('../../server/database/postgres/sensitiveInfoWorkshopDb').createFinflowWorkshopDb(finflow);
  await finflowStore.ensureObjectives(String(a.user.id));await finflowStore.completeObjective(String(a.user.id),'tool_enum');
  let finflowBefore=JSON.stringify(await finflowStore.getProgress(String(a.user.id)));
  const resetComposition=await require('../../server/services/legacyFileSsiResetComposition').createLegacyFileSsiResetComposition({identityPool:pool,finflowPool:finflow,runs});
  for(const [admin,repository,grant,revoke] of [
   [migration,resetComposition.journal,'GRANT UPDATE(owner_id) ON identity.legacy_file_ssi_resets TO dvaia_identity_runtime','REVOKE UPDATE(owner_id) ON identity.legacy_file_ssi_resets FROM dvaia_identity_runtime'],
   [migration,resetComposition.journal,'GRANT SELECT(owner_id) ON identity.legacy_file_ssi_reset_authority TO dvaia_identity_runtime','REVOKE SELECT(owner_id) ON identity.legacy_file_ssi_reset_authority FROM dvaia_identity_runtime'],
   [finflowMigration,resetComposition.cleanup,'GRANT SELECT(owner_id) ON finflow.legacy_file_ssi_cleanup_receipts TO dvaia_finflow_runtime','REVOKE SELECT(owner_id) ON finflow.legacy_file_ssi_cleanup_receipts FROM dvaia_finflow_runtime'],
   [finflowMigration,resetComposition.cleanup,'GRANT EXECUTE ON FUNCTION finflow.read_legacy_file_ssi_cleanup_receipt(uuid,text) TO PUBLIC','REVOKE EXECUTE ON FUNCTION finflow.read_legacy_file_ssi_cleanup_receipt(uuid,text) FROM PUBLIC'],
   [migration,resetComposition.journal,'ALTER TABLE identity.legacy_file_ssi_resets RENAME COLUMN failure_code TO unexpected_failure','ALTER TABLE identity.legacy_file_ssi_resets RENAME COLUMN unexpected_failure TO failure_code'],
   [finflowMigration,resetComposition.cleanup,'ALTER TABLE finflow.legacy_file_ssi_cleanup_receipts RENAME COLUMN completed_at TO unexpected_completed','ALTER TABLE finflow.legacy_file_ssi_cleanup_receipts RENAME COLUMN unexpected_completed TO completed_at'],
   [migration,resetComposition.journal,'ALTER TABLE graph_runtime.runs DISABLE TRIGGER legacy_file_ssi_reset_run_guard','ALTER TABLE graph_runtime.runs ENABLE TRIGGER legacy_file_ssi_reset_run_guard'],
  ]){await admin.query(grant);try{await assert.rejects(repository.assertReady(),{code:'RESET_STORAGE_NOT_READY'});}finally{await admin.query(revoke);}await repository.assertReady();}
  evidence.readinessGrantDriftRejected=true;
  const composition=await require('../../server/services/legacySensitiveCandidateComposition').createLegacySensitiveCandidateComposition({env:process.env,legacyRuns:runs,platformStores:{pool,progress,config},completionService:completion,agentProduction:production,aggregateReset:resetComposition.reset,legacyStore:{}});
  // Actual parent route and authentic manual sinks; only provider/composition admission are controlled.
  require('../../server/services/legacySensitiveCandidateComposition').getLegacySensitiveCandidateComposition=async()=>composition;
  require('../../server/services/legacySensitiveRunCoordinator').legacySensitiveRuns=runs;
  const express=require('express'),app=express();app.use(express.json());app.use('/api/sensitive-info',require('../../server/routes/sensitiveInfo'));
  if(process.env.LEGACY_FULL_APP_PARITY==='1')fullParity=await require('../fixtures/legacyFileSsiFullAppParity').mountLegacyParityRoutes({app,adapter,pool,migration,progress,config,identity});
  if(process.env.LEGACY_CANDIDATE_RENDERED==='1'&&!fullParity){const pass=(_req,_res,next)=>next();renderedAuth=require('../../server/routes/postgresAuth').createPostgresAuthRouter({adapter,limiters:{loginRateLimiter:pass,registerRateLimiter:pass,passwordResetRateLimiter:pass}});app.use('/api/auth',renderedAuth);}
  server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});const endpoint=`http://127.0.0.1:${server.address().port}/api/sensitive-info/canonical-agent/chat`;
  const request=async(o,message='read protected teaching record')=>{const r=await fetch(endpoint,{method:'POST',headers:{'content-type':'application/json',...(o?{authorization:'Bearer '+o.session.token}:{})},body:JSON.stringify({message,userId:b.user.id})});return{status:r.status,body:await r.json()};};
  assert.equal((await request(null)).status,401);assert.equal(calls,0);
  const manual=async(route,body)=>{const response=await fetch(endpoint.replace('/canonical-agent/chat','/'+route),{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer '+a.session.token},body:JSON.stringify(body)});return{status:response.status,body:await response.json()};};
  for(const [route,body,id] of [['file/read',{filename:'../secret/database_credentials.txt'},'path_traversal'],['template/render',{template:'<!--#include file="../secret/database_credentials.txt" -->'},'ssi_injection'],['document/process',{documentPath:'../secret/ssi_report.shtml',processSSI:true},'combined_traversal_ssi']]){
    const response=await manual(route,body);assert.equal(response.status,200);assert.equal(response.body.judgments[0].objectiveId,id);assert.equal(response.body.judgments[0].completed,true);
  }
  const stateResponse=await fetch(endpoint.replace('/chat','/state'),{headers:{authorization:'Bearer '+a.session.token}});assert.equal(stateResponse.status,200);
  const state=await stateResponse.json();assert.equal(state.challenges[0].completedObjectiveCount,3);assert.equal(state.challenges[0].objectiveCount,5);assert.equal(state.content.path_traversal.hints,undefined);
  evidence.fullParentManualHttpAndCanonicalState=true;

  const first=await request(a);assert.equal(first.status,200,JSON.stringify(first.body));assert.equal(first.body.completed,true,JSON.stringify(first.body));assert.equal(first.body.objectiveId,'ai_assisted_path_traversal');assert.equal(first.body.response,flag);
  const ssi=await request(a,'render exact SSI <!--#include file="../secret/database_credentials.txt" -->');assert.equal(ssi.body.objectiveId,'ai_assisted_ssi');assert.equal(ssi.body.completed,true);
  assert.equal((await progress.getWorkshopProgress(a.user.id,'legacy_sensitive_file_ssi')).completedObjectiveCount,5);assert.equal((await progress.getWorkshopProgress(b.user.id,'legacy_sensitive_file_ssi')).completedObjectiveCount,0);
  assert.equal((await request(b)).body.completed,true);
  if(fullParity){const now=Date.now();await progress.recordHeartbeat({userId:a.user.id,workshopKey:WORKSHOP_KEY,now:now-61000});await progress.recordHeartbeat({userId:a.user.id,workshopKey:WORKSHOP_KEY,now});}
  if(fullParity)evidence.fullAppParity=await require('../fixtures/legacyFileSsiFullAppParity').qualifyLegacyFullAppParity({backendPort:server.address().port,token:a.session.token,adminToken:fullParity.adminToken,studentId:a.user.id,runtimeRoot:root});
  if(process.env.LEGACY_CANDIDATE_RENDERED==='1'){evidence.rendered=await require('../fixtures/legacyFileSsiRendered').qualifyLegacyFileSsiRendered({backendPort:server.address().port,token:a.session.token,runtimeRoot:root});await request(a);}

  const negative=await request(a,'denied path');assert.equal(negative.status,200);assert.equal(negative.body.completed,false);
  const retained=(await pool.query('SELECT count(*)::int AS n FROM workshop_platform.objective_judgments')).rows[0].n;
  const resetId=randomUUID();const httpReset=await fetch(endpoint.replace('/chat','/reset'),{method:'POST',headers:{authorization:'Bearer '+a.session.token,'x-reset-operation-id':resetId}});assert.equal(httpReset.status,200);assert.equal((await progress.getWorkshopProgress(a.user.id,'legacy_sensitive_file_ssi')).completedObjectiveCount,0);assert.equal((await progress.getWorkshopProgress(b.user.id,'legacy_sensitive_file_ssi')).completedObjectiveCount,1);
  assert.equal((await pool.query('SELECT count(*)::int AS n FROM workshop_platform.objective_judgments')).rows[0].n,retained);
  assert.equal(JSON.stringify(await finflowStore.getProgress(String(a.user.id))),finflowBefore);
  assert.equal((await request(a)).body.completed,true);
  const aliasReset=await fetch(endpoint.replace('/canonical-agent/chat','/progress/reset'),{method:'POST',headers:{authorization:'Bearer '+a.session.token,'x-reset-operation-id':resetId}});assert.equal(aliasReset.status,200);assert.equal(JSON.stringify(await finflowStore.getProgress(String(a.user.id))),finflowBefore);
  await composition.application.reset(a.user.id,{operationId:resetId});assert.equal((await progress.getWorkshopProgress(a.user.id,'legacy_sensitive_file_ssi')).completedObjectiveCount,1,'Completed operation replay preserves newer completion');
  const legacyBefore=JSON.stringify(await progress.getWorkshopProgress(a.user.id,'legacy_sensitive_file_ssi'));
  const drainsBefore=legacyAggregateDrains,finflowOperation=randomUUID();await aggregate.reset(a.user.id,{operationId:finflowOperation});
  assert.equal((await aggregateJournal.read(finflowOperation)).planVersion,2);assert.equal(legacyAggregateDrains,drainsBefore);
  assert.equal(JSON.stringify(await progress.getWorkshopProgress(a.user.id,'legacy_sensitive_file_ssi')),legacyBefore);
  const persistedPlan=(await pool.query('SELECT step_key FROM identity.sensitive_info_reset_steps WHERE operation_id=$1',[finflowOperation])).rows.map(x=>x.step_key);assert.deepEqual(persistedPlan,['finflow_store']);
  await finflowStore.completeObjective(String(a.user.id),'tool_enum');finflowBefore=JSON.stringify(await finflowStore.getProgress(String(a.user.id)));
  const interruptedId=randomUUID();let interrupt=true;const interrupted=require('../../server/services/legacyFileSsiReset').createLegacyFileSsiReset({legacyRuns:runs,journal:resetComposition.journal,cleanup:{...resetComposition.cleanup,apply:async value=>{const result=await resetComposition.cleanup.apply(value);if(interrupt){interrupt=false;throw Error('controlled lost response after actual cleanup');}return result;}}});
  await assert.rejects(interrupted.reset(a.user.id,{operationId:interruptedId}),/controlled lost response/);
  await assert.rejects(interrupted.reset(a.user.id,{operationId:randomUUID()}),/Different legacy reset operation/);
  await interrupted.reset(a.user.id,{operationId:interruptedId});assert.equal((await progress.getWorkshopProgress(a.user.id,'legacy_sensitive_file_ssi')).completedObjectiveCount,0);
  assert.equal(JSON.stringify(await finflowStore.getProgress(String(a.user.id))),finflowBefore);
  hold=true;const started=new Promise(resolve=>{entered=resolve;});const pending=request(a);await started;const resetting=composition.application.reset(a.user.id,{operationId:randomUUID()});await new Promise(resolve=>setImmediate(resolve));release();await resetting;assert.notEqual((await pending).body.completed,true);hold=false;
  const compound=await request(a,'read then failed SSI');assert.equal(compound.status,200);assert.equal(compound.body.completed,false);assert.equal(compound.body.objectiveId,'ai_assisted_ssi');
  assert.deepEqual(compound.body.judgments.map(j=>[j.objectiveId,j.completed]),[['ai_assisted_path_traversal',true],['ai_assisted_ssi',false]]);assert.deepEqual(compound.body.completedObjectives,['ai_assisted_path_traversal']);
  assert.equal((await progress.getWorkshopProgress(a.user.id,'legacy_sensitive_file_ssi')).completedObjectiveCount,1);evidence.perObservationPartialCredit=true;
  if(process.env.LEGACY_CANDIDATE_BULK==='1')evidence.bulk=await require('../fixtures/legacyFileSsiBulkReplay').qualifyLegacyFileSsiBulkReplay({pool,migration,finflow,identity,owner,owners:[a,b],progress,resetComposition,runs,request});
  await migration.query('UPDATE identity.user_sessions SET is_active=0 WHERE id=$1',[a.session.internalSessionId]);const before=calls;assert.equal((await request(a)).status,401);assert.equal(calls,before);
  const admin=await owner();await migration.query("UPDATE identity.users SET role='admin',admin_level=2 WHERE id=$1",[admin.user.id]);
  const pendingDeletionReset=randomUUID();await resetComposition.journal.begin({ownerId:a.user.id,operationId:pendingDeletionReset});
  const deletion=require('../../server/database/postgres/studentDeletionRepository').createStudentDeletionRepository(pool,{steps:['revoke_runs','finflow','identity']});
  const deletionJob=await deletion.admit({requesterId:admin.user.id,subjectId:a.user.id});const lease=await deletion.claim(deletionJob.jobId);
  await require('../../server/services/studentDeletionRunDrain').createStudentDeletionRunDrain({pool,ledger:require('../../server/agent-runtime/postgresRunLedger').createPostgresRunLedger(pool)})({subjectId:a.user.id,jobId:deletionJob.jobId,check:()=>deletion.renew({...lease,jobId:deletionJob.jobId})});
  await deletion.acknowledge({...lease,jobId:deletionJob.jobId,stepKey:'revoke_runs'});
  const resourceLifecycle=await require('../../server/services/finflowDurableResourceComposition').createFinflowDurableResourceLifecycle({pool:finflow,appDataRoot:path.join(root,'resources')});
  await resourceLifecycle.cleanupOwner({subjectId:a.user.id,jobId:deletionJob.jobId,leaseToken:lease.leaseToken,check:()=>deletion.renew({...lease,jobId:deletionJob.jobId})});
  await finflow.query('SELECT finflow.destroy_student_owner($1::bigint,$2::uuid)',[a.user.id,deletionJob.jobId]);
  await deletion.acknowledge({...lease,jobId:deletionJob.jobId,stepKey:'finflow'});
  await pool.query('SELECT identity.finalize_student_deletion($1,$2,$3)',[deletionJob.jobId,lease.leaseToken,a.user.id]);
  await deletion.acknowledge({...lease,jobId:deletionJob.jobId,stepKey:'identity'});await deletion.complete({...lease,jobId:deletionJob.jobId});
  assert.ok(!(await resetComposition.journal.listRecoverable()).includes(pendingDeletionReset));
  await assert.rejects(resetComposition.reset.recover(pendingDeletionReset),{code:'LEGACY_FILE_SSI_OWNER_UNAVAILABLE'});
  assert.equal((await pool.query('SELECT username FROM identity.users WHERE id=$1',[a.user.id])).rows[0].username,'deleted-'+deletionJob.jobId);
  assert.equal((await progress.getWorkshopProgress(b.user.id,'legacy_sensitive_file_ssi')).completedObjectiveCount,1);
  Object.assign(evidence,{status:'passed',canonicalCredit:true,controlledNegative:true,resetPreservesHistoryAndSibling:true,heldResponseResetFenced:true,revokedBearerRejected:true,actorCalls:calls,splitResetPlans:true,deletedOwnerRecoveryExcluded:true,scopedDeletionFinalizer:true});
 }catch(error){evidence.failure={code:error.code||null,message:error.message};throw error;}finally{renderedAuth?.close();fullParity?.close();if(server)await new Promise(resolve=>server.close(resolve));await require('../../server/database/postgres').closePostgresPools();await Promise.all([migration.end(),finflowMigration.end(),finflow.end(),freshIdentity.end()]);if(root)fs.rmSync(root,{recursive:true,force:true});fs.writeFileSync(process.env.WORKSHOP_RAG_EVIDENCE_PATH,JSON.stringify(evidence,null,2)+'\n',{mode:0o600});}
});
