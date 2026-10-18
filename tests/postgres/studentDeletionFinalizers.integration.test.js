'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),path=require('node:path');
const {Pool}=require('pg');
const {migrate}=require('../../db/postgres/migrate');
const {initializeIdentityRepository,createIdentityRepository}=require('../../server/database/postgres/identityRepository');
const {createStudentDeletionRepository}=require('../../server/database/postgres/studentDeletionRepository');
const {createXssWorkshopDb}=require('../../server/database/postgres/xssWorkshopDb');
const {createFinflowWorkshopDb}=require('../../server/database/postgres/sensitiveInfoWorkshopDb');
const {createFinflowDurableResourceRepository}=require('../../server/database/postgres/finflowDurableResourceRepository');
const {createFinflowOwnerResourceDeletion}=require('../../server/services/finflowOwnerResourceDeletion');
const {createStudentDeletionStoreCleanup}=require('../../server/services/studentDeletionStoreCleanup');
const PREFIX='PG_STUDENT_DELETION_FINALIZER_';
const keys=['IDENTITY_MIGRATION_URL','IDENTITY_RUNTIME_URL','XSS_MIGRATION_URL','XSS_RUNTIME_URL','FINFLOW_MIGRATION_URL','FINFLOW_RUNTIME_URL'];
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&keys.every(key=>process.env[PREFIX+key]);
function url(key){const value=new URL(process.env[PREFIX+key]);assert.ok(['127.0.0.1','localhost'].includes(value.hostname));assert.match(value.pathname,/^\/dvaia_test_[a-z0-9_]+$/);return value.href;}
test('native deletion finalizers remove exact owner content, preserve siblings, and replay safely',{skip:!enabled,timeout:60000},async()=>{
 const im=new Pool({connectionString:url('IDENTITY_MIGRATION_URL')}),i=new Pool({connectionString:url('IDENTITY_RUNTIME_URL')});
 const xm=new Pool({connectionString:url('XSS_MIGRATION_URL')}),x=new Pool({connectionString:url('XSS_RUNTIME_URL')});
 const fm=new Pool({connectionString:url('FINFLOW_MIGRATION_URL')}),f=new Pool({connectionString:url('FINFLOW_RUNTIME_URL')});
 try{
  const identityApplied=await initializeIdentityRepository(i,im);
  const expectedIdentity=(await require('../../db/postgres/migrate').readMigrations(path.resolve(__dirname,'../../db/postgres/identity-migrations'))).map(row=>row.name);
  assert.ok(identityApplied.includes('0079_xss_deletion_redaction_recovery_filter.sql'));
  assert.ok(identityApplied.includes('0080_legacy_ai_private_history.sql'));
  assert.deepEqual(identityApplied,expectedIdentity);
  await createXssWorkshopDb(x).initializeXssWorkshopDb(xm);
  await createFinflowWorkshopDb(f).initialize(fm);
  assert.deepEqual(await initializeIdentityRepository(i,im),[],'identity migration replay must be empty');
  assert.deepEqual(await migrate(xm,path.resolve(__dirname,'../../db/postgres/workshop-migrations/xss')),[],
    'XSS migration replay must be empty');
  assert.deepEqual(await migrate(fm,path.resolve(__dirname,'../../db/postgres/workshop-migrations/finflow')),[],
    'FinFlow migration replay must be empty');
  const identities=createIdentityRepository(i),password='$2b$12$000000000000000000000uG3W0Jp6IPhhD1TRqN8Yc2zJQG3vVnSA';
  const subject=await identities.createUser({username:'delete-subject',email:'delete-subject@test.invalid',passwordHash:password});
  const sibling=await identities.createUser({username:'delete-sibling',email:'delete-sibling@test.invalid',passwordHash:password});
  const session=await identities.createSession({userId:subject.id,token:'subject-session',expiresAt:new Date(Date.now()+3600000),expectedPasswordHash:password});
  await im.query("INSERT INTO workshop_platform.exercises(workshop_key,challenge_key,challenge_name,ordinal) VALUES('delete_fixture','delete-fixture','Delete fixture',999); INSERT INTO workshop_platform.objectives(workshop_key,objective_id,label,ordinal) VALUES('delete_fixture','one','One',1); INSERT INTO workshop_platform.exercises(workshop_key,challenge_key,challenge_name,ordinal) VALUES('xss_workshop','xss-deletion-fixture','XSS deletion fixture',998) ON CONFLICT(workshop_key) DO NOTHING; INSERT INTO workshop_platform.objectives(workshop_key,objective_id,label,ordinal) VALUES('xss_workshop','deletion_fixture','Deletion fixture',999) ON CONFLICT DO NOTHING");
  await i.query("INSERT INTO workshop_platform.user_state(user_id,workshop_key) VALUES($1,'delete_fixture')",[subject.id]);
  await i.query("INSERT INTO workshop_platform.completions(user_id,workshop_key,objective_id) VALUES($1,'delete_fixture','one')",[subject.id]);
  await i.query("INSERT INTO workshop_platform.objective_judgments(user_id,evaluation_id,workshop_key,objective_id,family,scenario,rubric_version,evidence_digest,generation,verdict,result_json,disposition,evaluated_at) VALUES($1,'11111111-1111-4111-8111-111111111111','delete_fixture','one','fixture','fixture','v1',$2,0,'pass',$3,'awarded',clock_timestamp())",[subject.id,'a'.repeat(64),JSON.stringify({private:'remove-me'})]);
  await i.query("INSERT INTO workshop_platform.objective_judgments(user_id,evaluation_id,workshop_key,objective_id,family,scenario,rubric_version,evidence_digest,generation,disposition) VALUES($1,'66666666-6666-4666-8666-666666666666','delete_fixture','one','fixture','recoverable','v1',$2,0,'pending')",[subject.id,'c'.repeat(64)]);
  await i.query("INSERT INTO workshop_platform.objective_judgments(user_id,evaluation_id,workshop_key,objective_id,family,scenario,rubric_version,evidence_digest,generation,verdict,result_json,disposition,evaluated_at) VALUES($1,'77777777-7777-4777-8777-777777777777','delete_fixture','one','fixture','unavailable','v1',$2,0,'unavailable',$3,'not_pass',clock_timestamp())",[subject.id,'d'.repeat(64),JSON.stringify({private:'unavailable-detail'})]);
  await i.query("INSERT INTO workshop_platform.objective_judgments(user_id,evaluation_id,workshop_key,objective_id,family,scenario,rubric_version,evidence_digest,generation,verdict,result_json,result_digest,disposition,evaluated_at) VALUES($1,'88888888-8888-4888-8888-888888888888','xss_workshop','deletion_fixture','XSS','deletion-finalizer','v1',$2,0,'pass',$3,$4,'awarded',clock_timestamp())",[subject.id,'e'.repeat(64),JSON.stringify({private:'xss-remove-me'}),'f'.repeat(64)]);
  const xssJudgmentBefore=(await i.query(`SELECT to_jsonb(j)-ARRAY['result_json','result_digest'] AS retained
    FROM workshop_platform.objective_judgments j WHERE user_id=$1
      AND evaluation_id='88888888-8888-4888-8888-888888888888'`,[subject.id])).rows[0].retained;
  await assert.rejects(i.query(`INSERT INTO identity.xss_deletion_redaction_authority
    (backend_pid,transaction_id,job_id,lease_token,subject_user_id)
    VALUES(pg_backend_pid(),txid_current(),'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',$1)`,[subject.id]),{code:'42501'});
  await i.query("INSERT INTO workshop_platform.objective_evidence(user_id,workshop_key,scenario,generation,run_id,evidence_id,evidence_json,evidence_digest,expires_at) VALUES($1,'delete_fixture','fixture',0,'22222222-2222-4222-8222-222222222222','owned',$2,$3,clock_timestamp()+interval '1 hour')",[subject.id,JSON.stringify({private:'remove-me'}),'b'.repeat(64)]);
  for(const id of [subject.id,sibling.id]){await x.query('INSERT INTO xss.profiles(user_key,name,bio,website) VALUES($1,$2,$3,$4)',[String(id),`name-${id}`,`bio-${id}`,'https://example.invalid']);await x.query('INSERT INTO xss.progress(user_key,objective_id,completed) VALUES($1,\'stored_xss\',1)',[String(id)]);await f.query("INSERT INTO finflow.progress(user_id,objective_id,completed,completed_at) SELECT $1,objective_id,true,clock_timestamp() FROM finflow.objectives ORDER BY ordinal LIMIT 1",[String(id)]);await f.query('INSERT INTO legacy_sensitive.owner_state(user_id,generation) VALUES($1,2)',[id]);}
  const job='33333333-3333-4333-8333-333333333333',lease='44444444-4444-4444-8444-444444444444';
  const subjectChild='99999999-9999-4999-8999-999999999991',siblingChild='99999999-9999-4999-8999-999999999992';
  const subjectParent='99999999-9999-4999-8999-999999999993',siblingParent='99999999-9999-4999-8999-999999999994';
  for(const [operationId,ownerId] of [[subjectChild,subject.id],[siblingChild,sibling.id]])await im.query(`INSERT INTO identity.xss_profile_reset_operations
    (operation_id,owner_id,owner_key,graph_parent_generation,workshop_generation,stored_user_from,stored_user_to,stored_llm_from,stored_llm_to)
    VALUES($1,$2::integer,'["XSS","'||($2::integer)::text||'"]',0,0,0,1,0,1)`,[operationId,ownerId]);
  for(const [operationId,ownerId] of [[subjectParent,subject.id],[siblingParent,sibling.id]])await im.query(`INSERT INTO identity.xss_parent_reset_operations
    (operation_id,owner_id,owner_key,workshop_generation_from) VALUES($1,$2::integer,'["XSS","'||($2::integer)::text||'"]',0)`,[operationId,ownerId]);
  await i.query("INSERT INTO identity.student_deletion_jobs(job_id,subject_user_id,requested_by,state,lease_token,lease_expires_at) VALUES($1,$2,$3,'running',$4,clock_timestamp()+interval '1 hour')",[job,subject.id,sibling.id,lease]);
  for(const [n,key] of ['revoke_runs','xss','finflow','identity'].entries())await i.query("INSERT INTO identity.student_deletion_steps(job_id,step_key,ordinal,state,completed_at) VALUES($1,$2,$3,$4,CASE WHEN $4='completed' THEN clock_timestamp() END)",[job,key,n,key==='identity'?'pending':'completed']);
  await i.query('UPDATE identity.users SET is_active=0 WHERE id=$1',[subject.id]);
  assert.deepEqual((await i.query('SELECT operation_id FROM identity.list_recoverable_xss_profile_resets(10)')).rows,
    [{operation_id:siblingChild}], 'deleting owner child journal remains retained but is not recoverable');
  assert.deepEqual((await i.query('SELECT operation_id FROM identity.list_recoverable_xss_parent_resets(10)')).rows,
    [{operation_id:siblingParent}], 'deleting owner parent journal remains retained but is not recoverable');
  await assert.rejects(i.query(`UPDATE workshop_platform.objective_judgments SET
    result_json='{"deleted":true}'::jsonb,result_digest=NULL
    WHERE user_id=$1 AND evaluation_id='88888888-8888-4888-8888-888888888888'`,[subject.id]),{code:'55000'});
  await i.query("INSERT INTO identity.email_agent_progress(user_key,objective_number,completed) VALUES($1,1,1),($2,2,1),($3,3,1)",[String(subject.id),subject.username,subject.email]);
  await i.query("INSERT INTO identity.sent_emails_log(user_key,recipient_email) VALUES($1,'one@test.invalid'),($2,'two@test.invalid'),($3,'three@test.invalid')",[String(subject.id),subject.username,subject.email]);
  const cleanup=createStudentDeletionStoreCleanup({identityPool:i,xssPool:x,finflowPool:f}),scope={subjectId:subject.id,jobId:job,leaseToken:lease,check:async()=>{}};
  assert.deepEqual(await cleanup.xss(scope),{completed:true,removed:2});assert.deepEqual(await cleanup.xss(scope),{completed:true,removed:0});
  const cleanupFinflowResources=createFinflowOwnerResourceDeletion({
    repository:createFinflowDurableResourceRepository(f),
    files:{async remove(tokens){assert.deepEqual(tokens,[]);},async absent(){return true;}},
  });
  const physicalReceipt=await cleanupFinflowResources(scope);
  assert.deepEqual({completed:physicalReceipt.completed,ownerId:physicalReceipt.ownerId,
    jobId:physicalReceipt.jobId,artifactCount:physicalReceipt.artifactCount,datasetCount:physicalReceipt.datasetCount},
  {completed:true,ownerId:subject.id,jobId:job,artifactCount:0,datasetCount:0});
  assert.deepEqual(await cleanup.finflow(scope),{completed:true,removed:2});
  await assert.rejects(cleanup.identity({...scope,jobId:job,leaseToken:'55555555-5555-4555-8555-555555555555'}));
  assert.deepEqual(await cleanup.identity({...scope,jobId:job,leaseToken:lease}),{completed:true});
  assert.deepEqual(await cleanup.identity({...scope,jobId:job,leaseToken:lease}),{completed:true});
  const jobs=createStudentDeletionRepository(i,{steps:['revoke_runs','xss','finflow','identity']});
  assert.deepEqual(await jobs.acknowledge({jobId:job,leaseToken:lease,stepKey:'identity'}),{completed:true});
  assert.deepEqual(await jobs.complete({jobId:job,leaseToken:lease}),{state:'completed'});
  const deleted=(await i.query('SELECT username,email,full_name,is_active FROM identity.users WHERE id=$1',[subject.id])).rows[0];
  assert.equal(deleted.username,`deleted-${job}`);assert.equal(deleted.email,`deleted-${job}@invalid.local`);assert.equal(deleted.full_name,null);assert.equal(deleted.is_active,0);
  assert.equal((await i.query('SELECT count(*)::integer n FROM identity.user_sessions WHERE user_id=$1',[subject.id])).rows[0].n,0);
  assert.equal((await i.query('SELECT count(*)::integer n FROM workshop_platform.objective_evidence WHERE user_id=$1',[subject.id])).rows[0].n,0);
  assert.equal((await i.query('SELECT count(*)::integer n FROM workshop_platform.user_state WHERE user_id=$1',[subject.id])).rows[0].n,0);
  assert.equal((await i.query('SELECT count(*)::integer n FROM workshop_platform.completions WHERE user_id=$1',[subject.id])).rows[0].n,0);
  const judgments=(await i.query('SELECT verdict,result_json,result_digest FROM workshop_platform.objective_judgments WHERE user_id=$1 ORDER BY evaluation_id',[subject.id])).rows;
  assert.equal(judgments.length,4);assert.equal(judgments.find(row=>row.verdict===null).result_json,null);
  assert.ok(judgments.filter(row=>row.verdict!==null).every(row=>JSON.stringify(row.result_json)==='{"deleted":true}'));
  assert.ok(judgments.every(row=>row.result_digest===null));
  assert.deepEqual((await i.query(`SELECT to_jsonb(j)-ARRAY['result_json','result_digest'] AS retained
    FROM workshop_platform.objective_judgments j WHERE user_id=$1
      AND evaluation_id='88888888-8888-4888-8888-888888888888'`,[subject.id])).rows[0].retained,xssJudgmentBefore,
  'deletion finalizer changes only the documented judgment result fields');
  assert.equal((await im.query('SELECT count(*)::integer n FROM identity.xss_profile_reset_operations WHERE owner_id=$1',[subject.id])).rows[0].n,1);
  assert.equal((await im.query('SELECT count(*)::integer n FROM identity.xss_parent_reset_operations WHERE owner_id=$1',[subject.id])).rows[0].n,1);
  assert.equal((await im.query('SELECT count(*)::integer n FROM identity.xss_deletion_redaction_authority')).rows[0].n,0);
  assert.equal((await i.query('SELECT count(*)::integer n FROM identity.email_agent_progress WHERE user_key=ANY($1::text[])',[[String(subject.id),subject.username,subject.email]])).rows[0].n,0);
  assert.equal((await i.query('SELECT count(*)::integer n FROM identity.sent_emails_log WHERE user_key=ANY($1::text[])',[[String(subject.id),subject.username,subject.email]])).rows[0].n,0);
  assert.equal((await x.query('SELECT count(*)::integer n FROM xss.profiles WHERE user_key=$1',[String(sibling.id)])).rows[0].n,1);
  assert.equal((await f.query('SELECT count(*)::integer n FROM legacy_sensitive.owner_state WHERE user_id=$1',[sibling.id])).rows[0].n,1);
  assert.equal((await i.query('SELECT username FROM identity.users WHERE id=$1',[sibling.id])).rows[0].username,'delete-sibling');
 }finally{await Promise.allSettled([i.end(),im.end(),x.end(),xm.end(),f.end(),fm.end()]);}
});
