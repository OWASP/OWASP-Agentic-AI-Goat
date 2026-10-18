'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path');
test('native deletion admission authorizes, deduplicates and revokes atomically',{skip:process.env.PG_TEST_DISPOSABLE!=='yes'||!process.env.PG_DELETION_RUNTIME_URL},async()=>{
 const {createPool}=require('../../server/database/postgres');
 for(const key of ['PG_DELETION_RUNTIME_URL','PG_DELETION_MIGRATION_URL'])assert.match(new URL(process.env[key]).pathname,/^\/dvaia_test_/);
 const runtime=createPool(process.env,'PG_DELETION_RUNTIME_URL'),migration=createPool(process.env,'PG_DELETION_MIGRATION_URL');
 try{
  const {initializeIdentityRepository,createIdentityRepository}=require('../../server/database/postgres/identityRepository');
  await initializeIdentityRepository(runtime,migration);
  await migration.query(await fs.readFile(path.resolve(__dirname,'../../docs/modernization/drafts/student-deletion-journal.sql'),'utf8'));
  const users=createIdentityRepository(runtime),passwordHash=await require('bcryptjs').hash('owned fixture',4);
  const create=name=>users.createUser({username:name,email:name+'@fixture.test',passwordHash});
  const admin=await create('admin_fixture'),student=await create('student_fixture'),other=await create('other_fixture');
  await migration.query("UPDATE identity.users SET role='admin',admin_level=2 WHERE id=$1",[admin.id]);
  await users.createSession({userId:student.id,token:'owned-fixture-session-token-1234567890',expiresAt:new Date(Date.now()+60000),expectedPasswordHash:passwordHash,deviceInfo:{}});
  const {createStudentDeletionRepository}=require('../../server/database/postgres/studentDeletionRepository');
  const repository=createStudentDeletionRepository(runtime,{steps:['revoke_runs','excessive_agency','identity']});
  await assert.rejects(repository.admit({requesterId:other.id,subjectId:student.id}),{code:'ADMIN_REQUIRED'});
  const attempts=await Promise.all([repository.admit({requesterId:admin.id,subjectId:student.id}),repository.admit({requesterId:admin.id,subjectId:student.id})]);
  assert.equal(attempts[0].jobId,attempts[1].jobId);assert.equal(attempts.filter(x=>!x.replayed).length,1);
  assert.deepEqual(await repository.listRecoverable(),[attempts[0].jobId]);
  assert.equal((await runtime.query('SELECT is_active FROM identity.users WHERE id=$1',[student.id])).rows[0].is_active,0);
  const blockedOwner=JSON.stringify(['MCP',String(student.id)]);
  await runtime.query('INSERT INTO graph_runtime.owners(owner_key) VALUES($1) ON CONFLICT DO NOTHING',[blockedOwner]);
  await assert.rejects(runtime.query("INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status) VALUES($1,$2,0,'running')",[require('node:crypto').randomUUID(),blockedOwner]),{code:'23514'});
  const blockedSensitiveLookup=JSON.stringify(['SensitiveLookup',String(student.id)]);
  await runtime.query('INSERT INTO graph_runtime.owners(owner_key) VALUES($1) ON CONFLICT DO NOTHING',[blockedSensitiveLookup]);
  await assert.rejects(runtime.query("INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status) VALUES($1,$2,0,'running')",[require('node:crypto').randomUUID(),blockedSensitiveLookup]),{code:'23514'});
  assert.equal((await runtime.query('SELECT count(*)::int n FROM identity.student_deletion_run_blocks WHERE job_id=$1',[attempts[0].jobId])).rows[0].n,require('../../server/database/postgres/agentRunReadRepository').RUN_FAMILIES.length);
  await assert.rejects(runtime.query('UPDATE identity.users SET is_active=1 WHERE id=$1',[student.id]),{code:'23514'});
  await assert.rejects(runtime.query("UPDATE identity.users SET role='admin',admin_level=2 WHERE id=$1",[student.id]),{code:'23514'});
  assert.equal((await runtime.query('SELECT count(*)::int n FROM identity.user_sessions WHERE user_id=$1 AND is_active=1',[student.id])).rows[0].n,0);
  assert.equal((await runtime.query('SELECT count(*)::int n FROM identity.student_deletion_steps WHERE job_id=$1',[attempts[0].jobId])).rows[0].n,3);
  assert.equal((await runtime.query('SELECT is_active FROM identity.users WHERE id=$1',[other.id])).rows[0].is_active,1);
  const claims=await Promise.all([repository.claim(attempts[0].jobId),repository.claim(attempts[0].jobId)]);
  assert.equal(claims.filter(Boolean).length,1);
  const lease=claims.find(Boolean);
  assert.deepEqual(await repository.listRecoverable(),[]);
  assert.deepEqual(await repository.nextStep({jobId:attempts[0].jobId,leaseToken:lease.leaseToken}),{subjectId:student.id,stepKey:'revoke_runs'});
  await assert.rejects(repository.acknowledge({jobId:attempts[0].jobId,leaseToken:lease.leaseToken,stepKey:'identity'}),{code:'DELETION_STEP_OUT_OF_ORDER'});
  await repository.acknowledge({jobId:attempts[0].jobId,leaseToken:lease.leaseToken,stepKey:'revoke_runs'});
  await migration.query("UPDATE identity.student_deletion_jobs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE job_id=$1",[attempts[0].jobId]);
  // A fresh repository after restart discovers the expired job from PostgreSQL.
  const recovered=createStudentDeletionRepository(runtime,{steps:['revoke_runs','excessive_agency','identity']});
  assert.deepEqual(await recovered.listRecoverable(),[attempts[0].jobId]);
  const replacement=await repository.claim(attempts[0].jobId);
  assert.ok(replacement);assert.notEqual(replacement.leaseToken,lease.leaseToken);
  await assert.rejects(repository.acknowledge({jobId:attempts[0].jobId,leaseToken:lease.leaseToken,stepKey:'excessive_agency'}),{code:'STALE_DELETION_LEASE'});
  await repository.acknowledge({jobId:attempts[0].jobId,leaseToken:replacement.leaseToken,stepKey:'excessive_agency'});
  await repository.renew({jobId:attempts[0].jobId,leaseToken:replacement.leaseToken});
  await repository.fail({jobId:attempts[0].jobId,leaseToken:replacement.leaseToken,stepKey:'identity'});
  assert.deepEqual(await recovered.listRecoverable(),[]);
  await migration.query("UPDATE identity.student_deletion_jobs SET updated_at=clock_timestamp()-interval '31 seconds' WHERE job_id=$1",[attempts[0].jobId]);
  assert.deepEqual(await recovered.listRecoverable(),[attempts[0].jobId]);
  await assert.rejects(repository.renew({jobId:attempts[0].jobId,leaseToken:replacement.leaseToken}),{code:'STALE_DELETION_LEASE'});
  const retryLease=await repository.claim(attempts[0].jobId);assert.ok(retryLease);
  assert.deepEqual(await repository.nextStep({jobId:attempts[0].jobId,leaseToken:retryLease.leaseToken}),{subjectId:student.id,stepKey:'identity'});
  assert.equal((await runtime.query("SELECT error_code FROM identity.student_deletion_steps WHERE job_id=$1 AND step_key='identity'",[attempts[0].jobId])).rows[0].error_code,'CLEANUP_FAILED');
  await assert.rejects(repository.complete({jobId:attempts[0].jobId,leaseToken:retryLease.leaseToken}),{code:'DELETION_INCOMPLETE'});
  await assert.rejects(repository.acknowledge({jobId:attempts[0].jobId,leaseToken:retryLease.leaseToken,stepKey:'identity'}),{code:'DELETION_IDENTITY_REMAINS'});
  await repository.fail({jobId:attempts[0].jobId,leaseToken:retryLease.leaseToken,stepKey:'identity'});
  let identityAttempts=0;
  const identityWorker=require('../../server/services/studentDeletionWorker').createStudentDeletionWorker({repository,adapters:{
   revoke_runs:async()=>({completed:true}),excessive_agency:async()=>({completed:true}),identity:async({subjectId})=>{
    identityAttempts++;
    if(identityAttempts===2)await migration.query('DELETE FROM identity.users WHERE id=$1',[subjectId]);
    return{completed:true};
   },
  }});
  assert.deepEqual(await identityWorker.run(attempts[0].jobId),{state:'incomplete',code:'DELETION_INCOMPLETE'});
  assert.equal((await runtime.query("SELECT state FROM identity.student_deletion_steps WHERE job_id=$1 AND step_key='identity'",[attempts[0].jobId])).rows[0].state,'failed');
  assert.deepEqual(await identityWorker.run(attempts[0].jobId),{state:'completed'});
  assert.equal(identityAttempts,2,'A false identity receipt is failed and retried instead of acknowledged forever');

  if(process.env.PG_DELETION_EA_RUNTIME_URL && process.env.PG_DELETION_EA_MIGRATION_URL){
    for(const key of ['PG_DELETION_EA_RUNTIME_URL','PG_DELETION_EA_MIGRATION_URL'])assert.match(new URL(process.env[key]).pathname,/^\/dvaia_test_/);
    const eaRuntime=createPool(process.env,'PG_DELETION_EA_RUNTIME_URL'),eaMigration=createPool(process.env,'PG_DELETION_EA_MIGRATION_URL');
    try{
      const manager=require('../../server/database/postgres/excessiveAgencyLabDb').createExcessiveAgencyDatabaseManager(eaRuntime);
      await manager.initialize(eaMigration);
      const store=require('../../server/services/excessiveAgencyAttendeeLabStore').createPostgresExcessiveAgencyAttendeeLabStore({manager});
      const target=await create('composed_target'),sibling=await create('composed_sibling');
      await store.getOrCreate(String(target.id));await store.getOrCreate(String(sibling.id));
      const ledger=require('../../server/agent-runtime/postgresRunLedger').createPostgresRunLedger(runtime);
      const coordinator=require('../../server/agent-runtime/runCoordinator').createRunCoordinator({family:'ExcessiveAgency',ledger});
      let cleanups=0;
      const adapters=require('../../server/services/studentDeletionAdapters').createStudentDeletionAdapters(name=>{
        if(name==='./postgresIdentityAdapter')return{getPostgresIdentityAdapter:()=>({pool:runtime})};
        if(name==='../agent-runtime/postgresRunLedger')return{configuredRunLedger:()=>ledger};
        if(name==='./studentDeletionRunDrain')return require('../../server/services/studentDeletionRunDrain');
        if(name==='../routes/excessiveAgencyLab')return{resetOwner:(owner,work)=>coordinator.reset(owner,work)};
        if(name==='./excessiveAgencyAttendeeLabStore')return{excessiveAgencyAttendeeLabStore:{destroyAttendee:async owner=>{cleanups++;return store.destroyAttendee(owner);}}};
        throw Error('Unexpected adapter dependency');
      });
      const jobs=createStudentDeletionRepository(runtime,{steps:['revoke_runs','excessive_agency','identity']});
      const job=await jobs.admit({requesterId:admin.id,subjectId:target.id});
      const worker=require('../../server/services/studentDeletionWorker').createStudentDeletionWorker({repository:jobs,adapters});
      assert.equal((await worker.run(job.jobId)).state,'incomplete');
      assert.equal((await worker.run(job.jobId)).state,'incomplete');assert.equal(cleanups,1);
      assert.equal((await eaRuntime.query('SELECT count(*)::int n FROM excessive_agency.attendees WHERE platform_user_id=$1',[String(target.id)])).rows[0].n,0);
      assert.equal((await eaRuntime.query('SELECT count(*)::int n FROM excessive_agency.notes WHERE platform_user_id=$1',[String(sibling.id)])).rows[0].n,25);
      const state=(await runtime.query('SELECT step_key,state FROM identity.student_deletion_steps WHERE job_id=$1 ORDER BY ordinal',[job.jobId])).rows;
      assert.deepEqual(state,[{step_key:'revoke_runs',state:'completed'},{step_key:'excessive_agency',state:'completed'},{step_key:'identity',state:'failed'}]);
    }finally{await Promise.all([eaRuntime.end(),eaMigration.end()]);}
  }

  // A lease checked at transaction entry can expire while a later row lock is
  // blocked. Every state mutation must recheck the lease at its commit edge so
  // the complete transaction rolls back and a successor can claim authority.
  const delayed=[];
  for(const action of ['acknowledge','fail','complete']){
   const subject=await create(`lease_${action}`);
   const job=await repository.admit({requesterId:admin.id,subjectId:subject.id});
   if(action==='complete'){
    await migration.query("UPDATE identity.student_deletion_steps SET state='completed',completed_at=clock_timestamp() WHERE job_id=$1",[job.jobId]);
    await migration.query('DELETE FROM identity.users WHERE id=$1',[subject.id]);
   }
   delayed.push({action,job});
  }
  const blocker=await migration.connect();
  try{
   for(const {action,job} of delayed){
    const lease=await repository.claim(job.jobId,1000);
    assert.ok(lease);
    await blocker.query('BEGIN');
    await blocker.query(`SELECT job_id FROM identity.student_deletion_steps
      WHERE job_id=$1 AND step_key='revoke_runs' FOR UPDATE`,[job.jobId]);
    const args={jobId:job.jobId,leaseToken:lease.leaseToken};
    const operation=action==='acknowledge'?repository.acknowledge({...args,stepKey:'revoke_runs'})
     :action==='fail'?repository.fail({...args,stepKey:'revoke_runs'}):repository.complete(args);
    const settled=operation.then(value=>({value}),error=>({error}));
    let waiting=0;
    for(let attempt=0;attempt<100;attempt++){
     waiting=(await blocker.query("SELECT count(*)::int AS n FROM pg_locks WHERE NOT granted AND locktype='transactionid'")).rows[0].n;
     if(waiting>=1)break;
     await new Promise(resolve=>setTimeout(resolve,10));
    }
    assert.ok(waiting>=1,`${action} reached a real PostgreSQL row-lock wait`);
    await new Promise(resolve=>setTimeout(resolve,1100));
    await blocker.query('COMMIT');
    assert.equal((await settled).error?.code,'STALE_DELETION_LEASE');
   }
  }finally{
   await blocker.query('ROLLBACK');blocker.release();
  }
  for(const {action,job} of delayed){
   const state=(await runtime.query('SELECT state,completed_at FROM identity.student_deletion_jobs WHERE job_id=$1',[job.jobId])).rows[0];
   assert.equal(state.state,'running',`${action} did not commit after lease expiry`);
   assert.equal(state.completed_at,null);
   if(action!=='complete')assert.equal((await runtime.query("SELECT state FROM identity.student_deletion_steps WHERE job_id=$1 AND step_key='revoke_runs'",[job.jobId])).rows[0].state,'pending');
   assert.ok(await repository.claim(job.jobId),'An expired mutation leaves the job claimable by a successor');
  }

  await migration.query("CREATE FUNCTION identity.reject_deletion_step() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture rollback'; END $$; CREATE TRIGGER reject_step BEFORE INSERT ON identity.student_deletion_steps FOR EACH ROW EXECUTE FUNCTION identity.reject_deletion_step()");
  await assert.rejects(repository.admit({requesterId:admin.id,subjectId:other.id}),/fixture rollback/);
  assert.equal((await runtime.query('SELECT is_active FROM identity.users WHERE id=$1',[other.id])).rows[0].is_active,1);
  assert.equal((await runtime.query('SELECT count(*)::int n FROM identity.student_deletion_jobs WHERE subject_user_id=$1',[other.id])).rows[0].n,0);
 }finally{await Promise.all([runtime.end(),migration.end()]);}
});
