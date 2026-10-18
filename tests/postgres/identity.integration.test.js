'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const bcrypt=require('bcryptjs');
const {createPool}=require('../../server/database/postgres');
const {createIdentityRepository,initializeIdentityRepository}=require('../../server/database/postgres/identityRepository');
const {validateIdentityImport,importIdentity}=require('../../server/database/postgres/identityImport');
const {tokenHash}=require('../../server/database/postgres/identityValidation');
const {withPostgresStudentResetAdmission}=require('../../server/services/postgresWorkshopResetService');
const {createStudentDeletionRepository}=require('../../server/database/postgres/studentDeletionRepository');
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&Boolean(process.env.PG_IDENTITY_TEST_MIGRATION_URL);

async function waitForAdvisoryWait(observer,pid){
  const deadline=Date.now()+3000;
  while(Date.now()<deadline){
    const row=(await observer.query(`SELECT wait_event_type,wait_event FROM pg_stat_activity
      WHERE pid=$1`,[pid])).rows[0];
    if(row?.wait_event_type==='Lock'&&row.wait_event==='advisory')return;
    await new Promise(resolve=>setTimeout(resolve,10));
  }
  throw new Error('Deletion admission did not wait for the student lifecycle advisory lock');
}

test('identity import validates DTOs without opening source databases',async()=>{
  const hash=await bcrypt.hash('fixture-only',4);
  const user={id:7,username:'student',email:'student@example.test',password:hash,created_at:'2026-09-01 12:34:56'};
  const data=validateIdentityImport({users:[user]});
  assert.equal(data.users[0].id,7);assert.equal(data.users[0].password,hash);assert.equal(data.users[0].created_at,'2026-09-01T12:34:56.000Z');
  assert.throws(()=>validateIdentityImport({users:[{...user,password:'plain-secret'}]}),/bcrypt/);
  assert.throws(()=>validateIdentityImport({users:[{...user,is_active:'1'}]}),/flags/);
  assert.throws(()=>validateIdentityImport({users:[{...user,created_at:'09/01/2026'}]}),/timestamp/);
  assert.throws(()=>validateIdentityImport({users:[user,user]}),/Duplicate/);
  assert.throws(()=>validateIdentityImport({users:[{...user,unmapped_column:1}]}),/Unexpected/);
  assert.throws(()=>validateIdentityImport({users:[user],permissions:[{id:1,admin_id:8,permission_name:'system_logs',granted_at:user.created_at}]}),/missing user/);
  const report=await importIdentity(null,{users:[user]});assert.equal(report.dryRun,true);assert.equal(report.users,1);assert.ok(!JSON.stringify(report).includes(hash));
});

test('real PG18 identity: import, permissions, session ownership/expiry/revocation, atomic rotation and lockout', {skip:!enabled},async()=>{
  for(const key of ['PG_IDENTITY_TEST_MIGRATION_URL','PG_IDENTITY_TEST_RUNTIME_URL'])assert.match(new URL(process.env[key]).pathname,/^\/dvaia_test_[a-z0-9_]+$/);
  const migration=createPool(process.env,'PG_IDENTITY_TEST_MIGRATION_URL');
  const pool=createPool(process.env,'PG_IDENTITY_TEST_RUNTIME_URL');
  const lifecyclePool=createPool(process.env,'PG_IDENTITY_TEST_RUNTIME_URL',{purpose:'lease'});
  const deletionPool=createPool(process.env,'PG_IDENTITY_TEST_RUNTIME_URL');
  const repo=createIdentityRepository(pool);
  const hash1=await bcrypt.hash('old-fixture-password',4),hash2=await bcrypt.hash('new-fixture-password',4),hash3=await bcrypt.hash('third-fixture-password',4);
  const created='2026-09-01 12:34:56';
  const future=new Date(Date.now()+3600000).toISOString(),past=new Date(Date.now()-1000).toISOString();
  const input={
    users:[{id:17,username:'teacher',email:'teacher@example.test',password:hash1,role:'admin',admin_level:1,created_at:created},{id:21,username:'learner',email:'learner@example.test',password:hash1,created_at:created}],
    permissions:[{id:70,admin_id:17,permission_name:'user_management',granted_by:17,granted_at:created},{id:71,admin_id:17,permission_name:'system_logs',expires_at:past,granted_at:created}],
    sessions:[{id:31,user_id:17,session_token:'imported-active-token',expires_at:future,created_at:created,device_info:'{"platform":"macOS","password":"discard"}'},{id:32,user_id:21,session_token:'imported-revoked-token',expires_at:future,created_at:created,is_active:0}],
    audit:[{id:41,user_id:17,action_type:'user_login',action_details:JSON.stringify({method:'POST',url:'/login?password=hidden',password:'hidden',body:{token:'hidden'},timestamp:'2026-09-01T12:34:56Z'}),error_message:'credential secret',timestamp:created}],
  };
  try {
    assert.equal((await migration.query("SELECT to_regnamespace('identity') AS schema")).rows[0].schema,null,'Fresh test database required');
    await initializeIdentityRepository(pool,migration);
    const report=await importIdentity(migration,input,{dryRun:false});assert.equal(report.sessions,2);
    await assert.rejects(importIdentity(migration,input,{dryRun:false}),/empty/);
    const credential=await repo.findCredentialByUsername('teacher');assert.equal(credential.id,17);assert.equal(credential.password,hash1);
    assert.equal(await repo.findCredentialByUsername("teacher' OR 1=1 --"),null);
    assert.ok(!('password' in await repo.getUserById(17)));
    const newUser=await repo.createUser({username:'new-user',email:'new@example.test',passwordHash:hash1});assert.ok(newUser.id>21);assert.equal(newUser.role,'student');
    assert.equal(await repo.hasPermission(17,'user_management'),true);assert.equal(await repo.hasPermission(17,'system_logs'),false);assert.equal(await repo.hasPermission(21,'user_management'),false);
    await repo.grantPermission({userId:17,permission:'system_logs',grantedBy:17,expiresAt:future});assert.equal(await repo.hasPermission(17,'system_logs'),true);
    await repo.revokePermission(17,'system_logs');assert.equal(await repo.hasPermission(17,'system_logs'),false);
    await assert.rejects(repo.grantPermission({userId:17,permission:'unknown',grantedBy:17}),/Unknown/);
    const importedSession=await repo.findActiveSession('imported-active-token',17);assert.equal(importedSession.session.id,31);assert.ok(!('password' in importedSession.user));assert.deepEqual(importedSession.session.device_info,{platform:'macOS'});
    assert.equal(await repo.findActiveSession('imported-active-token',21),null);
    assert.equal(await repo.findActiveSession('imported-revoked-token',21),null);
    const stored=await migration.query('SELECT session_token_hash FROM identity.user_sessions WHERE id=31');assert.equal(stored.rows[0].session_token_hash,tokenHash('imported-active-token'));
    assert.equal(await repo.revokeSession('imported-active-token',21),0);assert.ok(await repo.findActiveSession('imported-active-token',17));
    assert.equal(await repo.revokeSession('imported-active-token',17),1);await repo.cleanupExpiredSessions();assert.equal(await repo.findActiveSession('imported-active-token',17),null,'Deleted revoked row must never be accepted');
    await assert.rejects(repo.createSession({userId:17,token:'expired',expiresAt:past,expectedPasswordHash:hash1}),/expired/);
    await repo.createSession({userId:17,token:'before-rotation',expiresAt:future,expectedPasswordHash:hash1});
    await repo.createSession({userId:21,token:'other-owner',expiresAt:future,expectedPasswordHash:hash1});
    await migration.query("ALTER TABLE identity.user_sessions ADD CONSTRAINT fail_rotation CHECK(revoke_reason IS DISTINCT FROM 'password_change') NOT VALID");
    await assert.rejects(repo.rotatePasswordAndRevoke(17,hash1,hash2));
    assert.equal((await repo.findCredentialByUsername('teacher')).password,hash1);assert.ok(await repo.findActiveSession('before-rotation',17));
    await migration.query('ALTER TABLE identity.user_sessions DROP CONSTRAINT fail_rotation');
    const rotated=await repo.rotatePasswordAndRevoke(17,hash1,hash2);assert.equal(rotated.sessionsRevoked,1);assert.equal(await repo.findActiveSession('before-rotation',17),null);assert.ok(await repo.findActiveSession('other-owner',21));
    await assert.rejects(repo.createSession({userId:17,token:'stale-login',expiresAt:future,expectedPasswordHash:hash1}),/Credentials changed/);
    await assert.rejects(repo.rotatePasswordAndRevoke(17,hash1,hash3),/concurrently/);
    const race=await Promise.allSettled([repo.createSession({userId:17,token:'race-login',expiresAt:future,expectedPasswordHash:hash2}),repo.rotatePasswordAndRevoke(17,hash2,hash3)]);
    assert.equal(race[1].status,'fulfilled');assert.equal(await repo.findActiveSession('race-login',17),null,'Rotation must defeat a concurrent login checked with old credentials');
    await Promise.all(Array.from({length:8},()=>repo.recordFailedLogin(17)));
    const lock=await repo.checkAccountLockout(17);assert.equal(lock.locked,true);assert.equal(lock.attempts,5);
    await assert.rejects(repo.createSession({userId:17,token:'locked',expiresAt:future,expectedPasswordHash:hash3}),/unavailable/);
    assert.equal(await repo.hasPermission(17,'user_management'),false);
    await migration.query('UPDATE identity.users SET account_locked_until=$1 WHERE id=17',[past]);
    await repo.createSession({userId:17,token:'after-unlock',expiresAt:future,expectedPasswordHash:hash3});assert.equal((await repo.checkAccountLockout(17)).attempts,0);
    await migration.query('UPDATE identity.users SET is_active=0 WHERE id=17');assert.equal(await repo.findActiveSession('after-unlock',17),null);
    await migration.query('UPDATE identity.users SET is_active=1 WHERE id=17');
    for(let i=0;i<6;i++)await repo.createSession({userId:17,token:`limit-${i}`,expiresAt:future,expectedPasswordHash:hash3});
    assert.equal((await repo.listActiveSessions(17)).length,5);assert.equal(await repo.findActiveSession('limit-0',17),null);
    await migration.query('UPDATE identity.user_sessions SET expires_at=$1 WHERE session_token_hash=$2',[past,tokenHash('limit-1')]);assert.equal(await repo.findActiveSession('limit-1',17),null);
    await repo.cleanupExpiredSessions();assert.equal(await repo.findActiveSession('limit-1',17),null);
    await repo.recordAudit({userId:17,actionType:'profile_updated',details:{method:'PUT',url:'/profile?token=hidden',body:{password:'hidden'},password:'hidden',token:'hidden'},errorMessage:'hidden'});
    const audits=(await migration.query('SELECT action_details FROM identity.activity_logs ORDER BY id')).rows;
    assert.ok(!JSON.stringify(audits).includes('hidden'));assert.equal(audits[0].action_details.url,'/login');
    assert.ok(!JSON.stringify(await repo.listActiveSessions(17)).includes('session_token'));
    await migration.query("UPDATE identity.users SET role='super_admin',admin_level=2 WHERE id=17");
    let deletionPid;
    const instrumentedDeletionPool={
      async connect(){
        const client=await deletionPool.connect();
        deletionPid=Number((await client.query('SELECT pg_backend_pid() AS pid')).rows[0].pid);
        return client;
      },
    };
    const deletion=createStudentDeletionRepository(instrumentedDeletionPool,{
      steps:['revoke_runs','excessive_agency','identity'],
    });
    let releaseReset,enteredReset;
    const resetEntered=new Promise(resolve=>{enteredReset=resolve;});
    const resetHeld=new Promise(resolve=>{releaseReset=resolve;});
    const heldReset=withPostgresStudentResetAdmission(lifecyclePool,newUser.id,async()=>{
      enteredReset();
      await resetHeld;
      return 'reset-complete';
    });
    await resetEntered;
    const admissionObserved=deletion.admit({requesterId:17,subjectId:newUser.id})
      .then(value=>({value}),error=>({error}));
    try{
      while(!deletionPid)await new Promise(resolve=>setImmediate(resolve));
      await waitForAdvisoryWait(pool,deletionPid);
      assert.equal((await pool.query('SELECT 1 AS available')).rows[0].available,1,
        'Control pool remains available while the dedicated lifecycle pool holds admission');
    }finally{releaseReset();}
    assert.equal(await heldReset,'reset-complete');
    const admitted=await admissionObserved;
    if(admitted.error)throw admitted.error;
    assert.equal(admitted.value.replayed,false);
    let resetMutated=false;
    await assert.rejects(withPostgresStudentResetAdmission(pool,newUser.id,async()=>{resetMutated=true;}),
      {code:'STUDENT_DELETION_ADMITTED',statusCode:409});
    assert.equal(resetMutated,false);
    await assert.rejects(repo.rotatePasswordAndRevoke(newUser.id,hash1,hash2),/concurrently/);
    assert.equal(await repo.rotateStudentPasswordAndRevoke(newUser.id,hash2),null);
    assert.equal((await repo.findCredentialByUsername('new-user')).password,hash1,
      'An admitted deletion must fence both self-service and administrative password rotation');
    await assert.rejects(pool.query('DELETE FROM identity.users'),{code:'42501'});
    await assert.rejects(pool.query('DELETE FROM identity.activity_logs'),{code:'42501'});
    await assert.rejects(pool.query('SELECT * FROM dvaia_migrations.ledger'),{code:'42501'});
    await initializeIdentityRepository(pool,migration);
    assert.ok(await createIdentityRepository(pool).findActiveSession('other-owner',21),'Sessions survive repository recreation and initialization');
  } finally {await Promise.all([pool.end(),migration.end(),lifecyclePool.end(),deletionPool.end()]);}
});
