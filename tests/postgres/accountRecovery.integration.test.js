'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {spawnSync}=require('node:child_process');
const bcrypt=require('bcryptjs');
const {createPool}=require('../../server/database/postgres');
const {createIdentityRepository,initializeIdentityRepository}=require('../../server/database/postgres/identityRepository');
const {seedWorkshopPlatform}=require('../../server/database/postgres/workshopPlatformSeed');
const ROOT=path.resolve(__dirname,'../..');

const enabled=process.env.PG_TEST_DISPOSABLE==='yes'
  && process.env.PG_ACCOUNT_RECOVERY_RUNTIME_URL
  && process.env.PG_ACCOUNT_RECOVERY_MIGRATION_URL;

test('PostgreSQL account recovery preserves identity and learner state while revoking only target sessions',{
  skip:!enabled,timeout:30000,
},async()=>{
  for(const key of ['PG_ACCOUNT_RECOVERY_RUNTIME_URL','PG_ACCOUNT_RECOVERY_MIGRATION_URL'])
    assert.match(new URL(process.env[key]).pathname,/^\/owasp_ai_goat_test_account_recovery$/);
  const runtime=createPool(process.env,'PG_ACCOUNT_RECOVERY_RUNTIME_URL');
  const migration=createPool(process.env,'PG_ACCOUNT_RECOVERY_MIGRATION_URL');
  try {
    await initializeIdentityRepository(runtime,migration);await seedWorkshopPlatform(migration);
    assert.deepEqual(await initializeIdentityRepository(runtime,migration),[]);
    const repository=createIdentityRepository(runtime);
    const oldPassword='Old-Recovery9!',newPassword='New-Recovery8!';
    const inactiveOldPassword='Inactive-Old9!',inactiveNewPassword='Inactive-New8!';
    const oldHash=await bcrypt.hash(oldPassword,4),newHash=await bcrypt.hash(newPassword,4);
    const inactiveOldHash=await bcrypt.hash(inactiveOldPassword,4);
    const target=(await runtime.query(`INSERT INTO identity.users
      (username,email,password,role,admin_level,full_name,department,is_active,login_attempts,account_locked_until)
      VALUES('recover-target','recover-target@owned.invalid',$1,'admin',1,'Retained Name','Retained Department',1,0,
        NULL) RETURNING id`,[oldHash])).rows[0];
    const sibling=(await runtime.query(`INSERT INTO identity.users
      (username,email,password,role,full_name,is_active)
      VALUES('recover-sibling','recover-sibling@owned.invalid',$1,'student','Sibling Name',1) RETURNING id`,[oldHash])).rows[0];
    const inactiveTarget=(await runtime.query(`INSERT INTO identity.users
      (username,email,password,role,admin_level,full_name,department,is_active,login_attempts,
       account_locked_until,last_password_change,updated_at)
      VALUES('recover-inactive','recover-inactive@owned.invalid',$1,'admin',2,'Inactive Target',
        'Retained Inactive Department',0,5,clock_timestamp()+interval '30 minutes',
        clock_timestamp()-interval '1 day',clock_timestamp()-interval '1 day') RETURNING id`,[inactiveOldHash])).rows[0];
    const expiry=new Date(Date.now()+3600000).toISOString();
    await repository.createSession({userId:target.id,token:'target-old-session',expiresAt:expiry,
      expectedPasswordHash:oldHash,deviceInfo:{platform:'owned-test'}});
    await repository.createSession({userId:sibling.id,token:'sibling-session',expiresAt:expiry,
      expectedPasswordHash:oldHash,deviceInfo:{platform:'owned-test'}});
    await runtime.query(`UPDATE identity.users SET login_attempts=5,
      account_locked_until=clock_timestamp()+interval '30 minutes' WHERE id=$1`,[target.id]);
    await runtime.query('UPDATE identity.users SET is_active=0 WHERE id=$1',[sibling.id]);
    const objective=(await migration.query(`SELECT workshop_key,objective_id FROM workshop_platform.objectives
      WHERE is_enabled=true ORDER BY workshop_key,ordinal,objective_id LIMIT 1`)).rows[0];
    assert.ok(objective,'seeded canonical objective required');
    for(const id of [target.id,sibling.id,inactiveTarget.id])await runtime.query(`INSERT INTO workshop_platform.completions
      (user_id,workshop_key,objective_id) VALUES($1,$2,$3)`,[id,objective.workshop_key,objective.objective_id]);
    const before=(await migration.query(`SELECT id,role,admin_level,full_name,department,is_active,
      password_reset_required FROM identity.users WHERE id=ANY($1::integer[]) ORDER BY id`,[[target.id,sibling.id]])).rows;
    const progressBefore=(await migration.query(`SELECT user_id,workshop_key,objective_id,completed_at
      FROM workshop_platform.completions WHERE user_id=ANY($1::integer[]) ORDER BY user_id,workshop_key,objective_id`,
    [[target.id,sibling.id]])).rows;

    // A late audit failure rolls back both the password write and session revocation.
    await migration.query(`ALTER TABLE identity.activity_logs ADD CONSTRAINT reject_recovery_audit
      CHECK(action_type<>'administrative_account_recovery') NOT VALID`);
    await assert.rejects(repository.recoverAccount('recover-target',newHash),error=>error.code==='23514');
    await migration.query('ALTER TABLE identity.activity_logs DROP CONSTRAINT reject_recovery_audit');
    assert.equal((await repository.findCredentialByUsername('recover-target')).password,oldHash);
    assert.equal((await runtime.query(`SELECT is_active FROM identity.user_sessions
      WHERE user_id=$1`,[target.id])).rows[0].is_active,1);

    // A session-update failure also restores the preceding password mutation.
    await migration.query(`ALTER TABLE identity.user_sessions ADD CONSTRAINT reject_recovery_revocation
      CHECK(revoke_reason IS DISTINCT FROM 'administrative_recovery') NOT VALID`);
    await assert.rejects(repository.recoverAccount('recover-target',newHash),error=>error.code==='23514');
    await migration.query('ALTER TABLE identity.user_sessions DROP CONSTRAINT reject_recovery_revocation');
    assert.equal((await repository.findCredentialByUsername('recover-target')).password,oldHash);
    assert.equal((await runtime.query(`SELECT is_active FROM identity.user_sessions
      WHERE user_id=$1`,[target.id])).rows[0].is_active,1);

    const targetBeforeRecovery=(await migration.query(`SELECT login_attempts,account_locked_until,
      last_password_change,updated_at FROM identity.users WHERE id=$1`,[target.id])).rows[0];
    const recovered=await repository.recoverAccount('recover-target',newHash);
    assert.deepEqual(recovered,{userId:target.id,sessionsRevoked:1});
    const credential=await repository.findCredentialByUsername('recover-target');
    assert.equal(await bcrypt.compare(oldPassword,credential.password),false);
    assert.equal(await bcrypt.compare(newPassword,credential.password),true);
    assert.equal(await repository.findActiveSession('target-old-session',target.id),null);
    const targetAfterRecovery=(await migration.query(`SELECT login_attempts,account_locked_until,
      last_password_change,updated_at FROM identity.users WHERE id=$1`,[target.id])).rows[0];
    assert.equal(targetBeforeRecovery.login_attempts,5);
    assert.ok(targetBeforeRecovery.account_locked_until);
    assert.equal(targetAfterRecovery.login_attempts,0);
    assert.equal(targetAfterRecovery.account_locked_until,null);
    assert.ok(new Date(targetAfterRecovery.last_password_change)>new Date(targetBeforeRecovery.last_password_change));
    assert.ok(new Date(targetAfterRecovery.updated_at)>new Date(targetBeforeRecovery.updated_at));
    const revokedTargetSession=(await migration.query(`SELECT is_active,revoked_at,revoke_reason
      FROM identity.user_sessions WHERE user_id=$1`,[target.id])).rows;
    assert.equal(revokedTargetSession.length,1);
    assert.equal(revokedTargetSession[0].is_active,0);
    assert.ok(revokedTargetSession[0].revoked_at);
    assert.equal(revokedTargetSession[0].revoke_reason,'administrative_recovery');
    assert.equal((await runtime.query(`SELECT is_active FROM identity.user_sessions
      WHERE user_id=$1`,[sibling.id])).rows[0].is_active,1,'sibling session remains active in durable storage');
    assert.deepEqual((await migration.query(`SELECT id,role,admin_level,full_name,department,is_active,
      password_reset_required FROM identity.users WHERE id=ANY($1::integer[]) ORDER BY id`,
    [[target.id,sibling.id]])).rows,before);
    assert.deepEqual((await migration.query(`SELECT user_id,workshop_key,objective_id,completed_at
      FROM workshop_platform.completions WHERE user_id=ANY($1::integer[]) ORDER BY user_id,workshop_key,objective_id`,
    [[target.id,sibling.id]])).rows,progressBefore);
    const audit=(await migration.query(`SELECT action_type,action_details::text AS details
      FROM identity.activity_logs WHERE user_id=$1 AND action_type='administrative_account_recovery'`,[target.id])).rows;
    assert.deepEqual(audit,[{action_type:'administrative_account_recovery',details:'{}'}]);
    assert.doesNotMatch(JSON.stringify(audit),/password|\$2[aby]\$/i);
    const auditCount=Number((await migration.query('SELECT count(*) AS n FROM identity.activity_logs')).rows[0].n);
    await assert.rejects(repository.recoverAccount('missing-target',newHash),{code:'IDENTITY_ACCOUNT_UNAVAILABLE'});
    assert.equal(Number((await migration.query('SELECT count(*) AS n FROM identity.activity_logs')).rows[0].n),auditCount);
    assert.equal((await repository.findCredentialByUsername('recover-target')).password,newHash);
    assert.equal((await runtime.query(`SELECT is_active FROM identity.user_sessions
      WHERE user_id=$1`,[sibling.id])).rows[0].is_active,1);

    // Exercise the real CLI process against this owned configured database. Its
    // environment is an allowlist, and the copied fixture intentionally has no
    // project .env from which private configuration could be inherited.
    assert.equal(fs.existsSync(path.join(ROOT,'.env')),false,'owned source copy must exclude project .env');
    const inactiveBefore=(await migration.query(`SELECT id,role,admin_level,full_name,department,is_active,
      password_reset_required,login_attempts,account_locked_until,last_password_change,updated_at
      FROM identity.users WHERE id=$1`,[inactiveTarget.id])).rows[0];
    const inactiveProgressBefore=(await migration.query(`SELECT user_id,workshop_key,objective_id,completed_at
      FROM workshop_platform.completions WHERE user_id=$1 ORDER BY workshop_key,objective_id`,
    [inactiveTarget.id])).rows;
    const childEnv={NODE_ENV:'production',PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres',
      IDENTITY_DATABASE_URL:process.env.PG_ACCOUNT_RECOVERY_RUNTIME_URL,AWS_EC2_METADATA_DISABLED:'true'};
    for(const key of ['PATH','HOME','TMPDIR'])if(process.env[key])childEnv[key]=process.env[key];
    const cli=spawnSync(process.execPath,[path.join(ROOT,'scripts/admin/reset-auth-defaults.js'),
      '--username','recover-inactive','--password-stdin'],{
      cwd:ROOT,env:childEnv,input:`${inactiveNewPassword}\n`,encoding:'utf8',timeout:15000,
    });
    assert.equal(cli.status,0,`CLI failed without exposing configuration: ${cli.stderr}`);
    assert.equal(cli.stderr,'');
    assert.match(cli.stdout,/Recovered one account and revoked 0 active session\(s\)\./);
    assert.ok(cli.stdout.length<512);
    assert.doesNotMatch(`${cli.stdout}${cli.stderr}`,
      new RegExp([inactiveOldPassword,inactiveNewPassword,inactiveOldHash,process.env.PG_ACCOUNT_RECOVERY_RUNTIME_URL]
        .map(value=>value.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')).join('|')));
    const inactiveAfter=(await migration.query(`SELECT id,role,admin_level,full_name,department,is_active,
      password_reset_required,login_attempts,account_locked_until,last_password_change,updated_at,password
      FROM identity.users WHERE id=$1`,[inactiveTarget.id])).rows[0];
    assert.equal(inactiveAfter.is_active,0,'recovery must preserve a disabled target account');
    for(const key of ['id','role','admin_level','full_name','department','is_active','password_reset_required'])
      assert.deepEqual(inactiveAfter[key],inactiveBefore[key]);
    assert.equal(inactiveAfter.login_attempts,0);
    assert.equal(inactiveAfter.account_locked_until,null);
    assert.ok(new Date(inactiveAfter.last_password_change)>new Date(inactiveBefore.last_password_change));
    assert.ok(new Date(inactiveAfter.updated_at)>new Date(inactiveBefore.updated_at));
    assert.equal(await bcrypt.compare(inactiveOldPassword,inactiveAfter.password),false);
    assert.equal(await bcrypt.compare(inactiveNewPassword,inactiveAfter.password),true);
    assert.deepEqual((await migration.query(`SELECT user_id,workshop_key,objective_id,completed_at
      FROM workshop_platform.completions WHERE user_id=$1 ORDER BY workshop_key,objective_id`,
    [inactiveTarget.id])).rows,inactiveProgressBefore);
    const inactiveAudit=(await migration.query(`SELECT action_type,action_details::text AS details
      FROM identity.activity_logs WHERE user_id=$1 AND action_type='administrative_account_recovery'`,
    [inactiveTarget.id])).rows;
    assert.deepEqual(inactiveAudit,[{action_type:'administrative_account_recovery',details:'{}'}]);
    assert.doesNotMatch(JSON.stringify(inactiveAudit),/password|\$2[aby]\$/i);
    assert.deepEqual(await initializeIdentityRepository(runtime,migration),[]);
    await assert.rejects(runtime.query('SELECT * FROM dvaia_migrations.ledger'),{code:'42501'});
  } finally {await Promise.allSettled([runtime.end(),migration.end()]);}
});
