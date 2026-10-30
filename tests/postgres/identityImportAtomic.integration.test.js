'use strict';
const{test}=require('node:test'),assert=require('node:assert/strict');
const{createPool,withTransaction}=require('../../server/database/postgres');
const{initializeIdentityRepository}=require('../../server/database/postgres/identityRepository');
const{importIdentity,importIdentityInTransaction}=require('../../server/database/postgres/identityImport');
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&!!process.env.PG_IDENTITY_ATOMIC_TEST_RUNTIME_URL;
test('identity dry run checks native constraints and shared transaction rolls back rows and sequences',{skip:!enabled},async()=>{
 for(const key of ['PG_IDENTITY_ATOMIC_TEST_RUNTIME_URL','PG_IDENTITY_ATOMIC_TEST_MIGRATION_URL'])assert.match(new URL(process.env[key]).pathname,/^\/owasp_ai_goat_test_[a-z0-9_]+$/);
 const runtime=createPool(process.env,'PG_IDENTITY_ATOMIC_TEST_RUNTIME_URL'),migration=createPool(process.env,'PG_IDENTITY_ATOMIC_TEST_MIGRATION_URL');
 try{
  await initializeIdentityRepository(runtime,migration);
  const password=await require('bcryptjs').hash('fixture-only',4);
  const user={id:41,username:'atomic-fixture',email:'atomic@example.invalid',password,created_at:'2025-01-01T01:00:00.123456+01:00'};
  const data={users:[user]};
  const snapshot=async()=>({rows:(await runtime.query('SELECT count(*)::int AS n FROM identity.users')).rows[0].n,sequence:(await migration.query('SELECT last_value,is_called FROM identity.users_id_seq')).rows[0]});
  const before=await snapshot();const dry=await importIdentity(migration,data);
  assert.equal(dry.dryRun,true);assert.equal(dry.validationOnly,false);assert.equal(dry.users,1);assert.deepEqual(await snapshot(),before);
  await assert.rejects(importIdentity(migration,{users:[user,{...user,id:42,email:'another@example.invalid'}]}),{code:'23505'});assert.deepEqual(await snapshot(),before);
  await assert.rejects(withTransaction(migration,async client=>{await importIdentityInTransaction(client,data);await client.query("INSERT INTO workshop_platform.completions(user_id,workshop_key,objective_id) VALUES(41,'missing-workshop','missing-objective')");}),{code:'23503'});
  assert.deepEqual(await snapshot(),before);
  await withTransaction(migration,async client=>{await importIdentityInTransaction(client,data);});
  assert.equal((await migration.query("SELECT to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS.US') AS stamp FROM identity.users WHERE id=41")).rows[0].stamp,'2025-01-01 00:00:00.123456');
  const next=(await migration.query("INSERT INTO identity.users(username,email,password) VALUES('next-atomic','next-atomic@example.invalid',$1) RETURNING id",[password])).rows[0];assert.equal(next.id,42);
 }finally{await Promise.all([runtime.end(),migration.end()]);}
});
