'use strict';
const{test}=require('node:test'),assert=require('node:assert/strict');
const{createPool}=require('../../server/database/postgres');
const{initializeIdentityRepository}=require('../../server/database/postgres/identityRepository');
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&!!process.env.PG_PROVENANCE_TEST_RUNTIME_URL;
test('historical import provenance survives owner deletion and denies runtime mutation',{skip:!enabled},async()=>{
 for(const key of ['PG_PROVENANCE_TEST_RUNTIME_URL','PG_PROVENANCE_TEST_MIGRATION_URL'])assert.match(new URL(process.env[key]).pathname,/^\/owasp_ai_goat_test_[a-z0-9_]+$/);
 const runtime=createPool(process.env,'PG_PROVENANCE_TEST_RUNTIME_URL'),migration=createPool(process.env,'PG_PROVENANCE_TEST_MIGRATION_URL');
 try{
  await initializeIdentityRepository(runtime,migration);
  const {importIdentity}=require('../../server/database/postgres/identityImport');
  const password=await require('bcryptjs').hash('fixture-only',4);
  const data={users:[{id:11,username:'import-fixture',email:'fixture@example.invalid',password,created_at:'2025-01-01T00:00:00Z'}],permissions:[{id:1,admin_id:11,permission_name:'user_management',granted_at:'2025-01-01T00:00:00Z'}]};
  const before=(await migration.query('SELECT last_value,is_called FROM identity.users_id_seq')).rows[0];
  await migration.query("CREATE FUNCTION identity.fail_import_fixture() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture later table failure'; END $$");
  await migration.query('CREATE TRIGGER fail_import_fixture BEFORE INSERT ON identity.admin_permissions FOR EACH ROW EXECUTE FUNCTION identity.fail_import_fixture()');
  await assert.rejects(importIdentity(migration,data,{dryRun:false}),/fixture later table failure/);
  assert.equal((await runtime.query('SELECT count(*)::int AS n FROM identity.users')).rows[0].n,0);
  assert.deepEqual((await migration.query('SELECT last_value,is_called FROM identity.users_id_seq')).rows[0],before);
  await migration.query('DROP TRIGGER fail_import_fixture ON identity.admin_permissions');
  await migration.query('DROP FUNCTION identity.fail_import_fixture()');
  await importIdentity(migration,data,{dryRun:false});
  const next=(await migration.query("INSERT INTO identity.users(username,email,password) VALUES('next-fixture','next@example.invalid',$1) RETURNING id",[password])).rows[0];assert.equal(next.id,12);
  const insert=`INSERT INTO identity.historical_import_provenance(archive_sha256,import_version,source_file,source_table,source_row_sha256,historical_user_id,workshop_key,objective_id,source_created_at,source_updated_at,source_completed_at) VALUES($1,'archive-v1','users_auth.db','workshop_objectives_progress',$2,777,'xss_workshop','xss_r1','2025-01-01T00:00:00Z','2025-01-01T00:00:00Z','2025-01-01T00:00:00Z')`;
  await migration.query(insert,['a'.repeat(64),'b'.repeat(64)]);
  await assert.rejects(runtime.query(insert,['c'.repeat(64),'d'.repeat(64)]),{code:'42501'});
  for(const query of ['DELETE FROM identity.historical_import_provenance','UPDATE identity.historical_import_provenance SET historical_user_id=778','TRUNCATE identity.historical_import_provenance']){
   await assert.rejects(runtime.query(query),{code:'42501'});await assert.rejects(migration.query(query),{code:'55000'});
  }
  await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(migration);
  await migration.query("INSERT INTO identity.users(id,username,email,password) VALUES(777,'historical-owner','historical@example.invalid',$1)",[password]);
  await migration.query("INSERT INTO workshop_platform.completions(user_id,workshop_key,objective_id) VALUES(777,'xss_workshop','xss_r1')");
  assert.equal((await migration.query("DELETE FROM workshop_platform.completions WHERE user_id=777")).rowCount,1);
  assert.equal((await migration.query('DELETE FROM identity.users WHERE id=777')).rowCount,1);
  const rows=(await runtime.query('SELECT * FROM identity.historical_import_provenance')).rows;assert.equal(rows.length,1);assert.equal(rows[0].source_completed_at.toISOString(),'2025-01-01T00:00:00.000Z');assert.equal(rows[0].provenance_kind,'historical_completion');assert.equal('verdict' in rows[0],false);
  await assert.rejects(migration.query(insert,['a'.repeat(64),'b'.repeat(64)]),{code:'23505'});
 }finally{await Promise.all([runtime.end(),migration.end()]);}
});
