'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises');
const {Pool}=require('pg');
const {bootstrapAdmin,BOOTSTRAP_PERMISSIONS}=require('../../db/postgres/bootstrap-admin');
const {initializeIdentityRepository,createIdentityRepository}=require('../../server/database/postgres/identityRepository');
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&!!process.env.PG_ADMIN_PERMISSIONS_TEST_ADMIN_URL;
test('bootstrap and existing admin grants preserve revocations and deny demoted/student accounts',{skip:!enabled},async()=>{
 const url=new URL(process.env.PG_ADMIN_PERMISSIONS_TEST_ADMIN_URL);assert.ok(['127.0.0.1','localhost','[::1]'].includes(url.hostname));assert.equal(url.pathname,'/postgres');
 const admin=new Pool({connectionString:url.href}),name=`owasp_ai_goat_test_permissions_${process.pid}_${Date.now()}`;let runtime,migration;
 try{
  await admin.query(`CREATE DATABASE ${name} OWNER dvaia_identity_migration`);
  await admin.query(`REVOKE CONNECT ON DATABASE ${name} FROM PUBLIC`);await admin.query(`GRANT CONNECT ON DATABASE ${name} TO dvaia_identity_runtime`);
  const connection=role=>{const x=new URL(url);x.pathname='/'+name;x.username=role;x.password='';return x.href;};
  runtime=new Pool({connectionString:connection('dvaia_identity_runtime')});migration=new Pool({connectionString:connection('dvaia_identity_migration')});
  await initializeIdentityRepository(runtime,migration);
  const credentials={pool:migration,username:'fixture-admin',email:'fixture@example.test',password:'private-fixture-password'};
  const {user}=await bootstrapAdmin(credentials),repo=createIdentityRepository(runtime);
  assert.deepEqual((await repo.getUserPermissions(user.id)).sort(),[...BOOTSTRAP_PERMISSIONS].sort());
  assert.equal(await repo.hasPermission(user.id,'view_analytics'),true);assert.equal(await repo.hasPermission(user.id,'database_access'),false);
  await repo.revokePermission(user.id,'view_analytics');await runtime.query("UPDATE identity.admin_permissions SET expires_at=now()-interval '1 day' WHERE admin_id=$1 AND permission_name='export_data'",[user.id]);
  await migration.query("DELETE FROM identity.admin_permissions WHERE admin_id=$1 AND permission_name='user_management'",[user.id]);
  await migration.query(await fs.readFile(require('node:path').join(__dirname,'../../db/postgres/identity-migrations/0020_bootstrap_admin_permissions.sql'),'utf8'));
  await bootstrapAdmin(credentials);
  assert.equal(await repo.hasPermission(user.id,'user_management'),true);assert.equal(await repo.hasPermission(user.id,'view_analytics'),false);assert.equal(await repo.hasPermission(user.id,'export_data'),false);
  await runtime.query("UPDATE identity.users SET role='student',admin_level=0 WHERE id=$1",[user.id]);
  assert.equal(await repo.hasPermission(user.id,'user_management'),false);assert.deepEqual(await repo.getUserPermissions(user.id),[]);
  await runtime.query("UPDATE identity.users SET role='admin',admin_level=1 WHERE id=$1",[user.id]);assert.equal(await repo.hasPermission(user.id,'user_management'),true);
  await runtime.query("UPDATE identity.users SET account_locked_until=now()+interval '1 hour' WHERE id=$1",[user.id]);assert.equal(await repo.hasPermission(user.id,'user_management'),false);
  await runtime.query('UPDATE identity.users SET account_locked_until=NULL,is_active=0 WHERE id=$1',[user.id]);assert.equal(await repo.hasPermission(user.id,'user_management'),false);
 }finally{await Promise.all([runtime?.end(),migration?.end()]);await admin.query(`DROP DATABASE IF EXISTS ${name}`);await admin.end();}
});
