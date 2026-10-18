'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path');
const {provisionApplication}=require('../../db/postgres/provision-application');
// Requires a fresh disposable cluster: names are deliberately identical to installation names.
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&process.env.PG_PROVISION_FRESH_CLUSTER==='yes'&&!!process.env.PG_ADMIN_DATABASE_URL;
test('fresh PostgreSQL provision, immutable replay, empty-only admin bootstrap',{skip:!enabled},async()=>{
 const dir=await fs.mkdtemp(path.join(os.tmpdir(),'dvaia-provision-integration-')),manifestPath=path.join(dir,'private.json');let runtime,migration;
 try{
  const first=await provisionApplication({manifestPath});assert.equal(first.status,'created');
  const replay=await provisionApplication({manifestPath});assert.equal(replay.status,'existing');assert.deepEqual(replay.configuration,first.configuration);
  await assert.rejects(provisionApplication({manifestPath:path.join(dir,'unowned.json')}),{code:'PROVISIONING_NAME_COLLISION'});
  const {Pool}=require('pg');runtime=new Pool({connectionString:first.configuration.IDENTITY_DATABASE_URL,max:1});migration=new Pool({connectionString:first.configuration.IDENTITY_MIGRATION_DATABASE_URL,max:1});
  await require('../../server/database/postgres/identityRepository').initializeIdentityRepository(runtime,migration);
  const {bootstrapAdmin}=require('../../db/postgres/bootstrap-admin');
  const created=await bootstrapAdmin({pool:migration,username:'fixture-admin',email:'fixture@example.test',password:'isolated-admin-password'});assert.equal(created.created,true);assert.equal(created.user.role,'super_admin');
  const again=await bootstrapAdmin({pool:migration,username:'fixture-admin',email:'fixture@example.test',password:'isolated-admin-password'});assert.equal(again.status,'already_created');await assert.rejects(bootstrapAdmin({pool:migration,username:'fixture-admin',email:'fixture@example.test',password:'wrong-private-password'}),/CREDENTIAL_MISMATCH/);
  assert.equal((await runtime.query('SELECT count(*)::integer AS count FROM identity.users')).rows[0].count,1);
  await assert.rejects(runtime.query('CREATE DATABASE forbidden'),{code:'42501'});
 }finally{await Promise.allSettled([runtime?.end(),migration?.end()]);await fs.rm(dir,{recursive:true,force:true});}
});
