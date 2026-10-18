'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const path=require('node:path');
const {randomUUID,createHash}=require('node:crypto');
const {Pool}=require('pg');
const bcrypt=require('bcryptjs');
const {initializeIdentityRepository,createIdentityRepository}=require('../../server/database/postgres/identityRepository');
const {createSecureShopLaunchRepository}=require('../../server/database/postgres/secureshopLaunchRepository');
const {createSecureShopProgressCleanupCheckpointRepository,WORKSHOP_KEY}=require('../../server/database/postgres/secureshopProgressCleanupCheckpointRepository');
const PREFIX='PG_SECURESHOP_CLEANUP_VISIBILITY_TEST';
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&process.env[`${PREFIX}_MIGRATION_URL`]&&process.env[`${PREFIX}_RUNTIME_URL`];

test('forward cleanup lifecycle retires a hidden catalog launch but still requires the canonical row',{
 skip:!enabled,timeout:30000},async()=>{
 const migrationUrl=new URL(process.env[`${PREFIX}_MIGRATION_URL`]);
 const runtimeUrl=new URL(process.env[`${PREFIX}_RUNTIME_URL`]);
 for(const url of [migrationUrl,runtimeUrl]){assert.ok(['127.0.0.1','localhost'].includes(url.hostname));assert.match(url.pathname,/^\/dvaia_test_[a-z0-9_]+$/);}
 assert.equal(migrationUrl.pathname,runtimeUrl.pathname);
 const migration=new Pool({connectionString:migrationUrl.href,max:1});
 const runtime=new Pool({connectionString:runtimeUrl.href,max:4});
 try{
  const applied=await initializeIdentityRepository(runtime,migration);
  assert.ok(applied.includes('0039_secureshop_cleanup_catalog_independence.sql'));
  assert.deepEqual(await initializeIdentityRepository(runtime,migration),[]);
  const migrationName='0039_secureshop_cleanup_catalog_independence.sql';
  const expected={name:migrationName,checksum:createHash('sha256').update(await fs.readFile(path.join(
    __dirname,`../../db/postgres/identity-migrations/${migrationName}`))).digest('hex')};
  assert.deepEqual((await migration.query(`SELECT name,checksum FROM dvaia_migrations.ledger
    WHERE name=$1`,[expected.name])).rows[0],expected);
  const identities=createIdentityRepository(runtime),launches=createSecureShopLaunchRepository(runtime);
  const checkpoint=createSecureShopProgressCleanupCheckpointRepository(runtime);
  const password=await bcrypt.hash('hidden-cleanup-owned',4);
  async function launch(label){
   const user=await identities.createUser({username:`${label}-${randomUUID().slice(0,8)}`,email:`${randomUUID()}@cleanup.invalid`,passwordHash:password});
   const session=await identities.createSession({userId:user.id,token:randomUUID(),expiresAt:new Date(Date.now()+3600000).toISOString(),expectedPasswordHash:password});
   const issued=await launches.issueOrRenew({platformOwnerId:user.id,platformSessionId:session.id,expiresAt:new Date(Date.now()+3600000).toISOString()});
   const reset=await launches.beginReset({launchId:issued.binding.launchId,platformSessionId:session.id,platformOwnerId:user.id,expectedGeneration:1,idempotencyKey:`${label}-reset`});
   return{user,session,issued,reset};
  }
  const absent=await launch('absent');
  await assert.rejects(checkpoint.finalize(absent.reset.resetId),{code:'CATALOG_UNAVAILABLE'});
  assert.equal((await runtime.query('SELECT progress_reconciliation_required FROM identity.secureshop_launch_resets WHERE reset_id=$1',[absent.reset.resetId])).rows[0].progress_reconciliation_required,true);

  await migration.query(`INSERT INTO workshop_platform.exercises
   (workshop_key,challenge_key,challenge_name,ordinal,catalog_active,is_visible)
   VALUES($1,'secureshop-agent-security','Hidden SecureShop',900,false,false)`,[WORKSHOP_KEY]);
  const hidden=await launch('hidden');
  const completed=await checkpoint.finalize(hidden.reset.resetId);
  assert.equal(completed.resetId,hidden.reset.resetId);assert.equal(completed.replayed,false);
  assert.equal((await runtime.query('SELECT progress_reconciliation_required FROM identity.secureshop_launch_resets WHERE reset_id=$1',[hidden.reset.resetId])).rows[0].progress_reconciliation_required,false);
  assert.equal((await runtime.query('SELECT catalog_active,is_visible FROM workshop_platform.exercises WHERE workshop_key=$1',[WORKSHOP_KEY])).rows[0].catalog_active,false);
  assert.equal((await checkpoint.finalize(hidden.reset.resetId)).replayed,true);
 }finally{await Promise.allSettled([runtime.end(),migration.end()]);}
});
