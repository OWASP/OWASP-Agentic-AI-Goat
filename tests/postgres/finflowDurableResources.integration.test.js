'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {randomUUID}=require('node:crypto');
const {Pool}=require('pg');
const {createFinflowWorkshopDb}=require('../../server/database/postgres/sensitiveInfoWorkshopDb');
const {createFinflowDurableResourceRepository}=require('../../server/database/postgres/finflowDurableResourceRepository');
const {createFinflowBackupFileStore,createFinflowDurableResources}=require('../../server/services/finflowDurableResources');
const {createFinflowOwnerResourceDeletion}=require('../../server/services/finflowOwnerResourceDeletion');
const {createStudentDeletionAdapters}=require('../../server/services/studentDeletionAdapters');
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&process.env.FINFLOW_TRAVERSAL_ISOLATED==='1';
const MIGRATION='0011_durable_customer_backups.sql';
function ownedUrl(name,database){const value=new URL(process.env[name]);assert.equal(value.hostname,'127.0.0.1');assert.equal(value.pathname,`/${database}`);return value.href;}
function pool(url){return new Pool({connectionString:url,max:2,connectionTimeoutMillis:5000,statement_timeout:30000,lock_timeout:5000,application_name:'finflow-durable-native'});}
async function code(work,expected){await assert.rejects(work,error=>error?.code===expected);}
function execution(ownerId,generation=0){return Object.freeze({ownerKey:JSON.stringify(['FinFlow',String(ownerId)]),durableGeneration:generation,runId:randomUUID(),check:async()=>{},effect:async(_key,work)=>work()});}
function scope(ownerId,generation=0){return{ownerId,generation};}
async function provision(resources,ownerId,name){return resources.createBackup({scope:scope(ownerId),execution:execution(ownerId),backupName:name});}

test('registered 0011 readiness detects missing/spoofed/drifted objects through the canonical loader',
 {skip:!enabled,timeout:120000},async t=>{
  const runtime=pool(ownedUrl('FINFLOW_TRAVERSAL_PROBE_DATABASE_URL','owasp_ai_goat_test_finflow_traversal_probe'));
  const migration=pool(ownedUrl('FINFLOW_TRAVERSAL_PROBE_MIGRATION_DATABASE_URL','owasp_ai_goat_test_finflow_traversal_probe'));
  t.after(async()=>Promise.allSettled([runtime.end(),migration.end()]));
  const repo=createFinflowDurableResourceRepository(runtime);
  await migration.query('DROP SCHEMA IF EXISTS finflow CASCADE');
  await migration.query('DROP SCHEMA IF EXISTS legacy_sensitive CASCADE');
  await migration.query('DROP SCHEMA IF EXISTS dvaia_migrations CASCADE');
  await code(repo.assertReady(),'FINFLOW_RESOURCE_STORAGE_NOT_READY');
  await migration.query(`CREATE SCHEMA finflow AUTHORIZATION dvaia_finflow_migration;
    REVOKE ALL ON SCHEMA finflow FROM PUBLIC;
    GRANT USAGE ON SCHEMA finflow TO dvaia_finflow_runtime;
    CREATE TABLE finflow.customer_datasets(owner_id bigint);
    CREATE TABLE finflow.spoof(id integer);
    CREATE FUNCTION finflow.guard_finflow_backup_lineage() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$BEGIN RETURN NEW;END$$;
    CREATE TRIGGER finflow_backup_lineage_guard BEFORE UPDATE OR DELETE ON finflow.spoof FOR EACH ROW EXECUTE FUNCTION finflow.guard_finflow_backup_lineage()`);
  assert.deepEqual((await runtime.query(`SELECT
    has_schema_privilege(current_user,'finflow','USAGE') AS schema_usage,
    has_table_privilege(current_user,'finflow.customer_datasets','SELECT,INSERT,UPDATE,DELETE') AS table_access`)).rows[0],
  {schema_usage:true,table_access:false});
  await code(repo.assertReady(),'FINFLOW_RESOURCE_STORAGE_NOT_READY');
  await migration.query('DROP SCHEMA finflow CASCADE');
  await migration.query('DROP SCHEMA IF EXISTS legacy_sensitive CASCADE');
  await migration.query('DROP SCHEMA IF EXISTS dvaia_migrations CASCADE');
  const workshop=createFinflowWorkshopDb(runtime);
  await workshop.initialize(migration);
  assert.equal(await repo.assertReady(),true);
  assert.equal((await migration.query('SELECT count(*)::integer count FROM dvaia_migrations.ledger WHERE name=$1',[MIGRATION])).rows[0].count,1);
  for(const [trigger,table] of [['finflow_dataset_deletion_guard','dataset_deletions'],['finflow_backup_read_guard','backup_reads'],['finflow_backup_lineage_guard','backup_artifacts'],['finflow_resource_retirement_guard','resource_retirements'],['finflow_owner_deletion_guard','owner_resource_deletions']]){
    await migration.query(`ALTER TABLE finflow.${table} DISABLE TRIGGER ${trigger}`);
    await code(repo.assertReady(),'FINFLOW_RESOURCE_STORAGE_NOT_READY');
    await migration.query(`ALTER TABLE finflow.${table} ENABLE TRIGGER ${trigger}`);
  }
  await migration.query('ALTER FUNCTION finflow.read_customer_dataset(bigint,bigint,jsonb) SECURITY INVOKER');
  await code(repo.assertReady(),'FINFLOW_RESOURCE_STORAGE_NOT_READY');
  await migration.query('ALTER FUNCTION finflow.read_customer_dataset(bigint,bigint,jsonb) SECURITY DEFINER');
  await migration.query('ALTER FUNCTION finflow.ensure_customer_dataset(bigint,bigint,jsonb) SET search_path=pg_catalog,finflow');
  await code(repo.assertReady(),'FINFLOW_RESOURCE_STORAGE_NOT_READY');
  await migration.query('ALTER FUNCTION finflow.ensure_customer_dataset(bigint,bigint,jsonb) SET search_path=pg_catalog');
  assert.equal(await repo.assertReady(),true);
});

test('actual files and SQL prove reset history, job retry, account scrub, siblings, guards and old-overload denial',
 {skip:!enabled,timeout:120000},async t=>{
  const runtime=pool(ownedUrl('FINFLOW_WORKSHOP_DATABASE_URL','owasp_ai_goat_test_finflow_traversal_store'));
  const migration=pool(ownedUrl('FINFLOW_WORKSHOP_MIGRATION_DATABASE_URL','owasp_ai_goat_test_finflow_traversal_store'));
  t.after(async()=>Promise.allSettled([runtime.end(),migration.end()]));
  const workshop=createFinflowWorkshopDb(runtime);
  await workshop.initialize(migration);
  const repository=createFinflowDurableResourceRepository(runtime);assert.equal(await repository.assertReady(),true);
  await code(runtime.query('SELECT backup_id FROM finflow.backup_artifacts LIMIT 1'),'42501');
  const appRoot=fs.mkdtempSync(path.join(os.tmpdir(),'finflow-durable-native-'));fs.chmodSync(appRoot,0o700);
  t.after(()=>fs.rmSync(appRoot,{recursive:true,force:true}));
  const files=createFinflowBackupFileStore({root:path.join(appRoot,'finflow-backups')});await files.assertReady();
  const resources=createFinflowDurableResources({repository,files,initialRecords:[{account:'private'}]});
  const resetOwner=42101;const resetBackup=await provision(resources,resetOwner,'reset_history');
  const resetToken=(await migration.query('SELECT file_token::text token,snapshot_records FROM finflow.backup_artifacts WHERE backup_id=$1',[resetBackup.metadata.backupId])).rows[0];
  await resources.retireGeneration({operationId:randomUUID(),ownerId:resetOwner,fromGeneration:0,toGeneration:1});
  await code(repository.listBackups({ownerId:resetOwner,generation:0}),'55000');
  assert.deepEqual(await repository.listBackups({ownerId:resetOwner,generation:1}),[]);
  const resetRow=(await migration.query('SELECT status,snapshot_records,content_scrubbed_at FROM finflow.backup_artifacts WHERE backup_id=$1',[resetBackup.metadata.backupId])).rows[0];
  assert.equal(resetRow.status,'retired');assert.deepEqual(resetRow.snapshot_records,[{account:'private'}]);assert.equal(resetRow.content_scrubbed_at,null);assert.equal(await files.absent(resetToken.token),true);

  const owner=42102,sibling=42103;const ownerBackup=await provision(resources,owner,'owner_delete');const siblingBackup=await provision(resources,sibling,'sibling');
  const ownerMeta=(await migration.query('SELECT file_token::text token,content_sha256,byte_length,record_count FROM finflow.backup_artifacts WHERE backup_id=$1',[ownerBackup.metadata.backupId])).rows[0];
  const siblingToken=(await migration.query('SELECT file_token::text token FROM finflow.backup_artifacts WHERE backup_id=$1',[siblingBackup.metadata.backupId])).rows[0].token;
  const ownerListing=await repository.listBackups({ownerId:owner,generation:0});
  assert.equal(ownerListing.length,1);assert.equal(ownerListing[0].backupId,ownerBackup.metadata.backupId);assert.equal(ownerListing[0].ownerId,owner);assert.equal(ownerListing[0].generation,0);assert.equal(ownerListing[0].status,'ready');
  const siblingListing=await repository.listBackups({ownerId:sibling,generation:0});
  assert.deepEqual(siblingListing.map(row=>row.backupId),[siblingBackup.metadata.backupId]);
  const job=randomUUID(),lease=randomUUID();let fail=true;
  const flaky={beginOwnerDeletion:value=>repository.beginOwnerDeletion(value),completeOwnerDeletion:value=>{if(fail){fail=false;throw Object.assign(Error('injected post-file failure'),{code:'INJECTED'});}return repository.completeOwnerDeletion(value);}};
  const cleanup=createFinflowOwnerResourceDeletion({repository:flaky,files});
  const deletionScope={subjectId:owner,jobId:job,leaseToken:lease,idempotencyKey:`${job}:finflow`,check:async()=>{},signal:new AbortController().signal};
  await code(cleanup(deletionScope),'INJECTED');assert.equal(await files.absent(ownerMeta.token),true);
  assert.equal((await migration.query('SELECT status FROM finflow.owner_resource_deletions WHERE job_id=$1',[job])).rows[0].status,'pending');
  const pendingReceipt=await repository.readOwnerDeletion({jobId:job,ownerId:owner});
  assert.equal(pendingReceipt.status,'pending');assert.equal(pendingReceipt.ownerId,owner);assert.equal(pendingReceipt.jobId,job);assert.deepEqual(pendingReceipt.fileTokens,[ownerMeta.token]);
  assert.equal(await repository.readOwnerDeletion({jobId:job,ownerId:sibling}),null);assert.equal(await repository.readOwnerDeletion({jobId:randomUUID(),ownerId:owner}),null);
  const receipt=await cleanup(deletionScope);assert.equal(receipt.completed,true);assert.equal(await files.absent(siblingToken),false);
  const completedReceipt=await repository.readOwnerDeletion({jobId:job,ownerId:owner});
  assert.equal(completedReceipt.status,'completed');assert.ok(completedReceipt.completedAt);assert.equal(completedReceipt.artifactCount,1);assert.equal(completedReceipt.datasetCount,1);assert.deepEqual(completedReceipt.fileTokens,pendingReceipt.fileTokens);
  const restartedRepository=createFinflowDurableResourceRepository(runtime);
  const restartedCleanup=createFinflowOwnerResourceDeletion({repository:restartedRepository,files});
  assert.equal((await restartedCleanup(deletionScope)).completed,true);
  assert.deepEqual(await restartedRepository.readOwnerDeletion({jobId:job,ownerId:owner}),completedReceipt);
  assert.deepEqual(await restartedRepository.listBackups({ownerId:sibling,generation:0}),siblingListing);
  await code(restartedRepository.listBackups({ownerId:owner,generation:0}),'55000');
  const scrubbed=(await migration.query('SELECT status,snapshot_records,content_sha256,byte_length,record_count,content_scrubbed_at FROM finflow.backup_artifacts WHERE backup_id=$1',[ownerBackup.metadata.backupId])).rows[0];
  assert.equal(scrubbed.status,'retired');assert.deepEqual(scrubbed.snapshot_records,[]);assert.ok(scrubbed.content_scrubbed_at);
  assert.equal(scrubbed.content_sha256,ownerMeta.content_sha256);assert.equal(Number(scrubbed.byte_length),Number(ownerMeta.byte_length));assert.equal(scrubbed.record_count,ownerMeta.record_count);
  assert.deepEqual((await migration.query('SELECT records FROM finflow.customer_datasets WHERE owner_id=$1',[owner])).rows[0].records,[]);
  await code(resources.readDataset({scope:scope(owner,1),execution:execution(owner,1)}),'55000');
  await code(runtime.query('SELECT finflow.destroy_student_owner($1::bigint)',[owner]),'42501');
  assert.equal((await workshop.completeObjective(String(owner),'admin_backup')).changes,1);
  assert.ok(Number((await runtime.query('SELECT finflow.destroy_student_owner($1::bigint,$2::uuid) removed',[owner,job])).rows[0].removed)>=1);
  assert.equal(Number((await runtime.query('SELECT finflow.destroy_student_owner($1::bigint,$2::uuid) removed',[owner,job])).rows[0].removed),0);
  for(const column of ['content_sha256=NULL','byte_length=NULL','record_count=NULL','committed_at=NULL'])await code(migration.query(`UPDATE finflow.backup_artifacts SET ${column} WHERE backup_id=$1`,[ownerBackup.metadata.backupId]),'23514');
  await code(migration.query("UPDATE finflow.backup_artifacts SET snapshot_records='[1]'::jsonb WHERE backup_id=$1",[ownerBackup.metadata.backupId]),'23514');
  await code(migration.query('DELETE FROM finflow.owner_resource_deletions WHERE job_id=$1',[job]),'23514');

  const adapterOwner=42104,adapterBackup=await provision(resources,adapterOwner,'adapter_real_file'),adapterJob=randomUUID();
  const adapterToken=(await migration.query('SELECT file_token::text token FROM finflow.backup_artifacts WHERE backup_id=$1',[adapterBackup.metadata.backupId])).rows[0].token;
  const adapters=createStudentDeletionAdapters(()=>({resetOwner:async(_owner,work)=>work()}),{secureShopCleanup:async()=>({completed:true}),
    cleanupFinflowBackups:createFinflowOwnerResourceDeletion({repository,files}),retireFinflowTraversalOwner:async()=>true,
    storeCleanup:{finflow:async value=>({completed:true,removed:Number((await runtime.query('SELECT finflow.destroy_student_owner($1,$2) removed',[value.subjectId,value.jobId])).rows[0].removed)})}});
  const adapterReceipt=await adapters.finflow({subjectId:adapterOwner,jobId:adapterJob,leaseToken:randomUUID(),idempotencyKey:`${adapterJob}:finflow`,check:async()=>{},signal:new AbortController().signal});
  assert.equal(adapterReceipt.completed,true);assert.equal(await files.absent(adapterToken),true);assert.equal(await files.absent(siblingToken),false);
});
