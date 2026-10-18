'use strict';
// Adapted archived pure assertions; no native/file allocation or draft migration authority.
const test=require('node:test'),assert=require('node:assert/strict'),path=require('node:path'),os=require('node:os');
const {createFinflowOwnerResourceDeletion}=require('../server/services/finflowOwnerResourceDeletion');
const {verifyFinflowOwnerDeletionReceipt,issueFinflowOwnerDeletionReceipt}=require('../server/services/finflowOwnerDeletionReceipt');
const {createStudentDeletionAdapters}=require('../server/services/studentDeletionAdapters');
const {createFinflowDurableResourceRepository,READINESS_FIELDS}=require('../server/database/postgres/finflowDurableResourceRepository');
const {controlledRoots}=require('../server/services/finflowDurableResourceComposition');
const sql=require('node:fs').readFileSync(path.join(__dirname,'../db/postgres/workshop-migrations/finflow/0011_durable_customer_backups.sql'),'utf8');
const A='11111111-1111-4111-8111-111111111111',JOB='33333333-3333-4333-8333-333333333333',LEASE='44444444-4444-4444-8444-444444444444';
function deletionScope(check=async()=>{}){return{subjectId:41,jobId:JOB,leaseToken:LEASE,idempotencyKey:`${JOB}:finflow`,check,signal:new AbortController().signal};}
test('remaining bytes or cleanup errors cannot publish completion',async()=>{
  let completed=false;
  const cleanup=createFinflowOwnerResourceDeletion({repository:{
    async beginOwnerDeletion(){return{ownerId:41,jobId:JOB,status:'pending',fileTokens:[A],artifactCount:1,datasetCount:1};},
    async completeOwnerDeletion(){completed=true;throw Error('must not run');}},
  files:{async remove(){},async absent(){return false;}}});
  await assert.rejects(cleanup(deletionScope()),{code:'FINFLOW_OWNER_CLEANUP_INCOMPLETE'});assert.equal(completed,false);
});

test('retry after post-file database failure rechecks absence and completes the same job',async()=>{
  let completions=0,removals=0,absenceChecks=0;
  const repo={
    async beginOwnerDeletion(){return{ownerId:41,jobId:JOB,status:'pending',fileTokens:[A],artifactCount:1,datasetCount:1};},
    async completeOwnerDeletion(){if(++completions===1)throw Error('transient database failure');return{ownerId:41,jobId:JOB,status:'completed',fileTokens:[A],artifactCount:1,datasetCount:1,completedAt:'2026-09-14T00:00:00.000Z'};}
  };
  const cleanup=createFinflowOwnerResourceDeletion({repository:repo,files:{async remove(){removals++;},async absent(){absenceChecks++;return true;}}});
  await assert.rejects(cleanup(deletionScope()),/transient database failure/);
  const receipt=await cleanup(deletionScope());
  assert.equal(verifyFinflowOwnerDeletionReceipt(receipt,{ownerId:41,jobId:JOB}),true);
  assert.equal(removals,2);assert.equal(absenceChecks,2);assert.equal(completions,2);
});

test('held drain orders backup cleanup, traversal and job-aware store deletion with lease checks',async()=>{
  const events=[];let checks=0;
  const scope=deletionScope(async()=>events.push(`check:${++checks}`));
  const adapters=createStudentDeletionAdapters(()=>({resetOwner:async(owner,work)=>{events.push(`drain:${owner}:begin`);await work();events.push(`drain:${owner}:end`);}}),{
    secureShopCleanup:async()=>({completed:true}),
    cleanupFinflowBackups:async value=>{events.push(`backup:${value.jobId}`);return issueFinflowOwnerDeletionReceipt({completed:true,ownerId:41,jobId:JOB,artifactCount:1});},
    retireFinflowTraversalOwner:async owner=>{events.push(`traversal:${owner}`);return true;},
    storeCleanup:{finflow:async value=>{events.push(`destroy:${value.jobId}`);return{completed:true,removed:3};}}});
  assert.deepEqual(await adapters.finflow(scope),{completed:true,removed:3});
  assert.deepEqual(events,['drain:41:begin','check:1',`backup:${JOB}`,'check:2','traversal:41','check:3',`destroy:${JOB}`,'drain:41:end']);
});

test('production resource roots are distinct direct children of one explicit application-data root',()=>{
  const root=path.resolve(os.tmpdir(),'owned-app-data');
  assert.deepEqual(controlledRoots({appDataRoot:root,env:{}}),{appDataRoot:root,
    traversalRoot:path.join(root,'finflow-traversal-targets'),backupRoot:path.join(root,'finflow-backups')});
  assert.throws(()=>controlledRoots({env:{}}),/Explicit absolute/);
  assert.throws(()=>controlledRoots({appDataRoot:root,env:{FINFLOW_BACKUP_ROOT:path.join(root,'nested','backups')}}),/direct application-data children/);
  assert.throws(()=>controlledRoots({appDataRoot:root,env:{FINFLOW_BACKUP_ROOT:path.join(root,'same'),FINFLOW_TRAVERSAL_TARGET_ROOT:path.join(root,'same')}}),/distinct/);
});

test('repository readiness is exhaustive and every failed predicate rejects',async()=>{
  let readiness=Object.fromEntries(READINESS_FIELDS.map(field=>[field,true]));let captured='';
  const pool={query:async text=>{captured=text;return{rows:[readiness]};}};
  const repo=createFinflowDurableResourceRepository(pool);assert.equal(await repo.assertReady(),true);
  for(const term of ['dataset_deletions','owner_resource_deletions','ensure_customer_dataset','assert_finflow_generation_active','guard_finflow_resource_immutable','guard_finflow_backup_lineage','guard_finflow_retirement','guard_finflow_owner_deletion','tgtype=27','prosecdef','search_path=pg_catalog'])assert.ok(captured.includes(term),term);
  for(const field of READINESS_FIELDS){readiness={...readiness,[field]:false};await assert.rejects(repo.assertReady(),{code:'FINFLOW_RESOURCE_STORAGE_NOT_READY'});readiness={...readiness,[field]:true};}
});

test('repository owner deletion calls bind exact job, owner and token set',async()=>{
  const calls=[];const pool={query:async(text,args)=>{calls.push([text,args]);return{rows:[{job_id:JOB,owner_id:41,status:'completed',file_tokens:[A],artifact_count:1,dataset_count:2,completed_at:'now'}]};}};
  const repo=createFinflowDurableResourceRepository(pool);
  assert.equal((await repo.beginOwnerDeletion({jobId:JOB,ownerId:41})).ownerId,41);
  assert.equal((await repo.completeOwnerDeletion({jobId:JOB,ownerId:41,fileTokens:[A]})).artifactCount,1);
  assert.deepEqual(calls[1][1],[JOB,41,[A]]);
});

test('canonical0011 separates reset history from account scrub and gates legacy destruction',()=>{
  for(const term of ['owner_resource_deletions','begin_owner_resource_deletion','complete_owner_resource_deletion',"snapshot_records='[]'::jsonb",'content_scrubbed_at','destroy_student_owner(requested_user_id bigint,requested_job_id uuid)',"d.status='completed'",'REVOKE ALL ON FUNCTION finflow.destroy_student_owner(bigint) FROM PUBLIC,dvaia_finflow_runtime'])assert.ok(sql.includes(term),term);
  assert.match(sql,/array_agg\(b\.file_token ORDER BY b\.file_token\)[\s\S]*WHERE b\.owner_id=p_owner_id;/);
  assert.match(sql,/NEW\.snapshot_records='\[\]'::jsonb[\s\S]*owner_resource_deletions[\s\S]*d\.status='pending'/);
  assert.match(sql,/CREATE TRIGGER finflow_dataset_deletion_guard BEFORE UPDATE OR DELETE ON finflow\.dataset_deletions/);
  assert.match(sql,/CREATE TRIGGER finflow_backup_read_guard BEFORE UPDATE OR DELETE ON finflow\.backup_reads/);
  assert.match(sql,/assert_finflow_generation_active[\s\S]*owner_resource_deletions[\s\S]*resource owner is deleted/);
  assert.match(sql,/OLD\.status IN \('ready','retired'\)[\s\S]*content_sha256 IS DISTINCT FROM OLD\.content_sha256/);
});
test('every reserved token is rechecked, replay retains same job and unreserved sibling is untouched',async()=>{
 const B='22222222-2222-4222-8222-222222222222',sibling='55555555-5555-4555-8555-555555555555';const remaining=new Set([A,B,sibling]),checks=[],removals=[];let completed=false;
 const cleanup=createFinflowOwnerResourceDeletion({repository:{beginOwnerDeletion:async()=>({ownerId:41,jobId:JOB,status:completed?'completed':'pending',fileTokens:[B,A],artifactCount:2,datasetCount:2}),completeOwnerDeletion:async scope=>{assert.equal(scope.ownerId,41);assert.equal(scope.jobId,JOB);assert.deepEqual(scope.fileTokens,[A,B]);completed=true;return{...scope,status:'completed',artifactCount:2,datasetCount:2,completedAt:'2026-09-14T00:00:00Z'};}},files:{remove:async tokens=>{removals.push([...tokens]);tokens.forEach(t=>remaining.delete(t));},absent:async token=>{checks.push(token);return!remaining.has(token);}}});
 for(let i=0;i<2;i++)assert(verifyFinflowOwnerDeletionReceipt(await cleanup(deletionScope()),{ownerId:41,jobId:JOB}));assert.deepEqual(checks,[A,B,A,B]);assert.deepEqual(removals,[[A,B],[A,B]]);assert.deepEqual([...remaining],[sibling]);
});
test('failed traversal retirement retries inside a fresh owner fence before store deletion',async()=>{
 const events=[];let attempts=0;const adapters=createStudentDeletionAdapters(()=>({resetOwner:async(owner,work)=>{assert.equal(owner,'41');events.push('enter');await work();events.push('exit');}}),{cleanupFinflowBackups:async()=>{events.push('backups');return issueFinflowOwnerDeletionReceipt({completed:true,ownerId:41,jobId:JOB,artifactCount:0});},retireFinflowTraversalOwner:async owner=>{assert.equal(owner,'41');events.push('retire');if(++attempts===1)throw Object.assign(Error('debt'),{code:'CONTROLLED_TRAVERSAL_CLEANUP_FAILED'});return true;},storeCleanup:{finflow:async()=>{events.push('store');return{completed:true};}}});
 await assert.rejects(adapters.finflow(deletionScope()),{code:'CONTROLLED_TRAVERSAL_CLEANUP_FAILED'});assert.deepEqual(events,['enter','backups','retire']);assert.deepEqual(await adapters.finflow(deletionScope()),{completed:true});assert.deepEqual(events.slice(3),['enter','backups','retire','store','exit']);
});
