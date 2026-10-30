'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { createFinflowDurableResources, createFinflowBackupFileStore } = require('../server/services/finflowDurableResources');
const { verifyFinflowBackupResourceReceipt } = require('../server/services/finflowBackupResourceReceipt');
const { createFinflowDurableResourceRepository, READINESS_FIELDS } = require('../server/database/postgres/finflowDurableResourceRepository');
const { createSensitiveInfoAggregateReset } = require('../server/services/sensitiveInfoAggregateReset');

const UUIDS = Object.freeze({
  create:'10000000-0000-4000-8000-000000000001', download:'10000000-0000-4000-8000-000000000002',
  delete:'10000000-0000-4000-8000-000000000003', sibling:'10000000-0000-4000-8000-000000000004',
  reset:'10000000-0000-4000-8000-000000000005', next:'10000000-0000-4000-8000-000000000006',
});
const clone = value => value == null ? value : structuredClone(value);
const key = value => `${value.ownerId}:${value.generation}`;
function memoryRepository(events = []) {
  const datasets=new Map(),backups=new Map(),operations=new Map(),reads=new Map(),retirements=new Map();
  function active(value) {
    if ([...retirements.values()].some(row=>row.ownerId===value.ownerId&&row.fromGeneration===value.generation)) {
      throw Object.assign(new Error('retired'),{code:'FINFLOW_RESOURCE_RETIRED'});
    }
  }
  function dataset(value) {
    active(value); const id=key(value);
    if(!datasets.has(id))datasets.set(id,{ownerId:value.ownerId,generation:value.generation,revision:0,
      records:clone(value.initialRecords),deleted:false,retired:false});
    return datasets.get(id);
  }
  return {
    datasets,backups,operations,reads,retirements,events,
    async readDataset(value){return clone(dataset(value));},
    async deleteDataset(value){active(value);const prior=operations.get(value.operationId);if(prior)return clone(prior);
      const data=dataset(value);data.records=[];data.deleted=true;data.revision+=1;
      const result={ownerId:value.ownerId,generation:value.generation,operationId:value.operationId,
        runId:value.runId,revision:data.revision,deleted:true,records:[]};
      operations.set(value.operationId,result);return clone(result);},
    async reserveBackup(value){active(value);const prior=operations.get(value.operationId);if(prior)return clone(prior);
      if([...backups.values()].some(row=>row.ownerId===value.ownerId&&row.generation===value.generation
        &&row.virtualPath===value.virtualPath))throw Object.assign(new Error('path conflict'),{code:'FINFLOW_BACKUP_PATH_CONFLICT'});
      const data=dataset(value);const row={ownerId:value.ownerId,generation:value.generation,operationId:value.operationId,
        runId:value.runId,backupId:value.backupId,fileToken:value.fileToken,virtualPath:value.virtualPath,
        datasetRevision:data.revision,records:clone(data.records),status:'writing',contentSha256:null,byteLength:null,recordCount:null};
      backups.set(row.backupId,row);operations.set(value.operationId,row);return clone(row);},
    async commitBackup(value){active(value);const row=backups.get(value.backupId);if(!row)throw Error('missing');
      for(const field of ['ownerId','generation','operationId','runId','fileToken','virtualPath','datasetRevision'])
        if(row[field]!==value[field])throw Error(`commit mismatch ${field}`);
      if(row.status==='writing')Object.assign(row,{status:'ready',contentSha256:value.contentSha256,
        byteLength:value.byteLength,recordCount:value.recordCount});
      else for(const field of ['contentSha256','byteLength','recordCount'])if(row[field]!==value[field])throw Error(`replay mismatch ${field}`);
      return clone(row);},
    async readBackup(value){active(value);return clone([...backups.values()].find(row=>row.ownerId===value.ownerId
      &&row.generation===value.generation&&row.virtualPath===value.virtualPath&&row.status==='ready'));},
    async listBackups(value){active(value);return clone([...backups.values()].filter(row=>row.ownerId===value.ownerId
      &&row.generation===value.generation&&row.status==='ready').sort((left,right)=>left.virtualPath.localeCompare(right.virtualPath)));},
    async recordBackupRead(value){active(value);const prior=reads.get(value.operationId);if(prior)return clone(prior);
      const backup=backups.get(value.backupId);if(!backup||backup.ownerId!==value.ownerId||backup.generation!==value.generation
        ||backup.virtualPath!==value.requestedPath||backup.contentSha256!==value.contentSha256
        ||backup.byteLength!==value.byteLength)throw Error('read mismatch');
      const row={ownerId:value.ownerId,generation:value.generation,operationId:value.operationId,
        runId:value.runId,backupId:value.backupId,
        requestedPath:value.requestedPath,contentSha256:value.contentSha256,byteLength:value.byteLength};
      reads.set(value.operationId,row);return clone(row);},
    async beginRetirement(value){const prior=retirements.get(value.operationId);if(prior)return clone(prior);
      if([...retirements.values()].some(row=>row.ownerId===value.ownerId&&(row.fromGeneration===value.fromGeneration
        ||row.toGeneration===value.toGeneration)))throw Error('retirement conflict');
      const fileTokens=[...backups.values()].filter(row=>row.ownerId===value.ownerId&&row.generation===value.fromGeneration
        &&['writing','ready'].includes(row.status)).map(row=>row.fileToken).sort();
      const row={...value,status:'pending',fileTokens,artifactCount:fileTokens.length};retirements.set(value.operationId,row);
      events.push('retirement-begun');return clone(row);},
    async completeRetirement(value){const row=retirements.get(value.operationId);assert.ok(row);assert.deepEqual(value.fileTokens,row.fileTokens);
      for(const backup of backups.values())if(backup.ownerId===value.ownerId&&backup.generation===value.fromGeneration)backup.status='retired';
      const data=datasets.get(`${value.ownerId}:${value.fromGeneration}`);if(data)data.retired=true;
      Object.assign(row,{status:'completed',completedAt:'2026-09-14T12:00:00.000Z'});events.push('retirement-completed');return clone(row);},
    async readRetirement(value){const row=retirements.get(value.operationId);return row&&row.ownerId===value.ownerId
      &&row.fromGeneration===value.fromGeneration&&row.toGeneration===value.toGeneration?clone(row):null;},
  };
}
function execution(ownerId,generation,runId,{checks}={}) {
  return {ownerKey:JSON.stringify(['FinFlow',String(ownerId)]),durableGeneration:generation,runId,
    async check(){checks?.push('check');},async effect(_key,work){return work();}};
}
async function fixture(t,repo=memoryRepository()) {
  const parent=await fs.mkdtemp(path.join(os.tmpdir(),'owasp-ai-goat-finflow-durable-'));t.after(()=>fs.rm(parent,{recursive:true,force:true}));
  const root=path.join(parent,'owned','backups');
  const files=createFinflowBackupFileStore({root});
  const resources=createFinflowDurableResources({repository:repo,files,
    initialRecords:[{id:1,name:'Ada'},{id:2,name:'Lin'}]});
  return {parent,root,files,resources,repo};
}

test('delete commits an empty dataset and a later backup writes and reads exact [] bytes',async t=>{
  const value=await fixture(t);const scope={ownerId:7,generation:0};
  const deleteExecution=execution(7,0,UUIDS.delete);
  const deletion=await value.resources.deleteDataset({scope,execution:deleteExecution});
  assert.equal(deletion.metadata.kind,'dataset_deleted');assert.equal(deletion.metadata.recordCount,0);
  assert.ok(verifyFinflowBackupResourceReceipt({receipt:deletion.authorityReceipt,execution:deleteExecution,
    action:'dataset_deleted',ownerId:7,operationId:deletion.metadata.operationId,result:deletion.metadata}));
  const createExecution=execution(7,0,UUIDS.create);
  const created=await value.resources.createBackup({scope,execution:createExecution,backupName:'after_delete'});
  assert.equal(created.metadata.virtualPath,'/var/app/data/backups/after_delete.bak');
  assert.equal(created.metadata.recordCount,0);assert.equal(created.metadata.byteLength,3);
  assert.ok(verifyFinflowBackupResourceReceipt({receipt:created.authorityReceipt,execution:createExecution,
    action:'backup_created',ownerId:7,operationId:created.metadata.operationId,backupId:created.metadata.backupId,
    requestedPath:created.metadata.virtualPath,result:created.metadata}));
  const downloadExecution=execution(7,0,UUIDS.download);
  const downloaded=await value.resources.downloadBackup({scope,execution:downloadExecution,
    requestedPath:'/var/app/data/backups/after_delete.bak'});
  assert.equal(downloaded.content,'[]\n');assert.equal(downloaded.metadata.contentSha256,created.metadata.contentSha256);
  const projection={content:downloaded.content,metadata:downloaded.metadata};
  assert.ok(verifyFinflowBackupResourceReceipt({receipt:downloaded.authorityReceipt,execution:downloadExecution,
    action:'backup_downloaded',ownerId:7,operationId:downloaded.metadata.operationId,
    backupId:downloaded.metadata.backupId,requestedPath:downloaded.metadata.requestedPath,result:projection}));
  assert.equal(verifyFinflowBackupResourceReceipt({receipt:{...downloaded.authorityReceipt},execution:downloadExecution,
    action:'backup_downloaded',ownerId:7,operationId:downloaded.metadata.operationId,
    backupId:downloaded.metadata.backupId,requestedPath:downloaded.metadata.requestedPath,result:projection}),null);
  const restarted=createFinflowDurableResources({repository:value.repo,
    files:createFinflowBackupFileStore({root:value.root}),initialRecords:[{id:1,name:'Ada'},{id:2,name:'Lin'}]});
  assert.equal((await restarted.downloadBackup({scope,execution:execution(7,0,UUIDS.next),
    requestedPath:'/var/app/data/backups/after_delete.bak'})).content,'[]\n');
});

test('create is idempotent under same-operation concurrency without a hard-link publication window',async t=>{
  const value=await fixture(t),scope={ownerId:7,generation:0},run=execution(7,0,UUIDS.create);
  const [left,right]=await Promise.all([
    value.resources.createBackup({scope,execution:run,backupName:'daily'}),
    value.resources.createBackup({scope,execution:run,backupName:'daily'}),
  ]);
  assert.equal(left.metadata.backupId,right.metadata.backupId);assert.equal(left.metadata.contentSha256,right.metadata.contentSha256);
  const names=await fs.readdir(path.join(value.root,'artifacts'));
  assert.deepEqual(names,[value.repo.backups.get(left.metadata.backupId).fileToken]);
  assert.equal((await value.files.read(value.repo.backups.get(left.metadata.backupId).fileToken)).byteLength,left.metadata.byteLength);
});

test('a crash after atomic publication but before metadata commit recovers the same immutable file',async t=>{
  const repo=memoryRepository(),original=repo.commitBackup.bind(repo);let failOnce=true;
  repo.commitBackup=async input=>{if(failOnce){failOnce=false;throw Object.assign(Error('lost commit response'),{code:'CONNECTION_LOST'});}return original(input);};
  const value=await fixture(t,repo),scope={ownerId:7,generation:0},run=execution(7,0,UUIDS.create);
  await assert.rejects(value.resources.createBackup({scope,execution:run,backupName:'recoverable'}),/lost commit response/);
  const reserved=[...repo.backups.values()][0],target=path.join(value.root,'artifacts',reserved.fileToken,'artifact.bak');
  const before=await fs.readFile(target);
  const recovered=await value.resources.createBackup({scope,execution:run,backupName:'recoverable'});
  assert.deepEqual(await fs.readFile(target),before);assert.equal(recovered.metadata.backupId,reserved.backupId);
});

test('exact requested path and bound repository scope are checked before file read',async t=>{
  const value=await fixture(t),scope={ownerId:7,generation:0};
  const created=await value.resources.createBackup({scope,execution:execution(7,0,UUIDS.create),backupName:'daily'});
  await assert.rejects(value.resources.downloadBackup({scope,execution:execution(7,0,UUIDS.download),
    requestedPath:'/var/app/data/backups/missing.bak'}),{code:'FINFLOW_BACKUP_NOT_FOUND'});
  await assert.rejects(value.resources.downloadBackup({scope:{ownerId:8,generation:0},execution:execution(8,0,UUIDS.sibling),
    requestedPath:created.metadata.virtualPath}),{code:'FINFLOW_BACKUP_NOT_FOUND'});
  let reads=0;const malicious={...value.repo,async readBackup(input){const row=await value.repo.readBackup(input);return{...row,ownerId:999};}};
  const resources=createFinflowDurableResources({repository:malicious,files:{...value.files,async read(token){reads++;return value.files.read(token);}},
    initialRecords:[{id:1}]});
  await assert.rejects(resources.downloadBackup({scope,execution:execution(7,0,UUIDS.next),requestedPath:created.metadata.virtualPath}),
    {code:'FINFLOW_BACKUP_METADATA_INVALID'});assert.equal(reads,0);
});

test('readback detects byte tamper and symlink substitution',async t=>{
  const value=await fixture(t),scope={ownerId:7,generation:0};
  const first=await value.resources.createBackup({scope,execution:execution(7,0,UUIDS.create),backupName:'daily'});
  const token=value.repo.backups.get(first.metadata.backupId).fileToken;
  const target=path.join(value.root,'artifacts',token,'artifact.bak');
  await fs.appendFile(target,'tamper');
  await assert.rejects(value.resources.downloadBackup({scope,execution:execution(7,0,UUIDS.download),
    requestedPath:first.metadata.virtualPath}),{code:'FINFLOW_BACKUP_FILE_INVALID'});
  await fs.rm(target);const outside=path.join(value.parent,'outside');await fs.writeFile(outside,'[]\n',{mode:0o600});
  await fs.symlink(outside,target);
  await assert.rejects(value.files.read(token),{code:'FINFLOW_BACKUP_FILE_UNAVAILABLE'});
});

test('controlled root ownership is revalidated after initialization and rejects parent substitution',async t=>{
  const value=await fixture(t);const scope={ownerId:7,generation:0};
  const created=await value.resources.createBackup({scope,execution:execution(7,0,UUIDS.create),backupName:'daily'});
  const owned=path.join(value.parent,'owned'),retained=path.join(value.parent,'owned-retained'),redirect=path.join(value.parent,'redirect');
  await fs.rename(owned,retained);await fs.mkdir(path.join(redirect,'backups'),{recursive:true,mode:0o700});
  await fs.symlink(redirect,owned);
  await assert.rejects(value.resources.downloadBackup({scope,execution:execution(7,0,UUIDS.download),
    requestedPath:created.metadata.virtualPath}),{code:'FINFLOW_BACKUP_STORE_UNAVAILABLE'});
  await fs.rm(owned);await fs.rename(retained,owned);
});

test('controlled file store rejects filesystem root and post-initialization permission drift',async t=>{
  assert.throws(()=>createFinflowBackupFileStore({root:path.parse(process.cwd()).root}),/private subdirectory/);
  const value=await fixture(t),scope={ownerId:7,generation:0};
  const created=await value.resources.createBackup({scope,execution:execution(7,0,UUIDS.create),backupName:'daily'});
  await fs.chmod(value.root,0o755);
  await assert.rejects(value.resources.downloadBackup({scope,execution:execution(7,0,UUIDS.download),
    requestedPath:created.metadata.virtualPath}),{code:'FINFLOW_BACKUP_STORE_UNAVAILABLE'});
  await fs.chmod(value.root,0o700);
});

test('aggregate reset retires files inside the canonical FinFlow drain, preserves siblings and does not seed ahead',async t=>{
  const events=[],repo=memoryRepository(events),value=await fixture(t,repo);
  const ownerScope={ownerId:7,generation:0},siblingScope={ownerId:8,generation:0};
  // Production owner coordinator; only durable ledger metadata is controlled here.
  const coordinator=require('../server/agent-runtime/runCoordinator').createRunCoordinator({family:'FinFlow',
    ledger:{begin:async()=>({durableGeneration:0})}});
  let releasePersistence,backupReady,oldExecution;
  const persistence=new Promise(resolve=>{releasePersistence=resolve;});
  const ready=new Promise(resolve=>{backupReady=resolve;});
  t.after(()=>releasePersistence());
  let owner;
  const older=coordinator.run('7',{},async current=>{
    oldExecution=current;
    owner=await value.resources.createBackup({scope:ownerScope,execution:current,backupName:'owner'});
    backupReady();
    await persistence;
    await current.check();
  });
  const olderRejected=assert.rejects(older,{name:'AbortError'});
  await ready;
  const sibling=await value.resources.createBackup({scope:siblingScope,execution:execution(8,0,UUIDS.sibling),backupName:'sibling'});
  const ownerToken=repo.backups.get(owner.metadata.backupId).fileToken;
  const abandoned=`.${ownerToken}.10000000-0000-4000-8000-000000000009.provisioning`;
  await fs.mkdir(path.join(value.root,'artifacts',abandoned),{mode:0o700});
  await fs.writeFile(path.join(value.root,'artifacts',abandoned,'.binding.json'),
    `${JSON.stringify({version:1,kind:'finflow-backup-artifact',fileToken:ownerToken})}\n`,{mode:0o600});
  await fs.writeFile(path.join(value.root,'artifacts',abandoned,'artifact.bak'),'partial',{mode:0o600});
  const receipts=new Map(),steps=['legacy_store','finflow_store'];let index=0,inDrain=false;
  const originalComplete=repo.completeRetirement.bind(repo);repo.completeRetirement=async input=>{assert.equal(inDrain,true);return originalComplete(input);};
  const journal={
    async begin(){return{operationId:UUIDS.reset,ownerId:7,fromGeneration:0,toGeneration:1,status:'pending'};},
    async read(){return{operationId:UUIDS.reset,ownerId:7,fromGeneration:0,toGeneration:1,status:'pending'};},
    async claim(){return{operationId:UUIDS.reset,ownerId:7,fromGeneration:0,toGeneration:1,status:'pending'};},
    async nextStep(){return steps[index++]||null;},async acknowledge(){},async fail(){},
    async complete(value){events.push('reset-completed');return{...value,status:'completed'};},
  };
  const cleanup={async apply(input){if(input.stepKey==='finflow_store'){
      const result=await value.resources.retireGeneration({operationId:input.operationId,ownerId:input.ownerId,
        fromGeneration:input.fromGeneration,toGeneration:input.toGeneration});receipts.set(input.stepKey,input);return result;
    }receipts.set(input.stepKey,input);return input;},async readReceipt(input){const stored=receipts.get(input.stepKey);
      assert.ok(stored);assert.equal(Object.keys(input).some(field=>stored[field]!==input[field]),false);return stored;}};
  const reset=createSensitiveInfoAggregateReset({legacyRuns:{async reset(_owner,work){events.push('legacy-drain');return work();}},
    finflowReset(owner,work){return coordinator.reset(owner,async()=>{
      events.push('finflow-drain');inDrain=true;try{return await work();}finally{inDrain=false;}
    });},cleanup,journal});
  const ownerBytes=(await value.files.read(ownerToken)).bytes.toString('utf8');
  const siblingToken=repo.backups.get(sibling.metadata.backupId).fileToken;
  const siblingBytes=(await value.files.read(siblingToken)).bytes.toString('utf8');
  assert.deepEqual(JSON.parse(ownerBytes),[{id:1,name:'Ada'},{id:2,name:'Lin'}]);
  let resetFinished=false;
  const resetting=reset.reset(7,{operationId:UUIDS.reset}).then(result=>{resetFinished=true;return result;});
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal(resetFinished,false,'reset waits for the older owner callback');
  assert.equal(events.includes('retirement-begun'),false,'no retirement before owner drain');
  assert.equal((await value.files.read(ownerToken)).bytes.toString('utf8'),ownerBytes);
  assert.equal((await value.files.read(siblingToken)).bytes.toString('utf8'),siblingBytes);
  await assert.rejects(oldExecution.check(),{name:'AbortError'});
  releasePersistence();
  await olderRejected;
  await resetting;
  assert.equal(await value.files.absent(ownerToken),true);
  assert.equal((await value.files.read(siblingToken)).bytes.toString('utf8'),siblingBytes);
  assert.ok(events.indexOf('finflow-drain')<events.indexOf('retirement-begun'));
  assert.ok(events.indexOf('retirement-completed')<events.indexOf('reset-completed'));
  assert.equal((await fs.readdir(path.join(value.root,'artifacts'))).includes(abandoned),false,
    'drained reset removes an abandoned staging directory bound to the retired token');
  assert.equal(repo.datasets.has('7:1'),false,'reset must not seed the next generation');
  await assert.rejects(value.resources.downloadBackup({scope:ownerScope,execution:execution(7,0,UUIDS.download),
    requestedPath:owner.metadata.virtualPath}),{code:'FINFLOW_RESOURCE_RETIRED'});
  assert.equal((await value.resources.downloadBackup({scope:siblingScope,execution:execution(8,0,UUIDS.next),
    requestedPath:sibling.metadata.virtualPath})).metadata.backupId,sibling.metadata.backupId);
  const next=await value.resources.readDataset({scope:{ownerId:7,generation:1},execution:execution(7,1,UUIDS.next)});
  assert.equal(next.records.length,2);assert.equal(repo.datasets.has('7:1'),true);
});

test('failed physical cleanup cannot publish a completed retirement receipt',async t=>{
  const value=await fixture(t),scope={ownerId:7,generation:0};
  await value.resources.createBackup({scope,execution:execution(7,0,UUIDS.create),backupName:'daily'});
  const resources=createFinflowDurableResources({repository:value.repo,files:{...value.files,async remove(){throw Error('disk busy');}},
    initialRecords:[{id:1,name:'Ada'},{id:2,name:'Lin'}]});
  const cleanup={operationId:UUIDS.reset,ownerId:7,fromGeneration:0,toGeneration:1};
  await assert.rejects(resources.retireGeneration(cleanup),/disk busy/);
  assert.equal((await resources.readRetirement(cleanup)).status,'pending');
});

test('repository adapter binds SQL arguments and registered 0011 retains least-privilege functions',async()=>{
  const calls=[];const pool={async query(sql,params){calls.push([sql,params]);
    if(sql.includes("to_regclass('finflow.customer_datasets')"))return{rows:[Object.fromEntries(READINESS_FIELDS.map(field=>[field,true]))]};
    if(sql.includes('read_customer_dataset'))return{rows:[{owner_id:7,generation:0,revision:0,records:[],deleted:false}]};
    throw Error(sql);}};
  const repository=createFinflowDurableResourceRepository(pool);assert.equal(await repository.assertReady(),true);
  assert.deepEqual(await repository.readDataset({ownerId:7,generation:0,initialRecords:[]}),
    {ownerId:7,generation:0,revision:0,records:[],deleted:false});
  assert.deepEqual(calls[1][1],[7,0,'[]']);
  assert.match(calls[0][0],/to_regnamespace\('finflow'\)/);assert.match(calls[0][0],/t\.tgrelid=artifacts_oid/);
  assert.match(calls[0][0],/list_customer_backups\(bigint,bigint\)/);
  assert.match(calls[0][0],/t\.tgfoid=lineage_function_oid/);assert.doesNotMatch(calls[0][0],/has_function_privilege\(current_user,'finflow/);
  const draft=await fs.readFile(path.join(__dirname,'../db/postgres/workshop-migrations/finflow/0011_durable_customer_backups.sql'),'utf8');
  for(const name of ['customer_datasets','backup_artifacts','backup_reads','resource_retirements',
    'reserve_customer_backup','commit_customer_backup','record_customer_backup_read','begin_resource_retirement','complete_resource_retirement'])
    assert.match(draft,new RegExp(name));
  assert.doesNotMatch(draft,/UNREGISTERED FORWARD DRAFT/);assert.match(draft,/REVOKE ALL ON/);assert.match(draft,/FROM PUBLIC/);
  assert.match(draft,/status='pending'[\s\S]*file_tokens[\s\S]*status='completed'/);
  assert.match(draft,/NEW\.content_sha256 IS DISTINCT FROM OLD\.content_sha256/);
  const migrationNames=await fs.readdir(path.join(__dirname,'../db/postgres/workshop-migrations/finflow'));
  assert.deepEqual(migrationNames.filter(name=>name.includes('durable_customer_backups')),
    ['0011_durable_customer_backups.sql']);
  const staged=await fs.readFile(path.join(__dirname,'../db/postgres/workshop-migrations/finflow/0011_durable_customer_backups.sql'),'utf8');
  assert.match(staged,/PRIVATE QUALIFICATION STAGE/);assert.doesNotMatch(staged,/UNREGISTERED FORWARD DRAFT/);
});

test('repository readiness fails closed for missing objects and a same-name spoof trigger',async()=>{
  for(const field of ['schema','datasets','read_dataset','lineage_function','lineage_guard','runtime_execute',
    'no_runtime_tables','no_public_execute','expected_definers']){
    const row=Object.fromEntries(READINESS_FIELDS.map(name=>[name,true]));row[field]=false;
    const repository=createFinflowDurableResourceRepository({async query(){return{rows:[row]};}});
    await assert.rejects(repository.assertReady(),{code:'FINFLOW_RESOURCE_STORAGE_NOT_READY'});
  }
});
