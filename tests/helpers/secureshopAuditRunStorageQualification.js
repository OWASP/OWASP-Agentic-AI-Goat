'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { randomUUID, createHash } = require('node:crypto');
async function qualifyAuditRunStorage({ migration, runtime, review, root }) {
  await require('./secureshopAuditMigrationQualification').qualifyAuditMigration({migration,root});
  const readiness=require('../../server/services/secureshopBoundAuditComposition').assertSecureShopBoundAuditReadiness;
  await readiness({agentsPool:runtime,reviewPool:review,includeRunArtifacts:true});
  await migration.query('ALTER TABLE secureshop_agents.bound_audit_run_publications DISABLE TRIGGER bound_audit_publications_validate');
  await assert.rejects(readiness({agentsPool:runtime,reviewPool:review,includeRunArtifacts:true}),{code:'SECURESHOP_AUDIT_RUN_UNAVAILABLE'});
  await migration.query('ALTER TABLE secureshop_agents.bound_audit_run_publications ENABLE TRIGGER bound_audit_publications_validate');
  for(const grant of ['UPDATE(summary) ON secureshop_agents.bound_audit_runs',
    'INSERT ON secureshop_agents.bound_audit_run_deletion_receipts',
    'INSERT(created_at) ON secureshop_agents.bound_audit_runs']){
    await migration.query(`GRANT ${grant} TO dvaia_secureshop_agents_runtime`);
    await assert.rejects(readiness({agentsPool:runtime,reviewPool:review,includeRunArtifacts:true}),{code:'SECURESHOP_AUDIT_RUN_UNAVAILABLE'});
    await migration.query(`REVOKE ${grant} FROM dvaia_secureshop_agents_runtime`);
  }
  await readiness({agentsPool:runtime,reviewPool:review,includeRunArtifacts:true});
  async function insertRun(owner) {
    const id = randomUUID();
    await runtime.query(`INSERT INTO secureshop_agents.bound_audit_runs
      (run_id,request_id,launch_id,scenario_id,generation,original_platform_owner_id,original_platform_session_id,
       shop_user_id,owner_key,durable_generation,effect_key,requested_count,row_count,provider,model,summary)
      VALUES($1,$2,$3,$4,1,$5,100,3,'owned',1,'effect',20,0,'ollama','llama3.1:8b','Observed source')`,
      [id,randomUUID(),randomUUID(),randomUUID(),owner]);
    return id;
  }
  const spoolRoot=await fs.mkdtemp(path.join(require('node:os').tmpdir(),'owasp-ai-goat-audit-publish-test-'));
  try {
    const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:804,platformSessionId:805};
    const runId=randomUUID();
    const spool=await require('../../server/services/secureshopAuditObservationSpool').spoolAuditObservation({
      root:spoolRoot,scope,runId,requestedCount:20,checkCurrent:async()=>{},rows:(async function*(){})()});
    const artifacts=await require('../../server/agent-runtime/workers/secureshopAuditWorker').writeArtifacts(spool.directory,{
      messages:[{text:'x'.repeat(150000)}],traces:[],effects:[]});
    const result={runId,provider:'ollama',model:'controlled-storage-fixture',summary:'Storage verification only',
      logSha256:spool.manifest.logSha256,sourcesSha256:spool.manifest.sourcesSha256,rowCount:0,objectiveCredit:false,artifacts};
    const input={scope,persona:{id:3,role:'admin'},requestId:randomUUID(),execution:{runId,ownerKey:'owned',durableGeneration:1},
      effectKey:'owned-storage-test',spool,result};
    const {createSecureShopAuditRunRepository}=require('../../server/database/postgres/secureshopAuditRunRepository');
    const repository=createSecureShopAuditRunRepository({pool:runtime,checkCurrent:async()=>{}});
    const published=await repository.publish(input);assert.equal(published.published,true);assert.equal(published.objectiveCredit,false);
    const chunks=(await runtime.query("SELECT ordinal,content,content_sha256 FROM secureshop_agents.bound_audit_run_chunks WHERE run_id=$1 AND artifact='messages' ORDER BY ordinal",[runId])).rows;
    assert.equal(chunks.length,3);
    const digest=createHash('sha256');for(const chunk of chunks){digest.update(chunk.content);assert.deepEqual(chunk.content_sha256,createHash('sha256').update(chunk.content).digest());}
    assert.equal(digest.digest('hex'),artifacts.messages.sha256);
    const {createSecureShopAuditRunReader}=require('../../server/database/postgres/secureshopAuditRunReader');
    const completed={runId,ownerKey:'owned',generation:'1',effectKey:input.effectKey,status:'completed'};
    let ledgerReads=0,receipt=completed;
    const reader=createSecureShopAuditRunReader({pool:runtime,checkCurrent:async()=>{},
      readCompletedEffect:async()=>{ledgerReads++;return receipt;}});
    const readInput={scope,persona:input.persona,runId};
    for(const rejected of [null,{...completed,status:'uncertain'},{...completed,ownerKey:'sibling'},
      {...completed,runId:randomUUID()},{...completed,generation:'2'},{...completed,effectKey:'other'}]){
      receipt=rejected;await assert.rejects(reader.open(readInput),{code:'AUDIT_RUN_EFFECT_UNVERIFIED'});
    }
    receipt=completed;const beforeReads=ledgerReads;
    await assert.rejects(reader.open({...readInput,scope:{...scope,platformOwnerId:806}}),{code:'AUDIT_RUN_UNAVAILABLE'});
    assert.equal(ledgerReads,beforeReads);
    const opened=await reader.open(readInput);assert.equal(opened.objectiveCredit,false);
    const restored=[];for await(const chunk of opened.readArtifact('messages'))restored.push(chunk);
    assert.equal(JSON.parse(Buffer.concat(restored).toString())[0].text,'x'.repeat(150000));
    let emptyChunks=0;for await(const chunk of opened.readArtifact('log'))emptyChunks++;
    assert.equal(emptyChunks,0);
    const interrupted=opened.readArtifact('messages');await interrupted.next();receipt=null;
    await assert.rejects(async()=>{for await(const chunk of interrupted){}},{code:'AUDIT_RUN_EFFECT_UNVERIFIED'});
    receipt=completed;
    let current=true;
    const interruptedPool={async connect(){const client=await runtime.connect();return{
      async query(sql,args){const value=await client.query(sql,args);if(sql.startsWith('INSERT INTO secureshop_agents.bound_audit_run_chunks'))current=false;return value;},
      release:error=>client.release(error),
    };}};
    const failedId=randomUUID();const failedSpool={...spool,manifest:{...spool.manifest,runId:failedId}};
    await assert.rejects(createSecureShopAuditRunRepository({pool:interruptedPool,checkCurrent:async()=>{if(!current)throw Error('generation retired');}})
      .publish({...input,requestId:randomUUID(),execution:{...input.execution,runId:failedId},spool:failedSpool,result:{...result,runId:failedId}}),/generation retired/);
    assert.equal((await runtime.query('SELECT run_id FROM secureshop_agents.bound_audit_runs WHERE run_id=$1',[failedId])).rowCount,0);
    assert.equal((await runtime.query('SELECT run_id FROM secureshop_agents.bound_audit_run_chunks WHERE run_id=$1',[failedId])).rowCount,0);
    await runtime.query('SELECT * FROM secureshop_agents.destroy_bound_audit_owner($1,$2)',[804,randomUUID()]);
    await assert.rejects(reader.open(readInput),{code:'AUDIT_RUN_UNAVAILABLE'});
  } finally {await fs.rm(spoolRoot,{recursive:true,force:true});}
  const id = await insertRun(801), sibling = await insertRun(802);
  await assert.rejects(runtime.query('INSERT INTO secureshop_agents.bound_audit_run_publications(run_id) VALUES($1)', [id]), { code: '23514' });
  const bytes = Buffer.from('[]'), sha = createHash('sha256').update(bytes).digest();
  for (const artifact of ['log','sources','messages','traces','effects']) {
    await runtime.query('INSERT INTO secureshop_agents.bound_audit_run_artifacts(run_id,artifact,bytes,sha256) VALUES($1,$2,$3,$4)', [id,artifact,2,sha]);
    if (artifact !== 'effects') await runtime.query('INSERT INTO secureshop_agents.bound_audit_run_chunks(run_id,artifact,ordinal,content) VALUES($1,$2,0,$3)', [id,artifact,bytes]);
  }
  await assert.rejects(runtime.query('INSERT INTO secureshop_agents.bound_audit_run_publications(run_id) VALUES($1)', [id]), { code: '23514' });
  await runtime.query("INSERT INTO secureshop_agents.bound_audit_run_chunks(run_id,artifact,ordinal,content) VALUES($1,'effects',0,$2)", [id,bytes]);
  await runtime.query('INSERT INTO secureshop_agents.bound_audit_run_publications(run_id) VALUES($1)', [id]);
  await assert.rejects(runtime.query("INSERT INTO secureshop_agents.bound_audit_run_chunks(run_id,artifact,ordinal,content) VALUES($1,'effects',1,$2)", [id,bytes]), { code: '55000' });
  await assert.rejects(runtime.query("UPDATE secureshop_agents.bound_audit_runs SET summary='changed' WHERE run_id=$1", [id]), { code: '42501' });
  await assert.rejects(runtime.query('DELETE FROM secureshop_agents.bound_audit_runs WHERE run_id=$1', [id]), { code: '42501' });
  const job = randomUUID();
  await assert.rejects(runtime.query('SELECT * FROM secureshop_agents.destroy_bound_audit_runs($1,$2)', [801,job]), { code: '55000' });
  await runtime.query('SELECT * FROM secureshop_agents.destroy_bound_audit_owner($1,$2)', [801,job]);
  const receipt = (await runtime.query('SELECT * FROM secureshop_agents.destroy_bound_audit_runs($1,$2)', [801,job])).rows[0];
  assert.equal(Number(receipt.deleted_run_count),1);assert.equal(Number(receipt.deleted_artifact_count),5);
  assert.equal(Number(receipt.deleted_chunk_count),5);assert.equal(Number(receipt.deleted_bytes),10);
  const digest = createHash('sha256').update(['secureshop-audit-run-deletion-v1',job,'801','1','5','5','10'].join('\x1f')).digest();
  assert.deepEqual(receipt.receipt_sha256,digest);
  assert.deepEqual((await runtime.query('SELECT * FROM secureshop_agents.destroy_bound_audit_runs($1,$2)', [801,job])).rows[0], receipt);
  await assert.rejects(insertRun(801), { code: '55000' });
  assert.equal((await runtime.query('SELECT run_id FROM secureshop_agents.bound_audit_runs WHERE run_id=$1', [sibling])).rowCount,1);
  assert.equal((await runtime.query('SELECT run_id FROM secureshop_agents.bound_audit_run_chunks WHERE run_id=$1', [id])).rowCount,0);
  const cleanJournals=require('../../server/services/secureshopBoundAuditCleanup').createSecureShopBoundAuditCleanup({agentsPool:runtime,reviewPool:review});
  const createCleanup=require('../../server/services/secureshopAuditRunCleanup').createSecureShopAuditRunCleanup;
  const artifactJob=(await runtime.query('SELECT deletion_job_id FROM secureshop_agents.bound_audit_owner_deletion_receipts WHERE original_platform_owner_id=804')).rows[0].deletion_job_id;
  const deletion={subjectId:804,jobId:artifactJob,check:async()=>{}};
  const interrupted=createCleanup({cleanJournals,pool:{async query(){throw Error('injected artifact cleanup outage');}}});
  await assert.rejects(interrupted(deletion),/injected artifact cleanup outage/);
  assert.equal((await runtime.query('SELECT run_id FROM secureshop_agents.bound_audit_runs WHERE original_platform_owner_id=804')).rowCount,1);
  const composed=require('../../server/services/secureshopBoundAuditComposition').createSecureShopBoundAuditComposition({
    agentsPool:runtime,reviewPool:review,includeRunArtifacts:true}).cleanup;
  const cleaned=await composed(deletion);
  assert.equal(cleaned.artifacts.deletedRunCount,'1');assert.equal(cleaned.artifacts.deletedArtifactCount,'5');
  assert.ok(BigInt(cleaned.artifacts.deletedBytes)>150000n);
  assert.deepEqual(await composed(deletion),cleaned);
  assert.equal((await runtime.query('SELECT run_id FROM secureshop_agents.bound_audit_runs WHERE original_platform_owner_id=804')).rowCount,0);
  assert.equal((await runtime.query('SELECT run_id FROM secureshop_agents.bound_audit_runs WHERE run_id=$1',[sibling])).rowCount,1);
}
module.exports = { qualifyAuditRunStorage };
