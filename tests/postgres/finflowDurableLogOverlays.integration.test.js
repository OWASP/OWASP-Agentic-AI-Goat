'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const path=require('node:path');
const crypto=require('node:crypto');
const {Pool}=require('pg');

const enabled=process.env.RUN_FINFLOW_LOG_OVERLAY_NATIVE==='1';
const runtimeUrl=process.env.FINFLOW_RUNTIME_DATABASE_URL;
const migrationUrl=process.env.FINFLOW_MIGRATION_DATABASE_URL;
const appDataRoot=process.env.DVAIA_APP_DATA_ROOT;
const integration=enabled&&runtimeUrl&&migrationUrl&&appDataRoot?test:test.skip;
const run=(suffix)=>`60000000-0000-4000-8000-${String(suffix).padStart(12,'0')}`;
const execution=(ownerId,generation,runId)=>({ownerId:String(ownerId),
  ownerKey:JSON.stringify(['FinFlow',String(ownerId)]),durableGeneration:generation,runId,
  async check(){},async effect(_key,work){return work();}});
async function bounded(promise,milliseconds=5000){
  let timer;
  try{return await Promise.race([promise,new Promise((_,reject)=>{
    timer=setTimeout(()=>reject(Object.assign(new Error('FinFlow concurrent operation timed out'),
      {code:'TEST_TIMEOUT'})),milliseconds);
  })]);}finally{clearTimeout(timer);}
}

integration('registered 0012 persists exact owner overlays across restart and retires them with generation reset',async t=>{
  const runtime=new Pool({connectionString:runtimeUrl,max:1});
  const restartedPool=new Pool({connectionString:runtimeUrl,max:1});
  const migration=new Pool({connectionString:migrationUrl,max:1});
  t.after(async()=>{await runtime.end();await restartedPool.end();await migration.end();});
  const {createFinflowDurableResourceLifecycle}=require('../../server/services/finflowDurableResourceComposition');
  const {createFinflowLogOverlayRepository}=require('../../server/database/postgres/finflowLogOverlayRepository');
  const lifecycle=await createFinflowDurableResourceLifecycle({pool:runtime,appDataRoot});
  assert.equal(await createFinflowLogOverlayRepository(runtime).assertReady(),true);
  const migrationName='0012_durable_log_overlays.sql';
  const migrationBytes=await fs.readFile(path.join(__dirname,'../../db/postgres/workshop-migrations/finflow',migrationName));
  const ledger=(await migration.query('SELECT checksum FROM dvaia_migrations.ledger WHERE name=$1',[migrationName])).rows;
  assert.equal(ledger.length,1,'0012 was applied by the canonical migration loader');
  assert.equal(ledger[0].checksum,crypto.createHash('sha256').update(migrationBytes).digest('hex'));
  const owner={ownerId:7001,generation:0},sibling={ownerId:7002,generation:0};
  const changed='2026-09-14T12:00:00Z owner-scoped audit redaction\n';
  const mutationExecution=execution(7001,0,run(1));
  const written=await lifecycle.resources.writeLogOverlay({scope:owner,execution:mutationExecution,
    logType:'audit',action:'modify',content:changed});
  assert.equal(written.contentSha256,crypto.createHash('sha256').update(changed).digest('hex'));
  const exactReplay=await lifecycle.resources.writeLogOverlay({scope:owner,execution:mutationExecution,
    logType:'audit',action:'modify',content:changed});
  assert.equal(exactReplay.operationId,written.operationId);assert.equal(exactReplay.revision,written.revision);
  const beforeNoEffect=(await migration.query(`SELECT o.action,o.content,o.content_sha256,o.byte_length,
      o.revision,count(m.*)::integer AS mutations
    FROM finflow.log_overlays o JOIN finflow.log_overlay_mutations m USING(owner_id,generation,log_type)
    WHERE o.owner_id=$1 AND o.generation=$2 AND o.log_type=$3
    GROUP BY o.owner_id,o.generation,o.log_type,o.action,o.content,o.content_sha256,o.byte_length,o.revision`,
    [7001,0,'audit'])).rows[0];
  await assert.rejects(lifecycle.resources.writeLogOverlay({scope:owner,
    execution:execution(7001,0,run(16)),logType:'audit',action:'modify',content:changed}),
  error=>error?.code==='55000');
  const afterNoEffect=(await migration.query(`SELECT o.action,o.content,o.content_sha256,o.byte_length,
      o.revision,count(m.*)::integer AS mutations
    FROM finflow.log_overlays o JOIN finflow.log_overlay_mutations m USING(owner_id,generation,log_type)
    WHERE o.owner_id=$1 AND o.generation=$2 AND o.log_type=$3
    GROUP BY o.owner_id,o.generation,o.log_type,o.action,o.content,o.content_sha256,o.byte_length,o.revision`,
    [7001,0,'audit'])).rows[0];
  assert.deepEqual(afterNoEffect,beforeNoEffect,'a distinct no-effect run cannot change state or history');
  assert.equal((await lifecycle.resources.readLogOverlay({scope:owner,execution:execution(7001,0,run(2)),
    logType:'audit'})).content,changed);
  assert.equal(await lifecycle.resources.readLogOverlay({scope:sibling,execution:execution(7002,0,run(3)),
    logType:'audit'}),null);

  const restarted=await createFinflowDurableResourceLifecycle({pool:restartedPool,appDataRoot});
  assert.equal((await restarted.resources.readLogOverlay({scope:owner,execution:execution(7001,0,run(4)),
    logType:'audit'})).content,changed);
  const deleted=await restarted.resources.writeLogOverlay({scope:owner,execution:mutationExecution,
    logType:'audit',action:'delete',content:'ignored for delete'});
  assert.notEqual(deleted.operationId,written.operationId);assert.equal(deleted.revision,2);
  assert.equal((await lifecycle.resources.readLogOverlay({scope:owner,execution:execution(7001,0,run(6)),
    logType:'audit'})).content,'');
  const beforeStaleReplay=(await migration.query(`SELECT o.action,o.content,o.content_sha256,o.byte_length,
      o.revision,count(m.*)::integer AS mutations
    FROM finflow.log_overlays o JOIN finflow.log_overlay_mutations m USING(owner_id,generation,log_type)
    WHERE o.owner_id=$1 AND o.generation=$2 AND o.log_type=$3
    GROUP BY o.owner_id,o.generation,o.log_type,o.action,o.content,o.content_sha256,o.byte_length,o.revision`,
    [7001,0,'audit'])).rows[0];
  await assert.rejects(lifecycle.resources.writeLogOverlay({scope:owner,execution:mutationExecution,
    logType:'audit',action:'modify',content:changed}),error=>error?.code==='55000');
  const afterStaleReplay=(await migration.query(`SELECT o.action,o.content,o.content_sha256,o.byte_length,
      o.revision,count(m.*)::integer AS mutations
    FROM finflow.log_overlays o JOIN finflow.log_overlay_mutations m USING(owner_id,generation,log_type)
    WHERE o.owner_id=$1 AND o.generation=$2 AND o.log_type=$3
    GROUP BY o.owner_id,o.generation,o.log_type,o.action,o.content,o.content_sha256,o.byte_length,o.revision`,
    [7001,0,'audit'])).rows[0];
  assert.deepEqual(afterStaleReplay,beforeStaleReplay);
  assert.equal(Number(afterStaleReplay.revision),2);assert.equal(afterStaleReplay.content,'');
  assert.equal(Number(afterStaleReplay.mutations),2);
  await assert.rejects(lifecycle.resources.writeLogOverlay({scope:owner,
    execution:execution(7001,0,run(17)),logType:'audit',action:'delete',content:''}),
  error=>error?.code==='55000');
  const afterRepeatedDelete=(await migration.query(`SELECT o.action,o.content,o.content_sha256,o.byte_length,
      o.revision,count(m.*)::integer AS mutations
    FROM finflow.log_overlays o JOIN finflow.log_overlay_mutations m USING(owner_id,generation,log_type)
    WHERE o.owner_id=$1 AND o.generation=$2 AND o.log_type=$3
    GROUP BY o.owner_id,o.generation,o.log_type,o.action,o.content,o.content_sha256,o.byte_length,o.revision`,
    [7001,0,'audit'])).rows[0];
  assert.deepEqual(afterRepeatedDelete,beforeStaleReplay,
    'a distinct repeated delete cannot change state or mutation history');

  await restarted.resources.retireGeneration({operationId:run(7),ownerId:7001,fromGeneration:0,toGeneration:1});
  await assert.rejects(lifecycle.resources.readLogOverlay({scope:owner,execution:execution(7001,0,run(8)),
    logType:'audit'}),error=>error?.code==='55000'||error?.code==='FINFLOW_RESOURCE_RETIRED');
  assert.equal(await lifecycle.resources.readLogOverlay({scope:{ownerId:7001,generation:1},
    execution:execution(7001,1,run(9)),logType:'audit'}),null);
  assert.equal(await lifecycle.resources.readLogOverlay({scope:sibling,execution:execution(7002,0,run(10)),
    logType:'audit'}),null);
  await assert.rejects(lifecycle.resources.readLogOverlay({scope:owner,execution:execution(7002,0,run(11)),
    logType:'audit'}),{code:'FINFLOW_RESOURCE_SCOPE_INVALID'});

  await restarted.resources.writeLogOverlay({scope:{ownerId:7001,generation:1},
    execution:execution(7001,1,run(12)),logType:'error',action:'modify',content:'owner deletion body'});
  const deletionReceipt=await restarted.cleanupOwner({subjectId:7001,jobId:run(13),leaseToken:run(14),async check(){}});
  assert.ok(deletionReceipt);
  await assert.rejects(restarted.resources.readLogOverlay({scope:{ownerId:7001,generation:1},
    execution:execution(7001,1,run(15)),logType:'error'}),error=>error?.code==='55000');

  const history=(await migration.query(`SELECT o.retired_at,o.content,o.revision,count(m.*)::integer AS mutations
    FROM finflow.log_overlays o JOIN finflow.log_overlay_mutations m USING(owner_id,generation,log_type)
    WHERE o.owner_id=$1 AND o.generation=$2 AND o.log_type=$3
    GROUP BY o.owner_id,o.generation,o.log_type,o.retired_at,o.content,o.revision`,[7001,0,'audit'])).rows[0];
  assert.ok(history.retired_at);assert.equal(history.content,'');assert.equal(Number(history.revision),2);
  assert.equal(Number(history.mutations),2);
  const scrubbed=(await migration.query(`SELECT content,content_scrubbed_at,content_sha256,byte_length
    FROM finflow.log_overlays WHERE owner_id=$1 AND generation=$2 AND log_type=$3`,[7001,1,'error'])).rows[0];
  assert.equal(scrubbed.content,'');assert.ok(scrubbed.content_scrubbed_at);
  assert.equal(scrubbed.byte_length,19);assert.equal(scrubbed.content_sha256,
    crypto.createHash('sha256').update('owner deletion body').digest('hex'),'historical digest survives body scrub');
  await assert.rejects(migration.query(`UPDATE finflow.log_overlay_mutations SET revision=99 WHERE owner_id=$1`,[7001]),
    error=>error?.code==='23514');
  await migration.query('ROLLBACK').catch(()=>{});
});

integration('same-owner concurrent writes serialize into one contiguous overlay lineage without deadlock',async t=>{
  const firstPool=new Pool({connectionString:runtimeUrl,max:1});
  const secondPool=new Pool({connectionString:runtimeUrl,max:1});
  const migration=new Pool({connectionString:migrationUrl,max:1});
  t.after(async()=>{await firstPool.end();await secondPool.end();await migration.end();});
  const {createFinflowDurableResourceLifecycle}=require('../../server/services/finflowDurableResourceComposition');
  const [first,second]=await Promise.all([
    createFinflowDurableResourceLifecycle({pool:firstPool,appDataRoot}),
    createFinflowDurableResourceLifecycle({pool:secondPool,appDataRoot}),
  ]);
  const owner={ownerId:7101,generation:0};
  const contents=['concurrent mutation from worker one\n','concurrent mutation from worker two\n'];
  const settled=await bounded(Promise.allSettled([
    first.resources.writeLogOverlay({scope:owner,execution:execution(7101,0,run(101)),
      logType:'access',action:'modify',content:contents[0]}),
    second.resources.writeLogOverlay({scope:owner,execution:execution(7101,0,run(102)),
      logType:'access',action:'modify',content:contents[1]}),
  ]));
  assert.deepEqual(settled.map(result=>result.status),['fulfilled','fulfilled']);
  assert.deepEqual(settled.map(result=>result.value.revision).sort((a,b)=>a-b),[1,2]);
  const row=(await migration.query(`SELECT o.content,o.content_sha256,o.revision,
      array_agg(m.revision ORDER BY m.revision) AS mutation_revisions,count(m.*)::integer AS mutations
    FROM finflow.log_overlays o JOIN finflow.log_overlay_mutations m USING(owner_id,generation,log_type)
    WHERE o.owner_id=$1 AND o.generation=$2 AND o.log_type=$3
    GROUP BY o.owner_id,o.generation,o.log_type,o.content,o.content_sha256,o.revision`,
    [7101,0,'access'])).rows[0];
  assert.equal(Number(row.revision),2);assert.equal(Number(row.mutations),2);
  assert.deepEqual(row.mutation_revisions.map(Number),[1,2]);assert.ok(contents.includes(row.content));
  assert.equal(row.content_sha256,crypto.createHash('sha256').update(row.content).digest('hex'));
});

integration('same-owner reset racing a write serializes retirement and leaves no active old-generation overlay',async t=>{
  const writePool=new Pool({connectionString:runtimeUrl,max:1});
  const resetPool=new Pool({connectionString:runtimeUrl,max:1});
  const migration=new Pool({connectionString:migrationUrl,max:1});
  t.after(async()=>{await writePool.end();await resetPool.end();await migration.end();});
  const {createFinflowDurableResourceLifecycle}=require('../../server/services/finflowDurableResourceComposition');
  const [writer,resetter]=await Promise.all([
    createFinflowDurableResourceLifecycle({pool:writePool,appDataRoot}),
    createFinflowDurableResourceLifecycle({pool:resetPool,appDataRoot}),
  ]);
  const owner={ownerId:7201,generation:0};
  await writer.resources.writeLogOverlay({scope:owner,execution:execution(7201,0,run(201)),
    logType:'error',action:'modify',content:'pre-race overlay\n'});
  const settled=await bounded(Promise.allSettled([
    resetter.resources.retireGeneration({operationId:run(202),ownerId:7201,fromGeneration:0,toGeneration:1}),
    writer.resources.writeLogOverlay({scope:owner,execution:execution(7201,0,run(203)),
      logType:'error',action:'modify',content:'racing write\n'}),
  ]));
  assert.equal(settled[0].status,'fulfilled','retirement must complete');
  if(settled[1].status==='rejected')assert.equal(settled[1].reason?.code,'55000');
  else assert.equal(settled[1].value.revision,2);
  const row=(await migration.query(`SELECT o.content,o.revision,o.retired_at,
      array_agg(m.revision ORDER BY m.revision) AS mutation_revisions,count(m.*)::integer AS mutations
    FROM finflow.log_overlays o JOIN finflow.log_overlay_mutations m USING(owner_id,generation,log_type)
    WHERE o.owner_id=$1 AND o.generation=$2 AND o.log_type=$3
    GROUP BY o.owner_id,o.generation,o.log_type,o.content,o.revision,o.retired_at`,
    [7201,0,'error'])).rows[0];
  assert.ok(row.retired_at);assert.ok([1,2].includes(Number(row.revision)));
  assert.equal(Number(row.mutations),Number(row.revision));
  assert.deepEqual(row.mutation_revisions.map(Number),
    Array.from({length:Number(row.revision)},(_,index)=>index+1));
  await assert.rejects(writer.resources.readLogOverlay({scope:owner,
    execution:execution(7201,0,run(204)),logType:'error'}),error=>
    error?.code==='55000'||error?.code==='FINFLOW_RESOURCE_RETIRED');
  assert.equal(await resetter.resources.readLogOverlay({scope:{ownerId:7201,generation:1},
    execution:execution(7201,1,run(205)),logType:'error'}),null);
});

integration('runtime role has function-only access to overlay state',async t=>{
  const runtime=new Pool({connectionString:runtimeUrl,max:1});t.after(()=>runtime.end());
  await assert.rejects(runtime.query('SELECT * FROM finflow.log_overlays LIMIT 1'),error=>error?.code==='42501');
  await assert.rejects(runtime.query('SELECT * FROM finflow.log_overlay_mutations LIMIT 1'),error=>error?.code==='42501');
  assert.equal(await require('../../server/database/postgres/finflowLogOverlayRepository')
    .createFinflowLogOverlayRepository(runtime).assertReady(),true);
});

integration('readiness detects disabled exact overlay guard and immutable mutation guard rejects tampering',async t=>{
  const runtime=new Pool({connectionString:runtimeUrl,max:1}),migration=new Pool({connectionString:migrationUrl,max:1});
  let disabled=false;
  t.after(async()=>{
    if(disabled)await migration.query('ALTER TABLE finflow.log_overlays ENABLE TRIGGER finflow_log_overlay_guard');
    await runtime.end();await migration.end();
  });
  await migration.query('ALTER TABLE finflow.log_overlays DISABLE TRIGGER finflow_log_overlay_guard');disabled=true;
  await assert.rejects(require('../../server/database/postgres/finflowLogOverlayRepository')
    .createFinflowLogOverlayRepository(runtime).assertReady(),{code:'FINFLOW_LOG_OVERLAY_STORAGE_NOT_READY'});
  await migration.query('ALTER TABLE finflow.log_overlays ENABLE TRIGGER finflow_log_overlay_guard');disabled=false;
  assert.equal(await require('../../server/database/postgres/finflowLogOverlayRepository')
    .createFinflowLogOverlayRepository(runtime).assertReady(),true);
  await assert.rejects(migration.query(`UPDATE finflow.log_overlay_mutations SET revision=revision+1
    WHERE owner_id=7001`),error=>error?.code==='23514');
});
