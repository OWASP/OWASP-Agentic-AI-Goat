'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');
const prefix = 'PG_HISTORY_CLEANUP_';
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' && process.env[prefix + 'MIGRATION_URL'] && process.env[prefix + 'RUNTIME_URL'];
function url(kind) {
  const value = new URL(process.env[prefix + kind + '_URL']);
  assert.equal(value.hostname, '127.0.0.1');
  assert.match(value.pathname, /^\/owasp_ai_goat_test_history_cleanup_[a-f0-9]+$/);
  assert.equal(value.username, 'dvaia_legacy_challenge_' + kind.toLowerCase());
  assert.equal(value.search, ''); assert.equal(value.hash, '');
  return value.href;
}
test('source cleanup compares exact rows atomically and denies runtime callers and stale replay', { skip: !enabled, timeout: 30000 }, async () => {
  const migration = new Pool({ connectionString: url('MIGRATION') });
  const runtime = new Pool({ connectionString: url('RUNTIME') });
  const prefixDirectory = await fs.mkdtemp(path.join(require('node:os').tmpdir(),'owasp-ai-goat-source-upgrade-'));
  try {
    const directory = path.resolve(__dirname, '../../db/postgres/workshop-migrations/legacy_challenge');
    await fs.cp(directory,prefixDirectory,{recursive:true});
    for (const name of (await fs.readdir(prefixDirectory)).filter(name => name >= '0004'))
      await fs.unlink(path.join(prefixDirectory,name));
    await migrate(migration,prefixDirectory);
    const rows = [
      { id: 401, userId: null, prompt: 'exact\nUnicode 🎓', response: null, modelUsed: null, createdAt: '2026-01-02T03:04:05.123456Z', platformOwnerId: null },
      { id: 402, userId: 19, prompt: 'second', response: 'response', modelUsed: 'local', createdAt: 'infinity', platformOwnerId: 31 },
      { id: 404, userId: null, prompt: 'null timestamp', response: '', modelUsed: '', createdAt: null, platformOwnerId: null },
      { id: 405, userId: null, prompt: 'negative infinity', response: null, modelUsed: null, createdAt: '-infinity', platformOwnerId: null },
      { id: 406, userId: null, prompt: 'BC timestamp', response: null, modelUsed: null, createdAt: '0001-01-01 00:00:00.123456 BC', platformOwnerId: null },
    ];
    for (const row of rows) await runtime.query(`INSERT INTO legacy_challenge.ai_conversations
      (id,user_id,prompt,response,model_used,created_at,platform_owner_id) VALUES($1,$2,$3,$4,$5,$6,$7)`,
    [row.id, row.userId, row.prompt, row.response, row.modelUsed, row.createdAt, row.platformOwnerId]);
    await runtime.query("INSERT INTO legacy_challenge.ai_conversations(id,prompt) VALUES(403,'synthetic sibling')");
    const beforeUpgrade = (await runtime.query('SELECT jsonb_agg(to_jsonb(row) ORDER BY id) AS rows FROM legacy_challenge.ai_conversations row')).rows[0].rows;
    assert.deepEqual(await migrate(migration,directory),['0004_private_history_source_cleanup.sql','0005_private_history_boundary.sql']);
    assert.deepEqual(await migrate(migration,directory),[]);
    assert.deepEqual((await migration.query('SELECT jsonb_agg(to_jsonb(row) ORDER BY id) AS rows FROM legacy_challenge.ai_conversations row')).rows[0].rows,beforeUpgrade);
    const batch = randomUUID();
    const call = (pool, id, records, target = 'owned-target') => pool.query(
      'SELECT * FROM legacy_ai_source_cleanup.cleanup_history_source($1,$2,$3,$4)',
      [id, target, 'a'.repeat(64), JSON.stringify(records)]);
    await assert.rejects(call(runtime, batch, rows), { code: '42501' });
    await assert.rejects(call(migration, batch, [rows[0], { ...rows[1], prompt: 'changed' }]));
    assert.equal((await migration.query('SELECT count(*)::integer AS n FROM legacy_challenge.ai_conversations WHERE id IN (401,402)')).rows[0].n, 2);
    await assert.rejects(runtime.query('SELECT * FROM legacy_ai_source_cleanup.receipts'), { code: '42501' });
    const transaction = await migration.connect();
    try {
      await transaction.query('BEGIN');
      await call(transaction, batch, rows);
      await transaction.query('ROLLBACK');
    } finally { await transaction.query('ROLLBACK'); transaction.release(); }
    assert.equal((await migration.query('SELECT count(*)::integer AS n FROM legacy_challenge.ai_conversations')).rows[0].n, rows.length + 1);
    assert.equal((await migration.query('SELECT count(*)::integer AS n FROM legacy_ai_source_cleanup.receipts')).rows[0].n, 0);
    const removed = (await call(migration, batch, rows)).rows[0];
    assert.equal(removed.removed_count, rows.length);
    assert.equal(removed.replayed, false);
    assert.deepEqual((await migration.query('SELECT id FROM legacy_challenge.ai_conversations ORDER BY id')).rows, [{ id: 403 }]);
    const replay = (await call(migration, batch, rows)).rows[0];
    assert.equal(replay.replayed, true);
    await assert.rejects(call(migration, batch, rows, 'different-target'));
    await migration.query("INSERT INTO legacy_challenge.ai_conversations(id,prompt) VALUES(401,'new content using old ID')");
    await assert.rejects(call(migration, batch, rows));
    assert.equal((await migration.query('SELECT prompt FROM legacy_challenge.ai_conversations WHERE id=401')).rows[0].prompt, 'new content using old ID');
    await assert.rejects(call(migration, randomUUID(), [rows[0], rows[0]]));
  } finally { await Promise.all([runtime.end(), migration.end()]); await fs.rm(prefixDirectory,{recursive:true,force:true}); }
});

test('two-store coordinator retains quarantine through source commit and recovers a failed target acknowledgement', {
  skip: !enabled || !process.env[prefix + 'TARGET_MIGRATION_URL'], timeout: 30000,
}, async () => {
  const { createLegacyAiHistoryCutoverCoordinator } = require('../../server/database/postgres/legacyAiHistoryCutoverCoordinator');
  const { digest } = require('../../server/database/postgres/legacyAiHistoryDraftImporter');
  const targetUrl = new URL(process.env[prefix + 'TARGET_MIGRATION_URL']);
  assert.equal(targetUrl.hostname, '127.0.0.1');
  assert.equal(targetUrl.username, 'dvaia_identity_migration');
  assert.match(targetUrl.pathname, /^\/owasp_ai_goat_test_history_cleanup_[a-f0-9]+$/);
  const source = new Pool({ connectionString: url('MIGRATION') });
  const target = new Pool({ connectionString: targetUrl.href });
  try {
    await migrate(target, path.resolve(__dirname, '../../db/postgres/identity-migrations'));
    const record = { id: 501, userId: null, prompt: 'cross-store private prompt', response: 'exact response', modelUsed: 'controlled', createdAt: '2026-01-02T03:04:05.123456Z', platformOwnerId: null };
    await source.query(`INSERT INTO legacy_challenge.ai_conversations(id,prompt,response,model_used,created_at)
      VALUES($1,$2,$3,$4,$5)`, [record.id,record.prompt,record.response,record.modelUsed,record.createdAt]);
    const batchId = randomUUID(), boundSourceStoreIdentity = 'owned-two-store-fixture';
    const aggregateDigest = digest([{ sourceRowId: record.id, sourceDigest: digest(record) }]);
    await target.query('SELECT * FROM legacy_ai_private.begin_history_import($1,$2,$3,$4)', [batchId,boundSourceStoreIdentity,1,aggregateDigest]);
    await target.query('SELECT * FROM legacy_ai_private.archive_history_import_row($1,$2,$3,$4,$5,$6)', [batchId,record.id,record,digest(record),'unknown',null]);
    await target.query('SELECT * FROM legacy_ai_private.verify_history_import_quarantine($1,$2,$3)', [batchId,1,aggregateDigest]);
    const options = { sourcePool: source, targetPool: target, sourceDatabase: new URL(url('MIGRATION')).pathname.slice(1), targetDatabase: targetUrl.pathname.slice(1) };
    const coordinator = createLegacyAiHistoryCutoverCoordinator(options);
    const request = { batchId,boundSourceStoreIdentity,aggregateDigest };
    await assert.rejects(coordinator.removeQuarantinedSource({ ...request, aggregateDigest: '0'.repeat(64) }), { code: 'LEGACY_AI_CUTOVER_UNAVAILABLE' });
    await target.query(`UPDATE legacy_ai_private.import_archive SET source_record=source_record||'{"unexpected":"field"}'::jsonb WHERE batch_id=$1`, [batchId]);
    await assert.rejects(coordinator.removeQuarantinedSource(request), /Exact archive fields required/);
    await target.query("UPDATE legacy_ai_private.import_archive SET source_record=source_record-'unexpected' WHERE batch_id=$1", [batchId]);
    await source.query("UPDATE legacy_challenge.ai_conversations SET prompt='changed after snapshot' WHERE id=501");
    await assert.rejects(coordinator.removeQuarantinedSource(request), { code: '55000' });
    assert.equal((await source.query('SELECT count(*)::integer AS n FROM legacy_challenge.ai_conversations WHERE id=501')).rows[0].n,1);
    await source.query('UPDATE legacy_challenge.ai_conversations SET prompt=$1 WHERE id=501',[record.prompt]);
    const failingTarget = { async connect() {
      const client = await target.connect();
      return { query(sql, values) {
        if (sql.startsWith('UPDATE legacy_ai_private.import_batches')) throw new Error('controlled acknowledgement failure');
        return client.query(sql, values);
      }, release(error) { client.release(error); } };
    } };
    await assert.rejects(createLegacyAiHistoryCutoverCoordinator({ ...options, targetPool: failingTarget }).removeQuarantinedSource(request), /controlled acknowledgement failure/);
    assert.equal((await source.query('SELECT count(*)::integer AS n FROM legacy_challenge.ai_conversations WHERE id=501')).rows[0].n,0);
    assert.equal((await target.query('SELECT state FROM legacy_ai_private.import_batches WHERE batch_id=$1',[batchId])).rows[0].state,'verified');
    assert.deepEqual((await target.query('SELECT source_record FROM legacy_ai_private.import_archive WHERE batch_id=$1',[batchId])).rows[0].source_record,record);
    assert.deepEqual(await coordinator.removeQuarantinedSource(request), { batchId, removedCount: 1, replayed: true, state: 'source_removed' });
    assert.equal((await coordinator.removeQuarantinedSource(request)).replayed,true);
    const timezoneSource = { async connect() {
      const client = await source.connect(); await client.query("SET TIME ZONE 'America/Los_Angeles'"); return client;
    } };
    assert.equal((await createLegacyAiHistoryCutoverCoordinator({ ...options, sourcePool: timezoneSource }).removeQuarantinedSource(request)).replayed,true);
    assert.equal((await source.query('SELECT count(*)::integer AS n FROM legacy_ai_source_cleanup.receipts WHERE batch_id=$1',[batchId])).rows[0].n,1);
    await source.query("INSERT INTO legacy_challenge.ai_conversations(id,prompt) VALUES(501,'new row must survive')");
    await assert.rejects(coordinator.removeQuarantinedSource(request), { code: '55000' });
    assert.equal((await source.query('SELECT prompt FROM legacy_challenge.ai_conversations WHERE id=501')).rows[0].prompt,'new row must survive');

    // Source commits, acknowledgement fails, then genuine canonical student
    // deletion removes the owner's archive before cutover recovery.
    const { createIdentityRepository } = require('../../server/database/postgres/identityRepository');
    const { createStudentDeletionRepository } = require('../../server/database/postgres/studentDeletionRepository');
    const { STUDENT_DELETION_STEPS } = require('../../server/services/studentDeletionComposition');
    const identities = createIdentityRepository(target);
    const makeUser = name => identities.createUser({ username: name, email: name + '@example.invalid',
      passwordHash: '$2b$12$000000000000000000000uG3W0Jp6IPhhD1TRqN8Yc2zJQG3vVnSA' });
    const admin = await makeUser('cutover-admin'), owner = await makeUser('cutover-deleted');
    await target.query("UPDATE identity.users SET role='admin',admin_level=2 WHERE id=$1", [admin.id]);
    const ownedRecord = { ...record, id: 502, platformOwnerId: owner.id };
    const ownedBatch = randomUUID(), requestId = randomUUID();
    const ownedDigest = digest([{ sourceRowId: 502, sourceDigest: digest(ownedRecord) }]);
    await source.query(`INSERT INTO legacy_challenge.ai_conversations(id,prompt,response,model_used,created_at,platform_owner_id)
      VALUES($1,$2,$3,$4,$5,$6)`, [502,ownedRecord.prompt,ownedRecord.response,ownedRecord.modelUsed,ownedRecord.createdAt,owner.id]);
    await target.query('SELECT * FROM legacy_ai_private.begin_history_import($1,$2,$3,$4)', [ownedBatch,boundSourceStoreIdentity,1,ownedDigest]);
    await target.query('SELECT * FROM legacy_ai_private.archive_history_import_row($1,$2,$3,$4,$5,$6)', [ownedBatch,502,ownedRecord,digest(ownedRecord),'owned',owner.id]);
    await target.query('SELECT * FROM legacy_ai_private.promote_owned_history_import_row($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',
      [ownedBatch,502,owner.id,requestId,'prompt_injection',ownedRecord.prompt,ownedRecord.response,ownedRecord.modelUsed,ownedRecord.createdAt,
        digest({ownerId:owner.id,requestId,sourceRoute:'prompt_injection',row:ownedRecord})]);
    await target.query('SELECT * FROM legacy_ai_private.verify_history_import_quarantine($1,$2,$3)', [ownedBatch,1,ownedDigest]);
    const ownedRequest = { batchId: ownedBatch, boundSourceStoreIdentity, aggregateDigest: ownedDigest };
    await assert.rejects(createLegacyAiHistoryCutoverCoordinator({ ...options, targetPool: failingTarget }).removeQuarantinedSource(ownedRequest), /controlled acknowledgement failure/);
    const runtimeUrl = new URL(targetUrl); runtimeUrl.username = 'dvaia_identity_runtime';
    const identityRuntime = new Pool({connectionString:runtimeUrl.href});
    try {
      const deletion = createStudentDeletionRepository(identityRuntime,{steps:STUDENT_DELETION_STEPS});
      const job = await deletion.admit({requesterId:admin.id,subjectId:owner.id});
      const lease = await deletion.claim(job.jobId,300000);
      for (const stepKey of STUDENT_DELETION_STEPS.slice(0,-1)) await deletion.acknowledge({jobId:job.jobId,leaseToken:lease.leaseToken,stepKey});
      await identityRuntime.query('SELECT identity.finalize_student_deletion($1,$2,$3)',[job.jobId,lease.leaseToken,owner.id]);
    } finally { await identityRuntime.end(); }
    assert.equal((await target.query('SELECT state FROM legacy_ai_private.import_batches WHERE batch_id=$1',[ownedBatch])).rows[0].state,'blocked');
    assert.deepEqual(await coordinator.removeQuarantinedSource(ownedRequest), {batchId:ownedBatch,removedCount:1,replayed:true,state:'source_removed_archive_invalidated'});
    assert.equal((await coordinator.removeQuarantinedSource(ownedRequest)).state,'source_removed_archive_invalidated');
    assert.equal((await target.query('SELECT count(*)::integer AS n FROM legacy_ai_private.import_archive WHERE batch_id=$1',[ownedBatch])).rows[0].n,0);
    assert.equal((await target.query("SELECT count(*)::integer AS n FROM legacy_ai_private.import_batch_events WHERE batch_id=$1 AND event_kind='source_cleanup_committed'",[ownedBatch])).rows[0].n,1);
    assert.equal((await target.query('SELECT count(*)::integer AS n FROM legacy_ai_private.history WHERE owner_id=$1',[owner.id])).rows[0].n,0);
    const missingReceiptBatch = randomUUID();
    await target.query(`INSERT INTO legacy_ai_private.import_batches
      (batch_id,source_store_identity,state,expected_count,copied_count,aggregate_digest)
      VALUES($1,$2,'blocked',1,1,$3)`, [missingReceiptBatch,boundSourceStoreIdentity,aggregateDigest]);
    await target.query(`INSERT INTO legacy_ai_private.import_batch_events(batch_id,event_kind,event_digest)
      VALUES($1,'invalidated_by_deletion',$2)`, [missingReceiptBatch,aggregateDigest]);
    await assert.rejects(coordinator.removeQuarantinedSource({ ...request,batchId:missingReceiptBatch }), /Durable source cleanup receipt required/);
    assert.equal((await target.query("SELECT count(*)::integer AS n FROM legacy_ai_private.import_batch_events WHERE batch_id=$1 AND event_kind='source_cleanup_committed'",[missingReceiptBatch])).rows[0].n,0);

  } finally { await Promise.all([source.end(),target.end()]); }
});

test('killed migration worker recovers from committed source journal without losing quarantine', {
  skip: !enabled || !process.env[prefix + 'TARGET_MIGRATION_URL'], timeout: 30000,
}, async () => {
  const { fork } = require('node:child_process');
  const { once } = require('node:events');
  const { digest } = require('../../server/database/postgres/legacyAiHistoryDraftImporter');
  const { createLegacyAiHistoryCutoverCoordinator } = require('../../server/database/postgres/legacyAiHistoryCutoverCoordinator');
  const sourceUrl = url('MIGRATION'), targetUrl = new URL(process.env[prefix + 'TARGET_MIGRATION_URL']);
  assert.equal(targetUrl.hostname, '127.0.0.1');
  assert.equal(targetUrl.username, 'dvaia_identity_migration');
  assert.match(targetUrl.pathname, /^\/owasp_ai_goat_test_history_cleanup_[a-f0-9]+$/);
  const source = new Pool({ connectionString: sourceUrl }), target = new Pool({ connectionString: targetUrl.href });
  let child, exited;
  try {
    const record = { id: 601, userId: null, prompt: 'crash-safe private row', response: null, modelUsed: null, createdAt: null, platformOwnerId: null };
    await source.query('INSERT INTO legacy_challenge.ai_conversations(id,prompt,response,model_used,created_at) VALUES($1,$2,NULL,NULL,NULL)', [record.id,record.prompt]);
    const batchId = randomUUID(), boundSourceStoreIdentity = 'owned-crash-fixture';
    const aggregateDigest = digest([{sourceRowId:record.id,sourceDigest:digest(record)}]);
    await target.query('SELECT * FROM legacy_ai_private.begin_history_import($1,$2,$3,$4)', [batchId,boundSourceStoreIdentity,1,aggregateDigest]);
    await target.query('SELECT * FROM legacy_ai_private.archive_history_import_row($1,$2,$3,$4,$5,$6)', [batchId,record.id,record,digest(record),'unknown',null]);
    await target.query('SELECT * FROM legacy_ai_private.verify_history_import_quarantine($1,$2,$3)', [batchId,1,aggregateDigest]);
    child = fork(path.join(__dirname,'helpers/legacyAiHistoryCutoverCrashWorker.js'), [], {
      env: { PATH: process.env.PATH }, stdio: ['ignore','ignore','ignore','ipc'],
    });
    exited = once(child,'exit');
    const message = once(child,'message', { signal: AbortSignal.timeout(10000) });
    child.send({sourceUrl,targetUrl:targetUrl.href,request:{batchId,boundSourceStoreIdentity,aggregateDigest}});
    const [status] = await message;
    assert.equal(status.phase,'source_committed');
    assert.equal(status.pid,child.pid);
    // Observe durable source commit from a separate connection before killing.
    assert.equal((await source.query('SELECT count(*)::integer AS n FROM legacy_ai_source_cleanup.receipts WHERE batch_id=$1',[batchId])).rows[0].n,1);
    assert.equal((await source.query('SELECT count(*)::integer AS n FROM legacy_challenge.ai_conversations WHERE id=601')).rows[0].n,0);
    assert.equal(child.kill('SIGKILL'),true);
    const [code,signal] = await exited;
    assert.equal(code,null); assert.equal(signal,'SIGKILL');
    child = null;
    assert.equal((await target.query('SELECT state FROM legacy_ai_private.import_batches WHERE batch_id=$1',[batchId])).rows[0].state,'verified');
    assert.deepEqual((await target.query('SELECT source_record FROM legacy_ai_private.import_archive WHERE batch_id=$1',[batchId])).rows[0].source_record,record);
    const coordinator = createLegacyAiHistoryCutoverCoordinator({sourcePool:source,targetPool:target,
      sourceDatabase:new URL(sourceUrl).pathname.slice(1),targetDatabase:targetUrl.pathname.slice(1)});
    assert.deepEqual(await coordinator.removeQuarantinedSource({batchId,boundSourceStoreIdentity,aggregateDigest}),
      {batchId,removedCount:1,replayed:true,state:'source_removed'});
  } finally {
    if (child && child.exitCode === null && child.signalCode === null) { child.kill('SIGKILL'); await exited; }
    await Promise.all([source.end(),target.end()]);
  }
});
