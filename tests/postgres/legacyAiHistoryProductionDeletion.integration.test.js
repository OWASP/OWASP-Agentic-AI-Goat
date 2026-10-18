'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fsp = require('node:fs/promises');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const { Pool } = require('pg');
const { migrate, readMigrations } = loadMigrationWithVirtualDirectories();
const { initializeIdentityRepository, createIdentityRepository } = require('../../server/database/postgres/identityRepository');
const { createStudentDeletionRepository } = require('../../server/database/postgres/studentDeletionRepository');
const { STUDENT_DELETION_STEPS } = require('../../server/services/studentDeletionComposition');
const { createLegacyAiHistoryRepository } = require('../../server/database/postgres/legacyAiHistoryRepository');
const { assertLegacyAiProtectedHistoryReadiness } = require('../../server/services/legacyAiProtectedHistoryComposition');
const PREFIX = 'PG_HISTORY_PRODUCTION_';
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' && process.env[PREFIX + 'MIGRATION_URL'] && process.env[PREFIX + 'RUNTIME_URL'];
const root = path.resolve(__dirname, '../..');
const identityMigrations = path.join(root, 'db/postgres/identity-migrations');
const virtualDirectories = new Map();
const virtualFs = {
  async readdir(directory, ...args) {
    const entries = virtualDirectories.get(directory);
    return entries ? [...entries.keys()] : fsp.readdir(directory, ...args);
  },
  async readFile(file, encoding) {
    const entries = virtualDirectories.get(path.dirname(file));
    if (!entries) return fsp.readFile(file, encoding);
    assert.equal(encoding, 'utf8');
    if (!entries.has(path.basename(file))) {
      throw Object.assign(Error('Missing virtual migration'), { code: 'ENOENT' });
    }
    return entries.get(path.basename(file));
  },
};
function loadMigrationWithVirtualDirectories() {
  const { Module, createRequire } = require('node:module');
  const filename = require.resolve('../../db/postgres/migrate');
  const localRequire = createRequire(filename);
  const loaded = new Module(filename, module);
  loaded.filename = filename;
  loaded.require = name => name === 'node:fs/promises' ? {
    readdir: (...args) => virtualFs.readdir(...args),
    readFile: (...args) => virtualFs.readFile(...args),
  } : localRequire(name);
  loaded._compile(require('node:fs').readFileSync(filename, 'utf8'), filename);
  return loaded.exports;
}
async function stageIdentityMigrationsBefore(lastExclusive) {
  const handle = path.join('/virtual-history-identity', randomUUID());
  const entries = new Map();
  for (const name of (await fsp.readdir(identityMigrations)).filter(name =>
    /^\d{4}_[a-z0-9_]+\.sql$/.test(name) && name < lastExclusive).sort()) {
    entries.set(name, await fsp.readFile(path.join(identityMigrations, name), 'utf8'));
  }
  virtualDirectories.set(handle, entries);
  return handle;
}
function disposeVirtualDirectory(directory) {
  assert.equal(virtualDirectories.delete(directory), true);
}
async function ledger(pool) {
  return (await pool.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
}
function url(kind, cohort = '') {
  const value = new URL(process.env[PREFIX + cohort + kind + '_URL']);
  assert.equal(value.hostname, '127.0.0.1');
  assert.match(value.pathname, /^\/dvaia_test_history_production_[a-f0-9]+$/);
  assert.equal(value.username, `dvaia_identity_${kind.toLowerCase()}`);
  assert.equal(value.search, ''); assert.equal(value.hash, '');
  return value.href;
}
test('history migration prefix is an exact in-memory canonical view', async () => {
  const originalReaddir = fsp.readdir;
  const originalReadFile = fsp.readFile;
  const full = await readMigrations(identityMigrations);
  const prefix = await stageIdentityMigrationsBefore('0080_legacy_ai_private_history.sql');
  try {
    const staged = await readMigrations(prefix);
    assert.deepEqual(staged.map(({ name }) => name),
      full.filter(({ name }) => name < '0080_legacy_ai_private_history.sql').map(({ name }) => name));
    assert.deepEqual(staged.map(({ name, checksum }) => ({ name, checksum })),
      full.filter(({ name }) => name < '0080_legacy_ai_private_history.sql')
        .map(({ name, checksum }) => ({ name, checksum })));
    assert.equal(staged.some(({ name }) => name >= '0080_legacy_ai_private_history.sql'), false);
  } finally {
    disposeVirtualDirectory(prefix);
  }
  assert.strictEqual(fsp.readdir, originalReaddir);
  assert.strictEqual(fsp.readFile, originalReadFile);
  assert.deepEqual(await readMigrations(identityMigrations), full);
});
test('private history successor installs with the entire fresh identity chain and replays without changes', {
  skip: !enabled || !process.env[PREFIX + 'FRESH_MIGRATION_URL'] || !process.env[PREFIX + 'FRESH_RUNTIME_URL'],
  timeout: 60000,
}, async () => {
  const migration = new Pool({ connectionString: url('MIGRATION', 'FRESH_') });
  const runtime = new Pool({ connectionString: url('RUNTIME', 'FRESH_') });
  try {
    assert.equal((await migration.query("SELECT to_regnamespace('identity') IS NULL AS empty")).rows[0].empty, true);
    const expected = (await fsp.readdir(identityMigrations)).filter(name => name.endsWith('.sql')).sort();
    assert.deepEqual(await migrate(migration, identityMigrations), expected);
    assert.deepEqual(await migrate(migration, identityMigrations), []);
    await assertLegacyAiProtectedHistoryReadiness({ identityPool: runtime,
      expectedDatabase: new URL(url('RUNTIME', 'FRESH_')).pathname.slice(1) });
    await qualifyProductionMount(runtime, url('RUNTIME', 'FRESH_'));
  } finally {
    await Promise.all([runtime.end(), migration.end()]);
  }
});
test('current-manifest private history deletion is atomic, replayable and covers previously advanced jobs', { skip: !enabled, timeout: 60000 }, async () => {
  const migration = new Pool({ connectionString: url('MIGRATION') });
  const runtime = new Pool({ connectionString: url('RUNTIME') });
  let held, prefixLedger;
  try {
    // Admit representative jobs at the actual pre-upgrade schema head.
    const candidateName = '0080_legacy_ai_private_history.sql';
    const prefix = await stageIdentityMigrationsBefore(candidateName);
    try {
      const prefixRows = await readMigrations(prefix);
      prefixLedger = prefixRows.map(({ name, checksum }) => ({ name, checksum }));
      assert.deepEqual(await migrate(migration, prefix), prefixRows.map(({ name }) => name));
      assert.deepEqual(await ledger(migration), prefixLedger);
    } finally {
      disposeVirtualDirectory(prefix);
    }
    const identities = createIdentityRepository(runtime);
    const passwordHash = '$2b$12$000000000000000000000uG3W0Jp6IPhhD1TRqN8Yc2zJQG3vVnSA';
    const user = suffix => identities.createUser({ username: `history-${suffix}`, email: `history-${suffix}@example.invalid`, passwordHash });
    const admin = await user('admin'), oldOwner = await user('old'), owner = await user('new'), sibling = await user('sibling');
    await migration.query("UPDATE identity.users SET role='admin',admin_level=2 WHERE id=$1", [admin.id]);
    const deletion = createStudentDeletionRepository(runtime, { steps: STUDENT_DELETION_STEPS });
    const admitted = await deletion.admit({ requesterId: admin.id, subjectId: oldOwner.id });
    const lease = await deletion.claim(admitted.jobId, 300000);
    for (const stepKey of STUDENT_DELETION_STEPS.slice(0, -1)) {
      await deletion.acknowledge({ jobId: admitted.jobId, leaseToken: lease.leaseToken, stepKey });
    }
    // A real current-manifest job is already beyond legacy_challenge before upgrade.
    const expectedUpgrade = (await fsp.readdir(identityMigrations)).filter(name =>
      name.endsWith('.sql') && name >= candidateName).sort();
    assert.deepEqual(await migrate(migration, identityMigrations), expectedUpgrade);
    assert.deepEqual(await migrate(migration, identityMigrations), []);
    assert.deepEqual((await ledger(migration)).slice(0, prefixLedger.length), prefixLedger);
    await assertLegacyAiProtectedHistoryReadiness({ identityPool: runtime,
      expectedDatabase: new URL(url('RUNTIME')).pathname.slice(1) });
    assert.deepEqual(await deletion.nextStep({ jobId: admitted.jobId, leaseToken: lease.leaseToken }), { subjectId: oldOwner.id, stepKey: 'identity' });
    const history = createLegacyAiHistoryRepository(runtime);
    const sessions = new Map();
    for (const subject of [owner, sibling]) {
      const session = await identities.createSession({ userId: subject.id, token: randomUUID(), expiresAt: new Date(Date.now() + 3600000), expectedPasswordHash: passwordHash });
      sessions.set(subject.id, session);
      const admission = await history.admit({ ownerId: subject.id, sessionId: session.id });
      await history.append({ ...admission, requestId: randomUUID(), sourceRoute: 'prompt_injection', prompt: `prompt-${subject.id}`, response: 'preserve exact response', modelUsed: 'controlled-storage-test' });
    }
    await assert.rejects(runtime.query('SELECT * FROM legacy_ai_private.history'), { code: '42501' });
    const batchId = randomUUID();
    await migration.query(`INSERT INTO legacy_ai_private.import_batches
      (batch_id,source_store_identity,state,expected_count,copied_count,aggregate_digest)
      VALUES($1,'disposable-production-deletion','copying',3,3,$2)`, [batchId, 'a'.repeat(64)]);
    for (const [index, classifiedOwner] of [owner.id, sibling.id, null].entries()) {
      await migration.query(`INSERT INTO legacy_ai_private.import_archive
        (batch_id,source_row_id,source_record,source_digest,classification,classified_owner_id)
        VALUES($1,$2,$3,$4,$5,$6)`, [batchId, index + 1,
        JSON.stringify({ original: `archive-${index}` }), String(index + 1).repeat(64),
        classifiedOwner === null ? 'unknown' : 'owned', classifiedOwner]);
    }
    const call = (pool, job, token, id) => pool.query('SELECT identity.finalize_student_deletion($1,$2,$3) AS finalized', [job, token, id]);
    await call(runtime, admitted.jobId, lease.leaseToken, oldOwner.id);
    assert.equal((await migration.query('SELECT history_removed FROM legacy_ai_private.deletion_receipts WHERE job_id=$1', [admitted.jobId])).rows[0].history_removed, 0);
    const current = await deletion.admit({ requesterId: admin.id, subjectId: owner.id });
    let currentLease = await deletion.claim(current.jobId, 300000);
    await assert.rejects(call(runtime, current.jobId, currentLease.leaseToken, owner.id), { code: '55000' });
    for (const stepKey of STUDENT_DELETION_STEPS.slice(0, -1)) await deletion.acknowledge({ jobId: current.jobId, leaseToken: currentLease.leaseToken, stepKey });
    const stale = currentLease.leaseToken;
    await deletion.fail({ jobId: current.jobId, leaseToken: stale, stepKey: 'identity' });
    currentLease = await deletion.claim(current.jobId, 300000);
    await assert.rejects(call(runtime, current.jobId, stale, owner.id), { code: '55000' });
    // Rollback after the DB finalizer must restore BOTH history and account state.
    held = await runtime.connect(); await held.query('BEGIN');
    await call(held, current.jobId, currentLease.leaseToken, owner.id);
    await held.query('ROLLBACK'); held.release(); held = null;
    assert.equal((await migration.query('SELECT count(*)::integer AS n FROM legacy_ai_private.history WHERE owner_id=$1', [owner.id])).rows[0].n, 1);
    assert.equal((await migration.query('SELECT count(*)::integer AS n FROM legacy_ai_private.deletion_receipts WHERE job_id=$1', [current.jobId])).rows[0].n, 0);
    await call(runtime, current.jobId, currentLease.leaseToken, owner.id);
    const receipt = (await migration.query('SELECT * FROM legacy_ai_private.deletion_receipts WHERE job_id=$1', [current.jobId])).rows[0];
    assert.equal(receipt.history_removed, 1);
    assert.equal(receipt.archive_removed, 1);
    assert.deepEqual((await migration.query(`SELECT source_record FROM legacy_ai_private.import_archive
      WHERE batch_id=$1 ORDER BY source_row_id`, [batchId])).rows.map(row => row.source_record),
    [{ original: 'archive-1' }, { original: 'archive-2' }]);
    assert.equal((await migration.query('SELECT state FROM legacy_ai_private.import_batches WHERE batch_id=$1', [batchId])).rows[0].state, 'blocked');
    await call(runtime, current.jobId, currentLease.leaseToken, owner.id);
    assert.deepEqual((await migration.query('SELECT * FROM legacy_ai_private.deletion_receipts WHERE job_id=$1', [current.jobId])).rows[0], receipt);
    assert.equal((await history.listOwn({ ownerId: sibling.id, sessionId: sessions.get(sibling.id).id })).length, 1);
    await assert.rejects(history.admit({ ownerId: owner.id, sessionId: sessions.get(owner.id).id }), { code: '55000' });
    await deletion.acknowledge({ jobId: current.jobId, leaseToken: currentLease.leaseToken, stepKey: 'identity' });
    await assert.rejects(call(runtime, current.jobId, currentLease.leaseToken, owner.id), { code: '55000' });
    await require('./helpers/legacyAiHistoryHttpQualification').qualifyLegacyAiHistoryHttp({ identities, history, migration });
  } finally {
    if (held) { await held.query('ROLLBACK').catch(() => {}); held.release(); }
    await Promise.all([runtime.end(), migration.end()]);
  }
});

test('owned import and deletion admission serialize; deleting identities cannot regain archived history', {
  skip: !enabled || !process.env[PREFIX + 'FRESH_MIGRATION_URL'] || !process.env[PREFIX + 'FRESH_RUNTIME_URL'],
  timeout: 15000,
}, async () => {
  const migration = new Pool({ connectionString: url('MIGRATION', 'FRESH_') });
  const runtime = new Pool({ connectionString: url('RUNTIME', 'FRESH_') });
  let held, pending;
  try {
    const identities = createIdentityRepository(runtime);
    const create = name => identities.createUser({ username: name, email: name + '@example.invalid',
      passwordHash: '$2b$12$000000000000000000000uG3W0Jp6IPhhD1TRqN8Yc2zJQG3vVnSA' });
    const admin = await create('history-race-admin'), owner = await create('history-race-owner');
    await migration.query("UPDATE identity.users SET role='admin',admin_level=2 WHERE id=$1", [admin.id]);
    const batch = randomUUID();
    await migration.query('SELECT * FROM legacy_ai_private.begin_history_import($1,$2,$3,$4)',
      [batch, 'owned-race-fixture', 1, 'a'.repeat(64)]);
    held = await migration.connect(); await held.query('BEGIN');
    const heldPid = (await held.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
    const archiveSql = 'SELECT * FROM legacy_ai_private.archive_history_import_row($1,$2,$3,$4,$5,$6)';
    const archiveArgs = [batch, 1, { original: 'private race row' }, 'b'.repeat(64), 'owned', owner.id];
    await held.query(archiveSql, archiveArgs);
    let admissionPid, settled = false;
    const admissionPool = { query: runtime.query.bind(runtime), async connect() {
      const client = await runtime.connect();
      admissionPid = (await client.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
      return client;
    } };
    const deletion = createStudentDeletionRepository(admissionPool, { steps: STUDENT_DELETION_STEPS });
    pending = deletion.admit({ requesterId: admin.id, subjectId: owner.id }).finally(() => { settled = true; });
    pending.catch(() => {});
    const deadline = Date.now() + 5000;
    let blocked = false;
    while (Date.now() < deadline) {
      if (admissionPid) blocked = (await runtime.query('SELECT $1::integer=ANY(pg_blocking_pids($2::integer)) AS blocked', [heldPid, admissionPid])).rows[0].blocked;
      if (blocked || settled) break;
      await new Promise(resolve => setTimeout(resolve, 10));
    }
    assert.equal(blocked, true, 'observe actual database wait behind the owned import');
    assert.equal(settled, false);
    await held.query('COMMIT'); held.release(); held = null;
    const job = await pending; pending = null;
    await assert.rejects(migration.query(archiveSql, archiveArgs), { code: '55000' });
    await assert.rejects(migration.query(`SELECT * FROM legacy_ai_private.promote_owned_history_import_row(
      $1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, [batch, 1, owner.id, randomUUID(),
      'prompt_injection', 'private race prompt', 'private race response', 'controlled',
      '2026-01-01T00:00:00.123456Z', 'c'.repeat(64)]), { code: '55000' });
    const lease = await deletion.claim(job.jobId, 300000);
    for (const stepKey of STUDENT_DELETION_STEPS.slice(0, -1)) await deletion.acknowledge({ jobId: job.jobId, leaseToken: lease.leaseToken, stepKey });
    await runtime.query('SELECT identity.finalize_student_deletion($1,$2,$3)', [job.jobId, lease.leaseToken, owner.id]);
    assert.equal((await migration.query('SELECT archive_removed FROM legacy_ai_private.deletion_receipts WHERE job_id=$1', [job.jobId])).rows[0].archive_removed, 1);
    assert.equal((await migration.query('SELECT count(*)::integer AS n FROM legacy_ai_private.import_archive WHERE batch_id=$1', [batch])).rows[0].n, 0);
  } finally {
    if (held) { await held.query('ROLLBACK').catch(() => {}); held.release(); }
    if (pending) await pending.catch(() => {});
    await Promise.all([runtime.end(), migration.end()]);
  }
});


async function qualifyProductionMount(runtime, connectionString) {
  const express = require('express');
  const { createPostgresIdentityAdapter } = require('../../server/services/postgresIdentityAdapter');
  const { createLegacyAiProtectedHistoryProduction } = require('../../server/services/legacyAiProtectedHistoryProduction');
  const identities = createIdentityRepository(runtime);
  const passwordHash = '$2b$12$000000000000000000000uG3W0Jp6IPhhD1TRqN8Yc2zJQG3vVnSA';
  const owner = await identities.createUser({username:'production-history-owner',
    email:'production-history-owner@example.invalid',passwordHash});
  const adapter = createPostgresIdentityAdapter({repository:identities,progress:null,
    jwtSecret:'disposable-production-history-signing-secret-2026'});
  adapter.pool = runtime;
  const session = await adapter.createSession(await identities.findCredentialById(owner.id),
    {get:()=>null,ip:'127.0.0.1'});
  let calls = 0, fallthrough = 0;
  const production = createLegacyAiProtectedHistoryProduction({
    env:{PLATFORM_DATABASE_ENGINE:'postgres',IDENTITY_DATABASE_URL:connectionString},
    getIdentityAdapter:()=>adapter,
    createInference:()=>async (input, execution)=>{
      await execution.check();
      assert.equal(execution.ownerId,owner.id);
      calls++;
      return {response:'Controlled production mount response',modelUsed:'controlled-mount-provider'};
    },
    createExperimentAccess:()=>((req,res,next)=>next()),
  });
  const app=express();app.use(express.json());app.use('/api/ai',production.middleware);
  app.use((req,res)=>{fallthrough++;res.status(599).end();});
  const server=await new Promise(resolve=>{const listener=app.listen(0,'127.0.0.1',()=>resolve(listener));});
  const base=`http://127.0.0.1:${server.address().port}/api/ai`;
  try {
    const post=()=>fetch(base+'/prompt-injection',{method:'POST',
      headers:{'Content-Type':'application/json',Authorization:`Bearer ${session.token}`},
      body:JSON.stringify({prompt:'Native production composition qualification'})});
    assert.equal((await post()).status,503);
    assert.equal(calls,0);assert.equal(fallthrough,0);
    const readiness=await production.initialize();assert.equal(readiness.ready,true);
    const response=await post();assert.equal(response.status,200);
    assert.equal((await response.json()).response,'Controlled production mount response');
    const page=await fetch(base+'/history',{headers:{Authorization:`Bearer ${session.token}`}});
    assert.equal(page.status,200);
    assert.match(JSON.stringify(await page.json()),/Native production composition qualification/);
    await identities.revokeSession(session.token,owner.id);
    assert.equal((await post()).status,401);
    assert.equal(calls,1);assert.equal(fallthrough,0);
  } finally {
    await new Promise(resolve=>{server.close(resolve);server.closeAllConnections();});
  }
}
