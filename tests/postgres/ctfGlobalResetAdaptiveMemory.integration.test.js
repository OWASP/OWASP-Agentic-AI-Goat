'use strict';
// Disposable SQL foundation only: no browser, provider, projection worker or credit.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { randomUUID, createHash } = require('node:crypto');
const { createPool, withTransaction, verifyServer } = require('../../server/database/postgres');
const { migrate, readMigrations, executionSql } = require('../../db/postgres/migrate');

const ROOT = path.resolve(__dirname, '../..');
const DIR = path.join(ROOT, 'db/postgres/identity-migrations');
const ENABLED = process.env.CTF_GLOBAL_RESET_MEMORY_NATIVE === '1';
const hash = value => createHash('sha256').update(value).digest('hex');
const one = async (pool, query, args = []) => (await pool.query(query, args)).rows[0];

function admittedUrls(state) {
  const names = ['RUNTIME', 'MIGRATION'].map(role => `PG_CTF_RESET_MEMORY_${state}_${role}_URL`);
  assert(names.every(name => typeof process.env[name] === 'string' && process.env[name].length));
  const urls = names.map(name => new URL(process.env[name]));
  for (const url of urls) {
    assert.equal(url.hostname, '127.0.0.1');
    assert.match(url.pathname, /^\/dvaia_test_ctf_reset_memory_[a-f0-9]{12}_(fresh|populated)$/);
    assert.equal(url.search, ''); assert.equal(url.hash, '');
  }
  assert.equal(urls[0].pathname, urls[1].pathname);
  assert.equal(urls[0].port, urls[1].port);
  assert.equal(decodeURIComponent(urls[0].username), 'dvaia_identity_runtime');
  assert.equal(decodeURIComponent(urls[1].username), 'dvaia_identity_migration');
  assert.equal(urls[0].pathname.endsWith(`_${state.toLowerCase()}`), true);
  return names;
}

async function migrateThrough0153(pool) {
  const migrations = (await readMigrations(DIR)).filter(item => item.name <= '0153_secureshop_external_test_mail.sql');
  assert.equal(migrations.at(-1)?.name, '0153_secureshop_external_test_mail.sql');
  await withTransaction(pool, async client => {
    await verifyServer(client);
    await client.query('SELECT pg_advisory_xact_lock(1886610804, 1)');
    await client.query('CREATE SCHEMA IF NOT EXISTS dvaia_migrations');
    await client.query(`CREATE TABLE IF NOT EXISTS dvaia_migrations.ledger (
      name text PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())`);
    assert.equal((await client.query('SELECT count(*)::integer AS n FROM dvaia_migrations.ledger')).rows[0].n, 0);
    for (const item of migrations) {
      await client.query(executionSql(item));
      await client.query('INSERT INTO dvaia_migrations.ledger(name,checksum) VALUES($1,$2)',
        [item.name, item.checksum]);
    }
  });
}

async function memoryRows(pool) {
  return (await pool.query('SELECT * FROM identity.ctf_adaptive_memory ORDER BY memory_id')).rows;
}

async function seedMemory(pool, label) {
  const normalized = `reset payload ${label.replace(/-/g, '_')}`;
  assert.match(normalized, /^[a-z0-9_ ]*$/, 'predefense requires canonical normalized payload bytes');
  await pool.query(`INSERT INTO identity.ctf_adaptive_memory
    (memory_id,kind,stage_id,stage_revision,clear_revision,owner_id,owner_generation,technique_tag,legacy_source)
    VALUES($1,'technique',9,0,0,701,0,'role_play',$2)`, [randomUUID(), label]);
  await pool.query(`INSERT INTO identity.ctf_adaptive_memory
    (memory_id,kind,stage_id,stage_revision,clear_revision,payload_hash,normalized_payload,legacy_source)
    VALUES($1,'payload',9,0,0,$2,$3,$4)`, [randomUUID(), hash(normalized), normalized, label]);
  return { normalized, payloadHash: hash(normalized) };
}

async function adaptive(pool, actor, payload) {
  const input = { binding: { stageId: '9', ownerId: String(actor), ownerGeneration: '0' },
    techniqueTag: 'role_play', normalizedPayload: payload.normalized, payloadHash: payload.payloadHash };
  return (await one(pool, 'SELECT identity.ctf_predefense_adaptive($1::jsonb) AS result',
    [JSON.stringify(input)])).result;
}

async function prepareAck(pool, sequence) {
  const operationId = randomUUID(), commandHash = 'a'.repeat(64);
  await pool.query(`INSERT INTO identity.ctf_outbox(sequence,operation_id,kind,command,command_hash)
    VALUES($1,$2,'global_reset',$3,$4)`, [sequence, operationId,
    JSON.stringify({ scope: { ownerId: null, stageId: null }, body: {} }), commandHash]);
  await pool.query(`UPDATE identity.ctf_authority SET lifecycle_state='pending',pending_operation_id=$1,
    next_sequence=$2 WHERE scope_key='global'`, [operationId, sequence]);
  const result = { version: 1, kind: 'global_reset', operationId, sequence: String(sequence),
    commandHash, outcome: 'applied', data: { removedParticipants: 1 } };
  return { operationId, result, raw: JSON.stringify(result) };
}

async function acknowledge(pool, prepared) {
  const { operationId, result, raw } = prepared;
  return one(pool, 'SELECT * FROM identity.ack_ctf_projection($1,$2,$3,$4,$5)',
    [operationId, result.sequence, result.commandHash, raw, hash(raw)]);
}

test('identity 0154 Full Reset ACK clears adaptive memory only on ordered first application',
  { skip: !ENABLED, timeout: 180000 }, async t => {
    assert.equal(process.env.PG_TEST_DISPOSABLE, 'yes');
    assert.equal(process.env.DVAIA_CURRENT_MAIN_WORKSPACE, ROOT);
    const pools = [], paths = new Set();
    t.after(async () => {
      const results = await Promise.allSettled(pools.map(pool => pool.end()));
      const failures = results.filter(result => result.status === 'rejected').map(result => result.reason);
      if (failures.length) throw new AggregateError(failures, 'Owned identity pool cleanup failed');
    });
    for (const state of ['FRESH', 'POPULATED']) {
      const [runtimeName, migrationName] = admittedUrls(state);
      const pathname = new URL(process.env[runtimeName]).pathname;
      assert(!paths.has(pathname)); paths.add(pathname);
      const runtime = createPool({ ...process.env, PG_POOL_MAX_WORKSHOP: '2' }, runtimeName);
      const migration = createPool({ ...process.env, PG_POOL_MAX_WORKSHOP: '2' }, migrationName);
      pools.push(runtime, migration);
      assert.equal((await one(runtime, 'SELECT current_user AS role')).role, 'dvaia_identity_runtime');
      assert.equal((await one(migration, "SELECT to_regclass('dvaia_migrations.ledger') AS value")).value, null);
      if (state === 'POPULATED') await migrateThrough0153(migration);
      const oldFunction = state === 'POPULATED' ? await one(migration,
        "SELECT p.prosrc FROM pg_proc p WHERE p.oid='identity.ack_ctf_projection(uuid,bigint,text,text,text)'::regprocedure") : null;
      if (oldFunction) {
        assert.equal(hash(oldFunction.prosrc), 'ed13ddf23f9fe18fe7932295d97eb5f093bb485ac3cf7eeaa87d2d0662d54e1e');
        const retained = await seedMemory(migration, 'predecessor');
        assert.deepEqual((await memoryRows(migration)).map(row => row.kind).sort(), ['payload', 'technique']);
        assert.equal(retained.normalized, 'reset payload predecessor');
      }
      const applied = await migrate(migration, DIR);
      assert.equal(applied.includes('0154_ctf_global_reset_adaptive_memory.sql'), true);
      assert.equal(state === 'POPULATED' ? applied.length : applied.length > 1, state === 'POPULATED' ? 1 : true);
      const ledger = (await migration.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
      assert.deepEqual(await migrate(migration, DIR), []);
      assert.deepEqual((await migration.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows, ledger);
      const functionState = await one(migration, `SELECT p.prosrc,p.prosecdef,p.proconfig,
        has_function_privilege('dvaia_identity_runtime',p.oid,'EXECUTE') AS runtime_execute,
        EXISTS(SELECT 1 FROM aclexplode(p.proacl) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE') AS public_execute
        FROM pg_proc p WHERE p.oid='identity.ack_ctf_projection(uuid,bigint,text,text,text)'::regprocedure`);
      assert(functionState.prosecdef);
      assert.deepEqual(functionState.proconfig, ['search_path=pg_catalog']);
      assert.equal(functionState.runtime_execute, true); assert.equal(functionState.public_execute, false);
      assert.equal(functionState.prosrc.includes('DELETE FROM identity.ctf_adaptive_memory;'), true);
      for (const action of ['INSERT', 'UPDATE', 'DELETE', 'TRUNCATE'])
        assert.equal((await one(runtime, "SELECT has_table_privilege(current_user,'identity.ctf_adaptive_memory',$1) AS allowed", [action])).allowed, false);
      await migration.query("UPDATE identity.ctf_authority SET lifecycle_state='ready' WHERE scope_key='global'");
      await migration.query("INSERT INTO identity.ctf_authority(scope_key,lifecycle_state,owner_generation) VALUES('owner:701','ready',0)");
      await migration.query("INSERT INTO identity.ctf_stage_bindings(stage_id,stage_number,stage_revision,global_revision,stage_digest,stage_order,active,adaptive_mode,feedback_mode,hint_count,level_score,max_attempts,applied_sequence,applied_operation_id) VALUES(9,9,0,0,$1,9,true,'hybrid','full',0,100,-1,0,$2)", ['b'.repeat(64),randomUUID()]);
      await migration.query("INSERT INTO identity.ctf_participant_bindings(owner_id,owner_generation,participant_id,owner_revision,global_revision,active,banned,registered_at,applied_sequence,applied_operation_id) VALUES(701,0,801,0,0,true,false,now(),0,$1)", [randomUUID()]);
      const payload = oldFunction ? { normalized: 'reset payload predecessor', payloadHash: hash('reset payload predecessor') } : await seedMemory(migration, 'fresh');
      assert.equal((await adaptive(migration, 701, payload)).disposition, 'category');
      assert.equal((await adaptive(migration, 703, payload)).disposition, 'payload');
      const historicalDecision = randomUUID();
      await migration.query(`INSERT INTO identity.ctf_decisions(decision_id,run_id,owner_id,session_id,owner_key,
        owner_generation,global_revision,stage_revision,participant_id,progress_id,stage_id,stage_digest,
        evidence_hash,evidence,verdict,accepted,sequence)
        VALUES($1,$2,701,1,'["CTF","701"]',0,0,0,801,901,9,$3,$4,'{}','fail',false,1000)`,
      [historicalDecision, randomUUID(), 'b'.repeat(64), 'c'.repeat(64)]);
      const historicalClaim = randomUUID(), snapshot = '[]';
      const claimInput = { version: 1, binding: { ownerId: '701', sessionId: '1', runId: historicalClaim,
        ownerGeneration: '0', globalRevision: '0', stageRevision: '0', ownerRevision: '0',
        participantId: '801', progressId: '901', stageId: '9', stageDigest: hash(snapshot) },
      payload: payload.normalized, normalizedPayload: payload.normalized, payloadHash: payload.payloadHash,
      techniqueTag: 'role_play', techniqueConfidence: 0.5 };
      const claimRaw = JSON.stringify(claimInput);
      await migration.query(`INSERT INTO identity.ctf_predefense_claims
        (run_id,owner_id,session_id,canonical_input,input_hash,input,stage_snapshot,initial_adaptive)
        VALUES($1,701,1,$2,$3,$4,$5,$6)`, [historicalClaim, claimRaw, hash(claimRaw),
        claimInput, snapshot, { disposition: 'category', matchedPayloadHash: null }]);
      const immutableBefore = Object.fromEntries(await Promise.all(['ctf_decisions', 'ctf_predefense_claims']
        .map(async table => [table, (await migration.query(`SELECT * FROM identity.${table} ORDER BY 1`)).rows])));
      assert.equal(immutableBefore.ctf_decisions.length, 1);
      assert.equal(immutableBefore.ctf_predefense_claims.length, 1);
      const staged = await migration.connect();
      try {
        await staged.query('BEGIN');
        const outOfOrder = await prepareAck(staged, 2);
        await assert.rejects(acknowledge(staged, outOfOrder), /out of order/);
        await staged.query('ROLLBACK');
      } finally { staged.release(); }
      assert.equal((await memoryRows(runtime)).length, 2);
      assert.equal((await one(runtime, 'SELECT count(*)::integer AS n FROM identity.ctf_outbox')).n, 0);
      const mutableSnapshot = async () => ({
        memory: await memoryRows(migration),
        binding: (await migration.query('SELECT * FROM identity.ctf_participant_bindings ORDER BY owner_id')).rows,
        outbox: (await migration.query('SELECT * FROM identity.ctf_outbox ORDER BY sequence')).rows,
        authority: (await migration.query('SELECT * FROM identity.ctf_authority ORDER BY scope_key')).rows });
      const beforeRollback = await mutableSnapshot();
      const rollback = await migration.connect();
      try {
        await rollback.query('BEGIN');
        const provisional = await prepareAck(rollback, 1);
        assert.equal((await acknowledge(rollback, provisional)).state, 'applied');
        assert.equal((await memoryRows(rollback)).length, 0, 'deletion occurs inside ordered ACK');
        await rollback.query('ROLLBACK');
      } finally { rollback.release(); }
      assert.deepEqual(await mutableSnapshot(), beforeRollback,
        'transaction rollback must restore memory, bindings, outbox and authority exactly');
      const valid = await prepareAck(migration, 1);
      assert.equal((await acknowledge(runtime, valid)).state, 'applied');
      assert.equal((await memoryRows(runtime)).length, 0);
      assert.equal((await one(runtime, 'SELECT active FROM identity.ctf_participant_bindings WHERE owner_id=701')).active, false);
      assert.equal((await adaptive(migration, 703, payload)).disposition, 'continue', 'new registrant must not meet old shared payload');
      assert.equal((await adaptive(migration, 701, payload)).disposition, 'continue');
      const postReset = await seedMemory(migration, 'post-reset');
      const savedMemory = await memoryRows(runtime);
      assert.equal((await acknowledge(runtime, valid)).state, 'applied');
      assert.deepEqual(await memoryRows(runtime), savedMemory, 'replayed old reset must not erase later memory');
      assert.equal((await adaptive(migration, 703, postReset)).disposition, 'payload');
      const outbox = await one(runtime, 'SELECT state,canonical_result,result_hash FROM identity.ctf_outbox WHERE operation_id=$1', [valid.operationId]);
      assert.equal(outbox.state, 'applied'); assert.equal(hash(outbox.canonical_result), outbox.result_hash);
      await assert.rejects(acknowledge(runtime, { ...valid, raw: JSON.stringify({ ...valid.result, data: { removedParticipants: 0 } }) }), /digest invalid|replay mismatch/);
      assert.deepEqual(await memoryRows(runtime), savedMemory);
      for (const table of ['ctf_decisions', 'ctf_predefense_claims'])
        assert.deepEqual((await migration.query(`SELECT * FROM identity.${table} ORDER BY 1`)).rows, immutableBefore[table]);
      assert.deepEqual(await migrate(migration, DIR), []);
      assert.deepEqual(await memoryRows(runtime), savedMemory);
      assert.equal((await one(runtime, 'SELECT count(*)::integer AS n FROM identity.ctf_outbox')).n, 1);
    }
  });
