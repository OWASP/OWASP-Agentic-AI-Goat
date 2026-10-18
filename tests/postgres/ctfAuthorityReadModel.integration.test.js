'use strict';
// Four empty disposable stores; synthetic persistence only, never model proof.
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), os = require('node:os');
const { randomUUID } = require('node:crypto');
const { createPool } = require('../../server/database/postgres');
const { migrate } = require('../../db/postgres/migrate');
const { createCtfAuthorityRepository } = require('../../server/database/postgres/ctfAuthorityRepository');
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' && process.env.CTF_AUTHORITY_SCHEMA_ISOLATED === '1';
const targets = { IDENTITY: '0104_ctf_authority_read_model.sql', CTF: '0006_authority_projection_read_model.sql' };
const dirs = { IDENTITY: path.resolve(__dirname, '../../db/postgres/identity-migrations'), CTF: path.resolve(__dirname, '../../db/postgres/workshop-migrations/ctf') };
test('inert CTF authority schema fresh/populated/no-op, grants and immutable history', { skip: !enabled, timeout: 180000 }, async t => {
  const pools = [], databases = new Set();
  t.after(async () => Promise.allSettled(pools.map(p => p.end())));
  for (const state of ['FRESH', 'POPULATED']) {
    const stores = {};
    for (const kind of ['IDENTITY', 'CTF']) {
      const keys = ['RUNTIME', 'MIGRATION'].map(role => `PG_CTF_AUTHORITY_${state}_${kind}_${role}_URL`);
      const urls = keys.map(key => new URL(process.env[key]));
      for (const url of urls) { assert.equal(url.hostname, '127.0.0.1'); assert.match(url.pathname, /^\/dvaia_test_[a-z0-9_]+$/); }
      assert.equal(urls[0].pathname, urls[1].pathname); assert.equal(urls[0].port, urls[1].port); assert.notEqual(urls[0].username, urls[1].username);
      assert.ok(!databases.has(urls[0].pathname)); databases.add(urls[0].pathname);
      const [runtime, migration] = keys.map(key => createPool(process.env, key)); pools.push(runtime, migration);
      const role = (await runtime.query('SELECT current_user AS role')).rows[0].role;
      assert.equal(role, `dvaia_${kind.toLowerCase()}_runtime`);
      assert.equal((await migration.query("SELECT to_regclass('dvaia_migrations.ledger') AS ledger")).rows[0].ledger, null);
      if (state === 'POPULATED') {
        const prefix = fs.mkdtempSync(path.join(os.tmpdir(), 'ctf-authority-prefix-'));
        t.after(() => fs.rmSync(prefix, { recursive: true, force: true }));
        for (const name of fs.readdirSync(dirs[kind]).filter(n => n.endsWith('.sql') && n < targets[kind])) fs.copyFileSync(path.join(dirs[kind], name), path.join(prefix, name));
        await migrate(migration, prefix);
      }
      stores[kind] = { runtime, migration, role };
    }
    const { IDENTITY: identity, CTF: ctf } = stores;
    let historical, before;
    if (state === 'POPULATED') {
      await require('../../server/database/postgres/ctfDb').seed(ctf.migration);
      await ctf.migration.query("INSERT INTO ctf.ctf_participants(id,user_id,username) VALUES(501,701,'synthetic history'),(502,702,'sibling')");
      await ctf.migration.query("INSERT INTO ctf.ctf_progress(id,participant_id,stage_id,status) VALUES(601,501,1,'completed'),(602,502,1,'in_progress')");
      historical = randomUUID();
      await ctf.migration.query(`INSERT INTO ctf.ctf_judgments(run_id,participant_id,stage_id,progress_id,stage_digest,verdict,accepted,metadata)
        VALUES($1,501,1,601,$2,'pass',1,$3)`, [historical, 'a'.repeat(64), '{"synthetic":true,"original":"preserve raw bytes"}']);
      before = { judgments: (await ctf.runtime.query('SELECT * FROM ctf.ctf_judgments ORDER BY run_id')).rows,
        progress: (await ctf.runtime.query('SELECT * FROM ctf.ctf_progress ORDER BY id')).rows };
    }
    for (const kind of ['IDENTITY', 'CTF']) {
      const store = stores[kind]; assert.ok((await migrate(store.migration, dirs[kind])).includes(targets[kind]));
      const ledger = (await store.migration.query('SELECT * FROM dvaia_migrations.ledger ORDER BY name')).rows;
      assert.deepEqual(await migrate(store.migration, dirs[kind]), []);
      assert.deepEqual((await store.migration.query('SELECT * FROM dvaia_migrations.ledger ORDER BY name')).rows, ledger);
      const tables = kind === 'IDENTITY' ? ['identity.ctf_authority','identity.ctf_decisions','identity.ctf_outbox','identity.ctf_adaptive_memory'] : ['ctf.projection_cursor','ctf.projection_scopes'];
      for (const table of tables) {
        assert.equal((await store.runtime.query('SELECT has_table_privilege(current_user,$1,\'SELECT\') AS allowed', [table])).rows[0].allowed, true);
        for (const privilege of ['INSERT','UPDATE','DELETE','TRUNCATE']) assert.equal((await store.runtime.query('SELECT has_table_privilege(current_user,$1,$2) AS allowed', [table, privilege])).rows[0].allowed, false);
      }
      await assert.rejects(store.runtime.query(`CREATE TABLE ${kind.toLowerCase()}.forbidden_fixture(id int)`), /permission denied/);
    }
    const repo = createCtfAuthorityRepository(identity.runtime, ctf.runtime);
    assert.equal((await repo.readScopeSnapshot(['global'])).available, false);
    assert.equal((await repo.readAppliedProjectionStatus()).available, false);
    if (before) {
      const after = (await ctf.runtime.query('SELECT * FROM ctf.ctf_judgments ORDER BY run_id')).rows;
      assert.deepEqual(after.map(({ decision_id, authority_version, ...row }) => { assert.equal(decision_id, null); assert.equal(authority_version, null); return row; }), before.judgments);
      assert.deepEqual((await ctf.runtime.query('SELECT * FROM ctf.ctf_progress ORDER BY id')).rows, before.progress);
      assert.equal((await repo.compareLegacyProjection(historical)).classification, 'legacy');
    }
    const insert = async (accepted, sequence, { generation = '0', evidence = '{"synthetic":true}' } = {}) => {
      const id = randomUUID(); await identity.migration.query(`INSERT INTO identity.ctf_decisions
        (decision_id,run_id,owner_id,session_id,owner_key,owner_generation,global_revision,stage_revision,participant_id,progress_id,stage_id,stage_digest,evidence_hash,evidence,verdict,accepted,sequence)
        VALUES($1,$2,701,99,'["CTF","701"]',$6,0,0,501,601,1,$3,$3,$7::jsonb,'pass',$4,$5)`, [id, randomUUID(), 'a'.repeat(64), accepted, sequence, generation, evidence]); return id;
    };
    await assert.rejects(insert(false, 10, { evidence: '[]' }), /check constraint/);
    await assert.rejects(insert(false, 10, { evidence: JSON.stringify({ text: 'x'.repeat(65536) }) }), /check constraint/);
    await assert.rejects(insert(false, 10, { generation: '-1' }), /check constraint/);
    await assert.rejects(insert(false, '9223372036854775808'), /out of range/);
    await assert.rejects(identity.migration.query(`INSERT INTO identity.ctf_outbox(sequence,operation_id,kind,command,command_hash)
      VALUES(10,$1,'register','[]',$2)`, [randomUUID(), 'a'.repeat(64)]), /check constraint/);
    await assert.rejects(identity.migration.query(`INSERT INTO identity.ctf_outbox(sequence,operation_id,kind,command,command_hash)
      VALUES(10,$1,'register',$2::jsonb,$3)`, [randomUUID(), JSON.stringify({ text: 'x'.repeat(65536) }), 'a'.repeat(64)]), /check constraint/);
    await insert(false, 1); await insert(false, 2); const accepted = await insert(true, 3);
    await assert.rejects(insert(true, 4), /unique/);
    await assert.rejects(identity.migration.query('DELETE FROM identity.ctf_decisions WHERE decision_id=$1', [accepted]), /immutable/);
    await assert.rejects(identity.migration.query("UPDATE identity.ctf_decisions SET verdict='fail' WHERE decision_id=$1", [accepted]), /immutable/);
    assert.equal((await identity.runtime.query("SELECT EXISTS (SELECT 1 FROM pg_proc p CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE p.oid='identity.reject_ctf_decision_mutation()'::regprocedure AND a.grantee=0 AND a.privilege_type='EXECUTE') AS allowed")).rows[0].allowed, false);
    await assert.rejects(identity.migration.query("INSERT INTO identity.ctf_authority(scope_key) VALUES('owner:701')"), /check constraint/);
    await assert.rejects(ctf.migration.query("INSERT INTO ctf.projection_scopes(scope_key,revision,applied_operation_id) VALUES('owner:701',0,$1)", [randomUUID()]), /check constraint/);
    await assert.rejects(identity.migration.query(`INSERT INTO identity.ctf_outbox(sequence,operation_id,decision_id,kind,command,command_hash)
      VALUES(99,$1,$2,'decision','{}',$3)`, [randomUUID(), accepted, 'a'.repeat(64)]), /foreign key/);
    // Negative nullable CHECK control: a new linked receipt cannot omit version.
    await assert.rejects(ctf.migration.query(`INSERT INTO ctf.ctf_judgments(run_id,participant_id,stage_id,progress_id,stage_digest,verdict,accepted,metadata,decision_id)
      VALUES($1,501,1,601,$2,'pass',1,'{}',$3)`, [randomUUID(), 'a'.repeat(64), randomUUID()]), /check constraint/);
  }
});
