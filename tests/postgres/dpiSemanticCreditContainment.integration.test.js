'use strict';

// Source-only qualification fixture. A launcher must provision TWO empty owned
// disposable identity databases and distinct runtime/migration roles. No model
// is called; fabricated historical/new verdicts are persistence probes only.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { randomUUID, createHash } = require('node:crypto');
const { createPool } = require('../../server/database/postgres');
const { migrate } = require('../../db/postgres/migrate');
const { initializeIdentityRepository, createIdentityRepository } = require('../../server/database/postgres/identityRepository');
const { seedWorkshopPlatform } = require('../../server/database/postgres/workshopPlatformSeed');
const { createObjectiveJudgmentRepository } = require('../../server/database/postgres/objectiveJudgmentRepository');
const { projectJudgment } = require('../../server/agent-runtime/dpiSemanticCreditPolicy');
const target = '0103_dpi_semantic_grading_qualification.sql';
const directory = path.resolve(__dirname, '../../db/postgres/identity-migrations');
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' && process.env.DPI_CONTAINMENT_ISOLATED === '1';
const workshop = 'direct_prompt_injection';

function input(userId, objectiveId) {
  return { userId, evaluationId: randomUUID(), workshopKey: workshop, objectiveId,
    family: 'DPI', scenario: 'aws_assistant', rubricVersion: 'synthetic-historical-v1',
    evidenceDigest: 'a'.repeat(64), runId: null, mode: 'vuln' };
}
function passing(scope) {
  return { family: scope.family, scenario: scope.scenario, objectiveId: scope.objectiveId,
    rubricVersion: scope.rubricVersion, evidenceDigest: scope.evidenceDigest,
    runId: scope.runId, mode: scope.mode, verdict: 'pass',
    criteria: [{ id: 'observed', satisfied: true, evidenceRefs: ['synthetic-response'] }],
    explanation: 'Synthetic persistence fixture, not genuine model evidence.',
    provider: 'fixture', model: 'fixture', usage: null };
}
async function snapshot(pool) {
  return {
    receipts: (await pool.query('SELECT * FROM workshop_platform.objective_judgments ORDER BY user_id,evaluation_id')).rows,
    completions: (await pool.query('SELECT * FROM workshop_platform.completions ORDER BY user_id,workshop_key,objective_id')).rows,
  };
}

test('0103 fresh/populated/no-op preserves historical awards and contains new DPI semantic credit',
  { skip: !enabled, timeout: 180000 }, async t => {
    const pools = [];
    t.after(async () => Promise.allSettled(pools.map(pool => pool.end())));
    const pairs = [];
    for (const label of ['FRESH', 'POPULATED']) {
      const keys = [`PG_DPI_CONTAINMENT_${label}_RUNTIME_URL`, `PG_DPI_CONTAINMENT_${label}_MIGRATION_URL`];
      const urls = keys.map(key => new URL(process.env[key]));
      for (const url of urls) {
        assert.equal(url.hostname, '127.0.0.1');
        assert.match(url.pathname, /^\/dvaia_test_[a-z0-9_]+$/);
      }
      assert.equal(urls[0].pathname, urls[1].pathname);
      assert.equal(urls[0].port, urls[1].port);
      assert.notEqual(urls[0].username, urls[1].username);
      const [runtime, migration] = keys.map(key => createPool(process.env, key));
      pools.push(runtime, migration);
      const identity = (await runtime.query('SELECT current_user AS role,current_database() AS db')).rows[0];
      const ddl = (await migration.query('SELECT current_user AS role,current_database() AS db')).rows[0];
      assert.equal(identity.role, 'dvaia_identity_runtime');
      assert.notEqual(identity.role, ddl.role);
      assert.equal(identity.db, ddl.db);
      assert.equal((await migration.query("SELECT to_regclass('dvaia_migrations.ledger') AS ledger")).rows[0].ledger, null,
        'Refuse an already initialized database; launcher owns fresh stores');
      pairs.push({ runtime, migration, database: identity.db });
    }
    assert.notEqual(pairs[0].database, pairs[1].database);
    const [fresh, populated] = pairs;
    assert.ok((await initializeIdentityRepository(fresh.runtime, fresh.migration)).includes(target));
    assert.deepEqual(await initializeIdentityRepository(fresh.runtime, fresh.migration), []);

    const prefix = fs.mkdtempSync(path.join(os.tmpdir(), 'dpi-containment-through-0102-'));
    t.after(() => fs.rmSync(prefix, { recursive: true, force: true }));
    for (const name of fs.readdirSync(directory).filter(name => /^\d{4}_[a-z0-9_]+\.sql$/.test(name) && name < target)) {
      fs.copyFileSync(path.join(directory, name), path.join(prefix, name));
    }
    await migrate(populated.migration, prefix);
    await seedWorkshopPlatform(populated.migration);
    const users = createIdentityRepository(populated.runtime);
    const passwordHash = await require('bcryptjs').hash('SyntheticFixtureOnly!', 4);
    const historical = await users.createUser({ username: 'dpi-history', email: 'history@fixture.test', passwordHash });
    const learner = await users.createUser({ username: 'dpi-new', email: 'new@fixture.test', passwordHash });
    const sibling = await users.createUser({ username: 'dpi-sibling', email: 'sibling@fixture.test', passwordHash });
    const repo = createObjectiveJudgmentRepository(populated.runtime);
    // Seed a representative historical award with the migration role. Current
    // production containment must NEVER be disabled to manufacture old credit.
    const old = input(historical.id, 'virtualization');
    await repo.beginEvaluation(old);
    const rawOld = passing(old);
    await populated.migration.query(`UPDATE workshop_platform.objective_judgments
      SET verdict='pass',disposition='awarded',result_json=$3::jsonb,result_digest=$4,evaluated_at=now()
      WHERE user_id=$1 AND evaluation_id=$2`, [old.userId, old.evaluationId,
      JSON.stringify(rawOld), createHash('sha256').update(JSON.stringify(rawOld)).digest('hex')]);
    await populated.migration.query('INSERT INTO workshop_platform.completions(user_id,workshop_key,objective_id) VALUES($1,$2,$3)',
      [old.userId, workshop, old.objectiveId]);
    const siblingScope = input(sibling.id, 'jailbreak');
    await repo.beginEvaluation(siblingScope);
    assert.equal((await repo.recordVerdict({ ...siblingScope, result: passing(siblingScope) })).disposition, 'awarded');
    const before = await snapshot(populated.runtime);
    assert.ok((await initializeIdentityRepository(populated.runtime, populated.migration)).includes(target));
    assert.deepEqual(await snapshot(populated.runtime), before);
    const ledger = (await populated.migration.query('SELECT * FROM dvaia_migrations.ledger ORDER BY name')).rows;
    assert.equal(ledger.filter(row => row.name === target).length, 1);
    assert.deepEqual(await initializeIdentityRepository(populated.runtime, populated.migration), []);
    assert.deepEqual((await populated.migration.query('SELECT * FROM dvaia_migrations.ledger ORDER BY name')).rows, ledger);
    assert.deepEqual(await snapshot(populated.runtime), before);

    for (const objectiveId of ['virtualization', 'obfuscation']) {
      const scope = input(learner.id, objectiveId), raw = passing(scope);
      await repo.beginEvaluation(scope);
      const receipt = await repo.recordVerdict({ ...scope, result: raw });
      assert.equal(receipt.disposition, 'grading_unqualified');
      assert.equal(receipt.result.verdict, 'pass');
      assert.equal(receipt.result.explanation, raw.explanation);
      assert.deepEqual(receipt.result.criteria, raw.criteria);
      assert.equal(Object.hasOwn(receipt.result, 'gradingStatus'), false);
      assert.equal(projectJudgment(receipt).gradingStatus, 'pending');
      const stored = await repo.getEvaluation(scope);
      assert.deepEqual((await repo.recordVerdict({ ...scope, result: raw })).result, stored.result);
      const [recovered] = await repo.listRecoverable({ userId: learner.id, evaluationId: scope.evaluationId, judgeVersion: 'fixture' });
      assert.equal(recovered.gradingStatus, 'pending');
      assert.equal(recovered.verdict, 'pass');
      assert.equal(recovered.canRetry, false);
      assert.equal(await repo.getEvaluation({ userId: sibling.id, evaluationId: scope.evaluationId }), null);
    }
    assert.equal((await populated.runtime.query('SELECT count(*)::integer AS count FROM workshop_platform.completions WHERE user_id=$1', [learner.id])).rows[0].count, 0);
    const after = await snapshot(populated.runtime);
    assert.deepEqual(after.completions, before.completions, 'Historical and sibling credit preserved exactly');
    assert.deepEqual(after.receipts.filter(row => row.user_id !== learner.id), before.receipts,
      'Historical and sibling immutable receipts preserved exactly');
    assert.deepEqual(await initializeIdentityRepository(populated.runtime, populated.migration), []);
    assert.deepEqual(await snapshot(populated.runtime), after, 'No-op initialization preserves new pending projections too');
  });
