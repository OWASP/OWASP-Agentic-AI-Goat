'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const Module = require('node:module');
const { randomUUID, createHash } = require('node:crypto');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');

const enabled = process.env.IPI_OBLIGATION_RECEIPT_REPLAY_NATIVE === '1';

test('retained synthetic v4 receipt survives canonical storage, owner projection, and reset fencing', {
  skip: !enabled,
  timeout: 300000,
}, async () => {
  assert.equal(process.env.PG_TEST_DISPOSABLE, 'yes');
  assert.equal(fs.realpathSync(process.env.DVAIA_ISOLATED_TEST_WORKSPACE), fs.realpathSync(process.cwd()));
  assert.deepEqual(Object.keys(process.env).filter(key => key.endsWith('_URL')).sort(),
    ['WORKSHOP_RAG_MIGRATION_URL', 'WORKSHOP_RAG_RUNTIME_URL'], 'installed/application URLs are forbidden');
  for (const key of ['OLLAMA_BASE_URL', 'JUDGE_BASE_URL', 'OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'BEDROCK_MODEL_ID']) {
    assert.equal(process.env[key], undefined, `${key} must not enter the no-model receipt replay`);
  }
  const forbidden = /(?:multiProviderAIService|ollamaService|objectiveJudge|sourceComparisonVerifier)$/;
  const originalLoad = Module._load;
  Module._load = function guardedLoad(request, parent, isMain) {
    if (forbidden.test(String(request).replace(/\.js$/, ''))) throw new Error(`provider/Judge module forbidden in receipt replay: ${request}`);
    return originalLoad.call(this, request, parent, isMain);
  };
  const url = role => {
    const value = new URL(process.env[`WORKSHOP_RAG_${role.toUpperCase()}_URL`]);
    assert.equal(value.protocol, 'postgresql:');
    assert.equal(value.hostname, '127.0.0.1');
    assert.match(value.pathname, /^\/dvaia_test_workshop_rag_[a-f0-9]+$/);
    assert.equal(value.username, `dvaia_identity_${role}`);
    return value.href;
  };
  const fixturePath = path.resolve(__dirname, '../fixtures/ipiObligationV4CalibrationReceipt.json');
  const fixture = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));
  assert.equal(fixture.provenance.kind, 'retained_synthetic_calibration');
  assert.equal(fixture.provenance.originSha256, '367b87d40ac78b82caf093227ef1c70dd493ae61eccb73488e09258f6d28f1c0');
  assert.equal(fixture.case.provenance, 'synthetic_calibration');
  assert.equal(fixture.case.result.runId, 'judge-calibration-synthetic_exact_target_positive');
  assert.deepEqual(fixture.case.result.comparisonStages.map(stage => stage.stage), ['source', 'effect', 'support']);

  process.env.IDENTITY_DATABASE_URL = url('runtime');
  process.env.IDENTITY_MIGRATION_DATABASE_URL = url('migration');
  process.env.PLATFORM_DATABASE_ENGINE = 'postgres';
  process.env.WORKSHOP_DATABASE_ENGINE = 'postgres';
  const migration = new Pool({ connectionString: url('migration'), max: 2 });
  const runtime = new Pool({ connectionString: url('runtime'), max: 4 });
  let directory;
  try {
    directory = fs.mkdtempSync(path.join(os.tmpdir(), 'ipi-receipt-migrations-'));
    const source = path.resolve(__dirname, '../../db/postgres/identity-migrations');
    for (const name of fs.readdirSync(source)) if (name.endsWith('.sql')) fs.copyFileSync(path.join(source, name), path.join(directory, name));
    await migrate(migration, directory);
    assert.deepEqual(await migrate(migration, directory), []);
    await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(migration);

    const catalog = (await runtime.query(`SELECT e.catalog_active AS exercise_active,e.is_visible,
      o.catalog_active AS objective_active,o.is_enabled
      FROM workshop_platform.exercises e JOIN workshop_platform.objectives o USING(workshop_key)
      WHERE e.workshop_key='indirect_prompt_injection' AND o.objective_id='rag_query_injection'`)).rows;
    assert.deepEqual(catalog, [{ exercise_active: true, is_visible: true, objective_active: true, is_enabled: true }]);

    const identity = require('../../server/database/postgres/identityRepository').createIdentityRepository(runtime);
    const hash = await require('bcryptjs').hash(randomUUID(), 4);
    const owner = await identity.createUser({ username: `ipi-receipt-${randomUUID()}`, email: `${randomUUID()}@example.invalid`, passwordHash: hash });
    const sibling = await identity.createUser({ username: `ipi-sibling-${randomUUID()}`, email: `${randomUUID()}@example.invalid`, passwordHash: hash });
    const ownerKey = JSON.stringify(['RAG', String(owner.id)]);
    const runId = randomUUID();
    await runtime.query('INSERT INTO graph_runtime.owners(owner_key,generation) VALUES($1,0)', [ownerKey]);
    await runtime.query("INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status,last_node,finished_at) VALUES($1,$2,0,'completed','judge_receipt_replay',now())", [runId, ownerKey]);
    const runBinding = (await runtime.query('SELECT run_id::text,owner_key,generation,status FROM graph_runtime.runs WHERE run_id=$1', [runId])).rows[0];
    assert.deepEqual(runBinding, { run_id: runId, owner_key: ownerKey, generation: '0', status: 'completed' });

    const copiedResult = structuredClone(fixture.case.result);
    copiedResult.runId = runId;
    const scope = {
      userId: owner.id,
      evaluationId: randomUUID(),
      workshopKey: 'indirect_prompt_injection',
      objectiveId: copiedResult.objectiveId,
      family: copiedResult.family,
      scenario: copiedResult.scenario,
      rubricVersion: copiedResult.rubricVersion,
      evidenceDigest: copiedResult.evidenceDigest,
      runId,
      mode: copiedResult.mode,
    };
    const receipts = require('../../server/database/postgres/objectiveJudgmentRepository').createObjectiveJudgmentRepository(runtime);
    const begun = await receipts.beginEvaluation(scope);
    assert.equal(begun.runId, runId);
    const pendingRow = (await runtime.query(`SELECT * FROM workshop_platform.objective_judgments
      WHERE user_id=$1 AND evaluation_id=$2`, [owner.id, scope.evaluationId])).rows[0];
    const expectedResult = require('../../server/database/postgres/objectiveJudgmentRepository').resultValue(copiedResult, pendingRow);
    const recorded = await receipts.recordVerdict({ ...scope, result: copiedResult });
    assert.equal(recorded.disposition, 'awarded');
    const exact = await receipts.getEvaluation(scope);
    assert.deepEqual(exact.result, expectedResult, 'canonical resultValue must roundtrip its exact normalized receipt');
    assert.deepEqual(exact.result.semanticObservation.sourceObligations, copiedResult.semanticObservation.sourceObligations);
    assert.deepEqual(exact.result.comparisonStages, copiedResult.comparisonStages);
    assert.equal(exact.result.errorCode, null, 'absent optional success metadata has the canonical null form');
    assert.equal(exact.result.evidenceDigest, fixture.case.result.evidenceDigest, 'digest remains bound to the copied synthetic evidence context');

    const reads = require('../../server/database/postgres/agentRunReadRepository').createPostgresAgentRunReadRepository(runtime);
    const projected = await reads.judgments(runId, { userId: owner.id, family: 'RAG' });
    assert.equal(projected.length, 1);
    assert.deepEqual(projected[0].semanticObservation, copiedResult.semanticObservation);
    assert.deepEqual(projected[0].comparisonStages, copiedResult.comparisonStages);
    assert.equal(projected[0].comparisonVersion, copiedResult.comparisonVersion);
    assert.equal(await reads.judgments(runId, { userId: sibling.id, family: 'RAG' }), null, 'sibling cannot inspect the owner run');

    const storedBeforeReset = (await runtime.query(`SELECT result_json,generation,verdict,disposition
      FROM workshop_platform.objective_judgments WHERE user_id=$1 AND evaluation_id=$2`, [owner.id, scope.evaluationId])).rows[0];
    const runBeforeReset = (await runtime.query('SELECT owner_key,generation,status,last_node FROM graph_runtime.runs WHERE run_id=$1', [runId])).rows[0];
    const progress = require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(runtime);
    await progress.resetWorkshopProgress(owner.id, scope.workshopKey);
    const storedAfterReset = (await runtime.query(`SELECT result_json,generation,verdict,disposition
      FROM workshop_platform.objective_judgments WHERE user_id=$1 AND evaluation_id=$2`, [owner.id, scope.evaluationId])).rows[0];
    const runAfterReset = (await runtime.query('SELECT owner_key,generation,status,last_node FROM graph_runtime.runs WHERE run_id=$1', [runId])).rows[0];
    assert.deepEqual(storedAfterReset, storedBeforeReset, 'reset preserves the immutable synthetic receipt snapshot');
    assert.deepEqual(runAfterReset, runBeforeReset, 'reset preserves the immutable owned run snapshot');
    assert.equal((await receipts.recordVerdict({ ...scope, result: copiedResult })).disposition, 'stale_generation');
    assert.equal((await progress.getWorkshopProgress(owner.id, scope.workshopKey)).completedObjectiveCount, 0, 'stale replay cannot restore credit');

    const evidence = {
      status: 'passed',
      scope: fixture.provenance.claim,
      retainedFixtureSha256: createHash('sha256').update(fs.readFileSync(fixturePath)).digest('hex'),
      originSha256: fixture.provenance.originSha256,
      generatedRunId: runId,
      originalSyntheticRunId: fixture.case.result.runId,
      evidenceDigest: copiedResult.evidenceDigest,
      comparisonVersion: copiedResult.comparisonVersion,
      obligationCount: copiedResult.semanticObservation.sourceObligations.length,
      comparisonStages: copiedResult.comparisonStages.map(stage => stage.stage),
      disposition: recorded.disposition,
      siblingDenied: true,
      resetPreservedReceipt: true,
      staleReplayDenied: true,
    };
    const evidencePath = process.env.IPI_RECEIPT_REPLAY_EVIDENCE_PATH;
    assert.ok(path.isAbsolute(evidencePath) && !path.resolve(evidencePath).startsWith(process.cwd() + path.sep));
    fs.writeFileSync(evidencePath, JSON.stringify(evidence, null, 2) + '\n', { mode: 0o600 });
  } finally {
    Module._load = originalLoad;
    await Promise.allSettled([runtime.end(), migration.end()]);
    if (directory) fs.rmSync(directory, { recursive: true, force: true });
  }
});
