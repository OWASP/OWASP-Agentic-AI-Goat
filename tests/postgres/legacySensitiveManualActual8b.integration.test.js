'use strict';

// Candidate harness only: requires its own reviewed isolated launcher. Retained
// legacy manual runtime qualification does not qualify FinFlow or HTTP wiring.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { createHash, randomUUID } = require('node:crypto');
const MODEL = 'llama3.1:8b';
const DIGEST = '46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e';
const BASE = 'http://127.0.0.1:11434';
const sha = value => createHash('sha256').update(value).digest('hex');
const within = (root, target) => {
  const relative = path.relative(root, target);
  return relative === '' || (!path.isAbsolute(relative) && relative !== '..' && !relative.startsWith(`..${path.sep}`));
};
const { CASES, validateLegacySensitiveManualReport } = require('../fixtures/legacySensitiveManualReportContract');
const NAMES = Object.keys(CASES);

test('actual8B retained Legacy Sensitive manual tools and Judge with disposable receipts', {
  skip: process.env.LEGACY_SENSITIVE_MANUAL_ACTUAL8B_ISOLATED !== '1', timeout: 1800000,
}, async () => {
  const output = process.env.LEGACY_SENSITIVE_MANUAL_EVIDENCE_PATH;
  assert.ok(output && path.isAbsolute(output) && path.basename(output) === 'qualification.json');
  const report = { version: 1, cohort: 'legacy-sensitive-manual-actual8b-v1', model: MODEL, digest: DIGEST,
    qualification: 'incomplete', modelVerifiedBefore: false, modelVerifiedAfter: false, casesPreservedSibling: false, cases: [],
    cancellation: { passed: false, actorCalls: 0, judgeCalls: 0, calls: [] }, failures: [] };
  const originalFetch = global.fetch;
  let pool;
  let calls = [];
  const inventory = async () => {
    const response = await originalFetch(`${BASE}/api/tags`, { signal: AbortSignal.timeout(5000) });
    assert.equal(response.status, 200);
    const matches = (await response.json()).models.filter(row => row.name === MODEL);
    assert.equal(matches.length, 1); assert.equal(matches[0].digest, DIGEST);
  };
  try {
    assert.equal(process.env.PG_TEST_DISPOSABLE, 'yes');
    assert.equal(process.env.OLLAMA_BASE_URL, BASE);
    assert.equal(process.env.OLLAMA_MODEL, MODEL); assert.equal(process.env.JUDGE_MODEL, MODEL);
    assert.equal(process.env.LEGACY_SENSITIVE_MANUAL_MODEL_DIGEST, DIGEST);
    const url = new URL(process.env.PG_LEGACY_SENSITIVE_MANUAL_RUNTIME_URL);
    assert.equal(url.hostname, '127.0.0.1');
    assert.match(url.pathname, /^\/dvaia_test_[a-z0-9_]+$/);
    assert.equal(decodeURIComponent(url.username), 'dvaia_identity_runtime');
    const fixture = process.env.LEGACY_SENSITIVE_MANUAL_FIXTURE_ROOT;
    assert.ok(fixture && path.isAbsolute(fixture));
    const realFixture = await fs.realpath(fixture);
    assert.equal(realFixture, path.resolve(fixture));
    assert.equal(within(await fs.realpath(process.cwd()), realFixture), false);
    assert.equal(within(realFixture, path.resolve(output)), false);
    assert.deepEqual(await fs.readdir(realFixture), []);
    await inventory(); report.modelVerifiedBefore = true;
    global.fetch = async (input, options = {}) => {
      const target = new URL(typeof input === 'string' || input instanceof URL ? input : input.url);
      assert.equal(target.origin, BASE);
      assert.ok(['/api/generate', '/api/chat'].includes(target.pathname));
      const body = String(options.body || ''); const parsed = JSON.parse(body);
      assert.equal(parsed.model, MODEL); assert.equal(parsed.options?.num_ctx, 32768);
      const call = { phase: 'judge', requestSha256: sha(body), requestBytes: Buffer.byteLength(body),
        completed: false, configuredContextTokens: parsed.options.num_ctx, outputSha256: sha(''), outputBytes: 0 };
      calls.push(call);
      const response = await originalFetch(input, options);
      const raw = await response.clone().text();
      const text = raw.split('\n').filter(line => line.trim()).map(line => {
        const row = JSON.parse(line); return row.response || row.message?.content || '';
      }).join('');
      call.outputSha256 = sha(text); call.outputBytes = Buffer.byteLength(text); call.completed = response.ok;
      return response;
    };
    const { Pool } = require('pg');
    const { createPostgresRunLedger } = require('../../server/agent-runtime/postgresRunLedger');
    const { createRunCoordinator } = require('../../server/agent-runtime/runCoordinator');
    const { createLegacySensitiveManualOwnedCases } = require('../fixtures/legacySensitiveManualOwnedCases');
    const { createLegacySensitiveObjectiveGrader, inspect, rubricFor } = require('../../server/services/legacySensitiveObjectiveGrader');
    const { createObjectiveJudge } = require('../../server/agent-runtime/objectiveJudge');
    const { createLangChainProvider } = require('../../server/agent-runtime/providers/langchainProvider');
    pool = new Pool({ connectionString: url.href, max: 6, connectionTimeoutMillis: 5000 });
    assert.equal((await pool.query('SELECT current_user AS role')).rows[0].role, 'dvaia_identity_runtime');
    assert.equal(Number((await pool.query('SELECT count(*) AS count FROM graph_runtime.runs')).rows[0].count), 0);
    const coordinator = createRunCoordinator({ family: 'LegacySensitiveInfo', ledger: createPostgresRunLedger(pool) });
    const ownerA = `fixture-a-${randomUUID()}`; const ownerB = `fixture-b-${randomUUID()}`;
    const rootA = path.join(realFixture, 'owner-a'); const rootB = path.join(realFixture, 'owner-b');
    await fs.mkdir(rootA, { mode: 0o700 }); await fs.mkdir(rootB, { mode: 0o700 });
    const specifications = createLegacySensitiveManualOwnedCases({ ownedRoot: rootA });
    const siblingCases = createLegacySensitiveManualOwnedCases({ ownedRoot: rootB });
    assert.deepEqual(specifications.map(spec => spec.name), NAMES);
    const judge = createObjectiveJudge({ model: createLangChainProvider({ provider: 'ollama', model: MODEL, baseURL: BASE }), timeoutMs: 90000 });
    const grader = createLegacySensitiveObjectiveGrader({ judge, postgres: false });
    // Populate sibling ledger as well as files, so isolation is not vacuous.
    await coordinator.run(ownerB, {}, execution => execution.effectWithReceipt('sibling_read', siblingCases[0].invoke));
    const siblingSnapshot = async () => {
      const ownerKey = JSON.stringify(['LegacySensitiveInfo', ownerB]); const snapshot = {};
      for (const table of ['owners', 'runs', 'effects', 'events']) {
        snapshot[table] = (await pool.query(`SELECT row_to_json(snapshot)::text AS value FROM graph_runtime.${table} AS snapshot
          WHERE owner_key=$1 ORDER BY row_to_json(snapshot)::text`, [ownerKey])).rows.map(row => row.value);
      }
      snapshot.files = [];
      for (const directory of ['public', 'secret']) for (const name of (await fs.readdir(path.join(rootB, directory))).sort()) {
        snapshot.files.push([directory, name, sha(await fs.readFile(path.join(rootB, directory, name)))]);
      }
      return JSON.stringify(snapshot);
    };
    const before = await siblingSnapshot();
    for (const spec of specifications) {
      calls = [];
      const row = { name: spec.name, objectiveId: spec.objectiveId, operation: spec.operation,
        passed: false, failedPositive: spec.expected.completed, toolCalls: 0, receiptCount: 0,
        receiptCompleted: false, observationSha256: null,
        scenarioChecks: { independentEffects: null, canonicalFacts: null },
        failureStage: null, failureCode: null, receiptReadFailed: false,
        verdict: 'unavailable', completed: false, durable: false, calls: [] };
      let stage = 'admission'; let identity;
      try {
        await coordinator.run(ownerA, { timeoutMs: 180000 }, async execution => {
          identity = { runId: execution.runId, ownerKey: execution.ownerKey };
          stage = 'tool';
          const observed = await execution.effectWithReceipt(spec.name, spec.invoke);
          row.toolCalls = 1; row.observationSha256 = sha(JSON.stringify(observed.value));
          stage = 'receipt_validation';
          const receipts = (await pool.query('SELECT effect_key,status FROM graph_runtime.effects WHERE run_id=$1 AND owner_key=$2',
            [execution.runId, execution.ownerKey])).rows;
          row.receiptCount = receipts.filter(receipt => receipt.status === 'completed').length;
          row.receiptCompleted = receipts.length === 1 && observed.receipt?.status === 'completed'
            && receipts[0].effect_key === observed.receipt.effectKey && receipts[0].status === 'completed'
            && observed.receipt.runId === execution.runId && observed.receipt.ownerKey === execution.ownerKey
            && String(observed.receipt.generation) === String(execution.durableGeneration);
          assert.equal(row.receiptCompleted, true);
          stage = 'scenario_validation';
          const result = observed.value; const expected = spec.expected;
          const facts = inspect(spec.objectiveId, result).facts;
          row.scenarioChecks.independentEffects = result.success === expected.success
            && ['content', 'rendered', 'ssiSucceeded', 'commandExecution', 'code'].every(key =>
              !Object.hasOwn(expected, key) || result[key] === expected[key])
            && (!Object.hasOwn(expected, 'protectedPath') || (result.boundary?.outsidePublic === true) === expected.protectedPath)
            && facts.known_flag === expected.knownFlag;
          row.scenarioChecks.canonicalFacts = rubricFor(spec.objectiveId).requiredFacts.every(key => facts[key] === true) === expected.completed;
          assert.ok(Object.values(row.scenarioChecks).every(value => value === true));
          assert.equal(calls.length, 0);
          stage = 'judge';
          const grade = await grader.evaluate({ userId: ownerA, objectiveId: spec.objectiveId, request: spec.request, result, execution });
          stage = 'judge_validation';
          row.verdict = grade.judgment.verdict; row.completed = grade.completed; row.durable = grade.durable;
          assert.equal(grade.durable, false); assert.equal(grade.completed, expected.completed);
          assert.equal(grade.judgment.verdict, expected.completed ? 'pass' : 'fail');
          assert.equal(grade.judgment.provider, 'ollama'); assert.equal(grade.judgment.model, MODEL);
          assert.ok(calls.length >= 1 && calls.length <= 2);
          assert.ok(calls.every(call => call.phase === 'judge' && call.completed && call.outputBytes > 0));
          stage = 'run_completion';
        });
        row.passed = true; row.failedPositive = false;
      } catch (error) {
        row.failureStage = stage;
        row.failureCode = ['23514', 'ERR_ASSERTION', 'EFFECT_RECEIPT_INVALID', 'GRAPH_EFFECT_REPLAY_BLOCKED'].includes(error?.code)
          ? error.code : error?.name === 'AbortError' ? 'ABORTED' : 'UNCLASSIFIED';
        if (identity) {
          try {
            const counts = (await pool.query(`SELECT count(*)::int AS attempted,
              count(*) FILTER (WHERE status='completed')::int AS completed FROM graph_runtime.effects WHERE run_id=$1 AND owner_key=$2`,
            [identity.runId, identity.ownerKey])).rows[0];
            row.toolCalls = counts.attempted; row.receiptCount = counts.completed;
          } catch { row.receiptReadFailed = true; row.toolCalls = null; row.receiptCount = null; }
        }
        report.failures.push(spec.name);
      }
      row.calls = calls.map(call => ({ ...call })); report.cases.push(row);
    }
    report.casesPreservedSibling = before === await siblingSnapshot();
    if (!report.casesPreservedSibling) report.failures.push('sibling_case_isolation');
    calls = [];
    let resetPromise; let cancelled = false; let published = false; let completedReceipt; let generationBefore; let runId;
    try {
      await coordinator.run(ownerA, {}, async execution => {
        runId = execution.runId; generationBefore = execution.durableGeneration;
        completedReceipt = (await execution.effectWithReceipt('cancelled_manual_read', specifications[0].invoke)).receipt;
        resetPromise = coordinator.reset(ownerA);
        await execution.check();
        // A stale run must not reach a Judge or publish a completion.
        published = true;
      });
    } catch (error) { cancelled = error.name === 'AbortError'; }
    if (resetPromise) await resetPromise;
    const effects = runId ? (await pool.query('SELECT effect_key,status FROM graph_runtime.effects WHERE run_id=$1', [runId])).rows : [];
    const status = runId ? (await pool.query('SELECT status FROM graph_runtime.runs WHERE run_id=$1', [runId])).rows[0]?.status : null;
    const generation = (await pool.query('SELECT generation FROM graph_runtime.owners WHERE owner_key=$1',
      [JSON.stringify(['LegacySensitiveInfo', ownerA])])).rows[0]?.generation;
    report.cancellation = { passed: Boolean(resetPromise) && cancelled && !published && effects.length === 1
      && effects[0].effect_key === completedReceipt?.effectKey && effects[0].status === 'completed'
      && Number(generation) === Number(generationBefore) + 1 && status === 'cancelled'
      && calls.length === 0 && before === await siblingSnapshot(), actorCalls: 0,
      judgeCalls: calls.length, calls: calls.map(call => ({ ...call })) };
    if (!report.cancellation.passed) report.failures.push('reset_cancellation');
  } catch { report.failures.push('qualification_infrastructure'); }
  finally {
    global.fetch = originalFetch;
    if (report.modelVerifiedBefore) {
      try { await inventory(); report.modelVerifiedAfter = true; } catch { report.failures.push('model_provenance'); }
    } else report.failures.push('model_provenance');
    if (pool) { try { await pool.end(); } catch { report.failures.push('pool_cleanup'); } }
    if (report.modelVerifiedBefore && report.modelVerifiedAfter && report.cases.length === NAMES.length
        && report.cases.every(row => row.passed) && report.casesPreservedSibling && report.cancellation.passed && report.failures.length === 0) report.qualification = 'qualified';
    validateLegacySensitiveManualReport(report, { requireQualified: false });
    await fs.writeFile(output, JSON.stringify(report, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  }
  assert.equal(report.qualification, 'qualified', 'Manual actual-model cohort incomplete; inspect redacted qualification report');
});
