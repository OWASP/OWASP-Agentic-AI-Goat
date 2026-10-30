'use strict';

process.env.EXPORT_INTERNALS = '1';

const test = require('node:test');
const assert = require('node:assert/strict');
const { randomBytes } = require('node:crypto');

const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' && !!process.env.PG_CSRF_BROWSER_COMPLETION_RUNTIME_URL;
const ATTACKER = 'http://attacker.completion.invalid';
const VICTIM = 'http://victim.completion.invalid';
const VICTIM_PATH = '/api/workshop/csrf/agent-action';

test('real browser workflow publishes only native scoped CSRF completion receipts', {
  skip: !enabled,
  timeout: 60000,
}, async t => {
  for (const key of ['PG_CSRF_BROWSER_COMPLETION_RUNTIME_URL', 'PG_CSRF_BROWSER_COMPLETION_MIGRATION_URL']) {
    assert.match(new URL(process.env[key]).pathname, /^\/owasp_ai_goat_test_[a-z0-9_]+$/);
  }
  const { createPool } = require('../../server/database/postgres');
  const runtime = createPool(process.env, 'PG_CSRF_BROWSER_COMPLETION_RUNTIME_URL');
  const migration = createPool(process.env, 'PG_CSRF_BROWSER_COMPLETION_MIGRATION_URL');
  const executor = require('../../server/services/csrfBrowserExecutor').createCsrfBrowserExecutor({
    attackerOrigin: ATTACKER,
    victimOrigin: VICTIM,
    victimPath: VICTIM_PATH,
    timeoutMs: 5000,
  });
  try {
    const identityApi = require('../../server/database/postgres/identityRepository');
    await identityApi.initializeIdentityRepository(runtime, migration);
    await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(migration);
    const identity = identityApi.createIdentityRepository(runtime);
    const hash = await require('bcryptjs').hash('owned browser completion fixture', 4);
    const user = await identity.createUser({
      username: 'csrf_browser_completion',
      email: 'csrf-browser-completion@fixture.invalid',
      passwordHash: hash,
    });
    const sibling = await identity.createUser({
      username: 'csrf_browser_sibling',
      email: 'csrf-browser-sibling@fixture.invalid',
      passwordHash: hash,
    });
    for (const id of [user.id, sibling.id]) {
      await runtime.query(`INSERT INTO workshop_platform.user_modes(user_id,workshop_key,mode)
        VALUES($1,'csrf_workshop','vulnerable')
        ON CONFLICT(user_id,workshop_key) DO UPDATE SET mode='vulnerable'`, [id]);
    }

    const progress = require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(runtime);
    const receipts = require('../../server/database/postgres/objectiveJudgmentRepository').createObjectiveJudgmentRepository(runtime);
    const { prepareJudgeInput } = require('../../server/agent-runtime/objectiveJudge');
    let judgeCalls = 0;
    const deterministicJudge = async packet => {
      judgeCalls += 1;
      const prepared = prepareJudgeInput(packet);
      return {
        family: packet.rubric.family,
        scenario: packet.rubric.scenario,
        objectiveId: packet.rubric.objectiveId,
        rubricVersion: packet.rubric.version,
        evidenceDigest: prepared.evidenceDigest,
        runId: packet.execution.runId,
        mode: packet.rubric.mode,
        verdict: 'pass',
        criteria: packet.rubric.criteria.map(criterion => ({
          id: criterion.id,
          satisfied: true,
          evidenceRefs: ['action', 'receipt'],
        })),
        explanation: 'Deterministic fixture accepted the server-observed browser effect.',
        provider: 'fixture',
        model: 'deterministic-native-proof',
        usage: null,
      };
    };
    const completionService = require('../../server/services/objectiveCompletionService').createObjectiveCompletionService({
      receipts,
      progress,
      judge: deterministicJudge,
    });
    const grader = require('../../server/services/csrfObjectiveGrader').createCsrfObjectiveGrader({
      postgres: true,
      completionService,
    });
    const ledger = require('../../server/agent-runtime/postgresRunLedger').createPostgresRunLedger(runtime);
    const coordinator = require('../../server/agent-runtime/runCoordinator').createRunCoordinator({ family: 'CSRF', ledger });
    const workflow = require('../../server/services/csrfBrowserWorkflow').createCsrfBrowserWorkflow({ executor, timeoutMs: 5000 });
    const { CsrfVictimSandbox } = require('../../server/services/csrfVictimSandbox');
    const sandbox = new CsrfVictimSandbox(`owned-native-${randomBytes(8).toString('hex')}`);

    const runBrowser = (html, finalGrade) => coordinator.run(String(user.id), { timeoutMs: 10000 }, async execution => {
      const actionHandlerDeps = {
        getUserKey: req => String(req.user.id),
        getUserId: req => req.user.id,
        sessionIdFor: () => sandbox.sessionId,
        victimSandbox: {
          VECTORS: { direct_post: { crossSite: true } },
          getOrCreateSandbox: () => sandbox,
        },
        tabOf: req => req.query.tab || req.body.tab,
        detectForgedVector: () => 'direct_post',
        csrfAgent: {
          chat: async (_session, tab, message) => {
            assert.equal(message, 'transfer 17');
            const toolResult = await execution.effect('browser-transfer', async () => sandbox.forge(
              tab,
              'direct_post',
              'transfer',
              { amount: 17, to: 'owned-fixture-payee' },
            ));
            return {
              response: toolResult.outcome,
              toolResult,
              victimState: sandbox.getTabState(tab),
              objectivesHit: ['csrf_p1'],
            };
          },
        },
        recordActivity: async () => {},
        getCompleted: async () => new Set(),
        creditObjective: async () => { throw new Error('Workflow must replace direct completion'); },
        pushCsrfEvent: () => {},
        syncWorkshopStarted: async () => {},
      };
      return workflow.run({
        execution,
        userId: user.id,
        objectiveId: 'csrf_p1',
        tab: 'post',
        html,
        victimCookie: { name: 'owned_victim', value: randomBytes(24).toString('base64url') },
        attackerOrigin: ATTACKER,
        victimOrigin: VICTIM,
        victimPath: VICTIM_PATH,
        actionHandlerDeps,
        beginGrading: childExecution => grader.begin(user.id, childExecution),
        finalGrade,
      });
    });

    const payload = `<form method="POST" action="${VICTIM}${VICTIM_PATH}"><input name="tab" value="post"><input name="message" value="transfer 17"></form><script>document.forms[0].submit()</script>`;
    const before = sandbox.tab('post').victim.account.balance;
    let positiveRunId;
    const positive = await runBrowser(payload, async packet => {
      positiveRunId = packet.execution.runId;
      assert.ok(packet.gradingAttempt, 'grading authority was captured before browser evidence');
      return grader.evaluate({
        userId: user.id,
        objectiveId: packet.objectiveId,
        execution: packet.execution,
        attempt: packet.gradingAttempt,
        snapshot: {},
        activity: packet.activity,
        receipt: packet.receipt,
      });
    });
    assert.equal(positive.graded, true);
    assert.equal(positive.grade.completed, true);
    assert.equal(positive.grade.durable, true);
    assert.equal(positive.grade.judgment.verdict, 'pass');
    assert.equal(sandbox.tab('post').victim.account.balance, before - 17, 'the actual sandbox effect preceded grading');
    assert.equal(judgeCalls, 1);

    const judgment = (await runtime.query(`SELECT user_id,evaluation_id,workshop_key,objective_id,family,scenario,
        rubric_version,evidence_digest,run_id,generation,verdict,disposition
      FROM workshop_platform.objective_judgments WHERE user_id=$1`, [user.id])).rows;
    assert.equal(judgment.length, 1);
    assert.equal(judgment[0].user_id, user.id);
    assert.equal(judgment[0].workshop_key, 'csrf_workshop');
    assert.equal(judgment[0].objective_id, 'csrf_p1');
    assert.equal(judgment[0].family, 'CSRF');
    assert.equal(judgment[0].scenario, 'post');
    assert.equal(judgment[0].rubric_version, 'csrf-observed-v8');
    assert.match(judgment[0].evidence_digest, /^[a-f0-9]{64}$/);
    assert.equal(judgment[0].run_id, positiveRunId);
    assert.equal(judgment[0].verdict, 'pass');
    assert.equal(judgment[0].disposition, 'awarded');
    assert.equal((await runtime.query(`SELECT count(*)::int AS n FROM workshop_platform.completions
      WHERE user_id=$1 AND workshop_key='csrf_workshop' AND objective_id='csrf_p1'`, [user.id])).rows[0].n, 1);
    assert.equal((await runtime.query('SELECT count(*)::int AS n FROM workshop_platform.objective_judgments WHERE user_id=$1', [sibling.id])).rows[0].n, 0);
    assert.equal((await runtime.query('SELECT count(*)::int AS n FROM workshop_platform.completions WHERE user_id=$1', [sibling.id])).rows[0].n, 0);

    let failedGradeCalls = 0;
    const oversizedPost = `<form method="POST" action="${VICTIM}${VICTIM_PATH}"><input name="tab" value="post"><textarea name="message">${'€'.repeat(10000)}</textarea></form><script>document.forms[0].submit()</script>`;
    await assert.rejects(runBrowser(oversizedPost, async () => { failedGradeCalls += 1; }), {
      code: 'CSRF_BROWSER_REQUEST_TOO_LARGE',
    });
    assert.equal(failedGradeCalls, 0);
    assert.equal(judgeCalls, 1);
    assert.equal((await runtime.query('SELECT count(*)::int AS n FROM workshop_platform.objective_judgments WHERE user_id=$1', [user.id])).rows[0].n, 1);
    assert.equal((await runtime.query(`SELECT count(*)::int AS n FROM workshop_platform.completions
      WHERE user_id=$1 AND workshop_key='csrf_workshop' AND objective_id='csrf_p1'`, [user.id])).rows[0].n, 1);

    let staleJudgeCalls = 0;
    const staleBefore = sandbox.tab('post').victim.account.balance;
    await assert.rejects(runBrowser(payload, async packet => {
      await progress.resetWorkshopProgress(user.id, 'csrf_workshop');
      staleJudgeCalls += 1;
      return grader.evaluate({
        userId: user.id,
        objectiveId: packet.objectiveId,
        execution: packet.execution,
        attempt: packet.gradingAttempt,
        snapshot: {},
        activity: packet.activity,
        receipt: packet.receipt,
      });
    }), { code: 'STALE_GENERATION' });
    assert.equal(staleJudgeCalls, 1, 'the native generation fence is reached after the observed effect');
    assert.equal(judgeCalls, 1, 'stale evidence is rejected before Judge execution');
    assert.equal(sandbox.tab('post').victim.account.balance, staleBefore - 17);
    assert.equal((await runtime.query('SELECT count(*)::int AS n FROM workshop_platform.objective_judgments WHERE user_id=$1', [user.id])).rows[0].n, 1,
      'stale evidence creates no additional receipt');
    assert.equal((await runtime.query(`SELECT count(*)::int AS n FROM workshop_platform.completions
      WHERE user_id=$1 AND workshop_key='csrf_workshop'`, [user.id])).rows[0].n, 0,
      'reset removed canonical completion and stale evidence did not restore it');
    assert.equal((await runtime.query('SELECT count(*)::int AS n FROM workshop_platform.completions WHERE user_id=$1', [sibling.id])).rows[0].n, 0);
    t.diagnostic('Judge was an injected deterministic fixture; browser, sandbox, owner ledger, receipt and progress stores were production implementations.');
  } finally {
    await executor.close();
    await Promise.all([runtime.end(), migration.end()]);
  }
});
