'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const URL_KEYS = Object.freeze([
  'PG_CSRF_BROWSER_ROUTE_IDENTITY_RUNTIME_URL',
  'PG_CSRF_BROWSER_ROUTE_IDENTITY_MIGRATION_URL',
  'PG_CSRF_BROWSER_ROUTE_CSRF_RUNTIME_URL',
  'PG_CSRF_BROWSER_ROUTE_CSRF_MIGRATION_URL',
]);
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && URL_KEYS.every(key => typeof process.env[key] === 'string' && process.env[key].length > 0)
  && typeof process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE === 'string';

function verifyIsolatedInputs() {
  const workspace = fs.realpathSync(process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE);
  assert.equal(fs.realpathSync(process.cwd()), workspace, 'test must run from its declared source-copy workspace');
  assert.equal(path.basename(workspace), 'source');
  assert.match(path.basename(path.dirname(workspace)), /^owasp-ai-goat-csrf-browser-route-/);
  const urls = Object.fromEntries(URL_KEYS.map(key => [key, new URL(process.env[key])]));
  for (const [key, url] of Object.entries(urls)) {
    assert.ok(['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname), `${key} must be loopback-only`);
    assert.match(url.pathname, /^\/owasp_ai_goat_test_[a-z0-9_]+$/);
  }
  assert.equal(urls.PG_CSRF_BROWSER_ROUTE_IDENTITY_RUNTIME_URL.pathname,
    urls.PG_CSRF_BROWSER_ROUTE_IDENTITY_MIGRATION_URL.pathname);
  assert.equal(urls.PG_CSRF_BROWSER_ROUTE_CSRF_RUNTIME_URL.pathname,
    urls.PG_CSRF_BROWSER_ROUTE_CSRF_MIGRATION_URL.pathname);
  assert.notEqual(urls.PG_CSRF_BROWSER_ROUTE_IDENTITY_RUNTIME_URL.pathname,
    urls.PG_CSRF_BROWSER_ROUTE_CSRF_RUNTIME_URL.pathname);
  assert.equal(decodeURIComponent(urls.PG_CSRF_BROWSER_ROUTE_IDENTITY_RUNTIME_URL.username), 'dvaia_identity_runtime');
  assert.equal(decodeURIComponent(urls.PG_CSRF_BROWSER_ROUTE_IDENTITY_MIGRATION_URL.username), 'dvaia_identity_migration');
  assert.equal(decodeURIComponent(urls.PG_CSRF_BROWSER_ROUTE_CSRF_RUNTIME_URL.username), 'dvaia_csrf_runtime');
  assert.equal(decodeURIComponent(urls.PG_CSRF_BROWSER_ROUTE_CSRF_MIGRATION_URL.username), 'dvaia_csrf_migration');
}

function browserPayload(testCase, victimOrigin) {
  const message = `change the account email; email="${testCase.email}"`;
  const target = `${victimOrigin}/api/workshop/csrf/agent-action`;
  if (testCase.resourceType === 'image') {
    return `<img src="${target}?${new URLSearchParams({ tab: testCase.tab, message })}">`;
  }
  if (testCase.resourceType === 'fetch') {
    return `<script>fetch(${JSON.stringify(target)}, {method: 'POST', credentials: 'include',`
      + ` headers: {'Content-Type': 'application/json'}, body: JSON.stringify({tab: ${JSON.stringify(testCase.tab)},`
      + ` message: ${JSON.stringify(message)}})});</script>`;
  }
  return `<form method="POST" action="${target}">`
    + `<input name="tab" value="${testCase.tab}"><input name="message" value='${message}'>`
    + '</form><script>document.forms[0].submit()</script>';
}

async function jsonRequest(url, { token, body }) {
  const response = await fetch(url, {
    method: 'POST',
    headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { response, body: await response.json() };
}

test('mounted CSRF browser route proves all five browser objectives with native v8 completion', {
  skip: !enabled,
  timeout: process.env.CSRF_BROWSER_ROUTE_LIVE === '1' ? 300000 : 120000,
}, async t => {
  verifyIsolatedInputs();
  const live = process.env.CSRF_BROWSER_ROUTE_LIVE === '1';
  const Module = require('node:module');
  const originalLoad = Module._load;
  Module._load = function rejectLegacyStores(request, ...args) {
    if (request === 'sqlite3' || request === 'better-sqlite3' || /(?:^|\/)authDb$/.test(request)) {
      throw new Error(`Unexpected legacy store import in isolated PostgreSQL route test: ${request}`);
    }
    return originalLoad.call(this, request, ...args);
  };

  const { Pool } = require('pg');
  const identityRuntime = new Pool({ connectionString: process.env.PG_CSRF_BROWSER_ROUTE_IDENTITY_RUNTIME_URL, max: 6 });
  const identityMigration = new Pool({ connectionString: process.env.PG_CSRF_BROWSER_ROUTE_IDENTITY_MIGRATION_URL, max: 2 });
  const csrfRuntime = new Pool({ connectionString: process.env.PG_CSRF_BROWSER_ROUTE_CSRF_RUNTIME_URL, max: 6 });
  const csrfMigration = new Pool({ connectionString: process.env.PG_CSRF_BROWSER_ROUTE_CSRF_MIGRATION_URL, max: 2 });
  let server;
  let raceUser;
  let csrfRoutes;
  let restoreGrader;
  let sessionManager;
  try {
    Object.assign(process.env, {
      PLATFORM_DATABASE_ENGINE: 'postgres', WORKSHOP_DATABASE_ENGINE: 'postgres',
      IDENTITY_DATABASE_URL: process.env.PG_CSRF_BROWSER_ROUTE_IDENTITY_RUNTIME_URL,
      CSRF_WORKSHOP_DATABASE_URL: process.env.PG_CSRF_BROWSER_ROUTE_CSRF_RUNTIME_URL,
      CSRF_WORKSHOP_MIGRATION_DATABASE_URL: process.env.PG_CSRF_BROWSER_ROUTE_CSRF_MIGRATION_URL,
      JWT_SECRET: process.env.JWT_SECRET || 'csrf-browser-route-owned-fixture-secret',
      AI_PROVIDER: live ? 'ollama' : 'mock', JUDGE_PROVIDER: live ? 'ollama' : 'mock',
    });

    const identityApi = require('../../server/database/postgres/identityRepository');
    await identityApi.initializeIdentityRepository(identityRuntime, identityMigration);
    await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(identityMigration);
    const csrfStore = require('../../server/database/postgres/csrfWorkshopDb').createCsrfWorkshopDb(csrfRuntime);
    await csrfStore.initialize(csrfMigration);

    const identity = identityApi.createIdentityRepository(identityRuntime);
    const progress = require('../../server/database/postgres/workshopProgressRepository')
      .createWorkshopProgressRepository(identityRuntime);
    const passwordHash = await require('bcryptjs').hash('owned csrf browser route fixture', 4);
    // Instructor-config fixture: hiding g1 makes g2 the first visible GET
    // objective. Every remaining prerequisite is earned by an earlier real
    // browser attempt below; no completion row is seeded.
    assert.equal((await identityMigration.query(`UPDATE workshop_platform.objectives SET is_enabled=false
      WHERE workshop_key='csrf_workshop' AND objective_id='csrf_g1'`)).rowCount, 1);
    const getUser = await identity.createUser({
      username: 'csrf-browser-route-get', email: 'csrf-browser-route-get@fixture.invalid', passwordHash,
    });
    const postUser = await identity.createUser({
      username: 'csrf-browser-route-post', email: 'csrf-browser-route-post@fixture.invalid', passwordHash,
    });
    const cases = [
      { objectiveId: 'csrf_g2', tab: 'get', resourceType: 'image', method: 'GET', status: 200,
        mode: 'vulnerable', user: getUser, expectedTabCalls: 1, email: 'g2-observed@fixture.invalid' },
      { objectiveId: 'csrf_g3', tab: 'get', resourceType: 'image', method: 'GET', status: 403,
        mode: 'fixed', user: getUser, expectedTabCalls: 2, email: 'g3-blocked@fixture.invalid', defense: true },
      { objectiveId: 'csrf_p1', tab: 'post', resourceType: 'document', method: 'POST', status: 200,
        mode: 'vulnerable', user: postUser, expectedTabCalls: 1, email: 'p1-observed@fixture.invalid' },
      { objectiveId: 'csrf_p2', tab: 'post', resourceType: 'fetch', method: 'POST', status: 200,
        mode: 'vulnerable', user: postUser, expectedTabCalls: 2, email: 'p2-observed@fixture.invalid' },
      { objectiveId: 'csrf_p3', tab: 'post', resourceType: 'document', method: 'POST', status: 403,
        mode: 'fixed', user: postUser, expectedTabCalls: 3, email: 'p3-blocked@fixture.invalid', defense: true },
    ];
    for (const user of [getUser, postUser]) {
      await identityRuntime.query(`INSERT INTO workshop_platform.user_modes(user_id,workshop_key,mode)
        VALUES($1,'csrf_workshop','vulnerable')`, [user.id]);
    }
    const sibling = await identity.createUser({
      username: 'csrf-browser-route-sibling', email: 'csrf-browser-route-sibling@fixture.invalid', passwordHash,
    });
    await identityRuntime.query(`INSERT INTO workshop_platform.user_modes(user_id,workshop_key,mode)
      VALUES($1,'csrf_workshop','vulnerable')`, [sibling.id]);
    let raceJudgeEntered;
    let releaseRaceJudge;
    if (!live) {
      raceUser = await identity.createUser({
        username: 'csrf-browser-route-reset-race', email: 'csrf-browser-route-reset-race@fixture.invalid', passwordHash,
      });
      await identityRuntime.query(`INSERT INTO workshop_platform.user_modes(user_id,workshop_key,mode)
        VALUES($1,'csrf_workshop','vulnerable')`, [raceUser.id]);
      let entered;
      let release;
      raceJudgeEntered = new Promise(resolve => { entered = resolve; });
      releaseRaceJudge = new Promise(resolve => { release = resolve; });
      raceUser.enterJudge = entered;
      raceUser.releaseJudge = release;
    }

    if (!live) {
      const { prepareJudgeInput } = require('../../server/agent-runtime/objectiveJudge');
      const deterministicJudge = async packet => {
        const prepared = prepareJudgeInput(packet);
        if (packet.execution.ownerKey === JSON.stringify(['CSRF', String(raceUser.id)])) {
          raceUser.enterJudge();
          await releaseRaceJudge;
        }
        return {
          family: packet.rubric.family, scenario: packet.rubric.scenario,
          objectiveId: packet.rubric.objectiveId, rubricVersion: packet.rubric.version,
          evidenceDigest: prepared.evidenceDigest, runId: packet.execution.runId,
          mode: packet.rubric.mode, verdict: 'pass',
          criteria: packet.rubric.criteria.map(criterion => ({
            id: criterion.id, satisfied: true, evidenceRefs: ['action', 'receipt'],
          })),
          explanation: 'Deterministic fixture accepted the server-observed browser effect.',
          provider: 'fixture', model: 'deterministic-route-proof', usage: null,
        };
      };
      const completionService = require('../../server/services/objectiveCompletionService').createObjectiveCompletionService({
        receipts: require('../../server/database/postgres/objectiveJudgmentRepository').createObjectiveJudgmentRepository(identityRuntime),
        progress, judge: deterministicJudge,
      });
      const graderModule = require('../../server/services/csrfObjectiveGrader');
      const originalFactory = graderModule.createCsrfObjectiveGrader;
      const grader = originalFactory({ postgres: true, completionService });
      graderModule.createCsrfObjectiveGrader = () => grader;
      restoreGrader = () => { graderModule.createCsrfObjectiveGrader = originalFactory; };
    }

    csrfRoutes = require('../../server/routes/csrfWorkshop');
    restoreGrader?.();
    restoreGrader = null;
    const identityAdapter = require('../../server/services/postgresIdentityAdapter').getPostgresIdentityAdapter();
    sessionManager = require('../../server/middleware/postgresSessionManager').createPostgresSessionManager(identityAdapter);
    const sessions = new Map();
    for (const user of [getUser, postUser, ...(raceUser ? [raceUser] : [])]) {
      sessions.set(user.id, await sessionManager.createSession(await identity.findCredentialById(user.id), {
        get: () => null, ip: '127.0.0.1',
      }));
    }
    for (const testCase of cases) testCase.session = sessions.get(testCase.user.id);

    const express = require('express');
    const app = express();
    app.use('/api/workshop/csrf/browser-attempt', require('../../server/middleware/csrfBrowserBody').csrfBrowserBody);
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));
    app.use(sessionManager.middleware());
    app.use('/api/workshop/csrf', csrfRoutes);
    server = await new Promise(resolve => {
      const listener = app.listen(0, '127.0.0.1', () => resolve(listener));
    });

    const base = `http://127.0.0.1:${server.address().port}/api/workshop/csrf`;
    const browserEndpoint = `${base}/browser-attempt`;
    const victimOrigin = require('../../server/services/csrfBrowserReceipt').VICTIM_ORIGIN;
    const first = cases[0];
    const unauthorized = await jsonRequest(browserEndpoint, {
      body: { tab: first.tab, objectiveId: first.objectiveId, html: browserPayload(first, victimOrigin) },
    });
    assert.equal(unauthorized.response.status, 401);
    assert.equal(unauthorized.body.error, 'Authentication required');
    assert.equal((await csrfRuntime.query(
      'SELECT count(*)::int AS n FROM csrf.victim_state WHERE session_key=$1', [`csrf_${first.user.id}`],
    )).rows[0].n, 0);
    assert.equal((await csrfRuntime.query(
      'SELECT count(*)::int AS n FROM csrf.tool_log WHERE user_key=$1', [String(first.user.id)],
    )).rows[0].n, 0);
    assert.equal((await identityRuntime.query(
      'SELECT count(*)::int AS n FROM workshop_platform.objective_judgments WHERE user_id=$1', [first.user.id],
    )).rows[0].n, 0);

    const awarded = new Map();
    for (const testCase of cases) {
      await identityRuntime.query(`UPDATE workshop_platform.user_modes SET mode=$3,updated_at=now()
        WHERE user_id=$1 AND workshop_key=$2`, [testCase.user.id, 'csrf_workshop', testCase.mode]);
      if (testCase.defense) {
        const toggled = await jsonRequest(`${base}/defense-toggle`, {
          token: testCase.session.token, body: { tab: testCase.tab, enabled: true },
        });
        assert.equal(toggled.response.status, 200, JSON.stringify(toggled.body));
        assert.equal(toggled.body.victimState.defenses.csrfToken, true);
        assert.equal(toggled.body.victimState.defenses.sameSite, 'Strict');
      }
      const stateBefore = (await csrfRuntime.query(
        'SELECT state_json FROM csrf.victim_state WHERE session_key=$1', [`csrf_${testCase.user.id}`],
      )).rows[0]?.state_json;
      const emailBefore = stateBefore?.[testCase.tab]?.victim?.profile?.email
        || require('../../server/services/csrfVictimSandbox').TABS[testCase.tab].victim.email;
      const attempt = await jsonRequest(browserEndpoint, {
        token: testCase.session.token,
        body: { tab: testCase.tab, objectiveId: testCase.objectiveId, html: browserPayload(testCase, victimOrigin) },
      });
      assert.equal(attempt.response.status, 200, `${testCase.objectiveId}: ${JSON.stringify(attempt.body)}`);
      assert.deepEqual(attempt.body.newlyCompleted, [testCase.objectiveId]);
      assert.equal(attempt.body.browser.method, testCase.method);
      assert.equal(attempt.body.browser.resourceType, testCase.resourceType);
      assert.equal(attempt.body.browser.responseStatus, testCase.status);
      assert.equal(attempt.body.browser.responseObserved, true);
      assert.equal(JSON.stringify(attempt.body).includes('browser_observed'), false,
        'private receipt must not cross HTTP');

      assert.equal(attempt.body.victimState.profile.email, testCase.defense ? emailBefore : testCase.email);
      const state = (await csrfRuntime.query(
        'SELECT state_json FROM csrf.victim_state WHERE session_key=$1', [`csrf_${testCase.user.id}`],
      )).rows[0]?.state_json;
      assert.ok(state, `${testCase.objectiveId} victim state must be persisted`);
      assert.equal(state[testCase.tab].victim.profile.email, attempt.body.victimState.profile.email);
      assert.equal((await csrfRuntime.query(
        'SELECT count(*)::int AS n FROM csrf.tool_log WHERE user_key=$1 AND exercise_id=$2',
        [String(testCase.user.id), testCase.tab],
      )).rows[0].n, testCase.expectedTabCalls);
      assert.equal((await csrfRuntime.query(
        'SELECT count(*)::int AS n FROM csrf.progress WHERE user_key=$1 AND objective_id=$2',
        [String(testCase.user.id), testCase.objectiveId],
      )).rows[0].n, 1);

      const judgment = (await identityRuntime.query(`SELECT objective_id,rubric_version,verdict,disposition,run_id
        FROM workshop_platform.objective_judgments WHERE user_id=$1 AND objective_id=$2`,
      [testCase.user.id, testCase.objectiveId])).rows[0];
      assert.ok(judgment);
      assert.deepEqual({ objective_id: judgment.objective_id, rubric_version: judgment.rubric_version,
        verdict: judgment.verdict, disposition: judgment.disposition }, {
        objective_id: testCase.objectiveId, rubric_version: 'csrf-observed-v8', verdict: 'pass', disposition: 'awarded',
      });
      assert.match(judgment.run_id, /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
      awarded.set(testCase.objectiveId, judgment.run_id);
      assert.equal((await identityRuntime.query(`SELECT count(*)::int AS n FROM workshop_platform.completions
        WHERE user_id=$1 AND workshop_key='csrf_workshop' AND objective_id=$2`,
      [testCase.user.id, testCase.objectiveId])).rows[0].n, 1);

      if (live && !testCase.defense) {
        const ownerKey = JSON.stringify(['CSRF', String(testCase.user.id)]);
        const events = (await identityRuntime.query(`SELECT node,event_type,metadata
          FROM graph_runtime.events WHERE run_id=$1 AND owner_key=$2 ORDER BY sequence`,
        [judgment.run_id, ownerKey])).rows;
        assert.ok(events.some(event => event.node === 'classify' && event.event_type === 'decision'
          && event.metadata?.decisionSource === 'model' && event.metadata?.tool === 'change_email'),
        `${testCase.objectiveId} credit must be tied to the persisted model-selected change_email decision`);
      }
    }

    assert.equal((await identityRuntime.query(
      'SELECT count(*)::int AS n FROM workshop_platform.objective_judgments WHERE user_id=$1', [sibling.id],
    )).rows[0].n, 0);
    assert.equal((await identityRuntime.query(
      'SELECT count(*)::int AS n FROM workshop_platform.completions WHERE user_id=$1', [sibling.id],
    )).rows[0].n, 0);
    assert.equal((await csrfRuntime.query(
      'SELECT count(*)::int AS n FROM csrf.victim_state WHERE session_key=$1', [`csrf_${sibling.id}`],
    )).rows[0].n, 0);

    if (!live) {
      const raceCase = { objectiveId: 'csrf_p1', tab: 'post', resourceType: 'document',
        email: 'reset-race-effect@fixture.invalid' };
      const raceOwnerKey = JSON.stringify(['CSRF', String(raceUser.id)]);
      const raceAttempt = jsonRequest(browserEndpoint, {
        token: sessions.get(raceUser.id).token,
        body: { tab: raceCase.tab, objectiveId: raceCase.objectiveId, html: browserPayload(raceCase, victimOrigin) },
      });
      await raceJudgeEntered;
      const generationBeforeReset = Number((await identityRuntime.query(
        'SELECT generation FROM graph_runtime.owners WHERE owner_key=$1', [raceOwnerKey],
      )).rows[0].generation);
      const persistedBeforeReset = (await csrfRuntime.query(
        'SELECT state_json FROM csrf.victim_state WHERE session_key=$1', [`csrf_${raceUser.id}`],
      )).rows[0]?.state_json;
      assert.equal(persistedBeforeReset.post.victim.profile.email, raceCase.email,
        'the actual browser effect must be durable before the Judge barrier opens');

      const raceReset = jsonRequest(`${base}/progress/reset`, {
        token: sessions.get(raceUser.id).token, body: {},
      });
      const deadline = Date.now() + 5000;
      while (true) {
        const generation = Number((await identityRuntime.query(
          'SELECT generation FROM graph_runtime.owners WHERE owner_key=$1', [raceOwnerKey],
        )).rows[0].generation);
        if (generation === generationBeforeReset + 1) break;
        if (Date.now() >= deadline) throw new Error('reset did not invalidate the pending browser run');
        await new Promise(resolve => setTimeout(resolve, 10));
      }
      assert.equal((await csrfRuntime.query(
        'SELECT count(*)::int AS n FROM csrf.victim_state WHERE session_key=$1', [`csrf_${raceUser.id}`],
      )).rows[0].n, 1, 'reset must wait for the admitted run to drain before clearing state');
      raceUser.releaseJudge();
      const [staleAttempt, completedReset] = await Promise.all([raceAttempt, raceReset]);
      assert.equal(staleAttempt.response.status, 409);
      assert.equal(staleAttempt.body.error, 'Request invalidated by reset');
      assert.equal(completedReset.response.status, 200, JSON.stringify(completedReset.body));
      assert.equal(completedReset.body.success, true);
      assert.equal((await identityRuntime.query(`SELECT count(*)::int AS n FROM workshop_platform.completions
        WHERE user_id=$1 AND workshop_key='csrf_workshop' AND objective_id='csrf_p1'`, [raceUser.id])).rows[0].n, 0);
      assert.equal((await csrfRuntime.query(
        'SELECT count(*)::int AS n FROM csrf.victim_state WHERE session_key=$1', [`csrf_${raceUser.id}`],
      )).rows[0].n, 0);
      assert.equal((await csrfRuntime.query(
        'SELECT count(*)::int AS n FROM csrf.progress WHERE user_key=$1', [String(raceUser.id)],
      )).rows[0].n, 0);
      assert.equal((await csrfRuntime.query(
        'SELECT count(*)::int AS n FROM csrf.tool_log WHERE user_key=$1', [String(raceUser.id)],
      )).rows[0].n, 0);
      const pending = (await identityRuntime.query(`SELECT run_id,verdict,disposition
        FROM workshop_platform.objective_judgments WHERE user_id=$1 AND objective_id='csrf_p1'`,
      [raceUser.id])).rows;
      assert.equal(pending.length, 1);
      assert.equal(pending[0].verdict, null);
      assert.equal(pending[0].disposition, 'pending');
      assert.equal((await identityRuntime.query(`SELECT status FROM graph_runtime.runs
        WHERE run_id=$1 AND owner_key=$2`, [pending[0].run_id, raceOwnerKey])).rows[0].status, 'cancelled');
    }

    // Authenticated reset proves generation advancement and durable cleanup;
    // it does not claim cancellation of a concurrent in-flight browser.
    const resetCase = cases.find(testCase => testCase.objectiveId === 'csrf_p1');
    const ownerKey = JSON.stringify(['CSRF', String(resetCase.user.id)]);
    const graphBefore = Number((await identityRuntime.query(
      'SELECT generation FROM graph_runtime.owners WHERE owner_key=$1', [ownerKey],
    )).rows[0].generation);
    const platformBefore = await progress.getGeneration(resetCase.user.id, 'csrf_workshop');
    const reset = await jsonRequest(`${base}/progress/reset`, { token: resetCase.session.token, body: {} });
    assert.equal(reset.response.status, 200, JSON.stringify(reset.body));
    assert.equal(reset.body.success, true);
    assert.equal(Number((await identityRuntime.query(
      'SELECT generation FROM graph_runtime.owners WHERE owner_key=$1', [ownerKey],
    )).rows[0].generation), graphBefore + 1);
    assert.equal(await progress.getGeneration(resetCase.user.id, 'csrf_workshop'), platformBefore + 1);
    assert.equal((await csrfRuntime.query(
      'SELECT count(*)::int AS n FROM csrf.victim_state WHERE session_key=$1', [`csrf_${resetCase.user.id}`],
    )).rows[0].n, 0);
    assert.equal((await csrfRuntime.query(
      'SELECT count(*)::int AS n FROM csrf.tool_log WHERE user_key=$1', [String(resetCase.user.id)],
    )).rows[0].n, 0);
    assert.equal((await csrfRuntime.query(
      'SELECT count(*)::int AS n FROM csrf.progress WHERE user_key=$1', [String(resetCase.user.id)],
    )).rows[0].n, 0);
    assert.equal((await identityRuntime.query(`SELECT count(*)::int AS n FROM workshop_platform.completions
      WHERE user_id=$1 AND workshop_key='csrf_workshop'`, [resetCase.user.id])).rows[0].n, 0);
    assert.equal((await identityRuntime.query(`SELECT count(*)::int AS n FROM workshop_platform.objective_judgments
      WHERE user_id=$1 AND objective_id='csrf_p1' AND run_id=$2`,
    [resetCase.user.id, awarded.get('csrf_p1')])).rows[0].n, 1, 'reset retains the historical judgment receipt');

    t.diagnostic(live
      ? 'All five objectives used actual browser/native stores/Judge; successful effects used persisted model selections, while fixed-mode blocks occurred before model dispatch.'
      : 'All five objectives used actual browser/auth/native stores; actor and Judge decisions were deterministic fixtures.');
  } finally {
    const cleanupFailures = [];
    const capture = async operation => {
      try { await operation(); } catch (error) { cleanupFailures.push(error); }
    };
    raceUser?.releaseJudge?.();
    if (restoreGrader) await capture(async () => restoreGrader());
    if (server) await capture(() => new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve())));
    if (csrfRoutes) await capture(() => csrfRoutes.closeBrowser());
    if (sessionManager) await capture(async () => sessionManager.stopCleanupTask());
    await capture(() => require('../../server/database/postgres').closePostgresPools());
    const poolResults = await Promise.allSettled(
      [identityRuntime, identityMigration, csrfRuntime, csrfMigration].map(pool => pool.end()),
    );
    cleanupFailures.push(...poolResults.filter(result => result.status === 'rejected').map(result => result.reason));
    Module._load = originalLoad;
    if (cleanupFailures.length) throw new AggregateError(cleanupFailures, 'CSRF browser route test cleanup failed');
  }
});
