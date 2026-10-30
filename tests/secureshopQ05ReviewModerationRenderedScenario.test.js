'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const scenario = require('./fixtures/secureshopQ05ReviewModerationRenderedScenario');

const tools = ['moderate_pending', 'approve', 'reject'].map(tool => ({ agent: 'review-moderator', tool }));
const scope = { launchId: '10000000-0000-4000-8000-000000000001',
  scenarioId: '20000000-0000-4000-8000-000000000001', generation: 1,
  platformOwnerId: 41, platformSessionId: 71 };

function ackFixture(change = value => value, absent = false) {
  const input = { workspace: '/repo', env: { SECURESHOP_Q05_REVIEW_MODERATION_BROWSER_SHA256: 'a'.repeat(64) },
    pid: 4321, profile: '/repo/profile', executablePath: '/repo/chrome', recordPath: '/repo/birth.json', ackPath: '/repo/ack.json' };
  const events = [], retained = new Map(); let clock = 0;
  const fail = code => Object.assign(Error(code), { code });
  const files = {
    promises: {
      async writeFile(name, bytes, options) { assert.deepEqual(options, { flag: 'wx', mode: 0o600 });
        if (retained.has(name)) throw fail('EEXIST'); retained.set(name, bytes); events.push('write'); },
      async link(from, to) { if (retained.has(to)) throw fail('EEXIST'); retained.set(to, retained.get(from)); events.push('publish'); },
      async unlink(name) { retained.delete(name); events.push('unlink-staging'); },
    },
    lstatSync(name) { assert.equal(name, input.ackPath); if (absent) throw fail('ENOENT');
      assert.ok(retained.has(input.recordPath)); events.push('read-ack');
      return { isFile: () => true, isSymbolicLink: () => false, uid: process.getuid(), mode: 0o600, size: 512 }; },
    readFileSync() { return JSON.stringify(change({ schemaVersion: 1,
      recordSha256: require('node:crypto').createHash('sha256').update(retained.get(input.recordPath)).digest('hex'),
      parentPid: process.pid, browserPid: input.pid, profile: input.profile })); },
  };
  const dependencies = { files, now: () => clock, sleep: async ms => { assert.equal(ms, 25); clock += ms; },
    capture: values => { assert.equal(values.kind, 'q05_review_moderation_browser'); events.push('inspect');
      return { schemaVersion: 2, processes: [{ pid: input.pid }] }; } };
  return { input, dependencies, retained, events, elapsed: () => clock };
}

test('exact ACK is read only after exclusive atomic birth publication', async () => {
  const f = ackFixture(); await scenario.acknowledgeRecord(f.input, f.dependencies);
  assert.deepEqual(f.events, ['inspect', 'write', 'publish', 'unlink-staging', 'read-ack']);
  assert.deepEqual([...f.retained.keys()], [f.input.recordPath]);
});

for (const key of ['recordSha256', 'parentPid', 'browserPid', 'profile'])
  test(`ACK rejects mismatched ${key} and preserves birth evidence`, async () => {
    const f = ackFixture(value => ({ ...value, [key]: 'foreign' }));
    await assert.rejects(scenario.acknowledgeRecord(f.input, f.dependencies));
    assert.ok(f.retained.has(f.input.recordPath)); assert.equal(f.elapsed(), 0);
  });

test('missing ACK expires at the fixed deadline without losing birth evidence', async () => {
  const f = ackFixture(undefined, true);
  await assert.rejects(scenario.acknowledgeRecord(f.input, f.dependencies), /ACK unavailable/);
  assert.equal(f.elapsed(), 15000); assert.ok(f.retained.has(f.input.recordPath));
});

test('existing birth record is never overwritten', async () => {
  const f = ackFixture(); f.retained.set(f.input.recordPath, 'prior');
  await assert.rejects(scenario.acknowledgeRecord(f.input, f.dependencies), { code: 'EEXIST' });
  assert.equal(f.retained.get(f.input.recordPath), 'prior'); assert.ok(!f.events.includes('read-ack'));
});

test('ACK failure closes browser before propagation and retains cleanup failure', async () => {
  const primary = Error('bad ACK'), cleanup = Error('close failed');
  let closed = 0;
  const admission = { acknowledgeBrowser: async () => { throw primary; } };
  await assert.rejects(scenario.acknowledgeOrClose(admission, { close: async () => { closed++; } }, '/profile'), error => error === primary);
  assert.equal(closed, 1);
  await assert.rejects(scenario.acknowledgeOrClose(admission, { close: async () => { throw cleanup; } }, '/profile'),
    error => error instanceof AggregateError && error.errors[0] === primary && error.errors[1] === cleanup);
  await scenario.acknowledgeOrClose({ acknowledgeBrowser: async () => {} }, { close: async () => { assert.fail('successful ACK must not close'); } }, '/profile');
});
test('Q05 no-sandbox admission requires its own exact inherited grant', () => {
  const expected = { launcherPid: 42, workerPid: 43, workspace: '/repo', evidencePath: '/repo/run/q05.json',
    buildSha256: 'a'.repeat(64), snapshotSha256: 'b'.repeat(64), chromium: '/repo/chrome', chromiumSha256: 'c'.repeat(64) };
  const grant = { version: 1, cohort: 'q05-review-moderation-browser', nonce: 'd'.repeat(64), outerSandbox: 'repository-only', ...expected };
  scenario.validateBrowserGrant(grant, expected);
  for (const [key, value] of Object.entries({ cohort: 'merchant-mail-actions-browser', workerPid: 44,
    launcherPid: 44, snapshotSha256: 'e'.repeat(64), outerSandbox: 'none', nonce: '' }))
    assert.throws(() => scenario.validateBrowserGrant({ ...grant, [key]: value }, expected));
  assert.throws(() => scenario.validateBrowserGrant({ ...grant, extra: true }, expected));
});

test('Q05 browser admission rejects unapproved no-sandbox before filesystem or browser work', async () => {
  await assert.rejects(scenario.admitBrowser({ [scenario.SELECTOR]: '1' }, {}));
  await assert.rejects(scenario.admitBrowser({ [scenario.SELECTOR]: '1', SECURESHOP_Q05_REVIEW_MODERATION_TEST_NO_SANDBOX: '1',
    SECURESHOP_REVIEW_INJECTION_BROWSER_NATIVE: '1' }, {}));
});
function evidence() {
  const requestId = '30000000-0000-4000-8000-000000000001';
  const runId = '40000000-0000-4000-8000-000000000001';
  const persona = { id: 7, role: 'merchant' }, personaSession = {
    sessionId: '50000000-0000-4000-8000-000000000001', authorityVersion: '1' };
  const authority = { scope, persona, session: personaSession };
  const body = { request_id: requestId, limit: 100, recoveryScopeKey: 'a'.repeat(64) };
  const before = { id: 19, product_id: 8, body: 'Useful product', status: 'pending', moderator_kind: null, moderator_notes: null };
  const siblingScope = { ...scope, platformOwnerId: 42 };
  const ownerTargetId = '60000000-0000-4000-8000-000000000001';
  const siblingTargetId = '70000000-0000-4000-8000-000000000001';
  const ownerReviewTargetId = '80000000-0000-4000-8000-000000000001';
  const siblingReviewTargetId = '90000000-0000-4000-8000-000000000001';
  const ownerReviewBirth = { targetId: ownerReviewTargetId, ...scope };
  const siblingReviewBirth = { targetId: siblingReviewTargetId, ...siblingScope };
  const ownerSceneMapping = { scene_id: 'a0000000-0000-4000-8000-000000000001',
    product_target_id: ownerTargetId, review_target_id: ownerReviewTargetId,
    original_platform_owner_id: scope.platformOwnerId };
  const siblingSceneMapping = { scene_id: 'b0000000-0000-4000-8000-000000000001',
    product_target_id: siblingTargetId, review_target_id: siblingReviewTargetId,
    original_platform_owner_id: siblingScope.platformOwnerId };
  const ownerProductBefore = { target_id: ownerTargetId, product_id: 8, retailer_id: 7, status: 'active' };
  const siblingProductBefore = { target_id: siblingTargetId, product_id: 8, retailer_id: 9, status: 'active' };
  const objectives = ['ss_loop_observation', 'ss_content_persist', 'ss_content_followed'];
  const assessmentWitness = { runId, rowCountAtLeast: 3, truncated: false,
    rows: objectives.map((objectiveId, index) => ({
      evaluationId: `c0000000-0000-4000-8000-00000000000${index + 1}`,
      objectiveId, verdict: 'inconclusive', disposition: 'hidden', resultDigest: 'b'.repeat(64),
      resultVerdict: 'inconclusive', errorCode: null, modelEvaluated: null,
      providerPresent: false, modelPresent: false, usagePresent: false,
      judgeObservationsState: 'json_null', judgeResultPresent: false,
      principalBindingMatches: true, ownerScopeMatches: true, siblingScopeMatches: false,
    })),
    catalog: objectives.map(objectiveId => ({ objectiveId,
      catalogActive: true, effectiveEnabled: false })) };
  return { scope, siblingScope, ownerTargetId, siblingTargetId,
    ownerReviewTargetId, siblingReviewTargetId, ownerReviewBirth, siblingReviewBirth,
    ownerSceneMapping, siblingSceneMapping, siblingSceneMappingAfter: { ...siblingSceneMapping },
    siblingPersonaId: 9,
    ownerProductBefore, siblingProductBefore, siblingProductAfter: { ...siblingProductBefore },
    persona, personaSession, requestId, reviewId: 19,
    post: { method: 'POST', path: scenario.POST, status: 200, body, authority },
    physicalPost: { method: 'POST', path: scenario.POST, body, mainFrame: true },
    readback: { method: 'GET', path: `/api/secureshop/merchant/reviews/moderation/${requestId}`, status: 200, authority,
      value: { state: 'completed', requestId, recoveryScopeKey: body.recoveryScopeKey,
        result: { processed: 1, decisions: [{ review_id: 19, applied_decision: 'approve' }] } } },
    beforeRows: [before], afterRows: [{ ...before, status: 'approved', moderator_kind: 'auto' }],
    turn: { request_id: requestId, status: 'completed', result_json: { taskMetadata: { reviewBatch: { runId } } } },
    effects: ['read', 'approve'].map(effect_key => ({ run_id: runId, status: 'completed', effect_key })),
    audits: [{ launch_id: scope.launchId, scenario_id: scope.scenarioId,
      generation: scope.generation, original_platform_owner_id: scope.platformOwnerId,
      original_platform_session_id: scope.platformSessionId,
      params_json: JSON.stringify({ receipt: { runId, reviewId: 19, applied: true,
        resultStatus: 'approved', scope: ownerReviewBirth,
        actor: { ...persona, personaSessionId: personaSession.sessionId } } }) }],
    reset: { resetId: 'reset' }, staleBefore: [], staleAfter: [],
    siblingBefore: [{ id: 20, product_id: 8 }], siblingAfter: [{ id: 20, product_id: 8 }],
    creditBefore: { judgments: 0, completions: 0, contributions: 0 },
    creditAfter: { judgments: 3, completions: 0, contributions: 0 }, assessmentWitness,
    staleObservation: { disabled: false, responses: [{ method: 'GET', path: '/api/secureshop/merchant/reviews/moderation/stale', status: 401 }],
      postsBefore: 1, postsAfter: 1, providerCallsBefore: 3, providerCallsAfter: 3 } };
}
test('Q05 exclusive selection cannot alias V17 or accept an implicit value', () => {
  assert.equal(scenario.selector({}), false);
  assert.equal(scenario.selector({ [scenario.SELECTOR]: '1' }), true);
  assert.throws(() => scenario.selector({ [scenario.SELECTOR]: 'true' }));
  assert.throws(() => scenario.selector({ [scenario.SELECTOR]: '1', SECURESHOP_REVIEW_INJECTION_BROWSER_NATIVE: '1' }));
  assert.throws(() => scenario.selector({ [scenario.SELECTOR]: '1', SECURESHOP_STANDALONE_ROLE_CHOICES_NATIVE: '1' }));
});

test('controlled provider is honestly mocked and requires the exact observed pending review', async () => {
  const provider = scenario.createControlledProvider();
  await assert.rejects(provider.chat({ tools, messages: [] }));
  provider.arm({ reviewId: 19, body: 'This product works.' });
  const read = await provider.chat({ tools, messages: [] });
  assert.equal(read.mocked, true); assert.equal(read.provider, 'mock');
  assert.deepEqual(read.tool_uses[0].args, { limit: 1 });
  const approve = await provider.chat({ tools, messages: [{ content: JSON.stringify({ ok: true,
    count: 1, reviews: [{ id: 19, body: 'This product works.', status: 'pending' }] }) }] });
  assert.equal(approve.tool_uses[0].name, 'review-moderator.approve');
  assert.deepEqual(approve.tool_uses[0].args, { review_id: 19 });
  const final = await provider.finalResponse();
  assert.equal(final.mocked, true);
  assert.equal(final.responseMode, 'structured_final');
  assert.equal(final.stop_reason, 'end_turn');
  assert.ok(final.text.trim());
  assert.deepEqual(provider.counts(), { controlledProviderCalls: 3, actualModelCalls: 0, judgeCalls: 0, canonicalCredit: 0 });
  await assert.rejects(provider.chat({ tools, messages: [] }));
});

test('Q05 private assessment witness binds real run/scope and redacts packets and result text', async () => {
  const runId = '40000000-0000-4000-8000-000000000001';
  const siblingScope = { ...scope, platformOwnerId: 42 };
  const rows = ['ss_loop_observation', 'ss_content_persist', 'ss_content_followed'].map((objective_id, index) => ({
    evaluation_id: `50000000-0000-4000-8000-00000000000${index + 1}`, run_id: runId,
    objective_id, verdict: 'inconclusive', disposition: 'hidden', result_digest: 'a'.repeat(64),
    result_verdict: 'inconclusive', error_code: null, model_evaluated: null,
    provider_present: false, model_present: false, usage_present: false,
    judge_observations_state: 'json_null', judge_result_present: false, execution_scope: scope,
    principal_binding_matches: true,
    packet: 'SECRET PACKET', result_json: { text: 'SECRET RESULT' },
  }));
  let reads = 0;
  const pool = { async query(sql, args) {
    reads += 1;
    if (reads === 1) {
      assert.match(sql, /FROM secureshop_auth\.assessment_judgments j/);
      assert.match(sql, /LEFT JOIN secureshop_auth\.execution_authority_state e ON e\.session_id=\$2/);
      assert.match(sql, /WHERE j\.run_id=\$1/);
      assert.match(sql, /LIMIT 17/);
      assert.deepEqual(args, [runId, scope.platformSessionId, scope.platformOwnerId]); return { rows };
    }
    assert.match(sql, /FROM secureshop_auth\.assessment_objectives o/);
    assert.deepEqual(args, [scope.platformSessionId,
      ['ss_loop_observation', 'ss_content_persist', 'ss_content_followed']]);
    return { rows: ['ss_content_followed', 'ss_content_persist', 'ss_loop_observation'].map(objective_id =>
      ({ objective_id, catalog_active: true, effective_enabled: false })) };
  } };
  const witness = await scenario.readAssessmentAttemptWitness(pool, { runId, scope, siblingScope });
  assert.equal(witness.rows.length, 3); assert.equal(witness.truncated, false);
  assert.equal(witness.catalog.length, 3);
  assert.deepEqual(witness.rows.map(row => row.objectiveId),
    ['ss_loop_observation', 'ss_content_persist', 'ss_content_followed']);
  assert.ok(witness.rows.every(row => row.principalBindingMatches && row.ownerScopeMatches && !row.siblingScopeMatches
    && row.verdict === 'inconclusive' && row.disposition === 'hidden' && row.modelEvaluated === null
    && row.judgeObservationsState === 'json_null' && !row.judgeResultPresent));
  assert.ok(!JSON.stringify(witness).includes('SECRET'));
  const foreign = scenario.redactAssessmentAttemptRows([{ ...rows[0], objective_id: 'untrusted',
    error_code: 'some arbitrary and private message', execution_scope: siblingScope }],
  { runId, scope, siblingScope });
  assert.equal(foreign.rows[0].objectiveId, 'unexpected'); assert.equal(foreign.rows[0].errorCode, 'other');
  assert.equal(foreign.rows[0].ownerScopeMatches, false); assert.equal(foreign.rows[0].siblingScopeMatches, true);
  assert.throws(() => scenario.redactAssessmentAttemptRows([{ ...rows[0], run_id: siblingScope.launchId }],
    { runId, scope, siblingScope }));
  const status = { evidence: { realEffect: true,
    turn: { result_json: { taskMetadata: { reviewBatch: { runId } } } } } };
  const before = { judgments: 0, completions: 0, contributions: 0 };
  const after = { judgments: 3, completions: 0, contributions: 0 };
  scenario.assertOnlyRunOwnedHiddenAssessments(status, before, after, witness);
  assert.deepEqual(status.evidence, { realEffect: true, turn: status.evidence.turn, creditBefore: before,
    creditAfter: after, assessmentWitness: witness });
});

test('Q05 permits colliding target-local product IDs only with independent owned composite rows', async () => {
  const ownerId = '60000000-0000-4000-8000-000000000001';
  const siblingId = '70000000-0000-4000-8000-000000000001';
  const queries = [];
  const reviewPool = { async query(sql, values) {
    assert.match(sql, /WHERE target_id=\$1 AND product_id=\$2/);
    queries.push(values);
    return { rows: [{ target_id: values[0], product_id: values[1],
      retailer_id: values[0] === ownerId ? 7 : 9, status: 'active' }] };
  } };
  const seeded = { ownerScope: scope,
    siblingScope: { ...scope, platformOwnerId: scope.platformOwnerId + 1 },
    ownerProductTarget: { targetId: ownerId }, siblingProductTarget: { targetId: siblingId },
    ownerPersonaId: 7, siblingPersonaId: 9, product: { productId: 8 },
    siblingProduct: { productId: 8 }, reviewPool };
  const rows = await scenario.assertSiblingSeed(seeded);
  assert.equal(rows.ownerProductRow.product_id, rows.siblingProductRow.product_id);
  assert.notEqual(rows.ownerProductRow.target_id, rows.siblingProductRow.target_id);
  assert.deepEqual(queries, [[ownerId, 8], [siblingId, 8]]);
  for (const changed of [
    { siblingProduct: null },
    { siblingScope: { ...seeded.siblingScope, platformOwnerId: scope.platformOwnerId } },
    { siblingProductTarget: seeded.ownerProductTarget },
    { siblingPersonaId: seeded.ownerPersonaId },
    { reviewPool: { async query() { return { rows: [] }; } } },
    { reviewPool: { async query(_sql, values) { return { rows: [{ target_id: values[0],
      product_id: values[1], retailer_id: 7, status: 'active' }] }; } } },
  ]) await assert.rejects(scenario.assertSiblingSeed({ ...seeded, ...changed }));
});

test('Q05 retained sibling seed binds both product target and scene on reuse', () => {
  const seeded = { targetId: '70000000-0000-4000-8000-000000000001',
    scene: { sceneId: '71000000-0000-4000-8000-000000000001' } };
  assert.doesNotThrow(() => scenario.assertReusedProductScene({ ...seeded, scene: { ...seeded.scene } }, seeded));
  assert.throws(() => scenario.assertReusedProductScene({ ...seeded,
    targetId: '70000000-0000-4000-8000-000000000002' }, seeded));
  assert.throws(() => scenario.assertReusedProductScene({ ...seeded,
    scene: { sceneId: '71000000-0000-4000-8000-000000000002' } }, seeded));
});

test('Q05 canonically prepares and seeds only the authenticated browser launch, not the logged-out preseed', async () => {
  const browserScope = { ...scope, launchId: '80000000-0000-4000-8000-000000000001' };
  const persona = { id: 7, role: 'merchant' };
  const personaSession = { sessionId: 'browser-session', authorityVersion: '1' };
  const productTarget = { ...browserScope, targetId: '90000000-0000-4000-8000-000000000001',
    scene: { sceneId: 'a0000000-0000-4000-8000-000000000001' } };
  const reviewTarget = { ...browserScope, targetId: 'b0000000-0000-4000-8000-000000000001' };
  const mapping = { scene_id: productTarget.scene.sceneId, product_target_id: productTarget.targetId,
    review_target_id: reviewTarget.targetId, original_platform_owner_id: browserScope.platformOwnerId };
  const calls = [];
  const reviewPool = { async query(sql, values) {
    calls.push('mapping'); assert.match(sql, /FROM secureshop_review\.scene_review_targets/);
    assert.deepEqual(values, [mapping.scene_id, mapping.product_target_id, mapping.review_target_id]);
    return { rows: [mapping] };
  } };
  const composition = {
    catalog: {
      async prepareTarget(input) {
        calls.push('prepare'); assert.deepEqual(input, { scope: browserScope, persona, personaSession });
        return productTarget;
      },
      async createMerchantProduct(input) {
        calls.push('create'); assert.deepEqual(input.scope, browserScope);
        assert.deepEqual(input.persona, persona); assert.deepEqual(input.personaSession, personaSession);
        assert.ok(input.listing.name.includes('browser-owned')); return { productId: 1 };
      },
    },
    runtime: { application: {
      async prepareScene(input) {
        calls.push('review'); assert.deepEqual(input, { scope: browserScope, persona, personaSession });
        return reviewTarget;
      },
      async resolveExistingTarget(selected) {
        calls.push('read'); assert.deepEqual(selected, browserScope); return reviewTarget;
      },
    } },
  };
  assert.deepEqual(await scenario.prepareBrowserOwnedProduct({ composition,
    scope: browserScope, persona, personaSession, reviewPool }),
  { productTarget, reviewTarget, product: { productId: 1 }, mapping });
  assert.deepEqual(calls, ['prepare', 'create', 'review', 'read', 'mapping']);
  const wrongTarget = { ...composition, runtime: { application: {
    ...composition.runtime.application,
    async resolveExistingTarget() { return { targetId: scope.scenarioId }; },
  } } };
  await assert.rejects(scenario.prepareBrowserOwnedProduct({ composition: wrongTarget,
    scope: browserScope, persona, personaSession, reviewPool }));
  assert.deepEqual(calls, ['prepare', 'create', 'review', 'read', 'mapping',
    'prepare', 'create', 'review']);
  const missing = { ...composition, catalog: { ...composition.catalog,
    async prepareTarget() { throw Error('PRODUCT_TARGET_UNAVAILABLE'); } } };
  await assert.rejects(scenario.prepareBrowserOwnedProduct({ composition: missing,
    scope: browserScope, persona, personaSession, reviewPool }), /PRODUCT_TARGET_UNAVAILABLE/);
  const wrongMapping = { async query() { return { rows: [{ ...mapping,
    product_target_id: reviewTarget.targetId }] }; } };
  await assert.rejects(scenario.prepareBrowserOwnedProduct({ composition,
    scope: browserScope, persona, personaSession, reviewPool: wrongMapping }));
});

test('failed Q05 setup records zero measured controlled calls, not the planned three', () => {
  const provider = scenario.createControlledProvider(), failed = { passed: false };
  scenario.recordControlledCounts(failed, provider);
  assert.equal(failed.controlledProviderCalls, 0);
  assert.equal(failed.controlledActorCalls, 0);
  assert.equal(failed.actualModelCalls, 0);
  assert.equal(failed.judgeCalls, 0);
  assert.equal(failed.canonicalCredit, 0);
  assert.throws(() => scenario.assertReceipt(failed));
});

test('controlled selection rejects foreign or changed observations', async () => {
  for (const change of [{ id: 20 }, { body: 'Changed text' }, { status: 'approved' }]) {
    const provider = scenario.createControlledProvider(); provider.arm({ reviewId: 19, body: 'Original' });
    await provider.chat({ tools, messages: [] });
    await assert.rejects(provider.chat({ tools, messages: [{ content: JSON.stringify({ ok: true, count: 1,
      reviews: [{ id: 19, body: 'Original', status: 'pending', ...change }] }) }] }));
  }
});

test('response observer records route authority after production middleware and never submits', () => {
  const responses = [];
  const request = { method: 'POST', path: '/merchant/reviews/moderate-all', query: {}, body: { limit: 100 } };
  let sent;
  const response = { statusCode: 200, json(value) { sent = value; } };
  scenario.observeResponse(request, response, responses);
  request.ssLaunch = scope; request.ssUser = { id: 7, role: 'merchant' };
  request.ssPersonaSession = { sessionId: 'session' };
  response.json({ ok: true });
  assert.deepEqual(sent, { ok: true }); assert.equal(responses.length, 1);
  assert.equal(responses[0].authority.persona.id, 7);
  assert.equal(responses[0].path, scenario.POST);
});

test('physical refreshed credentials are checked by live launch and persona authority, not old token bytes', async () => {
  const persona = { id: 7, role: 'merchant' };
  const personaSession = { sessionId: 'owned-session', authorityVersion: '1' };
  const seen = [];
  const composition = { launches: { async resolveCapability(launch) {
    seen.push(['launch', launch]);
    assert.equal(launch, 'refreshed-launch');
    return scope;
  } }, personaAuth: { async authenticateBoundToken(input) {
    seen.push(['persona', input.token]);
    assert.deepEqual(input.scope, scope);
    assert.equal(input.token, 'refreshed-persona');
    return { user: persona, ...personaSession };
  } } };
  const input = { headers: { authorization: 'Bearer refreshed-persona',
    'x-owasp-ai-goat-secureshop-launch': 'refreshed-launch' }, composition, scope,
  persona, personaSession };
  await scenario.assertPhysicalAuthority(input);
  assert.deepEqual(seen, [['launch', 'refreshed-launch'], ['persona', 'refreshed-persona']]);
  await assert.rejects(scenario.assertPhysicalAuthority({ ...input,
    headers: { ...input.headers, authorization: 'Bearer wrong' } }));
  await assert.rejects(scenario.assertPhysicalAuthority({ ...input,
    headers: { ...input.headers, authorization: 'Bearer refreshed-persona extra' } }));
  const wrongScope = { ...composition, launches: { async resolveCapability() {
    return { ...scope, generation: 2 };
  } } };
  await assert.rejects(scenario.assertPhysicalAuthority({ ...input, composition: wrongScope }));
  const wrongSession = { ...composition, personaAuth: { async authenticateBoundToken() {
    return { user: persona, ...personaSession, authorityVersion: '2' };
  } } };
  await assert.rejects(scenario.assertPhysicalAuthority({ ...input, composition: wrongSession }));
  const rejected = { ...composition, personaAuth: { async authenticateBoundToken() {
    throw Error('private refreshed-persona credential');
  } } };
  await assert.rejects(scenario.assertPhysicalAuthority({ ...input, composition: rejected }), error => {
    assert.equal(error.code, 'Q05_PHYSICAL_PERSONA_UNAVAILABLE');
    assert.equal(error.message.includes('refreshed-persona'), false);
    return true;
  });
});

test('receipt rejects any actual-model, Judge or credit claim and incomplete cleanup', () => {
  const receipt = { ...Object.fromEntries(scenario.FLAGS.map(key => [key, true])),
    version: 3, scope: scenario.SCOPE, actorCalls: 0, actualModelCalls: 0, judgeCalls: 0,
    canonicalCredit: 0, controlledActorCalls: 3, controlledProviderCalls: 3,
    errors: [], cleanupErrors: [], evidence: evidence() };
  scenario.assertReceipt(receipt);
  for (const key of ['actorCalls', 'actualModelCalls', 'judgeCalls', 'canonicalCredit'])
    assert.throws(() => scenario.assertReceipt({ ...receipt, [key]: 1 }));
  assert.throws(() => scenario.assertReceipt({ ...receipt, fixtureCleaned: false }));
  assert.throws(() => scenario.assertReceipt({ ...receipt, staleAuthorityNoEffect: false }));
  assert.throws(() => scenario.assertReceipt({ ...receipt, controlledProviderCalls: 2 }));
  assert.throws(() => scenario.assertReceipt({ ...receipt, version: 2 }));
});

for (const [label, mutate] of Object.entries({
  'missing physical click': e => { e.physicalPost.mainFrame = false; },
  'foreign session': e => { e.post.authority = { ...e.post.authority, session: { sessionId: 'foreign' } }; },
  'different GET request': e => { e.readback.value.requestId = scope.launchId; },
  'unconfirmed GET': e => { e.readback.value.state = 'uncertain'; },
  'different review changed': e => { e.afterRows[0].id = 20; },
  'uncompleted effect': e => { e.effects[0].status = 'uncertain'; },
  'duplicate effect': e => { e.effects[1] = e.effects[0]; },
  'wrong run ledger': e => { e.effects[0].run_id = scope.launchId; },
  'no durable decision': e => { e.audits = []; },
  'sibling changed': e => { e.siblingAfter = []; },
  'sibling product changed': e => { e.siblingProductAfter.name = 'changed'; },
  'wrong sibling product owner': e => { e.siblingProductBefore.retailer_id = e.persona.id; },
  'wrong owned review product': e => { e.ownerProductBefore.product_id++; },
  'wrong product-to-review scene mapping': e => { e.ownerSceneMapping.review_target_id = e.siblingReviewTargetId; },
  'changed sibling scene mapping': e => { e.siblingSceneMappingAfter.review_target_id = e.ownerReviewTargetId; },
  'review decision bound to product target': e => {
    const row = JSON.parse(e.audits[0].params_json);
    row.receipt.scope.targetId = e.ownerTargetId;
    e.audits[0].params_json = JSON.stringify(row);
  },
  'vacuous sibling': e => { e.siblingBefore = []; e.siblingAfter = []; },
  'stale click mutated': e => { e.staleAfter = [{ id: 30 }]; },
  'credit manufactured': e => { e.creditAfter.completions = 1; },
  'nonempty assessment prestate': e => { e.creditBefore.judgments = 1; e.creditAfter.judgments = 4; },
  'unexplained judgment': e => { e.creditAfter.judgments = 4; },
  'missing run judgment': e => { e.assessmentWitness.rows.pop(); e.assessmentWitness.rowCountAtLeast = 2; },
  'foreign assessment run': e => { e.assessmentWitness.runId = e.siblingScope.launchId; },
  'duplicate objective': e => { e.assessmentWitness.rows[2].objectiveId = e.assessmentWitness.rows[0].objectiveId; },
  'assessment pass': e => { e.assessmentWitness.rows[0].verdict = 'pass'; },
  'assessment result pass': e => { e.assessmentWitness.rows[0].resultVerdict = 'pass'; },
  'assessment award': e => { e.assessmentWitness.rows[0].disposition = 'awarded'; },
  'assessment provider': e => { e.assessmentWitness.rows[0].providerPresent = true; },
  'assessment model': e => { e.assessmentWitness.rows[0].modelPresent = true; },
  'assessment usage': e => { e.assessmentWitness.rows[0].usagePresent = true; },
  'assessment model evaluated': e => { e.assessmentWitness.rows[0].modelEvaluated = true; },
  'assessment Judge proof': e => { e.assessmentWitness.rows[0].judgeObservationsState = 'proof'; },
  'assessment Judge result': e => { e.assessmentWitness.rows[0].judgeResultPresent = true; },
  'assessment peer binding': e => { e.assessmentWitness.rows[0].siblingScopeMatches = true; },
  'assessment principal mismatch': e => { e.assessmentWitness.rows[0].principalBindingMatches = false; },
  'assessment catalog enabled': e => { e.assessmentWitness.catalog[0].effectiveEnabled = true; },
  'assessment catalog missing': e => { e.assessmentWitness.catalog.pop(); },
  'stale automatic resubmission': e => { e.staleObservation.responses.push({ method: 'POST' }); },
  'missing stale denial': e => { e.staleObservation.responses = []; },
})) test(`Q05 retained evidence rejects ${label}`, () => {
  const packet = structuredClone(evidence()); mutate(packet);
  assert.throws(() => scenario.assertDurableEvidence(packet));
});

test('controlled provider uses the genuine bound read and decision tools without a model transport', async () => {
  const provider = scenario.createControlledProvider(); provider.arm({ reviewId: 19, body: 'Useful product' });
  let writes = 0;
  const row = { id: 19, productId: 8, authorId: 7, body: 'Useful product', rating: 5,
    status: 'pending', moderatorKind: null, moderatorNotes: null, moderatedAt: null };
  const actual = require('../server/services/secureshopBoundReviewTools').createSecureShopBoundReviewTools({
    trustedScope: { ...scope, targetId: scope.scenarioId }, checkCurrent: async () => {},
    resolveTarget: async () => ({ ...scope, targetId: scope.scenarioId }),
    repository: { listPending: async () => [row], decide: async (_scope, input) => {
      writes++; assert.equal(input.reviewId, 19); assert.equal(input.decision, 'approve');
      return { applied: true, review: { ...row, status: 'approved', moderatorKind: 'auto', moderatedAt: new Date(0) } };
    } } });
  const read = (await provider.chat({ tools, messages: [] })).tool_uses[0];
  const observed = await actual[read.name](read.args);
  assert.equal(writes, 0);
  const decide = (await provider.chat({ tools, messages: [{ content: observed.content[0].text }] })).tool_uses[0];
  const result = await actual[decide.name](decide.args);
  assert.equal(JSON.parse(result.content[0].text).applied, true); assert.equal(writes, 1);
  await provider.finalResponse(); assert.equal(provider.counts().actualModelCalls, 0);
});
