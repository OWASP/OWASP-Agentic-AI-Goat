'use strict';

// New composed task-policy qualification only. The launcher supplies disposable
// stores, the strict renderer endpoint, the offline embedding cache and Ollama.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const express = require('express');
const bcrypt = require('bcryptjs');
const { randomUUID, createHash } = require('node:crypto');
const { Pool } = require('pg');

const PREFIX = 'PG_PROMPT_POLICY_TASK_COMPOSED_';
const STORES = ['IDENTITY', 'AGENTS', 'REVIEW', 'COMMERCE'];
const enabled = process.env.PROMPT_POLICY_TASK_COMPOSED_NATIVE === '1'
  && STORES.every(store => ['MIGRATION', 'RUNTIME'].every(role => process.env[`${PREFIX}${store}_${role}_URL`]));

function digest(value) { return createHash('sha256').update(value, 'utf8').digest('hex'); }
function dbUrl(store, role) {
  const value = new URL(process.env[`${PREFIX}${store}_${role}_URL`]);
  assert.equal(value.hostname, '127.0.0.1');
  assert.match(value.pathname, /^\/owasp_ai_goat_test_task_policy_[a-f0-9]+_(identity|agents|review|commerce)$/);
  return value.href;
}
function jsonResponse(response) { return response.text().then(text => ({ response, value: text ? JSON.parse(text) : null })); }

test('mounted task policies bind real renderer, consumers and genuine local model', {
  skip: !enabled, timeout: 350000,
}, async t => {
  assert.equal(process.env.PG_TEST_DISPOSABLE, 'yes');
  assert.equal(fs.realpathSync(process.cwd()), fs.realpathSync(process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE));
  assert.equal(process.env.OLLAMA_MODEL, 'llama3.1:8b');
  assert.match(process.env.OLLAMA_BASE_URL, /^http:\/\/(127\.0\.0\.1|localhost):11434\/?$/);
  assert.ok(path.isAbsolute(process.env.XENOVA_CACHE));
  assert.ok(fs.statSync(process.env.XENOVA_CACHE).isDirectory());
  assert.ok(['0', '1'].includes(process.env.PROMPT_POLICY_TASK_ACTUAL_MODEL));
  const actualModel = process.env.PROMPT_POLICY_TASK_ACTUAL_MODEL === '1';
  const pools = {}, all = [];
  for (const store of STORES) for (const role of ['MIGRATION', 'RUNTIME']) {
    const pool = new Pool({ connectionString: dbUrl(store, role), max: role === 'RUNTIME' ? 3 : 2,
      statement_timeout: 10000 });
    pools[`${store}_${role}`] = pool; all.push(pool);
  }
  const leases = new Pool({ connectionString: dbUrl('IDENTITY', 'RUNTIME'), max: 3, statement_timeout: 10000 });
  all.push(leases);
  let server, composition;
  const evidence = { version: 1, status: 'incomplete', scope: 'mounted task policy route, real renderer, controlled graph contrast, then genuine local llama3.1:8b ProductAssist pair',
    rendererCalls: 0, controlled: {}, actual: { model: 'llama3.1:8b', executed: actualModel,
      maxPhysicalCalls: actualModel ? 6 : 0, calls: [] } };
  const evidencePath = path.join(process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE, 'task-policy-composed-result.json');
  const save = () => { fs.writeFileSync(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600 }); fs.chmodSync(evidencePath, 0o600); };
  t.after(save); save();
  try {
    const { migrate } = require('../../db/postgres/migrate');
    await migrate(pools.IDENTITY_MIGRATION, 'db/postgres/identity-migrations');
    await migrate(pools.AGENTS_MIGRATION, 'db/postgres/workshop-migrations/secureshop_agents');
    await migrate(pools.REVIEW_MIGRATION, 'db/postgres/workshop-migrations/secureshop_review');
    await migrate(pools.COMMERCE_MIGRATION, 'db/postgres/workshop-migrations/secureshop');
    await require('../../server/database/postgres/secureshopSeed').seedSecureShop(pools.COMMERCE_MIGRATION);
    const { DEFAULT_OBJECTIVES, createSecureShopBoundReviewComposition } = require('../../server/services/secureshopBoundReviewComposition');
    await pools.IDENTITY_MIGRATION.query(`INSERT INTO workshop_platform.exercises
      (workshop_key,challenge_key,challenge_name,ordinal,catalog_active,is_visible)
      VALUES('secureshop_agent_security','secureshop_agent_security','SecureShop Agent Security',900,true,true)
      ON CONFLICT(workshop_key) DO UPDATE SET catalog_active=true,is_visible=true`);
    for (const [ordinal, objective] of DEFAULT_OBJECTIVES.entries()) await pools.IDENTITY_MIGRATION.query(`INSERT INTO workshop_platform.objectives
      (workshop_key,objective_id,label,ordinal,catalog_active,is_enabled)
      VALUES('secureshop_agent_security',$1,$1,$2,true,true)
      ON CONFLICT(workshop_key,objective_id) DO UPDATE SET catalog_active=true,is_enabled=true`, [objective, ordinal + 1]);

    const audit = require('../../server/services/secureshopBoundAuditComposition')
      .createSecureShopBoundAuditComposition({ agentsPool: pools.AGENTS_RUNTIME,
        reviewPool: pools.REVIEW_RUNTIME, includeRunArtifacts: true });
    const reset = require('../../server/services/secureshopCleanupComposition').createSecureShopCleanupComposition({
      identityPool: pools.IDENTITY_RUNTIME, agentsPool: pools.AGENTS_RUNTIME,
      reviewPool: pools.REVIEW_RUNTIME, leasePool: leases, audit,
    });
    const progress = require('../../server/database/postgres/workshopProgressRepository')
      .createWorkshopProgressRepository(pools.IDENTITY_RUNTIME);
    const gradingBootstrap = await require('../../server/services/secureshopGradingBootstrap')
      .createSecureShopGradingBootstrap({ identityPool: pools.IDENTITY_RUNTIME, agentsPool: pools.AGENTS_RUNTIME,
        progress, resetComposition: reset,
        expectedIdentityDatabase: new URL(dbUrl('IDENTITY', 'RUNTIME')).pathname.slice(1),
        expectedAgentsDatabase: new URL(dbUrl('AGENTS', 'RUNTIME')).pathname.slice(1) });
    const promptRepository = require('../../server/database/postgres/secureshopBoundPromptPolicyRepository')
      .createBoundPromptPolicyRepository({ pool: pools.AGENTS_RUNTIME,
        personaAuthority: gradingBootstrap.personaAuthority, audit: audit.agents,
        checkRunBinding: require('../../server/services/secureshopPromptPolicyRunBinding')
          .createPromptPolicyRunBinding({ identityPool: pools.IDENTITY_RUNTIME }) });
    await promptRepository.checkReadiness();
    const rendererRuntime = await require('../../server/services/secureshopPromptPolicyActivation')
      .preparePromptPolicyRenderer({ env: { SS_BOUND_PROMPT_POLICIES_ENABLED: 'true', SS_ENABLE: 'true',
        SS_BOUND_REVIEWS_ENABLED: 'true', PLATFORM_DATABASE_ENGINE: 'postgres', WORKSHOP_DATABASE_ENGINE: 'postgres',
        SS_POLICY_RENDERER_BASE_URL: process.env.PROMPT_POLICY_RENDERER_ORIGIN }, timeoutMs: 10000 });
    const renderer = Object.freeze({ async render(...args) { evidence.rendererCalls += 1; save(); return rendererRuntime.render(...args); } });

    const controlledQueue = [], controlledInputs = [];
    let phase = 'controlled', actualOperation = null, live;
    const provider = Object.freeze({
      async chat(input) {
        if (phase === 'actual') { evidence.actual.calls.push({ operation: actualOperation, phase: 'decision', system: input.system, status: 'started' }); save();
          try { const value = await live.provider.chat(input); evidence.actual.calls.at(-1).result = { provider: value.provider, model: value.model, mocked: value.mocked, stop_reason: value.stop_reason }; evidence.actual.calls.at(-1).status = 'returned'; save(); return value; }
          catch (error) { evidence.actual.calls.at(-1).status = 'failed'; evidence.actual.calls.at(-1).error = { name: error.name, code: error.code || null }; save(); throw error; } }
        controlledInputs.push({ phase: 'decision', system: input.system });
        const value = controlledQueue.shift(); if (!value) throw new Error('Controlled decision queue exhausted'); return value;
      },
      async finalResponse(input) {
        if (phase === 'actual') { evidence.actual.calls.push({ operation: actualOperation, phase: 'final', system: input.system, status: 'started' }); save();
          try { const value = await live.provider.finalResponse(input); evidence.actual.calls.at(-1).result = { provider: value.provider, model: value.model, mocked: value.mocked, stop_reason: value.stop_reason, text: value.text }; evidence.actual.calls.at(-1).status = 'returned'; save(); return value; }
          catch (error) { evidence.actual.calls.at(-1).status = 'failed'; evidence.actual.calls.at(-1).error = { name: error.name, code: error.code || null }; save(); throw error; } }
        controlledInputs.push({ phase: 'final', system: input.system });
        const value = controlledQueue.shift(); if (!value) throw new Error('Controlled final queue exhausted'); return value;
      },
    });
    composition = createSecureShopBoundReviewComposition({ identityPool: pools.IDENTITY_RUNTIME,
      agentsPool: pools.AGENTS_RUNTIME, reviewPool: pools.REVIEW_RUNTIME, commercePool: pools.COMMERCE_RUNTIME,
      resetComposition: reset, gradingBootstrap, promptPolicyRepository: promptRepository,
      promptPolicyRenderer: renderer, taskPoliciesEnabled: true,
      jwtSecret: 'owned-task-policy-composed-secret-at-least-32-bytes', agentRuntime: { provider },
      judge: async () => { throw Object.assign(new Error('Judge outside task-policy qualification'), { code: 'JUDGE_UNAVAILABLE' }); },
      fixtures: [],
      reviewCardRenderer: { sourceSha256: 'a'.repeat(64), artifactSha256: 'b'.repeat(64), renderReviewCard() { throw new Error('Browser outside task-policy qualification'); } },
      browserQualification: { async qualify() { throw new Error('Browser outside task-policy qualification'); } },
    });
    await composition.repositories.personas.ensureTemplates();
    assert.deepEqual(composition.promptPolicyTaskTargets, ['summarizer', 'review-moderator']);

    const users = require('../../server/database/postgres/identityRepository').createIdentityRepository(pools.IDENTITY_RUNTIME);
    const passwordHash = await bcrypt.hash('owned-task-policy', 4);
    const user = await users.createUser({ username: `task-policy-${randomUUID().slice(0, 8)}`,
      email: `${randomUUID()}@task-policy.invalid`, passwordHash });
    const platformSession = await users.createSession({ userId: user.id, token: randomUUID(),
      expiresAt: new Date(Date.now() + 3600000), expectedPasswordHash: passwordHash });
    const issued = await composition.launches.issueOrRenew({ platformOwnerId: user.id,
      platformSessionId: platformSession.id, expiresAt: new Date(Date.now() + 3600000) });
    let dropOperationId = null, dropped = false, committedRendererCalls = null;
    const app = express(); app.use(express.json());
    app.use('/api/secureshop', (req, res, next) => { const original = res.json.bind(res); res.json = value => {
      if (dropOperationId && req.method === 'POST' && value?.receipt?.operationId === dropOperationId) {
        dropped = true; committedRendererCalls = evidence.rendererCalls; dropOperationId = null; res.socket.destroy(); return res;
      } return original(value); }; next(); });
    app.use('/api/secureshop', require('../../server/routes/secureshop/boundGateway').createSecureShopBoundGateway({
      launches: composition.launches, authenticatePersona: composition.personaAuth.authenticatePersona,
      personaAuth: composition.personaAuth, reviewsRouter: composition.router, browserRouter: composition.browserRouter,
      catalog: composition.catalog, commerce: composition.commerce, account: composition.account, admin: composition.admin,
      refundRouter: composition.refund.router, productAssist: composition.productAssist,
      promptPolicies: composition.promptPolicies, promptPolicyTaskTargets: composition.promptPolicyTaskTargets,
    }));
    server = await new Promise(resolve => { const value = app.listen(0, '127.0.0.1', () => resolve(value)); });
    const base = `http://127.0.0.1:${server.address().port}/api/secureshop`;
    const launchHeaders = { 'x-owasp-ai-goat-secureshop-launch': issued.bearer, 'content-type': 'application/json' };
    async function login(username) {
      const { response, value } = await jsonResponse(await fetch(`${base}/v2/auth/login`, { method: 'POST', headers: launchHeaders,
        body: JSON.stringify({ username, password: 'student123' }) })); assert.equal(response.status, 200); return value;
    }
    const admin = await login('student_admin'), customer = await login('student_customer'), merchant = await login('student_merchant');
    const headers = token => ({ ...launchHeaders, authorization: `Bearer ${token}` });
    const adminHeaders = headers(admin.token), customerHeaders = headers(customer.token), merchantHeaders = headers(merchant.token);
    const initial = await jsonResponse(await fetch(`${base}/admin/policies`, { headers: adminHeaders }));
    assert.equal(initial.response.status, 200); assert.deepEqual(initial.value.supported_task_targets, ['review-moderator', 'summarizer']);
    let version = initial.value.version;
    async function publish(name, markdown, targets, { drop = false } = {}) {
      const operationId = randomUUID(); if (drop) dropOperationId = operationId;
      const body = { name, markdown, injected_into: targets, operationId, expectedVersion: version };
      let result;
      try { result = await jsonResponse(await fetch(`${base}/admin/policies`, { method: 'POST', headers: adminHeaders, body: JSON.stringify(body) })); }
      catch (error) { if (!drop) throw error; result = { dropped: true, error: error.name }; }
      if (!drop) { assert.equal(result.response.status, 200); version = result.value.receipt.version; }
      return { operationId, body, result };
    }
    const roleText = 'ROLE-WIDE-CONTROL-POLICY';
    const summaryText = 'SUMMARY-TASK-ONLY-POLICY';
    const reviewText = 'REVIEW-TASK-ONLY-POLICY';
    const role = await publish('role-wide', roleText, ['customer', 'merchant']);
    assert.equal(Object.hasOwn(role.result.value.receipt, 'policyRequestSha256'), false);
    assert.equal(role.result.value.receipt.requestSha256,
      require('../../server/services/secureshopPromptPolicyContract').requestDigest({ operationId: role.operationId,
        name: 'role-wide', markdown: roleText, targets: ['customer', 'merchant'] }));
    const summary = await publish('summary-only', summaryText, ['summarizer'], { drop: true });
    for (let attempt = 0; !dropped && attempt < 200; attempt += 1) await new Promise(resolve => setTimeout(resolve, 25));
    assert.equal(dropped, true); assert.equal(summary.result.dropped, true);
    let recovered;
    for (let attempt = 0; attempt < 200; attempt += 1) {
      const candidate = await jsonResponse(await fetch(`${base}/admin/policies/operations/${summary.operationId}`, { headers: adminHeaders }));
      if (candidate.response.status === 200) { recovered = candidate.value.receipt; break; }
      assert.equal(candidate.response.status, 202); await new Promise(resolve => setTimeout(resolve, 25));
    }
    assert.ok(recovered); assert.equal(evidence.rendererCalls, committedRendererCalls);
    const taskContract = require('../../server/services/secureshopPromptPolicyTaskMutation');
    const taskRequest = { contractVersion: 2, operationId: summary.operationId, name: 'summary-only', markdown: summaryText, targets: ['summarizer'] };
    assert.equal(recovered.requestSha256, require('../../server/services/secureshopPromptPolicyContract').requestDigest(taskContract.renderRequest(taskRequest)));
    assert.equal(recovered.policyRequestSha256, taskContract.taskMutationDigest(taskRequest)); version = recovered.version;
    const replacementAdmin = await login('student_admin');
    const denied = await fetch(`${base}/admin/policies/operations/${summary.operationId}`, { headers: headers(replacementAdmin.token) });
    assert.ok([404, 409].includes(denied.status)); assert.equal(evidence.rendererCalls, committedRendererCalls);
    const review = await publish('review-only', reviewText, ['review-moderator']);
    assert.match(review.result.value.receipt.policyRequestSha256, /^[a-f0-9]{64}$/);
    const listed = (await jsonResponse(await fetch(`${base}/admin/policies`, { headers: adminHeaders }))).value;
    assert.equal(listed.version, '4');
    assert.deepEqual(new Map(listed.policies.map(row => [row.name, JSON.parse(row.injected_into_json)])),
      new Map([['role-wide', ['customer', 'merchant']], ['review-only', ['review-moderator']], ['summary-only', ['summarizer']]]));
    evidence.route = { version: listed.version, originalSessionRecovered: true, replacementSessionDenied: denied.status,
      rendererCalls: evidence.rendererCalls, requestSha256: recovered.requestSha256,
      policyRequestSha256: recovered.policyRequestSha256, v1DigestUnchanged: true }; save();

    const productPage = await jsonResponse(await fetch(`${base}/products?limit=2`, { headers: customerHeaders }));
    assert.equal(productPage.response.status, 200); const productId = productPage.value.products[0].id;
    controlledQueue.push(
      { stop_reason: 'tool_use', tool_uses: [{ id: 'summary-read', name: 'summarizer.summarize_product', args: { product_id: productId } }], provider: 'controlled', model: 'controlled-provider', mocked: false, fallback: false },
      { stop_reason: 'end_turn', responseMode: 'structured_final', text: 'Controlled summary.', provider: 'controlled', model: 'controlled-provider', mocked: false, fallback: false },
      { stop_reason: 'tool_use', tool_uses: [{ id: 'similar-read', name: 'product-search.similar', args: { product_id: productId } }], provider: 'controlled', model: 'controlled-provider', mocked: false, fallback: false },
      { stop_reason: 'end_turn', responseMode: 'structured_final', text: 'Controlled similar.', provider: 'controlled', model: 'controlled-provider', mocked: false, fallback: false });
    assert.equal((await fetch(`${base}/products/${productId}/summary`, { method: 'POST', headers: customerHeaders, body: '{}' })).status, 200);
    assert.equal((await fetch(`${base}/products/${productId}/similar`, { headers: customerHeaders })).status, 200);
    assert.equal(controlledQueue.length, 0);
    const summarySystems = controlledInputs.slice(0, 2).map(row => row.system).join('\n');
    const similarSystems = controlledInputs.slice(2, 4).map(row => row.system).join('\n');
    assert.match(summarySystems, new RegExp(summaryText)); assert.match(summarySystems, new RegExp(roleText));
    assert.doesNotMatch(similarSystems, new RegExp(summaryText)); assert.match(similarSystems, new RegExp(roleText));
    const submissionId = randomUUID();
    const submitted = await jsonResponse(await fetch(`${base}/products/${productId}/reviews`, { method: 'POST', headers: customerHeaders,
      body: JSON.stringify({ submission_id: submissionId, author_id: 999, body: 'Task policy controlled review.', rating: 2 }) }));
    assert.equal(submitted.response.status, 200);
    const reviewId = submitted.value.review_id;
    controlledQueue.push(
      { stop_reason: 'tool_use', tool_uses: [{ id: 'review-read', name: 'review-moderator.moderate_pending', args: { limit: 1 } }], provider: 'controlled', model: 'controlled-provider', mocked: false, fallback: false },
      { stop_reason: 'tool_use', tool_uses: [{ id: 'review-approve', name: 'review-moderator.approve', args: { review_id: reviewId } }], provider: 'controlled', model: 'controlled-provider', mocked: false, fallback: false },
      { stop_reason: 'end_turn', responseMode: 'structured_final', text: 'Controlled moderation complete.', provider: 'controlled', model: 'controlled-provider', mocked: false, fallback: false });
    const moderated = await jsonResponse(await fetch(`${base}/merchant/reviews/moderate`, { method: 'POST', headers: merchantHeaders,
      body: JSON.stringify({ request_id: randomUUID(), limit: 1 }) }));
    evidence.controlled.moderation = moderated.value; save();
    assert.equal(moderated.response.status, 200); assert.equal(moderated.value.processed, 1);
    const reviewSystems = controlledInputs.slice(4).map(row => row.system).join('\n');
    assert.match(reviewSystems, new RegExp(reviewText)); assert.match(reviewSystems, new RegExp(roleText));
    assert.equal(controlledQueue.length, 0);
    evidence.controlled = { summaryIncludesTask: true, similarExcludesTask: true, reviewIncludesTask: true,
      allConsumersIncludeV1: true, calls: controlledInputs.length }; save();

    if (actualModel) {
      const tags = await fetch(`${process.env.OLLAMA_BASE_URL}/api/tags`, { signal: AbortSignal.timeout(5000) });
      assert.equal(tags.ok, true); const modelRow = (await tags.json()).models.find(row => row.name === 'llama3.1:8b');
      assert.match(modelRow?.digest, /^[a-f0-9]{64}$/); evidence.actual.modelDigestBefore = modelRow.digest; save();
      live = require('./secureshopRefundActual8bGate').createLiveRefundProvider({ env: { ...process.env, SS_REFUND_LIVE_MODEL: '1' }, maxCalls: 6 });
      phase = 'actual';
      const aggregate = new AbortController(); const timer = setTimeout(() => aggregate.abort(new Error('Task policy actual-model aggregate timeout')), 300000);
      try {
        actualOperation = 'summary';
        const actualSummary = await jsonResponse(await fetch(`${base}/products/${productId}/summary`, { method: 'POST', headers: customerHeaders, body: '{}', signal: aggregate.signal }));
        assert.equal(actualSummary.response.status, 200); assert.equal(actualSummary.value.provider, 'ollama'); assert.equal(actualSummary.value.model, 'llama3.1:8b');
        actualOperation = 'similar';
        const actualSimilar = await jsonResponse(await fetch(`${base}/products/${productId}/similar`, { headers: customerHeaders, signal: aggregate.signal }));
        assert.equal(actualSimilar.response.status, 200); assert.equal(actualSimilar.value.provider, 'ollama'); assert.equal(actualSimilar.value.model, 'llama3.1:8b');
        evidence.actual.outputs = { summary: actualSummary.value.summary, similar: actualSimilar.value.recommendation };
      } finally { clearTimeout(timer); aggregate.abort(); }
      evidence.actual.physicalCalls = live.getCalls(); assert.ok(evidence.actual.physicalCalls >= 4 && evidence.actual.physicalCalls <= 6);
      const actualSummarySystems = evidence.actual.calls.filter(row => row.operation === 'summary').map(row => row.system).join('\n');
      const actualSimilarSystems = evidence.actual.calls.filter(row => row.operation === 'similar').map(row => row.system).join('\n');
      assert.match(actualSummarySystems, new RegExp(summaryText)); assert.match(actualSummarySystems, new RegExp(roleText));
      assert.doesNotMatch(actualSimilarSystems, new RegExp(summaryText)); assert.match(actualSimilarSystems, new RegExp(roleText));
      assert.ok(evidence.actual.calls.every(row => row.status === 'returned' && row.result.provider === 'ollama'
        && row.result.model === 'llama3.1:8b' && row.result.mocked !== true));
      const finalTags = await fetch(`${process.env.OLLAMA_BASE_URL}/api/tags`, { signal: AbortSignal.timeout(5000) });
      assert.equal(finalTags.ok, true); evidence.actual.modelDigestAfter = (await finalTags.json()).models.find(row => row.name === 'llama3.1:8b')?.digest;
      assert.equal(evidence.actual.modelDigestAfter, evidence.actual.modelDigestBefore);
    } else {
      evidence.actual.physicalCalls = 0;
    }
    const snapshots = (await pools.AGENTS_RUNTIME.query(`SELECT payload_json FROM secureshop_agents.bound_prompt_policy_snapshots
      WHERE platform_launch_id=$1 ORDER BY run_id`, [issued.binding.launchId])).rows.map(row => row.payload_json);
    assert.ok(snapshots.some(value => value.policyContractVersion === 2 && value.recipient === 'summarizer'
      && value.policies.some(policy => policy.rendered === summaryText)));
    assert.ok(snapshots.some(value => value.policyContractVersion === 2 && value.recipient === null
      && value.policies.every(policy => policy.rendered !== summaryText)));
    evidence.actual.snapshotsVerified = true; evidence.actual.noJudgeOrCreditClaim = true;
    evidence.status = 'passed'; save();
  } finally {
    if (server) await new Promise(resolve => server.close(resolve));
    await composition?.closeBrowserAssessment?.();
    if (composition?.launchResetCoordinator?.close) await composition.launchResetCoordinator.close();
    const closed = await Promise.allSettled(all.map(pool => pool.end()));
    assert.ok(closed.every(result => result.status === 'fulfilled'));
  }
});
