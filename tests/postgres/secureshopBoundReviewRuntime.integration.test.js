'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const express = require('express');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const { initializeIdentityRepository, createIdentityRepository } = require('../../server/database/postgres/identityRepository');
const { createSecureShopLaunchRepository } = require('../../server/database/postgres/secureshopLaunchRepository');
const { createSecureShopBoundReviewRepository } = require('../../server/database/postgres/secureshopBoundReviewRepository');
const { createBoundConversationsRepository } = require('../../server/database/postgres/secureshopBoundConversationsRepository');
const { createTurnRequestsRepository } = require('../../server/database/postgres/secureshopTurnRequestsRepository');
const { createPostgresRunLedger } = require('../../server/agent-runtime/postgresRunLedger');
const { createRunCoordinator } = require('../../server/agent-runtime/runCoordinator');
const { createBoundReviewRuntime } = require('../../server/services/secureshopBoundReviewRuntime');
const { runSessionExclusive } = require('../../server/services/secureshop/sessionStore');
const { migrate } = require('../../db/postgres/migrate');
const { createSecureShopReviewExecutionConfig } = require(
  '../../server/services/secureshopReviewExecutionConfig');

const PREFIX = 'PG_SECURESHOP_BOUND_REVIEW_RUNTIME_';
const URL_KEYS = ['IDENTITY_MIGRATION_URL', 'IDENTITY_RUNTIME_URL', 'REVIEW_MIGRATION_URL',
  'REVIEW_RUNTIME_URL', 'AGENTS_MIGRATION_URL', 'AGENTS_RUNTIME_URL'];
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' && URL_KEYS.every(key => process.env[PREFIX + key]);
const negativeReview = 'The battery failed after one day. This is disappointing product feedback.';
const unrelatedAd = 'Buy our unrelated casino advertising package at https://ads.example.test today.';

function checkedUrl(key) {
  const value = new URL(process.env[PREFIX + key]);
  assert.ok(['127.0.0.1', 'localhost'].includes(value.hostname));
  assert.match(value.pathname, /^\/dvaia_test_[a-z0-9_]+$/);
  return value.href;
}
async function listen(app) {
  return new Promise((resolve, reject) => {
    const server = app.listen(0, '127.0.0.1', () => resolve(server));
    server.once('error', reject);
  });
}
async function closeServer(server) {
  if (!server) return;
  if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
  await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
}

test('full bound review runtime persists one assessed local decision and replays without rerun', {
  skip: !enabled, timeout: 120000,
}, async t => {
  const workspace = path.resolve(process.env.DVAIA_ISOLATED_TEST_WORKSPACE || '');
  assert.match(path.basename(path.dirname(workspace)), /^dvaia-secureshop-bound-review-runtime-/);
  const identityMigration = new Pool({ connectionString: checkedUrl('IDENTITY_MIGRATION_URL'), max: 2 });
  const identityRuntime = new Pool({ connectionString: checkedUrl('IDENTITY_RUNTIME_URL'), max: 8 });
  const identityLeases = new Pool({ connectionString: checkedUrl('IDENTITY_RUNTIME_URL'), max: 2,
    application_name: 'bound-review-runtime-lease' });
  const reviewMigration = new Pool({ connectionString: checkedUrl('REVIEW_MIGRATION_URL'), max: 2 });
  const reviewPool = new Pool({ connectionString: checkedUrl('REVIEW_RUNTIME_URL'), max: 8 });
  const agentsMigration = new Pool({ connectionString: checkedUrl('AGENTS_MIGRATION_URL'), max: 2 });
  const agentsPool = new Pool({ connectionString: checkedUrl('AGENTS_RUNTIME_URL'), max: 8 });
  let server;
  const cleanupErrors = [];
  try {
    await initializeIdentityRepository(identityRuntime, identityMigration);
    await migrate(reviewMigration, path.join(workspace,
      'db/postgres/workshop-migrations/secureshop_review'));
    await migrate(agentsMigration, path.join(workspace,
      'db/postgres/workshop-migrations/secureshop_agents'));

    const identity = createIdentityRepository(identityRuntime);
    const launches = createSecureShopLaunchRepository(identityRuntime);
    const passwordHash = await bcrypt.hash('owned-bound-review-runtime', 4);
    const expiresAt = new Date(Date.now() + 3600000).toISOString();
    async function owner(name) {
      const user = await identity.createUser({ username: name, email: `${name}@review.invalid`, passwordHash });
      const session = await identity.createSession({ userId: user.id, token: randomUUID(), expiresAt,
        expectedPasswordHash: passwordHash });
      return { user, session, issued: await launches.issueOrRenew({ platformOwnerId: user.id,
        platformSessionId: session.id, expiresAt }) };
    }
    const alice = await owner('bound-review-runtime-alice');
    const bob = await owner('bound-review-runtime-bob');
    const checkCurrent = scope => launches.assertCurrent(scope);
    const reviewRepository = createSecureShopBoundReviewRepository(reviewPool, {
      enableLearnerSubmissions: true, checkCurrent,
      checkRetirement: async () => { throw new Error('retirement is outside this qualification'); },
      checkCleanup: async () => { throw new Error('cleanup is outside this qualification'); },
    });
    const conversationRepository = createBoundConversationsRepository({ pool: agentsPool, queue: runSessionExclusive });
    const journal = createTurnRequestsRepository({ pool: agentsPool });
    const ledger = createPostgresRunLedger(identityRuntime, { leasePool: identityLeases });
    const coordinator = createRunCoordinator({ family: `SecureShopBoundReviewNative:${randomUUID()}`, ledger });
    const live = process.env.LIVE_OLLAMA_TEST === '1';
    const modelInputs = [], modelOutputs = [];
    const assessmentEvents = [];
    let scopedCalls = 0;
    let selectedReviewId;
    const deterministicProvider = { config: { provider: 'fixture-model', model: 'deterministic-observer' }, async chat(input) {
      modelInputs.push(input);
      if (modelInputs.length === 1) return { provider: 'fixture-model', model: 'deterministic-observer', mocked: false,
        stop_reason: 'tool_use', tool_uses: [{ id: 'observe-pending',
          name: 'review-moderator.moderate_pending', args: { limit: 10 } }] };
      if (modelInputs.length === 2) {
        const observation = JSON.parse(input.messages.at(-1).content);
        selectedReviewId = observation.reviews.find(row => row.body === negativeReview).id;
        return { provider: 'fixture-model', model: 'deterministic-observer', mocked: false,
          stop_reason: 'tool_use', tool_uses: [{ id: 'approve-negative-feedback',
            name: 'review-moderator.approve', args: { review_id: selectedReviewId } }] };
      }
      return { provider: 'fixture-model', model: 'deterministic-observer', mocked: false,
        stop_reason: 'end_turn', text: 'Observed genuine negative product feedback and approved it.' };
    } };
    const provider = live ? (() => {
      const { OllamaProvider } = require('../../server/services/secureshop/providers/ollamaProvider');
      const ollama = new OllamaProvider({ baseUrl: process.env.OLLAMA_BASE_URL || 'http://127.0.0.1:11434',
        model: 'llama3.1:8b' });
      return { config: { provider: 'ollama', model: 'llama3.1:8b' }, async chat(input) {
        modelInputs.push(input);
        const output = { ...(await ollama.chat(input)), provider: 'ollama', model: 'llama3.1:8b', mocked: false };
        modelOutputs.push(output);
        return output;
      } };
    })() : deterministicProvider;
    const executionConfig = createSecureShopReviewExecutionConfig();
    const shopTokens = new Map([
      ['alice-customer', { id: 41, role: 'customer' }], ['alice-merchant', { id: 77, role: 'merchant' }],
      ['bob-customer', { id: 42, role: 'customer' }], ['bob-merchant', { id: 78, role: 'merchant' }],
    ]);
    const runtime = createBoundReviewRuntime({ launches, reviewRepository, conversationRepository,
      journal, coordinator, manifest: executionConfig.manifest, provider,
      authenticatePersona(req, res, next) {
        const match = /^Shop (.+)$/.exec(req.get('authorization') || '');
        const persona = match && shopTokens.get(match[1]);
        if (!persona) return res.status(401).json({ error: 'Shop authentication required' });
        req.ssUser = { ...persona }; return next();
      },
      buildBasePrompt: executionConfig.buildBasePrompt,
      buildPolicyBlock: executionConfig.buildPolicyBlock,
      checkToolAcl: executionConfig.checkToolAcl,
      createScopedToolPool(binding) {
        assert.ok(Object.isFrozen(binding));
        assert.equal(binding.role, 'merchant');
        return Object.freeze({ async callTool() {
          scopedCalls += 1;
          throw new Error('Nonlocal scoped tools are outside this qualification');
        } });
      },
      assessmentFactory: context => {
        const record = { context, execution: null, observations: [] };
        return { async begin(execution) { record.execution = execution; assessmentEvents.push(['begin', record]); return { ungraded: true }; },
          async observe(execution, packet) { assert.equal(execution, record.execution); record.observations.push(packet);
            assessmentEvents.push(['observe', record]); },
          async finalize(execution, packet) { assert.equal(execution, record.execution); assert.ok(packet.traces.length > 0);
            record.final = packet; assessmentEvents.push(['finalize', record]); return { status: 'ungraded' }; } };
      }, fixtures: [{ productId: 7, authorId: 2,
        body: 'I used these headphones for a week. They paired quickly and the controls were easy to learn.', rating: 4 }],
    });
    const app = express(); app.use(express.json()); app.use('/api/secureshop', runtime.router);
    server = await listen(app);
    const base = `http://127.0.0.1:${server.address().port}/api/secureshop`;
    const headers = (ownerValue, persona, json = false) => ({ authorization: `Shop ${persona}`,
      'x-dvaia-secureshop-launch': ownerValue.issued.bearer,
      ...(json ? { 'content-type': 'application/json' } : {}) });
    async function submit(ownerValue, persona, id, body) {
      const response = await fetch(`${base}/products/7/reviews`, { method: 'POST',
        headers: headers(ownerValue, persona, true), body: JSON.stringify({ submission_id: id,
          author_id: 999, body, rating: 1 }) });
      assert.equal(response.status, 200); return response.json();
    }
    const aliceReview = await submit(alice, 'alice-customer', randomUUID(), negativeReview);
    const adReview = live ? await submit(alice, 'alice-customer', randomUUID(), unrelatedAd) : null;
    const bobReview = await submit(bob, 'bob-customer', randomUUID(), 'Sibling review must remain pending.');
    const requestId = randomUUID();
    const moderate = (id = requestId) => fetch(`${base}/merchant/reviews/moderate`, { method: 'POST',
      headers: headers(alice, 'alice-merchant', true), body: JSON.stringify({ request_id: id, limit: 10 }) });
    const firstResponse = await moderate();
    assert.equal(firstResponse.status, 200);
    const first = await firstResponse.json();
    assert.equal(first.replayed, false);
    if (live) {
      t.diagnostic(JSON.stringify({ scope: 'actual local8B; owned PostgreSQL stores; private assessment stub; no Judge credit',
        moderation: first, modelOutputs, modelCallCount: modelInputs.length }));
      const decisions = new Map(first.decisions.map(row => [row.review_id, row.applied_decision]));
      assert.equal(decisions.get(aliceReview.review_id), 'approve');
      assert.equal(decisions.get(adReview.review_id), 'reject');
      assert.equal(first.processed, 3);
      assert.equal(decisions.size, 3, 'each controlled review receives one applied business decision');
      assert.equal(first.ok, true); assert.equal(first.stopReason, 'end_turn');
      assert.equal(assessmentEvents[0][0], 'begin');
      assert.equal(assessmentEvents.at(-1)[0], 'finalize');
    } else {
      assert.equal(first.processed, 1);
      assert.equal(first.decisions[0].review_id, aliceReview.review_id);
      assert.equal(first.decisions[0].applied_decision, 'approve');
      assert.equal(selectedReviewId, aliceReview.review_id);
      assert.deepEqual(assessmentEvents.map(([name]) => name), ['begin', 'observe', 'observe', 'finalize']);
    }
    const record = assessmentEvents[0][1];
    assert.equal(record.context.binding.platformOwnerId, alice.user.id);
    assert.equal(record.context.binding.shopUserId, 77);
    if (!live) assert.equal(record.observations.length, 2);
    assert.ok(record.observations.every(entry => entry.run.runId === record.execution.runId));
    assert.ok(record.observations.every(entry => entry.observation.effectReceipt?.status === 'completed'));
    if (live) {
      const hops = record.final.result.hops;
      assert.equal(scopedCalls, 0, 'the model never selects a nonlocal or invented catalog tool');
      assert.equal(hops.length, record.observations.length,
        'every executed hop is an assessment-linked local observation');
      const decisionIds = [];
      let reads = 0;
      for (const hop of hops) {
        assert.equal(hop.error, null); assert.notEqual(hop.result?.isError, true);
        assert.match(hop.tool, /^review-moderator\.(moderate_pending|approve|reject)$/);
        const payload = JSON.parse(hop.result.content[0].text);
        assert.equal(payload.ok, true);
        if (hop.tool === 'review-moderator.moderate_pending') {
          reads += 1;
          assert.ok(Number.isInteger(hop.params.limit) && hop.params.limit >= 1 && hop.params.limit <= 100);
          assert.ok(Array.isArray(payload.reviews));
        } else {
          assert.equal(payload.applied, true);
          assert.equal(payload.review.id, hop.params.review_id);
          decisionIds.push(hop.params.review_id);
        }
      }
      assert.ok(reads >= 1, 'the model observes pending work before decisions');
      assert.equal(decisionIds.length, 3);
      assert.equal(new Set(decisionIds).size, 3, 'no business decision is repeated');
      assert.equal(record.final.result.stopReason, 'end_turn');
    }

    const sessions = await agentsPool.query(`SELECT id,platform_launch_id,user_id,role FROM secureshop_agents.agent_sessions
      WHERE authority_mode='launch_bound' ORDER BY created_at,id`);
    assert.equal(sessions.rows.length, 1);
    assert.equal(sessions.rows[0].platform_launch_id, alice.issued.binding.launchId);
    assert.equal(Number(sessions.rows[0].user_id), 77); assert.equal(sessions.rows[0].role, 'merchant');
    const binding = { ...alice.issued.binding, shopUserId: 77, role: 'merchant' };
    const trace = await conversationRepository.getTrace(
      sessions.rows[0].id, binding, 100, 'review_moderation');
    assert.equal(trace.filter(row => row.kind === 'model_decision').length, modelInputs.length);
    if (live) {
      assert.equal(trace.filter(row => row.kind === 'model_decision').every(row => row.provider === 'ollama'), true);
      assert.equal(trace.filter(row => row.kind === 'local_tool_call')[0].tool_name, 'moderate_pending');
    } else {
      assert.equal(trace.filter(row => row.kind === 'model_decision').length, 3);
      assert.deepEqual(trace.filter(row => row.kind === 'local_tool_call').map(row => row.tool_name),
        ['moderate_pending', 'approve']);
    }
    assert.ok(trace.some(row => row.kind === 'terminal'));
    assert.equal(Number((await identityRuntime.query(`SELECT count(*)::int AS count FROM graph_runtime.effects
      WHERE status='completed'`)).rows[0].count), record.observations.length);
    assert.equal(Number((await agentsPool.query(`SELECT count(*)::int AS count FROM secureshop_agents.turn_requests
      WHERE status='completed'`)).rows[0].count), 1);

    const modelCallCount = modelInputs.length;
    const replayResponse = await moderate();
    assert.equal(replayResponse.status, 200);
    assert.deepEqual(await replayResponse.json(), { ...first, replayed: true });
    assert.equal(modelInputs.length, modelCallCount, 'journal replay does not call the model again');
    assert.equal(assessmentEvents.length, record.observations.length + 2);
    assert.equal(Number((await identityRuntime.query('SELECT count(*)::int AS count FROM graph_runtime.effects')).rows[0].count),
      record.observations.length);
    assert.equal((await conversationRepository.getTrace(
      sessions.rows[0].id, binding, 100, 'review_moderation')).length, trace.length);

    const historicalSessionId = randomUUID();
    assert.deepEqual(await conversationRepository.createPendingBoundSession({
      id: historicalSessionId, binding, purpose: 'general',
    }), { id: historicalSessionId });
    assert.equal(await conversationRepository.activateBoundSession(
      historicalSessionId, binding, 'general'), true);
    const historicalMessage = 'Moderate up to 10 pending reviews according to the review moderation policy. '
      + 'Read the pending reviews, apply your decisions with the tools, and report the actual results. '
      + 'Stop when there are no pending reviews or you have considered 10 reviews.';
    async function seedGeneralRequest(id, message = historicalMessage, state = 'completed') {
      const claimed = await journal.claim({ sessionId: historicalSessionId, requestId: id,
        binding, message });
      assert.equal(claimed.status, 'claimed');
      if (state === 'completed') {
        await journal.complete({ sessionId: historicalSessionId, requestId: id, binding,
          claimId: claimed.claimId, result: record.final.result });
      } else if (state === 'uncertain') {
        assert.equal(await journal.markUncertain({ sessionId: historicalSessionId, requestId: id,
          binding, claimId: claimed.claimId }), true);
      }
    }
    const historicalRequestId = randomUUID();
    await seedGeneralRequest(historicalRequestId);
    const beforeHistoricalReplay = {
      modelCalls: modelInputs.length,
      assessmentEvents: assessmentEvents.length,
      effects: Number((await identityRuntime.query(
        'SELECT count(*)::int AS count FROM graph_runtime.effects')).rows[0].count),
      traces: Number((await agentsPool.query(
        'SELECT count(*)::int AS count FROM secureshop_agents.agent_trace')).rows[0].count),
    };
    const historicalResponse = await moderate(historicalRequestId);
    assert.equal(historicalResponse.status, 200);
    assert.deepEqual(await historicalResponse.json(), { ...first, replayed: true });
    assert.equal(modelInputs.length, beforeHistoricalReplay.modelCalls,
      'completed general-session replay does not call the provider');
    assert.equal(assessmentEvents.length, beforeHistoricalReplay.assessmentEvents,
      'completed general-session replay does not create assessment work');
    assert.equal(Number((await identityRuntime.query(
      'SELECT count(*)::int AS count FROM graph_runtime.effects')).rows[0].count),
    beforeHistoricalReplay.effects, 'completed general-session replay does not create effects');
    assert.equal(Number((await agentsPool.query(
      'SELECT count(*)::int AS count FROM secureshop_agents.agent_trace')).rows[0].count),
    beforeHistoricalReplay.traces, 'completed general-session replay does not append traces');

    const denied = async (id, expectedStatus) => {
      const response = await moderate(id);
      assert.equal(response.status, expectedStatus);
      assert.deepEqual(await response.json(), { error: expectedStatus === 409
        ? 'This request ID was already used for a different action'
        : 'Review service unavailable' });
      assert.equal(modelInputs.length, beforeHistoricalReplay.modelCalls);
      assert.equal(assessmentEvents.length, beforeHistoricalReplay.assessmentEvents);
      assert.equal(Number((await identityRuntime.query(
        'SELECT count(*)::int AS count FROM graph_runtime.effects')).rows[0].count),
      beforeHistoricalReplay.effects);
      assert.equal(Number((await agentsPool.query(
        'SELECT count(*)::int AS count FROM secureshop_agents.agent_trace')).rows[0].count),
      beforeHistoricalReplay.traces);
    };
    const startedRequestId = randomUUID();
    await seedGeneralRequest(startedRequestId, historicalMessage, 'started');
    await denied(startedRequestId, 503);
    const uncertainRequestId = randomUUID();
    await seedGeneralRequest(uncertainRequestId, historicalMessage, 'uncertain');
    await denied(uncertainRequestId, 503);
    const conflictRequestId = randomUUID();
    await seedGeneralRequest(conflictRequestId, `${historicalMessage} Conflicting historical bytes.`, 'started');
    await denied(conflictRequestId, 409);

    const aliceRows = await fetch(`${base}/merchant/reviews?page=1&per_page=25`,
      { headers: headers(alice, 'alice-merchant') }).then(response => response.json());
    const bobRows = await fetch(`${base}/merchant/reviews?page=1&per_page=25`,
      { headers: headers(bob, 'bob-merchant') }).then(response => response.json());
    assert.equal(aliceRows.reviews.find(row => row.id === aliceReview.review_id).status, 'approved');
    if (live) {
      assert.equal(aliceRows.reviews.find(row => row.body.startsWith('I used these headphones')).status, 'approved');
      assert.equal(aliceRows.reviews.find(row => row.id === adReview.review_id).status, 'rejected');
    }
    assert.equal(bobRows.reviews.find(row => row.id === bobReview.review_id).status, 'pending');
    assert.equal(bobRows.reviews.some(row => row.body === negativeReview), false);
  } finally {
    for (const close of [() => closeServer(server), () => agentsPool.end(), () => agentsMigration.end(),
      () => reviewPool.end(), () => reviewMigration.end(), () => identityLeases.end(),
      () => identityRuntime.end(), () => identityMigration.end()]) {
      try { await close(); } catch (error) { cleanupErrors.push(error); }
    }
    if (cleanupErrors.length) throw new AggregateError(cleanupErrors, 'Bound review runtime cleanup failed');
  }
});
