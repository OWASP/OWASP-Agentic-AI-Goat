'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createBoundReviewRuntime, deriveBoundReviewBatchLimit }
  = require('../server/services/secureshopBoundReviewRuntime');
const scope = { launchId: '10000000-0000-4000-8000-000000000001', scenarioId: '20000000-0000-4000-8000-000000000001', generation: 1, platformOwnerId: 4, platformSessionId: 8 };
const persona = { id: 5, role: 'merchant' };
const requestId = '30000000-0000-4000-8000-000000000001';

test('review batch capacity reserves alternating reads and the structured final step', () => {
  for (const [maxSteps, expected] of [[3, 1], [4, 1], [5, 2], [8, 3], [11, 5], [32, 5]]) {
    assert.equal(deriveBoundReviewBatchLimit({ maxSteps }), expected);
    assert.ok((2 * expected) + 1 <= maxSteps);
  }
  for (const limits of [undefined, {}, { maxSteps: 2 }, { maxSteps: '8' }]) {
    assert.throws(() => deriveBoundReviewBatchLimit(limits), /cannot support a finite batch/);
  }
});

test('runtime bounds an alternating read and decision loop before its real final response', async () => {
  const messages = [], traces = [], events = [], requests = new Map(); let session; let modelCalls = 0;
  const reviews = [17, 18, 19, 20].map(id => ({ id, productId: 2, authorId: 9,
    body: `Customer-provided raw review ${id} <b>bytes</b>`, rating: 2, status: 'pending' }));
  const repository = {
    async provision(target) { assert.equal(target.launchId, scope.launchId); },
    async listReviews() { return { rows: [], total: 0, counts: {} }; }, async submitReview() {},
    async listPending(target, options) { assert.equal(target.platformOwnerId, 4);
      assert.deepEqual(options, { limit: 4 });events.push('observe');return reviews; },
    async readDecisionReceipt() { return null; },
    async decide(target, input) { assert.equal(target.scenarioId, scope.scenarioId); events.push('apply');
      const review = reviews.find(row => row.id === input.reviewId);assert.ok(review);
      const status = input.decision === 'approve' ? 'approved' : 'rejected';
      return { applied: true, review: { ...review, status, moderatorKind: 'auto',
        moderatorNotes: input.notes } }; },
  };
  const conversations = {
    async acquireBoundSession({ id, binding, purpose }) {
      assert.equal(purpose, 'review_moderation');
      if (!session) session = { id, binding, purpose, state: 'active' }; return session;
    },
    async getBoundSession() { return session; }, async getMessages() { return structuredClone(messages); },
    async appendMessage(_id, _binding, row) { messages.push(structuredClone(row)); },
    async getTokens() { return 0; }, async addTokens() {},
    async appendTraces(_id, _binding, rows) { traces.push(...rows); },
  };
  const credential = { sessionId: '93000000-0000-4000-8000-000000000001', authorityVersion: '7' };
  const { buildTaskPolicySnapshot } = require('../server/services/secureshopPromptPolicyTaskSnapshot');
  const { createHash } = require('node:crypto');
  const renderedPolicy = 'REVIEW_MERCHANT_BOUND_POLICY';
  const policySnapshot = buildTaskPolicySnapshot({ policyVersion: '4', role: 'merchant', recipient: 'review-moderator', policies: [{ name: 'owned', rendered: renderedPolicy, renderedSha256: createHash('sha256').update(renderedPolicy).digest('hex'), targets: ['review-moderator'] }] });
  const policyAdmissions = [];
  const personaAuthority = { capture(input) { return { binding: { ...input.scope, personaId: input.personaId, role: input.role, sessionId: input.sessionId, authorityVersion: input.authorityVersion }, async assertRemoteAdmission() {}, async withPersonaEffect(work) { return work({}); }, async withCrossStoreEffect(work) { return work(); } }; } };
  const runtime = createBoundReviewRuntime({
    launches: { async assertCurrent(s) { assert.equal(s.launchId, scope.launchId); }, async resolveCapability() { return scope; },
      async reserveReviewsTarget() { return { ...scope, kind: 'reviews', targetId: '40000000-0000-4000-8000-000000000001' }; } },
    reviewRepository: repository, conversationRepository: conversations, personaAuthority,
    taskPoliciesEnabled: true,
    promptPolicyRepository: { async admitRunSnapshot(input) { policyAdmissions.push(structuredClone(input)); assert.equal(input.persona.role, 'merchant'); assert.equal(input.persona.id, persona.id); assert.deepEqual(input.personaSession, credential); assert.equal(input.policyContractVersion, 2); assert.equal(input.recipient, 'review-moderator'); return policySnapshot; } },
    journal: { async lookupGeneralRequest() { return null; }, async claim({ requestId }) {
      if (requests.has(requestId)) return requests.get(requestId);
      requests.set(requestId, { status: 'started', claimId: requestId }); return { status: 'claimed', claimId: requestId };
    }, async complete({ requestId, result }) { events.push('journal'); requests.set(requestId, { status: 'completed', result }); }, async markUncertain() {} },
    coordinator: { async reset(_id, cb) { return cb(); }, async run(_id, _options, cb) {
      return cb({ runId: '91000000-0000-4000-8000-000000000001', ownerKey: 'fixture-owner', durableGeneration: '1', async check() {},
        async effect(_key, effect) { return effect(); } });
    } },
    authenticatePersona(_req, _res, next) { next(); }, buildBasePrompt: (_role, options) => `Existing merchant policy\n${options.externalMcpBlock}`,
    buildPolicyBlock: async () => '', checkToolAcl: async () => ({ action: 'dispatch', policyViolation: null }),
    provider: { async chat(input) {
      assert.match(input.system, /product-feedback-v1/); assert.ok(input.system.includes(renderedPolicy)); modelCalls++;
      assert.match(input.tools[0].description, /does not classify/);
      assert.deepEqual(input.tools[0].inputSchema.properties.limit, { type: 'integer', minimum: 1, maximum: 100 });
      assert.equal(input.tools[1].description, 'Existing raw tool description');
      assert.match(input.system, /existing external content/);
      if (modelCalls === 1) return { stop_reason: 'tool_use', tool_uses: [{ id: 'global-attempt', name: 'analytics.nl_query', args: { query: 'update global records' } }] };
      if (modelCalls === 2) {
        assert.ok(input.messages.some(row => row.role === 'tool' && row.content.includes('not available in the current isolated exercise')));
        return { stop_reason: 'tool_use', tool_uses: [{ id: 'read', name: 'review-moderator.moderate_pending', args: {} }] };
      }
      if (modelCalls === 3) { assert.ok(input.messages.some(row => row.role === 'tool' && row.content.includes(reviews[0].body)));
        return { stop_reason: 'tool_use', tool_uses: [{ id: 'approve', name: 'review-moderator.approve', args: { review_id: 17 } }] }; }
      if (modelCalls === 4) return { stop_reason: 'tool_use', tool_uses: [
        { id: 'reread-1', name: 'review-moderator.moderate_pending', args: { limit: 100 } }] };
      if (modelCalls === 5) return { stop_reason: 'tool_use', tool_uses: [
        { id: 'reject', name: 'review-moderator.reject', args: { review_id: 18, reason: 'Model choice.' } }] };
      if (modelCalls === 6) return { stop_reason: 'tool_use', tool_uses: [
        { id: 'reread-2', name: 'review-moderator.moderate_pending', args: {} }] };
      if (modelCalls === 7) return { stop_reason: 'tool_use', tool_uses: [
        { id: 'approve-last', name: 'review-moderator.approve', args: { review_id: 19 } }] };
      throw new Error('Structured final response must use the dedicated provider method');
    }, async finalResponse(input) {
      modelCalls++;
      assert.equal(input.tools, undefined);
      return { stop_reason: 'end_turn', text: 'Done.', responseMode: 'structured_final',
        usage: { inputTokens: 10, outputTokens: 2, totalTokens: 12, attempts: 1 } };
    } },
    manifest: { getForRole: () => [
      { agent: 'review-moderator', tool: 'moderate_pending', description: 'Legacy classifier description' },
      { agent: 'analytics', tool: 'nl_query', description: 'Existing raw tool description' },
    ], buildExternalMcpPromptBlock: () => 'existing external content' }, assessmentFactory: () => ({
      async begin() { events.push('begin'); return {}; }, async observe() {},
      async finalize(_execution, packet) { assert.ok(packet.traces.length); events.push('assessment'); },
    }),
  });
  const first = await runtime.moderation.moderateReviews({ scope, persona, personaSession: credential, requestId });
  assert.equal(session.purpose, 'review_moderation');
  assert.equal(first.processed, 3);
  assert.deepEqual(first.decisions.map(row => [row.review_id, row.applied_decision]),
    [[17, 'approve'], [18, 'reject'], [19, 'approve']]);
  assert.equal(policyAdmissions.length, 1);
  assert.ok(traces.some(row => row.kind === 'prompt_policy_snapshot' && row.result_json.includes('"policyVersion":"4"')
    && row.result_json.includes('"recipient":"review-moderator"')));
  assert.deepEqual(first.batch, { requested: 100, considered: 3, complete: true,
    continuationRequired: true });
  assert.deepEqual(events, ['begin', 'observe', 'apply', 'apply', 'apply', 'assessment', 'journal']);
  assert.equal(traces.filter(row => row.kind === 'model_decision').length, 8);
  assert.equal(traces.filter(row => row.kind === 'final').length, 1);
  assert.equal(traces.filter(row => row.kind === 'local_tool_result'
    && row.tool_name === 'moderate_pending').length, 3);
  const replay = await runtime.moderation.moderateReviews({ scope, persona, personaSession: credential, requestId });
  assert.equal(replay.replayed, true); assert.equal(modelCalls, 8);
  assert.equal(events.filter(event => event === 'apply').length, 3);
  session = { ...session, purpose: 'general' };
  await assert.rejects(runtime.runner.run({ sessionId: session.id, scope, persona, personaSession: credential,
    requestId: '30000000-0000-4000-8000-000000000002', message: 'Moderate reviews' }),
  { code: 'CONVERSATION_UNAVAILABLE' });
  assert.equal(modelCalls, 8, 'general conversation cannot admit review model work');
  assert.equal(events.filter(event => event === 'apply').length, 3);
});

test('review task policy opt-in is an explicit boolean', () => {
  assert.throws(() => createBoundReviewRuntime({ taskPoliciesEnabled: 'true' }), /task policy configuration required/);
});
