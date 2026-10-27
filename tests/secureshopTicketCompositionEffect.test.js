'use strict';

// Exercise the real composition seam with controlled downstream services.
// This establishes wiring order, not a PostgreSQL, browser, or model result.
const test = require('node:test');
const assert = require('node:assert/strict');
const { createSecureShopCleanupComposition } = require('../server/services/secureshopCleanupComposition');
const { createSecureShopBoundReviewComposition } = require('../server/services/secureshopBoundReviewComposition');
const { createSecureShopGradingBootstrap } = require('../server/services/secureshopGradingBootstrap');
const { createObjectiveGradingCore } = require('../server/services/objectiveGradingCore');
const { createFeatureModeAuthority } = require('../server/services/secureshopFeatureModeAuthority');

const methods = names => Object.fromEntries(names.map(name => [name, async () => ({})]));

async function compositionOptions() {
  const pool = { query: async () => ({ rows: [] }), connect: async () => ({
    query: async () => ({ rows: [] }), release() {}, on() {}, removeListener() {},
  }) };
  const agentsPool = { ...pool };
  const launches = methods(['assertCurrent', 'resolveCapability', 'reserveReviewsTarget',
    'readExistingReviewsTarget', 'reserveProductsTarget', 'reservePersonaInboxTarget', 'beginReset', 'commitReset']);
  const cleanupAuthority = methods(['getOperation', 'checkTarget', 'checkReviewTarget',
    'checkProductTarget', 'listTargets', 'assertResolved', 'finalizeReconciliation']);
  const conversationRepository = methods(['acquireBoundSession', 'activateBoundSession',
    'abandonBoundSession', 'getBoundSession', 'appendMessage', 'getMessages', 'getTokens',
    'addTokens', 'appendTraces', 'getTrace', 'getTraceEvents', 'latestTrace', 'personaLatestTrace']);
  const journal = methods(['lookupGeneralRequest', 'lookupReviewModerationRequest', 'claim', 'complete', 'markUncertain',
    'readBoundRequest', 'readAuditRequest']);
  const reviewRepository = methods(['provision', 'listReviews', 'listPending', 'submitReview',
    'decide', 'cleanup', 'readCleanupReceipt', 'readSubmission', 'captureReviewAdmissionTime',
    'readDecisionReceipt', 'readSceneTarget', 'provisionScene']);
  const productRepository = methods(['open', 'provision', 'list', 'get', 'cleanup', 'readCleanupReceipt']);
  const audit = { agents: methods(['append', 'recent']), review: methods(['append', 'recent']),
    reader: methods(['recent']), async cleanup() {} };
  const resetComposition = createSecureShopCleanupComposition({ identityPool: pool, agentsPool,
    reviewPool: pool, leasePool: pool, launches, cleanupAuthority, conversationRepository,
    journal, reviewRepository, productRepository, runCoordinator: methods(['run', 'reset']), audit });
  const personaAuthority = { ...methods(['resolve', 'read']), capture() {
    return { assertRemoteAdmission: async () => {}, withCrossStoreEffect: async work => work({}),
      withPersonaEffect: async work => work({}) };
  } };
  const personaBindings = { ...methods(['capture', 'initial', 'inherit', 'commit', 'check', 'projectRecoverable']),
    assertReady: async () => ({ ready: true }) };
  const gradingBootstrap = await createSecureShopGradingBootstrap({ identityPool: pool, agentsPool,
    progress: { getGeneration: async () => 0 }, resetComposition, assertAuthorityReady: async () => true }, {
    createAuthority: () => personaAuthority, createBindings: () => personaBindings,
    createCore: input => createObjectiveGradingCore(input, {
      createObjectiveJudgmentRepository: () => methods(['listRecoverable', 'beginEvaluation',
        'recordVerdict', 'getEvaluation', 'beginRetry', 'assertRecoveryAuthority']),
      createObjectiveCompletionService: () => ({}), createObjectiveRegradeService: () => async () => {},
    }),
  });
  const modeAuthority = createFeatureModeAuthority({ launches,
    progress: { async getEvaluationScope() { return { mode: 'fixed', generation: 0, modeStamp: 'fixture' }; } } });
  return { identityPool: pool, agentsPool, reviewPool: pool, commercePool: pool, resetComposition,
    gradingBootstrap, modeAuthority,
    catalog: methods(['listProducts', 'getProduct', 'listMerchantProducts', 'getOwnedMerchantProduct',
      'createMerchantProduct', 'updateMerchantProduct', 'archiveMerchantProduct', 'hasProduct', 'prepareTarget']),
    account: methods(['profile', 'updateProfile', 'addresses', 'createAddress', 'updateAddress', 'deleteAddress']),
    scenes: methods(['readExisting', 'readRetained', 'withProvisionLease']),
    toolPolicyRepository: methods(['admitTool', 'readPolicy', 'mutate', 'readOperation']),
    jwtSecret: 'owned-ticket-composition-secret-at-least-32-bytes',
    agentRuntime: { manifest: { getForRole() { return []; } },
      provider: { chat: async () => ({}), finalResponse: async () => ({}) } },
    authenticatePersona(_req, _res, next) { next(); }, fixtures: [], requiredObjectives: ['fixture_objective'],
    judge: async () => ({ verdict: 'fail', criteria: [], explanation: 'controlled' }),
    reviewCardRenderer: { sourceSha256: 'a'.repeat(64), artifactSha256: 'b'.repeat(64),
      async renderReviewCard(review) { return `<article>${review.body}</article>`; } },
    browserQualification: { async qualify() { return { executed: false }; }, async close() {} },
  };
}

test('ticket composition forwards the captured effect callback only to confirmation repository and keeps saved read effect-free', async () => {
  const repositoryModule = require('../server/database/postgres/secureshopTicketRepository');
  const confirmationModule = require('../server/services/secureshopTicketAgentConfirmation');
  const originalRepositoryFactory = repositoryModule.createSecureShopTicketRepository;
  const originalConfirmationFactory = confirmationModule.createTicketAgentConfirmation;
  const calls = [];
  let captured;
  const result = Object.freeze({ ticketId: '41' });
  const saved = Object.freeze({ status: 'completed', result });
  repositoryModule.createSecureShopTicketRepository = () => ({
    async confirm(input) {
      calls.push(['confirm', input]);
      return input.withEffect(async () => {
        calls.push(['repository-effect']);
        return result;
      });
    },
    async readSavedCustomer(input) { calls.push(['readSaved', input]); return saved; },
    async listForAdmin() { return null; }, async readForAdmin() { return null; },
    async readForAssessment() { throw Error('Confirmation wiring must not assess tickets'); },
  });
  confirmationModule.createTicketAgentConfirmation = options => {
    captured = options;
    return { confirm: options.confirmTicket, readSaved: options.readSavedTicket };
  };
  try {
    const composition = createSecureShopBoundReviewComposition(await compositionOptions());
    assert.equal(composition.ticketAgent.ready, true);
    assert.ok(captured);
    const request = Object.freeze({ operationId: 'owned-operation' });
    let effectCount = 0;
    const withEffect = async work => {
      effectCount += 1;
      calls.push(['effect-enter']);
      const value = await work();
      calls.push(['effect-exit']);
      return value;
    };
    assert.equal(await captured.confirmTicket({ ...request, withEffect }), result);
    assert.deepEqual(calls, [
      ['confirm', { ...request, withEffect }], ['effect-enter'], ['repository-effect'], ['effect-exit'],
    ]);
    assert.equal(calls[0][1].withEffect, withEffect,
      'composition forwards the exact captured effect callback without invoking it');
    assert.equal(effectCount, 1);
    assert.deepEqual(await captured.readSavedTicket(request), saved);
    assert.deepEqual(calls.at(-1), ['readSaved', request]);
    assert.equal(effectCount, 1);
    assert.throws(() => captured.confirmTicket(request), { code: 'SECURESHOP_BOUND_REVIEW_UNAVAILABLE' });
    assert.equal(effectCount, 1);
    assert.equal(calls.filter(([kind]) => kind === 'confirm').length, 1);
  } finally {
    repositoryModule.createSecureShopTicketRepository = originalRepositoryFactory;
    confirmationModule.createTicketAgentConfirmation = originalConfirmationFactory;
  }
});
