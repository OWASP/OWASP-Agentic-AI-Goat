'use strict';

// Constructor/wiring regression only; controlled dependencies do not qualify
// a model, native transaction, HTTP effect, or objective completion.
const test = require('node:test');
const assert = require('node:assert/strict');
const { createSecureShopCleanupComposition } = require('../server/services/secureshopCleanupComposition');
const { createSecureShopBoundReviewComposition } = require('../server/services/secureshopBoundReviewComposition');
const { createSecureShopGradingBootstrap } = require('../server/services/secureshopGradingBootstrap');
const { createObjectiveGradingCore } = require('../server/services/objectiveGradingCore');
const { createFeatureModeAuthority } = require('../server/services/secureshopFeatureModeAuthority');
const methods = names => Object.fromEntries(names.map(name => [name, async () => ({})]));

async function options() {
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
    jwtSecret: 'owned-coupon-composition-secret-at-least-32-bytes',
    agentRuntime: { manifest: { getForRole() { return []; } },
      provider: { chat: async () => ({}), finalResponse: async () => ({}) } },
    authenticatePersona(_req, _res, next) { next(); }, fixtures: [], requiredObjectives: ['fixture_objective'],
    judge: async () => ({ verdict: 'fail', criteria: [], explanation: 'controlled' }),
    reviewCardRenderer: { sourceSha256: 'a'.repeat(64), artifactSha256: 'b'.repeat(64),
      async renderReviewCard(review) { return `<article>${review.body}</article>`; } },
    browserQualification: { async qualify() { return { executed: false }; }, async close() {} },
  };
}

test('real composition constructs the coupon confirmation branch only with complete effect/read dependencies', async () => {
  const input = await options();
  assert.equal(createSecureShopBoundReviewComposition(input).couponAgent, undefined);
  const dependencies = { repository: {}, mode: 'fixed', modeAuthority: input.modeAuthority,
    readCouponReceipt: async () => null,
    workflow: methods(['apply', 'applyConfirmed', 'readConfirmed']) };
  const ready = createSecureShopBoundReviewComposition({ ...input, couponDependencies: dependencies });
  assert.equal(ready.couponAgent.ready, true);
  assert.equal(typeof ready.couponAgent.confirmation.confirm, 'function');
  assert.equal(typeof ready.couponAgent.confirmation.readSaved, 'function');
  assert.equal(typeof ready.couponAgent.assessment.runAttempt, 'function');
  assert.equal(typeof ready.couponAgent.assessment.readOutcome, 'function');
  const routes = ready.couponAgent.router.stack.flatMap(layer => layer.handle.stack).filter(layer => layer.route).map(layer =>
    [layer.route.path, Object.keys(layer.route.methods)]);
  assert.deepEqual(routes, [
    ['/agents/customer/coupons/confirm', ['post']],
    ['/agents/customer/coupons/confirm/:sessionId/:requestId/:proposalId', ['get']],
    ['/agents/customer/coupons/assessment-retry', ['post']],
    ['/agents/customer/coupons/assessment/:sessionId/:requestId/:proposalId', ['get']],
  ]);
  assert.throws(() => createSecureShopBoundReviewComposition({ ...input,
    couponDependencies: { ...dependencies, readCouponReceipt: undefined } }),
  { code: 'SECURESHOP_BOUND_REVIEW_UNAVAILABLE' }, 'missing protected SQL receipt reader must not advertise ready');
  for (const missing of ['applyConfirmed', 'readConfirmed']) {
    const workflow = { ...dependencies.workflow }; delete workflow[missing];
    assert.throws(() => createSecureShopBoundReviewComposition({ ...input,
      couponDependencies: { ...dependencies, workflow } }),
    { code: 'SECURESHOP_BOUND_REVIEW_UNAVAILABLE' }, `missing ${missing} must not advertise ready`);
  }
  for (const modeAuthority of [undefined, { capture() {}, assertToken() {} }]) {
    assert.throws(() => createSecureShopBoundReviewComposition({ ...input,
      couponDependencies: { ...dependencies, modeAuthority } }),
    { code: 'SECURESHOP_BOUND_REVIEW_UNAVAILABLE' }, 'only the shared token issuer may make confirmation ready');
  }
});
