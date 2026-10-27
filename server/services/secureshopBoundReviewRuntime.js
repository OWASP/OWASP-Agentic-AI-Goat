'use strict';
const { SECURESHOP_CONVERSATION_PURPOSES: PURPOSES } = require('./secureshopConversationPurpose');
const { createBoundConversationService } = require('./secureshopBoundConversation');
const { createBoundTurns } = require('./secureshopBoundTurns');
const { createBoundAgentRunner } = require('./secureshopBoundAgentRunner');
const { createSecureShopBoundReviewApplication } = require('./secureshopBoundReviewApplication');
const { createSecureShopBoundReviewTools } = require('./secureshopBoundReviewTools');
const { createBoundReviewModeration, withBoundReviewPolicy } = require('./secureshopBoundReviewModeration');
const { assertBoundReviewBatchAuthority } = require('./secureshopBoundReviewBatchAuthority');
const { createBoundReviewsRouter } = require('../routes/secureshop/boundReviews');
const { captureFeatureMode, guardFeatureFence, featureModeForFence } = require('./secureshopFeatureModeAuthority');

function deriveBoundReviewBatchLimit(limits) {
  const maxSteps = limits?.maxSteps;
  // For N reviews, the conservative natural loop is one initial read, N
  // decisions, N-1 refresh reads, then the reserved structured final: 2N+1.
  const batchLimit = Number.isInteger(maxSteps)
    ? Math.min(5, Math.floor((maxSteps - 1) / 2)) : 0;
  if (batchLimit < 1) {
    throw new TypeError('Bound review step budget cannot support a finite batch');
  }
  return batchLimit;
}

// Retain one instance in the application composition. Its coordinator is the
// same instance used by conversation retirement; storage pools are supplied
// separately and must not serve as model-duration lease pools.
function createBoundReviewRuntime({ launches, reviewRepository, conversationRepository,
  journal, coordinator, authenticatePersona, buildBasePrompt, buildPolicyBlock,
  checkToolAcl, provider, createScopedToolPool, manifest, assessmentFactory,
  objectiveReceipts, workshopProgress, judge, fixtures = [], compatibleFixtures = [], limits,
  validateProduct, enableReviewContentAssessment = false, personaAuthority, personaBindings, toolPolicyRepository, promptPolicyRepository,
  taskPoliciesEnabled = false, modeAuthority = null, resolveProductScene, withProvisionLease,
  mirrorReviewScene, readRetainedReviewTarget, readRecoveryMode } = {}) {
  if (typeof taskPoliciesEnabled !== 'boolean') throw new TypeError('Bound review task policy configuration required');
  const promptPolicyOptions = require('./secureshopPromptPolicyRunnerOptions').promptPolicyRunnerOptions(promptPolicyRepository, personaAuthority,
    taskPoliciesEnabled ? { recipient: 'review-moderator' } : undefined);
  if (toolPolicyRepository !== undefined && (typeof toolPolicyRepository?.admitTool !== 'function'
      || typeof personaAuthority?.capture !== 'function')) throw new TypeError('Policy repository and persona authority required');
  if (personaBindings !== undefined && typeof personaBindings?.capture !== 'function') throw new TypeError('Trusted persona binding adapter required');
  if (personaBindings !== undefined && typeof personaAuthority?.capture !== 'function') throw new TypeError('Persona grading requires current persona authority');
  if (enableReviewContentAssessment && typeof launches?.readExistingReviewsTarget !== 'function') throw new TypeError('Existing review target reader required');
  if (typeof enableReviewContentAssessment !== 'boolean') {
    throw new TypeError('Bound review assessment configuration required');
  }
  const checkCurrent = scope => launches.assertCurrent(scope);
  if (modeAuthority !== null && modeAuthority !== undefined && typeof personaAuthority?.capture !== 'function') {
    throw new TypeError('Feature mode requires review persona authority');
  }
  const capturePersonaAuthority = personaAuthority === undefined ? undefined : async ({binding,personaSession}) => {
    const modeToken = await captureFeatureMode(modeAuthority, binding, 'review', 'vuln');
    const fence = await personaAuthority.capture({scope:binding,personaId:binding.shopUserId,role:binding.role,
      sessionId:personaSession?.sessionId,authorityVersion:personaSession?.authorityVersion});
    return fence ? guardFeatureFence(fence, modeToken) : fence;
  };
  if(personaAuthority!==undefined && typeof personaAuthority?.capture!=='function')throw new TypeError('Candidate persona authority required');
  const application = createSecureShopBoundReviewApplication({ launches,
    repository: reviewRepository, checkCurrent, validateProduct, fixtures, compatibleFixtures,
    ...(resolveProductScene ? { resolveProductScene, withProvisionLease, mirrorReviewScene } : {}),
    ...(personaAuthority ? { personaAuthority } : {}) });
  if (enableReviewContentAssessment && (typeof reviewRepository?.readSubmission !== 'function' || typeof reviewRepository?.captureReviewAdmissionTime !== 'function')) {
    throw new TypeError('Bound learner review provenance required');
  }
  if (typeof journal?.lookupReviewModerationRequest !== 'function') {
    throw new TypeError('Bound turn journal replay lookup required');
  }
  let completionService, contentCompletionService;
  if (assessmentFactory === undefined && objectiveReceipts && workshopProgress) {
    const { createSecureShopLoopAssessment } = require('./secureshopLoopAssessment');
    const { createSecureShopModelQualifier } = require('./secureshopModelQualification');
    const qualifyModel = createSecureShopModelQualifier(provider);
    const intro = createSecureShopLoopAssessment({ receipts: objectiveReceipts, progress: workshopProgress,
      qualifyModel, ...(personaBindings === undefined ? {} : {personaBindings}), ...(judge ? { judge } : {}) });
    assessmentFactory = intro.assessmentFactory;
    completionService = intro.completionService;
    if (enableReviewContentAssessment) {
      const { createSecureShopReviewContentAssessment, composeAssessmentFactories }
        = require('./secureshopReviewContentAssessment');
      const content = createSecureShopReviewContentAssessment({ receipts: objectiveReceipts,
        progress: workshopProgress, qualifyModel, ...(personaBindings === undefined ? {} : {personaBindings}), ...(judge ? { judge } : {}),
        captureAdmissionTime: async (binding, execution) => {
          await execution.check();
          await checkCurrent(binding);
          const value = await reviewRepository.captureReviewAdmissionTime(binding);
          await checkCurrent(binding);
          await execution.check();
          return value;
        },
        readSubmission: async (binding, reviewId) => {
          const target = await application.resolveExistingTarget(binding);
          return reviewRepository.readSubmission(target, reviewId);
        } });
      assessmentFactory = composeAssessmentFactories(intro.assessmentFactory, content.assessmentFactory);
      contentCompletionService = content.completionService;
    }
  }
  if (typeof launches?.assertCurrent !== 'function' || typeof coordinator?.reset !== 'function'
      || typeof assessmentFactory !== 'function') {
    throw new TypeError('Bound review authority, retirement and assessment required');
  }
  const conversations = createBoundConversationService({ conversations: conversationRepository, launches });
  const turns = createBoundTurns({ conversations, coordinator });
  if (createScopedToolPool !== undefined && typeof createScopedToolPool !== 'function') {
    throw new TypeError('Scoped tool pool factory required');
  }
  const scopedPool = createScopedToolPool || (() => Object.freeze({
    async callTool() {
      throw Object.assign(new Error('This tool is not available in the current isolated exercise'), {
        code: 'SCOPED_TOOL_UNAVAILABLE',
      });
    },
  }));
  if (typeof manifest?.getForRole !== 'function') throw new TypeError('Bound review manifest required');
  // The local read tool no longer runs the legacy classifier. Its advertised
  // behavior must match the actual observation-only adapter, or a model may
  // incorrectly treat a read as completed moderation. Other teaching catalogs
  // and the external MCP prompt block retain their existing content.
  const boundManifest = Object.freeze({
    getForRole: role => manifest.getForRole(role).map(tool => {
      if (tool.agent !== 'review-moderator') return tool;
      if (tool.tool === 'moderate_pending') return { ...tool,
        description: 'Read pending review data. This read does not classify or apply moderation in vulnerable mode. Fixed mode withholds raw text and supplies a bounded policy decision; it never applies a moderation decision.',
        inputSchema: { type: 'object', properties: { limit: { type: 'integer', minimum: 1, maximum: 100 } }, additionalProperties: false },
      };
      if (['approve', 'reject'].includes(tool.tool)) return { ...tool,
        inputSchema: { type: 'object', properties: { review_id: { type: 'integer', minimum: 1 },
          ...(tool.tool === 'reject' ? { reason: { type: 'string', maxLength: 16384 } } : {}),
        }, required: ['review_id'], additionalProperties: false },
      };
      return tool;
    }),
    ...(typeof manifest.buildExternalMcpPromptBlock === 'function' ? {
      buildExternalMcpPromptBlock: () => manifest.buildExternalMcpPromptBlock(),
    } : {}),
  });
  const configuredLimits = limits || { maxSteps: 8, maxParallelTools: 4 };
  const batchLimit = deriveBoundReviewBatchLimit(configuredLimits);
  const recoveryBatches = new WeakMap();
  const recovery = readRetainedReviewTarget === undefined && readRecoveryMode === undefined ? undefined
    : require('./secureshopReviewModerationRecovery').createReviewModerationRecovery({
      checkCurrent,personaAuthority,readTarget:readRetainedReviewTarget,readMode:readRecoveryMode});
  const runner = createBoundAgentRunner({ turns, conversations, ...promptPolicyOptions, repository: conversationRepository,
    ...(toolPolicyRepository === undefined ? {} : { toolPolicyAdmission: require('./secureshopBoundToolPolicyAdmission').createBoundToolPolicyAdmission({ repository: toolPolicyRepository, workflow: 'review', declaredTools: boundManifest.getForRole('merchant') }) }),
    journal, conversationPurpose: PURPOSES.reviewModeration,
    ...(capturePersonaAuthority ? {capturePersonaAuthority,personaLocalToolModes:{
      'review-moderator.moderate_pending':'remote_admission','review-moderator.approve':'remote_admission','review-moderator.reject':'remote_admission'}} : {}),
    buildBasePrompt: withBoundReviewPolicy(buildBasePrompt), buildPolicyBlock,
    checkToolAcl, provider, createToolPool: scopedPool, manifest: boundManifest, assessmentFactory,
    limits: configuredLimits, executionScope: 'turn',
    enterFinalResponseAfterLocalTool: packet => {
      const authority = assertBoundReviewBatchAuthority(packet.localToolAuthority);
      return authority.shouldEnterFinalResponse();
    },
    resultMetadata: async packet => {
      const captured = recoveryBatches.get(packet.localToolAuthority);
      await captured?.authority.check();
      return Object.freeze({ reviewBatch: Object.freeze({
      ...assertBoundReviewBatchAuthority(packet.localToolAuthority).metadata(),
      runId: packet.execution.runId,
      }), ...(captured ? {reviewRecovery:captured.metadata} : {}) });
    },
    createLocalTools: (binding, _context, localToolAuthority, execution, fence) => new Map(Object.entries(createSecureShopBoundReviewTools({
      repository: reviewRepository, trustedScope: binding,
      checkCurrent: async scope => {
        await checkCurrent(scope); await fence?.assertRemoteAdmission();
        await recoveryBatches.get(localToolAuthority)?.authority.check();
      },
      mode: featureModeForFence(fence)?.effectiveMode || 'vuln',
      ...(fence ? {personaEffectFence:fence,decisionOperation:require('./secureshopReviewDecisionOperation').createReviewDecisionOperation({runId:execution.runId,fence})} : {}),
      auditPersona: { id: binding.shopUserId, role: binding.role },
      resolveTarget: async scope => {
        const captured = recoveryBatches.get(localToolAuthority);
        if (!captured) return application.resolveTarget(scope);
        await captured.authority.check();
        return captured.authority.target;
      },
      batchAuthority: assertBoundReviewBatchAuthority(localToolAuthority),
    }))),
  });
  const moderation = createBoundReviewModeration({ conversations, runner, journal, checkCurrent, batchLimit,
    ...(recovery ? {recovery,bindRecovery:(batch,value)=>recoveryBatches.set(batch,value)} : {}),
    ...(capturePersonaAuthority ? {checkPersona:async({scope,persona,personaSession})=>{
      const fence = await capturePersonaAuthority({binding:{...scope,shopUserId:persona.id,role:persona.role},personaSession});
      await fence.assertRemoteAdmission();
    }} : {}) });
  const router = createBoundReviewsRouter({ launches, authenticatePersona,
    service: application, moderation, ...(personaAuthority ? {manualDecisions:require('./secureshopManualReviewDecision').createManualReviewDecision({authority:personaAuthority,repository:reviewRepository,resolveTarget:scope=>application.resolveTarget(scope)})} : {}) });
  return Object.freeze({ router, application, moderation, conversations, turns, runner,
    ...(completionService ? { completionService } : {}),
    ...(contentCompletionService ? { contentCompletionService } : {}) });
}

module.exports = { createBoundReviewRuntime, deriveBoundReviewBatchLimit };
