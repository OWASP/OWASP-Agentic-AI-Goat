'use strict';

const { createCouponProbeApplication } = require('./secureshopCouponProbeApplication');
const { createCouponBlindEvidenceRepository } =
  require('../database/postgres/secureshopCouponBlindEvidenceRepository');
const { createCouponBlindAssessment } = require('./secureshopCouponBlindAssessment');
const { createSecureShopModeRepository } = require('../database/postgres/secureshopModeRepository');
const { createSecureShopModelQualifier } = require('./secureshopModelQualification');
const { createObjectiveJudge } = require('../agent-runtime/objectiveJudge');
const { createBoundCouponProbeRouter } = require('../routes/secureshop/boundCouponProbe');

function createCouponProbeComposition({ identityPool, agentsPool, launches, conversations,
  journal, coordinator, provider, personaAuthority, personaBindings, receipts, progress,
  modeAuthority, customerChat, toolPolicyRepository, promptPolicyRepository,
  authenticatePersona, probeDependencies, judge, assertActorAvailable } = {}) {
  const service = probeDependencies?.service;
  if (typeof identityPool?.query !== 'function' || typeof identityPool.connect !== 'function'
      || typeof agentsPool?.query !== 'function'
      || typeof launches?.resolveCapability !== 'function' || typeof launches.assertCurrent !== 'function'
      || ['getTraceEvents', 'getBoundSession', 'acquireBoundSession', 'activateBoundSession',
        'appendTraces'].some(key => typeof conversations?.[key] !== 'function')
      || ['claim', 'complete', 'markUncertain'].some(key => typeof journal?.[key] !== 'function')
      || typeof coordinator?.run !== 'function'
      || typeof provider?.chat !== 'function' || typeof provider.finalResponse !== 'function'
      || typeof personaAuthority?.capture !== 'function'
      || typeof personaBindings?.capture !== 'function'
      || typeof receipts?.beginEvaluation !== 'function'
      || typeof receipts.recordVerdict !== 'function'
      || typeof progress?.getGeneration !== 'function'
      || typeof modeAuthority?.assertToken !== 'function'
      || typeof customerChat?.captureCouponProbe !== 'function'
      || typeof toolPolicyRepository?.admitTool !== 'function'
      || typeof promptPolicyRepository?.admitRunSnapshot !== 'function'
      || typeof authenticatePersona !== 'function'
      || typeof service?.provision !== 'function'
      || typeof service.lookupCouponProbe !== 'function'
      || typeof service.readCouponProbeReceipt !== 'function'
      || typeof service.readCouponProbeReference !== 'function'
      || typeof probeDependencies.readCoupons !== 'function'
      || judge !== undefined && typeof judge !== 'function'
      || assertActorAvailable !== undefined && typeof assertActorAvailable !== 'function')
    throw TypeError('Complete coupon probe composition required');

  const application = createCouponProbeApplication({
    captureCurrent: input => customerChat.captureCouponProbe(input),
    personaAuthority, modeAuthority, launches, conversationRepository: conversations,
    journal, coordinator, provider,
    probeService: Object.freeze({
      provision: (scope, options) => service.provision(scope, options),
      lookupCouponProbe: (input, options) => service.lookupCouponProbe(input, options),
    }),
    readCoupons: probeDependencies.readCoupons,
    agentsPool, promptPolicyRepository, toolPolicyRepository, assertActorAvailable,
  });
  const source = createCouponBlindEvidenceRepository({ identityPool,
    conversationRepository: conversations,
    readSavedSource: (context, selectors) => application.readSavedSource(context, selectors),
    readCouponProbeReceipt: (selectors, options) => service.readCouponProbeReceipt(selectors, options),
    readCouponProbeReference: (selectors, options) => service.readCouponProbeReference(selectors, options),
  });
  const assessment = createCouponBlindAssessment({ identityPool, agentsPool, launches,
    conversationRepository: conversations, coordinator, journal, personaAuthority,
    personaBindings, receipts, progress, publicationModes: createSecureShopModeRepository(identityPool),
    judge: judge || createObjectiveJudge(),
    current: (context, options) => application.current(context, options),
    readSource: (context, selectors) => source.readSource(context, selectors),
    qualifyModelTrace: createSecureShopModelQualifier(provider),
  });
  const router = createBoundCouponProbeRouter({ launches, authenticatePersona,
    application, assessment });
  return Object.freeze({ ready: true, application, assessment, router });
}

module.exports = { createCouponProbeComposition };
