'use strict';

const { createOrderStatusApplication } = require('./secureshopOrderStatusApplication');
const { createOrderStatusErrorEvidenceRepository } =
  require('../database/postgres/secureshopOrderStatusErrorEvidenceRepository');
const { createOrderStatusErrorAssessment } = require('./secureshopOrderStatusErrorAssessment');
const { createSecureShopModeRepository } = require('../database/postgres/secureshopModeRepository');
const { createSecureShopModelQualifier } = require('./secureshopModelQualification');
const { createObjectiveJudge } = require('../agent-runtime/objectiveJudge');
const { createBoundOrderStatusRouter } = require('../routes/secureshop/boundOrderStatus');

function createOrderStatusComposition({ identityPool, agentsPool, launches, conversations,
  journal, coordinator, provider, personaAuthority, personaBindings, receipts, progress,
  modeAuthority, customerChat, toolPolicyRepository, promptPolicyRepository,
  authenticatePersona, orderStatusDependencies, judge, assertActorAvailable } = {}) {
  const service = orderStatusDependencies?.service;
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
      || typeof customerChat?.captureOrderStatus !== 'function'
      || typeof toolPolicyRepository?.admitTool !== 'function'
      || typeof promptPolicyRepository?.admitRunSnapshot !== 'function'
      || typeof authenticatePersona !== 'function'
      || typeof service?.provision !== 'function'
      || typeof service.lookupOrderStatus !== 'function'
      || typeof service.readOrderStatusReceipt !== 'function'
      || typeof service.readOrderStatusReference !== 'function'
      || judge !== undefined && typeof judge !== 'function'
      || assertActorAvailable !== undefined && typeof assertActorAvailable !== 'function')
    throw TypeError('Complete order status composition required');

  const application = createOrderStatusApplication({
    captureCurrent: input => customerChat.captureOrderStatus(input),
    personaAuthority, modeAuthority, launches, conversationRepository: conversations,
    journal, coordinator, provider,
    orderStatusService: Object.freeze({
      provision: (scope, options) => service.provision(scope, options),
      lookupOrderStatus: (input, options) => service.lookupOrderStatus(input, options),
    }),
    agentsPool, promptPolicyRepository, toolPolicyRepository, assertActorAvailable,
  });
  const source = createOrderStatusErrorEvidenceRepository({ identityPool,
    conversationRepository: conversations,
    readSavedSource: (context, selectors) => application.readSavedSource(context, selectors),
    readOrderStatusReceipt: (selectors, options) => service.readOrderStatusReceipt(selectors, options),
    readOrderStatusReference: (selectors, options) => service.readOrderStatusReference(selectors, options),
  });
  const assessment = createOrderStatusErrorAssessment({ identityPool, agentsPool, launches,
    conversationRepository: conversations, coordinator, journal, personaAuthority,
    personaBindings, receipts, progress, publicationModes: createSecureShopModeRepository(identityPool),
    judge: judge || createObjectiveJudge(),
    current: (context, options) => application.current(context, options),
    readSource: (context, selectors) => source.readSource(context, selectors),
    qualifyModelTrace: createSecureShopModelQualifier(provider),
  });
  const router = createBoundOrderStatusRouter({ launches, authenticatePersona,
    application, assessment });
  return Object.freeze({ ready: true, application, assessment, router });
}

module.exports = { createOrderStatusComposition };
