'use strict';

const { createProductSearchApplication } = require('./secureshopProductSearchApplication');
const { createProductUnionEvidenceRepository } =
  require('../database/postgres/secureshopProductUnionEvidenceRepository');
const { createProductUnionAssessment } = require('./secureshopProductUnionAssessment');
const { createSecureShopModeRepository } = require('../database/postgres/secureshopModeRepository');
const { createSecureShopModelQualifier } = require('./secureshopModelQualification');
const { createObjectiveJudge } = require('../agent-runtime/objectiveJudge');
const { createBoundProductSearchRouter } = require('../routes/secureshop/boundProductSearch');

function createProductSearchComposition({ identityPool, agentsPool, launches, conversations,
  journal, coordinator, provider, personaAuthority, personaBindings, receipts, progress,
  modeAuthority, customerChat, toolPolicyRepository, promptPolicyRepository,
  authenticatePersona, searchDependencies, judge, assertActorAvailable } = {}) {
  const service = searchDependencies?.service;
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
      || typeof customerChat?.captureProductSearch !== 'function'
      || typeof toolPolicyRepository?.admitTool !== 'function'
      || typeof promptPolicyRepository?.admitRunSnapshot !== 'function'
      || typeof authenticatePersona !== 'function'
      || typeof service?.provision !== 'function'
      || typeof service.searchProducts !== 'function'
      || typeof service.readProductSearchReceipt !== 'function'
      || typeof service.readProductSearchReference !== 'function'
      || judge !== undefined && typeof judge !== 'function'
      || assertActorAvailable !== undefined && typeof assertActorAvailable !== 'function')
    throw TypeError('Complete product search composition required');

  const application = createProductSearchApplication({
    captureCurrent: input => customerChat.captureProductSearch(input),
    personaAuthority, modeAuthority, launches, conversationRepository: conversations,
    journal, coordinator, provider,
    searchService: Object.freeze({
      provision: (scope, options) => service.provision(scope, options),
      searchProducts: (input, options) => service.searchProducts(input, options),
    }),
    agentsPool, promptPolicyRepository, toolPolicyRepository, assertActorAvailable,
  });
  const source = createProductUnionEvidenceRepository({ identityPool,
    conversationRepository: conversations,
    readSavedSource: (context, selectors) => application.readSavedSource(context, selectors),
    readProductSearchReceipt: (selectors, options) => service.readProductSearchReceipt(selectors, options),
    readProductSearchReference: (selectors, options) => service.readProductSearchReference(selectors, options),
  });
  const assessment = createProductUnionAssessment({ identityPool, agentsPool, launches,
    conversationRepository: conversations, coordinator, journal, personaAuthority,
    personaBindings, receipts, progress, publicationModes: createSecureShopModeRepository(identityPool),
    judge: judge || createObjectiveJudge(),
    current: (context, options) => application.current(context, options),
    readSource: (context, selectors) => source.readSource(context, selectors),
    qualifyModelTrace: createSecureShopModelQualifier(provider),
  });
  const router = createBoundProductSearchRouter({ launches, authenticatePersona,
    application, assessment });
  return Object.freeze({ ready: true, application, assessment, router });
}

module.exports = { createProductSearchComposition };
