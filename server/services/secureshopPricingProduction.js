'use strict';

const {
  createPricingTargetSource
} = require('./secureshopPricingTargetSource');
const {
  createPricingRunBinding
} = require('./secureshopPricingRunBinding');
const {
  createPricingRepository
} = require('../database/postgres/secureshopPricingRepository');
const {
  createBoundAuditStore
} = require('../database/postgres/secureshopBoundAuditRepository');
const {
  createPricingHttpClient
} = require('./secureshopPricingHttpClient');
const {
  createSecureShopPricingComposition
} = require('./secureshopPricingComposition');
const {
  createBoundPricingRouter
} = require('../routes/secureshop/boundPricing');
const { createPricingHistoryRepository } = require('../database/postgres/secureshopPricingHistoryRepository');

// Coherent opt-in production assembly, not mounted by index/gateway. Readiness
// checks the actual candidate schema and private executor before returning a
// router. No request can choose its pools, target source, provider or bearer.
async function createSecureShopPricingProduction({
  enabled = false,
  identityPool,
  agentsPool,
  reviewPool,
  resetComposition,
  catalog,
  productRepository,
  personaAuthority,
  provider,
  promptPolicyRepository,
  toolPolicyRepository,
  createAssessmentFactory,
  authenticatePersona,
  client,
  baseURL,
  token,
  mode = 'vuln', modeAuthority
} = {}) {
  if (typeof enabled !== 'boolean') throw TypeError('Explicit pricing feature flag required');
  if (!enabled) return Object.freeze({
    ready: false
  });
  const source = createPricingTargetSource({
    catalog,
    productRepository,
    reviewPool,
    launches: resetComposition?.launches,
    personaAuthority,
    historyRepository: createPricingHistoryRepository({ pool:reviewPool,
      checkCurrent:scope=>resetComposition.launches.assertCurrent(scope) })
  });
  const repository = createPricingRepository({
    pool: agentsPool,
    personaAuthority,
    audit: createBoundAuditStore({
      store: 'agents',
      pool: agentsPool
    }),
    checkRunBinding: createPricingRunBinding({
      identityPool
    }),
    captureTarget: source.capture
  });
  const executor = client || createPricingHttpClient({
    baseURL,
    token
  });
  const application = await createSecureShopPricingComposition({
    enabled: true,
    pricingRepository: repository,
    executor,
    resetComposition,
    personaAuthority,
    provider,
    promptPolicyRepository,
    toolPolicyRepository,
    createAssessmentFactory,
    prepareTarget: source.prepare,
    readHistory: source.readHistory,
    mode, modeAuthority
  });
  const router = createBoundPricingRouter({
    application,
    authenticatePersona
  });
  return Object.freeze({
    ready: true,
    application,
    repository,
    router
  });
}
module.exports = {
  createSecureShopPricingProduction
};
