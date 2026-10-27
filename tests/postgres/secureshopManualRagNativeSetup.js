'use strict';
// Shared setup only. Callers own the actual workflow, evidence and cleanup.
const assert=require('node:assert/strict');
const path=require('node:path');
const {randomBytes}=require('node:crypto');
const {migrate}=require('../../db/postgres/migrate');
const ROOT=path.resolve(__dirname,'../..');
async function migrateManualRagStores(pools) {
for (const [store, directory] of [['IDENTITY', 'identity-migrations'],
  ['AGENTS', 'workshop-migrations/secureshop_agents'],
  ['REVIEW', 'workshop-migrations/secureshop_review'],
  ['COMMERCE', 'workshop-migrations/secureshop']])
  await migrate(pools[`${store}_MIGRATION`], path.join(ROOT, 'db/postgres', directory));
await require('../../server/database/postgres/workshopPlatformSeed')
  .seedWorkshopPlatform(pools.IDENTITY_MIGRATION);
await require('../../server/database/postgres/secureshopAssessmentSeed')
  .seedSecureShopAssessmentDefaults(pools.IDENTITY_MIGRATION);
await require('../../server/database/postgres/secureshopStandaloneSeed')
  .seedSecureShopStandaloneDefaults(pools.IDENTITY_MIGRATION);
const seed = await pools.COMMERCE_MIGRATION.connect();
try { await seed.query('BEGIN'); await require('../../server/database/postgres/secureshopSeed')
  .seedSecureShop(seed); await seed.query('COMMIT'); }
catch (error) { await seed.query('ROLLBACK'); throw error; } finally { seed.release(); }
}
async function createManualRagGrading({pools,urls,lifecycle,progress,judge}) {
const identity=pools.IDENTITY_RUNTIME,agents=pools.AGENTS_RUNTIME,review=pools.REVIEW_RUNTIME;
const grading = await require('../../server/services/secureshopGradingBootstrap')
  .createSecureShopGradingBootstrap({ identityPool: identity, agentsPool: agents,
    progress, resetComposition: lifecycle, judge,
    expectedIdentityDatabase: new URL(urls.IDENTITY_RUNTIME).pathname.slice(1),
    expectedAgentsDatabase: new URL(urls.AGENTS_RUNTIME).pathname.slice(1) });
const scenes = require('../../server/services/secureshopScenes').createSecureShopScenes({
  repository: require('../../server/database/postgres/secureshopSceneRepository')
    .createSecureShopSceneRepository({ pool: identity, launches: lifecycle.launches }),
  reviewPool: review, launches: lifecycle.launches });
return {grading,scenes};
}
async function createManualRagApplication({pools,lifecycle,grading,scenes,auth,provider,judge,audit}) {
const identity=pools.IDENTITY_RUNTIME,agents=pools.AGENTS_RUNTIME,review=pools.REVIEW_RUNTIME,commerce=pools.COMMERCE_RUNTIME;
const personaInboxFeature = require('../../server/services/secureshopPersonaInboxActivationPolicy')
  .activationPolicy(process.env).requested;
const modeRepository = require('../../server/database/postgres/secureshopModeRepository')
  .createSecureShopModeRepository(identity);
const toolPolicyRepository = require('../../server/database/postgres/secureshopBoundAclRepository')
  .createSecureShopBoundAclRepository({ personaAuthority: grading.personaAuthority,
    audit: audit.agents });
await require('../../server/database/postgres/secureshopBoundToolPolicyReadiness')
  .assertBoundToolPolicyReadiness(agents);
const composition = require('../../server/services/secureshopBoundReviewComposition')
  .createSecureShopBoundReviewComposition({ identityPool: identity, agentsPool: agents,
    reviewPool: review, commercePool: commerce, resetComposition: lifecycle,
    gradingBootstrap: grading, scenes, modeAuthority: lifecycle.modeAuthority,
    toolPolicyRepository, fixtures: [], personaInboxFeature,
    jwtSecret: randomBytes(32).toString('hex'), agentRuntime: { provider }, judge });
await composition.repositories.personas.ensureTemplates();
assert.equal(typeof composition.productAssist?.runSimilar, 'function');
const bootstrap = require('../../server/services/secureshopStandaloneBootstrap')
  .createSecureShopStandaloneBootstrap({ launches: composition.launches,
    personaAuth: composition.personaAuth, authService: auth });
const reset = require('../../server/services/secureshopStandaloneReset')
  .createSecureShopStandaloneReset({ identityPool: identity, authService: auth,
    launches: composition.launches, scenes,
    resetCoordinator: lifecycle.launchResetCoordinator,
    preflight: lifecycle.sceneResetPreflight });
const resetEnvelope = require('../../server/services/secureshopRegisteredAdminResetEnvelope')
  .createRegisteredAdminResetEnvelope({ activeKeyId: 'similar-owned',
    keys: new Map([['similar-owned', randomBytes(32)]]) });
const resetRepository = require('../../server/database/postgres/secureshopRegisteredAdminResetRepository')
  .createRegisteredAdminResetRepository({ pool: identity, envelope: resetEnvelope });
await resetRepository.checkReadiness();
const standalone = { service: auth, bootstrap, reset,
  registeredAdminReset: require('../../server/services/secureshopRegisteredAdminReset')
    .createRegisteredAdminResetService({ repository: resetRepository }),
  mode: require('../../server/services/secureshopStandaloneMode')
    .createSecureShopStandaloneMode({ authService: auth, repository: modeRepository }),
  assessmentObjectives: require('../../server/services/secureshopAssessmentCatalog')
    .createSecureShopAssessmentCatalog({ pool: identity, authService: auth }),
  assessmentProgress: require('../../server/services/secureshopAssessmentProgress')
    .createSecureShopAssessmentProgress({ repository:
      require('../../server/database/postgres/secureshopAssessmentProgressRepository')
        .createSecureShopAssessmentProgressRepository({ pool: identity }) }),
  assessmentRecovery: require('../../server/services/secureshopAssessmentRecovery')
    .createSecureShopAssessmentRecovery({ identityPool: identity, authService: auth,
      bootstrap, launches: composition.launches, personaAuth: composition.personaAuth,
      personaAuthority: grading.personaAuthority, modeAuthority: lifecycle.modeAuthority,
      scenes, judge }),
  cartImport: require('../../server/services/secureshopStandaloneCartImport')
    .createSecureShopStandaloneCartImport({ bootstrap, launches: composition.launches,
      personaAuth: composition.personaAuth, commerce: composition.commerce }) };
const publicCatalog = require('../../server/database/postgres/secureshopStorePublicCatalogRepository')
  .createSecureShopStorePublicCatalogRepository({ identityPool: identity,
    reviewPool: review, commercePool: commerce });
const bound = await require('../../server/services/secureshopBoundApplication')
  .createSecureShopBoundApplication({ engine: 'postgres', shopEnabled: true,
    applicationMode: 'standalone', authenticateToken: (_q, response) => response.sendStatus(401),
    audit: async () => {}, agentRuntime: {}, getComposition: async () =>
      ({ ...composition, standaloneAuth: standalone, publicCatalog }) });
assert.equal(bound.standaloneReadiness.ready, true);
assert.ok(Object.values(bound.standaloneReadiness.checks).every(value => value === true));
return {composition,bootstrap,reset,resetEnvelope,resetRepository,standalone,publicCatalog,bound,modeRepository,toolPolicyRepository};
}
module.exports={migrateManualRagStores,createManualRagGrading,createManualRagApplication};
