'use strict';

const { activationPolicy: personaInboxActivationPolicy } = require('./secureshopPersonaInboxActivationPolicy');
const { activationPolicy: mcpTrustActivationPolicy } = require('./secureshopMcpTrustActivationPolicy');
const { activationPolicy: ssrfActivationPolicy } = require('./secureshopSsrfProduction');
const { mountedReadiness, standaloneReadiness } = require('../routes/secureshopRuntimeReadiness');

// Compose the public application mounts only after database/bootstrap readiness.
// Neither this function nor the feature flag changes catalog visibility.
async function createSecureShopBoundApplication({ engine, shopEnabled, authenticateToken,
  audit, progress, agentRuntime, gradingCore, gradingBootstrap, promptPolicyRenderer, systemConfigClient, systemDiagnosticClient, systemRestartClient, pricingHttpClient, listingTemplateClient, uploadAssetOrigin, uploadAssetCapability,
  systemRebuildEnabled = false, applicationMode = 'full',
  fileSummaryFeature = false, filePathSummaryFeature = false,
  getComposition = require('./secureshopBoundReviewComposition').getSecureShopBoundReviewComposition,
} = {}) {
  if (engine !== 'postgres' || shopEnabled !== true
    || typeof authenticateToken !== 'function' || typeof audit !== 'function'
    || typeof getComposition !== 'function' || !agentRuntime) {
    throw new TypeError('Bound SecureShop requires PostgreSQL, enabled shop and platform authentication');
  }
  if (!['full', 'standalone'].includes(applicationMode)) throw new TypeError('Unknown SecureShop application mode');
  if (gradingCore !== undefined && gradingBootstrap !== undefined) {
    throw new TypeError('Choose one SecureShop grading configuration');
  }
  if (typeof systemRebuildEnabled !== 'boolean') throw new TypeError('Bound System rebuild option must be boolean');
  for (const requested of [fileSummaryFeature, filePathSummaryFeature]) {
    if (typeof requested !== 'boolean') throw new TypeError('Bound file lesson options must be boolean');
  }
  const personaInboxFeature = personaInboxActivationPolicy(process.env).requested;
  const mcpTrustFeature=mcpTrustActivationPolicy(process.env).requested;
  const ssrfFeature=ssrfActivationPolicy(process.env).requested;
  const auditSummaryFeature=process.env.SS_AUDIT_SUMMARY_ENABLED==='true';
  const composition = await getComposition({ agentRuntime,
    ...(promptPolicyRenderer === undefined ? {} : {promptPolicyRenderer}),
    ...(systemConfigClient === undefined ? {} : {systemConfigClient}),
    ...(systemDiagnosticClient === undefined ? {} : {systemDiagnosticClient}),
    ...(systemRestartClient === undefined ? {} : {systemRestartClient}),
    ...(pricingHttpClient === undefined ? {} : {pricingHttpClient}),
    ...(listingTemplateClient === undefined ? {} : {listingTemplateClient}),
    ...(uploadAssetOrigin === undefined ? {} : {uploadAssetOrigin}),
    ...(uploadAssetCapability === undefined ? {} : {uploadAssetCapability}),
    systemRebuildEnabled, fileSummaryFeature, filePathSummaryFeature,
    ...(gradingCore === undefined ? {} : {gradingCore}),
    ...(gradingBootstrap === undefined ? {} : { gradingBootstrap }), personaInboxFeature,mcpTrustFeature,ssrfFeature,auditSummaryFeature,
    ...(ssrfFeature?{ssrfFixtureRoot:process.env.SS_CONTROLLED_SSRF_FIXTURE_ROOT}:{}),
    ...(mcpTrustFeature?{mcpTrustFixtureRoot:process.env.SS_MCP_TRUST_FIXTURE_ROOT}:{}) });
  if (typeof composition?.launchResetCoordinator?.reset !== 'function'
      || typeof composition.launchResetCoordinator.recover !== 'function'
      || typeof composition?.ownerResetService?.assertReady !== 'function'
      || typeof composition?.ownerResetService?.resetOwner !== 'function'
      || typeof composition?.createStudentDeletionCleanup !== 'function'
      || typeof composition?.browserRouter !== 'function') {
    throw new TypeError('Bound SecureShop requires aggregate launch reset');
  }
  for (const [requested, name] of [[fileSummaryFeature, 'fileSummary'], [filePathSummaryFeature, 'filePathSummary']]) {
    if (requested && (composition?.[name]?.ready !== true || typeof composition[name].router !== 'function')) {
      throw new TypeError(`Bound ${name} service unavailable`);
    }
  }
  if(auditSummaryFeature && (typeof composition.auditSummary?.run!=='function'||typeof composition.auditSummary?.createSession!=='function'))
    throw new TypeError('Bound audit summary runtime unavailable');
  if (promptPolicyRenderer !== undefined && !composition.promptPolicies) throw new TypeError('Bound prompt policy service unavailable');
  if (systemConfigClient !== undefined && (composition.systemConfig?.ready !== true
      || typeof composition.systemConfig.router !== 'function')) {
    throw new TypeError('Bound System config service unavailable');
  }
  if (systemDiagnosticClient !== undefined && (composition.systemDiagnostic?.ready !== true
      || typeof composition.systemDiagnostic.router !== 'function')) {
    throw new TypeError('Bound System diagnostic service unavailable');
  }
  if (systemRestartClient !== undefined && (composition.systemRestart?.ready !== true
      || typeof composition.systemRestart.router !== 'function')) {
    throw new TypeError('Bound System restart service unavailable');
  }
  if (systemRebuildEnabled && (composition.systemRebuild?.ready !== true
      || typeof composition.systemRebuild.router !== 'function')) {
    throw new TypeError('Bound System rebuild service unavailable');
  }
  if (pricingHttpClient !== undefined && (composition.pricing?.ready !== true || typeof composition.pricing.router !== 'function')) throw new TypeError('Bound Pricing service unavailable');
  await composition.ownerResetService.assertReady();
  if (composition.standaloneAuth !== undefined
      && (typeof composition.standaloneAuth?.service?.authenticate !== 'function'
        || typeof composition.standaloneAuth?.bootstrap !== 'function')) {
    throw new TypeError('Standalone SecureShop authority unavailable');
  }
  const coreReadiness = applicationMode === 'standalone'
    ? standaloneReadiness(composition, { personaInboxFeature, mcpTrustFeature, ssrfFeature }) : null;
  const gateway = require('../routes/secureshop/boundGateway').createSecureShopBoundGateway({
    launches: composition.launches, authenticatePersona: composition.personaAuth?.authenticatePersona,
    standaloneAuth: composition.standaloneAuth?.service,
    personaAuth: composition.personaAuth, reviewsRouter: composition.router, catalog: composition.catalog,
    commerce: composition.commerce, account: composition.account, admin: composition.admin,
    ...(composition.scenes ? { scenes: composition.scenes } : {}),
    ...(composition.personaObservations ? { personaObservations: composition.personaObservations } : {}),
    ...(composition.userAdministration ? { userAdministration: composition.userAdministration } : {}),
    ...(composition.accessControl ? { accessControl: composition.accessControl } : {}),
    ...(composition.promptPolicies ? { promptPolicies: composition.promptPolicies,
      promptPolicyTaskTargets: composition.promptPolicyTaskTargets } : {}),
    ...(composition.systemConfig?.ready ? { systemConfigRouter: composition.systemConfig.router } : {}),
    ...(composition.systemDiagnostic?.ready === true ? { systemDiagnosticRouter: composition.systemDiagnostic.router } : {}),
    ...(composition.systemRebuild?.ready === true ? { systemRebuildRouter: composition.systemRebuild.router } : {}),
    ...(composition.systemRestart?.ready === true ? { systemRestartRouter: composition.systemRestart.router } : {}),
    ...(composition.analytics?.ready === true ? {analyticsRouter:composition.analytics.router} : {}),
    ...(composition.pricing?.ready === true ? {pricingRouter:composition.pricing.router} : {}),
    ...(composition.registeredInvocation?.ready === true ? {adminChatRouter:composition.registeredInvocation.router} : {}),
    ...(composition.ownedMcpRegistry?.ready === true ? {ownedMcpRegistryRouter:composition.ownedMcpRegistry.router} : {}),
    ...(composition.listings?.ready === true ? {listingsRouter:composition.listings.router} : {}),
    ...(composition.inventory?.ready === true ? {inventoryRouter:composition.inventory.router} : {}),
    ...(composition.mail?.ready === true ? {mailRouter:composition.mail.router} : {}),
    browserRouter: composition.browserRouter,
    ...(composition.auditSearch ? { auditSearch: composition.auditSearch,
      auditAgentReady: composition.auditAgentReady === true,
      auditTimingReady: composition.auditTimingReady === true } : {}),
    ...(composition.refund?.ready ? { refundRouter: composition.refund.router } : {}),
    ...(composition.customerChat?.ready ? { customerChatRouter: composition.customerChat.router } : {}),
    ...(composition.agencyRole?.ready ? { agencyRoleRouter: composition.agencyRole.router } : {}),
    ...(composition.idorLesson?.ready ? { idorLessonRouter: composition.idorLesson.router } : {}),
    ...(composition.checkoutAuditLesson?.ready ? { checkoutAuditLessonRouter: composition.checkoutAuditLesson.router } : {}),
    ...(composition.couponAgent?.ready ? { couponAgentRouter: composition.couponAgent.router } : {}),
    ...(composition.couponProbe?.ready === true ? { couponProbeRouter: composition.couponProbe.router } : {}),
    ...(composition.avatarUpload?.ready === true ? { avatarUploadRouter: composition.avatarUpload.router } : {}),
    ...(composition.fileSummary?.ready === true ? { fileSummaryRouter: composition.fileSummary.router } : {}),
    ...(composition.filePathSummary?.ready === true ? { filePathSummaryRouter: composition.filePathSummary.router } : {}),
    ...(composition.productSearch?.ready === true ? { productSearchRouter: composition.productSearch.router } : {}),
    ...(composition.orderStatus?.ready === true ? { orderStatusRouter: composition.orderStatus.router } : {}),
    ...(composition.ticketAgent?.ready ? { ticketAgentRouter: composition.ticketAgent.router } : {}),
    ...(composition.searchEcho?.ready ? { searchEchoRouter: composition.searchEcho.router } : {}),
    ...(composition.manualRag?.ready ? { manualRagRouter: composition.manualRag.router } : {}),
    ...(composition.productSummary?.ready ? { productSummaryRouter: composition.productSummary.router } : {}),
    ...(composition.roleAssistants?.merchant?.ready ? { merchantAssistantRouter: composition.roleAssistants.merchant.router } : {}),
    ...(composition.roleAssistants?.admin?.ready ? { adminAssistantRouter: composition.roleAssistants.admin.router } : {}),
    ...(composition.productManualIngestion ? { productManualIngestion: composition.productManualIngestion } : {}),
    ...(composition.accountAvatar ? { accountAvatar: composition.accountAvatar } : {}),
    ...(auditSummaryFeature ? { auditSummary: composition.auditSummary } : {}),
    ...(auditSummaryFeature && composition.auditUnbounded ? { auditUnbounded: composition.auditUnbounded } : {}),
    ...(composition.productAssist ? { productAssist: composition.productAssist } : {}),
    ...(composition.personaInbox?.ready ? { personaInboxRouter: composition.personaInbox.router } : {}),
    ...(composition.ssrf?.ready ? { ssrfRouter: composition.ssrf.router } : {}),
    ...(composition.mcpTrust?.ready ? { mcpTrustRouter: composition.mcpTrust.router } : {}),
  });
  const launchRouter = applicationMode === 'standalone' ? null : require('../routes/secureshopPlatformLaunch').createSecureShopLaunchRouter({
    enabled: true, engine, authenticateToken, audit, repository: composition.launches,
    resetCoordinator: composition.launchResetCoordinator, progress,
  });
  const readiness = applicationMode === 'full' ? mountedReadiness(composition) : null;
  return Object.freeze({ gateway, launchRouter, readiness,
    ...(coreReadiness ? { standaloneReadiness: coreReadiness } : {}),
    ...(composition.standaloneAuth ? { standaloneAuth: composition.standaloneAuth } : {}),
    ...(composition.publicCatalog ? { publicCatalog: composition.publicCatalog } : {}),
    ownerResetService: composition.ownerResetService,
    ...(composition.avatarUpload?.assetBackend ? { uploadAssetBackend: composition.avatarUpload.assetBackend } : {}),
    createStudentDeletionCleanup: composition.createStudentDeletionCleanup });
}

module.exports = { createSecureShopBoundApplication };
