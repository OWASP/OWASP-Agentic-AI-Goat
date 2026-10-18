'use strict';

function createSecureShopBoundUploadComposition({
  identityPool,
  agentsPool,
  reviewPool,
  launches,
  conversationRepository,
  journal,
  coordinator,
  provider,
  personaAuthority,
  modeAuthority,
  toolPolicyRepository,
  authenticatePersona,
  assetOrigin,
  assetCapability,
  uploadRepository,
  effectReader,
  assetRepository,
  writer,
  traversalWriter,
  resolveTarget,
  personaBindings,
  scenes,
  receipts,
  progress,
  publicationModes,
  judge,
  qualifyModel,
  svgBrowserQualification,
  uploadPreviewClient
} = {}) {
  if (typeof identityPool?.query !== 'function' || typeof agentsPool?.query !== 'function' || typeof reviewPool?.query !== 'function' || typeof authenticatePersona !== 'function' || typeof assetOrigin !== 'string' || typeof assetCapability?.mint !== 'function' || typeof assetRepository?.lookup !== 'function' || traversalWriter !== undefined && typeof traversalWriter?.writeAndReadBack !== 'function') throw new TypeError('Complete bound upload composition required');
  const repository = uploadRepository;
  if (typeof repository?.claim !== 'function' || typeof repository?.recordEffect !== 'function' || typeof repository?.recordServe !== 'function' || typeof effectReader?.find !== 'function') throw new TypeError('Bound upload journal unavailable');
  const assertCurrent = async admission => {
    const s = admission.scope;
    await launches.assertCurrent(s);
    const target = await resolveTarget(s);
    const current = require('./secureshopSceneBinding').executionScope(target);
    if (!target?.scene || target.targetId !== s.targetId || target.scene.sceneId !== s.sceneId || target.scene.sceneGeneration !== s.sceneGeneration || target.scene.grantId !== s.grantId || ['launchId', 'scenarioId', 'generation', 'platformOwnerId', 'platformSessionId'].some(k => current[k] !== s[k])) throw Object.assign(Error('Upload scene changed'), {
      code: 'SHOP_SCENE_STALE'
    });
    const token = modeAuthority.assertToken(await modeAuthority.capture(s, 'uploads')),
      snapshot = token.snapshot;
    if (snapshot.mode !== s.mode || snapshot.generation !== s.modeGeneration || snapshot.modeStamp !== s.modeStamp) throw Object.assign(Error('Upload mode changed'), {
      code: 'SHOP_MODE_CHANGED'
    });
    await token.assertCurrent();
    const fence = await personaAuthority.capture({
      scope: s,
      personaId: s.shopUserId,
      role: 'customer',
      sessionId: s.personaSessionId,
      authorityVersion: s.personaAuthorityVersion
    });
    const b = fence?.binding;
    if (!b || ['launchId', 'scenarioId', 'generation', 'platformOwnerId', 'platformSessionId'].some(k => b[k] !== s[k]) || b.personaId !== s.shopUserId || b.sessionId !== s.personaSessionId || String(b.authorityVersion) !== String(s.personaAuthorityVersion) || b.role !== 'customer') throw Object.assign(Error('Upload authority changed'), {
      code: 'SHOP_AUTH_INVALID'
    });
    await fence.assertRemoteAdmission();
  };
  const application = require('./secureshopBoundUploadApplication').createSecureShopBoundUploadApplication({
    effects: effectReader,
    writer,
    journal: repository
  });
  const reader = require('./secureshopUploadAssetReader').createSecureShopUploadAssetReader();
  const verifyEffect = async admission => {
    await assertCurrent(admission);
    const effect = await effectReader.find(admission);
    if (effect?.outcome === 'completed') await reader({
      storedVirtualPath: effect.file.storedVirtualPath,
      responseByteCount: effect.file.byteCount,
      responseSha256: effect.file.bodySha256
    });
    await assertCurrent(admission);
    return effect;
  };
  const graph = require('./secureshopBoundUploadGraph').createSecureShopBoundUploadGraph({
    launches,
    conversationRepository,
    journal,
    coordinator,
    provider,
    uploadApplication: application,
    uploadJournal: repository,
    personaAuthority,
    modeAuthority,
    toolPolicyRepository,
    assetOrigin,
    assetCapability,
    resolveTarget,
    assertUploadCurrent: assertCurrent,
    verifyEffect
  });
  let traversalReader, traversalGraph;
  if (traversalWriter) {
    traversalReader = require('./secureshopV46TraversalAssetReader').createSecureShopV46TraversalAssetReader();
    const traversalApplication = require('./secureshopV46TraversalApplication')
      .createSecureShopV46TraversalApplication({ effects: effectReader, writer: traversalWriter, journal: repository });
    const verifyTraversalEffect = async admission => {
      await assertCurrent(admission);
      const effect = await effectReader.find(admission);
      if (effect?.outcome === 'completed') {
        if (effect.file?.isTraversal !== true) throw Object.assign(Error('Traversal upload changed'), {
          code: 'BOUND_UPLOAD_EFFECT_MISMATCH'
        });
        await traversalReader({ storedVirtualPath: effect.file.storedVirtualPath,
          responseByteCount: effect.file.byteCount, responseSha256: effect.file.bodySha256 });
      }
      await assertCurrent(admission);
      return effect;
    };
    traversalGraph = require('./secureshopBoundUploadGraph').createSecureShopBoundUploadGraph({
      launches,conversationRepository,journal,coordinator,provider,uploadApplication:traversalApplication,
      uploadJournal:repository,personaAuthority,modeAuthority,toolPolicyRepository,assetOrigin,assetCapability,
      resolveTarget,assertUploadCurrent:assertCurrent,verifyEffect:verifyTraversalEffect,traversal:true
    });
  }
  const saved = require('./secureshopBoundUploadSavedOperation').createSecureShopBoundUploadSavedOperation({
    pool: reviewPool,
    assertCurrent,
    effects: effectReader,
    capability: assetCapability,
    assetOrigin
  });
  const assessmentJournal = Object.freeze({...journal,
    ...require('../database/postgres/secureshopV06UploadTurnReader')
      .createV06UploadTurnReader({pool:agentsPool})});
  const sourceReader = require('./secureshopV06UploadSourceReader').createV06UploadSourceReader({
    assets:assetRepository,assertCurrent,read:reader,
  });
  const assessment = require('./secureshopV06UploadAssessment').createV06UploadAssessment({
    identityPool,agentsPool,launches,conversationRepository,coordinator,
    journal:assessmentJournal,personaAuthority,personaBindings,scenes,modeAuthority,
    sourceReader,receipts,progress,publicationModes,judge,qualifyModel,
  });
  let traversalAssessment;
  if (traversalGraph) {
    const traversalRepository = require('../database/postgres/secureshopV46TraversalRepository')
      .createSecureShopV46TraversalRepository(reviewPool);
    const traversalSourceReader = require('./secureshopV46TraversalSourceReader').createV46TraversalSourceReader({
      assets: traversalRepository, assertCurrent, read: traversalReader
    });
    traversalAssessment = require('./secureshopV46TraversalAssessment').createSecureShopV46TraversalAssessment({
      identityPool,agentsPool,launches,conversationRepository,coordinator,
      journal:assessmentJournal,personaAuthority,personaBindings,scenes,modeAuthority,
      sourceReader:traversalSourceReader,receipts,progress,publicationModes,judge,qualifyModel,
    });
  }
  const ownedSvgBrowser = svgBrowserQualification === undefined;
  svgBrowserQualification ||= require('./secureshopSvgAssetBrowserQualification')
    .createSecureShopSvgAssetBrowserQualification({assetOrigin});
  const svgSourceReader = require('./secureshopV08SvgSourceReader').createV08SvgSourceReader({
    identityPool,conversationRepository,journal:assessmentJournal,assets:assetRepository,
    assertCurrent,read:reader,capability:assetCapability,assetOrigin,qualifyModel,
  });
  const svgAssessment = require('./secureshopV08SvgAssessment').createV08SvgAssessment({
    identityPool,agentsPool,launches,conversationRepository,coordinator,
    journal:assessmentJournal,personaAuthority,personaBindings,scenes,modeAuthority,
    sourceReader:svgSourceReader,receipts,progress,publicationModes,judge,qualifyModel,
    browserQualification:svgBrowserQualification,
  });
  let polyglotPreview, polyglotAssessment;
  if (uploadPreviewClient !== undefined) {
    const polyglotSource = require('./secureshopV07UploadSourceReader').createV07UploadSourceReader({
      identityPool,agentsPool,assets:assetRepository,assertCurrent,read:reader,
      journal:assessmentJournal,conversationRepository,qualifyModel
    });
    polyglotPreview = require('./secureshopV07UploadPreviewGraph').createV07UploadPreviewGraph({
      identityPool,agentsPool,launches,conversationRepository,journal:assessmentJournal,
      coordinator,provider,personaAuthority,modeAuthority,publicationModes,toolPolicyRepository,scenes,
      sourceReader:polyglotSource,client:uploadPreviewClient
    });
    polyglotAssessment = require('./secureshopV06UploadAssessment').createV06UploadAssessment({
      identityPool,agentsPool,launches,conversationRepository,coordinator,
      journal:assessmentJournal,personaAuthority,personaBindings,scenes,modeAuthority,
      sourceReader:polyglotSource,receipts,progress,publicationModes,judge,qualifyModel,
      evidenceContract:require('./secureshopV07UploadEvidence').evidenceContract
    });
  }
  const router = require('../routes/secureshop/boundAvatarUpload').createBoundAvatarUploadRouter({
    launches,
    authenticatePersona,
    graph,
    traversalGraph,
    saved,
    assessment,
    traversalAssessment,
    svgAssessment,polyglotPreview,polyglotAssessment
  });
  return Object.freeze({
    ready: true,
    graph,
    traversalGraph,
    router,
    assessment,
    traversalAssessment,
    svgAssessment,polyglotPreview,polyglotAssessment,
    async close() { if (ownedSvgBrowser) await svgBrowserQualification.close(); },
    assetBackend: Object.freeze({
      capability: assetCapability,
      lookup: assetRepository.lookup,
      assertCurrent,
      recordServe: (...args) => repository.recordServe(...args)
    })
  });
}
module.exports = {
  createSecureShopBoundUploadComposition
};
