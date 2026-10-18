'use strict';

const {
  createHash
} = require('node:crypto');
const {
  createBoundConversationService
} = require('./secureshopBoundConversation');
const {
  createBoundTurns
} = require('./secureshopBoundTurns');
const {
  createBoundAgentRunner
} = require('./secureshopBoundAgentRunner');
const {
  projectSecureShopV46TraversalDestination
} = require('./secureshopV46TraversalDestination');
const {
  createLaunchScope
} = require('./secureshopConversationBinding');
const {
  SECURESHOP_CONVERSATION_PURPOSES: PURPOSES
} = require('./secureshopConversationPurpose');
const {
  executionScope,
  withSceneLease
} = require('./secureshopSceneBinding');
const {
  guardFeatureFence
} = require('./secureshopFeatureModeAuthority');
const {
  createSecureShopUploadExecutionConfig,
  UPLOAD_TOOL
} = require('./secureshopUploadExecutionConfig');
const PURPOSE = PURPOSES.avatarUpload;
const MAX_BYTES = 20 * 1024 * 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA = /^[a-f0-9]{64}$/;
const fail = (code, message) => Object.assign(new Error(message), {
  code
});
const derive = (label, parts) => {
  const h = createHash('sha256').update(JSON.stringify([label, ...parts])).digest('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-5${h.slice(13, 16)}-a${h.slice(17, 20)}-${h.slice(20, 32)}`;
};
function genuine(value) {
  if (!value || typeof value.provider !== 'string' || !value.provider || typeof value.model !== 'string' || !value.model || value.mocked !== false || value.fallback === true || /^(mock|fixture|scripted|fallback|unavailable)$/i.test(value.provider) || /^(mock|fixture|scripted|fallback|unavailable)$/i.test(value.model)) throw fail('UPLOAD_MODEL_UNAVAILABLE', 'A genuine upload model response is required');
  return value;
}
function attachment(input) {
  if (!Buffer.isBuffer(input?.bytes) || !input.bytes.length || input.bytes.length > MAX_BYTES || typeof input.filename !== 'string' || !input.filename || Buffer.byteLength(input.filename) > 4096 || /[\0\r\n]/.test(input.filename) || typeof input.mime !== 'string' || !input.mime || Buffer.byteLength(input.mime) > 1024 || /[\0\r\n]/.test(input.mime) || typeof input.public !== 'boolean') throw fail('INVALID_ARGUMENT', 'Invalid bound upload attachment');
  return Object.freeze({
    bytes: Buffer.from(input.bytes),
    filename: input.filename,
    mime: input.mime,
    public: input.public,
    byteCount: input.bytes.length,
    bodySha256: createHash('sha256').update(input.bytes).digest('hex')
  });
}
function traversalAttachment(input) {
  const physical = attachment(input);
  if (typeof input.logicalFilename !== 'string' || !input.logicalFilename.isWellFormed()
      || !input.logicalFilename || Buffer.byteLength(input.logicalFilename) > 4096
      || !input.logicalFilename.includes('....//') || /[\\\0\r\n]/.test(input.logicalFilename)) {
    throw fail('INVALID_ARGUMENT', 'Invalid traversal upload filename');
  }
  return Object.freeze({ ...physical, sourceFilename: physical.filename, filename: input.logicalFilename });
}
function exactEmpty(value) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype || Reflect.ownKeys(value).length) throw fail('INVALID_ARGUMENT', 'Upload tool arguments must be empty');
}
function graphReceipt(observation, execution, requestId) {
  const r = observation?.effectReceipt,
    key = `${requestId}:${JSON.stringify([observation?.step, observation?.callId, UPLOAD_TOOL])}`;
  if (observation?.tool !== UPLOAD_TOOL || !Number.isSafeInteger(observation.step) || observation.step < 1 || typeof observation.callId !== 'string' || !observation.callId || !r || r.status !== 'completed' || r.runId !== execution.runId || r.ownerKey !== execution.ownerKey || String(r.generation) !== String(execution.durableGeneration) || r.effectKey !== key) throw fail('BOUND_UPLOAD_EFFECT_MISMATCH', 'Upload graph effect receipt changed');
  return Object.freeze({
    runId: r.runId,
    ownerKey: r.ownerKey,
    generation: String(r.generation),
    effectKey: r.effectKey,
    status: 'completed',
    step: observation.step,
    callId: observation.callId
  });
}
function createSecureShopBoundUploadGraph({
  launches,
  conversationRepository,
  journal,
  coordinator,
  provider,
  uploadApplication,
  uploadJournal,
  personaAuthority,
  modeAuthority,
  toolPolicyRepository,
  promptPolicyRepository,
  assetOrigin,
  assetCapability,
  resolveTarget,
  assertUploadCurrent,
  verifyEffect,
  traversal = false,
  runnerFactory = createBoundAgentRunner
} = {}) {
  if (typeof traversal !== 'boolean') throw new TypeError('Bound upload graph variant required');
  if (typeof verifyEffect !== 'function' || typeof resolveTarget !== 'function' || typeof assertUploadCurrent !== 'function' || typeof assetOrigin !== 'string' || !/^[a-z]+:\/\/[^/]+$/.test(assetOrigin) || typeof assetCapability?.mint !== 'function') throw new TypeError('Bound upload asset origin required');
  for (const [value, method] of [[launches, 'assertCurrent'], [coordinator, 'run'], [provider, 'chat'], [provider, 'finalResponse'], [uploadApplication, 'execute'], [uploadJournal, 'claim'], [personaAuthority, 'capture'], [modeAuthority, 'capture'], [modeAuthority, 'assertToken'], [toolPolicyRepository, 'admitTool']]) if (typeof value?.[method] !== 'function') throw new TypeError('Bound upload graph dependencies required');
  const conversations = createBoundConversationService({
    conversations: conversationRepository,
    launches
  });
  const turns = createBoundTurns({
    conversations,
    coordinator
  });
  return Object.freeze({
    purpose: PURPOSE,
    async createSession(input = {}) {
      input.signal?.throwIfAborted();
      const scope = createLaunchScope(input.scope);
      if (input.persona?.role !== 'customer' || !Number.isSafeInteger(input.persona.id) || input.persona.id < 1) throw fail('INVALID_ARGUMENT', 'Invalid bound upload persona');
      const result = await conversations.create(scope, input.persona, PURPOSE);
      input.signal?.throwIfAborted();
      return result;
    },
    async run(input = {}) {
      input.signal?.throwIfAborted();
      const scope = createLaunchScope(input.scope);
      await launches.assertCurrent(scope);
      const target = await resolveTarget(scope);
      const execution = executionScope(target);
      if (!target?.scene || ['launchId', 'scenarioId', 'generation', 'platformOwnerId', 'platformSessionId'].some(k => execution[k] !== scope[k])) throw fail('SHOP_AUTH_INVALID', 'Upload scene unavailable');
      if (input.persona?.role !== 'customer' || !Number.isSafeInteger(input.persona.id) || input.persona.id < 1 || !UUID.test(input.sessionId || '') || !UUID.test(input.requestId || '') || typeof input.message !== 'string' || !input.message.trim()) throw fail('INVALID_ARGUMENT', 'Invalid bound upload request');
      const file = traversal ? traversalAttachment(input.attachment) : attachment(input.attachment);
      const operationId = derive(traversal ? 'bound-upload-traversal-v1' : 'bound-upload-v1', [scope, input.persona.id, input.personaSession?.sessionId, input.requestId, file.filename, file.mime, file.public, file.bodySha256]);
      const storageKey = derive(traversal ? 'bound-upload-traversal-storage-v1' : 'bound-upload-storage-v1', [operationId]);
      const modeToken = modeAuthority.assertToken(await modeAuthority.capture(scope, 'uploads'));
      const fence = await personaAuthority.capture({
        scope,
        personaId: input.persona.id,
        role: 'customer',
        sessionId: input.personaSession?.sessionId,
        authorityVersion: input.personaSession?.authorityVersion
      });
      if (!fence?.binding || !target.scene) throw fail('SHOP_AUTH_INVALID', 'Bound upload authority unavailable');
      const guarded = guardFeatureFence(fence, modeToken);
      const mode = modeToken.snapshot;
      const rawAdmission = {
        operationId,
        uploadRequestId: input.requestId,
        storageKey,
        scope: {
          targetId: target.targetId,
          launchId: scope.launchId,
          scenarioId: scope.scenarioId,
          generation: scope.generation,
          platformOwnerId: scope.platformOwnerId,
          platformSessionId: scope.platformSessionId,
          sceneId: target.scene.sceneId,
          sceneGeneration: target.scene.sceneGeneration,
          grantId: target.scene.grantId,
          shopUserId: input.persona.id,
          personaSessionId: input.personaSession.sessionId,
          personaAuthorityVersion: String(input.personaSession.authorityVersion),
          mode: mode.mode,
          modeGeneration: mode.generation,
          modeStamp: mode.modeStamp
        },
        request: {
          kind: 'avatar',
          scopeId: input.persona.id,
          originalFilename: file.filename,
          declaredMime: file.mime,
          public: file.public,
          byteCount: file.byteCount,
          bodySha256: file.bodySha256
        }
      };
      await assertUploadCurrent(rawAdmission);
      input.signal?.throwIfAborted();
      const admitted = await uploadJournal.claim(rawAdmission);
      const envelope = JSON.stringify({
        version: traversal ? 2 : 1,
        message: input.message,
        attachment: {
          filename: file.filename,
          ...(traversal ? { sourceFilename: file.sourceFilename } : {}),
          mime: file.mime,
          byteCount: file.byteCount,
          bodySha256: file.bodySha256,
          public: file.public
        },
        bindingSha256: admitted.bindingSha256,
        operationId: admitted.operationId
      });
      await assertUploadCurrent(admitted);
      input.signal?.throwIfAborted();
      let completed = null,
        served = null,
        observed = null;
      const config = createSecureShopUploadExecutionConfig({
        filename: file.filename,
        byteCount: file.byteCount
      });
      const checkedProvider = {
        ...(provider.config ? {
          config: provider.config
        } : {}),
        async chat(args) {
          return genuine(await provider.chat({
            ...args,
            closedToolCatalog: true
          }));
        },
        async finalResponse(args) {
          return genuine(await provider.finalResponse(args));
        }
      };
      const runner = runnerFactory({
        turns,
        conversations,
        repository: conversationRepository,
        journal,
        provider: checkedProvider,
        pool: {
          async callTool() {
            throw fail('INVALID_ARGUMENT', 'External upload dispatch unavailable');
          }
        },
        ...config,
        conversationPurpose: PURPOSE,
        executionScope: 'turn',
        limits: {
          maxSteps: 2,
          maxParallelTools: 1
        },
        capturePersonaAuthority: () => guarded,
        personaLocalToolModes: {
          [UPLOAD_TOOL]: 'remote_admission'
        },
        toolPolicyAdmission: require('./secureshopBoundToolPolicyAdmission').createBoundToolPolicyAdmission({
          repository: toolPolicyRepository,
          workflow: 'avatar-upload',
          declaredTools: config.manifest.getForRole('customer')
        }),
        createLocalTools: async (_binding, _context, authority, execution) => new Map([[UPLOAD_TOOL, async (args, invocation) => {
          if (authority !== admitted) throw fail('INVALID_ARGUMENT', 'Upload attachment authority changed');
          exactEmpty(args);
          await execution.check();
          await assertUploadCurrent(admitted);
          const applied = await withSceneLease(target, () => uploadApplication.execute({
            admission: admitted,
            file,
            mode: mode.mode,
            execution,
            effectId: derive(traversal ? 'bound-upload-traversal-effect-v1' : 'bound-upload-effect-v1', [operationId, mode.mode])
          }));
          await assertUploadCurrent(admitted);
          completed = applied.effect;
          const ok = completed.outcome === 'completed';
          const traversalDestination = ok && traversal
            ? projectSecureShopV46TraversalDestination(completed.file, {
              storageKey: admitted.storageKey,
              shopUserId: admitted.scope.shopUserId
            }) : null;
          if (ok && !traversal) served = assetCapability.mint({
            effectId: completed.effectId,
            operationId: admitted.operationId,
            targetId: admitted.scope.targetId,
            generation: admitted.scope.generation,
            sceneId: admitted.scope.sceneId,
            sceneGeneration: admitted.scope.sceneGeneration,
            mode: admitted.scope.mode,
            modeGeneration: admitted.scope.modeGeneration,
            modeStamp: admitted.scope.modeStamp
          });
          return {
            content: [{
              type: 'text',
              text: JSON.stringify(ok ? {
                ok: true,
                kind: 'avatar',
                filename: file.filename,
                size_bytes: file.byteCount,
                ...(served ? { asset_url: `${assetOrigin}${served.path}` } : {
                  traversal: true,
                  operation_relative_path: traversalDestination.operationRelativePath,
                  escaped_avatar_subdirectory: traversalDestination.escapedAvatarSubdirectory
                })
              } : {
                ok: false,
                code: completed.denialCode || 'UPLOAD_UNAVAILABLE'
              })
            }],
            ...(ok ? {} : {
              isError: true
            }),
            _meta: {
              operationId,
              effectId: completed.effectId
            }
          };
        }]]),
        observeLocalTool: async packet => {
          if (packet.observation?.tool !== UPLOAD_TOOL) return;
          const meta = packet.observation.result?._meta;
          if (!completed || meta?.operationId !== operationId || meta?.effectId !== completed.effectId) throw fail('BOUND_UPLOAD_EFFECT_MISMATCH', 'Upload tool result changed');
          observed = graphReceipt(packet.observation, packet.run, input.requestId);
        },
        enterFinalResponseAfterLocalTool: () => true,
        resultMetadata: async packet => {
          if (!completed || !observed || packet.execution.runId !== observed.runId || packet.result.stopReason !== 'end_turn') throw fail('BOUND_UPLOAD_EFFECT_MISMATCH', 'Upload evidence unavailable');
          const traversalDestination = traversal && completed.outcome === 'completed'
            ? projectSecureShopV46TraversalDestination(completed.file, {
              storageKey: admitted.storageKey,
              shopUserId: admitted.scope.shopUserId
            }) : null;
          return {
            boundUpload: {
              version: traversal ? 2 : 1,
              ...(traversal ? { variant: 'path_traversal_upload' } : {}),
              originalEnvelope: envelope,
              traceEventIds: packet.traces.map(row => row.event_id),
              operationId,
              uploadRequestId: input.requestId,
              effectId: completed.effectId,
              outcome: completed.outcome,
              ...(traversalDestination || {}),
              ...(served ? {
                assetCapabilityExpiresAt: served.expiresAt,
                assetUrl: `${assetOrigin}${served.path}`
              } : {}),
              graphEffect: observed
            }
          };
        },
        captureResultTraces: true
      });
      const result = await runner.run({
        sessionId: input.sessionId,
        requestId: input.requestId,
        scope,
        persona: input.persona,
        personaSession: input.personaSession,
        message: envelope,
        signal: input.signal,
        localToolAuthority: admitted
      });
      await assertUploadCurrent(admitted);
      input.signal?.throwIfAborted();
      const savedEffect = await verifyEffect(admitted);
      if (!savedEffect || result.taskMetadata?.boundUpload?.effectId !== savedEffect.effectId || result.taskMetadata?.boundUpload?.outcome !== savedEffect.outcome || result.taskMetadata?.boundUpload?.operationId !== admitted.operationId) throw fail('BOUND_UPLOAD_EFFECT_MISMATCH', 'Saved upload changed');
      return result;
    }
  });
}
module.exports = {
  createSecureShopBoundUploadGraph,
  PURPOSE,
  UPLOAD_TOOL
};
