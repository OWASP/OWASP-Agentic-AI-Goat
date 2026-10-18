'use strict';

const { createHash } = require('node:crypto');
const { isDeepStrictEqual: equal } = require('node:util');
const { posix } = require('node:path');
const { createBoundConversationService } = require('./secureshopBoundConversation');
const { createBoundTurns } = require('./secureshopBoundTurns');
const { createBoundAgentRunner } = require('./secureshopBoundAgentRunner');
const { createLaunchScope, createConversationBinding } = require('./secureshopConversationBinding');
const { executionScope, withSceneLease } = require('./secureshopSceneBinding');
const { captureFeatureMode, guardFeatureFence } = require('./secureshopFeatureModeAuthority');
const { createBoundToolPolicyAdmission } = require('./secureshopBoundToolPolicyAdmission');
const { canonicalDigest } = require('./mcp/protocolContext');
const {
  SUMMARY_TOOL,
  validPath,
  createFilePathSummaryExecutionConfig,
} = require('./secureshopV44FilePathSummaryExecutionConfig');

const PURPOSE = 'secureshop_file_path_summary';
const FEATURE = 'file_path_summary';
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA = /^[a-f0-9]{64}$/;
const fail = code => Object.assign(new Error('Bound file path summary unavailable'), { code });
const digest = value => createHash('sha256').update(value).digest('hex');

function genuine(value) {
  if (!value || typeof value.provider !== 'string' || !value.provider
      || typeof value.model !== 'string' || !value.model || value.mocked !== false || value.fallback === true
      || /^(mock|fixture|scripted|fallback|unavailable)$/i.test(value.provider)
      || /^(mock|fixture|scripted|fallback|unavailable)$/i.test(value.model)) {
    throw fail('FILE_PATH_SUMMARY_MODEL_UNAVAILABLE');
  }
  return value;
}

function exactPathArgs(value, expected) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype
      || Reflect.ownKeys(value).length !== 1 || value.path !== expected || !validPath(value.path)) {
    throw fail('FILE_PATH_SUMMARY_INVALID_ARGUMENT');
  }
}

function prepare(input) {
  const binding = createConversationBinding(input.scope, input.persona);
  const scope = createLaunchScope(binding);
  if (binding.role !== 'customer' || !UUID.test(input.sessionId || '') || !UUID.test(input.requestId || '')
      || !UUID.test(input.personaSession?.sessionId || '')
      || typeof input.personaSession.authorityVersion !== 'string'
      || !/^[1-9][0-9]{0,18}$/.test(input.personaSession.authorityVersion)
      || typeof input.message !== 'string' || !input.message.trim() || !input.message.isWellFormed()
      || input.message.includes('\0') || Buffer.byteLength(input.message) > 8192 || !validPath(input.path)) {
    throw fail('FILE_PATH_SUMMARY_INVALID_ARGUMENT');
  }
  const ref = Object.freeze({
    scope,
    persona: Object.freeze({ id: binding.shopUserId, role: 'customer' }),
    personaSession: Object.freeze({
      sessionId: input.personaSession.sessionId.toLowerCase(),
      authorityVersion: input.personaSession.authorityVersion,
    }),
    sessionId: input.sessionId.toLowerCase(),
    requestId: input.requestId.toLowerCase(),
  });
  const bytes = createHash('sha256').update(JSON.stringify(['owned-file-path-summary-v1', ref])).digest();
  bytes[6] = bytes[6] & 15 | 80;
  bytes[8] = bytes[8] & 63 | 128;
  const hex = bytes.subarray(0, 16).toString('hex');
  const operationId = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  return Object.freeze({ ref, binding, operationId, path: input.path });
}

function graphReceipt(observation, execution, requestId) {
  const receipt = observation?.effectReceipt;
  if (observation?.tool !== SUMMARY_TOOL || !Number.isSafeInteger(observation.step) || observation.step < 1
      || typeof observation.callId !== 'string' || !observation.callId || receipt?.status !== 'completed'
      || receipt.runId !== execution.runId || receipt.ownerKey !== execution.ownerKey
      || String(receipt.generation) !== String(execution.durableGeneration)
      || receipt.effectKey !== `${requestId}:${JSON.stringify([observation.step, observation.callId, SUMMARY_TOOL])}`) {
    throw fail('FILE_PATH_SUMMARY_EFFECT_MISMATCH');
  }
  return Object.freeze({
    runId: receipt.runId,
    ownerKey: receipt.ownerKey,
    generation: String(receipt.generation),
    effectKey: receipt.effectKey,
    status: 'completed',
    step: observation.step,
    callId: observation.callId,
  });
}

function retainedReceipt(source, physical, authority) {
  if (!physical || typeof physical.targetId !== 'string' || !UUID.test(physical.targetId)
      || physical.launchId !== source.ref.scope.launchId || typeof physical.scenarioId !== 'string'
      || !UUID.test(physical.scenarioId) || physical.generation !== source.ref.scope.generation
      || physical.virtualPath !== posix.resolve('/uploads', source.path)
      || !Number.isSafeInteger(physical.bytes) || physical.bytes < 1 || physical.bytes > 256 * 1024
      || !SHA.test(physical.sha256) || !Buffer.isBuffer(physical.data)
      || physical.bytes !== physical.data.length || digest(physical.data) !== physical.sha256) {
    throw fail('FILE_PATH_SUMMARY_EFFECT_MISMATCH');
  }
  const body = Object.freeze({
    version: 1,
    operationId: source.operationId,
    requestedPath: source.path,
    resolvedPath: physical.virtualPath,
    targetId: physical.targetId,
    launchId: physical.launchId,
    scenarioId: physical.scenarioId,
    generation: physical.generation,
    byteCount: physical.bytes,
    bodySha256: physical.sha256,
    authority,
  });
  return Object.freeze({ ...body, receiptSha256: canonicalDigest(body) });
}

function createBoundFilePathSummaryGraph({
  launches,
  conversationRepository,
  journal,
  coordinator,
  provider,
  files,
  personaAuthority,
  modeAuthority,
  scenes,
  toolPolicyRepository,
  runnerFactory = createBoundAgentRunner,
  toolPolicyAdmissionFactory = createBoundToolPolicyAdmission,
} = {}) {
  for (const [object, method] of [
    [launches, 'assertCurrent'], [coordinator, 'run'], [provider, 'chat'], [provider, 'finalResponse'],
    [launches, 'reserveFilesTarget'], [files, 'provisionReservedTarget'], [files, 'readFile'],
    [personaAuthority, 'capture'], [modeAuthority, 'capture'],
    [modeAuthority, 'assertToken'], [scenes, 'readExisting'], [toolPolicyRepository, 'admitTool'],
  ]) if (typeof object?.[method] !== 'function') throw new TypeError('Bound file-path summary dependencies required');

  const conversations = createBoundConversationService({ conversations: conversationRepository, launches });
  const turns = createBoundTurns({ conversations, coordinator });
  return Object.freeze({
    purpose: PURPOSE,
    async createSession(input) {
      input.signal?.throwIfAborted();
      if (input.persona?.role !== 'customer') throw fail('FILE_PATH_SUMMARY_INVALID_ARGUMENT');
      const result = await conversations.create(createLaunchScope(input.scope), input.persona, PURPOSE);
      input.signal?.throwIfAborted();
      return result;
    },
    async run(input) {
      input.signal?.throwIfAborted();
      const source = prepare(input);
      const { ref } = source;
      await launches.assertCurrent(ref.scope);
      const target = await scenes.readExisting(source.binding);
      if (!target?.scene || !equal(createLaunchScope(executionScope(target)), ref.scope)) {
        throw fail('FILE_PATH_SUMMARY_AUTHORITY');
      }
      const mode = await captureFeatureMode(modeAuthority, ref.scope, FEATURE);
      if (mode.snapshot.featureId !== FEATURE || !equal(mode.snapshot.scope, ref.scope)
          || !['vuln', 'fixed'].includes(mode.snapshot.mode)) throw fail('FILE_PATH_SUMMARY_AUTHORITY');
      const fence = await personaAuthority.capture({ scope: ref.scope, personaId: ref.persona.id,
        role: 'customer', ...ref.personaSession });
      const expected = { ...ref.scope, personaId: ref.persona.id, role: 'customer', ...ref.personaSession };
      if (!Object.keys(expected).every(key => fence?.binding?.[key] === expected[key])) {
        throw fail('FILE_PATH_SUMMARY_AUTHORITY');
      }
      const guarded = guardFeatureFence(fence, mode);
      const authority = Object.freeze({ ...ref, scene: structuredClone(target.scene),
        sceneTargetId: target.targetId, mode: structuredClone(mode.snapshot) });
      const check = async () => {
        input.signal?.throwIfAborted();
        await launches.assertCurrent(ref.scope);
        await guarded.assertRemoteAdmission();
        const current = await scenes.readExisting(source.binding);
        if (!current?.scene || current.targetId !== target.targetId || !equal(current.scene, target.scene)
            || !equal(createLaunchScope(executionScope(current)), ref.scope)) throw fail('FILE_PATH_SUMMARY_AUTHORITY');
        input.signal?.throwIfAborted();
      };
      const checkAtEffect = async () => {
        input.signal?.throwIfAborted();
        await launches.assertCurrent(ref.scope);
        await (mode.assertCurrentAtEffect || mode.assertCurrent).call(mode);
        const current = await scenes.readExisting(source.binding);
        if (!current?.scene || current.targetId !== target.targetId || !equal(current.scene, target.scene)
            || !equal(createLaunchScope(executionScope(current)), ref.scope)) throw fail('FILE_PATH_SUMMARY_AUTHORITY');
        input.signal?.throwIfAborted();
      };
      await check();
      const envelope = JSON.stringify({ version: 1, message: input.message, path: source.path,
        operationId: source.operationId, authoritySha256: canonicalDigest(authority) });
      const config = createFilePathSummaryExecutionConfig({ mode: mode.snapshot.mode });
      let selected = false;
      let denied = false;
      let physical = null;
      let readReceipt = null;
      let observed = null;
      let toolResultSha256 = null;
      let localFailure = null;
      const checkedProvider = {
        ...(provider.config ? { config: provider.config } : {}),
        async chat(args) {
          await check();
          const out = genuine(await provider.chat({ ...args, closedToolCatalog: true }));
          await check();
          return out;
        },
        async finalResponse(args) {
          await check();
          const out = genuine(await provider.finalResponse(args));
          await check();
          return out;
        },
      };
      const runner = runnerFactory({
        turns,
        conversations,
        repository: conversationRepository,
        journal,
        provider: checkedProvider,
        ...config,
        conversationPurpose: PURPOSE,
        executionScope: 'turn',
        limits: { maxSteps: 2, maxParallelTools: 1 },
        capturePersonaAuthority: () => guarded,
        pool: { async callTool() { throw fail('FILE_PATH_SUMMARY_EXTERNAL_DISPATCH_FORBIDDEN'); } },
        personaLocalToolModes: { [SUMMARY_TOOL]: 'remote_admission' },
        toolPolicyAdmission: toolPolicyAdmissionFactory({ repository: toolPolicyRepository,
          workflow: 'file-path-summary', declaredTools: config.manifest.getForRole('customer') }),
        createLocalTools: async (_binding, _context, supplied, execution) => {
          return new Map([[SUMMARY_TOOL, async args => {
            try {
              exactPathArgs(args, source.path);
              if (supplied !== source || selected) throw fail('FILE_PATH_SUMMARY_EFFECT_REPLAY_FORBIDDEN');
              selected = true;
              if (mode.snapshot.mode === 'fixed'
                  && !posix.resolve('/uploads', source.path).startsWith('/uploads/')) {
                denied = true;
                const result = Object.freeze({ content: Object.freeze([Object.freeze({ type: 'text',
                  text: JSON.stringify({ path: source.path,
                    error: 'path outside owned uploads directory' }) })]) });
                toolResultSha256 = canonicalDigest(result);
                return result;
              }
              // Reservation/provisioning can lock the identity launch row. Do
              // both before the scene lease so no second connection attempts a
              // lock upgrade while the scene repository holds FOR SHARE.
              await execution.check();
              await checkAtEffect();
              const reserved = await launches.reserveFilesTarget({
                platformSessionId: ref.scope.platformSessionId,
                platformOwnerId: ref.scope.platformOwnerId,
                launchId: ref.scope.launchId,
                expectedGeneration: ref.scope.generation,
              });
              await checkAtEffect();
              const binding = Object.freeze({ targetId: reserved?.targetId,
                launchId: reserved?.launchId, scenarioId: reserved?.scenarioId,
                generation: reserved?.generation, ownerId: String(ref.scope.platformOwnerId) });
              if (reserved?.kind !== 'files' || binding.launchId !== ref.scope.launchId
                  || binding.scenarioId !== ref.scope.scenarioId
                  || binding.generation !== ref.scope.generation || !UUID.test(binding.targetId || '')) {
                throw fail('FILE_PATH_SUMMARY_EFFECT_MISMATCH');
              }
              const provisioned = await files.provisionReservedTarget(binding);
              await checkAtEffect();
              if (!Object.keys(binding).every(key => provisioned?.[key] === binding[key])
                  || typeof provisioned.capability !== 'string' || !provisioned.capability) {
                throw fail('FILE_PATH_SUMMARY_EFFECT_MISMATCH');
              }
              const file = await withSceneLease(target, () => files.readFile(provisioned.capability,
                source.path, { base: '/uploads', expectedGeneration: binding.generation,
                  maxBytes: 256 * 1024 }));
              await checkAtEffect();
              await execution.check();
              // Validate the reader's generation before overlaying the reserved
              // binding; otherwise a stale physical result inherits a fresh
              // generation and can manufacture a current receipt.
              if (!file || file.generation !== binding.generation
                  || !Buffer.isBuffer(file.data)
                  || file.virtualPath !== posix.resolve('/uploads', source.path)
                  || !Number.isSafeInteger(file.bytes) || file.bytes < 1 || file.bytes > 256 * 1024
                  || file.bytes !== file.data.length || !SHA.test(file.sha256 || '')
                  || digest(file.data) !== file.sha256) {
                throw fail('FILE_PATH_SUMMARY_EFFECT_MISMATCH');
              }
              physical = Object.freeze({ ...binding, virtualPath: file.virtualPath,
                bytes: file.bytes, sha256: file.sha256, data: Buffer.from(file.data) });
              readReceipt = retainedReceipt(source, physical, authority);
              const body = new TextDecoder('utf-8', { fatal: true }).decode(physical.data);
              if (body.includes('\0')) throw fail('FILE_PATH_SUMMARY_EFFECT_MISMATCH');
              const result = Object.freeze({ content: Object.freeze([Object.freeze({ type: 'text',
                text: JSON.stringify({ path: source.path,
                  cleaned_path: source.path.replace(/\.\.\//g, ''),
                  extension: posix.extname(source.path).toLowerCase(), body,
                  summary: `File ${source.path} contents:\n\n${body}` }) })]) });
              toolResultSha256 = canonicalDigest(result);
              return result;
            } catch (error) {
              localFailure = error;
              throw error;
            }
          }]]);
        },
        observeLocalTool: async packet => {
          if (localFailure) throw localFailure;
          if (packet.observation?.tool !== SUMMARY_TOOL || denied === Boolean(readReceipt)
              || canonicalDigest(packet.observation.result) !== toolResultSha256) {
            throw fail('FILE_PATH_SUMMARY_EFFECT_MISMATCH');
          }
          observed = graphReceipt(packet.observation, packet.run, ref.requestId);
        },
        enterFinalResponseAfterLocalTool: ({ observation, execution }) => {
          if (!selected || !observed || localFailure || observation.tool !== SUMMARY_TOOL
              || execution.runId !== observed.runId || observation.callId !== observed.callId
              || observation.step !== observed.step || !equal(observation.args, { path: source.path })
              || denied === Boolean(readReceipt)
              || canonicalDigest(observation.result) !== toolResultSha256) {
            throw fail('FILE_PATH_SUMMARY_EFFECT_MISMATCH');
          }
          return true;
        },
        resultMetadata: async packet => {
          await check();
          if (localFailure) throw localFailure;
          if (packet.result.stopReason !== 'end_turn'
              || selected && (!observed || packet.execution.runId !== observed.runId
                || denied === Boolean(readReceipt))) {
            throw fail('FILE_PATH_SUMMARY_EFFECT_MISMATCH');
          }
          return { boundFilePathSummary: {
            version: 1,
            originalEnvelope: envelope,
            operationId: source.operationId,
            outcome: selected && !denied ? 'read' : 'no_tool',
            traceEventIds: packet.traces.map(row => row.event_id),
            ...(selected && !denied ? { readReceipt, graphEffect: observed, toolResultSha256 } : {}),
          } };
        },
        captureResultTraces: true,
      });
      const result = await runner.run({ ...ref, message: envelope, signal: input.signal, localToolAuthority: source });
      await check();
      const saved = result.taskMetadata?.boundFilePathSummary;
      if (saved?.version !== 1 || saved.originalEnvelope !== envelope || saved.operationId !== source.operationId
          || !['read', 'no_tool'].includes(saved.outcome) || !Array.isArray(saved.traceEventIds)
          || saved.traceEventIds.length < 1 || saved.traceEventIds.some(id => !UUID.test(id))
          || new Set(saved.traceEventIds).size !== saved.traceEventIds.length) {
        throw fail('FILE_PATH_SUMMARY_EFFECT_MISMATCH');
      }
      if (saved.outcome === 'read') {
        if (!saved.readReceipt || saved.readReceipt.receiptSha256 !== canonicalDigest((({ receiptSha256, ...v }) => v)(saved.readReceipt))
            || saved.graphEffect?.status !== 'completed' || !saved.graphEffect.runId
            || !saved.graphEffect.ownerKey || !SHA.test(saved.toolResultSha256)) {
          throw fail('FILE_PATH_SUMMARY_EFFECT_MISMATCH');
        }
      } else if (saved.readReceipt || saved.graphEffect || saved.toolResultSha256) {
        throw fail('FILE_PATH_SUMMARY_EFFECT_MISMATCH');
      }
      return result;
    },
  });
}

module.exports = { createBoundFilePathSummaryGraph, PURPOSE, FEATURE, SUMMARY_TOOL };
