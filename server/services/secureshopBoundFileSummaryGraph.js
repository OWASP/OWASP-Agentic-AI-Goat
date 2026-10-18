'use strict';
const { createHash } = require('node:crypto');
const { isDeepStrictEqual: equal } = require('node:util');
const { createBoundConversationService } = require('./secureshopBoundConversation');
const { createBoundTurns } = require('./secureshopBoundTurns');
const { createBoundAgentRunner } = require('./secureshopBoundAgentRunner');
const { createLaunchScope, createConversationBinding } = require('./secureshopConversationBinding');
const { executionScope } = require('./secureshopSceneBinding');
const { captureFeatureMode, guardFeatureFence } = require('./secureshopFeatureModeAuthority');
const { createBoundToolPolicyAdmission } = require('./secureshopBoundToolPolicyAdmission');
const { canonicalDigest } = require('./mcp/protocolContext');
const { SUMMARY_TOOL, createFileSummaryExecutionConfig } = require('./secureshopFileSummaryExecutionConfig');
// Composition must register this purpose and its forward database migration.
// It deliberately cannot fall back to a general or avatar conversation.
const PURPOSE = 'secureshop_file_summary';
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const fail = code => Object.assign(new Error('Bound file summary unavailable'), { code });
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
function exactEmpty(value) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype || Reflect.ownKeys(value).length) {
    throw fail('FILE_SUMMARY_INVALID_ARGUMENT');
  }
}
function genuine(value) {
  if (!value || typeof value.provider !== 'string' || !value.provider
      || typeof value.model !== 'string' || !value.model || value.mocked !== false || value.fallback === true
      || /^(mock|fixture|scripted|fallback|unavailable)$/i.test(value.provider)
      || /^(mock|fixture|scripted|fallback|unavailable)$/i.test(value.model)) throw fail('FILE_SUMMARY_MODEL_UNAVAILABLE');
  return value;
}
function prepare(input) {
  const binding = createConversationBinding(input.scope, input.persona), scope = createLaunchScope(binding);
  if (binding.role !== 'customer' || !UUID.test(input.sessionId) || !UUID.test(input.requestId)
      || !UUID.test(input.personaSession?.sessionId) || typeof input.personaSession.authorityVersion !== 'string'
      || !/^[1-9][0-9]{0,18}$/.test(input.personaSession.authorityVersion)
      || typeof input.message !== 'string' || !input.message.trim() || Buffer.byteLength(input.message) > 8192) {
    throw fail('FILE_SUMMARY_INVALID_ARGUMENT');
  }
  const file = input.attachment;
  if (!Buffer.isBuffer(file?.bytes) || file.bytes.length < 1 || file.bytes.length > 8192
      || typeof file.filename !== 'string' || Buffer.byteLength(file.filename) > 255
      || !/^[^/\\\x00-\x1f]+\.(txt|md)$/i.test(file.filename)
      || !['text/plain', 'text/markdown'].includes(file.mime)) throw fail('FILE_SUMMARY_INVALID_ARGUMENT');
  const bytes = Buffer.from(file.bytes);
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  if (text.includes('\0')) throw fail('FILE_SUMMARY_INVALID_ARGUMENT');
  const ref = { scope, persona: { id: binding.shopUserId, role: 'customer' },
    personaSession: { sessionId: input.personaSession.sessionId, authorityVersion: input.personaSession.authorityVersion },
    sessionId: input.sessionId, requestId: input.requestId };
  const h = sha(JSON.stringify(['owned-file-summary-v1', ref]));
  const operationId = h.slice(0, 8) + '-' + h.slice(8, 12) + '-5' + h.slice(13, 16)
    + '-a' + h.slice(17, 20) + '-' + h.slice(20, 32);
  return { ref, binding, operationId, bytes, attachment: Object.freeze({ filename: file.filename,
    mime: file.mime, byteCount: bytes.length, bodySha256: sha(bytes) }) };
}
function effectReceipt(observation, execution, requestId) {
  const r = observation?.effectReceipt;
  if (observation?.tool !== SUMMARY_TOOL || !Number.isSafeInteger(observation.step) || observation.step < 1
      || typeof observation.callId !== 'string' || !observation.callId || !r || r.status !== 'completed'
      || r.runId !== execution.runId || r.ownerKey !== execution.ownerKey
      || String(r.generation) !== String(execution.durableGeneration)
      || r.effectKey !== requestId + ':' + JSON.stringify([observation.step, observation.callId, SUMMARY_TOOL])) {
    throw fail('FILE_SUMMARY_EFFECT_MISMATCH');
  }
  return Object.freeze({ runId: r.runId, ownerKey: r.ownerKey, generation: String(r.generation),
    effectKey: r.effectKey, status: 'completed', step: observation.step, callId: observation.callId });
}
function createBoundFileSummaryGraph({ launches, conversationRepository, journal, coordinator, provider,
  attachment, personaAuthority, modeAuthority, scenes, toolPolicyRepository,
  runnerFactory = createBoundAgentRunner, toolPolicyAdmissionFactory = createBoundToolPolicyAdmission } = {}) {
  for (const [object, method] of [[launches, 'assertCurrent'], [coordinator, 'run'], [provider, 'chat'],
    [provider, 'finalResponse'], [attachment, 'writeAndReadBack'], [attachment, 'readRetained'],
    [personaAuthority, 'capture'], [modeAuthority, 'capture'], [modeAuthority, 'assertToken'],
    [scenes, 'readExisting'], [toolPolicyRepository, 'admitTool']]) {
    if (typeof object?.[method] !== 'function') throw new TypeError('Bound summary dependencies required');
  }
  const conversations = createBoundConversationService({ conversations: conversationRepository, launches });
  const turns = createBoundTurns({ conversations, coordinator });
  return Object.freeze({
    purpose: PURPOSE,
    async createSession(input) {
      input.signal?.throwIfAborted();
      if (input.persona?.role !== 'customer') throw fail('FILE_SUMMARY_INVALID_ARGUMENT');
      const result = await conversations.create(createLaunchScope(input.scope), input.persona, PURPOSE);
      input.signal?.throwIfAborted(); return result;
    },
    async run(input) {
      input.signal?.throwIfAborted();
      const source = prepare(input), { ref } = source;
      await launches.assertCurrent(ref.scope);
      const target = await scenes.readExisting(source.binding);
      if (!target?.scene || !equal(createLaunchScope(executionScope(target)), ref.scope)) throw fail('FILE_SUMMARY_AUTHORITY');
      const mode = await captureFeatureMode(modeAuthority, ref.scope, 'file_summary');
      if (mode.snapshot.featureId !== 'file_summary' || !equal(mode.snapshot.scope, ref.scope)
          || !['vuln', 'fixed'].includes(mode.snapshot.mode)) throw fail('FILE_SUMMARY_AUTHORITY');
      const fence = await personaAuthority.capture({ scope: ref.scope, personaId: ref.persona.id,
        role: 'customer', ...ref.personaSession });
      const expected = { ...ref.scope, personaId: ref.persona.id, role: 'customer', ...ref.personaSession };
      if (!Object.keys(expected).every(key => fence?.binding?.[key] === expected[key])) throw fail('FILE_SUMMARY_AUTHORITY');
      const guarded = guardFeatureFence(fence, mode);
      const authority = { ...ref, scene: structuredClone(target.scene), sceneTargetId: target.targetId,
        mode: structuredClone(mode.snapshot) };
      async function check() {
        input.signal?.throwIfAborted(); await launches.assertCurrent(ref.scope);
        await guarded.assertRemoteAdmission();
        const current = await scenes.readExisting(source.binding);
        if (!current?.scene || current.targetId !== target.targetId || !equal(current.scene, target.scene)
            || !equal(createLaunchScope(executionScope(current)), ref.scope)) throw fail('FILE_SUMMARY_AUTHORITY');
        input.signal?.throwIfAborted();
      }
      async function checkAtEffect() {
        input.signal?.throwIfAborted(); await launches.assertCurrent(ref.scope);
        await (mode.assertCurrentAtEffect || mode.assertCurrent).call(mode);
        const current = await scenes.readExisting(source.binding);
        if (!current?.scene || current.targetId !== target.targetId || !equal(current.scene, target.scene)
            || !equal(createLaunchScope(executionScope(current)), ref.scope)) throw fail('FILE_SUMMARY_AUTHORITY');
        input.signal?.throwIfAborted();
      }
      await check();
      const envelope = JSON.stringify({ version: 1, message: input.message, attachment: source.attachment,
        operationId: source.operationId, authoritySha256: canonicalDigest(authority) });
      const config = createFileSummaryExecutionConfig({ mode: mode.snapshot.mode, byteCount: source.bytes.length });
      let selected = false, receipt = null, observed = null, resultSha256 = null, localFailure = null;
      const checkedProvider = {
        ...(provider.config ? { config: provider.config } : {}),
        async chat(args) { await check(); const out = genuine(await provider.chat({ ...args, closedToolCatalog: true })); await check(); return out; },
        async finalResponse(args) { await check(); const out = genuine(await provider.finalResponse(args)); await check(); return out; }
      };
      const runner = runnerFactory({ turns, conversations, repository: conversationRepository, journal,
        provider: checkedProvider, ...config, conversationPurpose: PURPOSE, executionScope: 'turn',
        limits: { maxSteps: 2, maxParallelTools: 1 }, capturePersonaAuthority: () => guarded,
        pool: { async callTool() { throw fail('FILE_SUMMARY_EXTERNAL_DISPATCH_FORBIDDEN'); } },
        personaLocalToolModes: { [SUMMARY_TOOL]: 'remote_admission' },
        toolPolicyAdmission: toolPolicyAdmissionFactory({ repository: toolPolicyRepository,
          workflow: 'file-summary', declaredTools: config.manifest.getForRole('customer') }),
        createLocalTools: async (_binding, _context, supplied, execution) => new Map([[SUMMARY_TOOL, async args => {
          try {
          exactEmpty(args);
          if (supplied !== source || selected) throw fail('FILE_SUMMARY_EFFECT_REPLAY_FORBIDDEN');
          selected = true; await execution.check(); await check();
          const saved = await attachment.writeAndReadBack({ ...ref, filename: source.attachment.filename,
            mime: source.attachment.mime, bytes: source.bytes }, execution);
          await check(); await execution.check();
          if (saved.receipt?.operationId !== source.operationId || !equal(saved.receipt.authority, authority)
              || !equal(saved.receipt.attachment, source.attachment) || !Buffer.isBuffer(saved.data)
              || sha(saved.data) !== source.attachment.bodySha256 || saved.data.length !== source.bytes.length) {
            throw fail('FILE_SUMMARY_EFFECT_MISMATCH');
          }
          receipt = saved.receipt;
          const body = new TextDecoder('utf-8', { fatal: true }).decode(saved.data);
          const payload = mode.snapshot.mode === 'fixed'
            ? { kind: 'untrusted_document', label: 'attached document', body }
            : { path: '/attachment', body, summary: 'File /attachment contents:\n\n' + body };
          const result = { content: [{ type: 'text', text: JSON.stringify(payload) }],
            _meta: { operationId: source.operationId, receiptSha256: receipt.receiptSha256 } };
          resultSha256 = canonicalDigest(result); return result;
          } catch (error) { localFailure = error; throw error; }
        }]]),
        observeLocalTool: async packet => {
          if (localFailure) throw localFailure;
          if (packet.observation?.tool !== SUMMARY_TOOL || !receipt
              || canonicalDigest(packet.observation.result) !== resultSha256) throw fail('FILE_SUMMARY_EFFECT_MISMATCH');
          observed = effectReceipt(packet.observation, packet.run, ref.requestId);
        },
        // Leave the graph's next decision to the model. A second tool attempt
        // is denied by selected above; it can never publish another attachment.
        resultMetadata: async packet => {
          await check();
          if (packet.result.stopReason !== 'end_turn' || selected && (!receipt || !observed
              || packet.execution.runId !== observed.runId)) throw fail('FILE_SUMMARY_EFFECT_MISMATCH');
          return { boundFileSummary: { version: 1, originalEnvelope: envelope,
            operationId: source.operationId, outcome: selected ? 'read' : 'no_tool',
            traceEventIds: packet.traces.map(row => row.event_id),
            ...(selected ? { attachmentReceipt: receipt, graphEffect: observed, toolResultSha256: resultSha256 } : {}) } };
        }, captureResultTraces: true });
      const result = await runner.run({ ...ref, message: envelope, signal: input.signal, localToolAuthority: source });
      await check();
      const saved = result.taskMetadata?.boundFileSummary;
      if (saved?.version !== 1 || saved.originalEnvelope !== envelope || saved.operationId !== source.operationId
          || !['read', 'no_tool'].includes(saved.outcome)) throw fail('FILE_SUMMARY_EFFECT_MISMATCH');
      if (!Array.isArray(saved.traceEventIds) || saved.traceEventIds.length < 1
          || saved.traceEventIds.some(id => !UUID.test(id))
          || new Set(saved.traceEventIds).size !== saved.traceEventIds.length) throw fail('FILE_SUMMARY_EFFECT_MISMATCH');
      if (saved.outcome === 'read') {
        if (saved.attachmentReceipt?.operationId !== source.operationId
            || !equal(saved.attachmentReceipt.authority, authority)
            || !equal(saved.attachmentReceipt.attachment, source.attachment)
            || saved.graphEffect?.status !== 'completed' || !saved.graphEffect.runId
            || !saved.graphEffect.ownerKey || !/^[a-f0-9]{64}$/.test(saved.toolResultSha256)) {
          throw fail('FILE_SUMMARY_EFFECT_MISMATCH');
        }
        await attachment.readRetained(ref, saved.attachmentReceipt,
          { check, checkAtEffect, signal: input.signal });
        await check();
      } else if (saved.attachmentReceipt || saved.graphEffect || saved.toolResultSha256) throw fail('FILE_SUMMARY_EFFECT_MISMATCH');
      // Trusted internal result: the future HTTP boundary must project a closed
      // public DTO, never serialize taskMetadata or private attachment receipts.
      return result;
    }
  });
}
module.exports = { createBoundFileSummaryGraph, PURPOSE, SUMMARY_TOOL };
