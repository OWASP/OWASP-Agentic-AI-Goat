'use strict';

const C = require('./secureshopRoleSystemRestartProposal');
const { createHash } = require('node:crypto');

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA = /^[a-f0-9]{64}$/;
const fail = code => Object.assign(new Error('System restart conversation unavailable'), { code });

// Preparation has no restart effect. The existing service remains the sole
// owner of target admission, sidecar execution and durable operation receipts.
function createBoundSystemRestartChat({ getRestart } = {}) {
  if (typeof getRestart !== 'function') throw new TypeError('Lazy bound System restart required');
  async function service() {
    const composition = await getRestart();
    if (composition?.ready !== true || typeof composition.service?.administration !== 'function'
        || typeof composition.service?.execute !== 'function'
        || typeof composition.service?.operation !== 'function') throw fail('SYSTEM_RESTART_UNAVAILABLE');
    return composition.service;
  }
  async function snapshot({ context, signal }) {
    signal?.throwIfAborted();
    const application = await service();
    const administration = await application.administration(structuredClone(context), { signal });
    signal?.throwIfAborted();
    return C.systemRestartSourceSnapshot({ context, administration });
  }
  async function prepare({ context, source, origin, name, modeCapability, signal }) {
    signal?.throwIfAborted();
    const application = await service();
    const administration = await application.administration(structuredClone(context), { signal });
    signal?.throwIfAborted();
    return C.createRoleSystemRestartProposal({ context, administration,
      source, origin, name, modeCapability });
  }
  function project(value, proposal) {
    if (!value || value.operationId !== proposal.proposalId) throw fail('SYSTEM_RESTART_CHAT_STATE_INVALID');
    const operationId = proposal.proposalId;
    if (['admitted', 'running'].includes(value.state)) {
      return { ok: false, state: value.state, operationId, automaticRetry: false };
    }
    if (['failed', 'retired'].includes(value.state)) {
      return { ok: false, state: value.state, operationId,
        failureCode: value.failureCode, automaticRetry: false };
    }
    if (value.state !== 'completed' || value.targetId !== proposal.targetId
        || value.requestSha256 !== proposal.requestSha256) throw fail('SYSTEM_RESTART_CHAT_STATE_INVALID');
    const receipt = value.receipt;
    if (!receipt || !UUID.test(receipt.beforeInstanceId || '')
        || !UUID.test(receipt.afterInstanceId || '')
        || receipt.beforeInstanceId === receipt.afterInstanceId
        || !Number.isSafeInteger(receipt.beforeGeneration) || receipt.beforeGeneration < 1
        || receipt.afterGeneration !== receipt.beforeGeneration + 1
        || !SHA.test(receipt.effectSha256 || '') || !SHA.test(receipt.outputSha256 || '')
        || !Number.isSafeInteger(receipt.outputBytes) || receipt.outputBytes < 0
        || receipt.outputBytes > 65536) throw fail('SYSTEM_RESTART_CHAT_STATE_INVALID');
    if (Object.hasOwn(receipt, 'outputText')) {
      if (typeof receipt.outputText !== 'string' || !receipt.outputText.isWellFormed()
          || Buffer.byteLength(receipt.outputText, 'utf8') !== receipt.outputBytes
          || Buffer.byteLength(receipt.outputText, 'utf8') > 16384
          || createHash('sha256').update(receipt.outputText).digest('hex') !== receipt.outputSha256) {
        throw fail('SYSTEM_RESTART_CHAT_STATE_INVALID');
      }
    }
    return { ok: true, state: 'completed', operationId,
      requestSha256: proposal.requestSha256, targetId: proposal.targetId,
      receipt: { beforeInstanceId: receipt.beforeInstanceId,
        afterInstanceId: receipt.afterInstanceId,
        beforeGeneration: receipt.beforeGeneration,
        afterGeneration: receipt.afterGeneration,
        effectSha256: receipt.effectSha256, outputSha256: receipt.outputSha256,
        outputBytes: receipt.outputBytes,
        ...(typeof receipt.outputText === 'string' ? { outputText: receipt.outputText } : {}) } };
  }
  async function confirm(raw) {
    const { context, source, proposal } = structuredClone({ context: raw.context,
      source: raw.source, proposal: raw.proposal });
    const { signal, beforeEffect } = raw;
    if (typeof beforeEffect !== 'function') throw fail('ROLE_SYSTEM_RESTART_PROPOSAL_INVALID');
    const saved = C.validateRoleSystemRestartProposal(proposal, source);
    signal?.throwIfAborted();
    const application = await service();
    const administration = await application.administration(context, { signal });
    const current = C.systemRestartSourceSnapshot({ context, administration });
    if (current.scopeKey !== saved.scopeKey || current.targetId !== saved.targetId
        || current.sourceSnapshotSha256 !== saved.sourceSnapshotSha256) throw fail('SYSTEM_RESTART_CHAT_SCOPE_MISMATCH');
    // The role graph checks the original scene and mode after this awaited
    // administration read. The service checks them again after its own
    // repository assertion, immediately before the owned sidecar POST.
    await beforeEffect();
    signal?.throwIfAborted();
    const value = await application.execute({ ...context, operationId: saved.proposalId,
      name: saved.name }, { signal, beforeEffect });
    return project(value, saved);
  }
  async function operation({ context, source, proposal, signal }) {
    const saved = C.validateRoleSystemRestartProposal(proposal, source);
    signal?.throwIfAborted();
    const application = await service();
    const value = await application.operation({ ...structuredClone(context),
      operationId: saved.proposalId });
    if (value?.state === 'not_found') return { ok: false, state: 'not_found', operationId: saved.proposalId };
    return project(value, saved);
  }
  return Object.freeze({ snapshot, prepare, confirm, operation });
}

module.exports = { createBoundSystemRestartChat };
