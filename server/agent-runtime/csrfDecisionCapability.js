'use strict';

const crypto = require('node:crypto');
const { decideCsrf } = require('./csrfDecision');

const HEX_SHA256 = /^[a-f0-9]{64}$/;

function executionIdentity(execution, allowMissingDurableGeneration) {
  if (!execution || typeof execution.ownerKey !== 'string' || !execution.ownerKey
    || typeof execution.runId !== 'string' || !execution.runId
    || !Number.isSafeInteger(execution.generation) || execution.generation < 0
    || !(execution.signal instanceof AbortSignal) || typeof execution.check !== 'function') {
    throw new TypeError('Captured owner execution required');
  }
  const hasDurableGeneration = execution.durableGeneration !== undefined;
  if (!hasDurableGeneration && allowMissingDurableGeneration !== true) {
    throw new TypeError('Durable generation required');
  }
  if (hasDurableGeneration && !/^(0|[1-9][0-9]*)$/.test(String(execution.durableGeneration))) {
    throw new TypeError('Valid durable generation required');
  }
  return { ownerKey: execution.ownerKey, runId: execution.runId, generation: execution.generation,
    hasDurableGeneration, durableGeneration: execution.durableGeneration };
}

function requestBinding({ sessionId, tabId, message, document, chain, inputVector, gadgetDigest }) {
  if (typeof sessionId !== 'string' || !sessionId || sessionId.length > 256
    || typeof tabId !== 'string' || !tabId || tabId.length > 64
    || typeof message !== 'string' || message.length > 16384
    || !(document === null || document === undefined || typeof document === 'string')
    || (typeof document === 'string' && document.length > 16384)
    || !(chain === null || chain === undefined || typeof chain === 'string')
    || (typeof chain === 'string' && chain.length > 1024)
    || !(inputVector === null || inputVector === undefined || typeof inputVector === 'string')
    || (typeof inputVector === 'string' && (inputVector.length < 1 || inputVector.length > 64))
    || typeof gadgetDigest !== 'string' || !HEX_SHA256.test(gadgetDigest)) {
    throw new TypeError('Invalid proposed CSRF gadget request');
  }
  const normalized = { sessionId, tabId, message, document: document == null ? null : document,
    chain: chain == null ? null : chain, inputVector: inputVector == null ? null : inputVector, gadgetDigest };
  return { ...normalized, requestDigest: crypto.createHash('sha256').update(JSON.stringify(normalized)).digest('hex') };
}

function sameExecution(left, right) {
  return left.ownerKey === right.ownerKey && left.runId === right.runId && left.generation === right.generation
    && left.hasDurableGeneration === right.hasDurableGeneration
    && (!left.hasDurableGeneration || left.durableGeneration === right.durableGeneration);
}

async function trace(execution, type, data) {
  // Persist capability lifecycle details within the canonical decision event.
  // The durable trace schema intentionally has a bounded event-type vocabulary.
  await execution.trace?.({ node: 'managed_decision', type: 'decision', data: { evidenceSummary: `csrf:${type}:${data.status || data.reason}` } });
}

async function checkExecution(execution) {
  execution.signal.throwIfAborted();
  await execution.check();
  execution.signal.throwIfAborted();
}

async function checkBoth(originatingExecution, suppliedExecution) {
  await checkExecution(originatingExecution);
  if (suppliedExecution !== originatingExecution) await checkExecution(suppliedExecution);
}

function createCsrfAgentDecisionCapability({ allowMissingDurableGeneration = false } = {}) {
  if (typeof allowMissingDurableGeneration !== 'boolean') throw new TypeError('Invalid fixture generation policy');
  const authorities = new WeakMap();
  return Object.freeze({
    async classify({ execution, sessionId, tabId, message, document = null, chain = null,
      inputVector = null, gadgetDigest,
      model, actions, vectors } = {}) {
      const owner = executionIdentity(execution, allowMissingDurableGeneration);
      const request = requestBinding({ sessionId, tabId, message, document, chain, inputVector, gadgetDigest });
      if (!model || typeof model.chatWithTools !== 'function' || model.provider === 'mock'
        || !actions || typeof actions !== 'object' || !vectors || typeof vectors !== 'object') {
        throw new TypeError('Actual structured CSRF model decision required');
      }
      await checkExecution(execution);
      const plan = await decideCsrf({ model, message, document: request.document, actions, vectors, execution });
      await checkExecution(execution);
      if (!plan || plan.intent !== 'attack' || typeof plan.action !== 'string'
        || !Object.hasOwn(actions, plan.action) || typeof plan.vector !== 'string'
        || !Object.hasOwn(vectors, plan.vector) || !plan.params || typeof plan.params !== 'object'
        || Array.isArray(plan.params)) {
        await trace(execution, 'decision_rejected', { reason: plan?.intent === 'unavailable'
          ? 'unavailable' : 'not_attack' });
        await checkExecution(execution);
        return null;
      }
      const capability = Object.freeze(Object.create(null));
      const authority = { owner, originatingExecution: execution, request,
        plan: structuredClone(plan), state: 'ready' };
      authorities.set(capability, authority);
      try {
        await trace(execution, 'decision_capability', { status: 'issued' });
        await checkExecution(execution);
      } catch (error) {
        authority.state = 'revoked';
        throw error;
      }
      return capability;
    },

    async apply({ capability, execution, sessionId, tabId, message, document = null, chain = null,
      inputVector = null, gadgetDigest, applyEffect } = {}) {
      const authority = authorities.get(capability);
      if (!authority || authority.state !== 'ready') throw new Error('CSRF decision capability unavailable');
      authority.state = 'consumed';
      const owner = executionIdentity(execution, allowMissingDurableGeneration);
      const request = requestBinding({ sessionId, tabId, message, document, chain, inputVector, gadgetDigest });
      if (!sameExecution(authority.owner, owner) || authority.request.requestDigest !== request.requestDigest) {
        await trace(execution, 'decision_rejected', { reason: 'binding_mismatch' });
        throw new Error('CSRF decision capability binding mismatch');
      }
      if (typeof applyEffect !== 'function') throw new TypeError('CSRF effect callback required');
      await checkBoth(authority.originatingExecution, execution);
      await trace(execution, 'decision_apply', { status: 'started' });
      await checkBoth(authority.originatingExecution, execution);
      const effectSignal = authority.originatingExecution.signal === execution.signal
        ? execution.signal : AbortSignal.any([authority.originatingExecution.signal, execution.signal]);
      let result;
      try {
        result = await applyEffect(Object.freeze({
          action: authority.plan.action,
          vector: authority.plan.vector,
          params: Object.freeze(structuredClone(authority.plan.params)),
          signal: effectSignal,
        }));
      } catch (error) {
        // Trace persistence is secondary to the effect failure. In particular,
        // do not replace an uncertain-write error with a telemetry error.
        try { await trace(execution, 'decision_apply', { status: 'failed' }); } catch {}
        throw error;
      }
      await trace(execution, 'decision_apply', { status: 'completed' });
      await checkBoth(authority.originatingExecution, execution);
      return result;
    },
  });
}

module.exports = { createCsrfAgentDecisionCapability };
