'use strict';

const crypto = require('node:crypto');
const { AsyncLocalStorage } = require('node:async_hooks');
const invocationContext = new AsyncLocalStorage();
const receipts = new WeakMap();
const RECEIPT_VERSION = 'mcp-protocol-invocation.v2';

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
function canonicalDigest(value) {
  return crypto.createHash('sha256').update(canonical(value)).digest('hex');
}

function validateExecution(sessionId, execution) {
  if (!/^mcp_[1-9][0-9]*$/.test(String(sessionId || '')) || !execution
      || typeof execution !== 'object' || typeof execution.check !== 'function'
      || typeof execution.effect !== 'function' || typeof execution.runId !== 'string') {
    throw Object.assign(new Error('Current owner-scoped MCP execution is required'), { code: 'MCP_PROTOCOL_CONTEXT_REQUIRED' });
  }
  const ownerId = String(sessionId).slice(4);
  if (execution.ownerKey !== JSON.stringify(['MCP', ownerId])) {
    throw Object.assign(new Error('MCP protocol execution owner mismatch'), { code: 'MCP_PROTOCOL_OWNER_MISMATCH' });
  }
  return ownerId;
}

function normalizeGeneration(execution) {
  const value = execution?.durableGeneration ?? execution?.generation;
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) throw Object.assign(new Error('Invalid MCP protocol generation'), { code: 'MCP_PROTOCOL_CONTEXT_REQUIRED' });
    return String(value);
  }
  if (typeof value === 'string' && /^(?:0|[1-9][0-9]*)$/.test(value)
      && BigInt(value) <= 9223372036854775807n) return value;
  throw Object.assign(new Error('Invalid MCP protocol generation'), { code: 'MCP_PROTOCOL_CONTEXT_REQUIRED' });
}

async function withProtocolInvocation({ sessionId, execution, surface, purpose = null, observation = null,
  effectKey = null, actor = null }, callback) {
  const ownerId = validateExecution(sessionId, execution);
  normalizeGeneration(execution);
  await execution.check();
  const state = {
    sessionId: String(sessionId), ownerId, execution, surface: String(surface), purpose,
    observation, effectKey: effectKey || `mcp_protocol_${crypto.randomUUID()}`,
    actor: Object.freeze({ platformRole: String(actor?.platformRole || 'unknown'),
      labRole: actor?.labRole === 'privileged' ? 'privileged' : 'operator' }),
    invocationId: crypto.randomUUID(), result: null, receipt: null, retired: false,
  };
  try {
    let value;
    try { value = await invocationContext.run(state, callback); }
    catch (error) {
      if (require('./ownedTargetClient').isProtectedOperationUncertain(state.protectedOperationFailure)) throw state.protectedOperationFailure;
      throw error;
    }
    if (require('./ownedTargetClient').isProtectedOperationUncertain(state.protectedOperationFailure)) throw state.protectedOperationFailure;
    await execution.check();
    return Object.freeze({ value, toolResult: state.result, receipt: state.receipt });
  } finally {
    // Async resources spawned by an SDK handler retain the ALS object. Close
    // that capability explicitly once this one request has settled.
    state.retired = true;
  }
}

function requireProtocolContext(sessionId) {
  const state = invocationContext.getStore();
  if (!state || state.retired || state.sessionId !== String(sessionId)) {
    throw Object.assign(new Error('Current MCP protocol invocation context is required'), { code: 'MCP_PROTOCOL_CONTEXT_REQUIRED' });
  }
  validateExecution(sessionId, state.execution);
  return state;
}

function bindResult(state, name, args, result) {
  if (!result || typeof result !== 'object' || Array.isArray(result) || state.result) {
    throw Object.assign(new Error('Invalid MCP protocol tool result'), { code: 'MCP_PROTOCOL_RESULT_INVALID' });
  }
  const receipt = Object.freeze({
    version: RECEIPT_VERSION,
    surface: state.surface,
    tool: name,
    argsSha256: canonicalDigest(args),
    purpose: typeof state.purpose === 'string' ? state.purpose : null,
    observationSource: typeof state.observation?.source === 'string' ? state.observation.source : null,
    observationSha256: state.observation && typeof state.observation === 'object'
      ? canonicalDigest({ source: state.observation.source || null,
        untrustedText: state.observation.untrustedText || null }) : null,
    invocationId: state.invocationId,
    effectKey: state.effectKey,
    ownerKey: state.execution.ownerKey,
    runId: state.execution.runId,
    generation: normalizeGeneration(state.execution),
    labRole: state.actor.labRole,
  });
  state.result = result;
  state.receipt = receipt;
  receipts.set(result, receipt);
}

function readProtocolReceipt(result) { return receipts.get(result) || null; }
function adoptProtocolReceipt(source, target) {
  const receipt = readProtocolReceipt(source);
  if (receipt && target && typeof target === 'object') receipts.set(target, receipt);
  return target;
}

module.exports = { RECEIPT_VERSION, withProtocolInvocation, requireProtocolContext, bindResult,
  readProtocolReceipt, adoptProtocolReceipt, canonicalDigest,
  _internals: { canonical, validateExecution, normalizeGeneration } };
