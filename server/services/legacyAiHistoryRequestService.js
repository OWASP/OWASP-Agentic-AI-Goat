'use strict';

const { randomUUID } = require('node:crypto');
const { projectLegacyAiExperimentResult } = require('./legacyAiExperimentPresenter');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SOURCE_ROUTES = new Set([
  'prompt_injection',
  'chain_of_thought',
  'context_stuffing',
  'multi_turn_jailbreak',
]);
const MAX_OPTIONS_BYTES = 256 * 1024;
const MAX_OPTIONS_DEPTH = 6;

function invalid(message) {
  return Object.assign(new TypeError(message), { code: 'BAD_REQUEST' });
}

function boundedText(value, label, maxBytes) {
  if (typeof value !== 'string' || !value.length || Buffer.byteLength(value) > maxBytes) {
    throw invalid(`Valid ${label} required`);
  }
  return value;
}

function checkedInput({ sourceRoute, prompt } = {}) {
  if (!SOURCE_ROUTES.has(sourceRoute)) {
    throw invalid('Valid legacy AI source route required');
  }
  return Object.freeze({
    sourceRoute,
    prompt: boundedText(prompt, 'history prompt', 65536),
  });
}

function checkedRequestId(value) {
  if (typeof value !== 'string' || !UUID.test(value)) {
    throw invalid('Valid server history request ID required');
  }
  return value.toLowerCase();
}

function freezeDeep(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freezeDeep(child);
    Object.freeze(value);
  }
  return value;
}

function optionError() {
  throw invalid('Valid bounded JSON inference options required');
}

function copyJsonOption(value, depth, ancestors) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return value;
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) optionError();
    return value;
  }
  if (!value || typeof value !== 'object' || depth > MAX_OPTIONS_DEPTH) optionError();
  if (ancestors.has(value)) optionError();
  ancestors.add(value);

  let copy;
  if (Array.isArray(value)) {
    if (Object.getPrototypeOf(value) !== Array.prototype) optionError();
    copy = new Array(value.length);
    const keys = Reflect.ownKeys(value);
    if (keys.length !== value.length + 1 || !keys.includes('length')) optionError();
    for (let index = 0; index < value.length; index += 1) {
      const key = String(index);
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !descriptor.enumerable || !('value' in descriptor)) optionError();
      copy[index] = copyJsonOption(descriptor.value, depth + 1, ancestors);
    }
  } else {
    if (Object.getPrototypeOf(value) !== Object.prototype) optionError();
    copy = {};
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== 'string') optionError();
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !descriptor.enumerable || !('value' in descriptor)) optionError();
      Object.defineProperty(copy, key, {
        configurable: true,
        enumerable: true,
        value: copyJsonOption(descriptor.value, depth + 1, ancestors),
        writable: true,
      });
    }
  }

  ancestors.delete(value);
  return copy;
}

function snapshotOptions(value) {
  if (value === undefined) return undefined;
  if (!value || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    optionError();
  }
  const copy = copyJsonOption(value, 0, new WeakSet());
  if (Buffer.byteLength(JSON.stringify(copy)) > MAX_OPTIONS_BYTES) optionError();
  return freezeDeep(copy);
}

function checkedAdmission(admission, ownerId, sessionId) {
  if (!admission
      || Number(admission.ownerId) !== ownerId
      || String(admission.sessionId) !== String(sessionId)
      || typeof admission.generation !== 'string'
      || !/^(0|[1-9][0-9]*)$/.test(admission.generation)) {
    throw Object.assign(new Error('History admission authority mismatch'), { code: '55000' });
  }
  return Object.freeze({
    ownerId,
    sessionId: String(sessionId),
    generation: admission.generation,
  });
}

function checkedInferenceResult(value, sourceRoute) {
  if (!value || typeof value !== 'object') {
    throw invalid('Bounded inference result required');
  }
  if (Object.hasOwn(value, 'teaching')) {
    const projected = projectLegacyAiExperimentResult(value, { sourceRoute });
    boundedText(projected.modelUsed, 'history model', 256);
    return projected;
  }
  return Object.freeze({
    response: boundedText(value.response, 'history response', 262144),
    modelUsed: boundedText(value.modelUsed, 'history model', 256),
  });
}

function checkedAppendReceipt(receipt, expected) {
  const fields = ['requestId', 'ownerId', 'generation', 'sourceRoute', 'prompt', 'response', 'modelUsed'];
  const ownsValue = (field, value) => {
    const descriptor = receipt && Object.getOwnPropertyDescriptor(receipt, field);
    return descriptor && 'value' in descriptor && descriptor.value === value;
  };
  // This online path issues a fresh UUID after admission. A replay indicates
  // collision or faulty composition, not a supported client retry protocol.
  if (!receipt || fields.some(field => !ownsValue(field, expected[field]))
      || !ownsValue('replayed', false)) {
    throw Object.assign(new Error('Private history persistence receipt mismatch'), {
      code: 'HISTORY_RECEIPT_MISMATCH',
    });
  }
  return Object.freeze({
    requestId: expected.requestId,
    response: expected.response,
    modelUsed: expected.modelUsed,
    replayed: false,
  });
}

function requiredDependencies({ history, infer, issueRequestId }) {
  if (!history
      || typeof history.admit !== 'function'
      || typeof history.append !== 'function'
      || typeof history.listOwn !== 'function'
      || typeof history.listAdmin !== 'function'
      || typeof infer !== 'function'
      || typeof issueRequestId !== 'function') {
    throw new TypeError('Fixed private-history dependencies required');
  }
}

// The second method argument is server-owned execution context, never request
// body data. Race the entire operation so an uncooperative inference provider
// cannot outlive the HTTP request; every continuation checks the same signal.
async function withExecutionDeadline(serverExecution, timeoutMs, work) {
  if (!serverExecution || Object.getPrototypeOf(serverExecution) !== Object.prototype
      || Object.keys(serverExecution).some(key => key !== 'signal')
      || (serverExecution.signal !== undefined && !(serverExecution.signal instanceof AbortSignal))) {
    throw invalid('Valid server execution signal required');
  }
  const controller = new AbortController();
  const external = serverExecution.signal;
  const abort = () => controller.abort(external.reason);
  if (external?.aborted) abort();
  else external?.addEventListener('abort', abort, { once: true });
  const timer = setTimeout(() => controller.abort(Object.assign(new Error('History request timed out'), {
    code: 'HISTORY_REQUEST_TIMEOUT',
  })), timeoutMs);
  let rejectAbort;
  const aborted = new Promise((resolve, reject) => { rejectAbort = reject; });
  const onAbort = () => rejectAbort(controller.signal.reason);
  controller.signal.addEventListener('abort', onAbort, { once: true });
  try {
    controller.signal.throwIfAborted();
    return await Promise.race([work(controller.signal), aborted]);
  } finally {
    clearTimeout(timer);
    external?.removeEventListener('abort', abort);
    controller.signal.removeEventListener('abort', onAbort);
  }
}

// Draft-only request composition. Callers must inject trusted authenticated
// owner/session values. The repository remains the authoritative live-session,
// deletion, and generation fence; this service deliberately holds no database
// transaction while inference is pending.
function createLegacyAiHistoryRequestService({
  history,
  infer,
  issueRequestId = randomUUID,
  requestTimeoutMs = 180000,
} = {}) {
  requiredDependencies({ history, infer, issueRequestId });
  if (!Number.isSafeInteger(requestTimeoutMs) || requestTimeoutMs < 100 || requestTimeoutMs > 240000) {
    throw invalid('Valid history request timeout required');
  }

  async function runAuthenticated({
    ownerId,
    sessionId,
    sourceRoute,
    prompt,
    options,
  } = {}, serverExecution = {}) {
    return withExecutionDeadline(serverExecution, requestTimeoutMs, async signal => {
      const safeOptions = snapshotOptions(options);
      const input = checkedInput({ sourceRoute, prompt });
      const admission = checkedAdmission(
        await history.admit({ ownerId, sessionId }),
        ownerId,
        sessionId,
      );
      signal.throwIfAborted();
      const check = async () => {
        signal.throwIfAborted();
        const current = checkedAdmission(await history.admit({ ownerId: admission.ownerId,
          sessionId: admission.sessionId }), admission.ownerId, admission.sessionId);
        signal.throwIfAborted();
        if (current.generation !== admission.generation) {
          throw Object.assign(new Error('History generation changed'), { code: '55000' });
        }
      };
      const execution = Object.freeze({ ...admission, signal, check });
      const requestId = checkedRequestId(issueRequestId());
      const result = checkedInferenceResult(
        await infer({ prompt: input.prompt, sourceRoute: input.sourceRoute, options: safeOptions }, execution),
        input.sourceRoute,
      );

      await check();
      const storedInput = Object.freeze({
        ownerId: admission.ownerId,
        sessionId: admission.sessionId,
        generation: admission.generation,
        requestId,
        sourceRoute: input.sourceRoute,
        prompt: input.prompt,
        response: result.response,
        modelUsed: result.modelUsed,
    });
    const receipt = checkedAppendReceipt(await history.append(storedInput), storedInput);
    signal.throwIfAborted();
    return Object.freeze({ ...result, requestId: receipt.requestId, replayed: receipt.replayed });
    });
  }

  async function runAnonymous({ sourceRoute, prompt, options } = {}, serverExecution = {}) {
    return withExecutionDeadline(serverExecution, requestTimeoutMs, async signal => {
      const safeOptions = snapshotOptions(options);
      const input = checkedInput({ sourceRoute, prompt });
      const execution = Object.freeze({ ownerId: null, signal, check: async () => signal.throwIfAborted() });
      const result = checkedInferenceResult(
        await infer({ prompt: input.prompt, sourceRoute: input.sourceRoute, options: safeOptions }, execution),
        input.sourceRoute,
      );
      signal.throwIfAborted();
      return result;
    });
  }

  return Object.freeze({
    runAuthenticated,
    runAnonymous,
    listOwner: ({ ownerId, sessionId, limit, beforeCursor } = {}) =>
      history.listOwn({ ownerId, sessionId, limit, beforeCursor }),
    listAdmin: ({ adminId, sessionId, limit, beforeCursor } = {}) =>
      history.listAdmin({ adminId, sessionId, limit, beforeCursor }),
  });
}

module.exports = { createLegacyAiHistoryRequestService };
