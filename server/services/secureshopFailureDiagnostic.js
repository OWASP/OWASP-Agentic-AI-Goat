'use strict';

// Failure diagnostics are process-local metadata. They never alter the thrown
// value or add fields which could later be serialized into an HTTP response.
const failures = new WeakMap();
const PHASES = new Set(['application_setup', 'agent_run', 'assessment_begin', 'tool_pool',
  'graph', 'external_observation', 'assessment_observe', 'assessment_finalize',
  'result_metadata', 'admission_publish', 'route']);
const CATEGORIES = new Set(['unclassified', 'external_tool_error', 'external_record_rejected']);
const ERROR_CODES = new Set(['ABORTED', 'ASSESSMENT_UNAVAILABLE', 'BOUND_SSRF_UNAVAILABLE', 'EFFECT_RECEIPT_INVALID',
  'GRAPH_EFFECT_REPLAY_BLOCKED', 'INVALID_MESSAGE', 'LAUNCH_UNAVAILABLE', 'OWNER_MISMATCH',
  'PROVIDER_ERROR', 'SECURESHOP_INVALID_DECISION', 'SESSION_UNAVAILABLE', 'STALE_LAUNCH',
  'TURN_RECOVERY_REQUIRED', 'TURN_REQUEST_CONFLICT']);
const ERROR_NAMES = new Set(['AbortError', 'AggregateError', 'Error', 'RangeError', 'TypeError']);

function isObject(value) {
  return value !== null && (typeof value === 'object' || typeof value === 'function');
}
function readString(value, key) {
  if (!isObject(value)) return null;
  try { return typeof value[key] === 'string' ? value[key] : null; }
  catch { return null; }
}

function markSecureShopFailure(error, phase, category = 'unclassified') {
  if (!PHASES.has(phase) || !CATEGORIES.has(category)) throw new TypeError('SecureShop diagnostic phase is invalid');
  if (isObject(error) && !failures.has(error)) failures.set(error, Object.freeze({ phase, category }));
  return error;
}

async function withSecureShopFailurePhase(phase, operation, category = 'unclassified') {
  if (!PHASES.has(phase) || !CATEGORIES.has(category) || typeof operation !== 'function') {
    throw new TypeError('SecureShop diagnostic boundary is invalid');
  }
  try { return await operation(); }
  catch (error) { markSecureShopFailure(error, phase, category); throw error; }
}

function projectSecureShopFailure(error, fallbackPhase = 'route') {
  const recorded = isObject(error) ? failures.get(error) : null;
  const phase = recorded?.phase || (PHASES.has(fallbackPhase) ? fallbackPhase : 'route');
  const failureCategory = recorded?.category || 'unclassified';
  const candidateCode = readString(error, 'code'), candidateName = readString(error, 'name');
  const errorCode = ERROR_CODES.has(candidateCode) ? candidateCode : 'UNCLASSIFIED';
  const errorName = ERROR_NAMES.has(candidateName) ? candidateName : 'UnknownError';
  return Object.freeze({ phase, failureCategory, errorCode, errorName });
}

module.exports = { markSecureShopFailure, withSecureShopFailurePhase, projectSecureShopFailure };
