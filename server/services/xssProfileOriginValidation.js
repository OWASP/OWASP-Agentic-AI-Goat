'use strict';
const { createHash } = require('node:crypto');
const { canonicalDurableGeneration } = require('../agent-runtime/durableGeneration');
const FIELDS = new Set(['name', 'bio', 'website']);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HASH = /^[a-f0-9]{64}$/;
const SCOPE_BINDING_KEYS = Object.freeze([
  'runId', 'ownerId', 'ownerKey', 'scopeKey', 'parentGeneration', 'childGeneration',
]);
function revision(value) {
  if (typeof value === 'number' && Number.isSafeInteger(value) && value > 0) return String(value);
  return typeof value === 'string' && /^[1-9][0-9]*$/.test(value) ? value : null;
}

function counter(value) {
  try { return canonicalDurableGeneration(value); } catch { return null; }
}
function currentScopeBinding(execution, platformUserId, ownerKey) {
  if (execution.scopeBinding === undefined) return Object.freeze({ scoped:false });
  const value = execution.scopeBinding;
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).length !== SCOPE_BINDING_KEYS.length
      || SCOPE_BINDING_KEYS.some(key => !Object.hasOwn(value, key))) return null;
  const parentGeneration = counter(value.parentGeneration);
  const childGeneration = counter(value.childGeneration);
  if (!UUID.test(value.runId || '') || value.runId.toLowerCase() !== execution.runId.toLowerCase()
      || value.ownerId !== platformUserId || value.ownerKey !== ownerKey
      || value.scopeKey !== 'stored_llm' || parentGeneration === null || childGeneration === null
      || parentGeneration !== counter(execution.durableGeneration)) return null;
  return Object.freeze({ scoped:true, scopeKey:'stored_llm', childGeneration });
}

// Validates a private repository snapshot, never a request body or model output.
// This is an integrity check, not an attestation issuer. The caller must read the
// snapshot from the owner-bound store and independently check canonical g2 credit.
function inspectXssProfileOrigin({ snapshot, userKey, platformUserId, field,
  workshopGeneration, execution, requireWriterRun = false } = {}) {
  const fail = reason => Object.freeze({ valid: false, reason, eventSource: null });
  if (!FIELDS.has(field) || !Number.isSafeInteger(platformUserId) || platformUserId < 1
    || userKey !== String(platformUserId) || counter(workshopGeneration) === null
    || !execution || !UUID.test(execution.runId || '')
    || execution.ownerKey !== JSON.stringify(['XSS', userKey])
    || counter(execution.durableGeneration) === null) return fail('scope_invalid');
  const binding = currentScopeBinding(execution, platformUserId, execution.ownerKey);
  if (!binding) return fail('scope_invalid');
  const origin = snapshot?.origin;
  if (!origin || typeof snapshot.value !== 'string') return fail('origin_missing');
  if (binding.scoped) {
    if (origin.version !== 'xss-profile-origin-v2' || origin.scopeKey !== binding.scopeKey
        || counter(origin.childGeneration) !== binding.childGeneration) return fail('scope_generation_mismatch');
  } else if (origin.version !== 'xss-profile-origin-v1'
      || origin.scopeKey != null || origin.childGeneration != null) return fail('scope_generation_mismatch');
  if (origin.userKey !== userKey || origin.platformUserId !== platformUserId || origin.field !== field
    || origin.ownerKey !== execution.ownerKey) return fail('owner_mismatch');
  if (counter(origin.workshopGeneration) !== counter(workshopGeneration) || counter(origin.durableGeneration) !== counter(execution.durableGeneration)) return fail('generation_mismatch');
  if (!revision(snapshot.revision) || revision(snapshot.revision) !== revision(origin.revision)) return fail('revision_mismatch');
  const digest = createHash('sha256').update(snapshot.value, 'utf8').digest('hex');
  if (snapshot.valueSha256 !== digest || origin.valueSha256 !== digest) return fail('value_mismatch');
  if (origin.decisionSource !== 'model' || typeof origin.provider !== 'string' || !origin.provider.trim()
    || /mock|fixture|fallback|unavailable/i.test(origin.provider)
    || typeof origin.model !== 'string' || !origin.model.trim() || /mock|fixture|fallback|unavailable/i.test(origin.model)
    || !HASH.test(origin.rawDecisionSha256 || '') || !UUID.test(origin.runId || '')
    || !Number.isSafeInteger(origin.observationIndex) || origin.observationIndex < 0) return fail('decision_invalid');
  if (requireWriterRun && origin.runId !== execution.runId) return fail('writer_run_mismatch');
  return Object.freeze({ valid: true, reason: null, eventSource: snapshot.value });
}
module.exports = { inspectXssProfileOrigin };
