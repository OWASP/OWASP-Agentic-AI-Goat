'use strict';

const { canonicalDurableGeneration } = require('../agent-runtime/durableGeneration');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const XSS_OBJECTIVE_SCOPES = Object.freeze({
  xss_r1: 'reflected', xss_r2: 'reflected', xss_r3: 'reflected',
  xss_s1: 'stored_user', xss_s2: 'stored_user', xss_s3: 'stored_user',
  xss_g1: 'stored_llm', xss_g2: 'stored_llm', xss_g3: 'stored_llm',
  xss_e1: 'email', xss_e2: 'email', xss_e3: 'email',
});
const KEYS = Object.freeze([
  'childGeneration', 'ownerId', 'ownerKey', 'parentGeneration', 'runId', 'scopeKey',
]);

function captureXssJudgmentScope(binding, { userId, runId, objectiveId } = {}) {
  if (!binding || typeof binding !== 'object' || Array.isArray(binding) || !Object.isFrozen(binding)
      || Object.keys(binding).sort().join(',') !== KEYS.join(',')) {
    throw new TypeError('Exact protected XSS scope binding required');
  }
  if (!Number.isSafeInteger(userId) || userId < 1 || userId > 2147483647
      || !Number.isSafeInteger(binding.ownerId) || binding.ownerId !== userId) {
    throw new TypeError('XSS judgment owner binding mismatch');
  }
  if (typeof runId !== 'string' || !UUID.test(runId)
      || typeof binding.runId !== 'string' || binding.runId.toLowerCase() !== runId.toLowerCase()) {
    throw new TypeError('XSS judgment run binding mismatch');
  }
  const ownerKey = JSON.stringify(['XSS', String(userId)]);
  if (binding.ownerKey !== ownerKey) throw new TypeError('XSS judgment owner key mismatch');
  if (objectiveId !== undefined) {
    if (!Object.hasOwn(XSS_OBJECTIVE_SCOPES, objectiveId)
        || XSS_OBJECTIVE_SCOPES[objectiveId] !== binding.scopeKey) {
      throw new TypeError('XSS objective does not match the admitted child scope');
    }
  } else if (!new Set(Object.values(XSS_OBJECTIVE_SCOPES)).has(binding.scopeKey)) {
    throw new TypeError('Closed XSS judgment scope required');
  }
  return Object.freeze({
    runId: binding.runId.toLowerCase(),
    ownerId: binding.ownerId,
    ownerKey,
    scopeKey: binding.scopeKey,
    parentGeneration: canonicalDurableGeneration(binding.parentGeneration),
    childGeneration: canonicalDurableGeneration(binding.childGeneration),
  });
}

module.exports = { XSS_OBJECTIVE_SCOPES, captureXssJudgmentScope };
