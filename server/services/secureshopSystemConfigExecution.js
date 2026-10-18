'use strict';

const path = require('node:path').posix;
const { isDeepStrictEqual } = require('node:util');
const { createLaunchScope } = require('./secureshopConversationBinding');
const { normalizeRequest } = require('../../sidecars/sandbox-runner/owned-system/contract');
const fail = () => Object.assign(new Error('System config execution unavailable'), { code: 'SYSTEM_CONFIG_MODE_INVALID' });
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).sort().join(',') === keys.sort().join(',');

function validateSystemConfigExecution(value, scope) {
  if (!exact(value, ['version', 'featureId', 'policyVersion', 'mode', 'generation', 'modeStamp', 'scope'])
      || value.version !== 1 || value.featureId !== 'system_config'
      || value.policyVersion !== 'owned-config-directory-v1' || !['vuln', 'fixed'].includes(value.mode)
      || !Number.isSafeInteger(value.generation) || value.generation < 0 || value.generation > 2147483647
      || typeof value.modeStamp !== 'string' || !value.modeStamp || Buffer.byteLength(value.modeStamp) > 128
      || !isDeepStrictEqual(value.scope, createLaunchScope(value.scope))
      || (scope && !isDeepStrictEqual(value.scope, scope))) throw fail();
  return Object.freeze(structuredClone(value));
}

function systemConfigAdmission(value, scope) {
  if (value?.version === 2) {
    if (!exact(value, ['version', 'request', 'execution'])) throw fail();
    return { request: normalizeRequest(value.request), execution: validateSystemConfigExecution(value.execution, scope) };
  }
  return { request: normalizeRequest(value) };
}

// Check both platform separator spellings and the *actual* legacy transformation.
// Never rewrite the caller's bytes or weaken the target's own symlink/tree checks.
function fixedConfigPathAllowed(input) {
  if (typeof input !== 'string' || !input.isWellFormed() || input.includes('\0')
      || !input || Buffer.byteLength(input) > 4096 || /^[\\/]/.test(input) || /^[a-z]:/i.test(input)) return false;
  const sanitized = input.replace(/\.\.\//g, '').replace(/\.\.\\/g, '');
  return [input, sanitized].every(value => {
    const resolved = path.resolve('/app/config', value.replace(/\\/g, '/'));
    return resolved.startsWith('/app/config/');
  });
}

module.exports = { validateSystemConfigExecution, systemConfigAdmission, fixedConfigPathAllowed };
