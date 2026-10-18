'use strict';

const { createHash } = require('node:crypto');

const CONTRACT_VERSION = 1;
const EXECUTION_VERSION = 2;
const ISOLATION = 'bwrap-policy-template-v1';
const COMPILER_SHA256 = 'e6d212d621f5f38de578c929afb5d2ac835f0b95bcd3fd0d61511eab1c8112d2';
const WORKER_SHA256 = '037fcf025f7534a727fb235c7f1ccb7a4e4164112bf877381b75f5f065dd5c13';
const SUPPORTED_TARGETS = Object.freeze(['customer', 'merchant', 'admin']);
const TARGET_SET = new Set(SUPPORTED_TARGETS);
const REQUEST_KEYS = Object.freeze(['operationId', 'name', 'markdown', 'targets']);
const RESULT_KEYS = Object.freeze([
  'version', 'operationId', 'requestSha256', 'isolation', 'rendered',
  'renderedSha256', 'exitCode', 'timedOut', 'truncated', 'drained',
]);
const EXECUTION_KEYS = Object.freeze(['version', 'mode', 'request']);
const EXECUTION_COMMON_KEYS = Object.freeze([
  'version', 'kind', 'operationId', 'requestSha256', 'executionSha256', 'rendered', 'renderedSha256',
]);
const EXECUTION_ISOLATED_KEYS = Object.freeze([
  ...EXECUTION_COMMON_KEYS, 'isolation', 'exitCode', 'timedOut', 'truncated', 'drained', 'effectWitness',
]);
const EFFECT_WITNESS_KEYS = Object.freeze([
  'version', 'workerAttested', 'commandEffectObserved', 'effectSha256', 'compilerSha256', 'workerSha256',
]);
const UUID_V1_TO_V5 = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HASH = /^[0-9a-f]{64}$/;
const CONTROL = /[\u0000-\u001f\u007f]/u;

function fail(message) {
  throw new TypeError(`Invalid prompt policy contract: ${message}`);
}

function plainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function exactKeys(value, expected, label) {
  if (!plainObject(value)) fail(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    fail(`${label} has unexpected fields`);
  }
}

function utf8Length(value) {
  return Buffer.byteLength(value, 'utf8');
}

function hasMalformedSurrogates(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function normalizePolicyName(value) {
  if (typeof value !== 'string' || value.length === 0 || utf8Length(value) > 80
      || hasMalformedSurrogates(value) || CONTROL.test(value)
      || value.includes('/') || value.includes('\\')) {
    fail('name is invalid');
  }
  return value;
}

function normalizePolicyTargets(value) {
  if (!Array.isArray(value) || value.length === 0) fail('targets are invalid');
  for (let index = 0; index < value.length; index += 1) {
    if (!Object.hasOwn(value, index) || typeof value[index] !== 'string' || !TARGET_SET.has(value[index])) {
      fail('targets are invalid');
    }
  }
  const targets = [...value].sort();
  if (new Set(targets).size !== targets.length) fail('targets must be unique');
  return Object.freeze(targets);
}

function normalizeRenderRequest(raw) {
  exactKeys(raw, REQUEST_KEYS, 'request');
  if (typeof raw.operationId !== 'string' || !UUID_V1_TO_V5.test(raw.operationId)) {
    fail('operationId must be a lowercase canonical UUID v1-v5');
  }
  const name = normalizePolicyName(raw.name);
  if (typeof raw.markdown !== 'string' || hasMalformedSurrogates(raw.markdown)
      || utf8Length(raw.markdown) > 16 * 1024 || raw.markdown.includes('\0')) {
    fail('markdown is invalid');
  }
  const targets = normalizePolicyTargets(raw.targets);
  return Object.freeze({
    operationId: raw.operationId,
    name,
    markdown: raw.markdown,
    targets,
  });
}

function canonicalRequest(request) {
  return JSON.stringify({
    version: CONTRACT_VERSION,
    operationId: request.operationId,
    name: request.name,
    markdown: request.markdown,
    targets: request.targets,
  });
}

function requestDigest(request) {
  const normalized = normalizeRenderRequest(request);
  return createHash('sha256').update(canonicalRequest(normalized), 'utf8').digest('hex');
}

function normalizeRenderExecution(raw) {
  exactKeys(raw, EXECUTION_KEYS, 'execution');
  if (raw.version !== EXECUTION_VERSION || !['vuln', 'fixed'].includes(raw.mode)) fail('execution mode is invalid');
  return Object.freeze({ version: EXECUTION_VERSION, mode: raw.mode, request: normalizeRenderRequest(raw.request) });
}

function renderExecutionDigest(raw) {
  const execution = normalizeRenderExecution(raw);
  return createHash('sha256').update(JSON.stringify({ version: EXECUTION_VERSION, mode: execution.mode,
    request: { operationId: execution.request.operationId, name: execution.request.name,
      markdown: execution.request.markdown, targets: execution.request.targets } }), 'utf8').digest('hex');
}

function validateRenderExecutionResult(rawExecution, raw) {
  const execution = normalizeRenderExecution(rawExecution);
  const isolated = execution.mode === 'vuln';
  exactKeys(raw, isolated ? EXECUTION_ISOLATED_KEYS : EXECUTION_COMMON_KEYS, 'execution result');
  if (raw.version !== EXECUTION_VERSION || raw.kind !== (isolated ? 'isolated_template' : 'literal')
      || raw.operationId !== execution.request.operationId || raw.requestSha256 !== requestDigest(execution.request)
      || raw.executionSha256 !== renderExecutionDigest(execution)) fail('execution result identity does not match request');
  if (typeof raw.rendered !== 'string' || hasMalformedSurrogates(raw.rendered)
      || utf8Length(raw.rendered) > 64 * 1024 || raw.rendered.includes('\0')
      || !HASH.test(raw.renderedSha256)
      || raw.renderedSha256 !== createHash('sha256').update(raw.rendered, 'utf8').digest('hex')) {
    fail('execution result text is invalid');
  }
  if (!isolated) {
    if (raw.rendered !== execution.request.markdown) fail('literal result changed the policy source');
    return Object.freeze({ ...raw });
  }
  if (raw.isolation !== ISOLATION || raw.exitCode !== 0 || raw.timedOut !== false
      || raw.truncated !== false || raw.drained !== true) fail('isolated execution did not complete cleanly');
  exactKeys(raw.effectWitness, EFFECT_WITNESS_KEYS, 'effect witness');
  const witness = raw.effectWitness;
  if (witness.version !== 1 || witness.workerAttested !== true
      || typeof witness.commandEffectObserved !== 'boolean'
      || (witness.commandEffectObserved ? !HASH.test(witness.effectSha256) : witness.effectSha256 !== null)
      || witness.compilerSha256 !== COMPILER_SHA256 || witness.workerSha256 !== WORKER_SHA256) {
    fail('effect witness is invalid');
  }
  return Object.freeze({ ...raw, effectWitness: Object.freeze({ ...witness }) });
}

function createLiteralRenderResult(request) {
  const execution = normalizeRenderExecution({ version: EXECUTION_VERSION, mode: 'fixed', request });
  const rendered = execution.request.markdown;
  return validateRenderExecutionResult(execution, { version: EXECUTION_VERSION, kind: 'literal',
    operationId: execution.request.operationId, requestSha256: requestDigest(execution.request),
    executionSha256: renderExecutionDigest(execution), rendered,
    renderedSha256: createHash('sha256').update(rendered, 'utf8').digest('hex') });
}

function validateRenderResult(request, raw) {
  const normalized = normalizeRenderRequest(request);
  exactKeys(raw, RESULT_KEYS, 'render result');
  if (raw.version !== CONTRACT_VERSION || raw.operationId !== normalized.operationId
      || raw.requestSha256 !== requestDigest(normalized) || raw.isolation !== ISOLATION) {
    fail('render receipt identity does not match request');
  }
  if (typeof raw.rendered !== 'string' || hasMalformedSurrogates(raw.rendered)
      || utf8Length(raw.rendered) > 64 * 1024
      || raw.rendered.includes('\0') || !HASH.test(raw.renderedSha256)
      || raw.renderedSha256 !== createHash('sha256').update(raw.rendered, 'utf8').digest('hex')) {
    fail('rendered output is invalid');
  }
  if (raw.exitCode !== 0 || raw.timedOut !== false || raw.truncated !== false || raw.drained !== true) {
    fail('render did not complete cleanly');
  }
  return Object.freeze({ ...raw });
}

module.exports = {
  CONTRACT_VERSION,
  EXECUTION_VERSION,
  ISOLATION,
  COMPILER_SHA256,
  WORKER_SHA256,
  SUPPORTED_TARGETS,
  normalizePolicyName,
  normalizePolicyTargets,
  normalizeRenderRequest,
  requestDigest,
  validateRenderResult,
  normalizeRenderExecution,
  renderExecutionDigest,
  validateRenderExecutionResult,
  createLiteralRenderResult,
};
