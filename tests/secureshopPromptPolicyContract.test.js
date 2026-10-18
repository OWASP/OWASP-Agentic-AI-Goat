'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const {
  CONTRACT_VERSION, ISOLATION, SUPPORTED_TARGETS,
  normalizePolicyName, normalizePolicyTargets, normalizeRenderRequest, requestDigest, validateRenderResult,
  normalizeRenderExecution, renderExecutionDigest, validateRenderExecutionResult, createLiteralRenderResult,
} = require('../server/services/secureshopPromptPolicyContract');

const OPERATION_ID = '018f5b4e-5c8a-4b9c-8d0e-1f2a3b4c5d6e';
const base = Object.freeze({ operationId: OPERATION_ID, name: 'policy', markdown: 'café', targets: ['merchant', 'admin'] });

function outputReceipt(request, overrides = {}) {
  const rendered = overrides.rendered === undefined ? `rendered:${request.markdown}` : overrides.rendered;
  return {
    version: CONTRACT_VERSION,
    operationId: request.operationId,
    requestSha256: requestDigest(request),
    isolation: ISOLATION,
    rendered,
    renderedSha256: createHash('sha256').update(rendered, 'utf8').digest('hex'),
    exitCode: 0, timedOut: false, truncated: false, drained: true,
    ...overrides,
  };
}

test('normalizes by copying and canonically sorting targets', () => {
  const raw = { ...base, targets: ['merchant', 'admin'] };
  const normalized = normalizeRenderRequest(raw);
  assert.deepEqual(normalized.targets, ['admin', 'merchant']);
  assert.ok(Object.isFrozen(normalized));
  assert.ok(Object.isFrozen(normalized.targets));
  raw.targets.push('customer');
  assert.deepEqual(normalized.targets, ['admin', 'merchant']);
});

test('enforces UTF-8 byte limits and preserves exact encoded content', () => {
  assert.doesNotThrow(() => normalizeRenderRequest({ ...base, name: 'é'.repeat(40) }));
  assert.throws(() => normalizeRenderRequest({ ...base, name: 'é'.repeat(41) }), TypeError);
  assert.doesNotThrow(() => normalizeRenderRequest({ ...base, markdown: 'é'.repeat(8192) }));
  assert.throws(() => normalizeRenderRequest({ ...base, markdown: 'é'.repeat(8193) }), TypeError);
  const composed = requestDigest({ ...base, markdown: 'é' });
  const decomposed = requestDigest({ ...base, markdown: 'e\u0301' });
  assert.notEqual(composed, decomposed);
});

test('rejects malformed UTF-16 while preserving replacement characters and valid pairs', () => {
  assert.doesNotThrow(() => normalizePolicyName('😀'));
  assert.doesNotThrow(() => normalizeRenderRequest({ ...base, markdown: '😀\uFFFD' }));
  for (const malformed of ['\uD800', '\uDC00', 'x\uD800y', 'x\uDC00y']) {
    assert.throws(() => normalizePolicyName(malformed), TypeError);
    assert.throws(() => normalizeRenderRequest({ ...base, markdown: malformed }), TypeError);
    const receipt = outputReceipt(normalizeRenderRequest(base), { rendered: malformed });
    assert.throws(() => validateRenderResult(base, receipt), TypeError);
  }
});

test('rejects malformed request fields, controls, duplicates and unknown targets', () => {
  assert.throws(() => normalizeRenderRequest({ ...base, extra: true }), TypeError);
  assert.throws(() => normalizeRenderRequest({ ...base, operationId: OPERATION_ID.toUpperCase() }), TypeError);
  for (const name of ['a/b', 'a\\b', 'a\n']) assert.throws(() => normalizeRenderRequest({ ...base, name }), TypeError);
  assert.throws(() => normalizeRenderRequest({ ...base, targets: ['admin', 'admin'] }), TypeError);
  assert.throws(() => normalizeRenderRequest({ ...base, targets: ['owner'] }), TypeError);
  const sparse = []; sparse.length = 2; sparse[1] = 'admin';
  assert.throws(() => normalizePolicyTargets(sparse), TypeError);
  assert.throws(() => normalizeRenderRequest({ ...base, targets: sparse }), TypeError);
});

test('accepts only an exact, clean render receipt', () => {
  const request = normalizeRenderRequest(base);
  const receipt = outputReceipt(request);
  const validated = validateRenderResult(request, receipt);
  assert.ok(Object.isFrozen(validated));
  for (const [field, value] of [['version', 2], ['requestSha256', '0'.repeat(64)], ['isolation', 'other'], ['exitCode', 1], ['timedOut', true], ['truncated', true], ['drained', false]]) {
    assert.throws(() => validateRenderResult(request, { ...receipt, [field]: value }), TypeError);
  }
  assert.throws(() => validateRenderResult(request, { ...receipt, forged: true }), TypeError);
  assert.throws(() => validateRenderResult(request, { ...receipt, renderedSha256: '0'.repeat(64) }), TypeError);
  assert.throws(() => validateRenderResult(request, { ...receipt, rendered: '\0' }), TypeError);
});

test('exports only the initially supported roles', () => {
  assert.deepEqual(SUPPORTED_TARGETS, ['customer', 'merchant', 'admin']);
});

test('v2 execution binds the exact mode while preserving the historical v1 digest', () => {
  const request = normalizeRenderRequest(base);
  const vulnerable = normalizeRenderExecution({ version: 2, mode: 'vuln', request });
  const fixed = normalizeRenderExecution({ version: 2, mode: 'fixed', request });
  assert.notEqual(renderExecutionDigest(vulnerable), renderExecutionDigest(fixed));
  assert.equal(requestDigest(vulnerable.request), requestDigest(fixed.request));
  assert.deepEqual(normalizeRenderExecution(vulnerable), vulnerable);
  for (const raw of [{ ...fixed, extra: true }, { ...fixed, version: 1 }, { ...fixed, mode: 'other' }]) {
    assert.throws(() => normalizeRenderExecution(raw), TypeError);
  }
  assert.equal(renderExecutionDigest(vulnerable),
    require('../sidecars/sandbox-runner/policy-render/secureshopPromptPolicyContract').renderExecutionDigest(vulnerable));
});

test('fixed v2 returns exact literal source and rejects fabricated sandbox effects', () => {
  const literal = createLiteralRenderResult(base);
  const fixed = normalizeRenderExecution({ version: 2, mode: 'fixed', request: base });
  assert.equal(literal.kind, 'literal');
  assert.equal(literal.rendered, base.markdown);
  assert.equal(literal.requestSha256, requestDigest(base));
  assert.deepEqual(validateRenderExecutionResult(fixed, literal), literal);
  for (const changed of [{ ...literal, rendered: 'changed' }, { ...literal, isolation: ISOLATION },
    { ...literal, effectWitness: { commandEffectObserved: true } },
    { ...literal, executionSha256: renderExecutionDigest({ version: 2, mode: 'vuln', request: base }) }]) {
    assert.throws(() => validateRenderExecutionResult(fixed, changed), TypeError);
  }
  assert.throws(() => validateRenderExecutionResult({ version: 2, mode: 'vuln', request: base }, literal), TypeError);
});

test('isolated v2 validates only the pinned executor witness shape', () => {
  const execution = normalizeRenderExecution({ version: 2, mode: 'vuln', request: base });
  const witness = { version: 1, workerAttested: true, commandEffectObserved: true,
    effectSha256: 'a'.repeat(64), compilerSha256: require('../server/services/secureshopPromptPolicyContract').COMPILER_SHA256,
    workerSha256: require('../server/services/secureshopPromptPolicyContract').WORKER_SHA256 };
  const result = { version: 2, kind: 'isolated_template', operationId: base.operationId,
    requestSha256: requestDigest(base), executionSha256: renderExecutionDigest(execution),
    rendered: base.markdown, renderedSha256: createHash('sha256').update(base.markdown).digest('hex'),
    isolation: ISOLATION, exitCode: 0, timedOut: false, truncated: false, drained: true,
    effectWitness: witness };
  assert.deepEqual(validateRenderExecutionResult(execution, result), result);
  assert.doesNotThrow(() => validateRenderExecutionResult(execution, { ...result,
    effectWitness: { ...witness, commandEffectObserved: false, effectSha256: null } }));
  for (const changed of [{ ...result, effectWitness: { ...witness, workerAttested: false } },
    { ...result, effectWitness: { ...witness, commandEffectObserved: false } },
    { ...result, effectWitness: { ...witness, effectSha256: null } },
    { ...result, effectWitness: { ...witness, compilerSha256: 'b'.repeat(64) } },
    { ...result, effectWitness: { ...witness, forged: true } }]) {
    assert.throws(() => validateRenderExecutionResult(execution, changed), TypeError);
  }
});
