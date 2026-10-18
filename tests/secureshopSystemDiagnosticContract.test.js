'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { normalizeDiagnosticRequest, diagnosticCommand, diagnosticRequestDigest } = require('../sidecars/sandbox-runner/owned-system/diagnostic-contract');
const request = { operationId: '44444444-4444-4444-8444-444444444444', cmd_template: 'echo', args: 'hello; printf "lab witness"' };
test('diagnostic contract preserves teaching shell syntax without executing it', () => {
  assert.equal(diagnosticCommand(request), 'echo hello; printf "lab witness"');
  assert.equal(diagnosticCommand({ ...request, cmd_template: '', args: 'echo first\necho second' }), 'echo first\necho second');
  const normalized = normalizeDiagnosticRequest(request); assert.ok(Object.isFrozen(normalized));
  assert.deepEqual(normalized, request);
  assert.equal(diagnosticRequestDigest({ args: request.args, operationId: request.operationId, cmd_template: request.cmd_template }), diagnosticRequestDigest(request));
  assert.notEqual(diagnosticRequestDigest({ ...request, args: 'other' }), diagnosticRequestDigest(request));
});
test('diagnostic requests reject authority expansion and bound UTF-8 input', () => {
  for (const value of [{ ...request, owner: 'foreign' }, { ...request, args: '\0' },
    { ...request, args: '😀'.repeat(2049) }, { ...request, operationId: 'invalid' },
    { ...request, cmd_template: ' ', args: '' }, { ...request, args: [] }]) {
    assert.throws(() => normalizeDiagnosticRequest(value));
  }
  assert.doesNotThrow(() => normalizeDiagnosticRequest({ ...request, args: '😀'.repeat(2048) }));
});
test('diagnostic digest cannot bind malformed Unicode that spawn would replace', () => {
  for (const field of ['cmd_template', 'args']) {
    for (const value of ['\ud800', '\udfff', 'before\ud800after']) {
      const malformed = { ...request, [field]: value };
      assert.throws(() => normalizeDiagnosticRequest(malformed));
      assert.throws(() => diagnosticRequestDigest(malformed));
    }
  }
  const unicode = { ...request, args: 'printf "😀 café"' };
  assert.equal(Buffer.from(diagnosticCommand(unicode)).toString('utf8'), diagnosticCommand(unicode));
});
