'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { VERSION, diagnosticRequestDigest, diagnosticCommand } = require('../sidecars/sandbox-runner/owned-system/diagnostic-contract');
const { validateDiagnosticResult } = require('../sidecars/sandbox-runner/owned-system/diagnostic-result');
const request = { operationId: '44444444-4444-4444-8444-444444444444', cmd_template: 'printf', args: 'lab' };
function result(stdout = Buffer.from([0xff, 0, 0x41]), stderr = Buffer.alloc(0)) {
  const value = { version: VERSION, isolation: 'bwrap-system-diagnostic-v1', operationId: request.operationId,
    requestSha256: diagnosticRequestDigest(request), command: diagnosticCommand(request), executed: true,
    exitCode: 70, signal: null, drained: true, encoding: 'base64', timedOut: false, truncated: false };
  for (const [name, bytes] of [['stdout', stdout], ['stderr', stderr]]) Object.assign(value, {
    [name]: bytes.toString('base64'), [`${name}Bytes`]: bytes.length,
    [`${name}Sha256`]: createHash('sha256').update(bytes).digest('hex') });
  return value;
}
test('execution validation preserves binary output and legitimate command exit70', () => {
  const value = result(); const validated = validateDiagnosticResult(value, request);
  assert.deepEqual(validated, value); assert.ok(Object.isFrozen(validated)); assert.notEqual(validated, value);
  assert.doesNotThrow(() => validateDiagnosticResult({ ...value, exitCode: null, signal: 9 }, request));
});
test('execution validation rejects altered bytes, request binding and completion claims', () => {
  for (const patch of [{ stdout: 'AAAA' }, { stdoutBytes: 2 }, { stdoutSha256: '0'.repeat(64) },
    { stdout: result().stdout + '\n' }, { requestSha256: '0'.repeat(64) }, { command: 'other' },
    { operationId: '55555555-5555-4555-8555-555555555555' }, { drained: false }, { timedOut: true },
    { truncated: true }, { executed: false }, { exitCode: 0, signal: 9 }, { exitCode: null, signal: null },
    { extra: true }]) assert.throws(() => validateDiagnosticResult({ ...result(), ...patch }, request));
  assert.throws(() => validateDiagnosticResult(result(), { ...request, args: 'different' }));
});
test('combined output must fit the admitted transport bound', () => {
  const value = result(Buffer.from('123'), Buffer.from('456'));
  assert.throws(() => validateDiagnosticResult(value, request, { maxOutputBytes: 5 }));
  assert.doesNotThrow(() => validateDiagnosticResult(value, request, { maxOutputBytes: 6 }));
});
