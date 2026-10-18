import { webcrypto, createHash } from 'node:crypto';
import { decodeRoleSystemDiagnosticOutcome } from './roleSystemDiagnosticOutcome.mjs';

const sha = value => createHash('sha256').update(value).digest('hex');
const operationId = 'cccccccc-cccc-5ccc-8ccc-cccccccccccc';
const targetId = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
const proposal = { proposalId: operationId, cmd_template: 'echo', args: 'owned',
  requestSha256: sha(JSON.stringify({ version: 'secureshop-owned-system-diagnostic.v1',
    request: { operationId, cmd_template: 'echo', args: 'owned' } })) };

beforeAll(() => { Object.defineProperty(globalThis, 'crypto', { configurable: true, value: webcrypto }); });

function completed() {
  const stdout = Buffer.from('owned\n'), stderr = Buffer.alloc(0);
  return { ok: true, state: 'completed', operationId, requestSha256: proposal.requestSha256,
    targetId, receipt: { version: 'secureshop-owned-system-diagnostic-http.v1', targetId,
      hostname: `system-diag-${targetId.replaceAll('-', '')}`,
      bindingSha256: sha(JSON.stringify({ version: 'secureshop-owned-system-diagnostic-http.v1',
        targetId, requestSha256: proposal.requestSha256 })),
      result: { version: 'secureshop-owned-system-diagnostic.v1',
        isolation: 'bwrap-system-diagnostic-v1', operationId,
        requestSha256: proposal.requestSha256, command: 'echo owned', executed: true,
        exitCode: 0, signal: null, drained: true, stdout: stdout.toString('base64'),
        stderr: stderr.toString('base64'), encoding: 'base64', stdoutBytes: stdout.length,
        stderrBytes: 0, stdoutSha256: sha(stdout), stderrSha256: sha(stderr),
        timedOut: false, truncated: false } } };
}

test('closed historical diagnostic outcome binds exact operation, command, target, and output bytes', async () => {
  expect(await decodeRoleSystemDiagnosticOutcome(completed(), proposal)).toEqual({
    state: 'completed', command: 'echo owned', exitCode: 0, signal: null,
    stdout: 'owned\n', stderr: '',
  });
  for (const altered of [
    value => { value.receipt.result.stdoutSha256 = 'f'.repeat(64); },
    value => { value.receipt.result.command = 'echo changed'; },
    value => { value.receipt.bindingSha256 = 'a'.repeat(64); },
    value => { value.receipt.result.privateTrace = []; },
  ]) {
    const value = completed(); altered(value);
    await expect(decodeRoleSystemDiagnosticOutcome(value, proposal)).rejects.toThrow();
  }
});

test('not-found, pending, and uncertain results cannot fabricate a completed receipt', async () => {
  expect(await decodeRoleSystemDiagnosticOutcome({ ok: false, state: 'not_found', operationId }, proposal))
    .toEqual({ state: 'not_found' });
  expect(await decodeRoleSystemDiagnosticOutcome({ ok: false, state: 'unknown', operationId,
    automaticRetry: false }, proposal)).toEqual({ state: 'unknown' });
  await expect(decodeRoleSystemDiagnosticOutcome({ ok: true, state: 'completed', operationId }, proposal))
    .rejects.toThrow();
});
