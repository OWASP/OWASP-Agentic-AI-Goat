import { webcrypto } from 'node:crypto';
import { decodeRoleSystemDiagnosticProposal } from './roleSystemDiagnosticProposal.mjs';

const digest = async value => [...new Uint8Array(await webcrypto.subtle.digest('SHA-256',
  new TextEncoder().encode(value)))].map(byte => byte.toString(16).padStart(2, '0')).join('');
const canonical = value => Array.isArray(value) ? `[${value.map(canonical).join(',')}]`
  : value && typeof value === 'object'
    ? `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`
    : JSON.stringify(value);
const proposalId = 'cccccccc-cccc-5ccc-8ccc-cccccccccccc';

beforeAll(() => { Object.defineProperty(globalThis, 'crypto', { configurable: true, value: webcrypto }); });

async function proposal() {
  const request = { operationId: proposalId, cmd_template: 'echo', args: "<img src=x onerror=alert('owned')>" };
  const body = { version: 1, proposalId, action: 'system_diagnostic',
    cmd_template: request.cmd_template, args: request.args, scopeKey: 'a'.repeat(64),
    diagnosticCapability: 'secureshop-owned-system-diagnostic.v1',
    sourceSnapshotSha256: 'b'.repeat(64),
    modeCapability: { version: 1, featureId: 'system_diagnostic',
      policyVersion: 'owned-system-diagnostic-shell-v1', effectiveMode: 'vuln',
      scope: { kind: 'launch_feature', id: 'system_diagnostic' } },
    requestSha256: await digest(JSON.stringify({ version: 'secureshop-owned-system-diagnostic.v1', request })) };
  return { ...body, proposalSha256: await digest(canonical(body)) };
}

test('closed role diagnostic proposal validates exact command, request, and source digest', async () => {
  const valid = await proposal();
  expect(await decodeRoleSystemDiagnosticProposal(valid)).toEqual(valid);
  for (const altered of [
    { ...valid, args: 'changed' }, { ...valid, cmd_template: 'curl' },
    { ...valid, sourceSnapshotSha256: 'c'.repeat(64) },
    { ...valid, modeCapability: { ...valid.modeCapability, effectiveMode: 'fixed' } },
    { ...valid, origin: { step: 1, callId: 'private' } },
  ]) await expect(decodeRoleSystemDiagnosticProposal(altered)).rejects.toThrow();
});
