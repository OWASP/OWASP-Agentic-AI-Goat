const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA = /^[a-f0-9]{64}$/;
const CAPABILITY = 'secureshop-owned-system-diagnostic.v1';
const POLICY = 'owned-system-diagnostic-shell-v1';
const VERSION = 'secureshop-owned-system-diagnostic.v1';
const encoder = new TextEncoder();
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const canonical = value => Array.isArray(value) ? `[${value.map(canonical).join(',')}]`
  : value && Object.getPrototypeOf(value) === Object.prototype
    ? `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`
    : JSON.stringify(value);
const fail = () => { throw Error('Saved System diagnostic proposal invalid'); };
async function sha256(value) {
  const bytes = await globalThis.crypto.subtle.digest('SHA-256', encoder.encode(value));
  return [...new Uint8Array(bytes)].map(byte => byte.toString(16).padStart(2, '0')).join('');
}
const diagnosticText = value => typeof value === 'string' && value.isWellFormed()
  && !value.includes('\0') && encoder.encode(value).byteLength <= 8192;

export async function decodeRoleSystemDiagnosticProposal(value) {
  if (value == null) return null;
  if (!exact(value, ['version', 'proposalId', 'action', 'cmd_template', 'args', 'scopeKey',
    'diagnosticCapability', 'sourceSnapshotSha256', 'modeCapability', 'requestSha256',
    'proposalSha256']) || value.version !== 1 || value.action !== 'system_diagnostic'
    || !UUID.test(value.proposalId) || !SHA.test(value.scopeKey)
    || value.diagnosticCapability !== CAPABILITY || !SHA.test(value.sourceSnapshotSha256)
    || !SHA.test(value.requestSha256) || !SHA.test(value.proposalSha256)
    || !diagnosticText(value.cmd_template) || !diagnosticText(value.args)
    || !`${value.cmd_template} ${value.args}`.trim()) fail();
  const mode = value.modeCapability;
  if (!exact(mode, ['version', 'featureId', 'policyVersion', 'effectiveMode', 'scope'])
    || mode.version !== 1 || mode.featureId !== 'system_diagnostic'
    || mode.policyVersion !== POLICY || !['vuln', 'fixed'].includes(mode.effectiveMode)
    || !exact(mode.scope, ['kind', 'id']) || mode.scope.kind !== 'launch_feature'
    || mode.scope.id !== 'system_diagnostic') fail();
  const request = { operationId: value.proposalId, cmd_template: value.cmd_template,
    args: value.args };
  if (await sha256(JSON.stringify({ version: VERSION, request })) !== value.requestSha256) fail();
  const body = { version: 1, proposalId: value.proposalId, action: 'system_diagnostic',
    cmd_template: value.cmd_template, args: value.args, scopeKey: value.scopeKey,
    diagnosticCapability: CAPABILITY, sourceSnapshotSha256: value.sourceSnapshotSha256,
    modeCapability: { version: 1, featureId: mode.featureId, policyVersion: mode.policyVersion,
      effectiveMode: mode.effectiveMode, scope: { kind: mode.scope.kind, id: mode.scope.id } },
    requestSha256: value.requestSha256 };
  if (await sha256(canonical(body)) !== value.proposalSha256) fail();
  return Object.freeze({ ...body, proposalSha256: value.proposalSha256 });
}
