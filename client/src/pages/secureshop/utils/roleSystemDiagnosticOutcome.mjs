const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA = /^[a-f0-9]{64}$/;
const VERSION = 'secureshop-owned-system-diagnostic.v1';
const HTTP_VERSION = 'secureshop-owned-system-diagnostic-http.v1';
const encoder = new TextEncoder();
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const fail = () => { throw Error('Saved System diagnostic outcome invalid'); };
async function sha256(value) {
  const digest = await globalThis.crypto.subtle.digest('SHA-256',
    typeof value === 'string' ? encoder.encode(value) : value);
  return [...new Uint8Array(digest)].map(byte => byte.toString(16).padStart(2, '0')).join('');
}
function bytes(value, length, digest) {
  if (typeof value !== 'string' || !Number.isSafeInteger(length) || length < 0
    || length > 200 * 1024 || !SHA.test(digest)) fail();
  let binary;
  try { binary = globalThis.atob(value); } catch { fail(); }
  const data = Uint8Array.from(binary, char => char.charCodeAt(0));
  if (data.byteLength !== length || globalThis.btoa(binary) !== value) fail();
  return data;
}

export async function decodeRoleSystemDiagnosticOutcome(value, proposal) {
  if (!proposal || !UUID.test(proposal.proposalId || '')) fail();
  const operationId = proposal.proposalId;
  if (!value || value.operationId !== operationId) fail();
  if (exact(value, ['ok', 'state', 'operationId']) && value.ok === false
    && value.state === 'not_found') return Object.freeze({ state: 'not_found' });
  if (exact(value, ['ok', 'state', 'operationId', 'automaticRetry'])
    && value.ok === false && value.automaticRetry === false
    && ['admitted', 'pending', 'unknown', 'not_executed'].includes(value.state)) {
    return Object.freeze({ state: value.state });
  }
  if (!exact(value, ['ok', 'state', 'operationId', 'requestSha256', 'targetId', 'receipt'])
    || value.ok !== true || value.state !== 'completed'
    || value.requestSha256 !== proposal.requestSha256 || !UUID.test(value.targetId || '')) fail();
  const receipt = value.receipt;
  if (!exact(receipt, ['version', 'targetId', 'hostname', 'bindingSha256', 'result'])
    || receipt.version !== HTTP_VERSION || receipt.targetId !== value.targetId
    || receipt.hostname !== `system-diag-${value.targetId.replaceAll('-', '')}`
    || !SHA.test(receipt.bindingSha256)) fail();
  if (await sha256(JSON.stringify({ version: HTTP_VERSION, targetId: value.targetId,
    requestSha256: proposal.requestSha256 })) !== receipt.bindingSha256) fail();
  const result = receipt.result;
  if (!exact(result, ['version', 'isolation', 'operationId', 'requestSha256', 'command',
    'executed', 'exitCode', 'signal', 'drained', 'stdout', 'stderr', 'encoding',
    'stdoutBytes', 'stderrBytes', 'stdoutSha256', 'stderrSha256', 'timedOut', 'truncated'])
    || result.version !== VERSION || result.isolation !== 'bwrap-system-diagnostic-v1'
    || result.operationId !== operationId || result.requestSha256 !== proposal.requestSha256
    || result.command !== `${proposal.cmd_template} ${proposal.args}`.trim()
    || result.executed !== true || result.drained !== true || result.timedOut !== false
    || result.truncated !== false || result.encoding !== 'base64') fail();
  const exited = Number.isInteger(result.exitCode) && result.exitCode >= 0
    && result.exitCode <= 255 && result.signal === null;
  const signaled = result.exitCode === null && Number.isInteger(result.signal)
    && result.signal >= 1 && result.signal <= 64;
  if (!exited && !signaled) fail();
  const stdout = bytes(result.stdout, result.stdoutBytes, result.stdoutSha256);
  const stderr = bytes(result.stderr, result.stderrBytes, result.stderrSha256);
  if (stdout.byteLength + stderr.byteLength > 200 * 1024
    || await sha256(stdout) !== result.stdoutSha256
    || await sha256(stderr) !== result.stderrSha256) fail();
  return Object.freeze({ state: 'completed', command: result.command,
    exitCode: result.exitCode, signal: result.signal,
    stdout: new TextDecoder().decode(stdout), stderr: new TextDecoder().decode(stderr) });
}
