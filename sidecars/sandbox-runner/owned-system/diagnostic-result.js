'use strict';
const { createHash } = require('node:crypto');
const { VERSION, normalizeDiagnosticRequest, diagnosticRequestDigest, diagnosticCommand } = require('./diagnostic-contract');
const KEYS = ['version', 'isolation', 'operationId', 'requestSha256', 'command', 'executed',
  'exitCode', 'signal', 'drained', 'stdout', 'stderr', 'encoding', 'stdoutBytes', 'stderrBytes',
  'stdoutSha256', 'stderrSha256', 'timedOut', 'truncated'].sort().join(',');
const invalid = () => new TypeError('Invalid owned System diagnostic result');

// Checks execution bytes, not authority or semantic claims in learner output.
// The admission service must separately verify the trusted transport/target and
// original launch/persona/session before publishing this result.
function validateDiagnosticResult(value, rawRequest, { maxOutputBytes = 200 * 1024 } = {}) {
  const request = normalizeDiagnosticRequest(rawRequest);
  if (!Number.isSafeInteger(maxOutputBytes) || maxOutputBytes < 1 || maxOutputBytes > 1024 * 1024)
    throw invalid();
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).sort().join(',') !== KEYS
      || value.version !== VERSION || value.isolation !== 'bwrap-system-diagnostic-v1'
      || value.operationId !== request.operationId || value.requestSha256 !== diagnosticRequestDigest(request)
      || value.command !== diagnosticCommand(request) || value.executed !== true || value.drained !== true
      || value.timedOut !== false || value.truncated !== false || value.encoding !== 'base64') throw invalid();
  const exited = Number.isInteger(value.exitCode) && value.exitCode >= 0 && value.exitCode <= 255 && value.signal === null;
  const signaled = value.exitCode === null && Number.isInteger(value.signal) && value.signal >= 1 && value.signal <= 64;
  if (!exited && !signaled) throw invalid();
  let total = 0;
  for (const stream of ['stdout', 'stderr']) {
    const encoded = value[stream], length = value[`${stream}Bytes`], digest = value[`${stream}Sha256`];
    if (typeof encoded !== 'string' || encoded.length > 4 * Math.ceil(maxOutputBytes / 3)
        || !Number.isSafeInteger(length) || length < 0 || length > maxOutputBytes
        || typeof digest !== 'string' || !/^[a-f0-9]{64}$/.test(digest)) throw invalid();
    const bytes = Buffer.from(encoded, 'base64');
    if (bytes.toString('base64') !== encoded || bytes.length !== length
        || createHash('sha256').update(bytes).digest('hex') !== digest) throw invalid();
    total += length;
  }
  if (total > maxOutputBytes) throw invalid();
  return Object.freeze({ ...value });
}
module.exports = { validateDiagnosticResult };
