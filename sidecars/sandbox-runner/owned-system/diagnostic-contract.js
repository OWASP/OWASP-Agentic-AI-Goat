'use strict';
const { createHash } = require('node:crypto');
const VERSION = 'secureshop-owned-system-diagnostic.v1';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const MAX_FIELD_BYTES = 8192;

// This only normalizes a teaching request; it never executes a command.
// Shell syntax intentionally survives unchanged for the isolated executor.
function normalizeDiagnosticRequest(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)
      || Object.keys(raw).sort().join(',') !== 'args,cmd_template,operationId'
      || typeof raw.operationId !== 'string' || !UUID.test(raw.operationId)) {
    throw new TypeError('Invalid System diagnostic request');
  }
  for (const value of [raw.cmd_template, raw.args]) {
    if (typeof value !== 'string' || !value.isWellFormed() || value.includes('\0') || Buffer.byteLength(value) > MAX_FIELD_BYTES)
      throw new TypeError('Invalid System diagnostic request');
  }
  if (!`${raw.cmd_template} ${raw.args}`.trim()) throw new TypeError('Empty System diagnostic command');
  return Object.freeze({ operationId: raw.operationId, cmd_template: raw.cmd_template, args: raw.args });
}
function diagnosticCommand(raw) {
  const request = normalizeDiagnosticRequest(raw);
  return `${request.cmd_template} ${request.args}`.trim();
}
function diagnosticRequestDigest(raw) {
  return createHash('sha256').update(JSON.stringify({ version: VERSION,
    request: normalizeDiagnosticRequest(raw) })).digest('hex');
}
module.exports = { VERSION, MAX_FIELD_BYTES, normalizeDiagnosticRequest, diagnosticCommand, diagnosticRequestDigest };
