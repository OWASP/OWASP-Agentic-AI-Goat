'use strict';

const {
  createHash
} = require('node:crypto');
const {
  normalizeInput
} = require('./input');
const VERSION = 'secureshop-owned-pricing-http.v1';
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const BINDING = ['targetId', 'operationId', 'runId', 'callId', 'requestSha256'];
const exact = (x, keys) => x && Object.getPrototypeOf(x) === Object.prototype && Reflect.ownKeys(x).length === keys.length && keys.every(k => Object.hasOwn(Object.getOwnPropertyDescriptor(x, k) || {}, 'value'));
const hash = x => createHash('sha256').update(x).digest('hex');
function normalizeRequest(raw) {
  if (!exact(raw, ['version', ...BINDING, 'input']) || raw.version !== VERSION || !['targetId', 'operationId', 'runId'].every(k => UUID.test(raw[k])) || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(raw.callId) || !/^[a-f0-9]{64}$/.test(raw.requestSha256)) throw Error('PRICING_HTTP_REQUEST_INVALID');
  return Object.freeze({
    version: VERSION,
    ...Object.fromEntries(BINDING.map(k => [k, raw[k]])),
    input: normalizeInput(raw.input)
  });
}
const digest = raw => hash(JSON.stringify(normalizeRequest(raw)));
function bindResult(raw, execution) {
  const request = normalizeRequest(raw);
  if (!exact(execution, ['drained', 'result']) || execution.drained !== true || !execution.result || Buffer.byteLength(JSON.stringify(execution)) > 65536) throw Error('PRICING_HTTP_RESULT_INVALID');
  return Object.freeze({
    version: VERSION,
    ...Object.fromEntries(BINDING.map(k => [k, request[k]])),
    wireSha256: digest(request),
    execution
  });
}
function validateResult(raw, value) {
  const request = normalizeRequest(raw);
  if (!exact(value, ['version', ...BINDING, 'wireSha256', 'execution']) || value.version !== VERSION || BINDING.some(k => value[k] !== request[k]) || value.wireSha256 !== digest(request)) throw Error('PRICING_HTTP_RESULT_MISMATCH');
  return bindResult(request, value.execution).execution;
}
module.exports = {
  VERSION,
  normalizeRequest,
  bindResult,
  validateResult,
  digest,
  exact
};
