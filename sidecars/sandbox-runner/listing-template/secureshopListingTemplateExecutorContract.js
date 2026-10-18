'use strict';

const { createHash } = require('node:crypto');

const VERSION = 1;
const ISOLATION = 'bwrap-listing-template-v1';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA = /^[0-9a-f]{64}$/;
const REQUEST_KEYS = ['version', 'operationId', 'productId', 'sourceSha256', 'templateSource', 'title', 'description', 'price'];
const RESULT_KEYS = ['version', 'operationId', 'productId', 'requestSha256', 'sourceSha256', 'isolation',
  'rendered', 'renderedSha256', 'exitCode', 'timedOut', 'truncated', 'drained',
  'workerAttested', 'commandEffectObserved', 'effectSha256'];

function invalid() { throw Object.assign(new TypeError('Invalid listing template execution contract'), { code: 'LISTING_TEMPLATE_INVALID' }); }
function exact(value, keys) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype) invalid();
  const fields = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(fields).length !== keys.length || keys.some(key => !Object.hasOwn(fields[key] || {}, 'value'))) invalid();
}
function text(value, limit) {
  if (typeof value !== 'string' || !value.isWellFormed() || value.includes('\0') || Buffer.byteLength(value, 'utf8') > limit) invalid();
  return value;
}
const digest = value => createHash('sha256').update(value).digest('hex');
function normalizeListingTemplateExecution(raw) {
  exact(raw, REQUEST_KEYS);
  if (raw.version !== VERSION || !UUID.test(raw.operationId) || !Number.isSafeInteger(raw.productId)
      || raw.productId < 1 || raw.productId > 2147483647 || !SHA.test(raw.sourceSha256)
      || typeof raw.price !== 'number' || !Number.isFinite(raw.price) || raw.price < 0
      || raw.price > 99999999.99 || raw.price !== Number(raw.price.toFixed(2))) invalid();
  const templateSource = text(raw.templateSource, 16 * 1024);
  if (!templateSource || digest(Buffer.from(templateSource, 'utf8')) !== raw.sourceSha256) invalid();
  return Object.freeze({ version: VERSION, operationId: raw.operationId, productId: raw.productId,
    sourceSha256: raw.sourceSha256, templateSource,
    title: text(raw.title, 4096), description: text(raw.description, 65536), price: raw.price });
}
function listingTemplateExecutionDigest(raw) {
  const request = normalizeListingTemplateExecution(raw);
  return digest(JSON.stringify(request));
}
function validateListingTemplateExecutionResult(rawRequest, raw) {
  const request = normalizeListingTemplateExecution(rawRequest);
  exact(raw, RESULT_KEYS);
  if (raw.version !== VERSION || raw.operationId !== request.operationId || raw.productId !== request.productId
      || raw.requestSha256 !== listingTemplateExecutionDigest(request) || raw.sourceSha256 !== request.sourceSha256
      || raw.isolation !== ISOLATION || !SHA.test(raw.renderedSha256)
      || typeof raw.rendered !== 'string' || !raw.rendered.isWellFormed()
      || Buffer.byteLength(raw.rendered, 'utf8') > 65536 || digest(Buffer.from(raw.rendered, 'utf8')) !== raw.renderedSha256
      || !Number.isInteger(raw.exitCode) || typeof raw.timedOut !== 'boolean'
      || typeof raw.truncated !== 'boolean' || typeof raw.drained !== 'boolean'
      || typeof raw.workerAttested !== 'boolean' || typeof raw.commandEffectObserved !== 'boolean'
      || (raw.effectSha256 !== null && !SHA.test(raw.effectSha256))
      || (raw.commandEffectObserved && (!raw.workerAttested || raw.effectSha256 === null))
      || (raw.exitCode === 0 && (!raw.workerAttested || !raw.drained || raw.timedOut || raw.truncated))) invalid();
  return Object.freeze({ ...raw });
}

module.exports = { VERSION, ISOLATION, REQUEST_KEYS, RESULT_KEYS, digest, normalizeListingTemplateExecution,
  listingTemplateExecutionDigest, validateListingTemplateExecutionResult };
