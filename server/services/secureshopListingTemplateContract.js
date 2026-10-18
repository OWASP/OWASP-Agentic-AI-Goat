'use strict';

const { createHash } = require('node:crypto');

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;

function invalid() {
  throw Object.assign(new TypeError('Invalid listing template request'), { code: 'INVALID_ARGUMENT' });
}

function normalizeListingTemplateRequest(raw) {
  if (!raw || Object.getPrototypeOf(raw) !== Object.prototype) invalid();
  const descriptors = Object.getOwnPropertyDescriptors(raw);
  const keys = ['version', 'operationId', 'productId'];
  if (Reflect.ownKeys(descriptors).length !== keys.length
      || keys.some(key => !Object.hasOwn(descriptors[key] || {}, 'value'))) invalid();
  if (raw.version !== 1 || typeof raw.operationId !== 'string' || !UUID.test(raw.operationId)
      || !Number.isSafeInteger(raw.productId) || raw.productId < 1 || raw.productId > 2147483647) invalid();
  return Object.freeze({ version: 1, operationId: raw.operationId, productId: raw.productId });
}

function listingTemplateRequestDigest(raw) {
  const request = normalizeListingTemplateRequest(raw);
  return createHash('sha256').update(JSON.stringify(request), 'utf8').digest('hex');
}

module.exports = { normalizeListingTemplateRequest, listingTemplateRequestDigest };
