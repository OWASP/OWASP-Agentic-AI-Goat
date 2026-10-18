'use strict';

const { createHash } = require('node:crypto');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const LIMITS = Object.freeze({ title: 1024, description: 32768, url: 4096, optimizeArgs: 8192 });
function invalid() {
  throw Object.assign(new Error('Invalid owned listing request'), { code: 'INVALID_ARGUMENT' });
}
function data(raw) {
  if (!raw || ![Object.prototype, null].includes(Object.getPrototypeOf(raw))) invalid();
  const descriptors = Object.getOwnPropertyDescriptors(raw);
  if (Reflect.ownKeys(descriptors).some(key => typeof key !== 'string'
      || !Object.hasOwn(descriptors[key], 'value'))) invalid();
  return descriptors;
}
function text(value, max, allowEmpty = false) {
  if (typeof value !== 'string' || !value.isWellFormed() || value.includes('\0')
      || (!allowEmpty && !value.trim()) || Buffer.byteLength(value, 'utf8') > max) invalid();
  return value;
}
function sourceUrl(value) {
  if (value === null) return null;
  text(value, LIMITS.url);
  let parsed;
  try { parsed = new URL(value); } catch { invalid(); }
  if (!['http:', 'https:'].includes(parsed.protocol)) invalid();
  // Preserve attack bytes. Resolution belongs exclusively to the owned executor;
  // a syntactically accepted address is never permission for a backend fetch.
  return value;
}
function normalizeListingRequest(raw) {
  const descriptors = data(raw);
  const action = descriptors.action?.value;
  const fields = action === 'rewrite' ? ['title', 'description']
    : action === 'import' ? ['json_url', 'xml_url']
      : action === 'optimize' ? ['productId', 'imageUrl', 'imageUrlSha256', 'sceneId', 'sceneGeneration', 'grantId'] : invalid();
  const keys = ['version', 'action', 'operationId', ...fields];
  if (Reflect.ownKeys(descriptors).length !== keys.length
      || keys.some(key => !Object.hasOwn(descriptors, key))) invalid();
  if (raw.version !== 1 || typeof raw.operationId !== 'string' || !UUID.test(raw.operationId)) invalid();
  const common = { version: 1, action, operationId: raw.operationId };
  if (action === 'rewrite') return Object.freeze({ ...common,
    title: text(raw.title, LIMITS.title), description: text(raw.description, LIMITS.description, true) });
  if (action === 'optimize') {
    if (!Number.isSafeInteger(raw.productId) || raw.productId < 1 || raw.productId > 2147483647 || !UUID.test(raw.sceneId) || !Number.isSafeInteger(raw.sceneGeneration) || raw.sceneGeneration < 1 || !UUID.test(raw.grantId)) invalid();
    const imageUrl = sourceUrl(raw.imageUrl);
    const imageUrlSha256 = createHash('sha256').update(imageUrl, 'utf8').digest('hex');
    if (raw.imageUrlSha256 !== imageUrlSha256
        || Buffer.byteLength(`${imageUrl} -strip -quality 82 ${imageUrl}.opt.jpg`, 'utf8') > LIMITS.optimizeArgs) invalid();
    return Object.freeze({ ...common, productId: raw.productId, imageUrl, imageUrlSha256, sceneId: raw.sceneId, sceneGeneration: raw.sceneGeneration, grantId: raw.grantId });
  }
  const json_url = sourceUrl(raw.json_url), xml_url = sourceUrl(raw.xml_url);
  if (json_url === null && xml_url === null) invalid();
  return Object.freeze({ ...common, json_url, xml_url });
}
function listingRequestDigest(raw) {
  return createHash('sha256').update(JSON.stringify(normalizeListingRequest(raw)), 'utf8').digest('hex');
}
module.exports = { normalizeListingRequest, listingRequestDigest, LISTING_REQUEST_LIMITS: LIMITS };
