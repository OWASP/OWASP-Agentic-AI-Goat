'use strict';

const { createHash } = require('node:crypto');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA = /^[a-f0-9]{64}$/;
const REVISION = /^(0|[1-9][0-9]{0,15})$/;
const PATCH_KEYS = Object.freeze(['name', 'description', 'price', 'category', 'templateSource', 'imageUrl']);
const VIEW_KEYS = Object.freeze(['name', 'description', 'descriptionHtml', 'price', 'category', 'templateSource', 'imageUrl']);
const LISTING_EDIT_PATCH_SCHEMA = Object.freeze({ type: 'object', minProperties: 1,
  properties: Object.freeze({ name: { type: 'string', minLength: 1, maxLength: 4096 },
    description: { type: ['string', 'null'], maxLength: 65536 },
    price: { type: 'number', minimum: 0, maximum: 99999999.99, multipleOf: 0.01 },
    category: { type: ['string', 'null'], maxLength: 1024 },
    templateSource: { type: ['string', 'null'], maxLength: 65536 },
    imageUrl: { type: ['string', 'null'], maxLength: 8192 } }), additionalProperties: false });
const fail = (code = 'LISTING_EDIT_INVALID') => Object.assign(new Error('Owned listing edit unavailable'), { code });
const exact = (value, keys) => value !== null && typeof value === 'object'
  && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === keys.slice().sort().join(',');
const digest = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
function normalizedPatch(value) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype
      || Object.keys(value).length === 0 || Object.keys(value).some(key => !PATCH_KEYS.includes(key))) throw fail();
  const output = {};
  for (const key of PATCH_KEYS) {
    if (!Object.hasOwn(value, key)) continue;
    const item = value[key];
    if (key === 'price') {
      if (typeof item !== 'number' || !Number.isFinite(item) || item < 0 || item > 99999999.99
          || Math.abs(item * 100 - Math.round(item * 100)) > 1e-8) throw fail();
      output.price = Number(item.toFixed(2));
      continue;
    }
    const max = key === 'name' ? 4096 : key === 'description' || key === 'templateSource' ? 65536
      : key === 'imageUrl' ? 8192 : 1024;
    if ((item === null && key === 'name') || (item !== null && (typeof item !== 'string'
        || Buffer.byteLength(item, 'utf8') > max || (key === 'name' && !item)))) throw fail();
    output[key] = item;
  }
  return Object.freeze(output);
}
function view(value) {
  if (!exact(value, VIEW_KEYS) || typeof value.name !== 'string' || !value.name
      || Buffer.byteLength(value.name, 'utf8') > 4096 || typeof value.price !== 'number'
      || !Number.isFinite(value.price) || value.price < 0 || value.price > 99999999.99)
    throw fail();
  for (const [key, max] of [['description', 65536], ['descriptionHtml', 65536],
    ['category', 1024], ['templateSource', 65536], ['imageUrl', 8192]]) {
    if (value[key] !== null && (typeof value[key] !== 'string' || Buffer.byteLength(value[key], 'utf8') > max)) throw fail();
  }
  return Object.freeze(Object.fromEntries(VIEW_KEYS.map(key => [key, value[key]])));
}
function merged(before, patch, invalidatesGeneratedHtml = false) {
  const result = { ...view(before) };
  for (const key of PATCH_KEYS) if (Object.hasOwn(patch, key)) result[key] = patch[key];
  if (invalidatesGeneratedHtml) result.descriptionHtml = null;
  return view(result);
}
function scopeKey(binding, actorId, session) {
  if (!binding?.scene || !UUID.test(binding.targetId || '') || !UUID.test(binding.launchId || '')
      || !UUID.test(binding.scenarioId || '') || !UUID.test(binding.scene.sceneId || '')
      || !UUID.test(binding.scene.grantId || '') || !Number.isSafeInteger(binding.generation)
      || !Number.isSafeInteger(binding.scene.sceneGeneration)
      || !Number.isSafeInteger(binding.platformOwnerId) || !Number.isSafeInteger(binding.platformSessionId)
      || !Number.isSafeInteger(actorId) || !UUID.test(session?.sessionId || '')
      || !/^[1-9]\d*$/.test(session.authorityVersion || '')) throw fail('SHOP_AUTH_INVALID');
  return digest(['owned-merchant-listing-edit.v1', binding.targetId.toLowerCase(), binding.launchId.toLowerCase(),
    binding.scenarioId.toLowerCase(), binding.generation, binding.platformOwnerId, binding.platformSessionId,
    binding.scene.sceneId.toLowerCase(), binding.scene.sceneGeneration, binding.scene.grantId.toLowerCase(),
    actorId, session.sessionId.toLowerCase(), session.authorityVersion]);
}
function requestDigest({ productId, scopeKey: key, catalogRevision, expectedSnapshotSha256, patch,
  invalidatesGeneratedHtml, after }) {
  if (!Number.isSafeInteger(productId) || productId < 1 || productId > 2147483647
      || !SHA.test(key || '') || !REVISION.test(catalogRevision || '')
      || BigInt(catalogRevision) > 9007199254740991n || !SHA.test(expectedSnapshotSha256 || '')
      || typeof invalidatesGeneratedHtml !== 'boolean') throw fail();
  return digest({ version: 1, productId, scopeKey: key, catalogRevision, expectedSnapshotSha256,
    patch: normalizedPatch(patch), invalidatesGeneratedHtml, after: view(after) });
}
function preview(value) {
  if (!exact(value, ['version', 'productId', 'before', 'after', 'patch', 'catalogRevision',
    'expectedSnapshotSha256', 'requestSha256', 'scopeKey', 'invalidatesGeneratedHtml'])
      || value.version !== 1 || typeof value.invalidatesGeneratedHtml !== 'boolean') throw fail();
  const patch = normalizedPatch(value.patch), before = view(value.before), after = view(value.after);
  if (JSON.stringify(merged(before, patch, value.invalidatesGeneratedHtml)) !== JSON.stringify(after)
      || value.requestSha256 !== requestDigest({ ...value, patch })) throw fail();
  return Object.freeze({ ...value, before, after, patch });
}
function receipt(value, operationId) {
  if (!UUID.test(operationId || '') || !value || Object.getPrototypeOf(value) !== Object.prototype
      || value.operationId !== operationId.toLowerCase() || !SHA.test(value.scopeKey || '')) throw fail();
  if (value.status === 'not_found') {
    if (!exact(value, ['operationId', 'status', 'scopeKey'])) throw fail();
    return Object.freeze({ ...value });
  }
  if (!exact(value, ['version', 'operationId', 'productId', 'status', 'scopeKey',
    'catalogRevision', 'requestSha256', 'beforeSha256', 'afterSha256', 'receiptSha256', 'replayed'])
      || value.version !== 1 || value.status !== 'completed' || typeof value.replayed !== 'boolean'
      || !Number.isSafeInteger(value.productId) || value.productId < 1 || value.productId > 2147483647
      || !REVISION.test(value.catalogRevision || '') || BigInt(value.catalogRevision) > 9007199254740991n
      || ![value.requestSha256, value.beforeSha256, value.afterSha256, value.receiptSha256]
        .every(hash => SHA.test(hash || ''))) throw fail();
  return Object.freeze({ ...value });
}
module.exports = { normalizeListingEditPatch: normalizedPatch, validateListingEditPreview: preview,
  validateListingEditReceipt: receipt,
  listingEditRequestDigest: requestDigest, listingEditScopeKey: scopeKey, listingEditView: view,
  listingEditMergedView: merged, listingEditDigest: digest, LISTING_EDIT_SHA: SHA, LISTING_EDIT_PATCH_SCHEMA };
