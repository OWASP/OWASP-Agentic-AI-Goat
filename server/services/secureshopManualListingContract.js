'use strict';

// These hashes bind a manual business operation, not a human gesture or model provenance.
const { createHash } = require('node:crypto');
const edit = require('./secureshopListingEditContract');
const SHA = /^[a-f0-9]{64}$/;
const FIELDS = ['name', 'description', 'price', 'category', 'images', 'templateSource'];
const MAX_BYTES = 128 * 1024;
const fail = () => Object.assign(Error('Invalid manual listing request'), { code: 'INVALID_ARGUMENT' });
const exact = (v, keys) => v && Object.getPrototypeOf(v) === Object.prototype
  && Object.keys(v).sort().join(',') === keys.slice().sort().join(',');
const digest = v => createHash('sha256').update(JSON.stringify(v)).digest('hex');
function bounded(value) {
  if (Buffer.byteLength(JSON.stringify(value), 'utf8') > MAX_BYTES) throw fail();
  return value;
}
function images(value) {
  if (!Array.isArray(value) || value.length > 16 || Object.keys(value).length !== value.length
      || Object.keys(value).some((key, index) => key !== String(index))
      || value.some(v => typeof v !== 'string' || !v || !v.isWellFormed() || v.includes('\0')
        || Buffer.byteLength(v, 'utf8') > 8192)) throw fail();
  return Object.freeze(value.slice());
}
function listing(value) {
  if (!exact(value, FIELDS)) throw fail();
  let normalized;
  try { normalized = edit.normalizeListingEditPatch({ name: value.name, description: value.description,
    price: value.price, category: value.category, templateSource: value.templateSource }); }
  catch { throw fail(); }
  for (const v of Object.values(normalized)) if (typeof v === 'string' && (!v.isWellFormed() || v.includes('\0'))) throw fail();
  return Object.freeze({ name: normalized.name, description: normalized.description, price: normalized.price,
    category: normalized.category, images: images(value.images), templateSource: normalized.templateSource });
}
function view(value) {
  if (!exact(value, ['name', 'description', 'descriptionHtml', 'price', 'category', 'templateSource', 'imageUrl', 'images'])) throw fail();
  const { images: raw, ...base } = value;
  let normalized;
  try { normalized = edit.listingEditView(base); } catch { throw fail(); }
  return Object.freeze({ ...normalized, images: images(raw) });
}
function after(before, item, invalidatesGeneratedHtml) {
  return view({ ...before, name: item.name, description: item.description, price: item.price,
    category: item.category, templateSource: item.templateSource, images: item.images,
    imageUrl: item.images[0] || null, descriptionHtml: invalidatesGeneratedHtml ? null : before.descriptionHtml });
}
function scopeKey(kind, binding, actor, session) {
  if (!['create', 'edit'].includes(kind)) throw fail();
  return digest([`owned-merchant-manual-listing-${kind}.v1`, edit.listingEditScopeKey(binding, actor, session)]);
}
function base(value) {
  const isEdit = value?.kind === 'edit';
  const keys = ['version', 'origin', 'kind', ...(isEdit ? ['productId'] : []), 'listing',
    ...(isEdit ? ['before', 'after', 'catalogRevision', 'expectedSnapshotSha256', 'invalidatesGeneratedHtml']
      : ['currency', 'initialStock', 'status']), 'scopeKey'];
  if (!exact(value, keys) || value.version !== 1 || value.origin !== 'manual'
      || !['create', 'edit'].includes(value.kind) || !SHA.test(value.scopeKey || '')) throw fail();
  const item = listing(value.listing);
  if (!isEdit) {
    if (value.currency !== 'USD' || value.initialStock !== 0 || value.status !== 'active') throw fail();
    return { version: 1, origin: 'manual', kind: 'create', listing: item,
      currency: 'USD', initialStock: 0, status: 'active', scopeKey: value.scopeKey };
  }
  if (!Number.isSafeInteger(value.productId) || value.productId < 1 || value.productId > 2147483647
      || typeof value.catalogRevision !== 'string' || !/^(0|[1-9][0-9]{0,15})$/.test(value.catalogRevision)
      || BigInt(value.catalogRevision) > 9007199254740991n || !SHA.test(value.expectedSnapshotSha256 || '')
      || typeof value.invalidatesGeneratedHtml !== 'boolean') throw fail();
  const before = view(value.before), next = view(value.after);
  if (JSON.stringify(after(before, item, value.invalidatesGeneratedHtml)) !== JSON.stringify(next)) throw fail();
  return { version: 1, origin: 'manual', kind: 'edit', productId: value.productId, listing: item,
    before, after: next, catalogRevision: value.catalogRevision, expectedSnapshotSha256: value.expectedSnapshotSha256,
    invalidatesGeneratedHtml: value.invalidatesGeneratedHtml, scopeKey: value.scopeKey };
}
function makePreview(value) {
  const normalized = base(value);
  return Object.freeze(bounded({ ...normalized, requestSha256: digest(normalized) }));
}
function preview(value, kind) {
  if (!value || !Object.hasOwn(value, 'requestSha256') || value.kind !== kind) throw fail();
  const { requestSha256, ...raw } = value, normalized = makePreview(raw);
  if (requestSha256 !== normalized.requestSha256) throw fail();
  return normalized;
}
module.exports = { normalizeManualListing: listing, manualListingView: view, manualListingAfter: after,
  manualListingScopeKey: scopeKey, makeManualListingPreview: makePreview,
  validateManualListingPreview: preview, boundManualListingRequest: bounded,
  manualListingStorageScope: (createKey, editKey) => {
    if (![createKey, editKey].every(key => SHA.test(key || ''))) throw fail();
    return digest(['owned-merchant-manual-listings-storage.v1', createKey, editKey]);
  } };
