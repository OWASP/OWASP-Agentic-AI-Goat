import { flushShopStorage, shopStorage, SHOP_LISTING_EDIT_KEY } from '../../utils/shopStorage.mjs';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA = /^[a-f0-9]{64}$/;
const REVISION = /^(0|[1-9][0-9]{0,15})$/;
const MAX_ID = 2147483647;
const PATCH_KEYS = ['name', 'description', 'price', 'category', 'templateSource', 'imageUrl'];
const VIEW_KEYS = ['name', 'description', 'descriptionHtml', 'price', 'category', 'templateSource', 'imageUrl'];
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const bytes = value => new TextEncoder().encode(value).byteLength;
const text = (value, max, required = false) => (value === null && !required) || (typeof value === 'string'
  && value.isWellFormed() && !value.includes('\0') && bytes(value) <= max && (!required || value.length > 0));
const same = (a, b) => !!a && Object.keys(a).length === Object.keys(b).length
  && Object.keys(a).every(key => a[key] === b[key]);

export function decodeListingEditView(value) {
  if (!exact(value, VIEW_KEYS) || !text(value.name, 4096, true)
    || typeof value.price !== 'number' || !Number.isFinite(value.price)
    || value.price < 0 || value.price > 99999999.99
    || Number(value.price.toFixed(2)) !== value.price
    || !text(value.description, 65536) || !text(value.descriptionHtml, 65536)
    || !text(value.category, 1024) || !text(value.templateSource, 65536)
    || !text(value.imageUrl, 8192)) throw Error('Saved listing preview is invalid.');
  return Object.freeze(Object.fromEntries(VIEW_KEYS.map(key => [key, value[key]])));
}

export function decodeListingEditPatch(value) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype || Object.keys(value).length === 0
    || Object.keys(value).some(key => !PATCH_KEYS.includes(key))) throw Error('Saved listing preview is invalid.');
  const output = {};
  for (const key of PATCH_KEYS) {
    if (!Object.hasOwn(value, key)) continue;
    const item = value[key];
    if (key === 'price') {
      if (typeof item !== 'number' || !Number.isFinite(item) || item < 0 || item > 99999999.99
        || Number(item.toFixed(2)) !== item) throw Error('Saved listing preview is invalid.');
    } else if (item === null ? key === 'name' : !text(item, key === 'name' ? 4096
      : key === 'description' || key === 'templateSource' ? 65536 : key === 'imageUrl' ? 8192 : 1024,
    key === 'name')) throw Error('Saved listing preview is invalid.');
    output[key] = item;
  }
  return Object.freeze(output);
}

const merged = (before, patch, invalidatesGeneratedHtml) => Object.freeze({ ...before, ...patch,
  ...(invalidatesGeneratedHtml ? { descriptionHtml: null } : {}) });
const digest = async value => [...new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256',
  new TextEncoder().encode(JSON.stringify(value))))].map(byte => byte.toString(16).padStart(2, '0')).join('');

export async function listingEditRequestDigest({ productId, scopeKey, catalogRevision, expectedSnapshotSha256,
  patch, invalidatesGeneratedHtml, after }) {
  if (!Number.isSafeInteger(productId) || productId < 1 || productId > MAX_ID || !SHA.test(scopeKey || '')
    || !REVISION.test(catalogRevision || '') || BigInt(catalogRevision) > BigInt(Number.MAX_SAFE_INTEGER)
    || !SHA.test(expectedSnapshotSha256 || '') || typeof invalidatesGeneratedHtml !== 'boolean')
    throw Error('Saved listing preview is invalid.');
  return digest({ version: 1, productId, scopeKey, catalogRevision, expectedSnapshotSha256,
    patch: decodeListingEditPatch(patch), invalidatesGeneratedHtml, after: decodeListingEditView(after) });
}

export async function decodeListingEditProposal(value) {
  if (value === null) return null;
  if (!exact(value, ['version', 'proposalId', 'product', 'preview']) || value.version !== 1
    || !UUID.test(value.proposalId || '') || !exact(value.product, ['choiceId', 'name'])
    || !UUID.test(value.product.choiceId || '') || !text(value.product.name, 256, true))
    throw Error('Saved listing proposal is invalid.');
  const preview = value.preview;
  if (!exact(preview, ['version', 'productId', 'before', 'after', 'patch', 'catalogRevision',
    'expectedSnapshotSha256', 'requestSha256', 'scopeKey', 'invalidatesGeneratedHtml']) || preview.version !== 1
    || !Number.isSafeInteger(preview.productId) || preview.productId < 1 || preview.productId > MAX_ID
    || !SHA.test(preview.scopeKey || '') || !SHA.test(preview.expectedSnapshotSha256 || '')
    || !SHA.test(preview.requestSha256 || '') || typeof preview.invalidatesGeneratedHtml !== 'boolean'
    || !REVISION.test(preview.catalogRevision || '')
    || BigInt(preview.catalogRevision) > BigInt(Number.MAX_SAFE_INTEGER)) throw Error('Saved listing proposal is invalid.');
  const before = decodeListingEditView(preview.before), patch = decodeListingEditPatch(preview.patch);
  const after = decodeListingEditView(preview.after);
  if (JSON.stringify(merged(before, patch, preview.invalidatesGeneratedHtml)) !== JSON.stringify(after)
    || await listingEditRequestDigest(preview) !== preview.requestSha256)
    throw Error('Saved listing proposal is invalid.');
  return Object.freeze({ version: 1, proposalId: value.proposalId, product: Object.freeze({ ...value.product }),
    preview: Object.freeze({ ...preview, before, after, patch }) });
}

export const sameListingEditProposal = (a, b) => !!a && !!b
  && a.version === b.version && a.proposalId === b.proposalId
  && a.product.choiceId === b.product.choiceId && a.product.name === b.product.name
  && a.preview.productId === b.preview.productId && a.preview.catalogRevision === b.preview.catalogRevision
  && a.preview.expectedSnapshotSha256 === b.preview.expectedSnapshotSha256
  && a.preview.requestSha256 === b.preview.requestSha256 && a.preview.scopeKey === b.preview.scopeKey
  && a.preview.invalidatesGeneratedHtml === b.preview.invalidatesGeneratedHtml
  && JSON.stringify(a.preview.before) === JSON.stringify(b.preview.before)
  && JSON.stringify(a.preview.after) === JSON.stringify(b.preview.after)
  && JSON.stringify(a.preview.patch) === JSON.stringify(b.preview.patch);

export function decodeListingEditReference(raw) {
  if (raw === null) return null;
  if (typeof raw !== 'string' || bytes(raw) > 1024) throw Error('Invalid listing edit reference.');
  let value; try { value = JSON.parse(raw); } catch { throw Error('Invalid listing edit reference.'); }
  if (!exact(value, ['version', 'scopeKey', 'operationId', 'productId', 'catalogRevision', 'requestSha256', 'expectedSnapshotSha256'])
    || value.version !== 1 || !SHA.test(value.scopeKey) || !UUID.test(value.operationId)
    || !Number.isSafeInteger(value.productId) || value.productId < 1 || value.productId > MAX_ID
    || !REVISION.test(value.catalogRevision) || BigInt(value.catalogRevision) > BigInt(Number.MAX_SAFE_INTEGER)
    || !SHA.test(value.requestSha256) || !SHA.test(value.expectedSnapshotSha256))
    throw Error('Invalid listing edit reference.');
  return Object.freeze({ ...value });
}
export const readListingEditReference = () => decodeListingEditReference(shopStorage.getItem(SHOP_LISTING_EDIT_KEY));
export async function saveListingEditReference(reference) {
  const next = decodeListingEditReference(JSON.stringify(reference));
  if (readListingEditReference()) throw Error('Check the saved listing edit before confirming another.');
  shopStorage.setItem(SHOP_LISTING_EDIT_KEY, JSON.stringify(next)); await flushShopStorage();
  if (!same(readListingEditReference(), next)) throw Error('Saved listing edit changed. No update was submitted.');
  return next;
}
export async function clearListingEditReference(reference, current = () => true) {
  const expected = decodeListingEditReference(JSON.stringify(reference));
  if (!current() || !same(readListingEditReference(), expected)) throw Error('Saved listing edit changed. Check it again.');
  try {
    shopStorage.removeItem(SHOP_LISTING_EDIT_KEY); await flushShopStorage();
    if (!current() || readListingEditReference()) throw Error('Saved listing edit changed. Check it again.');
  } catch (error) {
    if (current()) try {
      if (!readListingEditReference()) { shopStorage.setItem(SHOP_LISTING_EDIT_KEY, JSON.stringify(expected)); await flushShopStorage(); }
    } catch { /* The caller retains the unresolved reference. */ }
    throw error;
  }
}

export function decodeListingEditOperation(value, reference) {
  const saved = decodeListingEditReference(JSON.stringify(reference));
  if (exact(value, ['operationId', 'status', 'scopeKey']) && value.operationId === saved.operationId
    && value.status === 'not_found' && value.scopeKey === saved.scopeKey) return Object.freeze({ status: 'not_found' });
  if (!exact(value, ['version', 'operationId', 'productId', 'status', 'scopeKey', 'catalogRevision', 'requestSha256',
    'beforeSha256', 'afterSha256', 'receiptSha256', 'replayed']) || value.version !== 1
    || value.operationId !== saved.operationId || value.productId !== saved.productId || value.status !== 'completed'
    || value.scopeKey !== saved.scopeKey || value.catalogRevision !== saved.catalogRevision
    || value.requestSha256 !== saved.requestSha256
    || value.beforeSha256 !== saved.expectedSnapshotSha256
    || !SHA.test(value.beforeSha256 || '') || !SHA.test(value.afterSha256 || '')
    || !SHA.test(value.receiptSha256 || '') || typeof value.replayed !== 'boolean')
    throw Error('Saved listing edit receipt is invalid.');
  return Object.freeze({ ...value });
}
