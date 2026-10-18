import { flushShopStorage, shopStorage, SHOP_LISTING_CREATE_KEY } from '../../utils/shopStorage.mjs';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA = /^[a-f0-9]{64}$/;
const MAX_ID = 2147483647;
const LISTING_POLICY = 'owned-listing-import-v1';
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const bytes = value => new TextEncoder().encode(value).byteLength;
const text = (value, max, required = false) => (value === null && !required) || (typeof value === 'string' && value.isWellFormed()
  && !value.includes('\0') && bytes(value) <= max && (!required || value.length > 0));
const same = (a, b) => !!a && Object.keys(a).length === Object.keys(b).length
  && Object.keys(a).every(key => a[key] === b[key]);
const price = value => typeof value === 'number' && Number.isFinite(value) && value >= 0
  && value <= 99999999.99 && Number(value.toFixed(2)) === value;
const digest = async value => [...new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256',
  new TextEncoder().encode(JSON.stringify(value))))].map(byte => byte.toString(16).padStart(2, '0')).join('');
const escapeHtml = value => value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
const invalidDraft = () => { throw Error('Saved listing draft is invalid.'); };

function normalizeListing(value, version) {
  const html = version === 2;
  if (!exact(value, ['name', 'description', 'category', 'price', ...(html ? ['presentation'] : [])])
    || !text(value.name, 4096, true) || !text(value.description, html ? 8192 : 65536, html)
    || !text(value.category, 1024) || !price(value.price) || (html && value.presentation !== 'html')) invalidDraft();
  return Object.freeze({ name: value.name, description: value.description, category: value.category,
    price: value.price, ...(html ? { presentation: 'html' } : {}) });
}
function normalizeScope(value) {
  if (!exact(value, ['launchId', 'scenarioId', 'generation', 'platformOwnerId', 'platformSessionId'])
    || ![value.launchId, value.scenarioId].every(id => UUID.test(id || '') && id === id.toLowerCase())
    || !Number.isSafeInteger(value.generation) || value.generation < 1
    || ![value.platformOwnerId, value.platformSessionId].every(id => Number.isSafeInteger(id) && id >= 1 && id <= MAX_ID)) invalidDraft();
  return Object.freeze({ launchId: value.launchId, scenarioId: value.scenarioId, generation: value.generation,
    platformOwnerId: value.platformOwnerId, platformSessionId: value.platformSessionId });
}
function normalizeExecution(value) {
  if (!exact(value, ['version', 'featureId', 'policyVersion', 'mode', 'generation', 'modeStamp', 'scope'])
    || value.version !== 1 || value.featureId !== 'listings' || value.policyVersion !== LISTING_POLICY
    || !['vuln', 'fixed'].includes(value.mode) || !Number.isSafeInteger(value.generation) || value.generation < 0
    || value.generation > MAX_ID || !text(value.modeStamp, 128, true)) invalidDraft();
  return Object.freeze({ version: 1, featureId: 'listings', policyVersion: LISTING_POLICY, mode: value.mode,
    generation: value.generation, modeStamp: value.modeStamp, scope: normalizeScope(value.scope) });
}
function normalizeSource(value) {
  if (!exact(value, ['version', 'kind', 'listing', 'authoredHtml', 'storedHtml', 'preparation', 'execution'])
    || bytes(JSON.stringify(value)) > 131072 || value.version !== 1 || value.kind !== 'merchant_authored_html') invalidDraft();
  const listing = normalizeListing(value.listing, 2), preparation = value.preparation;
  if (!exact(preparation, ['sessionId', 'requestId', 'step', 'callId', 'message'])
    || ![preparation.sessionId, preparation.requestId].every(id => UUID.test(id || '') && id === id.toLowerCase())
    || !Number.isSafeInteger(preparation.step) || preparation.step < 1 || preparation.step > 4
    || !text(preparation.callId, 128, true) || !text(preparation.message, 8192, true)
    || value.authoredHtml !== listing.description || !preparation.message.includes(value.authoredHtml)) invalidDraft();
  const execution = normalizeExecution(value.execution);
  if (!text(value.storedHtml, 65536, true)
    || value.storedHtml !== (execution.mode === 'vuln' ? value.authoredHtml : escapeHtml(value.authoredHtml))) invalidDraft();
  return Object.freeze({ version: 1, kind: 'merchant_authored_html', listing, authoredHtml: value.authoredHtml,
    storedHtml: value.storedHtml, preparation: Object.freeze({ sessionId: preparation.sessionId,
      requestId: preparation.requestId, step: preparation.step, callId: preparation.callId, message: preparation.message }), execution });
}

function normalizedPreview(value, requireDigest) {
  const version = value?.version;
  if (![1, 2].includes(version)
    || !exact(value, ['version', 'listing', 'currency', 'initialStock', 'status', 'scopeKey', 'requestSha256', ...(version === 2 ? ['source'] : [])])
    || !SHA.test(value.scopeKey || '') || (requireDigest && !SHA.test(value.requestSha256 || ''))
    || value.currency !== 'USD' || value.initialStock !== 0 || value.status !== 'active') invalidDraft();
  const listing = normalizeListing(value.listing, version);
  const source = version === 2 ? normalizeSource(value.source) : null;
  if (source && JSON.stringify(source.listing) !== JSON.stringify(listing)) invalidDraft();
  return { version, listing, scopeKey: value.scopeKey, source };
}
export async function listingCreateSourceDigest(value) { return digest(normalizeSource(value)); }
export async function listingCreateRequestDigest(value) {
  const normalized = normalizedPreview({ ...value, requestSha256: '0'.repeat(64) }, false);
  return digest({ version: normalized.version, listing: normalized.listing, currency: 'USD', initialStock: 0,
    status: 'active', templateSource: null, images: [], scopeKey: normalized.scopeKey,
    ...(normalized.source ? { source: normalized.source } : {}) });
}

export async function decodeListingCreatePreview(value) {
  const base = normalizedPreview(value, true);
  const expected = await listingCreateRequestDigest({ version: base.version, listing: base.listing, currency: 'USD', initialStock: 0,
    status: 'active', scopeKey: base.scopeKey, requestSha256: value.requestSha256, ...(base.source ? { source: base.source } : {}) });
  if (expected !== value.requestSha256) invalidDraft();
  return Object.freeze({ version: base.version, listing: base.listing, currency: 'USD', initialStock: 0,
    status: 'active', scopeKey: base.scopeKey, requestSha256: value.requestSha256, ...(base.source ? { source: base.source } : {}) });
}

export async function decodeListingCreateProposal(value) {
  if (value === null) return null;
  if (!exact(value, ['version', 'proposalId', 'preview']) || value.version !== 1 || !UUID.test(value.proposalId || '')) invalidDraft();
  return Object.freeze({ version: 1, proposalId: value.proposalId, preview: await decodeListingCreatePreview(value.preview) });
}
export const sameListingCreateProposal = (a, b) => !!a && !!b && a.version === b.version
  && a.proposalId === b.proposalId && a.preview.version === b.preview.version && a.preview.scopeKey === b.preview.scopeKey
  && a.preview.requestSha256 === b.preview.requestSha256 && a.preview.currency === b.preview.currency
  && a.preview.initialStock === b.preview.initialStock && a.preview.status === b.preview.status
  && a.preview.listing.name === b.preview.listing.name && a.preview.listing.description === b.preview.listing.description
  && a.preview.listing.category === b.preview.listing.category && a.preview.listing.price === b.preview.listing.price
  && a.preview.listing.presentation === b.preview.listing.presentation;

export function decodeListingCreateReference(raw) {
  if (raw === null) return null;
  if (typeof raw !== 'string' || bytes(raw) > 1024) throw Error('Invalid listing create reference.');
  let value; try { value = JSON.parse(raw); } catch { throw Error('Invalid listing create reference.'); }
  if (!exact(value, ['version', 'scopeKey', 'operationId', 'requestSha256']) || value.version !== 1
    || !SHA.test(value.scopeKey || '') || !UUID.test(value.operationId || '') || !SHA.test(value.requestSha256 || '')) {
    throw Error('Invalid listing create reference.');
  }
  return Object.freeze({ ...value });
}
export const readListingCreateReference = () => decodeListingCreateReference(shopStorage.getItem(SHOP_LISTING_CREATE_KEY));
export async function saveListingCreateReference(reference) {
  const next = decodeListingCreateReference(JSON.stringify(reference));
  if (readListingCreateReference()) throw Error('Check the saved listing draft before confirming another.');
  shopStorage.setItem(SHOP_LISTING_CREATE_KEY, JSON.stringify(next)); await flushShopStorage();
  if (!same(readListingCreateReference(), next)) throw Error('Saved listing draft changed. No listing was created.');
  return next;
}
export async function clearListingCreateReference(reference, current = () => true) {
  const expected = decodeListingCreateReference(JSON.stringify(reference));
  if (!current() || !same(readListingCreateReference(), expected)) throw Error('Saved listing draft changed. Check it again.');
  try {
    shopStorage.removeItem(SHOP_LISTING_CREATE_KEY); await flushShopStorage();
    if (!current() || readListingCreateReference()) throw Error('Saved listing draft changed. Check it again.');
  } catch (error) {
    if (current()) try {
      if (!readListingCreateReference()) { shopStorage.setItem(SHOP_LISTING_CREATE_KEY, JSON.stringify(expected)); await flushShopStorage(); }
    } catch { /* Preserve uncertainty if acknowledged storage cannot be restored. */ }
    throw error;
  }
}

export async function decodeListingCreateOperation(value, reference) {
  const saved = decodeListingCreateReference(JSON.stringify(reference));
  if (exact(value, ['operationId', 'status', 'scopeKey']) && value.operationId === saved.operationId
    && value.status === 'not_found' && value.scopeKey === saved.scopeKey) return Object.freeze({ status: 'not_found' });
  const raw = value?.version === 2;
  if (!exact(value, ['version', 'operationId', 'status', 'productId', 'scopeKey', 'requestSha256',
    'sourceSha256', 'receiptSha256', 'replayed', ...(raw ? ['source', 'sourceDocumentSha256'] : [])])
    || ![1, 2].includes(value.version) || value.operationId !== saved.operationId || value.status !== 'completed'
    || !Number.isSafeInteger(value.productId) || value.productId < 1 || value.productId > MAX_ID
    || value.scopeKey !== saved.scopeKey || value.requestSha256 !== saved.requestSha256
    || !SHA.test(value.sourceSha256 || '') || !SHA.test(value.receiptSha256 || '') || typeof value.replayed !== 'boolean') {
    throw Error('Saved listing create receipt is invalid.');
  }
  if (!raw) return Object.freeze({ ...value });
  const source = normalizeSource(value.source);
  if (value.sourceDocumentSha256 !== await listingCreateSourceDigest(source)
    || value.requestSha256 !== await listingCreateRequestDigest({ version: 2, listing: source.listing,
      source, scopeKey: value.scopeKey, currency: 'USD', initialStock: 0, status: 'active' })) {
    throw Error('Saved listing create receipt is invalid.');
  }
  return Object.freeze({ ...value, source });
}
