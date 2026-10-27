const SHA = /^[a-f0-9]{64}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === keys.slice().sort().join(',');
const bytes = value => new TextEncoder().encode(value).length;
const string = (value, max, required = false) => (value === null && !required)
  || (typeof value === 'string' && value.isWellFormed() && !value.includes('\0')
    && bytes(value) <= max && (!required || value.length > 0));
export const manualDigest = async value => [...new Uint8Array(await crypto.subtle.digest('SHA-256',
  new TextEncoder().encode(JSON.stringify(value))))].map(byte => byte.toString(16).padStart(2, '0')).join('');
const deepFreeze = value => {
  if (value && typeof value === 'object') {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
};

export function manualListing(value) {
  if (!exact(value, ['name', 'description', 'price', 'category', 'images', 'templateSource'])
    || !string(value.name, 4096, true) || !string(value.description, 65536)
    || !string(value.category, 1024) || !string(value.templateSource, 65536)
    || typeof value.price !== 'number' || !Number.isFinite(value.price)
    || value.price < 0 || value.price > 99999999.99 || Number(value.price.toFixed(2)) !== value.price
    || !Array.isArray(value.images) || value.images.length > 16
    || Object.keys(value.images).length !== value.images.length
    || value.images.some(image => !string(image, 8192, true))) throw Error('Invalid manual listing');
  return Object.freeze({ ...value, images: Object.freeze(value.images.slice()) });
}

function view(value) {
  if (!exact(value, ['name', 'description', 'descriptionHtml', 'price', 'category', 'templateSource', 'imageUrl', 'images'])
    || !string(value.name, 4096, true) || !string(value.description, 65536)
    || !string(value.descriptionHtml, 65536) || !string(value.category, 1024)
    || !string(value.templateSource, 65536) || !string(value.imageUrl, 8192)
    || !Array.isArray(value.images) || value.images.length > 16
    || value.images.some(image => !string(image, 8192, true))
    || typeof value.price !== 'number' || !Number.isFinite(value.price)
    || value.price < 0 || value.price > 99999999.99 || Number(value.price.toFixed(2)) !== value.price)
    throw Error('Invalid manual listing preview');
  return value;
}

export async function decodeManualPreview(raw, kind, scopeKey) {
  if (!raw || Object.getPrototypeOf(raw) !== Object.prototype) throw Error('Invalid manual listing preview');
  // Keep the server's canonical key order for the request hash while severing
  // every mutable form/transport reference before showing consequences.
  const value = JSON.parse(JSON.stringify(raw));
  const edit = kind === 'edit';
  const keys = ['version', 'origin', 'kind', ...(edit ? ['productId'] : []), 'listing',
    ...(edit ? ['before', 'after', 'catalogRevision', 'expectedSnapshotSha256', 'invalidatesGeneratedHtml']
      : ['currency', 'initialStock', 'status']), 'scopeKey', 'requestSha256'];
  if (!['create', 'edit'].includes(kind) || !exact(value, keys) || value.version !== 1
    || value.origin !== 'manual' || value.kind !== kind || value.scopeKey !== scopeKey
    || !SHA.test(value.requestSha256 || '') || bytes(JSON.stringify(value)) > 128 * 1024)
    throw Error('Invalid manual listing preview');
  manualListing(value.listing);
  if (edit) {
    if (!Number.isSafeInteger(value.productId) || value.productId < 1 || value.productId > 2147483647
      || !/^(0|[1-9][0-9]{0,15})$/.test(value.catalogRevision || '')
      || BigInt(value.catalogRevision) > BigInt(Number.MAX_SAFE_INTEGER)
      || !SHA.test(value.expectedSnapshotSha256 || '') || typeof value.invalidatesGeneratedHtml !== 'boolean')
      throw Error('Invalid manual listing preview');
    view(value.before); view(value.after);
    const expected = { ...value.before, name: value.listing.name, description: value.listing.description,
      price: value.listing.price, category: value.listing.category, templateSource: value.listing.templateSource,
      images: value.listing.images, imageUrl: value.listing.images[0] || null,
      descriptionHtml: value.invalidatesGeneratedHtml ? null : value.before.descriptionHtml };
    if (JSON.stringify(expected) !== JSON.stringify(value.after)) throw Error('Invalid manual listing preview');
  } else if (value.currency !== 'USD' || value.initialStock !== 0 || value.status !== 'active')
    throw Error('Invalid manual listing preview');
  const { requestSha256, ...base } = value;
  if (await manualDigest(base) !== requestSha256) throw Error('Invalid manual listing preview');
  return deepFreeze(value);
}

export function decodeManualReceipt(value, kind, reference) {
  if (!['create', 'edit'].includes(kind) || !reference || !UUID.test(reference.operationId || '')
    || !SHA.test(reference.manualScopeKey || '') || !SHA.test(reference.requestSha256 || ''))
    throw Error('Invalid saved listing operation');
  const common = value?.origin === 'manual' && value.kind === kind && value.operationId === reference.operationId
    && value.scopeKey === reference.manualScopeKey;
  if (common && exact(value, ['origin', 'kind', 'operationId', 'status', 'scopeKey'])
    && value.status === 'not_found') return Object.freeze(value);
  const keys = ['version', 'operationId', 'productId', 'status', 'scopeKey', 'requestSha256',
    ...(kind === 'create' ? ['sourceSha256'] : ['catalogRevision', 'beforeSha256', 'afterSha256']),
    'receiptSha256', 'replayed', 'origin', 'kind'];
  if (!common || !exact(value, keys) || value.version !== 1 || value.status !== 'completed'
    || value.requestSha256 !== reference.requestSha256
    || !Number.isSafeInteger(value.productId) || value.productId < 1 || value.productId > 2147483647
    || kind === 'edit' && (value.productId !== reference.productId || !SHA.test(value.beforeSha256 || '')
      || !SHA.test(value.afterSha256 || '') || !/^(0|[1-9][0-9]{0,15})$/.test(value.catalogRevision || ''))
    || kind === 'create' && !SHA.test(value.sourceSha256 || '')
    || !SHA.test(value.receiptSha256 || '') || typeof value.replayed !== 'boolean')
    throw Error('Invalid saved listing receipt');
  return Object.freeze(value);
}
