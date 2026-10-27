import { shopStorage, flushShopStorage, SHOP_PRODUCT_MANUAL_KEY } from './shopStorage.mjs';

// This is a scene-scoped reference, never a copy of file bytes or a retry permit.
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA = /^[a-f0-9]{64}$/;
const DECIMAL = /^[1-9][0-9]*$/;
const encoder = new TextEncoder();
const reject = () => { throw new TypeError('Invalid product manual recovery reference'); };
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === keys.slice().sort().join(',');

export function validateProductManualDescriptor(value) {
  if (!exact(value, ['productId', 'sha256', 'sizeBytes', 'filename', 'mime', 'public'])
    || typeof value.productId !== 'string' || !DECIMAL.test(value.productId)
    || !Number.isSafeInteger(Number(value.productId)) || Number(value.productId) > 2147483647
    || typeof value.sha256 !== 'string' || !SHA.test(value.sha256)
    || typeof value.sizeBytes !== 'string' || !DECIMAL.test(value.sizeBytes)
    || !Number.isSafeInteger(Number(value.sizeBytes)) || Number(value.sizeBytes) > 20 * 1024 * 1024
    || typeof value.filename !== 'string' || !value.filename.trim() || !value.filename.isWellFormed()
    || encoder.encode(value.filename).byteLength > 255 || /[\x00-\x1f\x7f]/.test(value.filename)
    || typeof value.mime !== 'string' || !value.mime.trim() || !value.mime.isWellFormed()
    || encoder.encode(value.mime).byteLength > 128 || /[\x00-\x1f\x7f]/.test(value.mime)
    || !['true', 'false'].includes(value.public)) reject();
  return Object.freeze({ ...value });
}

export function decodeProductManualPendingReference(raw) {
  if (raw === null) return null;
  if (typeof raw !== 'string' || encoder.encode(raw).byteLength > 4096) reject();
  let value;
  try { value = JSON.parse(raw); } catch { reject(); }
  if (!exact(value, ['version', 'descriptor', 'operationId', 'recoveryScopeKey'])
    || value.version !== 1 || !UUID.test(value.operationId || '')
    || !SHA.test(value.recoveryScopeKey || '')) reject();
  return Object.freeze({ ...value, descriptor: validateProductManualDescriptor(value.descriptor) });
}

function verifyLookup(descriptor, lookup, operationId, recoveryScopeKey) {
  if (!exact(lookup, ['version', 'kind', 'operationId', 'recoveryScopeKey', 'state', 'receipt'])
    || lookup.version !== 1 || lookup.kind !== 'product_manual'
    || !UUID.test(lookup.operationId || '') || !SHA.test(lookup.recoveryScopeKey || '')
    || lookup.operationId !== operationId || lookup.recoveryScopeKey !== recoveryScopeKey) reject();
  if (lookup.state === 'not_found' && lookup.receipt === null) return false;
  const receipt = lookup.receipt;
  const firstChunk = Array.isArray(receipt?.chunkIds) ? receipt.chunkIds[0] : null;
  const sourceId = typeof firstChunk === 'string' ? /^manual:([1-9][0-9]*):0$/.exec(firstChunk)?.[1] : null;
  if (lookup.state !== 'indexed' || !exact(receipt, ['productId', 'sha256', 'sizeBytes', 'filename', 'mime',
    'isPublic', 'chunkCount', 'chunkIds', 'completedAt'])
    || !Number.isSafeInteger(receipt.productId) || receipt.productId !== Number(descriptor.productId)
    || receipt.sha256 !== descriptor.sha256
    || !Number.isSafeInteger(receipt.sizeBytes) || receipt.sizeBytes !== Number(descriptor.sizeBytes)
    || receipt.filename !== descriptor.filename
    || receipt.mime !== descriptor.mime || receipt.isPublic !== (descriptor.public === 'true')
    || !Number.isSafeInteger(receipt.chunkCount) || receipt.chunkCount < 1 || receipt.chunkCount > 129
    || !Array.isArray(receipt.chunkIds) || receipt.chunkIds.length !== receipt.chunkCount
    || !sourceId || !Number.isSafeInteger(Number(sourceId))
    || receipt.chunkIds.some((id, index) => id !== `manual:${sourceId}:${index}`)
    || typeof receipt.completedAt !== 'string' || !Number.isFinite(Date.parse(receipt.completedAt))) reject();
  return true;
}

export function verifyProductManualLookup(descriptor, lookup, expected = null) {
  const admitted = validateProductManualDescriptor(descriptor);
  if (expected !== null && !exact(expected, ['operationId', 'recoveryScopeKey'])) reject();
  const operationId = expected === null ? lookup?.operationId : expected.operationId;
  const recoveryScopeKey = expected === null ? lookup?.recoveryScopeKey : expected.recoveryScopeKey;
  const indexed = verifyLookup(admitted, lookup, operationId, recoveryScopeKey);
  return Object.freeze({ state: indexed ? 'indexed' : 'not_found', operationId,
    recoveryScopeKey, receipt: indexed ? lookup.receipt : null });
}

export function createProductManualPendingReferenceStore({ storage = shopStorage, flush = flushShopStorage } = {}) {
  if (!storage || ['getItem', 'setItem', 'removeItem'].some(key => typeof storage[key] !== 'function')
    || typeof flush !== 'function') reject();
  const read = () => decodeProductManualPendingReference(storage.getItem(SHOP_PRODUCT_MANUAL_KEY));
  let busy = false;
  const acknowledge = async expected => {
    await flush();
    if (storage.getItem(SHOP_PRODUCT_MANUAL_KEY) !== expected) reject();
  };
  const checkCurrent = assertCurrent => {
    if (assertCurrent === undefined) return;
    if (typeof assertCurrent !== 'function') reject();
    const current = assertCurrent();
    if (current === false || (current && typeof current.then === 'function')) reject();
  };
  return Object.freeze({
    read,
    async reserveInitialPost(descriptor, lookup, { assertCurrent } = {}) {
      if (busy) reject();
      if (assertCurrent !== undefined && typeof assertCurrent !== 'function') reject();
      busy = true;
      try {
        const admitted = validateProductManualDescriptor(descriptor);
        if (read() !== null) throw new Error('Pending product manual requires receipt recovery; upload retry is forbidden');
        if (verifyProductManualLookup(admitted, lookup).state !== 'not_found') reject();
        const value = { version: 1, descriptor: admitted,
          operationId: lookup.operationId, recoveryScopeKey: lookup.recoveryScopeKey };
        const raw = JSON.stringify(value);
        checkCurrent(assertCurrent);
        storage.setItem(SHOP_PRODUCT_MANUAL_KEY, raw);
        await acknowledge(raw);
        checkCurrent(assertCurrent);
        return decodeProductManualPendingReference(raw);
      } finally { busy = false; }
    },
    async reconcile(lookup, { assertCurrent } = {}) {
      if (busy) reject();
      if (assertCurrent !== undefined && typeof assertCurrent !== 'function') reject();
      busy = true;
      try {
        const pending = read();
        if (!pending) reject();
        const checked = verifyProductManualLookup(pending.descriptor, lookup,
          { operationId: pending.operationId, recoveryScopeKey: pending.recoveryScopeKey });
        if (checked.state !== 'indexed') return Object.freeze({ state: 'unresolved', pending });
        checkCurrent(assertCurrent);
        storage.removeItem(SHOP_PRODUCT_MANUAL_KEY);
        await acknowledge(null);
        return Object.freeze({ state: 'indexed', receipt: lookup.receipt });
      } finally { busy = false; }
    },
  });
}
