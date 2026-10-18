import { shopStorage, flushShopStorage, SHOP_INVENTORY_KEY } from '../../utils/shopStorage.mjs';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const MAX_ID = 2147483647;
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
export function validStockChange(access, value) {
  if (access === 'read') return value === null;
  return access === 'write' && exact(value, ['productId', 'quantity'])
    && Number.isSafeInteger(value.productId) && value.productId >= 1 && value.productId <= MAX_ID
    && Number.isSafeInteger(value.quantity) && value.quantity >= 0 && value.quantity <= MAX_ID;
}
export function decodeInventoryReference(raw) {
  if (raw === null) return null;
  if (typeof raw !== 'string' || new TextEncoder().encode(raw).length > 1024) throw Error('Invalid inventory reference');
  let value;
  try { value = JSON.parse(raw); } catch { throw Error('Invalid inventory reference'); }
  const graded = Object.hasOwn(value || {}, 'evaluationId');
  const newer = Object.hasOwn(value || {}, 'version');
  const keys = newer ? ['version', 'scopeKey', 'requestId', 'digest', 'access', 'stockChange']
    : Object.hasOwn(value || {}, 'access') ? ['scopeKey', 'requestId', 'digest', 'access']
      : ['scopeKey', 'requestId', 'digest'];
  if (!exact(value, graded ? [...keys, 'evaluationId', 'retryRequestId'] : keys)
    || typeof value.requestId !== 'string' || typeof value.scopeKey !== 'string' || typeof value.digest !== 'string'
    || !UUID.test(value.requestId) || !SHA256.test(value.scopeKey) || !SHA256.test(value.digest)
    || (graded && (typeof value.evaluationId !== 'string' || typeof value.retryRequestId !== 'string'
      || !UUID.test(value.evaluationId) || !UUID.test(value.retryRequestId)
      || value.requestId === value.retryRequestId))
    || (newer ? value.version !== 3 || !validStockChange(value.access, value.stockChange)
      : Object.hasOwn(value, 'access') && !['read', 'write'].includes(value.access))) {
    throw Error('Invalid inventory reference');
  }
  return value;
}

export function sameInventoryReference(a, b) {
  return !!a && !!b && Object.keys(a).length === Object.keys(b).length
    && Object.keys(a).every(key => key === 'stockChange'
      ? JSON.stringify(a[key]) === JSON.stringify(b[key]) : a[key] === b[key]);
}

export function readInventoryReference() {
  return decodeInventoryReference(shopStorage.getItem(SHOP_INVENTORY_KEY));
}

export async function saveInventoryReference(reference) {
  const next = decodeInventoryReference(JSON.stringify(reference));
  if (readInventoryReference()) throw Error('Check the saved inventory request before confirming another.');
  shopStorage.setItem(SHOP_INVENTORY_KEY, JSON.stringify(next));
  await flushShopStorage();
  if (!sameInventoryReference(readInventoryReference(), next)) {
    throw Error('Saved inventory reference changed. No stock change was submitted.');
  }
  return next;
}

export async function replaceInventoryReference(previous, reference) {
  const expected = decodeInventoryReference(JSON.stringify(previous));
  const next = decodeInventoryReference(JSON.stringify(reference));
  if (!sameInventoryReference(readInventoryReference(), expected)) {
    throw Error('Saved inventory reference changed. Check it again.');
  }
  shopStorage.setItem(SHOP_INVENTORY_KEY, JSON.stringify(next));
  await flushShopStorage();
  if (!sameInventoryReference(readInventoryReference(), next)) {
    throw Error('Saved inventory reference changed. Check it again.');
  }
  return next;
}

export async function clearInventoryReference(reference, current = () => true) {
  const expected = decodeInventoryReference(JSON.stringify(reference));
  if (!current()) throw Error('Inventory session changed.');
  if (!sameInventoryReference(readInventoryReference(), expected)) {
    throw Error('Saved inventory reference changed. Check it again.');
  }
  try {
    shopStorage.removeItem(SHOP_INVENTORY_KEY);
    await flushShopStorage();
    if (!current()) throw Error('Inventory session changed.');
    if (readInventoryReference()) throw Error('Saved inventory reference changed. Check it again.');
  } catch (error) {
    if (current()) try {
      if (!readInventoryReference()) {
        shopStorage.setItem(SHOP_INVENTORY_KEY, JSON.stringify(expected));
        await flushShopStorage();
      }
    } catch { /* The caller keeps the exact request latched. */ }
    throw error;
  }
}

export function decodeInventoryProposal(value) {
  if (value === null) return null;
  const encoder = new TextEncoder();
  const mode = value?.modeCapability;
  if (!exact(value, ['version', 'proposalId', 'product', 'stockChange', 'message', 'scopeKey', 'modeCapability'])
    || value.version !== 1 || typeof value.proposalId !== 'string' || !UUID.test(value.proposalId)
    || !exact(value.product, ['choiceId', 'name'])
    || typeof value.product.choiceId !== 'string' || !UUID.test(value.product.choiceId)
    || typeof value.product.name !== 'string' || !value.product.name.trim()
    || !value.product.name.isWellFormed() || encoder.encode(value.product.name).byteLength > 256
    || !validStockChange('write', value.stockChange)
    || typeof value.message !== 'string' || !value.message.trim()
    || !value.message.isWellFormed() || value.message.includes('\0')
    || encoder.encode(value.message).byteLength > 8192 || !SHA256.test(value.scopeKey)
    || !exact(mode, ['version', 'featureId', 'policyVersion', 'effectiveMode', 'scope'])
    || mode.version !== 1 || mode.featureId !== 'inventory'
    || typeof mode.policyVersion !== 'string' || !mode.policyVersion
    || !['vuln', 'fixed'].includes(mode.effectiveMode)
    || !exact(mode.scope, ['kind', 'id']) || mode.scope.kind !== 'launch_feature'
    || mode.scope.id !== 'inventory') throw Error('Saved inventory proposal is invalid.');
  return value;
}

export function sameInventoryProposal(a, b) {
  return !!a && !!b && a.proposalId === b.proposalId
    && a.product.choiceId === b.product.choiceId && a.product.name === b.product.name
    && a.stockChange.productId === b.stockChange.productId
    && a.stockChange.quantity === b.stockChange.quantity
    && a.message === b.message && a.scopeKey === b.scopeKey
    && a.modeCapability.version === b.modeCapability.version
    && a.modeCapability.featureId === b.modeCapability.featureId
    && a.modeCapability.policyVersion === b.modeCapability.policyVersion
    && a.modeCapability.effectiveMode === b.modeCapability.effectiveMode
    && a.modeCapability.scope.kind === b.modeCapability.scope.kind
    && a.modeCapability.scope.id === b.modeCapability.scope.id;
}
