import { flushShopStorage, shopStorage, SHOP_ADDRESS_SETUP_KEY } from './shopStorage.mjs';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA = /^[a-f0-9]{64}$/;
const LIMITS = Object.freeze({ label: 128, line1: 1024, line2: 1024, city: 256,
  state: 128, zip: 64, phone: 128 });
const FIELD_KEYS = Object.freeze([...Object.keys(LIMITS), 'isDefault']);
const REFERENCE_KEYS = Object.freeze(['version', 'scopeKey', 'operationId', 'action', 'choiceId',
  'expectedSnapshotSha256', 'defaultSetSha256', 'fieldsSha256']);
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const bytes = value => new TextEncoder().encode(value).byteLength;
const same = (left, right) => !!left && !!right && REFERENCE_KEYS.every(key => left[key] === right[key]);

function field(key, value, { draft = false } = {}) {
  if (value === null && !draft) return null;
  if (typeof value !== 'string' || !value.isWellFormed() || value.includes('\0')
    || bytes(value) > LIMITS[key]) throw Error('Address field is unavailable.');
  return draft ? value : value.trim() ? value : null;
}

export function normalizeAddressFields(value, { allowBlankLine1 = false } = {}) {
  if (!exact(value, FIELD_KEYS) || typeof value.isDefault !== 'boolean')
    throw Error('Review every address field before saving.');
  const fields = Object.fromEntries(Object.keys(LIMITS).map(key => [key, field(key, value[key])]));
  if (!allowBlankLine1 && fields.line1 === null) throw Error('Street address is required.');
  return Object.freeze({ ...fields, isDefault: value.isDefault });
}

export function decodeAddressSetup(value) {
  if (value === null) return null;
  if (!exact(value, ['version', 'kind', 'action', 'choiceId', 'draft']) || value.version !== 1
    || value.kind !== 'address_setup' || !['create', 'update'].includes(value.action)
    || (value.action === 'create' ? value.choiceId !== null : !UUID.test(value.choiceId || ''))
    || !value.draft || Object.getPrototypeOf(value.draft) !== Object.prototype
    || Object.keys(value.draft).some(key => !Object.hasOwn(LIMITS, key)))
    throw Error('Saved address setup is invalid.');
  const draft = Object.fromEntries(Object.keys(LIMITS).filter(key => Object.hasOwn(value.draft, key))
    .map(key => [key, field(key, value.draft[key], { draft: true })]));
  return Object.freeze({ version: 1, kind: 'address_setup', action: value.action,
    choiceId: value.choiceId, draft: Object.freeze(draft) });
}

export function decodeAddressForm(value) {
  if (!exact(value, ['scopeKey', 'action', 'choiceId', 'fields', 'expectedSnapshotSha256', 'defaultSetSha256'])
    || !SHA.test(value.scopeKey || '') || !SHA.test(value.defaultSetSha256 || '')
    || !['create', 'update'].includes(value.action)
    || (value.action === 'create'
      ? value.choiceId !== null || value.expectedSnapshotSha256 !== null
      : !UUID.test(value.choiceId || '') || !SHA.test(value.expectedSnapshotSha256 || '')))
    throw Error('Current address form is unavailable.');
  const fields = normalizeAddressFields(value.fields, { allowBlankLine1: value.action === 'create' });
  return Object.freeze({ scopeKey: value.scopeKey, action: value.action,
    choiceId: value.choiceId, fields, expectedSnapshotSha256: value.expectedSnapshotSha256,
    defaultSetSha256: value.defaultSetSha256 });
}

export async function addressFieldsDigest(fields) {
  const normalized = normalizeAddressFields(fields);
  if (typeof globalThis.crypto?.subtle?.digest !== 'function') throw Error('Secure address identity unavailable.');
  const digest = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(normalized)));
  return [...new Uint8Array(digest)].map(value => value.toString(16).padStart(2, '0')).join('');
}

export function decodeAddressReference(raw) {
  if (raw === null) return null;
  if (typeof raw !== 'string' || bytes(raw) > 768) throw Error('Invalid saved address reference.');
  let value; try { value = JSON.parse(raw); } catch { throw Error('Invalid saved address reference.'); }
  if (!exact(value, REFERENCE_KEYS) || value.version !== 1 || !SHA.test(value.scopeKey || '')
    || !UUID.test(value.operationId || '') || !['create', 'update'].includes(value.action)
    || (value.action === 'create'
      ? value.choiceId !== null || value.expectedSnapshotSha256 !== null
      : !UUID.test(value.choiceId || '') || !SHA.test(value.expectedSnapshotSha256 || ''))
    || !SHA.test(value.defaultSetSha256 || '') || !SHA.test(value.fieldsSha256 || ''))
    throw Error('Invalid saved address reference.');
  return Object.freeze({ ...value });
}

export const readAddressReference = () => decodeAddressReference(shopStorage.getItem(SHOP_ADDRESS_SETUP_KEY));
export async function saveAddressReference(reference) {
  const next = decodeAddressReference(JSON.stringify(reference));
  if (readAddressReference()) throw Error('Check the saved address before starting another.');
  shopStorage.setItem(SHOP_ADDRESS_SETUP_KEY, JSON.stringify(next));
  await flushShopStorage();
  if (!same(readAddressReference(), next)) throw Error('Saved address changed. No address was submitted.');
  return next;
}
export async function clearAddressReference(reference, current = () => true) {
  const expected = decodeAddressReference(JSON.stringify(reference));
  if (!current() || !same(readAddressReference(), expected)) throw Error('Saved address changed. Check it again.');
  try {
    shopStorage.removeItem(SHOP_ADDRESS_SETUP_KEY);
    await flushShopStorage();
    if (!current() || readAddressReference()) throw Error('Saved address changed. Check it again.');
  } catch (error) {
    if (current()) try {
      if (!readAddressReference()) {
        shopStorage.setItem(SHOP_ADDRESS_SETUP_KEY, JSON.stringify(expected));
        await flushShopStorage();
      }
    } catch { /* A failed restore leaves the exact outcome unresolved. */ }
    throw error;
  }
}

export function decodeAddressOperation(value, reference) {
  const saved = decodeAddressReference(JSON.stringify(reference));
  if (exact(value, ['scopeKey', 'operationId', 'status']) && value.scopeKey === saved.scopeKey
    && value.operationId === saved.operationId && value.status === 'not_found')
    return Object.freeze({ status: 'not_found' });
  if (!exact(value, ['scopeKey', 'operationId', 'status', 'receipt']) || value.scopeKey !== saved.scopeKey
    || value.operationId !== saved.operationId || value.status !== 'completed'
    || !exact(value.receipt, ['version', 'operationId', 'kind', 'status', 'result', 'replayed'])
    || value.receipt.version !== 1 || value.receipt.operationId !== saved.operationId
    || value.receipt.kind !== `address.${saved.action}`
    || !['completed', 'stale'].includes(value.receipt.status)
    || value.receipt.replayed !== true
    || value.receipt.result?.fieldsSha256 !== saved.fieldsSha256
    || (value.receipt.status === 'completed'
      ? !exact(value.receipt.result, ['addressId', 'fieldsSha256', 'addressSnapshotSha256', 'defaultSetSha256'])
        || !Number.isSafeInteger(value.receipt.result.addressId) || value.receipt.result.addressId < 1
        || !SHA.test(value.receipt.result.addressSnapshotSha256 || '')
        || !SHA.test(value.receipt.result.defaultSetSha256 || '')
      : !exact(value.receipt.result, ['fieldsSha256'])))
    throw Error('Saved address receipt is invalid.');
  return Object.freeze({ status: value.receipt.status, receipt: value.receipt });
}

export function decodeAddressCards(value) {
  if (!exact(value, ['scopeKey', 'cards', 'addresses']) || !SHA.test(value.scopeKey || '')
    || !Array.isArray(value.cards) || value.cards.length > 32
    || !Array.isArray(value.addresses) || value.addresses.length !== value.cards.length
    || value.cards.some((card, index) => !exact(card, ['version', 'kind', 'choiceId', 'title', 'detail'])
      || card.version !== 1 || card.kind !== 'address' || !UUID.test(card.choiceId || '')
      || value.cards.slice(0, index).some(previous => previous.choiceId === card.choiceId)
      || typeof card.title !== 'string' || !card.title.isWellFormed() || card.title.includes('\0')
      || !card.title.trim() || bytes(card.title) > 256
      || typeof card.detail !== 'string' || !card.detail.isWellFormed() || card.detail.includes('\0')
      || !card.detail.trim() || bytes(card.detail) > 512)
    || value.addresses.some((row, index) => !exact(row, ['addressId', 'choiceId', 'fields'])
      || !Number.isSafeInteger(row.addressId) || row.addressId < 1
      || row.choiceId !== value.cards[index].choiceId
      || value.addresses.slice(0, index).some(previous => previous.addressId === row.addressId)
      || (() => { try { normalizeAddressFields(row.fields); return false; } catch { return true; } })()))
    throw Error('Saved addresses are unavailable.');
  return Object.freeze({ scopeKey: value.scopeKey,
    cards: Object.freeze(value.cards.map(card => Object.freeze({ ...card }))),
    addresses: Object.freeze(value.addresses.map(row => Object.freeze({ addressId: row.addressId,
      choiceId: row.choiceId, fields: normalizeAddressFields(row.fields) }))) });
}
