import { flushShopStorage, shopStorage, SHOP_PROFILE_KEY } from './shopStorage.mjs';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA = /^[a-f0-9]{64}$/;
const KEYS = ['fullName', 'email', 'phone'];
const LIMITS = { fullName: 512, email: 320, phone: 128 };
const REF_KEYS = ['version', 'operationId', 'scopeKey', 'expectedSnapshotSha256',
  'fieldsSha256', 'requestSha256', 'sessionId', 'requestId'];
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const bytes = value => new TextEncoder().encode(value).byteLength;
const same = (left, right) => !!left && !!right && REF_KEYS.every(key => left[key] === right[key]);

function field(key, value) {
  if (value === null && key !== 'email') return null;
  if (typeof value !== 'string' || !value.isWellFormed() || value.includes('\0')
    || bytes(value) > LIMITS[key]) throw Error('Profile fields are invalid.');
  if (key === 'email') {
    if (!/^[^\s@]+@[^\s@]+$/.test(value)) throw Error('Enter a valid email address.');
    return value;
  }
  return value.trim() ? value : null;
}

function viewField(key, value) {
  if (value === null && key !== 'email') return null;
  if (typeof value !== 'string' || !value.isWellFormed() || value.includes('\0')
    || bytes(value) > LIMITS[key] || (key === 'email' && bytes(value) < 3))
    throw Error('Current profile is unavailable.');
  return value;
}

export function normalizeProfileFields(value) {
  if (!exact(value, KEYS)) throw Error('Review every profile field.');
  return Object.freeze(Object.fromEntries(KEYS.map(key => [key, viewField(key, value[key])])));
}

export function normalizeEditedProfileFields(value, before) {
  const current = normalizeProfileFields(before);
  if (!exact(value, KEYS)) throw Error('Review every profile field.');
  return Object.freeze(Object.fromEntries(KEYS.map(key => [key,
    value[key] === current[key] || (current[key] === null && value[key] === '')
      ? current[key] : field(key, value[key])])));
}

export function normalizeProfilePatch(value) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype || !Object.keys(value).length
    || Object.keys(value).some(key => !KEYS.includes(key))) throw Error('Saved profile patch is invalid.');
  return Object.freeze(Object.fromEntries(KEYS.filter(key => Object.hasOwn(value, key))
    .map(key => [key, field(key, value[key])])));
}

async function digest(value) {
  if (typeof globalThis.crypto?.subtle?.digest !== 'function') throw Error('Secure profile identity unavailable.');
  const result = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(value)));
  return [...new Uint8Array(result)].map(byte => byte.toString(16).padStart(2, '0')).join('');
}

export const profileFieldsDigest = fields => digest(normalizeProfileFields(fields));
export async function profileRequestDigest(operationId, expectedSnapshotSha256, fields) {
  if (!UUID.test(operationId || '') || !SHA.test(expectedSnapshotSha256 || ''))
    throw Error('Profile request identity is invalid.');
  const fieldsSha256 = await profileFieldsDigest(fields);
  return digest({ operationId, expectedSnapshotSha256, fieldsSha256 });
}

export function decodeProfileForm(value) {
  if (!exact(value, ['version', 'fields', 'expectedSnapshotSha256', 'scopeKey'])
    || value.version !== 1 || !SHA.test(value.expectedSnapshotSha256 || '')
    || !SHA.test(value.scopeKey || '')) throw Error('Current profile is unavailable.');
  return Object.freeze({ version: 1, fields: normalizeProfileFields(value.fields),
    expectedSnapshotSha256: value.expectedSnapshotSha256, scopeKey: value.scopeKey });
}

export function decodeProfileProposal(value) {
  if (value === null) return null;
  if (!exact(value, ['version', 'proposalId', 'scopeKey', 'expectedSnapshotSha256',
    'requestSha256', 'before', 'after', 'patch']) || value.version !== 1
    || !UUID.test(value.proposalId || '') || !SHA.test(value.scopeKey || '')
    || !SHA.test(value.expectedSnapshotSha256 || '') || !SHA.test(value.requestSha256 || ''))
    throw Error('Saved profile review is invalid.');
  const before = normalizeProfileFields(value.before);
  const patch = normalizeProfilePatch(value.patch);
  const after = normalizeProfileFields(value.after);
  if (KEYS.some(key => after[key] !== (Object.hasOwn(patch, key) ? patch[key] : before[key])))
    throw Error('Saved profile review is invalid.');
  return Object.freeze({ version: 1, proposalId: value.proposalId, scopeKey: value.scopeKey,
    expectedSnapshotSha256: value.expectedSnapshotSha256, requestSha256: value.requestSha256,
    before, after, patch });
}

export function decodeProfileReference(raw) {
  if (raw === null) return null;
  if (typeof raw !== 'string' || bytes(raw) > 1024) throw Error('Invalid saved profile reference.');
  let value; try { value = JSON.parse(raw); } catch { throw Error('Invalid saved profile reference.'); }
  if (!exact(value, REF_KEYS) || value.version !== 1 || !UUID.test(value.operationId || '')
    || !SHA.test(value.scopeKey || '') || !SHA.test(value.expectedSnapshotSha256 || '')
    || !SHA.test(value.fieldsSha256 || '') || !SHA.test(value.requestSha256 || '')
    || (value.sessionId === null ? value.requestId !== null
      : !UUID.test(value.sessionId || '') || !UUID.test(value.requestId || '')))
    throw Error('Invalid saved profile reference.');
  return Object.freeze({ ...value });
}

export const readProfileReference = () => decodeProfileReference(shopStorage.getItem(SHOP_PROFILE_KEY));
export async function saveProfileReference(reference) {
  const next = decodeProfileReference(JSON.stringify(reference));
  if (readProfileReference()) throw Error('Check the saved profile before starting another.');
  shopStorage.setItem(SHOP_PROFILE_KEY, JSON.stringify(next));
  await flushShopStorage();
  if (!same(readProfileReference(), next)) throw Error('Saved profile reference changed.');
  return next;
}
export async function clearProfileReference(reference, current = () => true) {
  const expected = decodeProfileReference(JSON.stringify(reference));
  if (!current() || !same(readProfileReference(), expected)) throw Error('Saved profile reference changed.');
  try {
    shopStorage.removeItem(SHOP_PROFILE_KEY);
    await flushShopStorage();
    if (!current() || readProfileReference()) throw Error('Saved profile reference changed.');
  } catch (error) {
    if (current()) try {
      if (!readProfileReference()) {
        shopStorage.setItem(SHOP_PROFILE_KEY, JSON.stringify(expected));
        await flushShopStorage();
      }
    } catch { /* The exact saved outcome remains unresolved. */ }
    throw error;
  }
}

export function decodeProfileOperation(value, reference) {
  const saved = decodeProfileReference(JSON.stringify(reference));
  if (exact(value, ['scopeKey', 'operationId', 'status']) && value.scopeKey === saved.scopeKey
    && value.operationId === saved.operationId && value.status === 'not_found')
    return Object.freeze({ status: 'not_found' });
  if (!exact(value, ['scopeKey', 'operationId', 'status', 'receipt'])
    || value.scopeKey !== saved.scopeKey || value.operationId !== saved.operationId
    || value.status !== 'completed'
    || !exact(value.receipt, ['version', 'operationId', 'kind', 'status', 'result', 'replayed'])
    || value.receipt.version !== 1 || value.receipt.operationId !== saved.operationId
    || value.receipt.kind !== 'profile.update' || !['completed', 'stale'].includes(value.receipt.status)
    || value.receipt.replayed !== true
    || !exact(value.receipt.result, value.receipt.status === 'stale'
      ? ['fieldsSha256'] : ['fieldsSha256', 'profileSnapshotSha256'])
    || value.receipt.result.fieldsSha256 !== saved.fieldsSha256
    || (value.receipt.status === 'completed' && !SHA.test(value.receipt.result.profileSnapshotSha256 || '')))
    throw Error('Saved profile receipt is invalid.');
  return Object.freeze({ status: value.receipt.status, receipt: value.receipt });
}

export const sameProfileReference = same;
