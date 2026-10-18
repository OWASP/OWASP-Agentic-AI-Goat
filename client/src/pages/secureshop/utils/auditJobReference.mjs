import { shopStorage, flushShopStorage, SHOP_AUDIT_JOB_KEY } from './shopStorage.mjs';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA = /^[a-f0-9]{64}$/;
const KEYS = ['version', 'scopeKey', 'sourceSessionId', 'sourceRequestId', 'proposalId',
  'jobSessionId', 'jobRequestId', 'requestSha256'];
const exact = value => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === KEYS.slice().sort().join(',');
const fail = () => { throw new Error('Saved audit job reference invalid'); };

export function decodeAuditJobReference(raw) {
  if (raw === null) return null;
  if (typeof raw !== 'string' || new TextEncoder().encode(raw).byteLength > 1024) fail();
  let value;
  try { value = JSON.parse(raw); } catch { fail(); }
  if (!exact(value) || value.version !== 1 || !SHA.test(value.scopeKey)
    || !UUID.test(value.sourceSessionId) || !UUID.test(value.sourceRequestId)
    || !UUID.test(value.proposalId) || !UUID.test(value.jobSessionId)
    || value.jobRequestId !== value.proposalId || !SHA.test(value.requestSha256)) fail();
  return Object.freeze(Object.fromEntries(KEYS.map(key => [key, value[key]])));
}

export const sameAuditJobReference = (left, right) => left && right
  && KEYS.every(key => left[key] === right[key]);
export const readAuditJobReference = () => decodeAuditJobReference(shopStorage.getItem(SHOP_AUDIT_JOB_KEY));

export async function saveAuditJobReference(reference, current = () => true) {
  const value = decodeAuditJobReference(JSON.stringify(reference));
  if (!current()) throw Error('Audit job authority changed');
  if (readAuditJobReference()) throw Error('Check the saved audit job before another Run');
  shopStorage.setItem(SHOP_AUDIT_JOB_KEY, JSON.stringify(value));
  await flushShopStorage();
  if (!current() || !sameAuditJobReference(readAuditJobReference(), value)) {
    throw Error('Saved audit job reference changed');
  }
  return value;
}

export function assertAuditJobReference(reference) {
  if (!sameAuditJobReference(readAuditJobReference(), reference)) {
    throw Error('Saved audit job reference changed');
  }
}

export async function clearAuditJobReference(reference, current = () => true) {
  if (!current()) throw Error('Audit job authority changed');
  assertAuditJobReference(reference);
  shopStorage.removeItem(SHOP_AUDIT_JOB_KEY);
  try {
    await flushShopStorage();
    if (!current() || readAuditJobReference() !== null) throw Error('Saved audit job reference did not clear');
  } catch (error) {
    if (current() && readAuditJobReference() === null) {
      shopStorage.setItem(SHOP_AUDIT_JOB_KEY, JSON.stringify(reference));
      await flushShopStorage();
    }
    throw error;
  }
}
