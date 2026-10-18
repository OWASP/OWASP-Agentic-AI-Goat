import { shopStorage, flushShopStorage, SHOP_ROLE_ASSISTANT_COMPLETED_KEY } from './shopStorage.mjs';
import { decodeRoleAssistantReferences, readRoleAssistantReference } from './roleAssistantReferences.mjs';

const MAX_REFERENCES = 32;
const MAX_BYTES = 8192;
const encoder = new TextEncoder();
const owner = row => `${row.role}:${row.shopUserId}`;
export const sameRoleAssistantReference = (left, right) => !!left && !!right
  && ['role', 'shopUserId', 'sessionId', 'requestId', 'startedAt']
    .every(key => left[key] === right[key]);
const own = row => decodeRoleAssistantReferences(JSON.stringify({ version: 1, references: [row] }))[0];
const decode = raw => decodeRoleAssistantReferences(raw);

export function readRoleAssistantCompletedReference(role, shopUserId) {
  if (!['merchant', 'admin'].includes(role) || !Number.isSafeInteger(shopUserId) || shopUserId < 1) {
    throw new Error('Invalid saved role assistant page');
  }
  return decode(shopStorage.getItem(SHOP_ROLE_ASSISTANT_COMPLETED_KEY))
    .find(row => row.role === role && row.shopUserId === shopUserId) || null;
}

export async function saveRoleAssistantCompletedReference(reference, isCurrent = () => true) {
  const row = own(reference);
  if (!sameRoleAssistantReference(readRoleAssistantReference(row.role, row.shopUserId), row)
    || isCurrent() !== true) throw new Error('Saved role assistant request changed');
  const current = decode(shopStorage.getItem(SHOP_ROLE_ASSISTANT_COMPLETED_KEY));
  const previous = current.find(value => sameRoleAssistantReference(value, row));
  // Re-reading the same acknowledged assistant result must not reopen a POST
  // after an assessment attempt whose acknowledgment may have been lost.
  if (previous?.restartAssessmentAttempted === true) row.restartAssessmentAttempted = true;
  const next = [...current.filter(value => owner(value) !== owner(row)), row];
  if (next.length > MAX_REFERENCES) throw new Error('Saved role assistant pages are full');
  const raw = JSON.stringify({ version: 1, references: next });
  if (encoder.encode(raw).byteLength > MAX_BYTES) throw new Error('Saved role assistant pages are full');
  shopStorage.setItem(SHOP_ROLE_ASSISTANT_COMPLETED_KEY, raw);
  await flushShopStorage();
  if (isCurrent() !== true || !sameRoleAssistantReference(
    readRoleAssistantCompletedReference(row.role, row.shopUserId), row)) {
    throw new Error('Saved role assistant page changed');
  }
  return row;
}

export async function markRoleAssistantRestartAssessmentAttempted(reference, isCurrent = () => true) {
  if (reference?.role !== 'admin' || !Number.isSafeInteger(reference.shopUserId)
    || reference.shopUserId < 1 || isCurrent() !== true) {
    throw new Error('Saved System restart assessment source changed');
  }
  const current = decode(shopStorage.getItem(SHOP_ROLE_ASSISTANT_COMPLETED_KEY));
  const index = current.findIndex(value => owner(value) === owner(reference));
  if (index < 0 || !sameRoleAssistantReference(current[index], reference)) {
    throw new Error('Saved System restart assessment source changed');
  }
  if (current[index].restartAssessmentAttempted === true) {
    throw new Error('Saved System restart assessment was already attempted');
  }
  const next = [...current];
  next[index] = { ...current[index], restartAssessmentAttempted: true };
  const raw = JSON.stringify({ version: 1, references: next });
  decode(raw);
  if (encoder.encode(raw).byteLength > MAX_BYTES) throw new Error('Saved role assistant pages are full');
  shopStorage.setItem(SHOP_ROLE_ASSISTANT_COMPLETED_KEY, raw);
  await flushShopStorage();
  const saved = readRoleAssistantCompletedReference('admin', reference.shopUserId);
  if (isCurrent() !== true || !sameRoleAssistantReference(saved, reference)
    || saved.restartAssessmentAttempted !== true) {
    throw new Error('Saved System restart assessment source changed');
  }
  return saved;
}

export async function clearRoleAssistantCompletedReference(reference, isCurrent = () => true) {
  const row = own(reference);
  if (isCurrent() !== true) return false;
  const current = decode(shopStorage.getItem(SHOP_ROLE_ASSISTANT_COMPLETED_KEY));
  if (!sameRoleAssistantReference(current.find(value => owner(value) === owner(row)), row)) return false;
  const next = current.filter(value => owner(value) !== owner(row));
  if (next.length) shopStorage.setItem(SHOP_ROLE_ASSISTANT_COMPLETED_KEY,
    JSON.stringify({ version: 1, references: next }));
  else shopStorage.removeItem(SHOP_ROLE_ASSISTANT_COMPLETED_KEY);
  await flushShopStorage();
  if (isCurrent() !== true) return false;
  if (readRoleAssistantCompletedReference(row.role, row.shopUserId)) {
    throw new Error('Saved role assistant page changed');
  }
  return true;
}
