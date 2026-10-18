import { shopStorage, flushShopStorage, SHOP_ROLE_ASSISTANT_KEY } from './shopStorage.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX_BYTES = 8192;
const MAX_REFERENCES = 32;
const encoder = new TextEncoder();
const invalid = () => { throw new Error('Invalid saved role assistant reference'); };
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === keys.slice().sort().join(',');
const same = (left, right) => left && right
  && ['role', 'shopUserId', 'sessionId', 'requestId', 'startedAt']
    .every(key => left[key] === right[key]);
const owner = row => `${row.role}:${row.shopUserId}`;

export function decodeRoleAssistantReferences(raw) {
  if (raw === null) return [];
  if (typeof raw !== 'string' || encoder.encode(raw).byteLength > MAX_BYTES) invalid();
  let value;
  try { value = JSON.parse(raw); } catch { invalid(); }
  if (!exact(value, ['version', 'references']) || value.version !== 1
    || !Array.isArray(value.references) || value.references.length < 1
    || value.references.length > MAX_REFERENCES) invalid();
  const owners = new Set(), requests = new Set();
  for (const row of value.references) {
    if (!(exact(row, ['role', 'shopUserId', 'sessionId', 'requestId', 'startedAt'])
        || exact(row, ['role', 'shopUserId', 'sessionId', 'requestId', 'startedAt', 'restartAssessmentAttempted']))
      || (Object.hasOwn(row, 'restartAssessmentAttempted')
        && (row.role !== 'admin' || row.restartAssessmentAttempted !== true))
      || !['merchant', 'admin'].includes(row.role)
      || !Number.isSafeInteger(row.shopUserId) || row.shopUserId < 1
      || typeof row.sessionId !== 'string' || !UUID.test(row.sessionId)
      || typeof row.requestId !== 'string' || !UUID.test(row.requestId)
      || row.sessionId !== row.sessionId.toLowerCase()
      || row.requestId !== row.requestId.toLowerCase()
      || !Number.isSafeInteger(row.startedAt) || row.startedAt < 1
      || owners.has(owner(row)) || requests.has(row.requestId)) invalid();
    owners.add(owner(row)); requests.add(row.requestId);
  }
  return value.references;
}

export function readRoleAssistantReference(role, shopUserId) {
  if (!['merchant', 'admin'].includes(role) || !Number.isSafeInteger(shopUserId) || shopUserId < 1) invalid();
  return decodeRoleAssistantReferences(shopStorage.getItem(SHOP_ROLE_ASSISTANT_KEY))
    .find(row => row.role === role && row.shopUserId === shopUserId) || null;
}

export async function saveRoleAssistantReference(reference) {
  const row = decodeRoleAssistantReferences(JSON.stringify({ version: 1, references: [reference] }))[0];
  const references = decodeRoleAssistantReferences(shopStorage.getItem(SHOP_ROLE_ASSISTANT_KEY));
  if (references.some(existing => owner(existing) === owner(row))) {
    throw new Error('Check the saved role assistant request before sending another');
  }
  if (references.length >= MAX_REFERENCES) throw new Error('Saved role assistant references are full');
  const bytes = JSON.stringify({ version: 1, references: [...references, row] });
  if (encoder.encode(bytes).byteLength > MAX_BYTES) throw new Error('Saved role assistant references are full');
  shopStorage.setItem(SHOP_ROLE_ASSISTANT_KEY, bytes);
  await flushShopStorage();
  if (!same(readRoleAssistantReference(row.role, row.shopUserId), row)) {
    throw new Error('Saved role assistant reference changed');
  }
  return row;
}

export async function clearRoleAssistantReference(reference) {
  const row = decodeRoleAssistantReferences(JSON.stringify({ version: 1, references: [reference] }))[0];
  const references = decodeRoleAssistantReferences(shopStorage.getItem(SHOP_ROLE_ASSISTANT_KEY));
  const existing = references.find(value => owner(value) === owner(row));
  if (!same(existing, row)) throw new Error('Saved role assistant reference changed');
  const next = references.filter(value => owner(value) !== owner(row));
  try {
    if (next.length) shopStorage.setItem(SHOP_ROLE_ASSISTANT_KEY,
      JSON.stringify({ version: 1, references: next }));
    else shopStorage.removeItem(SHOP_ROLE_ASSISTANT_KEY);
    await flushShopStorage();
    if (readRoleAssistantReference(row.role, row.shopUserId)) {
      throw new Error('Saved role assistant reference changed');
    }
  } catch (error) {
    // A missing removal ACK cannot release this role's request. Restore only
    // its exact opaque reference into the latest readable set; foreign rows
    // and a replacement for this owner always take precedence.
    try {
      const current = decodeRoleAssistantReferences(shopStorage.getItem(SHOP_ROLE_ASSISTANT_KEY));
      const occupied = current.find(value => owner(value) === owner(row));
      if (!occupied && current.length < MAX_REFERENCES) {
        const restored = JSON.stringify({ version: 1, references: [...current, row] });
        decodeRoleAssistantReferences(restored);
        shopStorage.setItem(SHOP_ROLE_ASSISTANT_KEY, restored);
        await flushShopStorage();
      }
    } catch { /* the mounted caller retains the unresolved reference */ }
    throw error;
  }
}
