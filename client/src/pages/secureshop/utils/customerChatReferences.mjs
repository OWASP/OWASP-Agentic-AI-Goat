import { shopStorage, flushShopStorage, SHOP_CUSTOMER_CHAT_KEY } from './shopStorage.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX_BYTES = 8192;
const MAX_REFERENCES = 32;
const encoder = new TextEncoder();
const same = (a, b) => !!a && a.shopUserId === b.shopUserId
  && a.sessionId === b.sessionId && a.requestId === b.requestId && a.startedAt === b.startedAt;
const invalid = () => { throw new Error('Invalid saved customer chat reference'); };

export function decodeCustomerChatReferences(raw) {
  if (raw === null) return [];
  if (typeof raw !== 'string' || encoder.encode(raw).byteLength > MAX_BYTES) invalid();
  let value;
  try { value = JSON.parse(raw); } catch { invalid(); }
  if (!value || Object.getPrototypeOf(value) !== Object.prototype
    || Object.keys(value).sort().join(',') !== 'references,version' || value.version !== 1
    || !Array.isArray(value.references) || value.references.length < 1
    || value.references.length > MAX_REFERENCES) invalid();
  const owners = new Set(), requests = new Set();
  for (const row of value.references) {
    if (!row || Object.getPrototypeOf(row) !== Object.prototype
      || Object.keys(row).sort().join(',') !== 'requestId,sessionId,shopUserId,startedAt'
      || !Number.isSafeInteger(row.shopUserId) || row.shopUserId < 1
      || typeof row.sessionId !== 'string' || !UUID.test(row.sessionId)
      || typeof row.requestId !== 'string' || !UUID.test(row.requestId)
      || !Number.isSafeInteger(row.startedAt) || row.startedAt < 1
      || owners.has(row.shopUserId) || requests.has(row.requestId)) invalid();
    owners.add(row.shopUserId); requests.add(row.requestId);
  }
  return value.references;
}

export function readCustomerChatReference(shopUserId) {
  if (!Number.isSafeInteger(shopUserId) || shopUserId < 1) invalid();
  return decodeCustomerChatReferences(shopStorage.getItem(SHOP_CUSTOMER_CHAT_KEY))
    .find(row => row.shopUserId === shopUserId) || null;
}

export async function saveCustomerChatReference(reference) {
  const row = decodeCustomerChatReferences(JSON.stringify({ version: 1, references: [reference] }))[0];
  const references = decodeCustomerChatReferences(shopStorage.getItem(SHOP_CUSTOMER_CHAT_KEY));
  if (references.some(existing => existing.shopUserId === row.shopUserId)) {
    throw new Error('Check the saved customer chat before sending another message');
  }
  if (references.length >= MAX_REFERENCES) throw new Error('Saved customer chat references are full');
  const raw = JSON.stringify({ version: 1, references: [...references, row] });
  if (encoder.encode(raw).byteLength > MAX_BYTES) throw new Error('Saved customer chat references are full');
  shopStorage.setItem(SHOP_CUSTOMER_CHAT_KEY, raw);
  await flushShopStorage();
  if (!same(readCustomerChatReference(row.shopUserId), row)) {
    throw new Error('Saved customer chat reference changed');
  }
  return row;
}

export async function clearCustomerChatReference(reference) {
  const row = decodeCustomerChatReferences(JSON.stringify({ version: 1, references: [reference] }))[0];
  const references = decodeCustomerChatReferences(shopStorage.getItem(SHOP_CUSTOMER_CHAT_KEY));
  const existing = references.find(value => value.shopUserId === row.shopUserId);
  if (!existing || !same(existing, row)) throw new Error('Saved customer chat reference changed');
  const next = references.filter(value => value.shopUserId !== row.shopUserId);
  try {
    if (next.length) shopStorage.setItem(SHOP_CUSTOMER_CHAT_KEY, JSON.stringify({ version: 1, references: next }));
    else shopStorage.removeItem(SHOP_CUSTOMER_CHAT_KEY);
    await flushShopStorage();
    if (readCustomerChatReference(row.shopUserId)) throw new Error('Saved customer chat reference changed');
  } catch (error) {
    // A lost parent removal acknowledgement cannot prove the UUID was retired.
    // Restore only the same request, preserving other owners and replacements.
    try {
      const current = decodeCustomerChatReferences(shopStorage.getItem(SHOP_CUSTOMER_CHAT_KEY));
      if (!current.some(value => value.shopUserId === row.shopUserId) && current.length < MAX_REFERENCES) {
        shopStorage.setItem(SHOP_CUSTOMER_CHAT_KEY,
          JSON.stringify({ version: 1, references: [...current, row] }));
        await flushShopStorage();
      }
    } catch { /* the mounted hook also keeps the request latched */ }
    throw error;
  }
}
