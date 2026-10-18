import { shopStorage, flushShopStorage, SHOP_REGISTERED_ADMIN_CHAT_KEY } from './shopStorage.mjs';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const same = (left, right) => !!left && !!right
  && ['shopUserId', 'sessionId', 'requestId', 'startedAt'].every(key => left[key] === right[key]);
const invalid = () => { throw Error('Invalid saved registered-tools request'); };

export function decodeRegisteredAdminChatReference(raw) {
  if (raw === null) return null;
  if (typeof raw !== 'string' || new TextEncoder().encode(raw).byteLength > 1024) invalid();
  let value;
  try { value = JSON.parse(raw); } catch { invalid(); }
  if (!exact(value, ['version', 'shopUserId', 'sessionId', 'requestId', 'startedAt'])
    || value.version !== 1 || !Number.isSafeInteger(value.shopUserId) || value.shopUserId < 1
    || typeof value.sessionId !== 'string' || !UUID.test(value.sessionId)
    || typeof value.requestId !== 'string' || !UUID.test(value.requestId)
    || !Number.isSafeInteger(value.startedAt) || value.startedAt < 1) invalid();
  return Object.freeze(value);
}

export const readRegisteredAdminChatReference = () =>
  decodeRegisteredAdminChatReference(shopStorage.getItem(SHOP_REGISTERED_ADMIN_CHAT_KEY));

export function assertRegisteredAdminChatReference(reference) {
  const saved = readRegisteredAdminChatReference();
  if (!same(saved, reference)) throw Error('Saved registered-tools request changed');
  return saved;
}

export async function saveRegisteredAdminChatReference(reference, current = () => true) {
  const saved = decodeRegisteredAdminChatReference(JSON.stringify({ version: 1, ...reference }));
  if (!current()) throw Error('Registered-tools authority changed');
  if (shopStorage.getItem(SHOP_REGISTERED_ADMIN_CHAT_KEY) !== null) {
    throw Error('Check the saved registered-tools request before sending another');
  }
  shopStorage.setItem(SHOP_REGISTERED_ADMIN_CHAT_KEY, JSON.stringify(saved));
  await flushShopStorage();
  if (!current()) throw Error('Registered-tools authority changed');
  assertRegisteredAdminChatReference(saved);
  return saved;
}

export async function clearRegisteredAdminChatReference(reference, current = () => true) {
  if (!current()) throw Error('Registered-tools authority changed');
  assertRegisteredAdminChatReference(reference);
  try {
    shopStorage.removeItem(SHOP_REGISTERED_ADMIN_CHAT_KEY);
    await flushShopStorage();
    if (!current() || readRegisteredAdminChatReference() !== null) {
      throw Error('Saved registered-tools request changed');
    }
  } catch (error) {
    if (current()) try {
      if (readRegisteredAdminChatReference() === null) {
        shopStorage.setItem(SHOP_REGISTERED_ADMIN_CHAT_KEY, JSON.stringify({ version: 1, ...reference }));
        await flushShopStorage();
      }
    } catch { /* keep the caller unresolved */ }
    throw error;
  }
}
