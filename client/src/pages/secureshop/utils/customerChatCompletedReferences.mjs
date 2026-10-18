import { shopStorage, flushShopStorage, SHOP_CUSTOMER_CHAT_COMPLETED_KEY } from './shopStorage.mjs';
import { decodeCustomerChatReferences, readCustomerChatReference } from './customerChatReferences.mjs';

const MAX_REFERENCES = 32;
const MAX_BYTES = 8192;
const encoder = new TextEncoder();
export const sameCustomerChatReference = (left, right) => !!left && !!right
  && ['shopUserId', 'sessionId', 'requestId', 'startedAt'].every(key => left[key] === right[key]);
const decode = raw => decodeCustomerChatReferences(raw);
const own = reference => decode(JSON.stringify({ version: 1, references: [reference] }))[0];

export function readCustomerChatCompletedReference(shopUserId) {
  if (!Number.isSafeInteger(shopUserId) || shopUserId < 1) throw new Error('Invalid saved customer chat page');
  return decode(shopStorage.getItem(SHOP_CUSTOMER_CHAT_COMPLETED_KEY))
    .find(row => row.shopUserId === shopUserId) || null;
}

export async function saveCustomerChatCompletedReference(reference, isCurrent = () => true) {
  const row = own(reference);
  if (!sameCustomerChatReference(readCustomerChatReference(row.shopUserId), row)
    || isCurrent() !== true) throw new Error('Saved customer chat request changed');
  const current = decode(shopStorage.getItem(SHOP_CUSTOMER_CHAT_COMPLETED_KEY));
  const next = [...current.filter(value => value.shopUserId !== row.shopUserId), row];
  if (next.length > MAX_REFERENCES) throw new Error('Saved customer chat pages are full');
  const raw = JSON.stringify({ version: 1, references: next });
  if (encoder.encode(raw).byteLength > MAX_BYTES) throw new Error('Saved customer chat pages are full');
  shopStorage.setItem(SHOP_CUSTOMER_CHAT_COMPLETED_KEY, raw);
  await flushShopStorage();
  if (isCurrent() !== true || !sameCustomerChatReference(readCustomerChatCompletedReference(row.shopUserId), row)) {
    throw new Error('Saved customer chat page changed');
  }
  return row;
}

export async function clearCustomerChatCompletedReference(reference, isCurrent = () => true) {
  const row = own(reference);
  if (isCurrent() !== true) return false;
  const current = decode(shopStorage.getItem(SHOP_CUSTOMER_CHAT_COMPLETED_KEY));
  if (!sameCustomerChatReference(current.find(value => value.shopUserId === row.shopUserId), row)) return false;
  const next = current.filter(value => value.shopUserId !== row.shopUserId);
  if (next.length) shopStorage.setItem(SHOP_CUSTOMER_CHAT_COMPLETED_KEY,
    JSON.stringify({ version: 1, references: next }));
  else shopStorage.removeItem(SHOP_CUSTOMER_CHAT_COMPLETED_KEY);
  await flushShopStorage();
  if (isCurrent() !== true) return false;
  if (readCustomerChatCompletedReference(row.shopUserId)) throw new Error('Saved customer chat page changed');
  return true;
}
