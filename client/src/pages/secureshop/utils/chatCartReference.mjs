import { shopStorage, flushShopStorage, SHOP_CHAT_CART_KEY } from './shopStorage.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA = /^[a-f0-9]{64}$/;
const same = (a, b) => !!a && !!b && a.operationId === b.operationId
  && a.intentDigest === b.intentDigest && a.scopeKey === b.scopeKey;

export function decodeChatCartReference(raw) {
  if (raw === null) return null;
  if (typeof raw !== 'string' || new TextEncoder().encode(raw).byteLength > 512) {
    throw new Error('Invalid saved cart confirmation');
  }
  let value;
  try { value = JSON.parse(raw); } catch { throw new Error('Invalid saved cart confirmation'); }
  if (!value || Object.getPrototypeOf(value) !== Object.prototype
    || Object.keys(value).sort().join(',') !== 'intentDigest,operationId,scopeKey'
    || !UUID.test(value.operationId) || !SHA.test(value.intentDigest) || !SHA.test(value.scopeKey)) {
    throw new Error('Invalid saved cart confirmation');
  }
  return value;
}

export function readChatCartReference() {
  return decodeChatCartReference(shopStorage.getItem(SHOP_CHAT_CART_KEY));
}

export async function saveChatCartReference(reference) {
  const next = decodeChatCartReference(JSON.stringify(reference));
  const existing = readChatCartReference();
  if (existing && !same(existing, next)) throw new Error('Check the saved cart change before confirming another');
  shopStorage.setItem(SHOP_CHAT_CART_KEY, JSON.stringify(next));
  await flushShopStorage();
  if (!same(readChatCartReference(), next)) throw new Error('Saved cart confirmation changed');
  return next;
}

export async function clearChatCartReference(reference) {
  const expected = decodeChatCartReference(JSON.stringify(reference));
  const saved = readChatCartReference();
  if (!same(saved, expected)) throw new Error('Saved cart confirmation changed');
  try {
    shopStorage.removeItem(SHOP_CHAT_CART_KEY);
    await flushShopStorage();
    if (readChatCartReference()) throw new Error('Saved cart confirmation changed');
  } catch (error) {
    try {
      const current = readChatCartReference();
      if (!current) {
        shopStorage.setItem(SHOP_CHAT_CART_KEY, JSON.stringify(saved));
        await flushShopStorage();
      }
    } catch { /* caller also keeps this exact request latched */ }
    throw error;
  }
}
