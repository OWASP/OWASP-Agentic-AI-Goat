import { shopStorage, flushShopStorage, SHOP_CHECKOUT_KEY } from './shopStorage.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA = /^[a-f0-9]{64}$/;
const encoder = new TextEncoder();
const sameReference = (a, b) => a?.operationId === b?.operationId
  && a?.intentDigest === b?.intentDigest && a?.scopeKey === b?.scopeKey;

export function decodeCheckoutReference(raw) {
  if (raw === null) return null;
  if (typeof raw !== 'string' || encoder.encode(raw).byteLength > 512) throw Error('Invalid checkout reference');
  let value;
  try { value = JSON.parse(raw); } catch { throw Error('Invalid checkout reference'); }
  if (!value || Object.getPrototypeOf(value) !== Object.prototype
      || Object.keys(value).sort().join(',') !== 'intentDigest,operationId,scopeKey'
      || !UUID.test(value.operationId) || !SHA.test(value.intentDigest) || !SHA.test(value.scopeKey)) {
    throw Error('Invalid checkout reference');
  }
  return value;
}

export async function checkoutIntentDigest(shippingAddress, paymentMethod) {
  if (typeof shippingAddress !== 'string' || typeof paymentMethod !== 'string') throw Error('Invalid checkout intent');
  const bytes = encoder.encode(JSON.stringify([shippingAddress, paymentMethod]));
  if (bytes.byteLength > 16384) throw Error('Checkout intent is too long');
  return [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))]
    .map(value => value.toString(16).padStart(2, '0')).join('');
}

export function readCheckoutReference() {
  return decodeCheckoutReference(shopStorage.getItem(SHOP_CHECKOUT_KEY));
}

export async function saveCheckoutReference(reference) {
  const next = decodeCheckoutReference(JSON.stringify(reference));
  const existing = readCheckoutReference();
  if (existing && !sameReference(existing, next)) throw Error('Check the saved checkout before starting another order.');
  shopStorage.setItem(SHOP_CHECKOUT_KEY, JSON.stringify(next));
  await flushShopStorage();
  return next;
}

export async function clearCheckoutReference(reference) {
  const saved = readCheckoutReference();
  if (!saved || !sameReference(saved, reference)) throw Error('Saved checkout changed. Check its receipt again.');
  try {
    shopStorage.removeItem(SHOP_CHECKOUT_KEY);
    await flushShopStorage();
  } catch (error) {
    // A lost remove acknowledgement is not proof of durable deletion. Restore
    // the exact opaque reference only if no other writer replaced it.
    try {
      const current = readCheckoutReference();
      if (!current || sameReference(saved, current)) {
        shopStorage.setItem(SHOP_CHECKOUT_KEY, JSON.stringify(saved));
        await flushShopStorage();
      }
    }
    catch { /* the mounted checkout also keeps its reference latched */ }
    throw error;
  }
}
