import { shopStorage, flushShopStorage, SHOP_REFUND_KEY } from './shopStorage.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const MAX_REFERENCES = 32;
const MAX_BYTES = 8192;
const encoder = new TextEncoder();
const same = (a, b) => a.orderId === b.orderId
  && a.sessionId === b.sessionId && a.requestId === b.requestId;

export function decodeRefundReferences(raw) {
  if (raw === null) return [];
  if (typeof raw !== 'string' || encoder.encode(raw).byteLength > MAX_BYTES) throw Error('Invalid saved refund references');
  let value;
  try { value = JSON.parse(raw); } catch { throw Error('Invalid saved refund references'); }
  if (!value || Object.getPrototypeOf(value) !== Object.prototype
      || Object.keys(value).sort().join(',') !== 'references,version'
      || value.version !== 1 || !Array.isArray(value.references)
      || value.references.length > MAX_REFERENCES) throw Error('Invalid saved refund references');
  const orders = new Set();
  const requests = new Set();
  for (const row of value.references) {
    if (!row || Object.getPrototypeOf(row) !== Object.prototype
        || Object.keys(row).sort().join(',') !== 'orderId,requestId,sessionId'
        || !Number.isSafeInteger(row.orderId) || row.orderId < 1
        || typeof row.sessionId !== 'string' || !UUID.test(row.sessionId)
        || typeof row.requestId !== 'string' || !UUID.test(row.requestId)
        || orders.has(row.orderId) || requests.has(row.requestId)) throw Error('Invalid saved refund references');
    orders.add(row.orderId);
    requests.add(row.requestId);
  }
  return value.references;
}

export function readRefundReferences() {
  return decodeRefundReferences(shopStorage.getItem(SHOP_REFUND_KEY));
}

export async function saveRefundReference(reference) {
  const row = decodeRefundReferences(JSON.stringify({ version: 1, references: [reference] }))[0];
  const current = readRefundReferences();
  const existing = current.find(value => value.orderId === row.orderId);
  if (existing) {
    if (!same(existing, row)) throw Error('Check the saved refund before requesting another for this order.');
    await flushShopStorage();
    return existing;
  }
  if (current.length >= MAX_REFERENCES) throw Error('Saved refund history is full.');
  const next = JSON.stringify({ version: 1, references: [...current, row] });
  if (encoder.encode(next).byteLength > MAX_BYTES) throw Error('Saved refund history is full.');
  shopStorage.setItem(SHOP_REFUND_KEY, next);
  await flushShopStorage();
  return row;
}
