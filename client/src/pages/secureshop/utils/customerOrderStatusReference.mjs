import { shopStorage, flushShopStorage, SHOP_CUSTOMER_ORDER_STATUS_KEY } from './shopStorage.mjs';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const invalid = () => { throw new Error('Saved order-status lesson reference unavailable'); };
const same = (a, b) => !!a && !!b && ['shopUserId', 'sessionId', 'requestId', 'startedAt']
  .every(key => a[key] === b[key]);

export function decodeOrderStatusReferences(raw) {
  if (raw === null) return [];
  if (typeof raw !== 'string' || new TextEncoder().encode(raw).byteLength > 8192) invalid();
  let value;
  try { value = JSON.parse(raw); } catch { invalid(); }
  if (!value || Object.getPrototypeOf(value) !== Object.prototype
    || Object.keys(value).sort().join(',') !== 'references,version' || value.version !== 1
    || !Array.isArray(value.references) || value.references.length > 32) invalid();
  const owners = new Set(), requests = new Set();
  return value.references.map(row => {
    if (!row || Object.getPrototypeOf(row) !== Object.prototype
      || Object.keys(row).sort().join(',') !== 'requestId,sessionId,shopUserId,startedAt'
      || !Number.isSafeInteger(row.shopUserId) || row.shopUserId < 1
      || ![row.sessionId, row.requestId].every(id => typeof id === 'string' && UUID.test(id))
      || !Number.isSafeInteger(row.startedAt) || row.startedAt < 1
      || owners.has(row.shopUserId) || requests.has(row.requestId)) invalid();
    owners.add(row.shopUserId); requests.add(row.requestId);
    return Object.freeze({ ...row });
  });
}

export function createOrderStatusReferenceStore({ storage = shopStorage, flush = flushShopStorage } = {}) {
  if (!storage || ['getItem', 'setItem', 'removeItem'].some(key => typeof storage[key] !== 'function')
    || typeof flush !== 'function') throw new TypeError('Order-status lesson storage required');
  const all = () => decodeOrderStatusReferences(storage.getItem(SHOP_CUSTOMER_ORDER_STATUS_KEY));
  const validate = row => decodeOrderStatusReferences(JSON.stringify({ version: 1, references: [row] }))[0];
  const write = async rows => {
    if (rows.length) storage.setItem(SHOP_CUSTOMER_ORDER_STATUS_KEY, JSON.stringify({ version: 1, references: rows }));
    else storage.removeItem(SHOP_CUSTOMER_ORDER_STATUS_KEY);
    await flush();
  };
  return Object.freeze({
    read(shopUserId) {
      if (!Number.isSafeInteger(shopUserId) || shopUserId < 1) invalid();
      return all().find(row => row.shopUserId === shopUserId) || null;
    },
    async save(reference, current = () => true) {
      const row = validate(reference), rows = all();
      if (current() !== true || rows.some(value => value.shopUserId === row.shopUserId)) invalid();
      await write([...rows, row]);
      if (current() !== true || !same(this.read(row.shopUserId), row)) invalid();
      return row;
    },
    async clear(reference, current = () => true) {
      const row = validate(reference), rows = all();
      if (current() !== true || !same(rows.find(value => value.shopUserId === row.shopUserId), row)) invalid();
      try {
        await write(rows.filter(value => value.shopUserId !== row.shopUserId));
        if (current() !== true || this.read(row.shopUserId) !== null) invalid();
      } catch (error) {
        if (current() === true) try {
          if (!this.read(row.shopUserId)) await write([...all(), row]);
        } catch { /* The caller keeps the reference latched. */ }
        throw error;
      }
    },
  });
}

export const orderStatusReferenceStore = createOrderStatusReferenceStore();
