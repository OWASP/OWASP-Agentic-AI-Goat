export const GUEST_CART_CHANNEL = 'dvaia-secureshop-guest-cart-v1';
export const GUEST_CART_STORAGE_KEY = 'dvaia.secureshop.guest-cart.v1';
export const MAX_GUEST_CART_ITEMS = 50;
export const MAX_GUEST_CART_BYTES = 4096;

const exactKeys = (value, keys) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));

export function validGuestCartItems(items) {
  if (!Array.isArray(items) || items.length > MAX_GUEST_CART_ITEMS) return false;
  const ids = new Set();
  for (const item of items) {
    if (!exactKeys(item, ['productId', 'quantity'])
      || !Number.isSafeInteger(item.productId) || item.productId < 1 || item.productId > 2147483647
      || !Number.isSafeInteger(item.quantity) || item.quantity < 1 || item.quantity > 99
      || ids.has(item.productId)) return false;
    ids.add(item.productId);
  }
  return new TextEncoder().encode(JSON.stringify(items)).byteLength < MAX_GUEST_CART_BYTES;
}

export function cartItemsFromRows(rows) {
  if (!Array.isArray(rows)) return null;
  const items = rows.map(row => ({ productId: Number(row?.product_id), quantity: Number(row?.quantity) }));
  return validGuestCartItems(items) ? items : null;
}

export function validStoredGuestCart(value) {
  return exactKeys(value, ['version', 'revision', 'items']) && value.version === 1
    && Number.isSafeInteger(value.revision) && value.revision >= 0
    && validGuestCartItems(value.items)
    && new TextEncoder().encode(JSON.stringify(value)).byteLength < MAX_GUEST_CART_BYTES;
}

export function parseStoredGuestCart(raw) {
  if (typeof raw !== 'string' || new TextEncoder().encode(raw).byteLength >= MAX_GUEST_CART_BYTES) return null;
  try { const value = JSON.parse(raw); return validStoredGuestCart(value) ? value : null; } catch { return null; }
}

export function exactCartMessage(value, type) {
  const keys = type === 'snapshot' ? ['channel', 'type', 'nonce', 'baseRevision', 'items']
    : type === 'hydrate' ? ['channel', 'type', 'nonce', 'revision', 'items']
      : type === 'ack' ? ['channel', 'type', 'nonce', 'revision']
        : ['channel', 'type', 'nonce'];
  return exactKeys(value, keys) && value.channel === GUEST_CART_CHANNEL && value.type === type
    && typeof value.nonce === 'string' && /^[a-f0-9]{64}$/i.test(value.nonce);
}

export function createGuestCartHost(storage) {
  let state = { version: 1, revision: 0, items: [] };
  let writable = Boolean(storage);
  if (writable) {
    try {
      const raw = storage.getItem(GUEST_CART_STORAGE_KEY);
      if (raw !== null) {
        const parsed = parseStoredGuestCart(raw);
        if (parsed) state = parsed;
        else storage.removeItem(GUEST_CART_STORAGE_KEY);
      }
    } catch { writable = false; }
  }
  return Object.freeze({
    current: () => ({ revision: state.revision, items: state.items.map(item => ({ ...item })) }),
    commit(baseRevision, items) {
      if (!Number.isSafeInteger(baseRevision) || baseRevision < 0 || !validGuestCartItems(items)) return 'invalid';
      if (baseRevision !== state.revision) return 'stale';
      if (!writable || state.revision === Number.MAX_SAFE_INTEGER) return 'unavailable';
      const next = { version: 1, revision: state.revision + 1,
        items: items.map(item => ({ productId: item.productId, quantity: item.quantity })) };
      if (!validStoredGuestCart(next)) return 'invalid';
      try { storage.setItem(GUEST_CART_STORAGE_KEY, JSON.stringify(next)); }
      catch { writable = false; return 'unavailable'; }
      state = next;
      return 'saved';
    },
  });
}
