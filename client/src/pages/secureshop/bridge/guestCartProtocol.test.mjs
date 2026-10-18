import { cartItemsFromRows, createGuestCartHost, GUEST_CART_STORAGE_KEY,
  parseStoredGuestCart, validGuestCartItems } from './guestCartProtocol.mjs';

function memoryStorage(initial = null) {
  let value = initial;
  return { getItem: jest.fn(() => value), setItem: jest.fn((_key, next) => { value = next; }),
    removeItem: jest.fn(() => { value = null; }), read: () => value };
}

test('guest cart persists only bounded product IDs and quantities with CAS revisions', () => {
  const storage = memoryStorage();
  const host = createGuestCartHost(storage);
  expect(host.current()).toEqual({ revision: 0, items: [] });
  expect(host.commit(0, [{ productId: 125, quantity: 2 }])).toBe('saved');
  expect(JSON.parse(storage.read())).toEqual({ version: 1, revision: 1,
    items: [{ productId: 125, quantity: 2 }] });
  expect(storage.read()).not.toMatch(/price|name|token|bearer/i);
  expect(host.commit(0, [])).toBe('stale');
  expect(host.commit(1, [])).toBe('saved');
  expect(host.current()).toEqual({ revision: 2, items: [] });
});

test('rejects malformed, oversized, duplicate, or authority-bearing cart data', () => {
  expect(validGuestCartItems([{ productId: 7, quantity: 1, price: 4 }])).toBe(false);
  expect(validGuestCartItems([{ productId: 7, quantity: 1 }, { productId: 7, quantity: 2 }])).toBe(false);
  expect(validGuestCartItems([{ productId: 7, quantity: 100 }])).toBe(false);
  expect(validGuestCartItems(Array.from({ length: 51 }, (_, index) => ({ productId: index + 1, quantity: 1 })))).toBe(false);
  expect(cartItemsFromRows([{ product_id: 7, quantity: 2, name: '<script>', price: 999 }]))
    .toEqual([{ productId: 7, quantity: 2 }]);
  expect(parseStoredGuestCart('{"version":1,"revision":1,"items":[],"token":"x"}')).toBeNull();
  const storage = memoryStorage('{"poison":true}');
  const host = createGuestCartHost(storage);
  expect(host.current()).toEqual({ revision: 0, items: [] });
  expect(storage.removeItem).toHaveBeenCalledWith(GUEST_CART_STORAGE_KEY);
});

test('storage failure cannot acknowledge persistence or advance revision', () => {
  const storage = memoryStorage();
  storage.setItem.mockImplementation(() => { throw new Error('quota'); });
  const host = createGuestCartHost(storage);
  expect(host.commit(0, [{ productId: 1, quantity: 1 }])).toBe('unavailable');
  expect(host.current()).toEqual({ revision: 0, items: [] });
  expect(host.commit(0, [])).toBe('unavailable');
});
