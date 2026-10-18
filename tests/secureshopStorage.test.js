'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const load = () => import('../client/src/pages/secureshop/utils/shopStorage.mjs');
function backing() {
  const values = new Map();
  return { values, getItem: key => values.get(key) ?? null, setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key) };
}

test('shop storage preserves normal persistence and externally changed teaching JWTs', async () => {
  const { createShopStorage, SHOP_TOKEN_KEY } = await load();
  const disk = backing(); const storage = createShopStorage({ getStorage: () => disk });
  storage.setItem(SHOP_TOKEN_KEY, 'synthetic-shop-token');
  assert.equal(disk.getItem(SHOP_TOKEN_KEY), 'synthetic-shop-token');
  assert.equal(createShopStorage({ getStorage: () => disk }).getItem(SHOP_TOKEN_KEY), 'synthetic-shop-token');
  disk.setItem(SHOP_TOKEN_KEY, 'learner-modified-shop-jwt');
  assert.equal(storage.getItem(SHOP_TOKEN_KEY), 'learner-modified-shop-jwt');
  disk.removeItem(SHOP_TOKEN_KEY);
  assert.equal(storage.getItem(SHOP_TOKEN_KEY), null);
});

test('opaque/blocked storage retains login and guest cart within one realm only', async () => {
  const { createShopStorage, SHOP_TOKEN_KEY, SHOP_CART_KEY } = await load();
  const unavailable = () => { throw new DOMException('Opaque origin', 'SecurityError'); };
  const storage = createShopStorage({ getStorage: unavailable });
  storage.setItem(SHOP_TOKEN_KEY, 'synthetic-token');
  storage.setItem(SHOP_CART_KEY, '[{"product_id":17,"quantity":2}]');
  assert.equal(storage.getItem(SHOP_TOKEN_KEY), 'synthetic-token');
  assert.equal(JSON.parse(storage.getItem(SHOP_CART_KEY))[0].quantity, 2);
  assert.equal(createShopStorage({ getStorage: unavailable }).getItem(SHOP_TOKEN_KEY), null);
  storage.removeItem(SHOP_TOKEN_KEY);
  assert.equal(storage.getItem(SHOP_TOKEN_KEY), null);
  assert.ok(storage.getItem(SHOP_CART_KEY));
});

test('failed writes/removal never resurrect an older persisted credential', async () => {
  const { createShopStorage, SHOP_TOKEN_KEY } = await load();
  const disk = backing();disk.setItem(SHOP_TOKEN_KEY, 'old-token');
  let writable = false;
  const storage = createShopStorage({ getStorage: () => ({
    getItem: disk.getItem,
    setItem: (...args) => { if (!writable) throw new Error('quota'); disk.setItem(...args); },
    removeItem: (...args) => { if (!writable) throw new Error('denied'); disk.removeItem(...args); },
  }) });
  assert.equal(storage.getItem(SHOP_TOKEN_KEY), 'old-token');
  storage.setItem(SHOP_TOKEN_KEY, 'new-token');
  assert.equal(storage.getItem(SHOP_TOKEN_KEY), 'new-token');
  storage.removeItem(SHOP_TOKEN_KEY);
  assert.equal(storage.getItem(SHOP_TOKEN_KEY), null);
  writable = true;
  storage.setItem(SHOP_TOKEN_KEY, 'recovered-token');
  assert.equal(disk.getItem(SHOP_TOKEN_KEY), 'recovered-token');
  storage.removeItem(SHOP_TOKEN_KEY);
  assert.equal(disk.getItem(SHOP_TOKEN_KEY), null);
});

test('storage adapter refuses platform keys and invalid values before accessing storage', async () => {
  const { createShopStorage, SHOP_TOKEN_KEY } = await load();
  let accesses = 0;
  const storage = createShopStorage({ getStorage: () => { accesses++; return backing(); } });
  for (const key of ['token', 'platform_token', '__proto__', 'launch', '', null, {}]) {
    assert.throws(() => storage.getItem(key), /Unsupported/);
    assert.throws(() => storage.setItem(key, 'value'), /Unsupported/);
    assert.throws(() => storage.removeItem(key), /Unsupported/);
  }
  assert.throws(() => storage.setItem(SHOP_TOKEN_KEY, {}), /strings/);
  assert.equal(accesses, 0);
});

test('fallback token reaches the existing fetch adapter and explicit teaching bearer still wins', async () => {
  const { createShopStorage, SHOP_TOKEN_KEY } = await load();
  const { createSecureShopFetch } = await import('../client/src/utils/secureShopFetch.mjs');
  const storage = createShopStorage({ getStorage: () => { throw new Error('storage unavailable'); } });
  const calls = [];
  const fetch = createSecureShopFetch({ fetchImpl: async (...args) => { calls.push(args); }, getPageUrl: () => 'http://localhost:3000/secureshop', getRequestBaseUrl: () => 'http://localhost:3000/', getToken: () => storage.getItem(SHOP_TOKEN_KEY) });
  storage.setItem(SHOP_TOKEN_KEY, 'synthetic-login');
  await fetch('/api/secureshop/cart');
  assert.equal(new Headers(calls[0][1].headers).get('authorization'), 'Bearer synthetic-login');
  await fetch('/api/secureshop/cart', { headers: { Authorization: 'Bearer learner-crafted' } });
  assert.equal(new Headers(calls[1][1].headers).get('authorization'), 'Bearer learner-crafted');
  storage.removeItem(SHOP_TOKEN_KEY);
  await fetch('/api/secureshop/cart');
  assert.equal(new Headers(calls[2][1]?.headers).get('authorization'), null);
});
