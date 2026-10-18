import { createScopedShopStateStore, validateShopSnapshot } from './stateStore.mjs';
import { createHostShopStateChannel, connectFrameShopState } from './stateChannel.mjs';
import { SHOP_TOKEN_KEY, SHOP_CART_KEY, SHOP_CUSTOMER_COUPON_PROBE_KEY,
  SHOP_CUSTOMER_ORDER_STATUS_KEY, createShopStorage } from '../utils/shopStorage.mjs';

const row = { shopUserId: 7, sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', startedAt: 1234 };
const reference = JSON.stringify({ version: 1, references: [row] });
const sibling = JSON.stringify({ version: 1, references: [{ ...row, shopUserId: 8,
  sessionId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
  requestId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd' }] });

function localPorts() {
  const listeners = [new Set(), new Set()];
  const ports = listeners.map((own, index) => ({
    addEventListener: (_type, listener) => own.add(listener),
    removeEventListener: (_type, listener) => own.delete(listener),
    start() {}, close() { own.clear(); },
    postMessage(data) { queueMicrotask(() => {
      for (const listener of listeners[1 - index]) listener({ data });
    }); },
  }));
  return { port1: ports[0], port2: ports[1] };
}

test('parent bridge persists only closed opaque order-status references with sibling state', () => {
  const coupon = JSON.stringify({ version: 1, references: [] });
  const snapshot = { [SHOP_TOKEN_KEY]: null, [SHOP_CART_KEY]: null,
    [SHOP_CUSTOMER_COUPON_PROBE_KEY]: coupon,
    [SHOP_CUSTOMER_ORDER_STATUS_KEY]: JSON.stringify({ version: 1,
      references: [row, JSON.parse(sibling).references[0]] }) };
  const storage = new Map();
  const store = createScopedShopStateStore({ storage: {
    getItem: key => storage.get(key) ?? null,
    setItem: (key, value) => storage.set(key, value),
  }, scenarioId: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', generation: 1,
  isCurrent: () => true });
  store.replace(snapshot);
  expect(store.read()[SHOP_CUSTOMER_ORDER_STATUS_KEY]).toBe(snapshot[SHOP_CUSTOMER_ORDER_STATUS_KEY]);
  expect(store.read()[SHOP_CUSTOMER_COUPON_PROBE_KEY]).toBe(coupon);
  expect(validateShopSnapshot({ [SHOP_TOKEN_KEY]: null, [SHOP_CART_KEY]: null,
    [SHOP_CUSTOMER_ORDER_STATUS_KEY]: reference })[SHOP_CUSTOMER_ORDER_STATUS_KEY]).toBe(reference);
});

test('fresh frame saves, flushes, reads and clears order-status reference through the host', async () => {
  const storage = new Map(), ports = localPorts();
  const store = createScopedShopStateStore({ storage: {
    getItem: key => storage.get(key) ?? null,
    setItem: (key, value) => storage.set(key, value),
  }, scenarioId: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', generation: 1,
  isCurrent: () => true });
  const host = createHostShopStateChannel({ port: ports.port1, store });
  try {
    const frame = await connectFrameShopState({ port: ports.port2, timeoutMs: 1000 });
    expect(frame.getItem(SHOP_CUSTOMER_ORDER_STATUS_KEY)).toBeNull();
    frame.setItem(SHOP_CUSTOMER_ORDER_STATUS_KEY, reference);
    await frame.flush();
    expect(frame.getItem(SHOP_CUSTOMER_ORDER_STATUS_KEY)).toBe(reference);
    expect(store.read()[SHOP_CUSTOMER_ORDER_STATUS_KEY]).toBe(reference);
    frame.removeItem(SHOP_CUSTOMER_ORDER_STATUS_KEY);
    await frame.flush();
    expect(frame.getItem(SHOP_CUSTOMER_ORDER_STATUS_KEY)).toBeNull();
    expect(store.read()).not.toHaveProperty(SHOP_CUSTOMER_ORDER_STATUS_KEY);
    frame.close();
  } finally { host.close(); }
});

test('parent bridge rejects order-status content, duplicate owners and oversized snapshots', () => {
  const base = { [SHOP_TOKEN_KEY]: null, [SHOP_CART_KEY]: null };
  for (const invalid of [
    JSON.stringify({ version: 1, references: [{ ...row, text: 'private result' }] }),
    JSON.stringify({ version: 1, references: [row, { ...row,
      requestId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd' }] }),
    'x'.repeat(8193),
  ]) expect(() => validateShopSnapshot({ ...base,
    [SHOP_CUSTOMER_ORDER_STATUS_KEY]: invalid })).toThrow();
});

test('order-status reference storage fails closed when browser storage is unavailable', () => {
  const storage = createShopStorage({ getStorage: () => ({
    getItem: () => { throw Error('offline'); }, setItem: () => { throw Error('offline'); },
    removeItem: () => { throw Error('offline'); },
  }) });
  expect(() => storage.getItem(SHOP_CUSTOMER_ORDER_STATUS_KEY)).toThrow('offline');
  expect(() => storage.setItem(SHOP_CUSTOMER_ORDER_STATUS_KEY, reference)).toThrow('offline');
  expect(() => storage.removeItem(SHOP_CUSTOMER_ORDER_STATUS_KEY)).toThrow('offline');
});
