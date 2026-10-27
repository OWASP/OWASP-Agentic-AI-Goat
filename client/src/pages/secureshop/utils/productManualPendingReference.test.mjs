import { createProductManualPendingReferenceStore, decodeProductManualPendingReference,
  verifyProductManualLookup } from './productManualPendingReference.mjs';
import { SHOP_PRODUCT_MANUAL_KEY, SHOP_TOKEN_KEY, SHOP_CART_KEY, createShopStorage } from './shopStorage.mjs';
import { validateShopSnapshot } from '../bridge/stateStore.mjs';

const descriptor = { productId: '12', sha256: 'a'.repeat(64), sizeBytes: '6',
  filename: 'manual.txt', mime: 'text/plain', public: 'false' };
const lookup = { version: 1, kind: 'product_manual',
  operationId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', recoveryScopeKey: 'b'.repeat(64),
  state: 'not_found', receipt: null };
const indexed = { ...lookup, state: 'indexed', receipt: { productId: 12,
  sha256: descriptor.sha256, sizeBytes: 6, filename: descriptor.filename,
  mime: descriptor.mime, isPublic: false, chunkCount: 1, chunkIds: ['manual:1:0'],
  completedAt: '2026-10-19T00:00:00.000Z' } };

function fixture() {
  const values = new Map();
  const storage = { getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key) };
  const flush = jest.fn(async () => {});
  return { values, storage, flush, store: createProductManualPendingReferenceStore({ storage, flush }) };
}

test('pending metadata is flushed and acknowledged before initial POST can be exposed', async () => {
  const { values, flush, store } = fixture();
  const pending = await store.reserveInitialPost(descriptor, lookup);
  expect(flush).toHaveBeenCalledTimes(1);
  expect(pending).toEqual({ version: 1, descriptor, operationId: lookup.operationId,
    recoveryScopeKey: lookup.recoveryScopeKey });
  const raw = values.get(SHOP_PRODUCT_MANUAL_KEY);
  expect(raw).not.toContain('file_bytes');
  expect(validateShopSnapshot({ [SHOP_TOKEN_KEY]: null, [SHOP_CART_KEY]: null,
    [SHOP_PRODUCT_MANUAL_KEY]: raw })[SHOP_PRODUCT_MANUAL_KEY]).toBe(raw);
  await expect(store.reserveInitialPost(descriptor, lookup)).rejects.toThrow(/retry is forbidden/);
  expect((await store.reconcile(lookup)).state).toBe('unresolved');
  expect(values.get(SHOP_PRODUCT_MANUAL_KEY)).toBe(raw);
  expect((await store.reconcile(indexed)).state).toBe('indexed');
  expect(store.read()).toBeNull();
});

test('initial GET verifier distinguishes exact indexed receipt without persistence or upload permission', () => {
  expect(verifyProductManualLookup(descriptor, lookup)).toEqual({ state: 'not_found',
    operationId: lookup.operationId, recoveryScopeKey: lookup.recoveryScopeKey, receipt: null });
  expect(verifyProductManualLookup(descriptor, indexed)).toEqual({ state: 'indexed',
    operationId: lookup.operationId, recoveryScopeKey: lookup.recoveryScopeKey, receipt: indexed.receipt });
  expect(() => verifyProductManualLookup(descriptor, { ...indexed,
    receipt: { ...indexed.receipt, sizeBytes: '6' } })).toThrow();
  expect(() => verifyProductManualLookup(descriptor, indexed,
    { operationId: lookup.operationId, recoveryScopeKey: 'c'.repeat(64) })).toThrow();
});

test('unavailable, foreign and mismatched receipts cannot clear or authorize retry', async () => {
  const { values, store } = fixture();
  await store.reserveInitialPost(descriptor, lookup);
  const raw = values.get(SHOP_PRODUCT_MANUAL_KEY);
  await expect(store.reconcile(null)).rejects.toThrow();
  for (const changed of [{ ...indexed, operationId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc' },
    { ...indexed, recoveryScopeKey: 'c'.repeat(64) },
    { ...indexed, receipt: { ...indexed.receipt, productId: 13 } },
    { ...indexed, receipt: { ...indexed.receipt, productId: '12' } },
    { ...indexed, receipt: { ...indexed.receipt, sizeBytes: '6' } },
    { ...indexed, receipt: { ...indexed.receipt, chunkIds: ['manual:1:1'] } },
    { ...indexed, receipt: { ...indexed.receipt, chunkCount: 130,
      chunkIds: Array.from({ length: 130 }, (_, i) => `manual:1:${i}`) } },
    { ...indexed, receipt: { ...indexed.receipt, completedAt: 'invalid' } }])
    await expect(store.reconcile(changed)).rejects.toThrow();
  expect(values.get(SHOP_PRODUCT_MANUAL_KEY)).toBe(raw);
  await expect(store.reserveInitialPost(descriptor, lookup)).rejects.toThrow(/retry is forbidden/);
});

test('storage or flush failure fails closed; reference codec rejects private payloads', async () => {
  const { storage } = fixture();
  const unavailable = createProductManualPendingReferenceStore({ storage, flush: async () => { throw Error('offline'); } });
  await expect(unavailable.reserveInitialPost(descriptor, lookup)).rejects.toThrow('offline');
  expect(unavailable.read()).not.toBeNull();
  expect(() => decodeProductManualPendingReference(JSON.stringify({ ...unavailable.read(), bytes: 'secret' }))).toThrow();
  const strict = createShopStorage({ getStorage: () => ({ getItem: () => { throw Error('offline'); },
    setItem: () => { throw Error('offline'); }, removeItem: () => { throw Error('offline'); } }) });
  expect(() => strict.setItem(SHOP_PRODUCT_MANUAL_KEY, '{}')).toThrow('offline');
  expect(() => strict.getItem(SHOP_PRODUCT_MANUAL_KEY)).toThrow('offline');
  for (const changed of [{ ...descriptor, productId: '2147483648' },
    { ...descriptor, mime: '  ' }, { ...descriptor, sizeBytes: '20971521' },
    { ...descriptor, filename: 'bad\nname.txt' }, { ...descriptor, bytes: 'private' }])
    await expect(createProductManualPendingReferenceStore({ storage: { ...storage,
      getItem: () => null }, flush: async () => {} }).reserveInitialPost(changed, lookup)).rejects.toThrow();
  expect(() => decodeProductManualPendingReference('x'.repeat(4097))).toThrow();
});

test('long valid metadata remains bounded and overlapping admission cannot pass a pending flush', async () => {
  const { storage } = fixture();
  let release;
  const waiting = new Promise(resolve => { release = resolve; });
  const store = createProductManualPendingReferenceStore({ storage, flush: () => waiting });
  const long = { ...descriptor, filename: '\\"'.repeat(120) + '.txt' };
  const first = store.reserveInitialPost(long, lookup);
  await expect(store.reserveInitialPost(long, lookup)).rejects.toThrow();
  release();
  expect((await first).descriptor.filename).toBe(long.filename);
  expect(store.read().descriptor.filename).toBe(long.filename);
});

test('stale synchronous authority guard blocks clearing an indexed pending reference', async () => {
  const { values, store } = fixture();
  await store.reserveInitialPost(descriptor, lookup);
  const raw = values.get(SHOP_PRODUCT_MANUAL_KEY);
  await expect(store.reconcile(indexed, { assertCurrent: () => false })).rejects.toThrow();
  await expect(store.reconcile(indexed, { assertCurrent: async () => true })).rejects.toThrow();
  expect(values.get(SHOP_PRODUCT_MANUAL_KEY)).toBe(raw);
  expect((await store.reconcile(indexed, { assertCurrent: () => true })).state).toBe('indexed');
});

test('initial POST authority guard fences before write and after delayed flush', async () => {
  const { storage, values } = fixture();
  let release;
  const waiting = new Promise(resolve => { release = resolve; });
  const store = createProductManualPendingReferenceStore({ storage, flush: () => waiting });
  await expect(store.reserveInitialPost(descriptor, lookup,
    { assertCurrent: () => false })).rejects.toThrow();
  expect(values.has(SHOP_PRODUCT_MANUAL_KEY)).toBe(false);
  let current = true;
  const pending = store.reserveInitialPost(descriptor, lookup, { assertCurrent: () => current });
  expect(values.has(SHOP_PRODUCT_MANUAL_KEY)).toBe(true);
  current = false;
  release();
  await expect(pending).rejects.toThrow();
  expect(store.read()).not.toBeNull();
  await expect(store.reserveInitialPost(descriptor, lookup)).rejects.toThrow(/retry is forbidden/);
});
