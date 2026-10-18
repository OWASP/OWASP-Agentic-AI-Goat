import { createProductSimilarReferenceStore, decodeProductSimilarReference } from './productSimilarReference.mjs';
import { SHOP_PRODUCT_SIMILAR_KEY } from './shopStorage.mjs';

const source = { shopUserId: 7, productId: 12,
  sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', startedAt: 12345 };

test('similar request persists only owner/product/source IDs and clears by exact CAS', async () => {
  const rows = new Map();
  const storage = { getItem: key => rows.get(key) ?? null,
    setItem: (key, value) => rows.set(key, value), removeItem: key => rows.delete(key) };
  const store = createProductSimilarReferenceStore({ storage, flush: async () => {} });
  const saved = await store.save(source);
  expect(saved).toEqual({ version: 1, ...source });
  expect(store.read(7)).toEqual(saved);
  expect(store.read(8)).toBeNull();
  await expect(store.save({ ...source, productId: 13 })).rejects.toThrow();
  await expect(store.clear({ ...saved, requestId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc' })).rejects.toThrow();
  await store.clear(saved);
  expect(storage.getItem(SHOP_PRODUCT_SIMILAR_KEY)).toBeNull();
});

test('reference decoder rejects fabricated authority, product, and oversized data', () => {
  for (const bad of [{ ...source, productId: 0 }, { ...source, mode: 'vuln' },
    { ...source, result: { recommendation: 'forged' } }, { ...source, sessionId: 'bad' },
    { ...source, requestId: 'bad' }])
    expect(() => decodeProductSimilarReference(JSON.stringify({ version: 1, ...bad }))).toThrow();
  expect(() => decodeProductSimilarReference('x'.repeat(513))).toThrow();
});
