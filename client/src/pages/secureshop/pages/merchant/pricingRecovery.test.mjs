import { attachShopStorage, SHOP_PRICING_KEY } from '../../utils/shopStorage.mjs';
import { clearPricingReference, readPricingReferences,
  savePricingReference } from './pricingRecovery.mjs';

const current = { scopeKey: 'a'.repeat(64), operationId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  productId: 7, action: 'suggest', requestSha256: 'b'.repeat(64) };
const foreign = { scopeKey: 'c'.repeat(64), operationId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
  productId: 8, action: 'experiment', requestSha256: 'e'.repeat(64) };
let values, release, flush;
const adapter = map => ({ getItem: key => map.get(key) ?? null,
  setItem: (key, value) => map.set(key, value), removeItem: key => map.delete(key),
  flush: () => flush() });
beforeEach(() => { values = new Map(); flush = async () => {}; release = attachShopStorage(adapter(values)); });
afterEach(() => { release(); });

test('Pricing save requires exact parent readback after its ACK', async () => {
  flush = async () => values.set(SHOP_PRICING_KEY, JSON.stringify({ version: 1,
    references: [{ ...current, operationId: 'ffffffff-ffff-4fff-8fff-ffffffffffff' }] }));
  await expect(savePricingReference(current)).rejects.toThrow('Pricing reference changed');
  expect(readPricingReferences()[0].operationId).toBe('ffffffff-ffff-4fff-8fff-ffffffffffff');
});

test('failed clear ACK restores only the same Pricing reference and retains foreign rows', async () => {
  values.set(SHOP_PRICING_KEY, JSON.stringify({ version: 1, references: [current, foreign] }));
  let attempts = 0;
  flush = async () => { if (++attempts === 1) throw Error('parent removal refused'); };
  await expect(clearPricingReference(current)).rejects.toThrow('parent removal refused');
  expect(readPricingReferences()).toEqual([foreign, current]);
});

test('late rejected clear ACK cannot restore an old Pricing reference into a renewed adapter', async () => {
  values.set(SHOP_PRICING_KEY, JSON.stringify({ version: 1, references: [current] }));
  let rejectAck;
  flush = () => new Promise((_resolve, reject) => { rejectAck = reject; });
  let active = true;
  const clearing = clearPricingReference(current, () => active);
  await Promise.resolve();
  const renewed = new Map();
  release(); release = attachShopStorage(adapter(renewed)); active = false;
  rejectAck(Error('late parent refusal'));
  await expect(clearing).rejects.toThrow('late parent refusal');
  expect(renewed.has(SHOP_PRICING_KEY)).toBe(false);
});
