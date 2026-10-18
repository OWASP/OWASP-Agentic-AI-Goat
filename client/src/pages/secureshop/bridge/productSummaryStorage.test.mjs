import { validateShopSnapshot } from './stateStore.mjs';
import { SHOP_TOKEN_KEY, SHOP_CART_KEY, SHOP_PRODUCT_SUMMARY_KEY,
  createShopStorage } from '../utils/shopStorage.mjs';

const entry = { version: 1, shopUserId: 7, productId: 12,
  sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', startedAt: 1234 };
const raw = JSON.stringify({version:1,entries:[entry]});

test('parent state accepts only the IDs-only saved product-summary reference', () => {
  expect(validateShopSnapshot({ [SHOP_TOKEN_KEY]: null, [SHOP_CART_KEY]: null,
    [SHOP_PRODUCT_SUMMARY_KEY]: raw })[SHOP_PRODUCT_SUMMARY_KEY]).toBe(raw);
  for (const extra of [{ recommendation: 'private result' }, { mode: 'vuln' },
    { ownerId: 'other' }])
    expect(() => validateShopSnapshot({ [SHOP_TOKEN_KEY]: null, [SHOP_CART_KEY]: null,
      [SHOP_PRODUCT_SUMMARY_KEY]: JSON.stringify({version:1,entries:[{...entry,...extra}]}) }))
      .toThrow();
});

test('saved product-summary reference has no memory fallback after storage failure', () => {
  const storage = createShopStorage({ getStorage: () => ({
    getItem: () => { throw Error('offline'); }, setItem: () => { throw Error('offline'); },
    removeItem: () => { throw Error('offline'); },
  }) });
  expect(() => storage.getItem(SHOP_PRODUCT_SUMMARY_KEY)).toThrow('offline');
  expect(() => storage.setItem(SHOP_PRODUCT_SUMMARY_KEY, raw)).toThrow('offline');
  expect(() => storage.removeItem(SHOP_PRODUCT_SUMMARY_KEY)).toThrow('offline');
});

test('mode-scoped summary references preserve separate pending IDs without trusting extra authority',()=>{
 const first={...entry,version:2,recoveryKey:'a'.repeat(64)},second={...entry,version:2,recoveryKey:'b'.repeat(64),requestId:'cccccccc-cccc-4ccc-8ccc-cccccccccccc',sessionId:'dddddddd-dddd-4ddd-8ddd-dddddddddddd'};
 const scoped=JSON.stringify({version:2,entries:[first,second]});
 expect(validateShopSnapshot({[SHOP_TOKEN_KEY]:null,[SHOP_CART_KEY]:null,[SHOP_PRODUCT_SUMMARY_KEY]:scoped})[SHOP_PRODUCT_SUMMARY_KEY]).toBe(scoped);
 for(const entries of [[first,{...second,recoveryKey:first.recoveryKey}],[{...first,mode:'fixed'}],[{...first,recoveryKey:'not-a-key'}]])
  expect(()=>validateShopSnapshot({[SHOP_TOKEN_KEY]:null,[SHOP_CART_KEY]:null,[SHOP_PRODUCT_SUMMARY_KEY]:JSON.stringify({version:2,entries})})).toThrow();
});
