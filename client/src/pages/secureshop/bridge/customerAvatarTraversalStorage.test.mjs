import { validateShopSnapshot } from './stateStore.mjs';
import { SHOP_TOKEN_KEY, SHOP_CART_KEY, SHOP_CUSTOMER_AVATAR_TRAVERSAL_KEY,
  createShopStorage } from '../utils/shopStorage.mjs';

const entry = { version: 1, shopUserId: 7, operationId: null,
  sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', startedAt: 1234 };
const raw = JSON.stringify(entry);

test('parent state accepts only the IDs-only saved avatar-traversal reference', () => {
  expect(validateShopSnapshot({ [SHOP_TOKEN_KEY]: null, [SHOP_CART_KEY]: null,
    [SHOP_CUSTOMER_AVATAR_TRAVERSAL_KEY]: raw })[SHOP_CUSTOMER_AVATAR_TRAVERSAL_KEY]).toBe(raw);
  for (const extra of [{ recommendation: 'private result' }, { mode: 'vuln' },
    { ownerId: 'other' }])
    expect(() => validateShopSnapshot({ [SHOP_TOKEN_KEY]: null, [SHOP_CART_KEY]: null,
      [SHOP_CUSTOMER_AVATAR_TRAVERSAL_KEY]: JSON.stringify({...entry,...extra}) }))
      .toThrow();
});

test('saved avatar-traversal reference has no memory fallback after storage failure', () => {
  const storage = createShopStorage({ getStorage: () => ({
    getItem: () => { throw Error('offline'); }, setItem: () => { throw Error('offline'); },
    removeItem: () => { throw Error('offline'); },
  }) });
  expect(() => storage.getItem(SHOP_CUSTOMER_AVATAR_TRAVERSAL_KEY)).toThrow('offline');
  expect(() => storage.setItem(SHOP_CUSTOMER_AVATAR_TRAVERSAL_KEY, raw)).toThrow('offline');
  expect(() => storage.removeItem(SHOP_CUSTOMER_AVATAR_TRAVERSAL_KEY)).toThrow('offline');
});

test('traversal assessment key uses its own closed smaller reference',()=>{
 const key='secureshop.customer-avatar-traversal.assessment.v1',assessment={version:1,shopUserId:7,sessionId:entry.sessionId,requestId:entry.requestId,startedAt:1234};
 expect(validateShopSnapshot({[SHOP_TOKEN_KEY]:null,[SHOP_CART_KEY]:null,[key]:JSON.stringify(assessment)})[key]).toBe(JSON.stringify(assessment));
 expect(()=>validateShopSnapshot({[SHOP_TOKEN_KEY]:null,[SHOP_CART_KEY]:null,[key]:raw})).toThrow();
 expect(()=>validateShopSnapshot({[SHOP_TOKEN_KEY]:null,[SHOP_CART_KEY]:null,[key]:JSON.stringify({...assessment,assetUrl:'http://invalid'})})).toThrow();
});
