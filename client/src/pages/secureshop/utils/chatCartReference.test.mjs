import { attachShopStorage, SHOP_CHAT_CART_KEY, SHOP_TOKEN_KEY, SHOP_CART_KEY } from './shopStorage.mjs';
import { readChatCartReference, saveChatCartReference,
  clearChatCartReference, decodeChatCartReference } from './chatCartReference.mjs';
import { validateShopSnapshot } from '../bridge/stateStore.mjs';

const ref = { operationId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  intentDigest: 'b'.repeat(64), scopeKey: 'c'.repeat(64) };
let values, releaseStorage, failRemove;
beforeEach(() => {
  values = new Map(); failRemove = false;
  releaseStorage = attachShopStorage({ getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key),
    flush: async () => { if (failRemove) { failRemove = false; throw Error('Parent ACK lost'); } } });
});
afterEach(() => releaseStorage());

test('opaque cart confirmation ref is exact and parent-acknowledged', async () => {
  expect(() => decodeChatCartReference(JSON.stringify({ ...ref, title: 'Raw product' }))).toThrow();
  await saveChatCartReference(ref);
  expect(readChatCartReference()).toEqual(ref);
  expect(values.get(SHOP_CHAT_CART_KEY)).not.toMatch(/title|quantity|product|token/i);
  expect(validateShopSnapshot({ [SHOP_TOKEN_KEY]: null, [SHOP_CART_KEY]: null,
    [SHOP_CHAT_CART_KEY]: values.get(SHOP_CHAT_CART_KEY) })[SHOP_CHAT_CART_KEY])
    .toBe(values.get(SHOP_CHAT_CART_KEY));
  expect(() => validateShopSnapshot({ [SHOP_TOKEN_KEY]: null, [SHOP_CART_KEY]: null,
    [SHOP_CHAT_CART_KEY]: JSON.stringify({ ...ref, title: 'Raw product' }) }))
    .toThrow();
  await clearChatCartReference(ref);
  expect(values.has(SHOP_CHAT_CART_KEY)).toBe(false);
});

test('lost removal ACK retains exact UUID for GET-only recovery', async () => {
  await saveChatCartReference(ref);
  failRemove = true;
  await expect(clearChatCartReference(ref)).rejects.toThrow('Parent ACK lost');
  expect(readChatCartReference()).toEqual(ref);
});
