import { decodeMailReferences } from '../bridge/mailReferences.mjs';
import { SHOP_MAIL_KEY, shopStorage } from './shopStorage.mjs';
import { assertMerchantMailPending, clearMerchantMailPending, readMerchantMailPending,
  saveMerchantMailPending } from './merchantMailReference.mjs';

const scope = 'a'.repeat(64);
const reference = { action: 'send', requestId: 'cccccccc-cccc-5ccc-accc-cccccccccccc',
  digest: 'b'.repeat(64), chatSource: { sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' } };

beforeEach(() => { localStorage.clear(); });
afterEach(() => { localStorage.clear(); });

test('one shared mail slot accepts a closed chat origin and retains legacy manual references', async () => {
  await saveMerchantMailPending(scope, reference);
  expect(readMerchantMailPending(scope)).toEqual(reference);
  const encoded = shopStorage.getItem(SHOP_MAIL_KEY);
  expect(decodeMailReferences(encoded).scopes[scope].pending).toEqual(reference);
  expect(encoded).not.toContain('subject');
  expect(encoded).not.toContain('body_markdown');
  assertMerchantMailPending(scope, reference);
  await clearMerchantMailPending(scope, reference);
  expect(readMerchantMailPending(scope)).toBeNull();
  const legacy = { action: 'send', requestId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
    digest: 'c'.repeat(64) };
  shopStorage.setItem(SHOP_MAIL_KEY, JSON.stringify({ version: 3,
    scopes: { [scope]: { pending: legacy, assessment: null } } }));
  expect(readMerchantMailPending(scope)).toEqual(legacy);
  await expect(saveMerchantMailPending(scope, reference)).rejects.toThrow('changed');
  expect(readMerchantMailPending(scope)).toEqual(legacy);
});

test('replaced or removed chat reference never authorizes a confirmation or foreign clear', async () => {
  await saveMerchantMailPending(scope, reference);
  const replacement = { ...reference, requestId: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee' };
  shopStorage.setItem(SHOP_MAIL_KEY, JSON.stringify({ version: 3,
    scopes: { [scope]: { pending: replacement, assessment: null } } }));
  expect(() => assertMerchantMailPending(scope, reference)).toThrow('changed');
  await expect(clearMerchantMailPending(scope, reference)).rejects.toThrow('changed');
  expect(readMerchantMailPending(scope)).toEqual(replacement);
});
