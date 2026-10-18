import { readAclPending, saveAclPending, clearAclPending } from './aclOperation.js';
import { flushShopStorage, SHOP_ACL_KEY } from '../../utils/shopStorage.mjs';

jest.mock('../../utils/shopStorage.mjs', () => {
  const actual = jest.requireActual('../../utils/shopStorage.mjs');
  return { ...actual, flushShopStorage: jest.fn(() => Promise.resolve()) };
});

const operation = (scopeKey = 'owner-one', operationId = '11111111-1111-4111-8111-111111111111') => ({
  kind: 'enforcement', scopeKey, registrySha256: 'a'.repeat(64),
  body: { operationId, expectedVersion: '1', enabled: true },
});

beforeEach(() => {
  localStorage.clear();
  flushShopStorage.mockReset().mockResolvedValue(undefined);
});

test('same-scope saved operation survives readback and clears only by exact reference', async () => {
  const pending = operation();
  await saveAclPending(pending);
  expect(readAclPending(pending.scopeKey)).toEqual(pending);
  await expect(clearAclPending(operation('owner-one', '22222222-2222-4222-8222-222222222222')))
    .rejects.toThrow('does not match');
  expect(readAclPending(pending.scopeKey)).toEqual(pending);
  await clearAclPending(readAclPending(pending.scopeKey));
  expect(readAclPending(pending.scopeKey)).toBeNull();
});

test('foreign-scope operation remains occupied and cannot be overwritten or cleared', async () => {
  const foreign = operation('owner-two');
  localStorage.setItem(SHOP_ACL_KEY, JSON.stringify(foreign));
  await expect(() => readAclPending('owner-one')).toThrow('another scope');
  await expect(saveAclPending(operation())).rejects.toThrow('needs recovery');
  await expect(clearAclPending(operation())).rejects.toThrow('does not match');
  expect(JSON.parse(localStorage.getItem(SHOP_ACL_KEY))).toEqual(foreign);
});

test('occupied same-scope and invalid references also fail closed', async () => {
  const first = operation();
  await saveAclPending(first);
  await expect(saveAclPending(operation('owner-one', '22222222-2222-4222-8222-222222222222')))
    .rejects.toThrow('needs recovery');
  expect(readAclPending('owner-one')).toEqual(first);

  localStorage.setItem(SHOP_ACL_KEY, '{bad json');
  expect(() => readAclPending('owner-one')).toThrow('invalid');
  await expect(saveAclPending(operation())).rejects.toThrow('needs recovery');
  await expect(clearAclPending(first)).rejects.toThrow('does not match');
  expect(localStorage.getItem(SHOP_ACL_KEY)).toBe('{bad json');
});

test('failed save acknowledgement leaves an exact reference that can be cleared without sending', async () => {
  const pending = operation();
  flushShopStorage.mockRejectedValueOnce(new Error('storage acknowledgement lost'));
  await expect(saveAclPending(pending)).rejects.toThrow('storage acknowledgement lost');
  expect(readAclPending(pending.scopeKey)).toEqual(pending);
  await clearAclPending(pending);
  expect(localStorage.getItem(SHOP_ACL_KEY)).toBeNull();
});

test('a replacement during save acknowledgement is preserved', async () => {
  const first = operation();
  const replacement = operation('owner-two', '22222222-2222-4222-8222-222222222222');
  flushShopStorage.mockImplementationOnce(async () => {
    localStorage.setItem(SHOP_ACL_KEY, JSON.stringify(replacement));
  });
  await expect(saveAclPending(first)).rejects.toThrow('was replaced');
  await expect(clearAclPending(first)).rejects.toThrow('does not match');
  expect(JSON.parse(localStorage.getItem(SHOP_ACL_KEY))).toEqual(replacement);
});

test('a replacement during clear acknowledgement is not reported as cleared', async () => {
  const first = operation();
  const replacement = operation('owner-two', '22222222-2222-4222-8222-222222222222');
  await saveAclPending(first);
  flushShopStorage.mockImplementationOnce(async () => {
    localStorage.setItem(SHOP_ACL_KEY, JSON.stringify(replacement));
  });
  await expect(clearAclPending(first)).rejects.toThrow('was replaced');
  expect(JSON.parse(localStorage.getItem(SHOP_ACL_KEY))).toEqual(replacement);
});

test('clearing an absent reference fails closed', async () => {
  await expect(clearAclPending(operation())).rejects.toThrow('does not match');
  expect(localStorage.getItem(SHOP_ACL_KEY)).toBeNull();
});


test('failed clear acknowledgement restores only own absent slot for exact GET recovery', async () => {
  const pending = operation();
  await saveAclPending(pending);
  flushShopStorage.mockRejectedValueOnce(new Error('Parent ACK failed')).mockResolvedValueOnce();
  await expect(clearAclPending(pending)).rejects.toThrow('Parent ACK failed');
  expect(readAclPending(pending.scopeKey)).toEqual(pending);
});

test('failed clear never overwrites a replacement or restores after authority renewal', async () => {
  const pending = operation(), replacement = operation('foreign');
  for (const renew of [false, true]) {
    localStorage.clear(); await saveAclPending(pending);
    let current = true;
    flushShopStorage.mockImplementationOnce(async () => {
      if (renew) current = false;
      else localStorage.setItem(SHOP_ACL_KEY, JSON.stringify(replacement));
      throw new Error('Lost clear ACK');
    });
    await expect(clearAclPending(pending, () => current)).rejects.toThrow('Lost clear ACK');
    expect(localStorage.getItem(SHOP_ACL_KEY)).toBe(renew ? null : JSON.stringify(replacement));
  }
});
