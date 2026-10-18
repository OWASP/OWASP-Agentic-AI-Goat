import { decodeRegisteredAdminChatReference, readRegisteredAdminChatReference,
  saveRegisteredAdminChatReference, clearRegisteredAdminChatReference } from './registeredAdminChatReference.mjs';
import { shopStorage, flushShopStorage, SHOP_REGISTERED_ADMIN_CHAT_KEY } from './shopStorage.mjs';

jest.mock('./shopStorage.mjs', () => ({
  SHOP_REGISTERED_ADMIN_CHAT_KEY: 'registered-pending',
  shopStorage: { getItem: jest.fn(), setItem: jest.fn(), removeItem: jest.fn() },
  flushShopStorage: jest.fn(),
}));

const reference = { shopUserId: 7, sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', startedAt: 1234 };
let raw;
beforeEach(() => {
  raw = null;
  shopStorage.getItem.mockImplementation(() => raw);
  shopStorage.setItem.mockImplementation((key, value) => { raw = value; });
  shopStorage.removeItem.mockImplementation(() => { raw = null; });
  flushShopStorage.mockResolvedValue();
});
afterEach(() => jest.clearAllMocks());

test('parent ACK precedes dispatch and the exact opaque reference survives decode', async () => {
  let release;
  flushShopStorage.mockImplementationOnce(() => new Promise(resolve => { release = resolve; }));
  const saving = saveRegisteredAdminChatReference(reference);
  expect(readRegisteredAdminChatReference()).toMatchObject(reference);
  expect(raw).not.toContain('message');
  release();
  await expect(saving).resolves.toMatchObject(reference);
  expect(decodeRegisteredAdminChatReference(raw)).toMatchObject(reference);
});

test('foreign saved reference cannot be replaced', async () => {
  raw = JSON.stringify({ version: 1, ...reference, shopUserId: 8 });
  await expect(saveRegisteredAdminChatReference(reference)).rejects.toThrow(/Check the saved/);
  expect(shopStorage.setItem).not.toHaveBeenCalled();
});

test('failed removal restores only an absent exact own reference', async () => {
  raw = JSON.stringify({ version: 1, ...reference });
  flushShopStorage.mockRejectedValueOnce(Error('Parent ACK unavailable'));
  await expect(clearRegisteredAdminChatReference(reference)).rejects.toThrow('Parent ACK unavailable');
  expect(readRegisteredAdminChatReference()).toMatchObject(reference);
  raw = JSON.stringify({ version: 1, ...reference });
  const replacement = { ...reference, requestId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc' };
  shopStorage.removeItem.mockImplementationOnce(() => { raw = JSON.stringify({ version: 1, ...replacement }); });
  flushShopStorage.mockRejectedValueOnce(Error('Parent ACK unavailable'));
  await expect(clearRegisteredAdminChatReference(reference)).rejects.toThrow('Parent ACK unavailable');
  expect(readRegisteredAdminChatReference()).toMatchObject(replacement);
});

test('expired lifecycle does not restore after a failed removal ACK', async () => {
  raw = JSON.stringify({ version: 1, ...reference });
  let live = true;
  flushShopStorage.mockImplementationOnce(async () => { live = false; throw Error('Parent ACK unavailable'); });
  await expect(clearRegisteredAdminChatReference(reference, () => live)).rejects.toThrow('Parent ACK unavailable');
  expect(raw).toBeNull();
});
