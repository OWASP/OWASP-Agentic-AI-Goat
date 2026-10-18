import { attachShopStorage, SHOP_ADDRESS_SETUP_KEY, SHOP_CART_KEY, SHOP_TOKEN_KEY } from './shopStorage.mjs';
import { validateShopSnapshot } from '../bridge/stateStore.mjs';
import { addressFieldsDigest, clearAddressReference, decodeAddressForm, decodeAddressOperation,
  decodeAddressSetup, readAddressReference, saveAddressReference } from './addressSetupOperation.mjs';

const operationId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const scopeKey = 'b'.repeat(64);
const fieldsSha256 = 'a9291c88277113b6d9c6513f4ddbb2f5d26d2b1b606ce6b3af13d1e538e184dc';
const fields = { label: 'Home', line1: '1 Main St', line2: null, city: 'Town', state: 'CA',
  zip: '90210', phone: null, isDefault: false };
const reference = { version: 1, scopeKey, operationId, action: 'create', choiceId: null,
  expectedSnapshotSha256: null, defaultSetSha256: 'c'.repeat(64), fieldsSha256 };
let release, values, flush;
beforeEach(() => {
  values = new Map(); flush = jest.fn(async () => {});
  release = attachShopStorage({ getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key),
    flush: () => flush() });
  Object.defineProperty(globalThis.crypto, 'subtle', { configurable: true,
    value: require('node:crypto').webcrypto.subtle });
});
afterEach(() => release());

test('canonical reviewed fields hash matches the server contract and parent state remains opaque', async () => {
  await expect(addressFieldsDigest(fields)).resolves.toBe(fieldsSha256);
  await saveAddressReference(reference);
  expect(flush).toHaveBeenCalledTimes(1);
  expect(readAddressReference()).toEqual(reference);
  expect(values.get(SHOP_ADDRESS_SETUP_KEY)).not.toMatch(/Home|Main|Town|90210/);
  expect(validateShopSnapshot({ [SHOP_TOKEN_KEY]: null, [SHOP_CART_KEY]: null,
    [SHOP_ADDRESS_SETUP_KEY]: values.get(SHOP_ADDRESS_SETUP_KEY) })[SHOP_ADDRESS_SETUP_KEY])
    .toBe(values.get(SHOP_ADDRESS_SETUP_KEY));
  await expect(saveAddressReference({ ...reference, operationId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd' }))
    .rejects.toThrow('Check the saved address');
});

test('exact operation read accepts the saved digest and rejects another address or raw fields', async () => {
  const completed = { scopeKey, operationId, status: 'completed', receipt: { version: 1,
    operationId, kind: 'address.create', status: 'completed', replayed: true,
    result: { addressId: 7, fieldsSha256, addressSnapshotSha256: 'd'.repeat(64),
      defaultSetSha256: 'e'.repeat(64) } } };
  expect(decodeAddressOperation(completed, reference).status).toBe('completed');
  expect(decodeAddressOperation({ ...completed, receipt: { ...completed.receipt,
    status: 'stale', result: { fieldsSha256 } } }, reference).status).toBe('stale');
  expect(() => decodeAddressOperation({ ...completed, receipt: { ...completed.receipt,
    status: 'stale', result: { fieldsSha256, addressId: 7 } } }, reference)).toThrow();
  expect(() => decodeAddressOperation({ ...completed, receipt: { ...completed.receipt,
    result: { ...completed.receipt.result, fieldsSha256: 'f'.repeat(64) } } }, reference)).toThrow();
  expect(() => decodeAddressOperation({ ...completed, fields }, reference)).toThrow();
  expect(() => validateShopSnapshot({ [SHOP_TOKEN_KEY]: null, [SHOP_CART_KEY]: null,
    [SHOP_ADDRESS_SETUP_KEY]: JSON.stringify({ ...reference, fields }) })).toThrow();
});

test('closed handoff and form reject missing ownership or invented model fields', () => {
  expect(decodeAddressSetup({ version: 1, kind: 'address_setup', action: 'create',
    choiceId: null, draft: { line1: '1 Main St' } }).draft.line1).toBe('1 Main St');
  expect(() => decodeAddressSetup({ version: 1, kind: 'address_setup', action: 'create',
    choiceId: null, draft: { productId: '7' } })).toThrow();
  expect(decodeAddressForm({ scopeKey, action: 'create', choiceId: null,
    fields: { label: null, line1: '', line2: null, city: null, state: null, zip: null,
      phone: null, isDefault: false }, expectedSnapshotSha256: null,
    defaultSetSha256: 'c'.repeat(64) }).fields.line1).toBeNull();
  expect(() => decodeAddressForm({ scopeKey, action: 'update', choiceId: operationId,
    fields, expectedSnapshotSha256: null, defaultSetSha256: 'c'.repeat(64) })).toThrow();
});

test('failed removal acknowledgement restores only the same pending address reference', async () => {
  await saveAddressReference(reference);
  flush.mockRejectedValueOnce(Error('parent refused remove'));
  await expect(clearAddressReference(reference)).rejects.toThrow('parent refused remove');
  expect(readAddressReference()).toEqual(reference);
  await clearAddressReference(reference);
  expect(values.has(SHOP_ADDRESS_SETUP_KEY)).toBe(false);
});
