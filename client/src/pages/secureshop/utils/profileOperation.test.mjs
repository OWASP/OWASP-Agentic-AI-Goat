import { createHash, webcrypto } from 'node:crypto';
import { attachShopStorage, SHOP_PROFILE_KEY, SHOP_TOKEN_KEY, SHOP_CART_KEY } from './shopStorage.mjs';
import { validateShopSnapshot } from '../bridge/stateStore.mjs';
import { clearProfileReference, decodeProfileOperation, decodeProfileProposal,
  normalizeEditedProfileFields, profileFieldsDigest, profileRequestDigest,
  readProfileReference, saveProfileReference } from './profileOperation.mjs';

const id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', sha = 'b'.repeat(64), scope = 'c'.repeat(64);
const fields = { fullName: 'Customer', email: 'legacy.invalid', phone: '  ' };
const reference = { version: 1, operationId: id, scopeKey: scope,
  expectedSnapshotSha256: sha, fieldsSha256: 'd'.repeat(64), requestSha256: 'e'.repeat(64),
  sessionId: null, requestId: null };
const hash = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
let values, detach;
beforeEach(() => {
  Object.defineProperty(globalThis, 'crypto', { configurable: true, value: { subtle: webcrypto.subtle } });
  values = new Map();
  detach = attachShopStorage({ getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key),
    flush: async () => {} });
});
afterEach(() => detach());

test('hashes exact ordered lossless legacy view and permits only unchanged retained malformed email', async () => {
  expect(await profileFieldsDigest(fields)).toBe(hash(fields));
  expect(await profileRequestDigest(id, sha, fields)).toBe(hash({ operationId: id,
    expectedSnapshotSha256: sha, fieldsSha256: hash(fields) }));
  expect(normalizeEditedProfileFields({ ...fields, fullName: 'New' }, fields))
    .toEqual({ ...fields, fullName: 'New' });
  expect(() => normalizeEditedProfileFields({ ...fields, email: 'new.invalid' }, fields))
    .toThrow('valid email');
  expect(() => decodeProfileProposal({ version: 1, proposalId: id, scopeKey: scope,
    expectedSnapshotSha256: sha, requestSha256: sha, before: fields,
    after: { ...fields, fullName: 'Changed' }, patch: { phone: '123' } })).toThrow();
});

test('exact completed stale receipt clears only same hash; not_found remains unresolved', async () => {
  await saveProfileReference(reference);
  expect(readProfileReference()).toEqual(reference);
  expect(validateShopSnapshot({ [SHOP_TOKEN_KEY]: null, [SHOP_CART_KEY]: null,
    [SHOP_PROFILE_KEY]: values.get(SHOP_PROFILE_KEY) })[SHOP_PROFILE_KEY])
    .toBe(values.get(SHOP_PROFILE_KEY));
  expect(() => validateShopSnapshot({ [SHOP_TOKEN_KEY]: null, [SHOP_CART_KEY]: null,
    [SHOP_PROFILE_KEY]: JSON.stringify({ ...reference, fields }) })).toThrow();
  expect(decodeProfileOperation({ scopeKey: scope, operationId: id, status: 'not_found' }, reference))
    .toEqual({ status: 'not_found' });
  const stale = { scopeKey: scope, operationId: id, status: 'completed', receipt: { version: 1,
    operationId: id, kind: 'profile.update', status: 'stale', replayed: true,
    result: { fieldsSha256: reference.fieldsSha256 } } };
  expect(decodeProfileOperation(stale, reference).status).toBe('stale');
  expect(() => decodeProfileOperation({ ...stale, receipt: { ...stale.receipt,
    result: { fieldsSha256: sha } } }, reference)).toThrow();
  await clearProfileReference(reference);
  expect(values.has(SHOP_PROFILE_KEY)).toBe(false);
});
